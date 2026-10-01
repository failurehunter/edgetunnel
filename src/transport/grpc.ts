// @ts-nocheck
// Фаза 4, пункт 3 (шаг 4): транспорт gRPC поверх HTTP/2.
//
// Раньше этот код жил в transport/handlers.ts вместе с двумя другими
// транспортами. Разнесено по одному файлу на транспорт: у каждого свои
// приватные хелперы, и общий файл только мешал читать ветку целиком.
// Первый пакет копится и разбирается инкрементально: клиент вправе разбить
// его по нескольким кадрам (P4.3, найдено при этом же разносе).
const log = (...args) => console.error('[grpc]', ...args);
import { 判断首包协议, 增量解析木马首包, 增量解析魏烈思首包, 累积首包 } from "../protocols";
import { 有效数据长度 } from "../util";
import { 下行Grain包字节 } from "./grain";
import { forwardataTCP, 失效TCP连接世代 } from "./relay";
import { forwardataudp, isSpeedTestSite, 构造本地204响应, 转发木马UDP数据 } from "./shared";
import { 创建Upstream会话 } from "./upstream-session";
import { 创建远端写入门 } from "./upstream-write";

/** varint по gRPC/HTTP2: младшие 7 бит в байт, старший бит — «есть продолжение». */
export function 编码gRPCVarint(число) {
	const байты = [];
	let remaining = число >>> 0;
	while (remaining > 127) {
		байты.push((remaining & 0x7f) | 0x80);
		remaining >>>= 7;
	}
	байты.push(remaining);
	return new Uint8Array(байты);
}

/**
 * Возвращает длину varint-префикса в начале payload, либо 0, если префикса нет.
 * Монолит начинал разбор с `payload[0] === 0x0a`; здесь условие вынесено наружу,
 * чтобы вызывающий не дублировал его (в инлайн-коде это был `if (payload[0] === 0x0a)`).
 */
export function 解析gRPCVarint前缀(payload) {
	if (payload.byteLength < 2 || payload[0] !== 0x0a) return 0;
	let shift = 0;
	let offset = 1;
	let varint有效 = false;
	while (offset < payload.length) {
		const current = payload[offset++];
		if ((current & 0x80) === 0) {
			varint有效 = true;
			break;
		}
		shift += 7;
		if (shift > 35) break;
	}
	return varint有效 ? offset : 0;
}

/**
 * Снимает очередной кадр из буфера.
 * @returns {{grpcPayload: Uint8Array, rest: Uint8Array, frameSize: number} | null}
 *   null — данных пока не хватает, ждём ещё.
 */
export function 拆解gRPC帧(pending) {
	if (pending.byteLength < 5) return null;
	const grpcLen = ((pending[1] << 24) >>> 0) | (pending[2] << 16) | (pending[3] << 8) | pending[4];
	const frameSize = 5 + grpcLen;
	if (pending.byteLength < frameSize) return null;
	return { grpcPayload: pending.subarray(5, frameSize), rest: pending.slice(frameSize), frameSize };
}

export async function 处理gRPC请求(request, yourUUID, 反代上下文 = {}, 请求上下文 = null) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const remoteConnWrapper = 创建Upstream会话(); // P4.1: явная сессия, владелец сокета
	const 失效远端连接 = () => 失效TCP连接世代(remoteConnWrapper);
	let isDnsQuery = false;
	const 木马UDP上下文 = { 缓存: new Uint8Array(0), 反代地址: 反代上下文.木马反代地址 };
	let 判断是否是木马 = null;
	// P4.3: накопленный первый пакет — состояние сессии, а не локальная
	// переменная цикла. Без накопления инкрементальный разбор бессмыслен:
	// need_more означает «пришли ещё», и нечего предъявить при следующем вызове.
	let 首包缓冲 = null;
	// P4.3: общий «запись в апстрим». Объявлен на уровне функции, а не внутри
	// start(), потому что им пользуется и start(), и соседний метод cancel(),
	// который переменных из области start() не видит. Присваивается сразу под
	// 关闭连接 — до try, так что к моменту любого вызова 关闭连接 значение есть.
	let 远端写入门 = null;
	//log('[gRPC] 开始处理双向流');
	const grpcHeaders = new Headers({
		'Content-Type': 'application/grpc',
		'grpc-status': '0',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store'
	});

	const 下行缓存上限 = 下行Grain包字节;
	const 下行刷新间隔 = 1;

	return new Response(new ReadableStream({
		async start(controller) {
			let 已关闭 = false;
			let 发送队列 = [];
			let 队列字节数 = 0;
			let 刷新定时器 = null;
			let 刷新Microtask已排队 = false;
			const grpcBridge = {
				readyState: WebSocket.OPEN,
				send(data) {
					if (已关闭) return;
					const chunk = data instanceof Uint8Array ? data : new Uint8Array(data);
					const lenBytes = 编码gRPCVarint(chunk.byteLength);
					const protobufLen = 1 + lenBytes.length + chunk.byteLength;
					const frame = new Uint8Array(5 + protobufLen);
					frame[0] = 0;
					frame[1] = (protobufLen >>> 24) & 0xff;
					frame[2] = (protobufLen >>> 16) & 0xff;
					frame[3] = (protobufLen >>> 8) & 0xff;
					frame[4] = protobufLen & 0xff;
					frame[5] = 0x0a;
					frame.set(lenBytes, 6);
					frame.set(chunk, 6 + lenBytes.length);
					发送队列.push(frame);
					队列字节数 += frame.byteLength;
					安排刷新发送队列();
				},
				close() {
					if (this.readyState === WebSocket.CLOSED) return;
					刷新发送队列(true);
					已关闭 = true;
					this.readyState = WebSocket.CLOSED;
					try { controller.close() } catch (e) { }
				}
			};

			const 刷新发送队列 = (force = false) => {
				刷新Microtask已排队 = false;
				if (刷新定时器) {
					clearTimeout(刷新定时器);
					刷新定时器 = null;
				}
				if ((!force && 已关闭) || 队列字节数 === 0) return;
				const out = new Uint8Array(队列字节数);
				let offset = 0;
				for (const item of 发送队列) {
					out.set(item, offset);
					offset += item.byteLength;
				}
				发送队列 = [];
				队列字节数 = 0;
				try {
					controller.enqueue(out);
				} catch (e) {
					已关闭 = true;
					grpcBridge.readyState = WebSocket.CLOSED;
				}
			};

			const 安排刷新发送队列 = () => {
				if (队列字节数 >= 下行缓存上限) {
					刷新发送队列();
					return;
				}
				if (刷新Microtask已排队 || 刷新定时器) return;
				刷新Microtask已排队 = true;
				queueMicrotask(() => {
					刷新Microtask已排队 = false;
					if (已关闭 || 队列字节数 === 0 || 刷新定时器) return;
					刷新定时器 = setTimeout(刷新发送队列, 下行刷新间隔);
				});
			};

			const 关闭连接 = () => {
				if (已关闭) return;
				远端写入门.队列.清空();
				失效远端连接();
				刷新发送队列(true);
				已关闭 = true;
				grpcBridge.readyState = WebSocket.CLOSED;
				if (刷新定时器) clearTimeout(刷新定时器);
				远端写入门.释放();
				try { reader.releaseLock() } catch (e) { }
				try { 木马UDP上下文.反代Socket?.close() } catch (e) { }
				try { controller.close() } catch (e) { }
			};

			// P4.3: ленивый writer, его пересоздание при смене сокета и очередь с
			// повторами — общее дело WS и gRPC, живёт в upstream-write.ts. Здесь
			// различаются только имя очереди и то, что происходит при закрытии.
			远端写入门 = 创建远端写入门({ remoteConnWrapper, 关闭连接, 名称: 'gRPC上行' });
			const 写入远端 = 远端写入门.写入并等待;

			let 转发失败 = false;
			try {
				let pending = new Uint8Array(0);
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					const 当前块 = value instanceof Uint8Array ? value : new Uint8Array(value);
					const merged = new Uint8Array(pending.length + 当前块.length);
					merged.set(pending, 0);
					merged.set(当前块, pending.length);
					pending = merged;
					for (;;) {
						const 帧 = 拆解gRPC帧(pending);
						if (!帧) break;
						const grpcPayload = 帧.grpcPayload;
						pending = 帧.rest;
						if (!grpcPayload.byteLength) continue;
						let payload = grpcPayload;
						const varintСдвиг = 解析gRPCVarint前缀(payload);
						if (varintСдвиг) payload = payload.subarray(varintСдвиг);
						if (!payload.byteLength) continue;
						if (isDnsQuery) {
							if (判断是否是木马) await 转发木马UDP数据(payload, grpcBridge, 木马UDP上下文, request);
							else await forwardataudp(payload, grpcBridge, null, request);
							continue;
						}
						if (remoteConnWrapper.socket || remoteConnWrapper.connectingPromise) {
							if (!(await 写入远端(payload))) throw new Error('Remote socket is not ready');
						} else {
							// P4.3: копим первый пакет и разбираем инкрементально.
							// Раньше здесь стояли неинкрементальные 解析木马请求 /
							// 解析魏烈思请求, а hasError превращался в исключение:
							// клиент, разбивший первый пакет по gRPC-кадрам, рвал
							// сессию вместо того, чтобы дождаться остатка.
							首包缓冲 = 累积首包(首包缓冲, payload);
							const 协议 = 判断首包协议(首包缓冲, yourUUID);
							if (协议 === 'need_more') continue;
							if (协议 === 'invalid') throw new Error('Invalid first packet');
							if (判断是否是木马 === null) 判断是否是木马 = 协议 === 'trojan';
							const 首包bytes = 首包缓冲;
							if (判断是否是木马) {
								const 解析结果 = 增量解析木马首包(首包bytes, yourUUID);
								if (解析结果.状态 === 'need_more') continue;
								if (解析结果.状态 === 'invalid') throw new Error('Invalid trojan request');
								// Инкрементальный разбор отдаёт rawData, а прежний
								// неинкрементальный — rawClientData.
								const { port, hostname, rawData, isUDP } = 解析结果.结果;
								log(`[gRPC] 木马首包: ${hostname}:${port} | UDP: ${isUDP ? '是' : '否'}`);
								if (isSpeedTestSite(hostname) && 反代上下文.代理类型 === null) {
									grpcBridge.send(构造本地204响应());
									return;
								}
								if (isUDP) {
									isDnsQuery = true;
									木马UDP上下文.目标主机 = hostname;
									木马UDP上下文.目标端口 = port;
									if (木马UDP上下文.反代地址) await 转发木马UDP数据(首包bytes, grpcBridge, 木马UDP上下文, request);
									else if (有效数据长度(rawData) > 0) await 转发木马UDP数据(rawData, grpcBridge, 木马UDP上下文, request);
								} else {
									await forwardataTCP({
										host: hostname,
										portNum: port,
										rawData: rawData,
										ws: grpcBridge,
										respHeader: null,
										remoteConnWrapper: remoteConnWrapper,
										yourUUID: yourUUID,
										request: request,
										反代上下文: 反代上下文,
										允许木马反代: true,
										木马反代首包数据: 首包bytes,
										仅建立连接: false,
										请求上下文: 请求上下文,
									});
							}
							} else {
								判断是否是木马 = false;
								const 解析结果 = 增量解析魏烈思首包(首包bytes, yourUUID);
								if (解析结果.状态 === 'need_more') continue;
								if (解析结果.状态 === 'invalid') throw new Error('Invalid 魏烈思 request');
								// respHeader разбор уже собрал сам; version отдельно
								// не нужен.
								const { port, hostname, isUDP, rawData, respHeader } = 解析结果.结果;
								log(`[gRPC] 魏烈思首包: ${hostname}:${port} | UDP: ${isUDP ? '是' : '否'}`);
								if (isSpeedTestSite(hostname) && 反代上下文.代理类型 === null) {
									grpcBridge.send(构造本地204响应(respHeader));
									return;
								}
								if (isUDP) {
									if (port !== 53) throw new Error('UDP is not supported');
									isDnsQuery = true;
								}
								grpcBridge.send(respHeader);
								if (isDnsQuery) {
									if (判断是否是木马) await 转发木马UDP数据(rawData, grpcBridge, 木马UDP上下文, request);
									else await forwardataudp(rawData, grpcBridge, null, request);
								}
								else await forwardataTCP({
									host: hostname,
									portNum: port,
									rawData: rawData,
									ws: grpcBridge,
									respHeader: null,
									remoteConnWrapper: remoteConnWrapper,
									yourUUID: yourUUID,
									request: request,
									反代上下文: 反代上下文,
									允许木马反代: false,
									木马反代首包数据: null,
									仅建立连接: false,
									请求上下文: 请求上下文,
									});
							}
						}
					}
					刷新发送队列();
				}
				await 远端写入门.队列.等待空();
			} catch (err) {
				转发失败 = true;
				log(`[gRPC转发] 处理失败: ${err?.message || err}`);
			} finally {
				const 保持木马UDP反代下行 = !转发失败 && isDnsQuery && 判断是否是木马 && 木马UDP上下文.反代地址 && 木马UDP上下文.反代Socket;
				if (保持木马UDP反代下行) {
					远端写入门.队列.清空();
					失效远端连接();
					远端写入门.释放();
					try { reader.releaseLock() } catch (e) { }
				} else {
					关闭连接();
				}
			}
		},
		cancel() {
			远端写入门?.队列.清空();
			失效远端连接();
			try { 木马UDP上下文.反代Socket?.close() } catch (e) { }
			try { reader.releaseLock() } catch (e) { }
		}
	}), { status: 200, headers: grpcHeaders });
}
