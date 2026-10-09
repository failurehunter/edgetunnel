// @ts-nocheck
// Фаза 3, Шаг 3.9: shared — UDP-релей (в т.ч. Trojan) и speed-test-204.
// from worker.ts — function-in-function, behavior preserved.
// Лог → console (telemetry остаётся шагом 11).

import { 拼接字节数据, 数据转Uint8Array, 有效数据长度 } from "../util";
import { 创建请求TCP连接器, 连接木马反代 } from "../upstream/dial";
import { WebSocket发送并等待, closeSocketQuietly, connectStreams } from "./relay";
import { 创建日志器 } from "../logging";
const log = 创建日志器('shared');

export async function 转发木马UDP反代数据(chunk, webSocket, 上下文, request) {
	const data = 数据转Uint8Array(chunk);
	if (!上下文.反代Socket) {
		const TCP连接 = 创建请求TCP连接器(request);
		const socket = await 连接木马反代(data, TCP连接, 上下文.反代地址);
		上下文.反代Socket = socket;
		socket.closed.catch(() => { }).finally(() => closeSocketQuietly(webSocket));
		connectStreams(socket, webSocket, null, null);
		return;
	}
	if (!data.byteLength) return;
	const writer = 上下文.反代Socket.writable.getWriter();
	try { await writer.write(data) }
	finally { try { writer.releaseLock() } catch (e) { } }
}

export async function 转发木马UDP数据(chunk, webSocket, 上下文, request) {
	const 当前块 = 数据转Uint8Array(chunk);
	if (上下文?.反代地址) return 转发木马UDP反代数据(当前块, webSocket, 上下文, request);
	const 缓存块 = 上下文?.缓存 instanceof Uint8Array ? 上下文.缓存 : new Uint8Array(0);
	const input = 缓存块.byteLength ? 拼接字节数据(缓存块, 当前块) : 当前块;
	let cursor = 0;

	while (cursor < input.byteLength) {
		const packetStart = cursor;
		const atype = input[cursor];
		let addrCursor = cursor + 1;
		let addrLen = 0;
		if (atype === 1) addrLen = 4;
		else if (atype === 4) addrLen = 16;
		else if (atype === 3) {
			if (input.byteLength < addrCursor + 1) break;
			addrLen = 1 + input[addrCursor];
		} else throw new Error(`invalid trojan udp addressType: ${atype}`);

		const portCursor = addrCursor + addrLen;
		if (input.byteLength < portCursor + 6) break;

		const port = (input[portCursor] << 8) | input[portCursor + 1];
		const payloadLength = (input[portCursor + 2] << 8) | input[portCursor + 3];
		if (input[portCursor + 4] !== 0x0d || input[portCursor + 5] !== 0x0a) throw new Error('invalid trojan udp delimiter');

		const payloadStart = portCursor + 6;
		const payloadEnd = payloadStart + payloadLength;
		if (input.byteLength < payloadEnd) break;

		const 地址端口头 = input.slice(packetStart, portCursor + 2);
		const payload = input.slice(payloadStart, payloadEnd);
		cursor = payloadEnd;

		if (port !== 53) throw new Error('UDP is not supported');
		if (!payload.byteLength) continue;

		let tcpDNS查询 = payload;
		if (payload.byteLength < 2 || ((payload[0] << 8) | payload[1]) !== payload.byteLength - 2) {
			tcpDNS查询 = new Uint8Array(payload.byteLength + 2);
			tcpDNS查询[0] = (payload.byteLength >>> 8) & 0xff;
			tcpDNS查询[1] = payload.byteLength & 0xff;
			tcpDNS查询.set(payload, 2);
		}

		const dns响应上下文 = { 缓存: new Uint8Array(0) };
		await forwardataudp(tcpDNS查询, webSocket, null, request, (dnsRespChunk) => {
			const 当前响应块 = 数据转Uint8Array(dnsRespChunk);
			const 响应输入 = dns响应上下文.缓存.byteLength ? 拼接字节数据(dns响应上下文.缓存, 当前响应块) : 当前响应块;
			const 响应帧列表 = [];
			let responseCursor = 0;
			while (responseCursor + 2 <= 响应输入.byteLength) {
				const dnsLen = (响应输入[responseCursor] << 8) | 响应输入[responseCursor + 1];
				const dnsStart = responseCursor + 2;
				const dnsEnd = dnsStart + dnsLen;
				if (dnsEnd > 响应输入.byteLength) break;
				const dnsPayload = 响应输入.slice(dnsStart, dnsEnd);
				const frame = new Uint8Array(地址端口头.byteLength + 4 + dnsPayload.byteLength);
				frame.set(地址端口头, 0);
				frame[地址端口头.byteLength] = (dnsPayload.byteLength >>> 8) & 0xff;
				frame[地址端口头.byteLength + 1] = dnsPayload.byteLength & 0xff;
				frame[地址端口头.byteLength + 2] = 0x0d;
				frame[地址端口头.byteLength + 3] = 0x0a;
				frame.set(dnsPayload, 地址端口头.byteLength + 4);
				响应帧列表.push(frame);
				responseCursor = dnsEnd;
			}
			dns响应上下文.缓存 = 响应输入.slice(responseCursor);
			return 响应帧列表.length ? 响应帧列表 : new Uint8Array(0);
		}, 上下文?.dns目标);
	}

	if (上下文) 上下文.缓存 = input.slice(cursor);
}

/** Цель по умолчанию — как было зашито в монолите. */
/**
 * Получен ли ответ DNS-over-TCP целиком.
 * Формат: двухбайтная длина, затем столько же байт сообщения (RFC 7766).
 * Пока заголовок не прочитан целиком или данных меньше объявленной длины —
 * ответ неполон и читать надо дальше.
 */
function DNS响应Полон(накоплено) {
	if (!накоплено || накоплено.byteLength < 2) return false;
	const длина = (накоплено[0] << 8) | накоплено[1];
	return накоплено.byteLength >= 2 + длина;
}

/** Цель по умолчанию — как было зашито в монолите. */
const DNS_目标ПоУмолчанию = { hostname: '8.8.4.4', port: 53 };
/** Таймаут DNS-запроса, мс. Раньше ожидания не было вовсе. */
const DNS_ТаймаутПоУмолчанию = 5000;

/**
 * Запрос DNS пересылается по TCP.
 *
 * Параметр 目标 приходит из 请求上下文.settings.dnsTarget: резолвер разбирается
 * один раз на запрос в parseSettings. Здесь только подстановка значения по
 * умолчанию — иначе настройка из окружения не дошла бы сюда вовсе.
 */
export async function forwardataudp(udpChunk, webSocket, respHeader, request, 响应封装器 = null, 目标 = null) {
	const 请求数据 = 数据转Uint8Array(udpChunk);
	const 请求字节数 = 请求数据.byteLength;
	目标 = 目标 && 目标.hostname ? 目标 : DNS_目标ПоУмолчанию;
	log.信息(`[UDP转发] 收到 DNS 请求: ${请求字节数}B -> ${目标.hostname}:${目标.port}`);
	// P1.5: раньше ожидания не было вовсе, а pipeTo ждёт закрытия удалённой
	// стороны, которого DNS-сервер не делает. По истечении таймаута рвём поток и
	// закрываем сокет, иначе запрос блокирует все следующие в сессии.
	let 当前DNSсокет = null;
	const 中止 = new AbortController();
	const 定时器 = setTimeout(() => 中止.abort(new Error('DNS 请求超时')), DNS_ТаймаутПоУмолчанию);
	try {
		const TCP连接 = 创建请求TCP连接器(request);
		当前DNSсокет = TCP连接({ hostname: 目标.hostname, port: 目标.port });
		const tcpSocket = 当前DNSсокет;
		let 魏烈思Header = respHeader;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(请求数据);
		log.信息(`[UDP转发] DNS 请求已写入上游: ${请求字节数}B`);
		writer.releaseLock();
		// P1.5: читаем сами, а не через pipeTo. pipeTo завершается только вместе
		// с удалённой стороной, а DNS-сервер соединение держит открытым: запрос
		// занимал сокет до таймаута оператора и блокировал следующие запросы
		// сессии. Условие завершения известно точно — двухбайтная длина ответа.
		const 读取器 = tcpSocket.readable.getReader();
		let накоплено = new Uint8Array(0);
		// P18: ровно один долгоживущий read(), без гонки с таймером. Раньше гонка
		// read() c 250мс-таймером оставляла проигравший read() висеть, а следующий
		// read() на том же reader — конкурентное чтение (по спеке повторный read
		// при незавершённом бросает TypeError). Таймаут будит pending read через
		// cancel(причина): reader всегда в одном состоянии, лишних висящих read()
		// на каждой тишине не остаётся (P1.9: и таймеров опроса тоже — отменяет
		// ровно тот, что ждём).
		const 取消读取 = () => { try { 读取器.cancel(中止.reason) } catch (e) { } };
		中止.signal.addEventListener('abort', 取消读取, { once: true });
		while (true) {
			if (中止.signal.aborted) break;
			let поступило;
			try {
				поступило = await 读取器.read();
			} catch (err) {
				// cancel() по таймауту селит pending read — штатный выход, не поломка.
				if (中止.signal.aborted) break;
				throw err;
			}
			if (поступило.done) break;
			const кусок = 数据转Uint8Array(поступило.value);
			log.信息(`[UDP转发] 收到 DNS 响应: ${кусок.byteLength}B`);
			const 封装结果 = 响应封装器 ? await 响应封装器(кусок) : кусок;
			const 发送片段列表 = Array.isArray(封装结果) ? 封装结果 : [封装结果];
			if (发送片段列表.length && webSocket.readyState === WebSocket.OPEN) {
				for (const fragment of 发送片段列表) {
					const 转发响应 = 数据转Uint8Array(fragment);
					if (!转发响应.byteLength) continue;
					if (魏烈思Header) {
						const response = new Uint8Array(魏烈思Header.length + 转发响应.byteLength);
						response.set(魏烈思Header, 0);
						response.set(转发响应, 魏烈思Header.length);
						await WebSocket发送并等待(webSocket, response.buffer);
						魏烈思Header = null;
					} else {
						await WebSocket发送并等待(webSocket, 转发响应);
					}
				}
			}
			// Ответ получен целиком? Тогда сокет закрываем в finally, а не ждём.
			накоплено = накоплено.byteLength
				? 拼接字节数据(накоплено, кусок)
				: кусок;
			if (DNS响应Полон(накоплено)) break;
		}
		try { 读取器.releaseLock(); } catch (e) { }
	} catch (error) {
		// Прерывание по таймауту — не поломка: сокет закрыт ниже, ответ не пришёл.
		if (中止.signal.aborted) log.错误(`[UDP转发] DNS 转发 не получил ответа за ${DNS_ТаймаутПоУмолчанию}ms`);
		else log.错误(`[UDP转发] DNS 转发失败: ${error?.message || error}`);
	} finally {
		// Таймер снимаем всегда, иначе он держит выполнение до конца запроса.
		clearTimeout(定时器);
		// P1.5: сокет закрываем явно. Раньше close() не вызывался вовсе, и сокет
		// жил до закрытия удалённой стороны — то есть практически навсегда.
		try { 当前DNSсокет?.close?.(); } catch (e) { }
	}
}


export function isSpeedTestSite(hostname) {
	const speedTestDomains = ['speed.cloudflare.com', 'cp.cloudflare.com'];
	hostname = hostname.toLowerCase();
	return speedTestDomains.some(domain => hostname === domain || hostname.endsWith('.' + domain));
}

export function 构造本地204响应(respHeader = null) {
	const 本地204响应 = new TextEncoder().encode(
		'HTTP/1.1 204 No Content\r\n' +
		'Content-Length: 0\r\n' +
		'Connection: close\r\n' +
		'\r\n'
	);
	if (有效数据长度(respHeader) === 0) return 本地204响应;
	const 协议响应头 = 数据转Uint8Array(respHeader);
	const response = new Uint8Array(协议响应头.byteLength + 本地204响应.byteLength);
	response.set(协议响应头, 0);
	response.set(本地204响应, 协议响应头.byteLength);
	log.信息(`[TCP转发] 构造本地204响应: ${response.byteLength}B`);
	return response;
}

export function 构造WS本地204响应(respHeader = null) {
	const WS本地204响应 = new TextEncoder().encode(
		'HTTP/1.1 204 No Content\r\n' +
		'Content-Length: 0\r\n' +
		'Connection: keep-alive\r\n' +
		'\r\n'
	);
	if (有效数据长度(respHeader) === 0) return WS本地204响应;
	const 协议响应头 = 数据转Uint8Array(respHeader);
	const response = new Uint8Array(协议响应头.byteLength + WS本地204响应.byteLength);
	response.set(协议响应头, 0);
	response.set(WS本地204响应, 协议响应头.byteLength);
	return response;
}
