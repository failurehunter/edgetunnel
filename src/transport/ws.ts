// @ts-nocheck
// Фаза 4, пункт 3 (шаг 4): транспорт WebSocket.
//
// Раньше этот код жил в transport/handlers.ts вместе с двумя другими
// транспортами. Разнесено по одному файлу на транспорт: у каждого свои
// приватные хелперы, и общий файл только мешал читать ветку целиком.
// SS-сессия вынесена в transport/ss.ts, общая запись в апстрим — в
// transport/upstream-write.ts. Здесь только состояние WS-сокеты и разбор.
const log = (...args) => console.error('[ws]', ...args);
import { UUID字节匹配, sha224, 判断首包协议, 增量解析木马首包, 增量解析魏烈思首包, 累积首包, 解析木马请求, 魏烈思文本解码器 } from "../protocols";
import { 拼接字节数据, 数据转Uint8Array, 有效数据长度 } from "../util";
import { 上行队列最大字节, 上行队列最大条目 } from "./grain";
import { WebSocket发送并等待, closeSocketQuietly, forwardataTCP, 失效TCP连接世代 } from "./relay";
import { forwardataudp, isSpeedTestSite, 构造WS本地204响应, 转发木马UDP数据 } from "./shared";
import { 创建SS会话 } from "./ss";
import { 创建Upstream会话 } from "./upstream-session";
import { 创建远端写入门 } from "./upstream-write";

// Пределы WS-early-data. Раньше жили в worker.ts (строка 21); используются только
// здесь, поэтому переехали вместе с блоком диспетчеров.
const WS早期数据最大字节 = 8 * 1024, WS早期数据最大头长度 = Math.ceil(WS早期数据最大字节 * 4 / 3) + 4;


export function 是有效WS早期数据(bytes, token) {
	if (!bytes?.byteLength) return false;
	if (bytes.byteLength >= 18 && UUID字节匹配(bytes, 1, token)) return true;
	if (bytes.byteLength < 58 || bytes[56] !== 0x0d || bytes[57] !== 0x0a) return false;

	const trojanPassword = sha224(token);
	for (let i = 0; i < 56; i++) {
		if (bytes[i] !== trojanPassword.charCodeAt(i)) return false;
	}
	return true;
}

export function 解码WS早期数据(header, token) {
	if (!header) return null;
	if (header.length > WS早期数据最大头长度) throw new Error('early data is too large');

	let bytes;
	const Uint8ArrayBase64 = /** @type {any} */ (Uint8Array);
	if (typeof Uint8ArrayBase64.fromBase64 === 'function') {
		try {
			bytes = Uint8ArrayBase64.fromBase64(header, { alphabet: 'base64url' });
		} catch (_) { }
	}
	if (!bytes) {
		let normalized = header.replace(/-/g, '+').replace(/_/g, '/');
		const padding = normalized.length % 4;
		if (padding) normalized += '='.repeat(4 - padding);
		let binaryString;
		try {
			binaryString = atob(normalized);
		} catch (_) {
			return null;
		}
		bytes = new Uint8Array(binaryString.length);
		for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
	}

	if (bytes.byteLength > WS早期数据最大字节) throw new Error('early data is too large');
	return 是有效WS早期数据(bytes, token) ? bytes : null;
}

///////////////////////////////////////////////////////////////////////WS传输数据///////////////////////////////////////////////
export async function 处理WS请求(request, yourUUID, url, 反代上下文 = {}, 请求上下文 = null) {
	const WS套接字对 = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(WS套接字对);
	try { (/** @type {any} */ (serverSock)).accept({ allowHalfOpen: true }) }
	catch (_) { serverSock.accept() }
	serverSock.binaryType = 'arraybuffer';
	let remoteConnWrapper = 创建Upstream会话(); // P4.1: явная сессия, владелец сокета
	const 失效远端连接 = () => 失效TCP连接世代(remoteConnWrapper);
	let isDnsQuery = false;
	let 判断是否是木马 = null;
	const 木马UDP上下文 = { 缓存: new Uint8Array(0), 反代地址: 反代上下文.木马反代地址 };
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	const SS模式禁用EarlyData = !!url.searchParams.get('enc');
	let WS显式传输链 = Promise.resolve();
	let WS显式传输停止接收 = false, WS显式传输失败 = false, WS显式传输收尾已入队 = false;
	let WS显式队列字节 = 0, WS显式队列条目 = 0;
	let 判断协议类型 = null;
	// P4.3: накопленный первый пакет. Прежде он жил как `let 当前块字节` внутри
	// 处理WS入站数据, а значит обнулялся на каждом WS-кадре: каждый кадр
	// переразбирал один и тот же обрывок, и разорванный первый пакет не доезжал
	// никогда — сессия навсегда оставалась в need_more.
	let 当前块字节 = null;
	let WS本地测速模式 = false, WS本地测速回包Socket = null;
	let WS本地测速请求缓存 = new Uint8Array(0);
	let WS本地测速首包响应头 = null;
	const WS本地测速请求上限 = 64 * 1024;

	const 发送WS本地测速响应 = async () => {
		if (!WS本地测速回包Socket) return;
		const respHeader = WS本地测速首包响应头;
		WS本地测速首包响应头 = null;
		await WebSocket发送并等待(WS本地测速回包Socket, 构造WS本地204响应(respHeader));
	};

	const 查找HTTP请求头结尾 = (data) => {
		for (let i = 0; i <= data.byteLength - 4; i++) {
			if (data[i] === 0x0d && data[i + 1] === 0x0a && data[i + 2] === 0x0d && data[i + 3] === 0x0a) return i + 4;
		}
		return -1;
	};

	const 处理WS本地测速数据 = async (data) => {
		const chunk = 数据转Uint8Array(data);
		if (!chunk.byteLength) return;
		if (WS本地测速请求缓存.byteLength + chunk.byteLength > WS本地测速请求上限) throw new Error('WS local speed-test request is too large');
		WS本地测速请求缓存 = 拼接字节数据(WS本地测速请求缓存, chunk);

		while (WS本地测速请求缓存.byteLength) {
			const headerEnd = 查找HTTP请求头结尾(WS本地测速请求缓存);
			if (headerEnd === -1) return;
			const headerText = 魏烈思文本解码器.decode(WS本地测速请求缓存.subarray(0, headerEnd));
			const contentLengthMatch = headerText.match(/(?:^|\r\n)content-length\s*:\s*(\d+)/i);
			const contentLength = contentLengthMatch ? Number(contentLengthMatch[1]) : 0;
			const requestLength = headerEnd + contentLength;
			if (!Number.isSafeInteger(contentLength) || requestLength > WS本地测速请求上限) throw new Error('WS local speed-test request body is too large');
			if (WS本地测速请求缓存.byteLength < requestLength) return;
			WS本地测速请求缓存 = WS本地测速请求缓存.slice(requestLength);
			await 发送WS本地测速响应();
		}
	};

	const 启用WS本地测速模式 = async (回包Socket, respHeader = null, 首请求数据 = null) => {
		WS本地测速模式 = true;
		WS本地测速回包Socket = 回包Socket;
		WS本地测速请求缓存 = new Uint8Array(0);
		WS本地测速首包响应头 = respHeader;
		if (有效数据长度(首请求数据) > 0) await 处理WS本地测速数据(首请求数据);
	};

	// P4.3: тот же общий «запись в апстрим», что и у gRPC. Различие — в выборе
	// 写入 (WS не ждёт флаша) против 写入并等待 (gRPC обязан убедиться, что кадр
	// ушёл), и в обработчике закрытия.
	const 远端写入门 = 创建远端写入门({
		remoteConnWrapper,
		关闭连接: err => 处理WS显式传输错误(err),
		名称: 'WS上行',
	});

	const 写入远端 = 远端写入门.写入;

	// P4.3: SS-сессия вынесена в transport/ss.ts. Адаптер передаёт ей свои хуки:
	// запись в апстрим и режим локального speed-test — они принадлежат транспорту,
	// но SS-сессия обязана их использовать (иначе первый SS-кадр ушёл бы мимо
	// очереди и апстрим не увидел бы адреса назначения).
	const { 处理SS数据 } = 创建SS会话({
		serverSock, remoteConnWrapper, yourUUID, url, 反代上下文, 请求上下文, request,
		写入远端, WS本地测速模式, 处理WS本地测速数据, 启用WS本地测速模式,
	});

	const 处理WS入站数据 = async (chunk) => {
		if (isDnsQuery) {
			if (判断是否是木马) return await 转发木马UDP数据(chunk, serverSock, 木马UDP上下文, request);
			return await forwardataudp(chunk, serverSock, null, request);
		}
		if (判断协议类型 === 'ss') {
			await 处理SS数据(chunk);
			return;
		}
		if (WS本地测速模式) {
			await 处理WS本地测速数据(chunk);
			return;
		}
		if (await 写入远端(chunk)) return;

		// P4.3: копим первый пакет ровно один раз на кадр — до обоих разборов,
		// иначе фрагмент попал бы в буфер дважды. Для SS-сессии не копим: там
		// первый пакет обрабатывает 创建SS会话 своими средствами.
		if (判断协议类型 !== 'ss') 当前块字节 = 累积首包(当前块字节, chunk);

		if (判断协议类型 === null) {
			if (url.searchParams.get('enc')) 判断协议类型 = 'ss';
			else {
				// P4.3: протокол определяет разбор, а не длина первого кадра.
				// Прежний признак «длина ≥ 58 и 0d 0a на 56..57» на фрагменте
				// троян-пакета срабатывал в обратную сторону: 58 не набралось =>
				// «не троян», и разбор уходил не туда.
				const 协议 = 判断首包协议(当前块字节, yourUUID);
				if (协议 === 'need_more') return;
				if (协议 === 'invalid') throw new Error('Invalid first packet');
				判断协议类型 = 协议 === 'trojan' ? '木马' : '魏烈思';
			}
			判断是否是木马 = 判断协议类型 === '木马';
			log(`[WS转发] 协议类型: ${判断协议类型} | 来自: ${url.host} | UA: ${request.headers.get('user-agent') || '未知'}`);
		}

		if (判断协议类型 === 'ss') {
			await 处理SS数据(chunk);
			return;
		}
		if (await 写入远端(chunk)) return;
		if (判断协议类型 === '木马') {
			// P4.2: разбор инкрементальный. Раньше звался 解析木马请求(chunk) на
			// сыром чанке, поэтому клиент, разбивший первый пакет, получал
			// «Invalid trojan request» вместо ожидания остатка.
			// P4.3: буфер теперь копится (см. выше), иначе need_more был вечным.
			const 解析结果 = 增量解析木马首包(当前块字节, yourUUID);
			if (解析结果.状态 === 'need_more') return;
			if (解析结果.状态 === 'invalid') throw new Error('Invalid trojan request');
			const { port, hostname, isUDP } = 解析结果.结果;
			const rawClientData = 解析结果.结果.rawData;
			if (isSpeedTestSite(hostname) && 反代上下文.代理类型 === null) {
				await 启用WS本地测速模式(serverSock, null, rawClientData);
				return;
			}
			if (isUDP) {
				isDnsQuery = true;
				木马UDP上下文.目标主机 = hostname;
				木马UDP上下文.目标端口 = port;
				if (木马UDP上下文.反代地址) return 转发木马UDP数据(当前块字节 || 数据转Uint8Array(chunk), serverSock, 木马UDP上下文, request);
				if (有效数据长度(rawClientData) > 0) return 转发木马UDP数据(rawClientData, serverSock, 木马UDP上下文, request);
				return;
			}
			await forwardataTCP({
				host: hostname,
				portNum: port,
				rawData: rawClientData,
				ws: serverSock,
				respHeader: null,
				remoteConnWrapper: remoteConnWrapper,
				yourUUID: yourUUID,
				request: request,
				反代上下文: 反代上下文,
				允许木马反代: true,
				木马反代首包数据: 当前块字节 || 数据转Uint8Array(chunk),
				仅建立连接: false,
				请求上下文: 请求上下文,
				});
		} else {
			判断是否是木马 = false;
			// P4.2: тот же инкрементальный разбор вместо неинкрементального.
			const 解析结果 = 增量解析魏烈思首包(当前块字节, yourUUID);
			if (解析结果.状态 === 'need_more') return;
			if (解析结果.状态 === 'invalid') throw new Error('Invalid 魏烈思 request');
			const { port, hostname, isUDP } = 解析结果.结果;
			const rawClientData = 解析结果.结果.rawData;
			const respHeader = 解析结果.结果.respHeader;
			if (isSpeedTestSite(hostname) && 反代上下文.代理类型 === null) {
				await 启用WS本地测速模式(serverSock, respHeader, rawClientData);
				return;
			}
			if (isUDP) {
				if (port === 53) isDnsQuery = true;
				else throw new Error('UDP is not supported');
			}
			const rawData = rawClientData;
			if (isDnsQuery) {
				if (判断是否是木马) return 转发木马UDP数据(rawData, serverSock, 木马UDP上下文, request);
				return forwardataudp(rawData, serverSock, respHeader, request);
			}
			await forwardataTCP({
				host: hostname,
				portNum: port,
				rawData: rawData,
				ws: serverSock,
				respHeader: respHeader,
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
	};

	const 处理WS显式传输错误 = (err) => {
		if (WS显式传输失败) return;
		WS显式传输失败 = true;
		WS显式传输停止接收 = true;
		WS显式队列字节 = 0;
		WS显式队列条目 = 0;
		const msg = err?.message || `${err}`;
		if (msg.includes('Network connection lost') || msg.includes('ReadableStream is closed')) {
			log(`[WS转发] 连接结束: ${msg}`);
		} else {
			log(`[WS转发] 处理失败: ${msg}`);
		}
		远端写入门.队列.清空();
		远端写入门.释放();
		失效远端连接();
		try { 木马UDP上下文.反代Socket?.close() } catch (e) { }
		closeSocketQuietly(serverSock);
	};

	const 追加WS显式传输任务 = (任务) => {
		WS显式传输链 = WS显式传输链.then(任务).catch(处理WS显式传输错误);
		return WS显式传输链;
	};

	const 入队WS显式传输 = (data) => {
		if (WS显式传输停止接收 || WS显式传输失败) return;
		const chunkSize = Math.max(0, 有效数据长度(data));
		const nextBytes = WS显式队列字节 + chunkSize;
		const nextItems = WS显式队列条目 + 1;
		if (nextBytes > 上行队列最大字节 || nextItems > 上行队列最大条目) {
			处理WS显式传输错误(new Error(`[WS显式传输] 队列溢出: ${nextBytes}B/${nextItems}`));
			return;
		}
		WS显式队列字节 = nextBytes;
		WS显式队列条目 = nextItems;
		追加WS显式传输任务(async () => {
			WS显式队列字节 = Math.max(0, WS显式队列字节 - chunkSize);
			WS显式队列条目 = Math.max(0, WS显式队列条目 - 1);
			if (WS显式传输失败) return;
			await 处理WS入站数据(data);
		});
	};

	const 收尾WS显式传输 = () => {
		if (WS显式传输收尾已入队) return;
		WS显式传输收尾已入队 = true;
		WS显式传输停止接收 = true;
		追加WS显式传输任务(async () => {
			if (WS显式传输失败) return;
			await 远端写入门.队列.等待空();
			远端写入门.释放();
			失效远端连接();
			try { 木马UDP上下文.反代Socket?.close() } catch (e) { }
		});
	};

	serverSock.addEventListener('message', (event) => {
		入队WS显式传输(event.data);
	});
	serverSock.addEventListener('close', () => {
		closeSocketQuietly(serverSock);
		收尾WS显式传输();
	});
	serverSock.addEventListener('error', (err) => {
		处理WS显式传输错误(err);
	});

	// SS 模式下禁用 sec-websocket-protocol early-data，避免把子协议值（如 "binary"）误当作 base64 数据注入首包导致 AEAD 解密失败。
	if (!SS模式禁用EarlyData && earlyDataHeader) {
		try {
			const bytes = 解码WS早期数据(earlyDataHeader, yourUUID);
			if (bytes?.byteLength) 入队WS显式传输(bytes.buffer);
		} catch (error) {
			处理WS显式传输错误(error);
		}
	}

	return new Response(null, { status: 101, webSocket: clientSock, headers: { 'Sec-WebSocket-Extensions': '' } });
}
