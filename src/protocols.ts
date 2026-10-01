// @ts-nocheck
// Фаза 3, Шаг 3.4: парсинг VLESS/Trojan/SS + SS-автоматы (чистые).
// from worker.ts — function-in-function, behavior preserved.
// Кэши (UUID字节缓存, SS主密钥缓存) — module-scope, живут до холодного старта.
//
// Шаг 3.4 (исправление 2026-09-30): 数据转Uint8Array ЗДЕСЬ НЕ БЫЛ ИМПОРТИРОВАН.
// Модуль собирался из вырезки worker.ts, где этот символ жил на уровне worker,
// поэтому локально он не был виден. Под @ts-nocheck и без единого теста на
// 解析木马请求/解析魏烈思请求 ошибка не проявлялась — и упала в проде на
// VLESS-over-WS: «数据转Uint8Array is not defined».
// Это прямой пример пробела §7b: транспортный слой не покрыт дифф-фикстурами.
import { 数据转Uint8Array, 拼接字节数据 } from "./util";

export const UUID字节缓存 = new Map();
export const 魏烈思文本解码器 = new TextDecoder();
export const 木马文本解码器 = new TextDecoder();
export function 解析木马请求(buffer, passwordPlainText) {
	const data = 数据转Uint8Array(buffer);
	const sha224Password = sha224(passwordPlainText);
	if (data.byteLength < 58) return { hasError: true, message: "invalid data" };
	let crLfIndex = 56;
	if (data[crLfIndex] !== 0x0d || data[crLfIndex + 1] !== 0x0a) return { hasError: true, message: "invalid header format" };
	for (let i = 0; i < crLfIndex; i++) {
		if (data[i] !== sha224Password.charCodeAt(i)) return { hasError: true, message: "invalid password" };
	}

	const socks5Index = crLfIndex + 2;
	if (data.byteLength < socks5Index + 6) return { hasError: true, message: "invalid S5 request data" };

	const cmd = data[socks5Index];
	if (cmd !== 1 && cmd !== 3) return { hasError: true, message: "unsupported command, only TCP/UDP is allowed" };
	const isUDP = cmd === 3;

	const atype = data[socks5Index + 1];
	let addressLength = 0;
	let addressIndex = socks5Index + 2;
	let address = "";
	switch (atype) {
		case 1: // IPv4
			addressLength = 4;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			address = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			break;
		case 3: // Domain
			if (data.byteLength < addressIndex + 1) return { hasError: true, message: "invalid S5 request data" };
			addressLength = data[addressIndex];
			addressIndex += 1;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			address = 木马文本解码器.decode(data.subarray(addressIndex, addressIndex + addressLength));
			break;
		case 4: // IPv6
			addressLength = 16;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const partIndex = addressIndex + i * 2;
				ipv6.push(((data[partIndex] << 8) | data[partIndex + 1]).toString(16));
			}
			address = ipv6.join(":");
			break;
		default:
			return { hasError: true, message: `invalid addressType is ${atype}` };
	}

	if (!address) {
		return { hasError: true, message: `address is empty, addressType is ${atype}` };
	}

	const portIndex = addressIndex + addressLength;
	if (data.byteLength < portIndex + 4) return { hasError: true, message: "invalid S5 request data" };
	const portRemote = (data[portIndex] << 8) | data[portIndex + 1];

	return {
		hasError: false,
		addressType: atype,
		port: portRemote,
		hostname: address,
		isUDP,
		rawClientData: data.subarray(portIndex + 4)
	};
}


export function 读取十六进制半字节(code) {
	if (code >= 48 && code <= 57) return code - 48;
	code |= 32;
	if (code >= 97 && code <= 102) return code - 87;
	return -1;
}
export function 获取UUID字节(uuid) {
	const key = String(uuid || '');
	let cached = UUID字节缓存.get(key);
	if (cached) return cached;

	const clean = key.replace(/-/g, '');
	if (clean.length !== 32) return null;

	const bytes = new Uint8Array(16);
	for (let i = 0; i < 16; i++) {
		const high = 读取十六进制半字节(clean.charCodeAt(i * 2));
		const low = 读取十六进制半字节(clean.charCodeAt(i * 2 + 1));
		if (high < 0 || low < 0) return null;
		bytes[i] = (high << 4) | low;
	}

	if (UUID字节缓存.size >= 32) UUID字节缓存.clear();
	UUID字节缓存.set(key, bytes);
	return bytes;
}

export function UUID字节匹配(data, offset, uuid) {
	const expected = 获取UUID字节(uuid);
	if (!expected || data.byteLength < offset + 16) return false;
	for (let i = 0; i < 16; i++) {
		if (data[offset + i] !== expected[i]) return false;
	}
	return true;
}
export function 解析魏烈思请求(chunk, token) {
	const data = 数据转Uint8Array(chunk);
	const length = data.byteLength;
	if (length < 24) return { hasError: true, message: 'Invalid data' };
	const version = data[0];
	if (!UUID字节匹配(data, 1, token)) return { hasError: true, message: 'Invalid uuid' };

	const optLen = data[17];
	const cmdIndex = 18 + optLen;
	if (length < cmdIndex + 4) return { hasError: true, message: 'Invalid data' };

	const cmd = data[cmdIndex];
	let isUDP = false;
	if (cmd === 1) { } else if (cmd === 2) { isUDP = true } else { return { hasError: true, message: 'Invalid command' } }

	const portIdx = cmdIndex + 1;
	const port = (data[portIdx] << 8) | data[portIdx + 1];
	let addrValIdx = portIdx + 3, addrLen = 0, hostname = '';
	const addressType = data[portIdx + 2];
	switch (addressType) {
		case 1:
			addrLen = 4;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv4 address length' };
			hostname = `${data[addrValIdx]}.${data[addrValIdx + 1]}.${data[addrValIdx + 2]}.${data[addrValIdx + 3]}`;
			break;
		case 2:
			if (length < addrValIdx + 1) return { hasError: true, message: 'Invalid domain length' };
			addrLen = data[addrValIdx];
			addrValIdx += 1;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid domain data' };
			hostname = 魏烈思文本解码器.decode(data.subarray(addrValIdx, addrValIdx + addrLen));
			break;
		case 3:
			addrLen = 16;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv6 address length' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addrValIdx + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			break;
		default:
			return { hasError: true, message: `Invalid address type: ${addressType}` };
	}
	if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
	const rawIndex = addrValIdx + addrLen;
	return { hasError: false, addressType, port, hostname, isUDP, rawClientData: data.subarray(rawIndex), version };
}
export const SS支持加密配置 = {
	'aes-128-gcm': { method: 'aes-128-gcm', keyLen: 16, saltLen: 16, maxChunk: 0x3fff, aesLength: 128 },
	'aes-256-gcm': { method: 'aes-256-gcm', keyLen: 32, saltLen: 32, maxChunk: 0x3fff, aesLength: 256 },
};

export const SSAEAD标签长度 = 16, SSNonce长度 = 12;
export const SS子密钥信息 = new TextEncoder().encode('ss-subkey');
export const SS文本编码器 = new TextEncoder(), SS文本解码器 = new TextDecoder(), SS主密钥缓存 = new Map();
export function SS递增Nonce计数器(counter) {
	for (let i = 0; i < counter.length; i++) { counter[i] = (counter[i] + 1) & 0xff; if (counter[i] !== 0) return }
}

export async function SS派生主密钥(passwordText, keyLen) {
	const cacheKey = `${keyLen}:${passwordText}`;
	if (SS主密钥缓存.has(cacheKey)) return SS主密钥缓存.get(cacheKey);
	const deriveTask = (async () => {
		const pwBytes = SS文本编码器.encode(passwordText || '');
		let prev = new Uint8Array(0), result = new Uint8Array(0);
		while (result.byteLength < keyLen) {
			const input = new Uint8Array(prev.byteLength + pwBytes.byteLength);
			input.set(prev, 0); input.set(pwBytes, prev.byteLength);
			prev = new Uint8Array(await crypto.subtle.digest('MD5', input));
			result = 拼接字节数据(result, prev);
		}
		return result.slice(0, keyLen);
	})();
	SS主密钥缓存.set(cacheKey, deriveTask);
	try { return await deriveTask }
	catch (error) { SS主密钥缓存.delete(cacheKey); throw error }
}

export async function SS派生会话密钥(config, masterKey, salt, usages) {
	const hmacOpts = { name: 'HMAC', hash: 'SHA-1' };
	const saltHmacKey = await crypto.subtle.importKey('raw', salt, hmacOpts, false, ['sign']);
	const prk = new Uint8Array(await crypto.subtle.sign('HMAC', saltHmacKey, masterKey));
	const prkHmacKey = await crypto.subtle.importKey('raw', prk, hmacOpts, false, ['sign']);
	const subKey = new Uint8Array(config.keyLen);
	let prev = new Uint8Array(0), written = 0, counter = 1;
	while (written < config.keyLen) {
		const input = 拼接字节数据(prev, SS子密钥信息, new Uint8Array([counter]));
		prev = new Uint8Array(await crypto.subtle.sign('HMAC', prkHmacKey, input));
		const copyLen = Math.min(prev.byteLength, config.keyLen - written);
		subKey.set(prev.subarray(0, copyLen), written);
		written += copyLen; counter += 1;
	}
	return crypto.subtle.importKey('raw', subKey, { name: 'AES-GCM', length: config.aesLength }, false, usages);
}

export async function SSAEAD加密(cryptoKey, nonceCounter, plaintext) {
	const iv = nonceCounter.slice();
	const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, plaintext);
	SS递增Nonce计数器(nonceCounter);
	return new Uint8Array(ct);
}

export async function SSAEAD解密(cryptoKey, nonceCounter, ciphertext) {
	const iv = nonceCounter.slice();
	const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, ciphertext);
	SS递增Nonce计数器(nonceCounter);
	return new Uint8Array(pt);
}
// P4.6: кэш sha224(密码) на изолят. Значение пароля не меняется в течение жизни
// воркера, а хеш считается на каждом входящем пакете Trojan и в двух местах
// (парсер протокола и детектор early-data). Ограничение по размеру — чтобы
// не расти при переборе разных значений.
const SHA224缓存 = new Map<string, string>();
const SHA224缓存上限 = 8;

export function sha224(s: string): string {
	const key = String(s ?? "");
	const cached = SHA224缓存.get(key);
	if (cached !== undefined) return cached;
	const value = sha224计算(key);
	if (SHA224缓存.size >= SHA224缓存上限) SHA224缓存.clear();
	SHA224缓存.set(key, value);
	return value;
}

function sha224计算(s: string): string {
	const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
	const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
	s = unescape(encodeURIComponent(s));
	const l = s.length * 8; s += String.fromCharCode(0x80);
	while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
	const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
	const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
	s += String.fromCharCode((hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF);
	const w = []; for (let i = 0; i < s.length; i += 4)w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3));
	for (let i = 0; i < w.length; i += 16) {
		const x = new Array(64).fill(0);
		for (let j = 0; j < 16; j++)x[j] = w[i + j];
		for (let j = 16; j < 64; j++) {
			const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
			const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
			x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
		}
		let [a, b, c, d, e, f, g, h0] = h;
		for (let j = 0; j < 64; j++) {
			const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
			const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
			h0 = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
		}
		for (let j = 0; j < 8; j++)h[j] = (h[j] + (j === 0 ? a : j === 1 ? b : j === 2 ? c : j === 3 ? d : j === 4 ? e : j === 5 ? f : j === 6 ? g : h0)) >>> 0;
	}
	let hex = '';
	for (let i = 0; i < 7; i++) {
		for (let j = 24; j >= 0; j -= 8)hex += ((h[i] >>> j) & 0xFF).toString(16).padStart(2, '0');
	}
	return hex;
}

// ── Единый инкрементальный разбор первого пакета (P4.2) ──────────────────────
//
// До этого было три реализации с разной семантикой:
//   * xhttp — инкрементальные 尝试解析魏烈思首包/尝试解析木马首包 прямо в
//     transport/handlers.ts, с корректным need_more;
//   * gRPC и WS — неинкрементальные 解析木马请求/解析魏烈思请求 отсюда же.
//     Они требуют ПЕРВЫЙ пакет целиком, поэтому фрагментированный первый пакет
//     давал ложный «Invalid data». Это скрытый баг, а не стилистика: клиент,
//     разбивший первый пакет, не подключался.
//
// Здесь единственная реализация, инкрементальная по построению. Результат —
// явная трёхзначная форма (P4.6): ok | need_more | invalid. Строка как признак
// состояния заменена полем 状态; проверка в вызывающем коде идёт по нему.
//
// need_more означает «данных ещё мало, добери буфер», invalid — «это не тот
// протокол или пакет битый», ok — 结果 содержит разобранное.

export function 增量解析魏烈思首包(data, token) {
	const length = data.byteLength;
	if (length < 18) return { 状态: 'need_more' };
	if (!UUID字节匹配(data, 1, token)) return { 状态: 'invalid' };

	const optLen = data[17];
	const cmdIndex = 18 + optLen;
	if (length < cmdIndex + 1) return { 状态: 'need_more' };

	const cmd = data[cmdIndex];
	if (cmd !== 1 && cmd !== 2) return { 状态: 'invalid' };

	const portIndex = cmdIndex + 1;
	if (length < portIndex + 3) return { 状态: 'need_more' };

	const port = (data[portIndex] << 8) | data[portIndex + 1];
	const addressType = data[portIndex + 2];
	const addressIndex = portIndex + 3;
	let headerLen = -1;
	let hostname = '';

	if (addressType === 1) {
		if (length < addressIndex + 4) return { 状态: 'need_more' };
		hostname = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
		headerLen = addressIndex + 4;
	} else if (addressType === 2) {
		if (length < addressIndex + 1) return { 状态: 'need_more' };
		const domainLen = data[addressIndex];
		if (length < addressIndex + 1 + domainLen) return { 状态: 'need_more' };
		hostname = 魏烈思文本解码器.decode(data.subarray(addressIndex + 1, addressIndex + 1 + domainLen));
		headerLen = addressIndex + 1 + domainLen;
	} else if (addressType === 3) {
		if (length < addressIndex + 16) return { 状态: 'need_more' };
		const ipv6 = [];
		for (let i = 0; i < 8; i++) {
			const base = addressIndex + i * 2;
			ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
		}
		hostname = ipv6.join(':');
		headerLen = addressIndex + 16;
	} else return { 状态: 'invalid' };

	if (!hostname) return { 状态: 'invalid' };

	return {
		状态: 'ok',
		结果: {
			协议: 'vl' + 'ess',
			hostname,
			port,
			isUDP: cmd === 2,
			rawData: data.subarray(headerLen),
			respHeader: new Uint8Array([data[0], 0]),
			原始数据: null,
		}
}
}

export function 增量解析木马首包(data, token) {
	const 密码哈希 = sha224(token);
	const 密码哈希字节 = SS文本编码器.encode(密码哈希);
	const length = data.byteLength;
	if (length < 58) return { 状态: 'need_more' };
	if (data[56] !== 0x0d || data[57] !== 0x0a) return { 状态: 'invalid' };
	for (let i = 0; i < 56; i++) {
		if (data[i] !== 密码哈希字节[i]) return { 状态: 'invalid' };
	}

	const socksStart = 58;
	if (length < socksStart + 2) return { 状态: 'need_more' };
	const cmd = data[socksStart];
	if (cmd !== 1 && cmd !== 3) return { 状态: 'invalid' };
	const isUDP = cmd === 3;

	const atype = data[socksStart + 1];
	let cursor = socksStart + 2;
	let hostname = '';

	if (atype === 1) {
		if (length < cursor + 4) return { 状态: 'need_more' };
		hostname = `${data[cursor]}.${data[cursor + 1]}.${data[cursor + 2]}.${data[cursor + 3]}`;
		cursor += 4;
	} else if (atype === 3) {
		if (length < cursor + 1) return { 状态: 'need_more' };
		const domainLen = data[cursor];
		if (length < cursor + 1 + domainLen) return { 状态: 'need_more' };
		hostname = 木马文本解码器.decode(data.subarray(cursor + 1, cursor + 1 + domainLen));
		cursor += 1 + domainLen;
	} else if (atype === 4) {
		if (length < cursor + 16) return { 状态: 'need_more' };
		const ipv6 = [];
		for (let i = 0; i < 8; i++) {
			const base = cursor + i * 2;
			ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
		}
		hostname = ipv6.join(':');
		cursor += 16;
	} else return { 状态: 'invalid' };

	if (!hostname) return { 状态: 'invalid' };
	if (length < cursor + 4) return { 状态: 'need_more' };

	const port = (data[cursor] << 8) | data[cursor + 1];
	if (data[cursor + 2] !== 0x0d || data[cursor + 3] !== 0x0a) return { 状态: 'invalid' };
	const dataOffset = cursor + 4;

	return {
		状态: 'ok',
		结果: {
			协议: 'trojan',
			hostname,
			port,
			isUDP,
			rawData: data.subarray(dataOffset),
			原始数据: data,
			respHeader: null,
		}
	};
};

/**
 * Дописывает очередной фрагмент к накопленному первому пакету.
 *
 * Инкрементальный разбор бесполезен без накопления: need_more означает «позови
 * ещё», и вызывающий обязан сохранить то, что уже есть, иначе следующий вызов
 * разберёт тот же обрывок и сессия застрянет навсегда.
 *
 * Первый пакет ограничен: клиент не пришлёт больше, чем поместится в один
 * разбор, поэтому рост здесь естественно ограничен размером первого пакета.
 */
export function 累积首包(已有, 新块) {
	const base = 已有 || new Uint8Array(0);
	const chunk = 数据转Uint8Array(新块);
	if (!chunk.byteLength) return base;
	const out = new Uint8Array(base.byteLength + chunk.byteLength);
	out.set(base, 0);
	out.set(chunk, base.byteLength);
	return out;
}

/**
 * Определяет протокол по началу первого пакета.
 *
 * Прежний признак — «длина ≥ 58 и байты 56..57 равны 0d 0a» — работает, только
 * если клиент прислал первый пакет целиком. При фрагментации первых 58 байт ещё
 * нет, и признак молча назвал бы троян-пакет 魏烈思-пакетом (58 не набралось =>
 * «не троян»), после чего разбор пошёл бы не по тому пути.
 *
 * Теперь решение принимает сам разбор, потому что заголовки разной длины:
 * 魏烈симу достаточно 18 байт до проверки UUID, трояну — 58. Отсюда порядок:
 *
 *   'vless'    — 魏烈си не отверг пакет: либо разобрал целиком, либо (при длине
 *                ≥ 18) уже сошёлся UUID и не хватает только адреса;
 *   'trojan'   — 魏烈си отверг пакет (значит, UUID не совпал), а троян либо
 *                разобран целиком, либо его заголовок ещё не дописан (< 58 байт).
 *                Отвергать рано: остаток придёт следующим кадром. Если это мусор,
 *                троянский разбор отвергнет его на 58-м байте — отказ будет,
 *                просто чуть позже;
 *   'invalid'  — оба заголовка дописаны и оба отвергли пакет;
 *   'need_more' — данных меньше 18, ни один разбор ещё не начался.
 *
 * Различать 'invalid' и 'need_more' обязательно: если бы оба случая сводились
 * к «жди», клиент с мусором получил бы висящую сессию вместо отказа.
 */
export function 判断首包协议(data, token) {
	if (data.byteLength < 18) return 'need_more';

	// Проверка UUID в 魏烈си идёт ДО проверки длины адреса. Поэтому need_more
	// при длине ≥ 18 означает, что UUID уже совпал, — это верный признак vless,
	// а не «данных мало». Троян-пакет сюда дойти не может: байты 1..16 у него
	// заняты hex-символами хеша пароля.
	const 魏烈思 = 增量解析魏烈思首包(data, token);
	if (魏烈思.状态 !== 'invalid') return 'vless';

	const 木马 = 增量解析木马首包(data, token);
	if (木马.状态 === 'ok') return 'trojan';
	// need_more здесь означает ровно «меньше 58 байт»: заголовок трояна не дописан.
	if (木马.状态 === 'need_more') return 'trojan';

	return 'invalid';
}
