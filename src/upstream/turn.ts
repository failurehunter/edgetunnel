// @ts-nocheck
// Фаза 3, шаг 3.3 был выполнен неверно (P0.2, найдено 2026-09-30): TURN/STUN
// в dns.ts переписаны, а не перенесены. createTurnStunMessage ждал {type,value}
// и оборачивал атрибуты повторно, тогда как вызывающий код передаёт уже готовые
// байтовые атрибуты; createTurnStunAttribute дописывал лишние setUint8(4/5),
// выходя за границу буфера при пустом теле атрибута.
//
// Здесь тела восстановлены ДОСЛОВНО из legacy/frozen.js (sha256 db916ec5…).
// Проверка: scripts/check-frozen-parity.mjs сравнивает каждое тело с эталоном.
//
// Лог → console: расхождение с эталоном только в этом, поведение не меняется
// (console.error пишет всегда, log — только при 调试日志打印). Поведенческий риск
// тот же, что и у остальных модулей после шага 3.1; отмечен для отдельной задачи.
import { 拼接字节数据, 数据转Uint8Array, 有效数据长度 } from "../util";
import { 创建日志器 } from "../logging";
const log = 创建日志器('turn');

export const CONNECT_TIMEOUT_MS = 9999;
export const TURN_STUN_MAGIC_COOKIE = new Uint8Array([0x21, 0x12, 0xa4, 0x42]);
export const TURN_STUN_TYPE = {
	ALLOCATE_REQUEST: 0x0003,
	ALLOCATE_SUCCESS: 0x0103,
	REFRESH_REQUEST: 0x0004,
	CREATE_PERMISSION_REQUEST: 0x0008,
	CREATE_PERMISSION_SUCCESS: 0x0108,
	CHANNEL_BIND_REQUEST: 0x0009,
	CHANNEL_BIND_SUCCESS: 0x0109,
	CONNECT_REQUEST: 0x000a,
	CONNECT_SUCCESS: 0x010a,
	CONNECTION_BIND_REQUEST: 0x000b,
	CONNECTION_BIND_SUCCESS: 0x010b,
};
export const TURN_STUN_ATTR = {
	MAPPED_ADDRESS: 0x0001,
	USERNAME: 0x0006,
	MESSAGE_INTEGRITY: 0x0008,
	ERROR_CODE: 0x0009,
	UNKNOWN_ATTRIBUTES: 0x000a,
	REALM: 0x0014,
	NONCE: 0x0015,
	XOR_RELAYED_ADDRESS: 0x0016,
	REQUESTED_TRANSPORT: 0x0019,
	XOR_MAPPED_ADDRESS: 0x0020,
	SOFTWARE: 0x8022,
	ALTERNATE_SERVER: 0x8023,
	FINGERPRINT: 0x8028,
	XOR_PEER_ADDRESS: 0x0012,
	DATA: 0x0013,
};

export function turnStunPadding(length) {
	return -length & 3;
}

export function createTurnStunAttribute(type, value) {
	const body = 数据转Uint8Array(value);
	const attribute = new Uint8Array(4 + body.byteLength + turnStunPadding(body.byteLength));
	const view = new DataView(attribute.buffer);
	view.setUint16(0, type);
	view.setUint16(2, body.byteLength);
	attribute.set(body, 4);
	return attribute;
}

export function createTurnStunMessage(type, transactionId, attributes) {
	const body = 拼接字节数据(...attributes);
	const header = new Uint8Array(20);
	const view = new DataView(header.buffer);
	view.setUint16(0, type);
	view.setUint16(2, body.byteLength);
	header.set(TURN_STUN_MAGIC_COOKIE, 4);
	header.set(transactionId, 8);
	return 拼接字节数据(header, body);
}

export async function readTurnStunMessage(reader, bufferedData = null, timeoutMessage = 'TURN response timed out') {
	let buffer = 有效数据长度(bufferedData) ? 数据转Uint8Array(bufferedData) : new Uint8Array(0);
	const pull = async () => {
		const { done, value } = await withTimeout(reader.read(), CONNECT_TIMEOUT_MS, timeoutMessage);
		if (done) throw new Error('TURN server closed connection');
		if (value?.byteLength) buffer = 拼接字节数据(buffer, value);
	};
	while (buffer.byteLength < 20) await pull();

	const messageLength = 20 + ((buffer[2] << 8) | buffer[3]);
	if (messageLength > 65555) throw new Error('TURN response is too large');
	while (buffer.byteLength < messageLength) await pull();
	const messageBuffer = buffer.subarray(0, messageLength);
	if (TURN_STUN_MAGIC_COOKIE.some((value, index) => messageBuffer[4 + index] !== value)) throw new Error('Invalid TURN/STUN response');

	const view = new DataView(messageBuffer.buffer, messageBuffer.byteOffset, messageBuffer.byteLength);
	let offset = 20;
	const attributes = {};
	while (offset + 4 <= messageLength) {
		const attrType = view.getUint16(offset);
		const attrLength = view.getUint16(offset + 2);
		const paddedLength = 4 + attrLength + turnStunPadding(attrLength);
		if (offset + paddedLength > messageLength) break;
		const attrValue = messageBuffer.subarray(offset + 4, offset + 4 + attrLength);
		if (attrType === TURN_STUN_ATTR.XOR_MAPPED_ADDRESS && attrValue.byteLength >= 8) {
			const port = view.getUint16(offset + 4 + 2) ^ 0x2112;
			let ip = '';
			for (let i = 0; i < 4; i++) ip += (view.getUint8(offset + 4 + 4 + i) ^ TURN_STUN_MAGIC_COOKIE[i]) + '.';
			attributes[attrType] = { ip: ip.slice(0, -1), port };
		} else if (attrType === TURN_STUN_ATTR.XOR_PEER_ADDRESS && attrValue.byteLength >= 8) {
			const port = view.getUint16(offset + 4 + 2) ^ 0x2112;
			let ip = '';
			for (let i = 0; i < 4; i++) ip += (view.getUint8(offset + 4 + 4 + i) ^ TURN_STUN_MAGIC_COOKIE[i]) + '.';
			attributes[attrType] = { ip: ip.slice(0, -1), port };
		} else {
			attributes[attrType] = attrValue;
		}
		offset += paddedLength;
	}
	return {
		message: { type: view.getUint16(0), attributes },
		extraData: buffer.byteLength > messageLength ? buffer.subarray(messageLength) : null
	};
}

export async function writeTurnBytes(writer, bytes, timeoutMessage) {
	await withTimeout(writer.write(bytes), CONNECT_TIMEOUT_MS, timeoutMessage);
}

export async function withTimeout(promise, timeoutMs, message) {
	let timer;
	try {
		return await Promise.race([
			promise,
			new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), timeoutMs) })
		]);
	} finally {
		clearTimeout(timer);
	}
}

export function parseTurnErrorCode(data) {
	return data?.byteLength >= 4 ? (data[2] & 7) * 100 + data[3] : 0;
}

export function randomTurnTransactionId() {
	return crypto.getRandomValues(new Uint8Array(12));
}

export async function addTurnMessageIntegrity(message, key) {
	const signedMessage = new Uint8Array(message);
	const view = new DataView(signedMessage.buffer);
	view.setUint16(2, view.getUint16(2) + 24);
	const hmacKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
	const signature = await crypto.subtle.sign('HMAC', hmacKey, signedMessage);
	return 拼接字节数据(signedMessage, createTurnStunAttribute(TURN_STUN_ATTR.MESSAGE_INTEGRITY, new Uint8Array(signature)));
}

void log;
