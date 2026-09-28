// @ts-nocheck
// Фаза 3, Шаг 3.14: admin.ts — uuidRegex, выдача/проверка auth-cookie, check-proxy.
//
// План §Детали, шаг 14: «cookie issue/verify, `uuidRegex`, admin-роуты, check-proxy
// (`MD5MD5` — в util)». ВЫНОСЕНЫ примитивы и check-proxy; сам диспетчер admin-роутов
// остаётся в worker.ts — это цепочка if/else внутри fetch на 500 строк, её разрыв
// менял бы порядок проверок доступа.
//
// БЕЗОПАСНОСТЬ (план §7, «не молчать»):
//   * Сравнение пароля админки — обычный `===`, НЕ constant-time. Оставлено как есть
//     намеренно (это рефакторинг, не аудит); зафиксировано здесь. План: «осознанно
//     оставляется как есть в этой миграции (не менять)».
//   * Токен cookie — MD5(UA + KEY + 管理员密码). План §7: заменить на HMAC-SHA256,
//     не блокируя миграцию, но зафиксировав в issue-трекере. Здесь переносится
//     без изменений.

import { MD5MD5, isIPHostname, 拼接字节数据 } from "./util";
import {
	获取SOCKS5账号,
	获取代理默认端口,
	创建请求TCP连接器,
	socks5Connect,
	httpConnect,
	httpsConnect,
	turnConnect,
	sstpConnect,
} from "./upstream/dial";
import { TlsClient } from "./tls";

// UUID v4 с корректным вариантом ([89abAB]) — как в монолите.
export const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;

/** Значение auth-cookie. MD5 используется как в монолите (см. security-notes). */
export function 计算AuthCookie(UA, 加密秘钥, 管理员密码) {
	return MD5MD5(UA + 加密秘钥 + 管理员密码);
}

/** Строка Set-Cookie для выдачи после успешного логина. */
export async function 签发AuthCookie(UA, 加密秘钥, 管理员密码) {
	return `auth=${await 计算AuthCookie(UA, 加密秘钥, 管理员密码)}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Lax`;
}

/** Достаёт значение auth= из заголовка Cookie. */
export function 读取AuthCookie(cookies) {
	return cookies.split(";").find(c => c.trim().startsWith("auth="))?.split("=")[1];
}

/**
 * Сверка пароля админки.
 * ВНИМАНИЕ: `===` — не constant-time (план §7, оставлено намеренно).
 * Ожидаемое значение дополнительно очищается от CR/LF, как в монолите.
 */
export function 校验管理密码(输入密码, 管理员密码) {
	return 输入密码 === (typeof 管理员密码 === "string" ? 管理员密码.replace(/[\r\n]/g, "") : 管理员密码);
}

// admin/check: подключиться через указанный прокси к cloudflare.com и прочитать
// /cdn-cgi/trace. Тело перенесено из fetch-обработчика (строки 170-236 монолита).
export async function checkProxy(url, request) {
const 代理协议 = ['socks5', 'http', 'https', 'turn', 'sstp'].find(类型 => url.searchParams.has(类型)) || null;
if (!代理协议) return new Response(JSON.stringify({ error: '缺少代理参数' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
const 代理参数 = url.searchParams.get(代理协议);
const startTime = Date.now();
let 检测代理响应;
try {
	const checkParsed = await 获取SOCKS5账号(代理参数, 获取代理默认端口(代理协议));
	const { username, password, hostname, port } = checkParsed;
	const 完整代理参数 = username && password ? `${username}:${password}@${hostname}:${port}` : `${hostname}:${port}`;
	try {
		const 检测主机 = 'cloudflare.com', 检测端口 = 443, encoder = new TextEncoder(), decoder = new TextDecoder();
		const TCP连接 = 创建请求TCP连接器(request);
		let tcpSocket = null, tlsSocket = null;
		try {
			tcpSocket = 代理协议 === 'socks5'
				? await socks5Connect(检测主机, 检测端口, new Uint8Array(0), TCP连接, checkParsed)
				: 代理协议 === 'turn'
					? await turnConnect(checkParsed, 检测主机, 检测端口, TCP连接)
					: 代理协议 === 'sstp'
						? await sstpConnect(checkParsed, 检测主机, 检测端口, TCP连接)
						: (代理协议 === 'https' && isIPHostname(hostname)
							? await httpsConnect(检测主机, 检测端口, new Uint8Array(0), TCP连接, checkParsed)
							: await httpConnect(检测主机, 检测端口, new Uint8Array(0), 代理协议 === 'https', TCP连接, checkParsed));
			if (!tcpSocket) throw new Error('无法连接到代理服务器');
			tlsSocket = new TlsClient(tcpSocket, { serverName: 检测主机, insecure: true });
			await tlsSocket.handshake();
			await tlsSocket.write(encoder.encode(`GET /cdn-cgi/trace HTTP/1.1\r\nHost: ${检测主机}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`));
			let responseBuffer = new Uint8Array(0), headerEndIndex = -1, contentLength = null, chunked = false;
			const 最大响应字节 = 64 * 1024;
			while (responseBuffer.length < 最大响应字节) {
				const value = await tlsSocket.read();
				if (!value) break;
				if (value.byteLength === 0) continue;
				responseBuffer = 拼接字节数据(responseBuffer, value);
				if (headerEndIndex === -1) {
					const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
					if (crlfcrlf !== -1) {
						headerEndIndex = crlfcrlf + 4;
						const headers = decoder.decode(responseBuffer.slice(0, headerEndIndex));
						const statusLine = headers.split('\r\n')[0] || '';
						const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
						const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
						if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`代理检测请求失败: ${statusLine || '无效响应'}`);
						const lengthMatch = headers.match(/\r\nContent-Length:\s*(\d+)/i);
						if (lengthMatch) contentLength = parseInt(lengthMatch[1], 10);
						chunked = /\r\nTransfer-Encoding:\s*chunked/i.test(headers);
					}
				}
				if (headerEndIndex !== -1 && contentLength !== null && responseBuffer.length >= headerEndIndex + contentLength) break;
				if (headerEndIndex !== -1 && chunked && decoder.decode(responseBuffer).includes('\r\n0\r\n\r\n')) break;
			}
			if (headerEndIndex === -1) throw new Error('代理检测响应头过长或无效');
			const response = decoder.decode(responseBuffer);
			const ip = response.match(/(?:^|\n)ip=(.*)/)?.[1];
			const loc = response.match(/(?:^|\n)loc=(.*)/)?.[1];
			if (!ip || !loc) throw new Error('代理检测响应无效');
			检测代理响应 = { success: true, proxy: 代理协议 + "://" + 完整代理参数, ip, loc, responseTime: Date.now() - startTime };
		} finally {
			try { tlsSocket ? tlsSocket.close() : await tcpSocket?.close?.() } catch (e) { }
		}
	} catch (error) {
		检测代理响应 = { success: false, error: error.message, proxy: 代理协议 + "://" + 完整代理参数, responseTime: Date.now() - startTime };
	}
} catch (err) {
	检测代理响应 = { success: false, error: err.message, proxy: 代理协议 + "://" + 代理参数, responseTime: Date.now() - startTime };
}
return new Response(JSON.stringify(检测代理响应, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
}
