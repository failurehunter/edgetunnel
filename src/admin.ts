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
import { 读取config_JSON, getCloudflareUsage, 获取传输协议配置 } from "./config";
import { 识别运营商, 请求优选API, 生成随机IP } from "./subscription";
import { 请求日志记录 } from "./telemetry";
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
// Маршруты login / admin/* / logout. Извлечены из fetch-обработчика монолита
// (строки 123-268) на финальной сборке, шаг 3.16. Ветка, не нашедшая себя,
// ничего не возвращает — вызывающий тогда продолжает цепочку маршрутов, как в монолите.
/** @returns {import('./dispatch-contract').МаршрутОтвет} null, если ни одна ветка не нашла себя. */
export async function 处理管理路由(env, request, ctx, url, host, userID, UA, 访问IP, 访问路径, 区分大小写访问路径, 管理员密码, 加密秘钥, Pages静态页面) {
	if (访问路径 === 'login') {//处理登录页面和登录请求
		const cookies = request.headers.get('Cookie') || '';
		const authCookie = 读取AuthCookie(cookies);
		if (authCookie == await 计算AuthCookie(UA, 加密秘钥, 管理员密码)) return new Response('重定向中...', { status: 302, headers: { 'Location': '/admin' } });
		if (request.method === 'POST') {
			const formData = await request.text();
			const params = new URLSearchParams(formData);
			const 输入密码 = params.get('password');
			if (校验管理密码(输入密码, 管理员密码)) {
				// 密码正确，设置cookie并返回成功标记
				const 响应 = new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
				响应.headers.set('Set-Cookie', await 签发AuthCookie(UA, 加密秘钥, 管理员密码));
				return 响应;
			}
		}
		return fetch(Pages静态页面 + '/login');
	} else if (访问路径 === 'admin' || 访问路径.startsWith('admin/')) {//验证cookie后响应管理页面
		const cookies = request.headers.get('Cookie') || '';
		const authCookie = 读取AuthCookie(cookies);
		// 没有cookie或cookie错误，跳转到/login页面
		if (!authCookie || authCookie !== await 计算AuthCookie(UA, 加密秘钥, 管理员密码)) return new Response('重定向中...', { status: 302, headers: { 'Location': '/login' } });
		if (访问路径 === 'admin/log.json') {// 读取日志内容
			const 读取日志内容 = await env.KV.get('log.json') || '[]';
			return new Response(读取日志内容, { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
		} else if (区分大小写访问路径 === 'admin/getCloudflareUsage') {// 查询请求量
			try {
				const Usage_JSON = await getCloudflareUsage(url.searchParams.get('Email'), url.searchParams.get('GlobalAPIKey'), url.searchParams.get('AccountID'), url.searchParams.get('APIToken'));
				return new Response(JSON.stringify(Usage_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
			} catch (err) {
				const errorResponse = { msg: '查询请求量失败，失败原因：' + err.message, error: err.message };
				return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
			}
		} else if (区分大小写访问路径 === 'admin/getADDAPI') {// 验证优选API
			if (url.searchParams.get('url')) {
				const 待验证优选URL = url.searchParams.get('url');
				try {
					new URL(待验证优选URL);
					const 请求优选API内容 = await 请求优选API([待验证优选URL], url.searchParams.get('port') || '443');
					let 优选API的IP = 请求优选API内容[0].length > 0 ? 请求优选API内容[0] : 请求优选API内容[1];
					优选API的IP = 优选API的IP.map(item => item.replace(/#(.+)$/, (_, remark) => '#' + decodeURIComponent(remark)));
					return new Response(JSON.stringify({ success: true, data: 优选API的IP }, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
				} catch (err) {
					const errorResponse = { msg: '验证优选API失败，失败原因：' + err.message, error: err.message };
					return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
				}
			}
			return new Response(JSON.stringify({ success: false, data: [] }, null, 2), { status: 403, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
		} else if (访问路径 === 'admin/check') {// 代理检查
			return await checkProxy(url, request);
		}
		const config_JSON = await 读取config_JSON(env, host, userID, UA);

		if (访问路径 === 'admin/init') {// 重置配置为默认值
			try {
				const config_JSON = await 读取config_JSON(env, host, userID, UA, true);
				ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Init_Config', config_JSON));
				config_JSON.init = '配置已重置为默认值';
				return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
			} catch (err) {
				const errorResponse = { msg: '配置重置失败，失败原因：' + err.message, error: err.message };
				return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
			}
		} else if (request.method === 'POST') {// 处理 KV 操作（POST 请求）
			if (访问路径 === 'admin/config.json') { // 保存config.json配置
				try {
					const newConfig = await request.json();
					// 验证配置完整性
					if (!newConfig.UUID || !newConfig.HOST) return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });

					// 保存到 KV
					await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
					ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
					return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
				} catch (error) {
					console.error('保存配置失败:', error);
					return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
				}
			} else if (访问路径 === 'admin/cf.json') { // 保存cf.json配置
				try {
					const newConfig = await request.json();
					const CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
					if (!newConfig.init || newConfig.init !== true) {
						if (newConfig.Email && newConfig.GlobalAPIKey) {
							CF_JSON.Email = newConfig.Email;
							CF_JSON.GlobalAPIKey = newConfig.GlobalAPIKey;
						} else if (newConfig.AccountID && newConfig.APIToken) {
							CF_JSON.AccountID = newConfig.AccountID;
							CF_JSON.APIToken = newConfig.APIToken;
						} else if (newConfig.UsageAPI) {
							CF_JSON.UsageAPI = newConfig.UsageAPI;
						} else {
							return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						}
					}

					// 保存到 KV
					await env.KV.put('cf.json', JSON.stringify(CF_JSON, null, 2));
					ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
					return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
				} catch (error) {
					console.error('保存配置失败:', error);
					return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
				}
			} else if (访问路径 === 'admin/tg.json') { // 保存tg.json配置
				try {
					const newConfig = await request.json();
					if (newConfig.init && newConfig.init === true) {
						const TG_JSON = { BotToken: null, ChatID: null };
						await env.KV.put('tg.json', JSON.stringify(TG_JSON, null, 2));
					} else {
						if (!newConfig.BotToken || !newConfig.ChatID) return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						await env.KV.put('tg.json', JSON.stringify(newConfig, null, 2));
					}
					ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
					return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
				} catch (error) {
					console.error('保存配置失败:', error);
					return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
				}
			} else if (区分大小写访问路径 === 'admin/ADD.txt') { // 保存自定义优选IP
				try {
					const customIPs = await request.text();
					await env.KV.put('ADD.txt', customIPs);// 保存到 KV
					ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Custom_IPs', config_JSON));
					return new Response(JSON.stringify({ success: true, message: '自定义IP已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
				} catch (error) {
					console.error('保存自定义IP失败:', error);
					return new Response(JSON.stringify({ error: '保存自定义IP失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
				}
			} else return new Response(JSON.stringify({ error: '不支持的POST请求路径' }), { status: 404, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
		} else if (访问路径 === 'admin/config.json') {// 处理 admin/config.json 请求，返回JSON
			return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
		} else if (区分大小写访问路径 === 'admin/ADD.txt') {// 处理 admin/ADD.txt 请求，返回本地优选IP
			let 本地优选IP = await env.KV.get('ADD.txt') || 'null';
			if (本地优选IP == 'null') 本地优选IP = (await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口))[1];
			return new Response(本地优选IP, { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8', 'asn': request.cf.asn } });
		} else if (访问路径 === 'admin/cf.json') {// CF配置文件
			return new Response(JSON.stringify(request.cf, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
		}

		ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Admin_Login', config_JSON));
		return fetch(Pages静态页面 + '/admin' + url.search);
	} else if (访问路径 === 'logout' || uuidRegex.test(访问路径)) {//清除cookie并跳转到登录页面
		const 响应 = new Response('重定向中...', { status: 302, headers: { 'Location': '/login' } });
		响应.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly');
		return 响应;
	}	// конец ветки logout
	return null;   // контракт диспетчера: «не моё» — строго null (src/dispatch-contract.ts)
}


// /locations: отдаёт список colo через speed.cloudflare.com, только при валидной
// auth-cookie. Без неё ветка ничего не возвращает — цепочка маршрутов продолжается.
/** @returns {import('./dispatch-contract').МаршрутОтвет} null без валидной auth-cookie. */
export async function 处理Locations路由(request, UA, 加密秘钥, 管理员密码) {
	const cookies = request.headers.get('Cookie') || '';
	const authCookie = 读取AuthCookie(cookies);
	if (authCookie && authCookie == await 计算AuthCookie(UA, 加密秘钥, 管理员密码)) return fetch(new Request('https://speed.cloudflare.com/locations', { headers: { 'Referer': 'https://speed.cloudflare.com/' } }));
	return null;
}
