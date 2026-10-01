// @ts-nocheck
// Фаза 3, Шаг 3.1: чистые утилиты вынесены функция-в-функцию в src/util.ts.
import { MD5MD5 } from "./util";
import { 创建日志器, 设置日志级别 } from "./logging";
import { 特征码字典 } from "./obfuscation-tokens";
import { 整理成数组 } from "./dns";
import { 反代参数获取, 创建请求TCP连接器 } from "./upstream/dial";
import { 取SOCKS5白名单, 获取叉HTTPPadding标识, 解析白名单环境 } from "./config";
import { 规范化伪装页URL, 处理伪装页 } from "./decoy";
import { 识别运营商, 处理订阅请求, 快速订阅重定向 } from "./subscription";
import { uuidRegex, 处理管理路由, 处理Locations路由 } from "./admin";
import { 处理叉HTTP请求 } from "./transport/xhttp";
import { 处理gRPC请求 } from "./transport/grpc";
import { 处理WS请求 } from "./transport/ws";
const Version = '2026-09-22 20:01:17';
const log = 创建日志器('entry');
const Pages静态页面 = 'https://edt-pages.github.io';
///////////////////////////////////////////////////////全局常量和工具函数///////////////////////////////////////////////
const WS早期数据最大字节 = 8 * 1024, WS早期数据最大头长度 = Math.ceil(WS早期数据最大字节 * 4 / 3) + 4;

// Шаг 1.1 (реестр 1.1, строка 1): настройки запроса собираются чистой функцией.
// cmcc-пин старой строки 43 удалён — оператор больше не урезает 并发拨号 до 1.
// Ни одно request-зависимое значение не пишется в module-scope во время обслуживания.
export function parseSettings(env, request) {
	return {
		// P1.10: все dial-настройки читаются отсюда, на каждый запрос заново.
		// Раньше 预加载竞速拨号 и 反代并发拨号数 жили в модуле relay и накапливались
		// между запросами: включённый флаг уже нельзя было выключить, число —
		// заменить. Значения по умолчанию — те же, что были в модуле.
		dialConcurrency: Math.max(1, Number(env?.TCP_CONCURRENT_DIAL) || 2),
		proxyConcurrency: Math.max(1, Number(env?.PROXY_CONCURRENT_DIAL) || 1),
		preloadRace: ['1', 'true'].includes(String(env?.PRELOAD_RACE_DIAL)),
		// P1.10: 白名单 — тоже. Раньше 应用白名单环境 дописывала в модульный
		// массив, и отозванное правило не исчезало никогда.
		whiteList: 取SOCKS5白名单(解析白名单环境(env)),
		// P1.5: цель DNS-over-TCP. Раньше резолвер был зашит в коде (8.8.4.4).
		dnsTarget: 解析DNS目标(env),
	};
}


/**
 * Цель DNS-запроса из окружения. `адрес`, `адрес:порт` или `[ipv6]:порт`.
 * Пусто или нечитаемо — значение по умолчанию, как было зашито.
 */
export function 解析DNS目标(env) {
	const 原始 = String(env?.DNS_TCP_RESOLVER || env?.DNS_SERVER || '').trim();
	if (!原始) return { hostname: '8.8.4.4', port: 53 };
	const 括号内 = 原始.match(/^\[([^\]]+)\](?::(\d+))?$/);
	if (括号内) return { hostname: 括号内[1], port: Number(括号内[2] || 53) };
	const 端口 = 原始.match(/^(.*):(\d+)$/);
	if (端口) return { hostname: 端口[1], port: Number(端口[2]) };
	return { hostname: 原始, port: 53 };
}

/**
 * Контекст запроса (P4.5). Состав сокращён до того, что реально читается:
 *   settings.dialConcurrency — берётся в relay.ts для 并发拨号;
 *   dial                    — шов создания TCP-сокета.
 *
 * Убрано как мёртвое: client{operator,访问IP,ua} и identity. Ни одно
 * транспортное место к ним не обращалось. Значения берутся локально там,
 * где нужны: operator — в 识别运营商 при сборке подписки, 访问IP/ua — в fetch.
 */
export function 创建请求上下文(request, env) {
	return {
		settings: parseSettings(env, request),
		// Шов dial: единственное поле контекста (без интерфейса и фабрики).
		// Лениво — запросы без fetcher (admin/version/...) создают контекст безболезненно.
		dial: (options, init) => 创建请求TCP连接器(request)(options, init),
	};
}
export default {
	async fetch(request, env, ctx) {
		let 请求URL文本 = request.url.replace(/%5[Cc]/g, '').replace(/\\/g, '');
		const 请求URL锚点索引 = 请求URL文本.indexOf('#');
		const 请求URL主体部分 = 请求URL锚点索引 === -1 ? 请求URL文本 : 请求URL文本.slice(0, 请求URL锚点索引);
		if (!请求URL主体部分.includes('?') && /%3f/i.test(请求URL主体部分)) {
			const 请求URL锚点部分 = 请求URL锚点索引 === -1 ? '' : 请求URL文本.slice(请求URL锚点索引);
			请求URL文本 = 请求URL主体部分.replace(/%3f/i, '?') + 请求URL锚点部分;
		}
		const url = new URL(请求URL文本);
		const UA = request.headers.get('User-Agent') || 'null';
		const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase(), contentType = (request.headers.get('content-type') || '').toLowerCase();
		const 管理员密码 = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
		const 加密秘钥 = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';
		const userIDMD5 = await MD5MD5(管理员密码 + 加密秘钥);
		const envUUID = env.UUID || env.uuid;
		const userID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');
		const hosts = env.HOST ? (await 整理成数组(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]) : [url.hostname];
		const host = hosts[0];
		const 访问路径 = url.pathname.slice(1).toLowerCase();
		// P1: уровень пишется присваиванием, а не «sticky OR». Прежний
		// 调试日志打印 = ... || 调试日志打印 не давал погасить логирование
		// обновлением переменной: однажды включённый, он жил до перезапуска изоликата.
		设置日志级别(env);
		// TCP并发拨号数 больше не пишется на уровне запроса (Шаг 1.1, реестр 1.1, строка 1);
		// значение живёт в RequestContext.settings, см. parseSettings/创建请求上下文.
		// Флаги 反代并发拨号数/预加载竞速拨号/白名单 живут в relay.ts (шаг 3.8) — пишем их
		// через 应用拨号环境(), читаем 白名单 через 取SOCKS5白名单(); см. config.ts (шаг 3.10).
		const settings = parseSettings(env, request);
		const 请求上下文 = 创建请求上下文(request, env);
		let 默认反代IP = (`${request.cf.colo}.${特征码字典[0]}.${特征码字典[1]}SsSs.nEt`).toLowerCase(), 默认反代兜底 = true;
		if (env.PROXYIP) {
			const proxyIPs = await 整理成数组(env.PROXYIP);
			默认反代IP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
			默认反代兜底 = false;
		};
		const 访问IP = request.headers.get('CF-Connecting-IP') || request.headers.get('True-Client-IP') || request.headers.get('X-Real-IP') || request.headers.get('X-Forwarded-For') || request.headers.get('Fly-Client-IP') || request.headers.get('X-Appengine-Remote-Addr') || request.headers.get('X-Cluster-Client-IP') || '未知IP';
		if (访问路径 === 'version') {// 版本信息接口
			const 请求UUID = (url.searchParams.get('uuid') || '').toLowerCase();
			if (uuidRegex.test(请求UUID)) {
				const 目标UUID = String(userID).toLowerCase();
				let 请求前8总和 = 0, 目标前8总和 = 0;
				for (let i = 0; i < 8; i++) {
					const 请求码 = 请求UUID.charCodeAt(i);
					请求前8总和 += 请求码 <= 57 ? 请求码 - 48 : 请求码 - 87;
					const 目标码 = 目标UUID.charCodeAt(i);
					目标前8总和 += 目标码 <= 57 ? 目标码 - 48 : 目标码 - 87;
				}
				if (请求前8总和 === 目标前8总和 && 请求UUID.slice(-12) === 目标UUID.slice(-12)) return new Response(JSON.stringify({ Version: Number(String(Version).replace(/\D+/g, '')) }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
			}
		} else if (管理员密码 && upgradeHeader === 'websocket') {// WebSocket代理
			const 反代上下文 = await 反代参数获取(url, userID, 默认反代IP, 默认反代兜底);
			log.调试(`[WebSocket] 命中请求: ${url.pathname}${url.search}`);
			return await 处理WS请求(request, userID, url, 反代上下文, 请求上下文);
		} else if (管理员密码 && !访问路径.startsWith('admin/') && 访问路径 !== 'login' && request.method === 'POST') {// gRPC/叉HTTP代理
			const 反代上下文 = await 反代参数获取(url, userID, 默认反代IP, 默认反代兜底);
			const { 头: 本机Padding头, 键: 本机Padding键 } = 获取叉HTTPPadding标识(userID);
			const 命中叉HTTP特征 = !!request.headers.get(本机Padding头) || !!url.searchParams.get(本机Padding键);
			if (!命中叉HTTP特征 && contentType.startsWith('application/grpc')) {
				log.调试(`[gRPC] 命中请求: ${url.pathname}${url.search}`);
				return await 处理gRPC请求(request, userID, 反代上下文, 请求上下文);
			}
			log.调试(`[叉HTTP] 命中请求: ${url.pathname}${url.search}`);
			return await 处理叉HTTP请求(request, userID, 反代上下文, 请求上下文);
		} else {
			if (url.protocol === 'http:') return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
			if (!管理员密码) return fetch(Pages静态页面 + '/noADMIN').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }) });
			if (env.KV && typeof env.KV.get === 'function') {
				const 区分大小写访问路径 = url.pathname.slice(1);
				const 快速响应 = await 快速订阅重定向(url, host, userID, 加密秘钥, 区分大小写访问路径);
				if (快速响应) return 快速响应;
				if (访问路径 === 'login' || 访问路径 === 'admin' || 访问路径.startsWith('admin/') || 访问路径 === 'logout' || uuidRegex.test(访问路径)) {//管理路由
					const 管理响应 = await 处理管理路由(env, request, ctx, url, host, userID, UA, 访问IP, 访问路径, 区分大小写访问路径, 管理员密码, 加密秘钥, Pages静态页面);
					if (管理响应) return 管理响应;
				} else if (访问路径 === 'sub') {//处理订阅请求
					const 订阅响应 = await 处理订阅请求(request, env, ctx, url, host, userID, UA, 访问IP);
					if (订阅响应) return 订阅响应;
				} else if (访问路径 === 'locations') {//反代locations列表
					const locations响应 = await 处理Locations路由(request, UA, 加密秘钥, 管理员密码);
					if (locations响应) return locations响应;
				} else if (访问路径 === 'robots.txt') return new Response('User-agent: *\nDisallow: /', { status: 200, headers: { 'Content-Type': 'text/plain; charset=UTF-8' } });
			} else if (!envUUID) return fetch(Pages静态页面 + '/noKV').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }) });
		}

		return await 处理伪装页(request, url, 访问IP, UA, 规范化伪装页URL(env.URL));
	}
};

