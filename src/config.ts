// @ts-nocheck
// Фаза 3, Шаг 3.10: config.ts — чтение/запись KV (config.json/cf.json/tg.json),
// дефолты, KV-seed, CF-usage. TOKEN через MD5MD5 (см. §7 — замена на HMAC
// зафиксирована как issue, здесь переносится без изменений).
// from worker.ts — function-in-function, behavior preserved.
// Лог → console (telemetry остаётся шагом 11).

import { MD5MD5, 掩码敏感信息, 随机路径, 获取传输路径参数值 } from "./util";
import { 整理成数组 } from "./dns";
import { 特征码字典 } from "./obfuscation-tokens";
import { 创建日志器 } from "./logging";
const log = 创建日志器('config');

// SOCKS5-белый список: значение по умолчанию для конфига, читается также из
// transport/relay.ts. Раньше жил в worker.ts (строка 12) — переехал сюда, чтобы
// config.ts не зависел от transport/relay.ts (инверсия слоёв, шаг 3.8).
const 默认白名单 = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];

// Вызывается из fetch-обработчика worker.ts на месте старой строки 77.

/**
 * Правила SOCKS5-белого списка.
 *
 * P1.10: список больше не накапливается в модуле. Пришёл аргументом — берётся
 * он, не пришёл — умолчания. Прежде 应用白名单环境 дописывала в модульный
 * массив, и отозванное правило не исчезало до перезапуска изолиата.
 */
export function 取SOCKS5白名单(правила = null) {
	const изЗапроса = Array.isArray(правила) ? 规则去重(правила) : [];
	return изЗапроса.length ? изЗапроса : 默认白名单;
}

/** Правила GO2SOCKS5 из окружения; пусто — берутся умолчания. */
export function 解析白名单环境(env) {
	const 原始 = String(env?.GO2SOCKS5 || '').trim();
	if (!原始) return null;
	return 原始.split(',').map(x => x.trim()).filter(Boolean);
}

function 规则去重(список) {
	return [...new Set(список.map(x => String(x).trim().toLowerCase()).filter(Boolean))];
}

export function 获取叉HTTPPadding标识(yourUUID) {
	return { 头: yourUUID.slice(1, 7), 键: '_' + yourUUID.slice(25, 31) };
}

export function 获取传输协议配置(配置 = {}) {
	const 是gRPC = 配置.传输协议 === 'grpc';
	const { 头: 本机Padding头, 键: 本机Padding键 } = 获取叉HTTPPadding标识(配置.UUID);
	const 叉混淆JSON = {
		"xPaddingObfsMode": true,
		"xPaddingMethod": "tokenish",
		"xPaddingPlacement": "queryInHeader",
		"xPaddingHeader": 本机Padding头,
		"xPaddingKey": 本机Padding键
	};
	return {
		type: 是gRPC ? (配置.gRPC模式 === 'multi' ? 'grpc&mode=multi' : 'grpc&mode=gun') : (配置.传输协议 === 'xhttp' ? `xhttp&mode=stream-one&extra=${encodeURIComponent(JSON.stringify(叉混淆JSON))}` : 'ws'),
		路径字段名: 是gRPC ? 'serviceName' : 'path',
		域名字段名: 是gRPC ? 'authority' : 'host'
	};
}

export async function 读取config_JSON(env, hostname, userID, UA = "Mozilla/5.0", 重置配置 = false) {
	const _p = 特征码字典[0];
	const host = hostname, Ali_DoH = "https://dns.alidns.com/dns-query", ECH_SNI = "cloudflare-ech.com", 占位符 = '{{IP:PORT}}', 初始化开始时间 = performance.now(), 默认配置JSON = {
		TIME: new Date().toISOString(),
		HOST: host,
		HOSTS: [hostname],
		UUID: userID,
		PATH: "/",
		ALPN: "",
		协议类型: "v" + "le" + "ss",
		传输协议: "ws",
		gRPC模式: "gun",
		gRPCUserAgent: UA,
		跳过证书验证: false,
		启用0RTT: false,
		TLS分片: null,
		随机路径: false,
		ECH: false,
		ECHConfig: {
			DNS: Ali_DoH,
			SNI: ECH_SNI,
		},
		SS: {
			加密方式: "aes-128-gcm",
			TLS: true,
		},
		Fingerprint: "chrome",
		优选订阅生成: {
			local: true, // true: 基于本地的优选地址  false: 优选订阅生成器
			本地IP库: {
				随机IP: true, // 当 随机IP 为true时生效，启用随机IP的数量，否则使用KV内的ADD.txt
				随机数量: 16,
				指定端口: -1,
			},
			SUB: null,
			SUBNAME: "edge" + "tunnel",
			SUBUpdateTime: 3, // 订阅更新时间（小时）
			TOKEN: await MD5MD5(hostname + userID),
		},
		订阅转换配置: {
			SUBAPI: `https://SUBAPI.${特征码字典[1]}ssss.net`,
			SUBCONFIG: `https://raw.githubusercontent.com/${特征码字典[1]}/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini`,
			SUBEMOJI: false,
			SUBLIST: false, //仅输出节点信息
			UDP: false, // 启用 UDP
			XUDP: false, // 启用 XUDP
			TLS13: false, // 启用 TLS 1.3
			APPEND_TYPE: false, // 插入节点类型
			SORT: false, // 基础节点排序
			EXPAND: true, // 展开规则全文
		},
		反代: {
			[_p]: "auto",
			SOCKS5: {
				启用: null,
				全局: false,
				账号: '',
				// P1.10: правила из окружения запроса, без накопления в модуле.
				白名单: 取SOCKS5白名单(解析白名单环境(env)),
			},
			路径模板: {
				[_p]: "proxyip=" + 占位符,
				SOCKS5: {
					全局: "socks5://" + 占位符,
					标准: "socks5=" + 占位符
				},
				HTTP: {
					全局: "http://" + 占位符,
					标准: "http=" + 占位符
				},
				HTTPS: {
					全局: "https://" + 占位符,
					标准: "https=" + 占位符
				},
				TURN: {
					全局: "turn://" + 占位符,
					标准: "turn=" + 占位符
				},
				SSTP: {
					全局: "sstp://" + 占位符,
					标准: "sstp=" + 占位符
				},
			},
		},
		TG: {
			启用: false,
			BotToken: null,
			ChatID: null,
		},
		CF: {
			Email: null,
			GlobalAPIKey: null,
			AccountID: null,
			APIToken: null,
			UsageAPI: null,
			Usage: {
				success: false,
				pages: 0,
				workers: 0,
				total: 0,
				max: 100000,
			},
		}
	};

	// Шаг 1.2: конфиг собирается в локальную переменную и возвращается наружу;
	// module-global config_JSON больше не пишется (регресс бага #1 — два
	// параллельных запроса с разными env не перезаписывают друг друга).
	let config_JSON = 默认配置JSON;

	try {
		let configJSON = await env.KV.get('config.json');
		if (!configJSON || 重置配置 == true) {
			await env.KV.put('config.json', JSON.stringify(默认配置JSON, null, 2));
			config_JSON = 默认配置JSON;
		} else {
			config_JSON = JSON.parse(configJSON);
		}
	} catch (error) {
		log.错误(`读取config_JSON出错: ${error.message}`);
		config_JSON = 默认配置JSON;
	}

	if (!config_JSON.订阅转换配置.SUBLIST) config_JSON.订阅转换配置.SUBLIST = false;
	if (!config_JSON.订阅转换配置.UDP) config_JSON.订阅转换配置.UDP = false;
	if (!config_JSON.订阅转换配置.XUDP) config_JSON.订阅转换配置.XUDP = false;
	if (!config_JSON.订阅转换配置.TLS13) config_JSON.订阅转换配置.TLS13 = false;
	if (!config_JSON.订阅转换配置.APPEND_TYPE) config_JSON.订阅转换配置.APPEND_TYPE = false;
	if (!config_JSON.订阅转换配置.SORT) config_JSON.订阅转换配置.SORT = false;
	if (typeof config_JSON.订阅转换配置.EXPAND !== 'boolean') config_JSON.订阅转换配置.EXPAND = true;
	if (!config_JSON.gRPCUserAgent) config_JSON.gRPCUserAgent = UA;
	config_JSON.HOST = host;
	if (!config_JSON.HOSTS) config_JSON.HOSTS = [hostname];
	if (env.HOST) config_JSON.HOSTS = (await 整理成数组(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]);
	config_JSON.UUID = userID;
	if (!config_JSON.随机路径) config_JSON.随机路径 = false;
	if (!config_JSON.启用0RTT) config_JSON.启用0RTT = false;

	if (env.PATH) config_JSON.PATH = env.PATH.startsWith('/') ? env.PATH : '/' + env.PATH;
	else if (!config_JSON.PATH) config_JSON.PATH = '/';
	if (!config_JSON.ALPN) config_JSON.ALPN = "";

	if (!config_JSON.gRPC模式) config_JSON.gRPC模式 = 'gun';
	if (!config_JSON.SS) config_JSON.SS = { 加密方式: "aes-128-gcm", TLS: false };

	if (!config_JSON.反代.路径模板?.[_p]) {
		config_JSON.反代.路径模板 = {
			[_p]: "proxyip=" + 占位符,
			SOCKS5: {
				全局: "socks5://" + 占位符,
				标准: "socks5=" + 占位符
			},
			HTTP: {
				全局: "http://" + 占位符,
				标准: "http=" + 占位符
			},
			HTTPS: {
				全局: "https://" + 占位符,
				标准: "https=" + 占位符
			},
			TURN: {
				全局: "turn://" + 占位符,
				标准: "turn=" + 占位符
			},
			SSTP: {
				全局: "sstp://" + 占位符,
				标准: "sstp=" + 占位符
			},
		};
	}
	if (!config_JSON.反代.路径模板.HTTPS) config_JSON.反代.路径模板.HTTPS = { 全局: "https://" + 占位符, 标准: "https=" + 占位符 };
	if (!config_JSON.反代.路径模板.TURN) config_JSON.反代.路径模板.TURN = { 全局: "turn://" + 占位符, 标准: "turn=" + 占位符 };
	if (!config_JSON.反代.路径模板.SSTP) config_JSON.反代.路径模板.SSTP = { 全局: "sstp://" + 占位符, 标准: "sstp=" + 占位符 };

	const 代理配置 = config_JSON.反代.路径模板[config_JSON.反代.SOCKS5.启用?.toUpperCase()];

	let 路径反代参数 = '';
	if (代理配置 && config_JSON.反代.SOCKS5.账号) 路径反代参数 = (config_JSON.反代.SOCKS5.全局 ? 代理配置.全局 : 代理配置.标准).replace(占位符, config_JSON.反代.SOCKS5.账号);
	else if (config_JSON.反代[_p] !== 'auto') 路径反代参数 = config_JSON.反代.路径模板[_p].replace(占位符, config_JSON.反代[_p]);

	let 反代查询参数 = '';
	if (路径反代参数.includes('?')) {
		const [反代路径部分, 反代查询部分] = 路径反代参数.split('?');
		路径反代参数 = 反代路径部分;
		反代查询参数 = 反代查询部分;
	}

	config_JSON.PATH = config_JSON.PATH.replace(路径反代参数, '').replace('//', '/');
	const normalizedPath = config_JSON.PATH === '/' ? '' : config_JSON.PATH.replace(/\/+(?=\?|$)/, '').replace(/\/+$/, '');
	const [路径部分, ...查询数组] = normalizedPath.split('?');
	const 查询部分 = 查询数组.length ? '?' + 查询数组.join('?') : '';
	const 最终查询部分 = 反代查询参数 ? (查询部分 ? 查询部分 + '&' + 反代查询参数 : '?' + 反代查询参数) : 查询部分;
	config_JSON.完整节点路径 = (路径部分 || '/') + (路径部分 && 路径反代参数 ? '/' : '') + 路径反代参数 + 最终查询部分 + (config_JSON.启用0RTT ? (最终查询部分 ? '&' : '?') + 'ed=2560' : '');

	if (!config_JSON.TLS分片 && config_JSON.TLS分片 !== null) config_JSON.TLS分片 = null;
	const TLS分片参数 = config_JSON.TLS分片 == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLS分片 == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
	if (!config_JSON.Fingerprint) config_JSON.Fingerprint = "chrome";
	if (!config_JSON.ECH) config_JSON.ECH = false;
	if (!config_JSON.ECHConfig) config_JSON.ECHConfig = { DNS: Ali_DoH, SNI: ECH_SNI };
	const ECHLINK参数 = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';
	const { type: 传输协议, 路径字段名, 域名字段名 } = 获取传输协议配置(config_JSON);
	const 传输路径参数值 = 获取传输路径参数值(config_JSON, config_JSON.完整节点路径);
	config_JSON.LINK = config_JSON.协议类型 === 'ss'
		? `${config_JSON.协议类型}://${btoa(config_JSON.SS.加密方式 + ':' + userID)}@${host}:${config_JSON.SS.TLS ? '443' : '80'}?plugin=v2${encodeURIComponent(`ray-plugin;mode=websocket;host=${host};path=${((config_JSON.完整节点路径.includes('?') ? config_JSON.完整节点路径.replace('?', '?enc=' + config_JSON.SS.加密方式 + '&') : (config_JSON.完整节点路径 + '?enc=' + config_JSON.SS.加密方式)) + (config_JSON.SS.TLS ? ';tls' : ''))};mux=0`) + ECHLINK参数}#${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`
		: `${config_JSON.协议类型}://${userID}@${host}:443?security=tls&type=${传输协议 + ECHLINK参数}&${域名字段名}=${host}&fp=${config_JSON.Fingerprint}&sni=${host}&${路径字段名}=${encodeURIComponent(传输路径参数值) + TLS分片参数}&encryption=none#${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`;
	config_JSON.优选订阅生成.TOKEN = await MD5MD5(hostname + userID);

	const 初始化TG_JSON = { BotToken: null, ChatID: null };
	config_JSON.TG = { 启用: config_JSON.TG.启用 ? config_JSON.TG.启用 : false, ...初始化TG_JSON };
	try {
		const TG_TXT = await env.KV.get('tg.json');
		if (!TG_TXT) {
			await env.KV.put('tg.json', JSON.stringify(初始化TG_JSON, null, 2));
		} else {
			const TG_JSON = JSON.parse(TG_TXT);
			config_JSON.TG.ChatID = TG_JSON.ChatID ? TG_JSON.ChatID : null;
			config_JSON.TG.BotToken = TG_JSON.BotToken ? 掩码敏感信息(TG_JSON.BotToken) : null;
		}
	} catch (error) {
		log.错误(`读取tg.json出错: ${error.message}`);
	}

	const 初始化CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
	config_JSON.CF = { ...初始化CF_JSON, Usage: { success: false, pages: 0, workers: 0, total: 0, max: 100000 } };
	try {
		const CF_TXT = await env.KV.get('cf.json');
		if (!CF_TXT) {
			await env.KV.put('cf.json', JSON.stringify(初始化CF_JSON, null, 2));
		} else {
			const CF_JSON = JSON.parse(CF_TXT);
			if (CF_JSON.UsageAPI) {
				try {
					const response = await fetch(CF_JSON.UsageAPI);
					const Usage = await response.json();
					config_JSON.CF.Usage = Usage;
				} catch (err) {
					log.错误(`请求 CF_JSON.UsageAPI 失败: ${err.message}`);
				}
			} else {
				config_JSON.CF.Email = CF_JSON.Email ? CF_JSON.Email : null;
				config_JSON.CF.GlobalAPIKey = CF_JSON.GlobalAPIKey ? 掩码敏感信息(CF_JSON.GlobalAPIKey) : null;
				config_JSON.CF.AccountID = CF_JSON.AccountID ? 掩码敏感信息(CF_JSON.AccountID) : null;
				config_JSON.CF.APIToken = CF_JSON.APIToken ? 掩码敏感信息(CF_JSON.APIToken) : null;
				config_JSON.CF.UsageAPI = null;
				const Usage = await getCloudflareUsage(CF_JSON.Email, CF_JSON.GlobalAPIKey, CF_JSON.AccountID, CF_JSON.APIToken);
				config_JSON.CF.Usage = Usage;
			}
		}
	} catch (error) {
		log.错误(`读取cf.json出错: ${error.message}`);
	}

	config_JSON.加载时间 = (performance.now() - 初始化开始时间).toFixed(2) + 'ms';
	return config_JSON;
}

export async function getCloudflareUsage(Email, GlobalAPIKey, AccountID, APIToken) {
	const API = "https://api.cloudflare.com/client/v4";
	const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
	const cfg = { "Content-Type": "application/json" };

	try {
		if (!AccountID && (!Email || !GlobalAPIKey)) return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };

		if (!AccountID) {
			const r = await fetch(`${API}/accounts`, {
				method: "GET",
				headers: { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey }
			});
			if (!r.ok) throw new Error(`账户获取失败: ${r.status}`);
			const d = await r.json();
			if (!d?.result?.length) throw new Error("未找到账户");
			const idx = d.result.findIndex(a => a.name?.toLowerCase().startsWith(Email.toLowerCase()));
			AccountID = d.result[idx >= 0 ? idx : 0]?.id;
		}

		const now = new Date();
		now.setUTCHours(0, 0, 0, 0);
		const hdr = APIToken ? { ...cfg, "Authorization": `Bearer ${APIToken}` } : { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey };

		const res = await fetch(`${API}/graphql`, {
			method: "POST",
			headers: hdr,
			body: JSON.stringify({
				query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
					viewer { accounts(filter: {accountTag: $AccountID}) {
						pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
						workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
					} }
				}`,
				variables: { AccountID, filter: { datetime_geq: now.toISOString(), datetime_leq: new Date().toISOString() } }
			})
		});

		if (!res.ok) throw new Error(`查询失败: ${res.status}`);
		const result = await res.json();
		if (result.errors?.length) throw new Error(result.errors[0].message);

		const acc = result?.data?.viewer?.accounts?.[0];
		if (!acc) throw new Error("未找到账户数据");

		const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups);
		const workers = sum(acc.workersInvocationsAdaptive);
		const total = pages + workers;
		const max = 100000;
		log.信息(`统计结果 - Pages: ${pages}, Workers: ${workers}, 总计: ${total}, 上限: 100000`);
		return { success: true, pages, workers, total, max };

	} catch (error) {
		log.错误('获取使用量错误:', error.message);
		return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };
	}
}
