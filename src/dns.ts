// @ts-nocheck
// Фаза 3, Шаг 3.3: DNS/DoH/разрешение адресов.
// from worker.ts — function-in-function, behavior preserved (свой log → console).
//
// TURN/STUN-хелперы, ошибочно переписанные сюда в шаге 3.3, удалены: рабочая
// версия — upstream/turn.ts (восстановлена дословно из legacy, dial.ts импортирует
// из неё). Здесь остаются только DNS-примитивы и ALERT-константы TLS.

import { 创建日志器 } from "./logging";
const log = 创建日志器('dns');

export const ALERT_CLOSE_NOTIFY = 0, ALERT_LEVEL_WARNING = 1, ALERT_UNRECOGNIZED_NAME = 112;
export const shouldIgnoreTlsAlert = fragment => fragment?.[0] === ALERT_LEVEL_WARNING && fragment?.[1] === ALERT_UNRECOGNIZED_NAME;

/** Человеческие названия rcode: без них в логе не отличить NXDOMAIN от SERVFAIL. */
const RCODE名称表 = {
	0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN',
	4: 'NOTIMP', 5: 'REFUSED', 9: 'NOTAUTH',
};

export function RCODE名称(rcode) {
	return RCODE名称表[rcode] || `RCODE${rcode}`;
}

export const DoH缓存 = {};
export const DoH缓存最大条目 = 256;
export const DoH记录类型映射 = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, SRV: 33, HTTPS: 65 };
// P1.1: таймаут DoH-запроса. Раньше fetch не имел signal и мог висеть вечно:
// дозвон ждал резолвер неопределённо долго. Вилка 1–1.5 с: дальше держать
// соединение без ответа бессмысленно — вся попытка дозвона и так ограничена
// секундой на кандидата. Значение экспортируется, чтобы тест пиновал вилку.
export const DoH超时毫秒 = 1200;
// P2.4 (фикс 5): кэш СБОЕВ DoH — отдельно от DoH缓存 (ответов). Сбой резолвера
// (таймаут/обрыв/HTTP-ошибка/SERVFAIL/REFUSED/FORMERR/NOTIMP/NOTAUTH) — это не
// «домена нет»: он проходит сам, и повторный запрос в ближайшие секунды только
// умножает латентность. TTL короткий (вилка 5–10 с), чтобы временная ошибка не
// консервировала «нет данных»; NXDOMAIN по-прежнему живёт в DoH缓存 со своим
// отрицательным TTL. Экспортируется, чтобы тесты чистили между прогонами.
export const DoH失败缓存 = {};
export const DoH失败缓存TTL = 5000;
// P1.1: single-flight по «домен:тип». Два конкурентных дозвона на один и тот же
// proxyip (параллельные кандидаты, повторные соединения, AAAA-хвост вместе с
// TXT/A) раньше оба промахивались в кэш — он пишется только после ответа — и
// оба слали одинаковый DoH-запрос. Второй ждёт обещание первого и делит
// результат; ключ тот же, что у кэша. Это «кэш для ещё не завершившегося
// запроса»: после ответа запись удаляется, дальше работает DoH缓存.
export const DoH进行中 = {};

function 写入失败缓存(缓存键) {
	DoH失败缓存[缓存键] = { 过期时间: Date.now() + DoH失败缓存TTL };
}

export async function DoH查询(域名, 记录类型, DoH解析服务 = "https://cloudflare-dns.com/dns-query", 超时毫秒 = DoH超时毫秒) {
	const 规范化域名 = String(域名 || '').trim().toLowerCase().replace(/\.$/, '');
	const 规范化记录类型 = String(记录类型 || '').trim().toUpperCase();
	const 缓存键 = `${规范化域名}:${规范化记录类型}`;
	const qtype = DoH记录类型映射[规范化记录类型] || 1;
	const 当前时间戳 = Date.now();
	const 现缓存项 = DoH缓存[缓存键];
	if (现缓存项 && 当前时间戳 < 现缓存项.过期时间) {
		log.调试(`[DoH查询] 命中缓存 ${域名} ${记录类型} via ${DoH解析服务}`);
		return 现缓存项.data.map(data => ({ type: qtype, data }));
	}
	// P2.4 (фикс 5): сбой в окне 5 с не бьёт в сеть повторно. Первый сбой
	// залогирован на уровне 错误 («DoH查询失败»), а тёплый кэш-сбой возвращает
	// пусто быстро — потребители держат тот же фолбэк, что и при NXDOMAIN.
	const 现失败项 = DoH失败缓存[缓存键];
	if (现失败项 && 当前时间戳 < 现失败项.过期时间) {
		log.调试(`[DoH查询] 命中 кэш сбоя ${域名} ${记录类型} via ${DoH解析服务}`);
		return [];
	}
	// P1.1: пока первый запрос в полёте, все совпадающие домен:тип ждут его же.
	// Проверка после кэша: завершённый запрос уже в DoH缓存, сюда не попадёт.
	if (DoH进行中[缓存键]) {
		log.调试(`[DoH查询] слияние с идущим запросом ${域名} ${记录类型}`);
		return await DoH进行中[缓存键];
	}
	const 当前查询 = (async () => {
		const 开始时间 = performance.now();
		log.调试(`[DoH查询] 开始查询 ${域名} ${记录类型} via ${DoH解析服务}`);
		// P1.1: AbortController, а не AbortSignal.timeout: clearTimeout в finally,
		// таймер не течёт и снимается после самого медленного из fetch/arrayBuffer.
		// Прерванный запрос падает в catch ниже и в кэш не пишется.
		const 控制器 = new AbortController();
		const 定时器 = setTimeout(() => 控制器.abort(), 超时毫秒);
		try {
			const 编码域名 = (name) => {
				const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
				const bufs = [];
				for (const label of parts) {
					const enc = new TextEncoder().encode(label);
					bufs.push(new Uint8Array([enc.length]), enc);
				}
				bufs.push(new Uint8Array([0]));
				const total = bufs.reduce((s, b) => s + b.length, 0);
				const result = new Uint8Array(total);
				let off = 0;
				for (const b of bufs) { result.set(b, off); off += b.length }
				return result;
			};
			const qname = 编码域名(规范化域名);
			const query = new Uint8Array(12 + qname.length + 4);
			const qview = new DataView(query.buffer);
			qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]);
			qview.setUint16(2, 0x0100);
			qview.setUint16(4, 1);
			query.set(qname, 12);
			qview.setUint16(12 + qname.length, qtype);
			qview.setUint16(12 + qname.length + 2, 1);
			log.调试(`[DoH查询] 发送查询报文 ${域名} via ${DoH解析服务} (type=${qtype}, ${query.length}字节)`);
			const response = await fetch(DoH解析服务, {
				method: 'POST',
				headers: { 'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message' },
				body: query,
				signal: 控制器.signal,
			});
			if (!response.ok) {
				// P2.4 (фикс 5): HTTP-ошибка — сбой, а не «пусто». Раньше здесь
				// был log.调试 + return [] — от NXDOMAIN не отличалось, и резолвер,
				// который отдаёт 5xx, выглядел как «домена нет».
				log.错误(`[DoH查询] 请求失败 ${域名} ${记录类型} via ${DoH解析服务} 响应代码:${response.status}`);
				写入失败缓存(缓存键);
				throw new Error(`DoH查询失败: ${域名} ${记录类型} HTTP ${response.status} via ${DoH解析服务}`);
			}
			const buf = new Uint8Array(await response.arrayBuffer());
			const dv = new DataView(buf.buffer);
			const qdcount = dv.getUint16(4);
			const ancount = dv.getUint16(6);
			// P1.8: rcode — младшие 4 бита второго 16-битного слова заголовка.
			// Раньше не читался вовсе, и ошибка резолвера была неотличима от
			// «NXDOMAIN»: обе попадали в кэш на 5 минут.
			const rcode = dv.getUint16(2) & 0x0f;
			log.调试(`[DoH查询] 收到响应 ${域名} ${记录类型} via ${DoH解析服务} (${buf.length}字节, rcode=${rcode}(${RCODE名称(rcode)}), ${ancount}条应答)`);
			// P2.4 (фикс 5): ошибки резолвера — сбой, а не «пусто». SERVFAIL,
			// REFUSED, FORMERR, NOTIMP, NOTAUTH говорят о беде самого резолвера:
			// это не «домена нет», повтор в ближайшие секунды не поможет. Раньше
			// они возвращались как [] (P1.8 их просто не кэшировал) — от NXDOMAIN
			// в логах не отличались, и клиент видел «домена нет» при живом домене.
			// Теперь: исключение DoH查询失败 + короткий кэш сбоя (5–10 с).
			if (rcode !== 0 && rcode !== 3) {
				写入失败缓存(缓存键);
				throw new Error(`DoH查询失败: ${域名} ${记录类型} rcode=${rcode}(${RCODE名称(rcode)}) via ${DoH解析服务}`);
			}
			const 解析域名 = (pos) => {
				const labels = [];
				let p = pos, jumped = false, endPos = -1, safe = 128;
				while (p < buf.length && safe-- > 0) {
					const len = buf[p];
					if (len === 0) { if (!jumped) endPos = p + 1; break }
					if ((len & 0xC0) === 0xC0) {
						if (!jumped) endPos = p + 2;
						p = ((len & 0x3F) << 8) | buf[p + 1];
						jumped = true;
						continue;
					}
					labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
					p += len + 1;
				}
				if (endPos === -1) endPos = p + 1;
				return [labels.join('.'), endPos];
			};
			let offset = 12;
			for (let i = 0; i < qdcount; i++) {
				const [, end] = 解析域名(offset);
				offset = /** @type {number} */ (end) + 4;
			}
			const answers = [];
			for (let i = 0; i < ancount && offset < buf.length; i++) {
				const [name, nameEnd] = 解析域名(offset);
				offset = /** @type {number} */ (nameEnd);
				const type = dv.getUint16(offset); offset += 2;
				offset += 2;
				const ttl = dv.getUint32(offset); offset += 4;
				const rdlen = dv.getUint16(offset); offset += 2;
				const rdata = buf.slice(offset, offset + rdlen);
				offset += rdlen;
				let data;
				if (type === 1 && rdlen === 4) {
					data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
				} else if (type === 28 && rdlen === 16) {
					const segs = [];
					for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
					data = segs.join(':');
				} else if (type === 16) {
					let tOff = 0;
					const parts = [];
					while (tOff < rdlen) {
						const tLen = rdata[tOff++];
						parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen)));
						tOff += tLen;
					}
					data = parts.join('');
				} else if (type === 5) {
					const [cname] = 解析域名(offset - rdlen);
					data = cname;
				} else {
					data = Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join('');
				}
				answers.push({ name, type, TTL: ttl, data, rdata });
			}
			const 耗时 = (performance.now() - 开始时间).toFixed(2);
			log.调试(`[DoH查询] 查询完成 ${域名} ${记录类型} via ${DoH解析服务} ${耗时}ms 共${answers.length}条结果`);
			const 相关记录 = answers.filter(answer => answer.type === qtype);
			const 最小TTL = 相关记录.length > 0 ? Math.min(...相关记录.map(a => a.TTL)) : 0;
			const 有数据 = 相关记录.length > 0;
			// P1.8: отрицательный ответ кэшируется только если он честный.
			// NXDOMAIN (3) и NOERROR (0) без записей — это «домена нет», и повтор
			// имеет смысл. Ошибка резолвера (SERVFAIL/REFUSED/FORMERR/NOTIMP) — нет:
			// это его собственная беда, и она проходит, а кэш живёт 5 минут.
			const 可缓存 = 有数据 || rcode === 0 || rcode === 3;
			// TTL для отрицательного ответа короче: SOA.MINIMUM обычно 60..300 с,
			// а пять минут вслепую — ровно то, на что и жаловались.
			const 缓存TTL = 有数据 ? Math.max(最小TTL, 60) : 30;
			const 缓存过期时间 = Date.now() + 缓存TTL * 1000;
			const 缓存数据 = 相关记录.map(answer => answer.data);
			if (可缓存) {
				if (Object.keys(DoH缓存).length >= DoH缓存最大条目) {
					const 清理时间戳 = Date.now();
					for (const [缓存条目键, 缓存条目] of Object.entries(DoH缓存)) {
						if (清理时间戳 >= 缓存条目.过期时间) delete DoH缓存[缓存条目键];
					}
					if (Object.keys(DoH缓存).length >= DoH缓存最大条目) {
						delete DoH缓存[Object.keys(DoH缓存)[0]];
					}
				}
				DoH缓存[缓存键] = { data: 缓存数据, 过期时间: 缓存过期时间 };
				log.调试(`[DoH查询] 写入缓存 ${域名} ${记录类型} TTL=${缓存TTL}s${有数据 ? '' : `（负缓存, rcode=${rcode}）`}`);
			}
			return answers;
		} catch (error) {
			const 耗时 = (performance.now() - 开始时间).toFixed(2);
			// P2.4 (фикс 5): таймаут/обрыв/сеть — сбой, а не «пусто». Раньше —
			// return [] на уровне 调试: резолвер мог лежать часами, а по логам это
			// выглядело как NXDOMAIN. Теперь сбой кэшируется на 5 с и падает
			// исключением; потребители различают его по DoH查询失败.
			log.错误(`[DoH查询] 查询失败 ${域名} ${记录类型} via ${DoH解析服务} ${耗时}ms:`, error);
			写入失败缓存(缓存键);
			const 原由 = error instanceof Error ? error.message : String(error);
			throw new Error(`DoH查询失败: ${域名} ${记录类型} via ${DoH解析服务} (${原由})`);
		} finally {
			clearTimeout(定时器);
		}
	})();
	DoH进行中[缓存键] = 当前查询;
	try {
		return await 当前查询;
	} finally {
		// Запись из single-flight удаляется только после того, как все ждущие
		// получили результат: cache.js уже успел записать DoH缓存 к этому моменту,
		// следующий запрос пойдёт в кэш. Гонки «увидел до удаления, но после
		// резолва» нет: await уже держит resolved-обещание по ссылке.
		delete DoH进行中[缓存键];
	}
}

export async function 整理成数组(内容) {
	var 替换后的内容 = 内容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
	if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
	if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);
	const 地址数组 = 替换后的内容.split(',');
	return 地址数组;
}

/** FNV-1a 32-bit: детерминированная распределённая по ключу функция для HRW
 * (P1.3). Криптостойкость не нужна — важен стабильный разброс весов по ключу
 * и кандидату. Числовые операции — Math.imul, чтобы результат был ровно 32 бита. */
export function 哈希字符串(input) {
	let h = 0x811c9dc5;
	for (let i = 0; i < input.length; i++) {
		h ^= input.charCodeAt(i);
		h = Math.imul(h, 0x01000193);
	}
	return h >>> 0;
}

export async function 解析地址端口(proxyIP, 目标域名 = 'dash.cloudflare.com', UUID = '00000000-0000-4000-8000-000000000000') {
	proxyIP = proxyIP.toLowerCase();
	function 解析地址端口字符串(str) {
		let 地址 = str, 端口 = 443;
		if (str.includes(']:')) {
			const parts = str.split(']:');
			地址 = parts[0] + ']';
			端口 = parseInt(parts[1], 10) || 端口;
		} else if ((str.match(/:/g) || []).length === 1 && !str.startsWith('[')) {
			const colonIndex = str.lastIndexOf(':');
			地址 = str.slice(0, colonIndex);
			端口 = parseInt(str.slice(colonIndex + 1), 10) || 端口;
		}
		return [地址, 端口];
	}
	function 解析TXT反代记录(txtData) {
		return txtData.flatMap(data => {
			if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
			return data.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
		}).map(prefix => 解析地址端口字符串(prefix));
	}
	const 反代IP数组 = await 整理成数组(proxyIP);
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
	const ipv6Regex = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;
	// P2.4 (фикс 4): домены резолвятся ПАРАЛЛЕЛЬНО, а не по очереди. Раньше
	// длинный список PROXYIP стоял клиенту последовательно: каждый домен — до
	// 3 × DoH (TXT+A+AAAA) с таймаутом 1.2с, пока не соберётся результат.
	// Теперь все домены идут разом (single-flight P1.1 дублей не даёт), а
	// порядок кандидатов восстанавливает HRW-сортировка ниже (вес + адрес).
	const 各域名结果 = await Promise.all(反代IP数组.map(async (singleProxyIP) => {
		let [地址, 端口] = 解析地址端口字符串(singleProxyIP);
		if (singleProxyIP.includes('.tp')) {
			const tpMatch = singleProxyIP.match(/\.tp(\d+)/);
			if (tpMatch) 端口 = parseInt(tpMatch[1], 10);
		}
		if (ipv4Regex.test(地址) || ipv6Regex.test(地址)) {
			log.调试(`[反代解析] ${地址} 为IP地址，直接使用`);
			return [[地址, 端口]];
		}
		// P1.1: AAAA-запрос идёт ПАРАЛЛЕЛЬНО с TXT и A, а не после их пустоты.
		// Раньше третий DNS-запрос стартовал только когда TXT и A оба пустые:
		// это лишний RTT (и лишний таймаут при висящем резолвере) на в каждом
		// разрешении. Три запроса начинаются разом, третьим типом пользуемся по
		// необходимости — попытка дозвона от этого не тормозится, single-flight
		// (P1.1) дублей не даёт.
		try {
			const [txtRecords, aRecords, aaaaRecords] = await Promise.all([DoH查询(地址, 'TXT'), DoH查询(地址, 'A'), DoH查询(地址, 'AAAA')]);
			const txtData = txtRecords.filter(r => r.type === 16).map(r => (r.data));
			const txtAddresses = 解析TXT反代记录(txtData);
			if (txtAddresses.length > 0) {
				log.调试(`[反代解析] ${地址} 使用TXT记录，共${txtAddresses.length}个结果`);
				return txtAddresses;
			}
			const ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
			if (ipv4List.length > 0) {
				log.调试(`[反代解析] ${地址} 未获取到TXT记录，使用A记录，共${ipv4List.length}个结果`);
				return ipv4List.map(ip => [ip, 端口]);
			}
			const ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
			if (ipv6List.length > 0) {
				log.调试(`[反代解析] ${地址} 未获取到TXT和A记录，使用AAAA记录，共${ipv6List.length}个结果`);
				return ipv6List.map(ip => [ip, 端口]);
			}
			log.调试(`[反代解析] ${地址} 未获取到TXT、A和AAAA记录，保留原域名`);
			return [[地址, 端口]];
		} catch (error) {
			// P2.4 (фикс 5): сбой резолвера ≠ «пусто». Раньше DoH возвращал [] и
			// на таймаут, и на NXDOMAIN — обе ветки молча сводились к этой строке.
			// Теперь сбой падает сюда с исключением DoH查询失败: логируем отдельно
			// (видно в [反代解析], что именно резолвер лежал), а домен оставляем
			// кандидатом — платформа при дозвоне резолвит его сама. Короткий кэш
			// сбоя (5–10 с) не даст молотить резолвер на каждое соединение.
			log.错误(`[反代解析] ${地址} 解析失败（резолвер недоступен）: ${error?.message || error}`);
			return [[地址, 端口]];
		}
	}));
	const 所有反代数组 = 各域名结果.flat();
	const 目标根域名 = 目标域名.includes('.') ? 目标域名.split('.').slice(-2).join('.') : 目标域名;
	// P1.3: HRW (rendezvous hashing) вместо seed-перемешивания. Перемешивание
	// Фишера–Йетса (введённое в P4.6 против смещённого sort() со случайным
	// компаратором) делало порядок кандидатов равновероятным: кто первый — был
	// случаен, «лучшего» не существовало. Вес хэша каждого кандидата по ключу
	// (目标根域名|UUID|地址:端口) даёт стабильный приоритет: для одного целевого
	// сайта один и тот же кандидат всегда пробуется первым, нагрузка между
	// репликами распределяется ключом, порядок не зависит от порядка во входном
	// списке. Равенство весов добивается адресом — детерминизм и тут.
	const 候选加权 = 所有反代数组.map(([地址, 端口]) => ({ 地址, 端口, 权重: 哈希字符串(`${目标根域名}|${UUID}|${地址}:${端口}`) }));
	候选加权.sort((a, b) => (b.权重 - a.权重) || a.地址.localeCompare(b.地址));
	const 解析结果 = 候选加权.slice(0, 8).map(({ 地址, 端口 }) => [地址, 端口]);
	log.调试(`[反代解析] 解析完成（HRW） 总数: ${解析结果.length}个\n${解析结果.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
	return 解析结果;
}


