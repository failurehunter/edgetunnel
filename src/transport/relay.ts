// @ts-nocheck
// Фаза 3, Шаг 3.8: relay — поколения TCP-соединения, forwardataTCP, downlink-отправитель.
// from worker.ts — function-in-function, behavior preserved.
//
// Relay владеет 已通过代理发送首包 и поставляет canRetry() в очередь (фаза 2).
// Лог → console (telemetry остаётся шагом 11).
//
// ИЗВЕСТНОЕ ОТКЛОНЕНИЕ (исправлено в шаге 3.10, config.ts): env-флаги изолята
// 反代并发拨号数 / 预加载竞速拨号 раньше жили в worker.ts. Чтобы не заводить
// circular import (relay → worker), их владельцем стал relay.ts, а worker.ts
// пишет их через 应用拨号环境(). Значения и момент записи не изменились.
// SOCKS5白名单 тоже переехал сюда в 3.8, но в 3.10 вернулся в config.ts
// (это значение конфига, а не dial-настройка) — отсюда он импортируется.

import { 有效数据长度, 数据转Uint8Array, isIPHostname, isIPv4 } from "../util";
import { DoH查询, 解析地址端口 } from "../dns";
import { 特征码字典 } from "../obfuscation-tokens";
import { 创建请求TCP连接器, 连接木马反代, 提取木马反代握手数据, socks5Connect, httpConnect, httpsConnect, turnConnect, sstpConnect } from "../upstream/dial";
import { 创建Grain收纳器, 下行Grain包字节, 下行Grain尾部阈值, 下行Grain低水位字节, 下行Grain最大等待轮次 } from "./grain";
import { 取SOCKS5白名单 } from "../config";
import { 创建日志器, 安全错误 } from "../logging";
const log = 创建日志器('relay');

// Флаги изолята, ранее объявленные в worker.ts (строка 16).
// P1.10: модульных накапливаемых переменных больше нет. Значения по
// умолчанию живут здесь как константы для вызовов БЕЗ контекста запроса
// (тесты, опциональные аргументы); обычный путь берёт их из settings.
const 默认拨号并发数 = 2, 默认反代并发数 = 1;
const 默认预加载竞速 = false;

// Вызывается из fetch-обработчика worker.ts на прежнем месте (строки 63-64).
export function 失效TCP连接世代(remoteConnWrapper) {
	if (!remoteConnWrapper) return;
	remoteConnWrapper.generation = (Number.isInteger(remoteConnWrapper.generation) ? remoteConnWrapper.generation : 0) + 1;
	const socket = remoteConnWrapper.socket;
	remoteConnWrapper.socket = null;
	remoteConnWrapper.downlinkController = null;
	remoteConnWrapper.downlinkDrain = Promise.resolve();
	try { socket?.close?.() } catch (e) { }
}

export function 开始TCP连接世代(remoteConnWrapper) {
	if (!Number.isInteger(remoteConnWrapper.generation)) remoteConnWrapper.generation = 0;
	const generation = ++remoteConnWrapper.generation;
	const previousSocket = remoteConnWrapper.socket;
	remoteConnWrapper.socket = null;
	const previousDownlink = remoteConnWrapper.downlinkController;
	remoteConnWrapper.downlinkController = null;
	const previousDrain = remoteConnWrapper.downlinkDrain || Promise.resolve();
	let currentDrain;
	try { currentDrain = previousDownlink?.停止并刷新?.() || Promise.resolve() }
	catch (error) { currentDrain = Promise.reject(error) }
	const downlinkDrain = Promise.all([previousDrain, currentDrain]);
	// Installation awaits this promise; attach a handler immediately in case draining fails before dialing completes.
	downlinkDrain.catch(() => { });
	remoteConnWrapper.downlinkDrain = downlinkDrain;
	try { previousSocket?.close?.() } catch (e) { }
	return { generation, downlinkDrain };
}


export function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
			socket.close();
		}
	} catch (error) { }
}

export async function WebSocket发送并等待(webSocket, payload) {
	const sendResult = webSocket.send(payload);
	if (sendResult && typeof sendResult.then === 'function') await sendResult;
}

export async function forwardataTCP({
	host,
	portNum,
	rawData,
	ws,
	respHeader,
	remoteConnWrapper,
	yourUUID,
	request = null,
	反代上下文 = {},
	允许木马反代 = false,
	木马反代首包数据 = null,
	仅建立连接 = false,
	请求上下文 = null,
}) {
	const ctx反代IP = 反代上下文.反代IP || '';
	const ctx代理类型 = 反代上下文.代理类型 !== undefined ? 反代上下文.代理类型 : null;
	const ctx代理全局 = 反代上下文.代理全局 !== undefined ? 反代上下文.代理全局 : false;
	const ctx代理参数 = 反代上下文.代理参数 || {};
	// P2.1: мёртвый фолбэк «兜底» удалён. После P2 (дефолт false) ветка
	// `connectDirect(<словарь0>.tp1.<словарь1>.xyz, 1)` не достигалась ни одним
	// путём: 反代默认设置 отдаёт false, 反代参数获取 и параметры URL его не ставят.
	// Оставлять ветку — держать мёртвый код, писавший на порт 1 заведомо
	// проигрышную попытку после отказа всех кандидатов.
	log.调试(`[TCP转发] 目标: ${host}:${portNum} | 反代IP: ${ctx反代IP} | 反代类型: ${ctx代理类型 || 'proxyip'} | 全局: ${ctx代理全局 ? '是' : '否'}`);
	const 连接超时毫秒 = 1000;
	// P1.10: настройки берутся из контекста запроса; без него — умолчания.
	const 拨号设置 = {
		反代并发数: 请求上下文?.settings?.proxyConcurrency ?? 默认反代并发数,
		预加载竞速: 请求上下文?.settings?.preloadRace ?? 默认预加载竞速,
	};
	// P1.2: единственный источник истины — сколько байт РЕАЛЬНО записано в
	// апстрим. Прежний флаг 已通过代理发送首包 ставился только в прокси-ветке,
	// а прямой путь писал первый пакет через connectDirect, флаг не трогал, и
	// canRetry首包() навсегда оставалась true. Тогда падение записи следующего
	// чанка приводило к повтору «первый пакет + текущий чанк» на новом сокете:
	// промежуточные байты терялись, поток клиента рвался молча.
	let 已发送上游字节数 = 0;
	/** Записать факт отправки. Вызывается из всех путей, пишущих в апстрим. */
	const 记录发送 = (字节数) => { 已发送上游字节数 += Math.max(0, 有效数据长度(字节数)); };
	if (remoteConnWrapper) remoteConnWrapper.canRetry首包 = () => 已发送上游字节数 === 0;
	// P0.2: тот же счётчик доходит до очереди аплинка. Без этого первая посылка
	// (写入首包) учитывалась, а вся полезная нагрузка после неё — нет: если
	// первый пакет был пустым/заголовком, счётчик навсегда оставался 0, и
	// canRetry() разрешал переиграть часть потока на новом апстриме, который
	// ранее отправленных байт не видел. Хук зовётся очередью только после
	// успешной записи, поэтому счётчик = реально ушедшим байтам.
	if (remoteConnWrapper) remoteConnWrapper.记发送 = (数据) => 记录发送(数据);
	const TCP连接 = 请求上下文?.dial || 创建请求TCP连接器(request);
	// Шаг 1.1: 并发拨号 берётся из RequestContext.settings (фолбэк — глобал для
	// вызовов без контекста); cmcc-пин удалён — оператор не урезает до 1.
	const 拨号并发数 = 请求上下文?.settings?.dialConcurrency ?? 默认拨号并发数;
	const 使用木马反代 = 允许木马反代 && (反代上下文.木马反代地址 || null);
	const 木马反代目标 = 使用木马反代 ? 反代上下文.木马反代地址 : null;
	const 木马反代握手数据 = 使用木马反代 ? 提取木马反代握手数据(木马反代首包数据, rawData) : null;
	let 待发送响应头 = respHeader;
	const 取出响应头 = () => {
		const header = 待发送响应头;
		待发送响应头 = null;
		return header;
	};
	if (!Number.isInteger(remoteConnWrapper.generation)) remoteConnWrapper.generation = 0;

	const 安装当前连接 = async (socket, generation, downlinkDrain, retryFunc = null) => {
		try { await downlinkDrain } catch (e) {
			if (remoteConnWrapper.downlinkDrain === downlinkDrain) remoteConnWrapper.downlinkDrain = Promise.resolve();
			try { socket?.close?.() } catch (_) { }
			if (remoteConnWrapper.generation === generation) closeSocketQuietly(ws);
			throw e;
		}
		if (remoteConnWrapper.downlinkDrain === downlinkDrain) remoteConnWrapper.downlinkDrain = Promise.resolve();
		const 连接仍有效 = () => remoteConnWrapper.generation === generation && remoteConnWrapper.socket === socket;
		if (remoteConnWrapper.generation !== generation || ws.readyState !== WebSocket.OPEN) {
			try { socket?.close?.() } catch (e) { }
			if (remoteConnWrapper.generation === generation) remoteConnWrapper.socket = null;
			throw new Error('connection superseded or client closed');
		}
		remoteConnWrapper.socket = socket;
		if (仅建立连接) return socket;
		connectStreams(socket, ws, 取出响应头, retryFunc, 连接仍有效, remoteConnWrapper).catch(err => {
			if (!连接仍有效()) return;
			log.错误(`[TCP下行] 处理失败: ${安全错误(err)}`);
			try { socket?.close?.() } catch (e) { }
			closeSocketQuietly(ws);
		});
		return true;
	};

	async function 等待连接建立(remoteSock, timeoutMs = 连接超时毫秒) {
		// P1.9: таймер снимается, как только соединение установилось или упало.
		// Раньше он жил полную секунду после каждого успешного подключения —
		// на потоке соединений это живые таймеры, удерживающие изолят.
		let 定时器 = null;
		try {
			await Promise.race([
				remoteSock.opened,
				new Promise((_, reject) => { 定时器 = setTimeout(() => reject(new Error('连接超时')), timeoutMs); }),
			]);
		} finally {
			if (定时器) clearTimeout(定时器);
		}
	}

	async function 打开TCP连接(address, port) {
		const remoteSock = TCP连接({ hostname: address, port });
		try {
			await 等待连接建立(remoteSock);
			return remoteSock;
		} catch (err) {
			try { remoteSock?.close?.() } catch (e) { }
			throw err;
		}
	}

	async function 写入首包(remoteSock, data) {
		if (有效数据长度(data) <= 0) return;
		const writer = remoteSock.writable.getWriter();
		try {
			await writer.write(数据转Uint8Array(data));
			// P1.2: счётчик двигается здесь, а не в ветке прокси. Прямой путь
			// писал первый пакет мимо флага, из-за чего повтор считался
			// допустимым после того, как байты уже ушли.
			记录发送(data);
		} finally { try { writer.releaseLock() } catch (e) { } }
	}

	async function 并发打开候选连接(候选列表) {
		if (候选列表.length === 1) {
			const 候选 = 候选列表[0];
			return { socket: await 打开TCP连接(候选.hostname, 候选.port), candidate: 候选 };
		}
		// Причина отказа каждой попытки сохраняется, но rejection остаётся
		// rejection'ом. Превращать ошибку в fulfillment нельзя: Promise.any
		// берёт первый fulfilled, и ранний отказ «победил» бы ещё не успевшее
		// установиться успешное соединение (гонка), а его сокет после этого
		// закрылся бы в finally как «лузер»: у winner с ошибкой нет socket,
		// и любой настоящий сокет не равен undefined.
		const 各候选错误 = [];
		const attempts = 候选列表.map(候选 =>
			打开TCP连接(候选.hostname, 候选.port)
				.then(socket => ({ socket, candidate: 候选 }))
				.catch(err => { 各候选错误.push(err); throw err; })
		);
		let winner = null;
		try {
			winner = await Promise.any(attempts);
			return winner;
		} catch (聚合错误) {
			// Все попытки отказали: отдаём первую сохранённую причину.
			// Promise.any сам отдал бы AggregateError «All promises were
			// rejected» — бессмыслицу вместо настоящей причины (например
			// «预加载解析为空» или getaddrinfo), и диагностика была бы слепой.
			if (各候选错误.length) throw 各候选错误[0];
			throw 聚合错误;
		} finally {
			if (winner) {
				for (const attempt of attempts) {
					attempt.then(({ socket }) => {
						if (socket !== winner.socket) {
							try { socket?.close?.() } catch (e) { }
						}
					}).catch(() => { });
				}
			}
		}
	}

	async function 构建预加载竞速候选列表(address, port) {
		if (!拨号设置.预加载竞速 || isIPHostname(address)) return null;
		log.调试(`[TCP直连] 预加载竞速拨号开启，开始并发查询 ${address} 的 A/AAAA 记录`);
		const [aRecords, aaaaRecords] = await Promise.all([
			DoH查询(address, 'A'),
			DoH查询(address, 'AAAA')
		]);
		const ipv4List = [...new Set(aRecords.flatMap(r => {
			const data = r.data;
			return r.type === 1 && typeof data === 'string' && isIPv4(data) ? [data] : [];
		}))];
		const ipv6List = [...new Set(aaaaRecords.flatMap(r => {
			const data = r.data;
			return r.type === 28 && typeof data === 'string' && isIPHostname(data) ? [data] : [];
		}))];
		const 拨号上限 = Math.max(1, 拨号并发数);
		const ipList = ipv4List.length >= 拨号上限
			? ipv4List.slice(0, 拨号上限)
			: ipv4List.concat(ipv6List.slice(0, 拨号上限 - ipv4List.length));
		const 使用记录类型 = ipv4List.length > 0
			? (ipList.length > ipv4List.length ? 'A+AAAA' : 'A')
			: 'AAAA';
		if (ipList.length === 0) {
			log.调试(`[TCP直连] ${address} 的 A/AAAA 未获得可用解析结果，预加载竞速不可用，回退到原始 hostname 直连。`);
			return null;
		}
		const 选中IP列表 = ipList;
		log.调试(`[TCP直连] ${address} A记录:${ipv4List.length} AAAA记录:${ipv6List.length}，使用${使用记录类型}记录，竞速拨号 ${选中IP列表.length}/${拨号上限}: ${选中IP列表.join(', ')}`);
		return 选中IP列表.map((hostname, attempt) => ({ hostname, port, attempt, resolvedFrom: address }));
	}

	async function connectDirect(address, port, data = null, 启用预加载 = false) {
		const 预加载候选列表 = 启用预加载 ? await 构建预加载竞速候选列表(address, port) : null;
		const 候选列表 = 预加载候选列表 || Array.from({ length: 拨号并发数 }, (_, attempt) => ({ hostname: address, port, attempt }));
		log.信息(预加载候选列表
			? `[TCP直连] 并发尝试 ${候选列表.length} 路: ${候选列表.map(候选 => `${候选.hostname}:${候选.port}`).join(', ')}`
			: `[TCP直连] 并发尝试 ${候选列表.length} 路: ${address}:${port}`);
		let socket = null;
		try {
			const 连接结果 = await 并发打开候选连接(候选列表);
			socket = 连接结果.socket;
			if (预加载候选列表) {
				const winner = 连接结果.candidate;
				log.调试(`[TCP直连] 预加载竞速结果: ${winner.hostname}:${winner.port} 胜出，源域名: ${winner.resolvedFrom || address}`);
			}
			await 写入首包(socket, data);
			return socket;
		} catch (err) {
			try { socket?.close?.() } catch (e) { }
			if (预加载候选列表) log.错误(`[TCP直连] 预加载竞速失败: ${安全错误(err, [address])}`);
			throw err;
		}
	}

	async function connectProxyIP(address, port, data = null, 所有反代数组 = null) {
		if (所有反代数组 && 所有反代数组.length > 0) {
			const 实际并发数 = 拨号设置.反代并发数;
			for (let i = 0; i < 所有反代数组.length; i += 实际并发数) {
				const 候选列表 = [];
				for (let j = 0; j < 实际并发数 && i + j < 所有反代数组.length; j++) {
					// P2.2: сдвиг 反代数组索引 убран. Раньше после успеха номер
					// кандидата запоминался и следующий заход начинался с него.
					// С P1.3 массив уже упорядочен HRW — «лучший для ключа» первый,
					// и перезапуск с последнего использованного противоречит
					// приоритету: после «принял и закрыл без данных» ретрай
					// (P0.1) шёл на тот же подозрительный кандидат и повторял
					// оборванный поток вместо свежего лучшего. Сканирование всегда
					// начинается с начала списка.
					const 索引 = (i + j) % 所有反代数组.length;
					const [反代地址, 反代端口] = 所有反代数组[索引];
					候选列表.push({ hostname: 反代地址, port: 反代端口, index: 索引 });
				}
				let socket = null, candidate = null;
				try {
					log.调试(`[反代连接] 并发尝试 ${候选列表.length} 路: ${候选列表.map(候选 => `${候选.hostname}:${候选.port}`).join(', ')}`);
					const 连接结果 = await 并发打开候选连接(候选列表);
					socket = 连接结果.socket;
					candidate = 连接结果.candidate;
					await 写入首包(socket, data);
					log.信息(`[反代连接] 成功连接到: ${candidate.hostname}:${candidate.port} (索引: ${candidate.index})`);
					return socket;
				} catch (err) {
					try { socket?.close?.() } catch (e) { }
					log.错误(`[反代连接] 本批连接失败: ${安全错误(err, [address, port])}`);
				}
			}
		}

		// P2.1: мёртвая ветка фолбэка удалена — единственный исход после отказа
		// всех кандидатов: соединение невозможно.
		throw new Error('[反代连接] 所有反代连接失败，连接终止。');
	}

	// P2: 原始原因 нужна для диагностики. Раньше она терялась по дороге: каждый
	// вызов connecttoPry шёл из места, где причина отказа прямого пути уже была
	// известна, но внутрь не передавалась, и пользователь видел следствие
	// («反代未启用») вместо причины. Причина пуста при прямом вызове без отказа.
	async function connecttoPry(允许发送首包 = true, 原始原因 = null) {
		if (remoteConnWrapper.connectingPromise) {
			await remoteConnWrapper.connectingPromise;
			return;
		}
		const { generation: 当前连接世代, downlinkDrain } = 开始TCP连接世代(remoteConnWrapper);

		let 本次发送首包 = false, 本次首包数据 = null;
		// P0.1: переигрывать первый пакет разрешено не только когда апстрим
		// ничего не получил (=== 0), но и когда ушёл РОВНО первый пакет и ничего
		// сверх (=== 有效数据长度(rawData)). Второй случай — режим «принял и
		// закрыл без данных»: ретрай no-data (connectStreams, ветка !hasData)
		// уводит поток на обратный путь, и если первый пакет не переслать,
		// новый апстрим не получит запрос — клиент висит. Клиент при этом
		// гарантированно не получил ни байта (ретрай зовётся только из !hasData),
		// а счётчик после 写入首包 равен ровно длине первого пакета; любые чанки
		// очереди (P0.2, 记录成功发送) делают его БОЛЬШЕ — тогда переигрывание
		// запрещено, иначе новый апстрим увидит разорванный поток.
		const 允许重演首包 = 允许发送首包 && (已发送上游字节数 === 0 || 已发送上游字节数 === 有效数据长度(rawData));
		if (使用木马反代) {
			if (允许重演首包 && 有效数据长度(木马反代首包数据) > 0) {
				本次首包数据 = 木马反代首包数据;
				本次发送首包 = 有效数据长度(rawData) > 0;
			} else {
				本次首包数据 = 木马反代握手数据;
			}
		} else {
			本次发送首包 = 允许重演首包 && 有效数据长度(rawData) > 0;
			本次首包数据 = 本次发送首包 ? rawData : null;
		}

		const 当前连接任务 = (async () => {
			let newSocket = null;
			// P2: флаг «первый пакет уже учтён» для веток с ВНУТРЕННИМ счётом.
			// Без него хвостовой счёт ниже учитывал бы байты второй раз: TURN/SSTP
			// и обратный путь уже вызвали 记录发送 в момент реальной записи, и
			// 已发送上游字节数 показывал 200 вместо реальных 100 (см. разбор
			// пользователя). Хвост считает только ветки, которые пишут пакет
			// внутри dial.ts и не имеют доступа к счётчику (Trojan, SOCKS5, HTTP).
			let 首包已计入 = false;
			try {
				if (使用木马反代) {
					log.调试(`[木马反代] 代理到: ${host}:${portNum}`);
					newSocket = await 连接木马反代(本次首包数据, TCP连接, 木马反代目标);
				} else if (ctx代理类型 === 'socks5') {
					log.调试(`[SOCKS5代理] 代理到: ${host}:${portNum}`);
					newSocket = await socks5Connect(host, portNum, 本次首包数据, TCP连接, ctx代理参数);
				} else if (ctx代理类型 === 'http') {
					log.调试(`[HTTP代理] 代理到: ${host}:${portNum}`);
					newSocket = await httpConnect(host, portNum, 本次首包数据, false, TCP连接, ctx代理参数);
				} else if (ctx代理类型 === 'https') {
					log.调试(`[HTTPS代理] 代理到: ${host}:${portNum}`);
					newSocket = isIPHostname(ctx代理参数.hostname)
						? await httpsConnect(host, portNum, 本次首包数据, TCP连接, ctx代理参数)
						: await httpConnect(host, portNum, 本次首包数据, true, TCP连接, ctx代理参数);
				} else if (ctx代理类型 === 'turn') {
					log.调试(`[TURN代理] 代理到: ${host}:${portNum}`);
					newSocket = await turnConnect(ctx代理参数, host, portNum, TCP连接);
					if (有效数据长度(本次首包数据) > 0) {
						const writer = newSocket.writable.getWriter();
						try {
							await writer.write(数据转Uint8Array(本次首包数据));
							记录发送(本次首包数据);
							首包已计入 = true;
						} finally { try { writer.releaseLock() } catch (e) { } }
					}
				} else if (ctx代理类型 === 'sstp') {
					log.调试(`[SSTP代理] 代理到: ${host}:${portNum}`);
					newSocket = await sstpConnect(ctx代理参数, host, portNum, TCP连接);
					if (有效数据长度(本次首包数据) > 0) {
						const writer = newSocket.writable.getWriter();
						try {
							await writer.write(数据转Uint8Array(本次首包数据));
							记录发送(本次首包数据);
							首包已计入 = true;
						} finally { try { writer.releaseLock() } catch (e) { } }
					}
				} else if (!ctx反代IP) {
					// P2: обратного пути нет — ни PROXYIP, ни параметр URL не задан,
					// а дефолт выключен.
					//
					// Раньше здесь стоял безусловный throw новой ошибки, и это была
					// ошибка: когда до строки доходил ПРЯМОЙ путь, его собственная
					// причина отказа (например «预加载解析为空») терялась, и в лог
					// уходило только следствие. Теперь причина, если она известна,
					// сохраняется: пользователь видит то, что произошло на самом
					// деле, а не следствие.
					//
					// Без гарда сюда попадал 整理成数组('') -> ['']: фиктивный кандидат,
					// DoH-запросы к пустому имени и connectDirect на порт 1.
					const причина = 原始原因 || new Error(`反代未启用：无反代地址且无代理类型（${host}:${portNum}）`);
					try { newSocket?.close?.() } catch (e) { }
					closeSocketQuietly(ws);
					throw причина;
				} else {
					log.调试(`[反代连接] 代理到: ${host}:${portNum}`);
					const 所有反代数组 = await 解析地址端口(ctx反代IP, host, yourUUID);
					newSocket = await connectProxyIP(`${特征码字典[0]}.tp1.${特征码字典[2]}.xyz`, 1, 本次首包数据, 所有反代数组);
					// Внутри connectProxyIP первый пакет уходит через 写入首包,
					// который сам двигает счётчик. Хвост ниже не должен считать
					// второй раз (в т.ч. при фолбэке connectProxyIP → connectDirect).
					首包已计入 = true;
				}
				await 安装当前连接(newSocket, 当前连接世代, downlinkDrain);
				// P1.2: тот же счётчик, что и на прямом пути. P2: только для веток
				// БЕЗ внутреннего счёта (Trojan/SOCKS5/HTTP/HTTPS пишут пакет в
				// dial.ts, где счётчика нет). TURN/SSTP/обратный путь уже посчитали
				// в момент реальной записи.
				if (本次发送首包 && !首包已计入) 记录发送(本次首包数据);
			} catch (err) {
				try { newSocket?.close?.() } catch (e) { }
				if (remoteConnWrapper.generation === 当前连接世代) {
					remoteConnWrapper.socket = null;
					closeSocketQuietly(ws);
					throw err;
				}
				// P1.3: поколение сменилось, но это НЕ одно и то же.
				//
				//   * вытеснила более новая попытка — глотать правильно, исход
				//     выдаст она, наш провал не важен;
				//   * сессию инвалидировали или закрыли (teardown, клиент ушёл) —
				//     новой попытки не будет, а раньше мы отчитывались успехом
				//     и вызывающий шёл дальше с socket === null.
				//
				// `active` есть у UpstreamSession. Для «голого» литерала (тесты)
				// свойства нет — там остаётся прежнее поведение, судить не о чем.
				const сессияЖива = typeof remoteConnWrapper.active === 'boolean'
					? remoteConnWrapper.active
					: true;
				if (!сессияЖива) {
					// Сессия мертва: успеха нет, отчитываемся отказом.
					throw err;
				}
				log.调试('[连接] попытка вытеснена более новой, ошибка отброшена');
			}
		})();

		remoteConnWrapper.connectingPromise = 当前连接任务;
		try {
			await 当前连接任务;
		} finally {
			if (remoteConnWrapper.connectingPromise === 当前连接任务) {
				remoteConnWrapper.connectingPromise = null;
			}
		}
	}
	// P1.2: 允许发送首包 выводится из счётчика, а не из отдельного флага —
	// иначе повтор после отправки первого пакета опять разрешался бы.
	remoteConnWrapper.retryConnect = async () => connecttoPry(已发送上游字节数 === 0);

	if (ctx代理类型 && (ctx代理全局 || 取SOCKS5白名单(请求上下文?.settings?.whiteList).some(p => new RegExp(`^${p.replace(/\*/g, '.*')}$`, 'i').test(host)))) {
		log.信息(`[TCP转发] 启用 SOCKS5/HTTP/HTTPS/TURN/SSTP 全局代理`);
		try {
			await connecttoPry();
			if (仅建立连接) return remoteConnWrapper.socket;
		} catch (err) {
			log.错误(`[TCP转发] SOCKS5/HTTP/HTTPS/TURN/SSTP 代理连接失败: ${安全错误(err, [host, portNum])}`);
			throw err;
		}
	} else {
		let 直连世代 = remoteConnWrapper.generation;
		// P1.4: замер времени до сигнала отказа прямого пути. Тип (таймаут vs
		// ошибка vs закрытие без данных) и задержка логируются на debug:
		// это единственные данные, по которым решается ipset-классификатор
		// (P3.1) — «прямой отказ мгновенный по ошибке или висит до таймаута».
		const 直连开始时间 = performance.now();
		try {
			log.调试(`[TCP转发] 尝试直连到: ${host}:${portNum}`);
			const 世代连接 = 开始TCP连接世代(remoteConnWrapper);
			直连世代 = 世代连接.generation;
			// P2: флаг передаётся из настройки, а не литералом `true`. Литерал был
			// ложным: читатель видел «direct всегда с прелоадом» и понимал это как
			// «всегда DoH→IP». На деле DoH-ветка внутри 构建预加载竞速候选列表
			// гейтится на 拨号设置.预加载竞速 (дефолт false), и литерал `true` не
			// менял поведение — только запускал холостой вызов конструктора списка.
			// Теперь вызов отражает фактическое решение: preload включается ровно
			// тогда, когда включён, и обычный path = connect(hostname:port) без DoH.
			const initialSocket = await connectDirect(host, portNum, rawData, 拨号设置.预加载竞速);
			await 安装当前连接(initialSocket, 直连世代, 世代连接.downlinkDrain, async () => {
				if (remoteConnWrapper.generation !== 直连世代 || remoteConnWrapper.socket !== initialSocket) return;
				await connecttoPry();
			});
			if (仅建立连接) return initialSocket;
		} catch (err) {
			// P2: уровень возвращён с 调试 на 错误. Классификатор П1.1 опустил строку
			// на debug из-за подстановки адреса — и спрятал единственное сообщение,
			// ради которого смотрят лог: ПОЧЕМУ не соединилось. Адрес при этом
			// редактируется, поэтому требование «адреса не логируются по умолчанию»
			// соблюдается. Диагностика здесь важнее косметики приватности: без
			// причины отказа в логе видно только следствие.
			log.错误(`[TCP转发] 直连失败: ${安全错误(err, [host, String(portNum)])}`);
			// P1.4: тип сигнала отказа + задержка до него, без адресов. Таймаут —
			// собственный таймер 等待连接建立 (сообщение «连接超时»); всё остальное —
			// ошибка соединения (getaddrinfo, RST и т.п.). Замер считает время от
			// начала прямого дозвона до появления сигнала.
			const 直连耗时 = Math.round(performance.now() - 直连开始时间);
			const 是超时 = err instanceof Error && err.message === '连接超时';
			log.调试(`[TCP直连] сигнал отказа: ${是超时 ? 'таймаут' : 'ошибка'}, спустя ${直连耗时}мс`);
			if (remoteConnWrapper.generation !== 直连世代) throw err;
			if (err instanceof Error && err.name === '预加载解析为空') {
				closeSocketQuietly(ws);
				throw err;
			}
			if (ws.readyState !== WebSocket.OPEN) throw err;
			// P2: причина отказа прямого пути передаётся дальше, иначе при
			// отсутствии обратного пути в лог уходит только следствие.
			await connecttoPry(true, err);
			if (仅建立连接) return remoteConnWrapper.socket;
		}
	}
}


export function 创建下行Grain发送器(webSocket, headerData = null, isActive = null) {
	const packetCap = 下行Grain包字节;
	const tailBytes = 下行Grain尾部阈值;
	const grain = 创建Grain收纳器(packetCap, true);
	let header = typeof headerData === 'function' ? null : headerData;
	const 获取响应头 = typeof headerData === 'function' ? headerData : () => {
		const value = header;
		header = null;
		return value;
	};
	let flushTimer = null;
	let generation = 0;
	let scheduledGeneration = 0;
	let waitRounds = 0;
	let flushPromise = null;
	let directSendPromise = null;
	let 强制排空 = false;
	let 停止已开始 = false;
	let 活动发送数 = 0;
	let 活动直发数 = 0;
	let 活动发送错误 = null;
	let 活动发送等待者 = [];
	const 等待活动发送完成 = () => {
		if (!活动发送数 && !活动直发数) return Promise.resolve();
		return new Promise(resolve => 活动发送等待者.push(resolve));
	};
	const 标记发送完成 = () => {
		if (活动发送数 || 活动直发数 || !活动发送等待者.length) return;
		const resolvers = 活动发送等待者;
		活动发送等待者 = [];
		for (const resolve of resolvers) resolve();
	};
	const 检查活动发送错误 = () => {
		if (!活动发送错误) return;
		const err = 活动发送错误;
		grain.清空();
		throw err;
	};
	const 当前发送器有效 = () => 强制排空 || !isActive || isActive();
	const 关闭活动连接 = () => {
		if (当前发送器有效()) closeSocketQuietly(webSocket);
	};

	const 发送原始块 = async (chunk) => {
		if (!当前发送器有效()) return;
		if (webSocket.readyState !== WebSocket.OPEN) throw new Error('ws.readyState is not open');
		chunk = 附加响应头(chunk);
		await WebSocket发送并等待(webSocket, chunk);
	};

	const 串行发送原始块 = async (chunk) => {
		while (directSendPromise) await directSendPromise;
		const sendTask = 发送原始块(chunk);
		directSendPromise = sendTask;
		try { await sendTask }
		finally {
			if (directSendPromise === sendTask) directSendPromise = null;
		}
	};

	const 附加响应头 = (chunk) => {
		const responseHeader = 获取响应头();
		if (!responseHeader) return chunk;
		const merged = new Uint8Array(responseHeader.length + chunk.byteLength);
		merged.set(responseHeader, 0);
		merged.set(chunk, responseHeader.length);
		return merged;
	};

	const flush = async () => {
		while (flushPromise) await flushPromise;
		if (flushTimer) clearTimeout(flushTimer);
		flushTimer = null;
		waitRounds = 0;
		if (!当前发送器有效()) {
			grain.清空();
			return;
		}
		const 发送任务 = (async () => {
			for (; ;) {
				if (!当前发送器有效()) {
					grain.清空();
					break;
				}
				const packed = grain.合包();
				if (!packed) break;
				await 串行发送原始块(packed.chunk);
			}
		})();
		flushPromise = 发送任务.catch(err => {
			活动发送错误 ||= err;
			throw err;
		}).finally(() => { flushPromise = null });
		return flushPromise;
	};

	const scheduleFlush = () => {
		if (!当前发送器有效()) {
			grain.清空();
			return;
		}
		if (grain.为空 || flushTimer) return;
		if (grain.字节数 >= packetCap || packetCap - grain.字节数 < tailBytes) {
			flush().catch(关闭活动连接);
			return;
		}
		flushTimer = setTimeout(() => {
			flushTimer = null;
			if (!当前发送器有效()) {
				grain.清空();
				return;
			}
			if (grain.为空) return;
			if (grain.字节数 >= packetCap || packetCap - grain.字节数 < tailBytes) {
				flush().catch(关闭活动连接);
				return;
			}
			if (waitRounds < 下行Grain最大等待轮次 && (generation !== scheduledGeneration || grain.字节数 < 下行Grain低水位字节)) {
				waitRounds++;
				scheduledGeneration = generation;
				scheduleFlush();
				return;
			}
			flush().catch(关闭活动连接);
		}, 1);
	};

	return {
		async 直接发送(data) {
			if (停止已开始 || !当前发送器有效()) return;
			活动直发数++;
			try {
				const chunk = 数据转Uint8Array(data);
				if (!chunk.byteLength) return;
				await 串行发送原始块(chunk);
			} catch (err) {
				活动发送错误 ||= err;
				throw err;
			} finally {
				活动直发数--;
				标记发送完成();
			}
		},
		async 发送(data) {
			if (停止已开始 || !当前发送器有效()) return;
			活动发送数++;
			try {
				const chunk = 数据转Uint8Array(data);
				if (!chunk.byteLength) return;
				let offset = 0;
				const totalBytes = chunk.byteLength;
				while (offset < totalBytes) {
					const remainingBytes = totalBytes - offset;
					if (grain.为空 && remainingBytes >= packetCap) {
						const sendBytes = Math.min(packetCap, remainingBytes);
						const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
						await 串行发送原始块(view);
						offset += sendBytes;
						continue;
					}
					const copyBytes = Math.min(packetCap - grain.字节数, totalBytes - offset);
					if (!copyBytes) {
						await flush();
						continue;
					}
					grain.收纳({ chunk: offset || copyBytes !== totalBytes ? chunk.subarray(offset, offset + copyBytes) : chunk });
					offset += copyBytes;
					generation++;
					if (grain.字节数 >= packetCap || packetCap - grain.字节数 < tailBytes) await flush();
					else scheduleFlush();
				}
			} catch (err) {
				活动发送错误 ||= err;
				throw err;
			} finally {
				活动发送数--;
				标记发送完成();
			}
		},
		flush,
		async 停止并刷新() {
			if (停止已开始) {
				await 等待活动发送完成();
				while (directSendPromise) await directSendPromise;
				检查活动发送错误();
				await flush();
				return;
			}
			停止已开始 = true;
			强制排空 = true;
			if (flushTimer) clearTimeout(flushTimer);
			flushTimer = null;
			await 等待活动发送完成();
			while (directSendPromise) await directSendPromise;
			检查活动发送错误();
			await flush();
		}
	};
}

export async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, isCurrentSocket = null, remoteConnWrapper = null) {
	let header = headerData, hasData = false, reader, useBYOB = false, readError = null;
	const BYOB单次读取上限 = 64 * 1024;
	// P1.4: замер времени до сигнала «закрытие без данных» — от момента начала
	// чтения до закрытия сокета без единого байта клиенту. Это третий режим
	// отказа прямого пути (см. 反代/ipset-разбор): рантайм принимает TCP и
	// закрывает без единого байта — для CF-назначений это единственный сигнал,
	// по которому отличается «принял и молчит» от «отверг сразу».
	const 读开始时间 = performance.now();
	const 当前连接仍有效 = () => !isCurrentSocket || isCurrentSocket();
	const 下行发送器 = 创建下行Grain发送器(webSocket, header, 当前连接仍有效);
	header = null;
	const 下行控制器 = { 停止并刷新: () => 下行发送器.停止并刷新() };
	if (remoteConnWrapper) remoteConnWrapper.downlinkController = 下行控制器;
	try { remoteSocket.closed?.catch?.(() => { }) } catch (e) { }

	try { reader = remoteSocket.readable.getReader({ mode: 'byob' }); useBYOB = true }
	catch (e) { reader = remoteSocket.readable.getReader() }

	try {
		if (!useBYOB) {
			while (true) {
				const { done, value } = await reader.read();
				if (!当前连接仍有效()) break;
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (value.byteLength >= 下行Grain包字节) {
					await 下行发送器.flush();
					await 下行发送器.直接发送(value);
				} else {
					await 下行发送器.发送(value);
				}
			}
		} else {
			let readBuffer = new ArrayBuffer(BYOB单次读取上限);
			while (true) {
				const { done, value } = await reader.read(new Uint8Array(readBuffer, 0, BYOB单次读取上限));
				if (!当前连接仍有效()) break;
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (value.byteLength >= 下行Grain包字节) {
					await 下行发送器.flush();
					await 下行发送器.直接发送(value);
					readBuffer = new ArrayBuffer(BYOB单次读取上限);
				} else {
					await 下行发送器.发送(value.slice());
					readBuffer = value.buffer.byteLength >= BYOB单次读取上限 ? value.buffer : new ArrayBuffer(BYOB单次读取上限);
				}
			}
		}
		if (当前连接仍有效()) await 下行发送器.flush();
	} catch (err) { readError = err }
	finally {
		if (当前连接仍有效() && webSocket.readyState === WebSocket.OPEN) {
			try { await 下行发送器.停止并刷新() } catch (err) { readError ||= err }
		}
		if (remoteConnWrapper?.downlinkController === 下行控制器) remoteConnWrapper.downlinkController = null;
		try { await reader.cancel() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { remoteSocket.close() } catch (e) { }
	}
	if (!hasData && retryFunc && webSocket.readyState === WebSocket.OPEN && 当前连接仍有效()) {
		// P1.4: сигнал «закрытие без данных» — апстрим закрылся, не отдав клиенту
		// ни байта (успешная запись первого пакета, ноль в ответ). Диагностика на
		// debug, без адресов: по доле и задержке этого сигнала решается ipset —
		// если рантайм так «принимает и молчит», классификатор по ошибке его не
		// увидит, а по «нет данных» увидит.
		const 静默时长 = Math.round(performance.now() - 读开始时间);
		log.调试(`[TCP直连] сигнал отказа: закрытие без данных, спустя ${静默时长}мс`);
		try {
			await retryFunc();
			return;
		} catch (err) {
			readError ||= err;
		}
	}
	if (!当前连接仍有效()) return;
	if (readError) log.错误(`[TCP下行] 读取失败: ${readError?.message || readError}`);
	closeSocketQuietly(webSocket);
}

