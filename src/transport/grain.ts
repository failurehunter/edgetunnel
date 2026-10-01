// @ts-nocheck
// Фаза 3, Шаг 3.6: Grain-примитивы — создание/упаковка/очередь.
// from worker.ts — function-in-function, behavior preserved.
// Лог → console (отдельный telemetry — шаг 11).

import { 数据转Uint8Array } from "../util";
import { 创建日志器 } from "../logging";
export const 上行合包目标字节 = 20 * 1024, 上行队列最大字节 = 16 * 1024 * 1024, 上行队列最大条目 = 4096;
export const 下行Grain包字节 = 32 * 1024, 下行Grain尾部阈值 = 512, 下行Grain低水位字节 = Math.max(4096, 下行Grain尾部阈值 * 12), 下行Grain最大等待轮次 = 4;
const log = 创建日志器('grain');
export function 创建Grain收纳器(容量, 复制合包结果 = false) {
	let 队列 = [];
	let 头 = 0;
	let 字节数 = 0;
	let 合包缓冲 = null;

	const 为空 = () => 头 >= 队列.length;
	const 压缩 = () => {
		if (头 > 32 && 头 * 2 >= 队列.length) {
			队列 = 队列.slice(头);
			头 = 0;
		}
	};
	const 取出 = () => {
		if (为空()) return null;
		const item = 队列[头];
		队列[头++] = undefined;
		字节数 -= item.chunk.byteLength;
		压缩();
		return item;
	};

	return {
		get 字节数() { return 字节数 },
		get 条目数() { return 队列.length - 头 },
		get 为空() { return 为空() },
		清空(处理项目 = null) {
			if (处理项目) {
				for (let i = 头; i < 队列.length; i++) {
					if (队列[i]) 处理项目(队列[i]);
				}
			}
			队列 = [];
			头 = 0;
			字节数 = 0;
		},
		收纳(item) {
			if (!item?.chunk?.byteLength) return false;
			队列.push(item);
			字节数 += item.chunk.byteLength;
			return true;
		},
		合包() {
			const first = 取出();
			if (!first) return null;
			const items = [first];
			if (为空() || first.chunk.byteLength >= 容量) return { chunk: first.chunk, items };

			let totalBytes = first.chunk.byteLength;
			let end = 头;
			while (end < 队列.length) {
				const nextBytes = totalBytes + 队列[end].chunk.byteLength;
				if (nextBytes > 容量) break;
				totalBytes = nextBytes;
				end++;
			}
			if (end === 头) return { chunk: first.chunk, items };

			const output = (合包缓冲 ||= new Uint8Array(容量));
			output.set(first.chunk, 0);
			let offset = first.chunk.byteLength;
			while (头 < end) {
				const next = 队列[头];
				队列[头++] = undefined;
				字节数 -= next.chunk.byteLength;
				items.push(next);
				output.set(next.chunk, offset);
				offset += next.chunk.byteLength;
			}
			压缩();
			const bundled = output.subarray(0, totalBytes);
			return { chunk: 复制合包结果 ? bundled.slice() : bundled, items };
		}
	};
}

export function 创建上行Grain合包流(目标字节 = 上行合包目标字节) {
	const identity = typeof IdentityTransformStream !== 'undefined'
		? new IdentityTransformStream()
		: new TransformStream();
	const writer = identity.writable.getWriter();
	const 缓冲 = new Uint8Array(目标字节);
	let 缓冲长度 = 0;
	let 定时器 = null;
	let 在途写 = null;
	let 冲刷链 = Promise.resolve();

	const 清理定时器 = () => {
		if (定时器) {
			clearTimeout(定时器);
			定时器 = null;
		}
	};

	const 串行写 = async (chunk) => {
		if (在途写) await 在途写;
		在途写 = writer.write(chunk);
		try { await 在途写 } finally { 在途写 = null; }
	};

	const 冲刷 = async () => {
		if (缓冲长度) {
			const chunk = 缓冲.slice(0, 缓冲长度);
			缓冲长度 = 0;
			await 串行写(chunk);
		}
	};

	const 排队冲刷 = () => {
		冲刷链 = 冲刷链.then(() => 冲刷()).catch(() => { });
	};

	const 启动定时器 = () => {
		if (定时器) return;
		定时器 = setTimeout(() => {
			定时器 = null;
			排队冲刷();
		}, 1);
	};

	return {
		readable: identity.readable,
		写入: async (chunk) => {
			const data = 数据转Uint8Array(chunk);
			if (!data.byteLength) return;
			if (data.byteLength >= 目标字节) {
				清理定时器();
				if (缓冲长度) await 冲刷();
				await 串行写(data);
				return;
			}
			if (缓冲长度 + data.byteLength >= 目标字节) {
				const output = new Uint8Array(缓冲长度 + data.byteLength);
				output.set(缓冲.subarray(0, 缓冲长度), 0);
				output.set(data, 缓冲长度);
				缓冲长度 = 0;
				清理定时器();
				await 串行写(output);
			} else {
				缓冲.set(data, 缓冲长度);
				缓冲长度 += data.byteLength;
				启动定时器();
			}
		},
		结束: async () => {
			清理定时器();
			try {
				await 冲刷链;
				await 冲刷();
				await writer.close();
			} finally {
				try { writer.releaseLock() } catch (e) { }
			}
		}
	};
}

/**
 * Хуки, которые очередь зовет наружу. Все, кроме 获取写入器, необязательные.
 * canRetry возвращает «повтор первой посылки ещё допустим»: если ни один байт
 * не мог уйти, упавшую запись можно переиграть, иначе — только закрытие,
 * иначе клиент получит дубликат.
 */
interface 上行写入队列参数 {
	获取写入器: () => { write(chunk: Uint8Array): Promise<void> } | null;
	获取连接任务?: () => Promise<unknown> | null | undefined;
	释放写入器?: () => void;
	重试连接?: () => Promise<unknown>;
	关闭连接?: (err?: unknown) => void;
	canRetry?: () => boolean;
	名称?: string;
}

export function 创建上行写入队列({ 获取写入器, 获取连接任务 = null, 释放写入器, 重试连接, 关闭连接, canRetry = null, 名称 = '上行队列' }: 上行写入队列参数) {
	const grain = 创建Grain收纳器(上行合包目标字节);
	let draining = false;
	let closed = false;
	let idleResolvers = [];
	let activeCompletions = null;

	const settleCompletions = (completions, err = null) => {
		if (!completions) return;
		for (const completion of completions) {
			if (err) completion.reject(err);
			else completion.resolve();
		}
	};

	const resolveIdle = () => {
		if (grain.字节数 || draining || !idleResolvers.length) return;
		const resolvers = idleResolvers;
		idleResolvers = [];
		for (const resolve of resolvers) resolve();
	};

	const clear = (err = null) => {
		const closeErr = err || (closed ? new Error(`${名称}: queue closed`) : null);
		if (closeErr) {
			grain.清空(item => settleCompletions(item.completions, closeErr));
			settleCompletions(activeCompletions, closeErr);
			activeCompletions = null;
		} else grain.清空();
		resolveIdle();
	};

	const bundle = () => {
		const packed = grain.合包();
		if (!packed) return null;
		let allowRetry = true;
		let completions = null;
		for (const item of packed.items) {
			allowRetry = allowRetry && item.allowRetry;
			if (item.completions) completions = completions ? completions.concat(item.completions) : item.completions;
		}
		return { chunk: packed.chunk, allowRetry, completions };
	};

	const 等待可用写入器 = async () => {
		let writer = 获取写入器();
		if (writer) return writer;
		const connectionTask = 获取连接任务?.();
		if (connectionTask) await connectionTask;
		return 获取写入器();
	};

	const drain = async () => {
		if (draining || closed) return;
		draining = true;
		try {
			for (; ;) {
				if (closed) break;
				const item = bundle();
				if (!item) break;
				const completions = item.completions || null;
				activeCompletions = completions;
				try {
					let writer = await 等待可用写入器();
					if (closed) break;
					if (!writer) throw new Error(`${名称}: remote writer unavailable`);
					try {
						await writer.write(item.chunk);
					} catch (err) {
						释放写入器?.();
						if (closed) break;
						// Фаза 2 (реестр 1.1, строка 2): replay допустим только пока ни один
						// байт не мог уйти — canRetry() от relay (по сути `!已通过代理发送首包`).
						// Иначе — закрытие соединения, без дубликатов.
						const 允许重试 = item.allowRetry && typeof 重试连接 === 'function' && (!canRetry || canRetry());
						if (!允许重试) throw err;
						await 重试连接();
						if (closed) break;
						writer = 获取写入器();
						if (!writer) throw err;
						await writer.write(item.chunk);
					}
					settleCompletions(completions);
				} catch (err) {
					settleCompletions(completions, err);
					throw err;
				} finally {
					if (activeCompletions === completions) activeCompletions = null;
				}
			}
		} catch (err) {
			closed = true;
			clear(err);
			log.错误(`[${名称}] 写入失败: ${err?.message || err}`);
			try { 关闭连接?.(err) } catch (_) { }
		} finally {
			draining = false;
			if (!closed && !grain.为空) drain();
			else resolveIdle();
		}
	};

	const enqueue = (data, allowRetry = true, waitForFlush = false) => {
		if (closed) return false;
		// 首包解析阶段既没有 writer 也没有连接任务；返回 false 交给上层继续协议解析。
		// 已建立会话的重拨阶段则先收纳，drain 会等待新 writer，避免数据被误当成首包。
		if (!获取写入器() && !获取连接任务?.()) return false;
		const chunk = 数据转Uint8Array(data);
		if (!chunk.byteLength) return true;
		const nextBytes = grain.字节数 + chunk.byteLength;
		const nextItems = grain.条目数 + 1;
		if (nextBytes > 上行队列最大字节 || nextItems > 上行队列最大条目) {
			closed = true;
			const err = Object.assign(new Error(`${名称}: upload queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
			clear(err);
			log.信息(`[${名称}] 队列超限，关闭连接`);
			try { 关闭连接?.(err) } catch (_) { }
			throw err;
		}
		let completionPromise = null;
		let completions = null;
		if (waitForFlush) {
			completions = [];
			completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
		}
		grain.收纳({ chunk, allowRetry, completions });
		if (!draining) drain();
		return waitForFlush ? completionPromise.then(() => true) : true;
	};

	return {
		写入(data, allowRetry = true) {
			return enqueue(data, allowRetry, false);
		},
		写入并等待(data, allowRetry = true) {
			return enqueue(data, allowRetry, true);
		},
		async 等待空() {
			if (!grain.字节数 && !draining) return;
			await new Promise(resolve => idleResolvers.push(resolve));
		},
		清空() {
			closed = true;
			clear();
		}
	};
}
