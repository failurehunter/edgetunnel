// Фаза 4, пункт 3 (шаг 3): общий «запись в апстрим» вынесен из транспортов.
//
// До этого файл каждый из адаптеров WS и gRPC делал одно и то же: держал
// 当前写入Socket/远端写入器, лениво брал writer у socket, пересоздавал его при
// смене сокета (переподключение после обрыва) и собирал 创建上行写入队列 с шестью
// одинаковыми хуками. Два экземпляра отличались только именем очереди и тем,
// что происходит при закрытии соединения.
//
// Третий транспорт (叉HTTP) сюда НЕ относится: там request.body перекладывается
// в socket.writable через pipeTo с abort-контроллером, без очереди и без повторов.
// Управлять им отдельно — значило бы натянуть примитивы, которые ему не нужны
// (см. P4.4: порты только ради dial).
//
// Контракт наружу: 创建远端写入门({ remoteConnWrapper, 关闭连接, 名称 })
//   -> { 队列, 写入, 写入并等待, 释放 }
// Разница 写入/写入并等待 — та же, что в grain.ts: fire-and-forget против
// ожидания фактического флаша на сокете. Выбор делает транспорт, потому что
// семантика у него разная: gRPC обязан убедиться, что кадр ушёл, WS — нет.
import { 创建上行写入队列 } from "./grain";

/**
 * Структурный минимум, который нужен очереди: grain зовёт только write и
 * releaseLock. Полный WritableStreamDefaultWriter здесь требовать нельзя —
 * workerd отдаёт duck-типы, а тесты подставляют заглушки.
 */
interface 远端Writer {
	write(chunk: Uint8Array): Promise<void>;
	releaseLock(): void;
}

interface 远端写入门参数 {
	remoteConnWrapper: {
		socket?: { writable: { getWriter(): 远端Writer } } | null;
		connectingPromise?: Promise<unknown> | null;
		retryConnect?: () => Promise<unknown>;
		canRetry首包?: () => boolean;
		// P0.2: хук «байты реально записаны в апстрим». Relay вешает его на
		// сессию в момент создания замыкания счётчика; очередь зовёт только
		// после успешного writer.write. Ленивое обращение — сессия могла быть
		// создана раньше, чем relay поставил хук (тот же приём, что у canRetry).
		记发送?: (chunk: Uint8Array) => void;
		// P2.4 (фикс 2, вариант b): хук «попытка записи чанка очереди». Так же
		// лениво ставится relay; очередь зовёт ДО writer.write (консервативно:
		// «возможно, отправлено»). Гейтит 允许重演首包.
		记写入尝试?: () => void;
	};
	关闭连接?: (err?: unknown) => void;
	名称: string;
}

export function 创建远端写入门({ remoteConnWrapper, 关闭连接, 名称 }: 远端写入门参数) {
	// Сокет переподключается после обрыва, поэтому writer нельзя держать вечно:
	// при смене сокета старый writer уже мёртв. Поэтому храним оба и сверяем.
	let 当前写入Socket: 远端写入门参数["remoteConnWrapper"]["socket"] = null;
	let 远端写入器: 远端Writer | null = null;

	const 释放 = () => {
		if (远端写入器) {
			try { 远端写入器.releaseLock() } catch (e) { }
			远端写入器 = null;
		}
		当前写入Socket = null;
	};

	const 队列 = 创建上行写入队列({
		获取写入器: () => {
			const socket = remoteConnWrapper.socket;
			if (!socket) return null;
			if (socket !== 当前写入Socket) {
				释放();
				当前写入Socket = socket;
				远端写入器 = socket.writable.getWriter();
			}
			return 远端写入器;
		},
		获取连接任务: () => remoteConnWrapper.connectingPromise,
		释放写入器: 释放,
		重试连接: async () => {
			if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
			await remoteConnWrapper.retryConnect();
		},
		关闭连接,
		canRetry: () => (typeof remoteConnWrapper.canRetry首包 === 'function' ? remoteConnWrapper.canRetry首包() : true),
		记录成功发送: chunk => {
			if (typeof remoteConnWrapper.记发送 === 'function') remoteConnWrapper.记发送(chunk);
		},
		记写入尝试: () => {
			if (typeof remoteConnWrapper.记写入尝试 === 'function') remoteConnWrapper.记写入尝试();
		},
		名称,
	});

	return {
		队列,
		释放,
		写入: (chunk: Uint8Array | ArrayBuffer, allowRetry = true) => 队列.写入(chunk, allowRetry),
		写入并等待: (payload: Uint8Array | ArrayBuffer, allowRetry = true) => 队列.写入并等待(payload, allowRetry),
	};
}