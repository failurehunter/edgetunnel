// @ts-nocheck
// Фаза 4, пункт 1: явная сессия upstream.
//
// До этого remoteConnWrapper был мешком из семи разрозненных полей
// (socket, generation, downlinkDrain, downlinkController, connectingPromise,
// retryConnect, canRetry首包), которые создавались литералом в трёх местах
// handlers.ts и мутировались из relay.ts. Владелец сокета не был назван,
// отмена не была идемпотентной, состояние не выражалось явно.
//
// Здесь владелец ровно один — сам объект сессии. Состояния:
//   idle        — сокета нет, ничего не начато
//   dialing     — идёт connect, connectingPromise ждёт
//   established — сокет установлен, идёт downlink
//   superseded  — сессия вытеснена более новой, её сокет уже закрыт
//   closed      — закрыта окончательно, повторные вызовы не делают ничего
//
// Поля socket/generation/downlinkDrain/downlinkController/connectingPromise/
// retryConnect/canRetry首包 сохранены как геттеры/сеттеры с прежними именами:
// ~30 мест использования в relay.ts и handlers.ts остаются нетронутыми, а
// поведение не меняется. Проверяемость обеспечивается тестом сессии.

export const 会话状态 = {
	IDLE: "idle",
	DIALING: "dialing",
	ESTABLISHED: "established",
	SUPERSEDED: "superseded",
	CLOSED: "closed",
};

export class UpstreamSession {
	/** Числовая метка поколения. Растёт при каждой смене соединения. */
	#generation = 0;
	#socket: any = null;
	#downlinkController: any = null;
	#downlinkDrain: Promise<unknown> = Promise.resolve();
	#connectingPromise: any = null;
	#retryConnect: any = null;
	#canRetry首包: any = null;
	#state: string = 会话状态.IDLE;
	/** Заведён ли уже whoami-wrapped close; гонки закрытия не должно быть. */
	#closedOnce = false;

	// ── состояние ────────────────────────────────────────────────────────

	get state() { return this.#state; }
	get generation() { return this.#generation; }
	// Сеттер оставлен для мест, которые инкрементят метку напрямую
	// (relay.ts при supersede). Сами переходы идут через invalidate/beginGeneration.
	set generation(v: any) { this.#generation = v; }
	get socket() { return this.#socket; }
	set socket(v: any) { this.#socket = v; }
	get downlinkController() { return this.#downlinkController; }
	set downlinkController(v: any) { this.#downlinkController = v; }
	get downlinkDrain() { return this.#downlinkDrain; }
	set downlinkDrain(v: any) { this.#downlinkDrain = v; }
	get connectingPromise() { return this.#connectingPromise; }
	set connectingPromise(v: any) { this.#connectingPromise = v; }
	get retryConnect() { return this.#retryConnect; }
	set retryConnect(v: any) { this.#retryConnect = v; }
	get canRetry首包() { return this.#canRetry首包; }
	set canRetry首包(v: any) { this.#canRetry首包 = v; }

	/** Жива ли сессия: не вытеснена и не закрыта. */
	get active() {
		return this.#state !== 会话状态.SUPERSEDED && this.#state !== 会话状态.CLOSED;
	}

	// ── переходы ─────────────────────────────────────────────────────────

	/**
	 * Отмечает начало дозвона. Повторный вызов во время dialing не создаёт
	 * второго обещания — возвращается уже идущее.
	 */
	beginDial() {
		if (!this.active) return null;
		if (this.#state === 会话状态.DIALING && this.#connectingPromise) return this.#connectingPromise;
		this.#state = 会话状态.DIALING;
		return null;
	}

	/** Регистрирует обещание текущего дозвона. */
	setConnecting(promise) {
		this.#connectingPromise = promise;
	}

	/** Сокет установлен: dialing → established. */
	markEstablished(socket) {
		if (!this.active) return false;
		this.#socket = socket;
		this.#state = 会话状态.ESTABLISHED;
		return true;
	}

	/**
	 * Начинает новое поколение: прежний сокет и downlink гасятся, счётчик растёт.
	 * Возвращает метку и обещание дренажа — вызывающий обязан его ждать перед
	 * подключением downlink, иначе данные старого поколения попадут в новый канал.
	 */
	beginGeneration() {
		if (!this.active) return { generation: this.#generation, downlinkDrain: Promise.resolve() };
		if (!Number.isInteger(this.#generation)) this.#generation = 0;
		const generation = ++this.#generation;

		const previousSocket = this.#socket;
		this.#socket = null;
		const previousDownlink = this.#downlinkController;
		this.#downlinkController = null;
		const previousDrain = this.#downlinkDrain || Promise.resolve();

		let currentDrain;
		try { currentDrain = previousDownlink?.停止并刷新?.() || Promise.resolve(); }
		catch (error) { currentDrain = Promise.reject(error); }

		const downlinkDrain = Promise.all([previousDrain, currentDrain]);
		// Установщик ждёт это обещание; обработчик вешаем сразу, чтобы отказ
		// дренажа до завершения дозвона не стал необработанным.
		downlinkDrain.catch(() => { });
		this.#downlinkDrain = downlinkDrain;
		try { previousSocket?.close?.(); } catch (e) { }
		return { generation, downlinkDrain };
	}

	/**
	 * Делает сессию неактивной: generation растёт, сокет отцепляется и закрывается,
	 * downlink обнуляется. Идемпотентна.
	 */
	invalidate() {
		if (this.#state === 会话状态.CLOSED) return;
		this.#generation = (Number.isInteger(this.#generation) ? this.#generation : 0) + 1;
		const socket = this.#socket;
		this.#socket = null;
		this.#downlinkController = null;
		this.#downlinkDrain = Promise.resolve();
		if (this.active) this.#state = 会话状态.SUPERSEDED;
		try { socket?.close?.(); } catch (e) { }
	}

	/** Окончательное закрытие. Идемпотентна. */
	close() {
		if (this.#closedOnce) return;
		this.#closedOnce = true;
		this.invalidate();
		this.#state = 会话状态.CLOSED;
		this.#connectingPromise = null;
		this.#retryConnect = null;
		this.#canRetry首包 = null;
	}
}

/** Обёртка для мест, где сессия ещё не создана (тесты, опциональные аргументы). */
export function 创建Upstream会话(): UpstreamSession {
	return new UpstreamSession();
}

/**
 * Совместимость с прежним API: функции принимали «мешок с полями».
 * Теперь принимают UpstreamSession. Оставлены, потому что на них ссылаются
 * handlers.ts; по мере разбора handlers.ts (P4.3) будут удалены.
 */
export function 失效TCP连接世代(session) {
	if (!session) return;
	if (typeof session.invalidate === "function") { session.invalidate(); return; }
	// страховка для «голого» литерала: прежнее поведение
	session.generation = (Number.isInteger(session.generation) ? session.generation : 0) + 1;
	const socket = session.socket;
	session.socket = null;
	session.downlinkController = null;
	session.downlinkDrain = Promise.resolve();
	try { socket?.close?.(); } catch (e) { }
}

export function 开始TCP连接世代(session) {
	if (typeof session?.beginGeneration === "function") return session.beginGeneration();
	// страховка для «голого» литерала: прежнее поведение
	if (!Number.isInteger(session.generation)) session.generation = 0;
	const generation = ++session.generation;
	const previousSocket = session.socket;
	session.socket = null;
	const previousDownlink = session.downlinkController;
	session.downlinkController = null;
	const previousDrain = session.downlinkDrain || Promise.resolve();
	let currentDrain;
	try { currentDrain = previousDownlink?.停止并刷新?.() || Promise.resolve(); }
	catch (error) { currentDrain = Promise.reject(error); }
	const downlinkDrain = Promise.all([previousDrain, currentDrain]);
	downlinkDrain.catch(() => { });
	session.downlinkDrain = downlinkDrain;
	try { previousSocket?.close?.(); } catch (e) { }
	return { generation, downlinkDrain };
}
