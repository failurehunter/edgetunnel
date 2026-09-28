// Главный воркер = диспетчер харнесса (Шаг 0.3 спайк-пробники + маршрутизация в монолит worker.ts).
// Фазы 1–2 правят worker.ts; этот файл — тонкая обвязка тестового воркера.
import monolith from "./entry";

const ECHO_PORT = 28333;

// cf-мок для проброса в монолит (SELF-запросы cf не несут).
const SPIKE_CF = {
	colo: "HKG",
	asn: 45102,
	country: "HK",
	city: "Hong Kong",
	asOrganization: "Example-ISP",
};

function json(x: unknown): Response {
	return new Response(JSON.stringify(x), {
		headers: { "content-type": "application/json" },
	});
}

function introspect(request: Request): unknown {
	const f = (
		request as unknown as {
			fetcher?: { connect?: unknown };
		}
	)?.fetcher;
	return {
		path: new URL(request.url).pathname,
		hasFetcher: typeof f !== "undefined",
		fetcherType: typeof f,
		hasConnectFn: typeof f?.connect === "function",
	};
}

type ConnectFn = (opts: { hostname: string; port: number }) => unknown;

function isConnectFn(f: unknown): f is ConnectFn {
	return typeof f === "function";
}

async function tcpProbe(connectFn: ConnectFn | undefined): Promise<unknown> {
	if (connectFn === undefined) {
		return { error: "request.fetcher.connect unavailable" };
	}
	let socket: any;
	try {
		socket = connectFn({ hostname: "127.0.0.1", port: ECHO_PORT });
	} catch (e) {
		return { error: "connect threw: " + (e as Error).message };
	}
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	const writer = socket.writable.getWriter();
	const reader = socket.readable.getReader();
	const timeout = new Promise<never>((_, reject) =>
		setTimeout(() => reject(new Error("echo timeout 5s")), 5000)
	);
	try {
		await writer.write(encoder.encode("PING"));
		const race = await Promise.race([reader.read(), timeout]);
		const value: Uint8Array | undefined = race.value;
		return {
			ok: true,
			echoed: value ? decoder.decode(value) : null,
			done: race.done,
		};
	} catch (e) {
		return { error: (e as Error).message };
	} finally {
		try {
			socket.close();
		} catch {}
		try {
			await writer.close();
		} catch {}
	}
}

export default {
	async fetch(request: Request, env: unknown, ctx: unknown): Promise<Response> {
		const url = new URL(request.url);
		if (url.pathname === "/__spike/introspect") {
			return json(introspect(request));
		}
		if (url.pathname === "/__spike/tcp") {
			const f = (
				request as unknown as {
					fetcher?: { connect?: unknown };
				}
			)?.fetcher;
			return json(
				await tcpProbe(isConnectFn(f?.connect) ? f.connect.bind(f) : undefined)
			);
		}
		if (url.pathname === "/__spike/ws-echo") {
			// Изоляция слоёв: ретранслирует ли SELF-loopback WS-фреймы (текст/бинар)?
			const pair = new WebSocketPair();
			const [client, server] = Object.values(pair);
			server.accept();
			server.addEventListener("message", (e) => {
				const d = e.data;
				if (typeof d === "string" || d instanceof ArrayBuffer) {
					server.send(d);
				} else if (d && typeof (d as Blob).arrayBuffer === "function") {
					(d as Blob).arrayBuffer().then((ab) => server.send(ab));
				} else {
					server.send(String(d));
				}
			});
			server.addEventListener("close", () => {});
			return new Response(null, { status: 101, webSocket: client });
		}
		// SELF-запросы не несут request.cf (см. test/phase0-spike.notes.md),
		// а монолит читает cf безусловно (строка 43). Впрыскиваем фиксированный cf.
		const proxyRequest = new Proxy(request, {
			get(target, prop) {
				if (prop === "cf") return SPIKE_CF;
				const v = Reflect.get(target, prop);
				return typeof v === "function" ? v.bind(target) : v;
			},
		});
		return monolith.fetch(
			proxyRequest as never,
			env as never,
			ctx as never
		) as unknown as Response;
	},
};