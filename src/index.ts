// Шаг 0.1: пустой smoke-воркер. Реальный монолит появится в шаге 0.2 (src/worker.ts).
export default {
	async fetch(): Promise<Response> {
		return new Response("OK", { status: 200 });
	},
};