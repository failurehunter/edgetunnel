// Продовый вход: тонкий диспетчер над ./entry.
//
// P0.4: ранее entry-файл был src/index.ts — спайк-харнесс фазы 0. Он содержал
//   * три неаутентифицированных маршрута /__spike/{introspect,tcp,ws-echo};
//   * безусловную подмену request.cf константой SPIKE_CF.
// Последнее портило прод: colo для дефолтного proxyip всегда был HKG (а с
// правки пользователя — WAW), 识别运营商 всегда возвращала «cf», а в логах и
// заголовке asn стояли фейковые ASN и страна.
//
// Теперь прод-вход — этот файл, чистый: только делегирование. Спайк-харнесс
// переехал в test/spike-worker.ts и в прод не попадает. cf для тестов
// подставляет сам харнесс (makeRequest в test/diff-harness.ts).
import entry from "./entry";

export default {
	fetch(request: Request, env: unknown, ctx: unknown): Promise<Response> {
		return entry.fetch(request as never, env as never, ctx as never) as unknown as Promise<Response>;
	},
};
