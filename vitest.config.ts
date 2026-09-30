import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

// Фиксированный выбор по C2: @cloudflare/vitest-plugin 1.3.0 (доки Workers, Aug 2026).
//
// configPath указывает на wrangler.test.toml, а не на wrangler.toml: тестам нужен
// спайк-харнесс (SELF-запросы не несут request.cf, монолит читает cf безусловно).
// В wrangler.test.toml main = test/spike-worker.ts. Прод-вход — src/index.ts,
// он чистый: без /__spike/* и без подмены cf (P0.4).
export default defineConfig({
	plugins: [
		cloudflareTest({
			wrangler: { configPath: "./wrangler.test.toml" },
		}),
	],
});
