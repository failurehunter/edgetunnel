import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

// Фиксированный выбор по C2: @cloudflare/vitest-plugin 1.3.0 (доки Workers, Aug 2026)
export default defineConfig({
	plugins: [
		cloudflareTest({
			wrangler: { configPath: "./wrangler.toml" },
		}),
	],
});