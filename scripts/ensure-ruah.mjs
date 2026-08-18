// After install, make sure the `ruah` front door exists.
// sync-with: ruah-opt/scripts/ensure-ruah.mjs
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const require = createRequire(import.meta.url);

try {
	const hook = require.resolve("@ruah-dev/cli/postinstall.mjs");
	await import(pathToFileURL(hook).href);
} catch {
	console.warn(
		"[@ruah-dev/guard] @ruah-dev/cli not found. Install it so `ruah guard` works: npm i -g @ruah-dev/cli",
	);
}
