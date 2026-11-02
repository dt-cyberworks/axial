// Loads a TypeScript module of the console for a behavioural test: bundled with esbuild (already a
// dependency of Vite) into a temporary file and imported. Type-only imports disappear; nothing else
// is mocked, so the test runs the real code.
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { buildSync } from "esbuild";

const frontend = resolve(import.meta.dirname, "..");

export async function loadTs(relativePath) {
  const out = join(mkdtempSync(join(tmpdir(), "asm-ts-")), "module.mjs");
  const result = buildSync({
    entryPoints: [resolve(frontend, relativePath)],
    bundle: true, format: "esm", platform: "node", write: false,
    define: { "import.meta.env.VITE_API_BASE_URL": '""', "import.meta.env": "{}" },
    logLevel: "silent",
  });
  writeFileSync(out, result.outputFiles[0].text);
  return import(pathToFileURL(out).href);
}
