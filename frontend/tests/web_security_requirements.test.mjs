import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = read("docs/requirements/web-security-headers.md");
const indexHtml = read("frontend/index.html");
const main = read("frontend/src/main.tsx");
const pkg = JSON.parse(read("frontend/package.json"));

function requirement(id) {
  assert.match(requirementDoc, new RegExp(`## ${id}:`), `${id} must be documented before it is tested`);
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-WEBSEC-002 fonts are bundled; the page loads nothing from third parties", () => {
  requirement("REQ-WEBSEC-002");
  assert.doesNotMatch(indexHtml, /https?:\/\//, "index.html must not reference any external origin");
  assert.doesNotMatch(indexHtml, /<script>(?!<\/script>)/, "no inline script");
  assert.match(main, /import "@fontsource\/inter\/400\.css";/);
  assert.match(main, /import "@fontsource\/space-grotesk\/600\.css";/);
  assert.ok(pkg.dependencies["@fontsource/inter"] && pkg.dependencies["@fontsource/space-grotesk"]);
});

test("REQ-WEBSEC-002 the document declares its real language", () => {
  assert.match(indexHtml, /<html lang="en">/);
});

let failed = 0;
for (const { name, fn } of tests) {
  try {
    fn();
    console.log(`ok - ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`not ok - ${name}`);
    console.error(error.stack || error.message || error);
  }
}
if (failed) {
  console.error(`${failed} requirement test(s) failed`);
  process.exit(1);
}
console.log(`${tests.length} requirement test(s) passed`);
