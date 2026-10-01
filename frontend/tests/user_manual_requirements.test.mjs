import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = read("docs/requirements/user-manual.md");
const app = read("frontend/src/App.tsx");
const styles = read("frontend/src/styles.css");

function requirement(id) {
  assert.match(requirementDoc, new RegExp(`## ${id}:`), `${id} must be documented before it is tested`);
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

function sourceFiles(dir) {
  return readdirSync(resolve(repo, dir), { withFileTypes: true }).flatMap((entry) => {
    const path = `${dir}/${entry.name}`;
    return entry.isDirectory() ? sourceFiles(path) : [path];
  });
}

test("REQ-MANUAL-005 the in-app documentation page, route and navigation link are gone", () => {
  requirement("REQ-MANUAL-005");
  assert.equal(existsSync(resolve(repo, "frontend/src/pages/Documentation.tsx")), false, "the page file must not come back");
  assert.doesNotMatch(app, /pages\/Documentation/, "no import of the page");
  assert.doesNotMatch(app, /path="\/docs"/, "no /docs route: it falls through to the not-found page");
  assert.doesNotMatch(app, /<NavLink to="\/docs"/, "no navigation link to it");
  assert.match(app, /<Route path="\*" element=\{<NotFound \/>\} \/>/, "/docs shows Page not found");
});

test("REQ-MANUAL-005 no source file keeps documentation content or its styles", () => {
  for (const file of sourceFiles("frontend/src").filter((path) => /\.(tsx?|css)$/.test(path))) {
    assert.doesNotMatch(read(file), /REQ-DOC-001/, `${file} must not claim the superseded in-app documentation`);
  }
  assert.doesNotMatch(styles, /\.docs-(layout|index|body|section|fields)/, "the styles only the page used are removed");
});

test("REQ-MANUAL-005 the Manual link exists only when the console was built with VITE_MANUAL_URL", () => {
  assert.match(app, /import\.meta\.env\.VITE_MANUAL_URL/, "the address comes from the build, not from the source");
  assert.match(app, /\{MANUAL_URL && <a href=\{MANUAL_URL\} target="_blank" rel="noopener noreferrer">Manual<\/a>\}/,
    "the link is conditional, opens in a new tab and carries no opener");
  // Only an http(s) address can be shown; anything else (a javascript: URL, an empty value) means no link.
  assert.match(app, /\/\^https\?:\\\/\\\/\/i\.test\(/, "the address must be http(s)");
  assert.equal((app.match(/>Manual</g) || []).length, 1, "one link, not a page of content");
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
