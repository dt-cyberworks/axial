import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = read("docs/requirements/axial-rebrand.md");
const html = read("frontend/index.html");
const app = read("frontend/src/App.tsx");
const authLayout = read("frontend/src/components/AuthLayout.tsx");
const logo = read("frontend/src/components/Logo.tsx");
const styles = read("frontend/src/styles.css");

function requirement(id) {
  assert.match(requirementDoc, new RegExp(`## ${id}:`), `${id} must be documented before it is tested`);
}

function contains(source, pattern, message) {
  if (pattern instanceof RegExp) assert.match(source, pattern, message);
  else assert.equal(source.includes(pattern), true, message);
}

function notContains(source, pattern, message) {
  if (pattern instanceof RegExp) assert.doesNotMatch(source, pattern, message);
  else assert.equal(source.includes(pattern), false, message);
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-BRAND-001 renders 'Axial' as the product identity, not 'ASM Console'", () => {
  requirement("REQ-BRAND-001");
  contains(html, "<title>Axial</title>", "browser tab title must read Axial");
  notContains(html, "ASM Console", "browser tab title must not carry the old name");
  notContains(app, "ASM Console", "sidebar brand block must not carry the old name");
  notContains(authLayout, "ASM Console", "auth screen brand block must not carry the old name");
});

test("REQ-BRAND-001 uses one shared Logo component for sidebar, auth screen, and favicon", () => {
  requirement("REQ-BRAND-001");
  contains(app, 'import Logo from "./components/Logo"', "sidebar must import the shared Logo component");
  contains(app, "<Logo", "sidebar must render the shared Logo component");
  contains(authLayout, 'import Logo from "./Logo"', "auth screen must import the shared Logo component");
  contains(authLayout, "<Logo", "auth screen must render the shared Logo component");
  contains(html, 'href="/favicon.svg"', "favicon must point at the shared SVG mark asset");
  // One source of truth: the mark's gradient id/path data must not be duplicated inline elsewhere.
  const markDefinitions = [app, authLayout].filter((src) => src.includes("axialMark")).length;
  assert.equal(markDefinitions, 0, "the mark geometry must live only in Logo.tsx, not be duplicated at call sites");
  contains(logo, "export default function Logo", "Logo.tsx must export the shared component");
});

test("REQ-BRAND-001 exposes the Axial color tokens on :root", () => {
  requirement("REQ-BRAND-001");
  for (const token of ["--bg", "--surface", "--text", "--purple", "--blue", "--teal"]) {
    contains(styles, new RegExp(`${token}:\\s*#`), `:root must define the ${token} token`);
  }
  for (const semanticToken of ["--tint-good-bg", "--tint-warn-bg", "--tint-bad-bg"]) {
    contains(styles, semanticToken, `:root must define the semantic ${semanticToken} token`);
  }
});

test("REQ-BRAND-001 headings use Space Grotesk, body text stays Inter", () => {
  requirement("REQ-BRAND-001");
  contains(styles, /--font-heading:\s*"Space Grotesk"/, "heading font token must be Space Grotesk");
  contains(styles, /--font-body:\s*Inter/, "body font token must remain Inter");
  contains(styles, /h1,\s*h2,\s*h3,\s*h4\s*\{[^}]*font-family:\s*var\(--font-heading\)/, "headings must use the heading font token");
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
