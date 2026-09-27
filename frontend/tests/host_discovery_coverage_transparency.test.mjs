import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = read("docs/requirements/cidr-host-discovery.md");
const wizard = read("frontend/src/pages/EngagementWizard.tsx");
const edit = read("frontend/src/pages/EngagementEdit.tsx");

function requirement(id) {
  assert.match(requirementDoc, new RegExp(`## ${id}:`), `${id} must be documented before it is tested`);
}

function contains(source, pattern, message) {
  if (pattern instanceof RegExp) assert.match(source, pattern, message);
  else assert.equal(source.includes(pattern), true, message);
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-CIDRDISC-002 (2026-08-12 amendment) documents the coverage caveat", () => {
  requirement("REQ-CIDRDISC-002");
  contains(requirementDoc, "GitHub issue #36", "requirement doc must record the issue this amendment closes");
  contains(requirementDoc, "80/443", "requirement doc must name the fixed discovery ports");
});

test("the wizard's Scope step shows a coverage note when a cidr asset is present", () => {
  contains(wizard, 'assets.some((a) => a.asset_type === "cidr")', "wizard must gate the note on a cidr-type scope asset being present");
  contains(wizard, "80/443", "wizard note must name the fixed discovery ports");
});

test("the engagement edit page's scope-assets section shows the same coverage note", () => {
  contains(edit, 'scopeAssets.some((a) => a.asset_type === "cidr")', "edit page must gate the note on a cidr-type scope asset being present");
  contains(edit, "80/443", "edit page note must name the fixed discovery ports");
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
