import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { readRecord, record } from "./_records.mjs";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirements = readRecord("requirements", "scan-pipeline.md");
const depth = read("frontend/src/components/ScanDepth.tsx");
const capabilities = read("frontend/src/components/CapabilitiesEditor.tsx");
const plan = read("frontend/src/components/ScanPlanView.tsx");

// Strip comments: they may quote the old phrase when they explain the correction.
const code = (source) => source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");

test("REQ-PIPE-005 the record says thorough is the index, not every template the scanner ships", () => {
  record.match(requirements, /It is not every\s+template the scanner ships, and user-facing text says so/);
});

test("REQ-PIPE-005 [negative] no depth text promises every or all templates (#66)", () => {
  for (const [name, source] of [["ScanDepth", depth], ["CapabilitiesEditor", capabilities], ["ScanPlanView", plan]]) {
    const text = code(source).replace(/thorough:every_template/g, "");
    assert.doesNotMatch(text, /every template|all templates|every nuclei/i, `${name} still claims complete template coverage`);
  }
});

test("REQ-PIPE-005 the depth texts say what thorough runs: non-intrusive templates, product identified or not", () => {
  assert.match(depth, /Every non-intrusive template that applies to a web service, whether or not the scan identified its product/);
  assert.match(capabilities, /All non-intrusive web templates/);
  assert.match(plan, /Thorough depth: all non-intrusive web templates/);
});
