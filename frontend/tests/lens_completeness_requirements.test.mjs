import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { readRecord, record } from "./_records.mjs";

// REQ-LENS-005..007 (GitHub #88): a cut-off Lens analysis is never final, the cap is a bounded global setting, and the display was
// never the cause (the container has no clamp). The provider side is covered by test_lens_analysis_completeness.py.
const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");
const requirements = readRecord("requirements", "agent-naming-and-lens.md");
const detail = read("frontend/src/components/FindingDetail.tsx");
const settings = read("frontend/src/pages/Settings.tsx");
const client = read("frontend/src/api/client.ts");
const styles = read("frontend/src/styles.css");

record.match(requirements, /## REQ-LENS-005:/);
record.match(requirements, /## REQ-LENS-007:/);

// REQ-LENS-005: Regenerate for a cut-off analysis, the normal label for a complete one, the warning for the former only.
assert.match(detail, /lensIsCutOff \? "Regenerate" : "Show Lens analysis"/, "a cut-off analysis offers Regenerate");
assert.match(detail, /\{lensIsCutOff && \(\s*<div className="warning-block">/, "the warning shows only for a cut-off analysis");
assert.match(detail, /Use Regenerate to ask again/);
assert.match(detail, /finding\.id in lensTruncatedByFinding \? lensTruncatedByFinding\[finding\.id\] : cachedLensTruncated\(finding\)/,
  "a fresh result overrides the saved flag, so a regenerated complete analysis loses the warning at once");

// The display was never the cause: nothing in the container may hide text.
const lensOutput = styles.match(/\.lens-output\s*\{[^}]*\}/)?.[0] ?? "";
assert.ok(lensOutput.length > 0, ".lens-output rule exists");
for (const forbidden of ["max-height", "line-clamp", "text-overflow", "overflow: hidden", "overflow:hidden", "height:"]) {
  assert.ok(!lensOutput.includes(forbidden), `.lens-output must not contain ${forbidden}`);
}

// REQ-LENS-007: a bounded global setting, in Settings, like the agent's.
assert.match(client, /getLensMaxTokens: \(\) => request<LensMaxTokens>\("\/settings\/lens-max-tokens"\)/);
assert.match(client, /updateLensMaxTokens: \(value: number\) =>/);
assert.match(settings, /queryKey: \["lens-max-tokens"\]/);
assert.match(settings, /Lens Agent max tokens \(global default\)/);
assert.match(settings, /useState\(4096\)/, "the form default must match the built-in default");
const lensPanel = settings.slice(settings.indexOf("Lens Agent max tokens (global default)"));
assert.match(lensPanel.slice(0, 1500), /min=\{1024\}/);
assert.match(lensPanel.slice(0, 1500), /max=\{16384\}/);
assert.match(lensPanel.slice(0, 1200), /at most two provider calls/);

console.log("ok - REQ-LENS-005..007 cut-off analysis is never final, the cap is a bounded setting, nothing hides the text");
