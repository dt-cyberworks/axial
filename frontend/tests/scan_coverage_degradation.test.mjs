import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = read("docs/requirements/scan-integrity.md");
const runDetail = read("frontend/src/pages/RunDetail.tsx");
const translation = read("frontend/src/lib/runActivity.ts");
const styles = read("frontend/src/styles.css");

function requirement(id) {
  assert.match(requirementDoc, new RegExp(`## ${id}:`), `${id} must be documented before it is tested`);
}
function contains(source, pattern, message) {
  if (pattern instanceof RegExp) assert.match(source, pattern, message);
  else assert.equal(source.includes(pattern), true, message);
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-SCAN-014 is documented", () => {
  requirement("REQ-SCAN-014");
});

test("REQ-SCAN-014 run detail shows a distinct reduced-coverage indicator", () => {
  // The state pill alone reads "done" - which is precisely the ambiguity this
  // requirement exists to remove, so a separate indicator is required.
  contains(runDetail, "coverage_degraded:", "RunDetail must detect the coverage_degraded marker");
  contains(runDetail, "reduced coverage", "RunDetail must label the degraded state in plain words");
  contains(runDetail, "pill warn", "the indicator must be visually distinct as a warning");
  contains(styles, ".pill.warn", "the warn pill style must exist");
});

test("REQ-SCAN-014 the explanation states this is not a clean result", () => {
  contains(translation, "coverage_degraded:", "the translator must handle the compound marker");
  contains(
    translation,
    /NOT a clean bill of health/i,
    "the copy must say explicitly that a degraded run is not a clean result",
  );
  contains(
    translation,
    /never once succeeded/i,
    "the copy must explain what actually happened, not just that something is wrong",
  );
});

test("REQ-SCAN-014 compound and combined reasons are both expanded", () => {
  // state_reason may carry "coverage_degraded:...; agent_incomplete:..." - an
  // exact-match lookup cannot resolve either, so prefix handling is required.
  contains(translation, "compoundReasonExplanation", "compound reasons need dedicated handling");
  contains(translation, 'reason.split(";")', "independent warnings must each be explained");
  contains(translation, "agent_incomplete:", "the pre-existing agent_incomplete prefix must also be handled");
});

let failed = 0;
for (const { name, fn } of tests) {
  try {
    fn();
    console.log(`ok - ${name}`);
  } catch (err) {
    failed += 1;
    console.error(`not ok - ${name}\n  ${err.message}`);
  }
}
if (failed > 0) {
  console.error(`\n${failed} test(s) failed`);
  process.exit(1);
}
console.log(`\n${tests.length} test(s) passed`);
