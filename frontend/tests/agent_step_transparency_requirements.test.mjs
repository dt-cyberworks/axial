import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = read("docs/requirements/scan-run-workflow-and-transparency.md");
const runDetail = read("frontend/src/pages/RunDetail.tsx");

function requirement(id) {
  assert.match(requirementDoc, new RegExp(`## ${id}:`), `${id} must be documented before it is tested`);
}

function notContains(source, pattern, message) {
  if (pattern instanceof RegExp) assert.doesNotMatch(source, pattern, message);
  else assert.equal(source.includes(pattern), false, message);
}

function contains(source, pattern, message) {
  if (pattern instanceof RegExp) assert.match(source, pattern, message);
  else assert.equal(source.includes(pattern), true, message);
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-RUN-006 renders the Vector Agent tab as an incremental transcript", () => {
  requirement("REQ-RUN-006");
  contains(runDetail, "previous={agentSteps[i - 1]}", "each step row must receive the previous step for slicing");
  contains(runDetail, /request_messages\.slice\(previous\?\.request_messages\.length/, "step body must slice off messages already shown by the previous step");
  notContains(runDetail, /step\.request_messages\.map\(\(m, i\)/, "must not unconditionally map the full cumulative request_messages every step");
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
