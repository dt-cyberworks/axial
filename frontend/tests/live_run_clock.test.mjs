import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirement = read("docs/requirements/operator-console-usability-fixes.md");
const ticker = read("frontend/src/lib/useTicker.ts");
const runs = read("frontend/src/lib/runs.ts");
const runDetail = read("frontend/src/pages/RunDetail.tsx");

assert.match(requirement, /## REQ-RUNUI-001:/);

// A clock exists, ticks once per second, and is cleaned up.
assert.match(ticker, /setInterval\(/, "the ticker must schedule an interval");
assert.match(ticker, /intervalMs = 1000/, "the default cadence must be 1s");
assert.match(ticker, /clearInterval\(timer\)/, "the interval must be cleared on cleanup");
// Gated: an inactive ticker must not schedule anything at all.
assert.match(ticker, /if \(!active\) return;/, "no interval may be scheduled while inactive");

// fmtDuration takes the current time as an explicit input, and ignores it once
// the run has an end timestamp (which is why finished runs need no ticker).
assert.match(
  runs,
  /export function fmtDuration\(startIso: string \| null, endIso: string \| null, now: number = Date\.now\(\)\)/,
  "fmtDuration must accept an explicit `now`",
);
assert.match(runs, /const end = endIso \? new Date\(endIso\)\.getTime\(\) : now;/);

// RunDetail drives it from the run's own state and consumes it at BOTH
// elapsed-time call sites - the header duration and the current-tool banner.
assert.match(runDetail, /useTicker\(isRunning\)/, "the ticker must be gated on the run being in progress");
assert.match(
  runDetail,
  /fmtDuration\(run\?\.started_at \?\? null, run\?\.finished_at \?\? null, now\)/,
  "the header duration must use the ticking value",
);
assert.match(
  runDetail,
  /fmtDuration\(run\.current_started_at, null, now\)/,
  "the current-tool banner must use the ticking value",
);

console.log("ok - REQ-RUNUI-001 live run elapsed time advances on its own cadence");
