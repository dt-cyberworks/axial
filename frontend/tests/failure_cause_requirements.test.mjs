import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirements = read("docs/requirements/scan-pipeline.md");
const activity = read("frontend/src/lib/runActivity.ts");
const planView = read("frontend/src/components/ScanPlanView.tsx");
const report = read("control-plane/app/report_builder.py");

// REQ-PIPE-021 (GitHub issue #49): a failed or safety-stopped run says why.
assert.match(requirements, /## REQ-PIPE-021:/);

// The console explains the real reason instead of "Technical reason: Pipeline Error".
assert.match(activity, /cancellation_status_unavailable:\s*\n?\s*"The control plane could not say whether the operator had cancelled/,
  "the run summary must explain a safety stop");
assert.doesNotMatch(activity.match(/cancellation_status_unavailable:[\s\S]*?",\n/)[0], /operator requested/,
  "a safety stop must not read as an operator request");
assert.match(activity, /task_time_limit_exceeded:/, "the time-limit reason needs text too");
assert.match(activity, /reason\.startsWith\("pipeline_error:"\)/, "pipeline_error:<Type>:<phase> is expanded");
assert.match(activity, /internal error \(\$\{type\}\) while it was in the \$\{phase\} phase/);

// The plan view and the customer report must not call it an operator stop.
assert.match(planView, /cancellation_status_unavailable: "Stopped as a safety measure/);
assert.match(report, /"cancellation_status_unavailable": "stopped as a safety measure/);
assert.match(planView, /cancelled_by_operator: "Stopped by the operator"/, "a real operator stop keeps its text");

console.log("ok - REQ-PIPE-021 a failed or safety-stopped run names its real cause");
