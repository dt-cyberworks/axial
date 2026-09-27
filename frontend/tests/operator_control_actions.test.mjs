import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");
const requirement = read("docs/requirements/operator-control-actions.md");
const dashboard = read("frontend/src/pages/Dashboard.tsx");
const engagement = read("frontend/src/pages/EngagementDetail.tsx");
const run = read("frontend/src/pages/RunDetail.tsx");
const client = read("frontend/src/api/client.ts");

assert.match(requirement, /## REQ-ENG-001:/);
assert.match(client, /res\.status === 204/);
assert.match(client, /deleteEngagement:.*request<void>/s);
assert.match(dashboard, /current\.filter\(\(engagement\) => engagement\.id !== deletedId\)/);
assert.match(dashboard, /removeQueries\(\{ queryKey: \["engagement", deletedId\] \}\)/);
assert.match(dashboard, /removeQueries\(\{ queryKey: \["scan-runs", deletedId\] \}\)/);
assert.match(dashboard, /Audit entries are retained/);
assert.match(engagement, /r\.state === "running" \|\| r\.state === "waiting_approval"/);
assert.match(run, /api\.cancelScanRun/);
assert.match(run, /run\?\.cancel_requested/);
console.log("ok - REQ-ENG-001 and REQ-RUN-001 operator controls are wired to API state");
