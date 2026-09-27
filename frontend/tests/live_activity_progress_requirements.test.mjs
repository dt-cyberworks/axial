import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = read("docs/requirements/live-activity-progress.md");
const runDetail = read("frontend/src/pages/RunDetail.tsx");
const activity = read("frontend/src/components/RunActivity.tsx");
const translation = read("frontend/src/lib/runActivity.ts");
const runs = read("frontend/src/lib/runs.ts");
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

test("REQ-LIVE-001 renders phase-first expandable scan progress", () => {
  requirement("REQ-LIVE-001");
  contains(runDetail, "Scan progress", "Run page must retain its high-level progress section");
  contains(activity, "Activity by scan phase", "Activity must be grouped by scan phase");
  contains(activity, "progress-tree", "Activity must use a progress tree container");
  contains(activity, "progress-node-header", "Each phase must have an expandable header");
  contains(activity, "aria-expanded", "Phase headers must expose expanded state");
  contains(activity, "row.events.length", "Phase headers must aggregate event counts");
  contains(activity, "row.allowed", "Phase headers must aggregate authorized counts");
  contains(activity, "row.denied", "Phase headers must aggregate blocked counts");
  notContains(runDetail, "entry.reason ?? entry.action", "Raw reasons must not be the operator presentation");
});

test("REQ-LIVE-002 explains phase handoffs and next-step consumption", () => {
  requirement("REQ-LIVE-002");
  contains(runs, "PHASE_COPY", "Phase handoff copy must be explicit and stable");
  contains(runs, "uses:", "Each phase must define what it uses");
  contains(runs, "produces:", "Each phase must define what it produces");
  contains(activity, "Next step", "Expanded phase must identify the next consuming phase");
  contains(runs, "Vector Agent", "Agent phase must be labeled Vector Agent");
  contains(runs, "attack-path validation", "Vector Agent phase must describe attack-path validation");
  contains(styles, "phase-handoff", "Handoff blocks must be styled distinctly");
});

test("REQ-LIVE-003 bounds live details and delegates raw evidence to audit", () => {
  requirement("REQ-LIVE-003");
  contains(runDetail, "limit: 180", "SSE history must be bounded");
  contains(runDetail, "prev.slice(-179)", "In-memory live log must be bounded");
  contains(activity, "visibleEvents.slice(-12)", "Expanded phase detail events must be bounded");
  contains(activity, "older event", "UI must disclose hidden older events");
  contains(activity, "View full audit evidence", "Raw evidence must remain reachable through Audit");
  contains(styles, "progress-events", "Detailed events must remain inside the phase tree");
});

test("REQ-LIVE-004 translates evidence into truthful human outcomes", () => {
  requirement("REQ-LIVE-004");
  contains(translation, "translateToolExecution", "Terminal tool evidence needs a dedicated translation");
  contains(translation, "authorized_target", "Authorized target must remain visible");
  contains(translation, "resolved_target", "Audited materialized IP must remain visible");
  contains(translation, "port_range", "Scanned port range must remain visible");
  contains(translation, "discovered_services", "Discovered service count must remain visible");
  contains(translation, "stderr_summary", "Bounded failure context must remain visible");
  contains(translation, "const successful = payload.success === true;", "Only persisted terminal success may count as completed");
  contains(translation, "countsAsCompletedTool: true", "Successful terminal tool evidence must carry an explicit summary marker");
  contains(translation, "activity.countsAsCompletedTool", "Tool and service totals must use the explicit terminal marker");
  contains(translation, "payload.will_retry === true", "Recoverable length limits must be shown as bounded retries");
  contains(translation, "event === \"finding_reported\"", "Recorded agent findings must remain high-signal events");
  notContains(translation, "payload.success === true || entry.decision", "An audit decision alone must not imply tool success");
  contains(translation, "This records authorization only; execution is reported separately.", "Gateway ALLOW must not claim execution success");
  contains(translation, "Nothing was sent", "Denied actions must explain absence of target traffic");
  contains(translation, "outcome: \"Information\"", "Unknown events must receive a neutral outcome");
  contains(activity, "Technical details", "Technical evidence must use progressive disclosure");
  contains(translation, "Array.isArray(payload.resolved) ? payload.resolved : []", "DNS materialization must read the audited resolved list, not misparse it as an object map");
  contains(translation, "uniqueHosts.add(hostname)", "DNS materialization host count must come from the resolved list's hostnames");
  notContains(translation, "const resolved = record(payload.resolved);", "DNS materialization must not treat the resolved list as a {hostname: ip} map (it always collapses arrays to zero counts)");
});

test("REQ-LIVE-005 prioritizes results and attention over orchestration noise", () => {
  requirement("REQ-LIVE-005");
  for (const label of ["Tool executions completed", "Services discovered", "Actions safely blocked", "Needs attention"]) {
    contains(activity, label, `Summary must include ${label}`);
  }
  contains(activity, "Show routine checks", "Operators must be able to reveal routine events");
  contains(activity, "event.routine", "Routine events must be filtered by default");
  contains(activity, "activity.tone", "Attention semantics must include text-bearing event presentation");
  contains(styles, "human-activity-event.danger", "Failures need a distinct visual treatment");
});

test("REQ-LIVE-006 scopes, deduplicates, and opens the selected run phase", () => {
  requirement("REQ-LIVE-006");
  contains(translation, "at < started || at > finished", "Events outside the run window must be excluded");
  contains(translation, "payloadRunId !== run.id", "Explicit foreign run IDs must be excluded");
  contains(translation, "seen.has(key)", "History duplicates must be removed");
  contains(runDetail, "activityKey(current) === activityKey(entry)", "SSE reconnect duplicates must be rejected before storage");
  contains(activity, "setExpandedPhases(new Set([current]))", "Current phase must open automatically");
  contains(activity, "activity.countsAsAttention || activity.countsAsBlocked", "Attention-bearing phases must be surfaced automatically");
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
