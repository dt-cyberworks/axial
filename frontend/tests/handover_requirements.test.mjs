import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { loadTs } from "./_ts.mjs";
import { readRecord, record } from "./_records.mjs";

// REQ-HANDOVER-001..007 (GitHub #84): the console side of "Test deeper". The rules live in src/lib/handover.ts so they run
// here without a browser; the components are checked against what the requirement says they must show.
const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");
const requirements = readRecord("requirements", "monitor-to-assessment-handover.md");
const h = await loadTs("src/lib/handover.ts");

const HOSTS = [
  { host: "www.example.test", asset_type: "domain", held: false, services: 2, open_findings: 1, denied_by: null },
  { host: "dev.example.test", asset_type: "domain", held: true, services: 1, open_findings: 1, denied_by: null },
  { host: "secret.example.test", asset_type: "domain", held: false, services: 0, open_findings: 0, denied_by: "secret.example.test" },
];
const form = (patch = {}) => ({ ...h.emptyForm("Test: Sirkos", "ops@example.test"), ...patch });
const WINDOW = { from: "2026-11-02T09:00", until: "2026-11-09T18:00" };

test("REQ-HANDOVER-001 the action is for the owner or an administrator of an active or paused monitor, and for nobody else", () => {
  record.match(requirements, /## REQ-HANDOVER-001:/);
  const base = { operating_mode: "monitoring", status: "active", can_manage: true };
  assert.equal(h.canStartHandover(base), true);
  assert.equal(h.canStartHandover({ ...base, status: "paused" }), true);
  for (const status of ["draft", "completed", "revoked", "awaiting_signature"]) assert.equal(h.canStartHandover({ ...base, status }), false, status);
  assert.equal(h.canStartHandover({ ...base, operating_mode: "assessment" }), false);
  assert.equal(h.canStartHandover({ ...base, can_manage: false }), false, "a reader of someone else's monitor does not see it");
});

test("REQ-HANDOVER-003 the window starts empty, is required and must end after it starts: the monitor's is never reused", () => {
  record.match(requirements, /## REQ-HANDOVER-003:/);
  const empty = h.emptyForm("Test: x");
  assert.equal(empty.from, "");
  assert.equal(empty.until, "");
  assert.match(h.blocker(form(), HOSTS), /Give the test window/);
  assert.match(h.blocker(form({ from: WINDOW.until, until: WINDOW.from, chosen: ["www.example.test"] }), HOSTS), /must end after it starts/);
  assert.match(h.blocker(form({ from: WINDOW.from, until: WINDOW.from, chosen: ["www.example.test"] }), HOSTS), /must end after it starts/);
  assert.equal(h.blocker(form({ ...WINDOW, chosen: ["www.example.test"] }), HOSTS), null);
});

test("REQ-HANDOVER-003 at least one selectable host is needed, and a denied host can never be chosen or sent", () => {
  assert.match(h.blocker(form({ ...WINDOW }), HOSTS), /Pick at least one host/);
  assert.equal(h.selectable(HOSTS[2]), false);
  assert.match(h.blocker(form({ ...WINDOW, chosen: ["secret.example.test"] }), HOSTS), /Pick at least one host/);
  const request = h.buildRequest(form({ ...WINDOW, chosen: ["www.example.test", "secret.example.test"] }), HOSTS);
  assert.deepEqual(request.hosts, ["www.example.test"], "a denied host is dropped before the request is built");
});

test("REQ-HANDOVER-003 a held host may be chosen; the row says the monitor's hold is not released", () => {
  assert.equal(h.selectable(HOSTS[1]), true);
  assert.match(h.HELD_NOTE, /you are choosing to test it here/);
  assert.match(h.HELD_NOTE, /hold is not released/);
  assert.deepEqual(h.buildRequest(form({ ...WINDOW, chosen: ["dev.example.test"] }), HOSTS).hosts, ["dev.example.test"]);
});

test("REQ-HANDOVER-003 the whole scope is a second, confirmed choice and sends no individual hosts", () => {
  const whole = form({ ...WINDOW, wholeScope: true, chosen: ["www.example.test"] });
  assert.match(h.blocker(whole, HOSTS), /Confirm that the whole scope/);
  const confirmed = { ...whole, wholeScopeConfirmed: true };
  assert.equal(h.blocker(confirmed, HOSTS), null);
  const request = h.buildRequest(confirmed, HOSTS);
  assert.equal(request.scope_mode, "same_scope");
  assert.deepEqual(request.hosts, []);
  assert.equal(h.buildRequest(form({ ...WINDOW, chosen: ["www.example.test"] }), HOSTS).scope_mode, "hosts", "hosts is the default");
});

test("REQ-HANDOVER-001 the request carries the window as UTC instants, a trimmed title and a contact only when given", () => {
  const request = h.buildRequest(form({ ...WINDOW, title: "  Deep test  ", emergencyContact: " ", chosen: ["www.example.test"] }), HOSTS);
  assert.equal(request.title, "Deep test");
  assert.equal(request.emergency_contact, undefined);
  assert.equal(request.authorized_from, new Date(WINDOW.from).toISOString());
  assert.equal(request.authorized_until, new Date(WINDOW.until).toISOString());
  assert.equal(h.buildRequest(form({ ...WINDOW, title: "", chosen: ["www.example.test"] }), HOSTS).title, undefined);
});

test("REQ-HANDOVER-009 every refusal code has a sentence, and an unknown message is passed through", () => {
  record.match(requirements, /## REQ-HANDOVER-009:/);
  for (const code of ["handover_monitor_not_active", "handover_source_unsupported", "handover_host_unknown", "handover_host_denied",
    "handover_window_invalid", "handover_hosts_required", "handover_hosts_not_allowed", "handover_forbidden"]) {
    assert.ok(h.HANDOVER_REFUSALS[code], code);
    assert.equal(h.handoverRefusal(`POST /engagements/x/handover -> 422: ${code}`), h.HANDOVER_REFUSALS[code]);
  }
  assert.equal(h.handoverCode("POST /x -> 409: handover_monitor_not_active"), "handover_monitor_not_active");
  assert.equal(h.handoverCode("something else"), null);
  assert.equal(h.handoverRefusal("network down"), "network down");
  assert.match(h.HANDOVER_REFUSALS.handover_host_denied, /can never be tested/);
});

test("REQ-HANDOVER-006 the dialog tells the truth about running both at once, and never pauses the monitor itself", () => {
  record.match(requirements, /## REQ-HANDOVER-006:/);
  assert.match(h.overlapSentence("both_may_run"), /keeps running while the assessment is active/);
  assert.match(h.overlapSentence("both_may_run"), /traffic from both/);
  const blocked = h.overlapSentence("monitor_must_pause");
  assert.match(blocked, /will be refused while the monitor is active/);
  assert.match(blocked, /Pause engagement/);
  assert.match(blocked, /Nothing here pauses it for you/);
});

test("REQ-HANDOVER-001/004 the dialog shows what carries over and what does not, creates a draft and opens the wizard on it", () => {
  const dialog = read("frontend/src/components/HandoverDialog.tsx");
  assert.match(dialog, /What carries over/);
  assert.match(dialog, /What does not/);
  assert.match(dialog, /Test this target in depth/);
  assert.match(dialog, /Create draft assessment/);
  assert.match(dialog, /Test window starts/);
  assert.match(dialog, /Test window ends/);
  assert.match(dialog, /Use the monitor's whole scope instead/);
  assert.match(dialog, /The monitor's deny rules are always carried/);
  assert.match(dialog, /Nothing is authorized yet/);
  assert.match(dialog, /navigate\(`\/new\?mode=assessment&draft=\$\{created\.id\}`\)/);
  assert.doesNotMatch(dialog, /api\.(pause|close|revoke|resume)Engagement/, "the handover never touches the monitor's lifecycle");
});

test("REQ-HANDOVER-001/007 the button is in the lifecycle row, behind the same rule, and the two engagements link to each other", () => {
  record.match(requirements, /## REQ-HANDOVER-007:/);
  const lifecycle = read("frontend/src/components/EngagementLifecycle.tsx");
  assert.match(lifecycle, /canStartHandover\(engagement\) && \(/);
  assert.match(lifecycle, /Test deeper/);
  const detail = read("frontend/src/pages/EngagementDetail.tsx");
  assert.match(detail, /Follows monitoring engagement/);
  assert.match(detail, /isMonitoring && !isDraft && <HandoverList/);
  const list = read("frontend/src/components/HandoverList.tsx");
  assert.match(list, /Assessments from this monitor/);
  assert.match(list, /No assessment has been started from this monitor\./);
  for (const column of ["Title", "Status", "Owner", "Test window"]) assert.match(list, new RegExp(`<th>${column}</th>`));
});

test("REQ-HANDOVER-004 the wizard says on a handover draft that it was prefilled and that nothing is authorized", () => {
  record.match(requirements, /## REQ-HANDOVER-004:/);
  const wizard = read("frontend/src/pages/EngagementWizard.tsx");
  assert.match(wizard, /handoverFrom && \(/);
  assert.match(wizard, /Prefilled from monitoring engagement/);
  assert.match(wizard, /Nothing is authorized until you attest your authorization and activate in step 5/);
  assert.match(wizard, /setHandoverFrom\(eng\.handover_from \?\? null\)/);
});
