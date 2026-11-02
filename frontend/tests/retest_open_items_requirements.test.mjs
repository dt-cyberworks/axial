import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { loadTs } from "./_ts.mjs";
import { readRecord, record } from "./_records.mjs";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");
const requirements = readRecord("requirements", "retest-open-items.md");
const review = await loadTs("src/lib/runReview.ts");
const activity = await loadTs("src/lib/runActivity.ts");

const check = (over = {}) => ({
  id: "check:app.example.test:443:ffuf", kind: "check", host: "app.example.test", port: 443, check: "ffuf", tool: "ffuf",
  title: "ffuf on app.example.test:443", state: "failed", reason: "nonzero_exit", needs_confirmation: false,
  state_changing: false, age_days: 1, run_id: "r1", expired: false, ...over,
});
const post = (over = {}) => ({
  id: "0199aaaa-0000-7000-8000-000000000001", kind: "request", host: "app.example.test", port: null, check: null,
  tool: "http_request", title: "POST /login on app.example.test", state: "held_back", reason: "approval_unavailable_unattended",
  needs_confirmation: true, state_changing: true, age_days: 2, run_id: "r0", expired: false,
  request: { target: "app.example.test", method: "POST", path: "/login", body: "username=guest&password=guest",
    headers: {}, rationale: "the login page shows a demo account", risk: { level: "low", description: "establishes a session" } },
  ...over,
});

test("REQ-RETEST-005 read-only checks are one group and everything that needs a confirmation is another", () => {
  record.match(requirements, /## REQ-RETEST-005:/);
  const items = [check(), post(), check({ id: "check:x:80:nikto", needs_confirmation: true, tool: "nikto" }), post({ id: "p2", expired: true })];
  const groups = review.groupItems(items);
  assert.deepEqual(groups.readOnly.map((i) => i.id), ["check:app.example.test:443:ffuf"]);
  assert.deepEqual(groups.needsConfirmation.map((i) => i.id), [post().id, "check:x:80:nikto"]);
  assert.deepEqual(groups.expired.map((i) => i.id), ["p2"]);
});

test("REQ-RETEST-005 [negative] nothing that needs a confirmation, and nothing expired, is preselected", () => {
  const items = [check(), post(), check({ id: "c2", needs_confirmation: true }), post({ id: "p2", expired: true })];
  const chosen = review.initialChoice(items);
  assert.equal(chosen["check:app.example.test:443:ffuf"], true, "a read-only check starts included");
  assert.equal(chosen[post().id], false);
  assert.equal(chosen.c2, false);
  assert.equal(chosen.p2, false);
  assert.equal(review.buildStartOptions([post(), check({ id: "c2", needs_confirmation: true })], review.initialChoice([post(), check({ id: "c2", needs_confirmation: true })])), null,
    "starting with only unconfirmed items starts nothing");
});

test("REQ-RETEST-006 a request is sent only when it is chosen, and only the chosen ones", () => {
  record.match(requirements, /## REQ-RETEST-006:/);
  const a = post({ id: "p-a" }), b = post({ id: "p-b" });
  const chosen = { ...review.initialChoice([a, b]), "p-b": true };
  const options = review.buildStartOptions([a, b], chosen);
  assert.deepEqual(options.send_requests, ["p-b"]);
  assert.equal(options.items, undefined, "no check is part of a run that only sends");
  assert.equal(options.supervision, "attended", "a run that sends a request is attended");
});

test("REQ-RETEST-006 [negative] an expired request can never be sent, even if it was chosen", () => {
  const old = post({ id: "p-old", expired: true });
  assert.equal(review.buildStartOptions([old], { "p-old": true }), null);
  assert.equal(review.countChosen([old], { "p-old": true }).requests, 0);
});

test("REQ-RETEST-002 the start options carry the checks, the host and the finding being retested", () => {
  const items = [check(), check({ id: "n", check: null, tool: "nuclei", port: null, host: "app.example.test", title: "nuclei" })];
  const options = review.buildStartOptions(items, review.initialChoice(items), { retestFindingId: "f1" });
  assert.deepEqual(options.items, [
    { host: "app.example.test", port: 443, check: "ffuf" },
    { host: "app.example.test", tool: "nuclei" },
  ]);
  assert.equal(options.retest_finding_id, "f1");
  assert.equal(options.send_requests, undefined);
});

test("REQ-RETEST-005 the button says what it starts", () => {
  const a = post({ id: "p-a" }), b = post({ id: "p-b" });
  const c1 = check(), c2 = check({ id: "c2" });
  assert.equal(review.runLabel([c1], review.initialChoice([c1])), "Run 1 check");
  assert.equal(review.runLabel([c1, c2], review.initialChoice([c1, c2])), "Run 2 checks");
  assert.equal(review.runLabel([c1, c2, a], { ...review.initialChoice([c1, c2, a]), [a.id]: true }), "Run 2 checks and 1 request that changes data");
  assert.equal(review.runLabel([a, b], { [a.id]: true, [b.id]: true }), "Send 2 requests that change data");
  assert.equal(review.runLabel([a], review.initialChoice([a])), "Nothing chosen to run");
});

test("REQ-RETEST-005 a request says in plain words what it does, by what it sends, not by the agent's rating", () => {
  assert.match(review.describeRequest("POST", true), /sends data to the target \(POST\)/);
  assert.match(review.describeRequest("DELETE", false), /deletes data on the target \(DELETE\)/);
  assert.match(review.describeRequest("GET", true), /sends data to the target \(GET with a body\)/, "a body makes any method a write");
  assert.match(review.describeRequest("GET", false), /reads from the target/);
  assert.deepEqual(review.choiceLabels(post()), { off: "Do not send", on: "Send this request" });
  assert.deepEqual(review.choiceLabels(check()), { off: "Do not run", on: "Run this check" });
});

test("REQ-RETEST-003 the ids and families match the control plane's", () => {
  assert.equal(review.checkFamily("nuclei:generic:2of5"), "nuclei:generic");
  assert.equal(review.checkFamily("ffuf:deep"), "ffuf:deep");
  assert.equal(review.openItemId("APP.Example.test", 443, "nuclei:all:3of14"), "check:app.example.test:443:nuclei:all");
  assert.equal(review.ageText(0.2), "today");
  assert.equal(review.ageText(3.4), "3 days ago");
  assert.equal(review.ageText(1.1), "1 day ago");
});

test("REQ-RETEST-005/007 the screen: two groups, a choice per item, no send-all, no bare OK", () => {
  const screen = read("frontend/src/components/RunReview.tsx");
  assert.match(screen, /Review before you run/);
  assert.match(screen, /Runs without asking \(read-only\)/);
  assert.match(screen, /Needs your confirmation - this sends data to the target/);
  assert.match(screen, /type="radio"/, "each item has its own choice");
  assert.match(screen, /Never send this/);
  assert.match(screen, /Too old to send/);
  assert.doesNotMatch(screen, /[Ss]end all|[Aa]pprove all|[Ss]elect all/, "there is no bulk way to send");
  assert.doesNotMatch(screen, />\s*OK\s*</, "a button names the action");
  assert.match(screen, /Nothing starts until you press the button/);
});

test("REQ-RETEST-001/003 the entry points: the finding, the plan step and the open-items page", () => {
  record.match(requirements, /## REQ-RETEST-001:/);
  record.match(requirements, /## REQ-RETEST-003:/);
  assert.match(read("frontend/src/components/FindingDetail.tsx"), /<RetestControl finding=\{finding\} canManage=\{canManage\}/);
  const control = read("frontend/src/components/RetestControl.tsx");
  assert.match(control, /Retest this finding/);
  assert.match(control, /getRetestPlan/);
  assert.match(control, /finding\.status !== "open"/, "only an open finding can be retested");
  assert.match(read("frontend/src/components/ScanPlanView.tsx"), /Run this step again/);
  assert.match(read("frontend/src/App.tsx"), /\/engagements\/:id\/open-items/);
  assert.match(read("frontend/src/pages/EngagementDetail.tsx"), /Not done yet \(\{openItems!\.counts\.total\}\)/);
  assert.match(read("frontend/src/pages/OpenItems.tsx"), /A monitor never sends requests that change data/);
});

test("REQ-RETEST-007 the activity view tells a sent request, an unsent one and a left-out check apart", () => {
  record.match(requirements, /## REQ-RETEST-007:/);
  const entry = (event, extra = {}) => ({
    ts: "2026-10-20T10:00:00Z", actor: "worker", action: "agent_event", decision: "ALLOW", reason: "x",
    payload: { event, proposal: { tool: "http_request", target: "app.example.test", method: "POST", path: "/login" }, ...extra },
  });
  const sending = activity.translateActivity(entry("open_request_sending"), "agent");
  assert.match(sending.title, /Sending the request you confirmed/);
  const sent = activity.translateActivity(entry("open_request_sent", { observation: "HTTP 302" }), "agent");
  assert.equal(sent.outcome, "Sent");
  assert.equal(sent.tone, "success");
  const notSent = activity.translateActivity({ ...entry("open_request_not_sent"), decision: "DENY", reason: "outside_time_window" }, "agent");
  assert.equal(notSent.outcome, "Not sent");
  assert.notEqual(notSent.tone, "danger", "a request that was not sent is open again, not a red failure");
  assert.match(activity.reasonExplanation("not_in_this_run"), /not a failure and nothing is missing/);
  assert.match(activity.reasonExplanation("not_sent:outside_time_window"), /open again, nothing was lost \(outside_time_window\)/);
  assert.match(activity.reasonExplanation("run_ended_early"), /Run it again/);
});
