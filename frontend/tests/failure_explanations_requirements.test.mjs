import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { loadTs } from "./_ts.mjs";
import { readRecord, record } from "./_records.mjs";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");
const requirements = readRecord("requirements", "failure-explanations.md");
const activity = await loadTs("src/lib/runActivity.ts");

const entry = (action, fields) => ({
  ts: "2026-10-19T10:00:00Z", actor: "worker", action, decision: null, reason: null, payload: {}, ...fields,
});
const execution = (tool, target, errorReason, extra = {}) => entry("tool_execution", {
  payload: { tool, authorized_target: target, success: false, error_reason: errorReason, ...extra },
});
const translate = (e) => activity.translateActivity(e, "fingerprint");

test("REQ-EXPLAIN-002 a reason with no text is shown as unexplained, with its code", () => {
  record.match(requirements, /## REQ-EXPLAIN-002:/);
  const text = activity.reasonExplanation("a_code_nobody_wrote_down");
  assert.match(text, /^Unexplained reason: a_code_nobody_wrote_down\./);
  assert.doesNotMatch(text, /Technical reason|A Code Nobody/);
});

test("REQ-EXPLAIN-002 a family code with a detail is explained through its family", () => {
  assert.match(activity.reasonExplanation("gateway_denied:no_tool_grant"), /Scope Gateway refused this call\. This engagement does not grant/);
  assert.match(activity.reasonExplanation("approval_claim_denied:window_closed"), /checked it again before running/);
  assert.doesNotMatch(activity.reasonExplanation("handler_error:KeyError"), /Unexplained/);
});

test("REQ-EXPLAIN-003 materialized_ip_missing names the cause, is true for every tool, and says what to do", () => {
  record.match(requirements, /## REQ-EXPLAIN-003:/);
  const text = activity.reasonExplanation("materialized_ip_missing");
  assert.match(text, /This name has no DNS address, so nothing was sent to it/);
  assert.match(text, /fix its DNS record/);
  assert.match(text, /add a deny rule or remove it from the scope/);
  assert.doesNotMatch(text, /raw scanning/, "the old text blamed nmap only");
  // The Plan tab uses the same cause in its own words.
  assert.match(read("frontend/src/components/ScanPlanView.tsx"), /materialized_ip_missing: "The name has no DNS address/);
});

test("REQ-EXPLAIN-004 six tools skipping one unresolvable name make one calm row, not six failures", () => {
  record.match(requirements, /## REQ-EXPLAIN-004:/);
  const name = "events-test.example.org";
  const rows = ["nmap", "httpx", "wafw00f", "testssl", "ffuf", "nuclei"].map((tool) => translate(execution(tool, name, "materialized_ip_missing")));
  for (const row of rows) {
    assert.equal(row.outcome, "Skipped", `${row.title} must read as a skip`);
    assert.notEqual(row.tone, "danger");
  }
  const merged = activity.consolidateActivities(rows);
  assert.equal(merged.length, 1);
  assert.equal(merged[0].title, `${name} has no DNS address`);
  assert.equal(merged[0].outcome, "Skipped");
  assert.equal(merged[0].countsAsAttention, false);
  for (const tool of ["Nmap", "HTTPX", "WAF detection", "TLS test", "Content discovery", "Nuclei"]) {
    assert.match(merged[0].facts.map((f) => f.value).join(" | "), new RegExp(tool));
  }
});

test("REQ-EXPLAIN-004 [negative] another name, and a real failure, are not merged away", () => {
  const rows = [
    translate(execution("nmap", "a.example.com", "materialized_ip_missing")),
    translate(execution("nmap", "b.example.com", "materialized_ip_missing")),
    translate(execution("httpx", "c.example.com", "nonzero_exit")),
  ];
  const merged = activity.consolidateActivities(rows);
  assert.equal(merged.length, 3);
  const failure = merged.find((row) => row.target === "c.example.com");
  assert.equal(failure.outcome, "Failed");
  assert.equal(failure.tone, "danger");
  assert.equal(failure.countsAsAttention, true);
});

test("REQ-EXPLAIN-004 a recorded outcome beats the code list; the code list matches the worker's", () => {
  const skipped = translate(execution("nuclei", "x.example.com", "something_new", { outcome_summary: { outcome: "skipped:something_new" } }));
  assert.equal(skipped.outcome, "Skipped");
  const workerSkips = /SKIP_REASONS = frozenset\(\{(.*?)\}\)/s.exec(read("worker/app/tool_execution.py"))[1].match(/"([a-z_]+)"/g).map((s) => s.replace(/"/g, ""));
  assert.deepEqual([...activity.SKIPPED_CODES].sort(), workerSkips.sort());
});

test("REQ-GRANT-001 a refused call for a missing grant names the category and mode it needed", () => {
  record.match(requirements, /## REQ-GRANT-001:/);
  const deny = entry("tool_call", {
    actor: "gateway", decision: "DENY", reason: "no_tool_grant",
    payload: { tool: "subfinder", category: "recon", mode: "passive", target: "example.org" },
  });
  const row = translate(deny);
  assert.match(row.summary, /no recon \/ passive grant, which Subdomain discovery needs/);
  assert.match(row.summary, /Tick Passive for Recon under Edit engagement → Tool grants/);
  assert.ok(row.facts.some((f) => f.label === "Needs grant" && f.value === "recon / passive"));
});

test("REQ-GRANT-001 [negative] other refusals keep their own text", () => {
  const row = translate(entry("tool_call", {
    actor: "gateway", decision: "DENY", reason: "explicit_out_of_scope",
    payload: { tool: "httpx", category: "fingerprint", mode: "active", target: "x.example.com" },
  }));
  assert.match(row.summary, /A deny rule matched this target/);
  assert.ok(!row.facts.some((f) => f.label === "Needs grant"));
});

test("REQ-GRANT-001 one denial is one row: the gateway's entry and the tool's 'gateway_denied' result are paired", () => {
  const deny = entry("tool_call", {
    actor: "gateway", decision: "DENY", reason: "no_tool_grant",
    payload: { tool: "subfinder", category: "recon", mode: "passive", target: "example.org" },
  });
  const result = execution("subfinder", "example.org", "gateway_denied:no_tool_grant");
  const rows = [translate(deny), translate(result)];
  assert.equal(activity.consolidateActivities(rows).length, 1);
  // [negative] a result with no matching refusal (older logs) stays visible, as a skip.
  const alone = activity.consolidateActivities([translate(result)]);
  assert.equal(alone.length, 1);
  assert.equal(alone[0].outcome, "Skipped");
  // [negative] a refusal for another host is not swallowed.
  const other = translate(execution("subfinder", "other.example.com", "gateway_denied:no_tool_grant"));
  assert.equal(activity.consolidateActivities([translate(deny), other]).length, 2);
});

test("REQ-EXPLAIN-001 every key of the console's map has a real text", () => {
  record.match(requirements, /## REQ-EXPLAIN-001:/);
  const block = /const REASON_COPY: Record<string, string> = \{(.*?)\n\};/s.exec(read("frontend/src/lib/runActivity.ts"))[1];
  const keys = [...block.matchAll(/^\s{2}"?([a-z_]+)"?:/gm)].map((m) => m[1]);
  assert.ok(keys.length > 100, `the map must be read completely (found ${keys.length})`);
  for (const key of keys) assert.ok(activity.reasonExplanation(key).length > 20 && !activity.reasonExplanation(key).startsWith("Unexplained"), key);
});
