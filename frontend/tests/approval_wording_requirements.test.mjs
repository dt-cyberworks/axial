import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { loadTs } from "./_ts.mjs";
import { readRecord, record } from "./_records.mjs";

const repo = resolve(import.meta.dirname, "../..");
const requirements = readRecord("requirements", "approval-popup-wording.md");
const { approvalWording, isWriteRequest } = await loadTs("src/lib/approvalWording.ts");

const get = (over = {}) => ({ tool: "http_request", target: "3.74.27.213", phase: "agent", args: { method: "GET", path: "/", headers: { Host: "3.74.27.213" } },
  rationale: "The proxy needs a Host header for a bare IP.", risk: null, ...over });
const post = (over = {}) => ({ tool: "http_request", target: "app.example.test", phase: "agent", args: { method: "POST", path: "/login", body: "a=1" },
  rationale: "log in with the demo account", risk: { level: "low", description: "establishes a session" }, ...over });
const pipeline = (over = {}) => ({ tool: "ffuf", target: "app.example.test", phase: "fingerprint", args: { wordlist: "quickhits" },
  rationale: "Content discovery (quickhits), part of the automatic scan", risk: null, ...over });

test("REQ-APPROVALUI-003 an agent GET reads as a read-only request with the agent's own reason", () => {
  record.match(requirements, /## REQ-APPROVALUI-003:/);
  const w = approvalWording(get());
  assert.equal(w.heading, "Approval required — request");
  assert.equal(w.action, "The Vector Agent wants to send a read-only request");
  assert.equal(w.badge, "read-only request");
  assert.equal(w.whyLabel, "Why (agent rationale)");
  assert.equal(w.whyText, "The proxy needs a Host header for a bare IP.");
  assert.equal(w.isWrite, false);
});

test("REQ-APPROVALUI-003 a write keeps the state-changing wording and its risk level", () => {
  const w = approvalWording(post());
  assert.equal(w.heading, "Approval required — state-changing request");
  assert.equal(w.action, "The Vector Agent wants to send a write request");
  assert.equal(w.badge, "risk: low");
  for (const method of ["PUT", "PATCH", "DELETE"]) assert.equal(approvalWording(post({ args: { method } })).isWrite, true, method);
  assert.equal(approvalWording(post({ risk: null })).badge, "risk: not assessed");
});

test("REQ-APPROVALUI-003 [negative] a request with a body is a write whatever its method or its rating says", () => {
  const sneaky = get({ args: { method: "GET", path: "/", body: "x=1" }, risk: { level: "low", description: "harmless" } });
  assert.equal(isWriteRequest(sneaky), true);
  const w = approvalWording(sneaky);
  assert.equal(w.heading, "Approval required — state-changing request");
  assert.match(w.badge, /^risk:/);
});

test("REQ-APPROVALUI-003 the heading, the badge and the sender never contradict the request", () => {
  for (const tc of [get(), get({ args: { method: "HEAD" } }), get({ args: { method: "OPTIONS" } }), post(), pipeline(), pipeline({ phase: "agent" })]) {
    const w = approvalWording(tc);
    if (!w.isWrite) {
      assert.doesNotMatch(w.heading, /state-changing/, JSON.stringify(tc));
      assert.doesNotMatch(w.action, /write request/, JSON.stringify(tc));
      assert.doesNotMatch(w.badge, /^risk:/, JSON.stringify(tc));
    } else {
      assert.match(w.heading, /state-changing/);
      assert.match(w.action, /write request/);
    }
  }
});

test("REQ-APPROVALUI-003 a check of the automatic scan names the scan, not the agent, and shows its reason", () => {
  const w = approvalWording(pipeline());
  assert.equal(w.heading, "Approval required — check");
  assert.equal(w.action, "The automatic scan wants to run ffuf");
  assert.equal(w.whyLabel, "Why (automatic scan)");
  assert.equal(w.whyText, "Content discovery (quickhits), part of the automatic scan");
  assert.equal(w.badge, "read-only check");
  assert.equal(w.fromAgent, false);
  assert.equal(approvalWording(pipeline({ phase: "agent" })).action, "The Vector Agent wants to run ffuf");
});

test("REQ-APPROVALUI-003 a missing reason is said honestly, in the voice of whoever raised the request", () => {
  for (const empty of [null, undefined, "", "   "]) {
    assert.equal(approvalWording(get({ rationale: empty })).whyText, "The agent gave no reason for this request.");
    assert.equal(approvalWording(pipeline({ rationale: empty })).whyText, "No reason was recorded for this check.");
  }
  assert.doesNotMatch(readFileSync(resolve(repo, "frontend/src/components/ApprovalModal.tsx"), "utf8"), /no rationale provided/);
});

test("REQ-APPROVALUI-003 [negative] the reason is shown as text: markup in it is neither run nor interpreted", () => {
  const evil = '<script>alert(1)</script><img src=x onerror=alert(1)>';
  assert.equal(approvalWording(get({ rationale: evil })).whyText, evil, "the helper does not touch the text");
  const modal = readFileSync(resolve(repo, "frontend/src/components/ApprovalModal.tsx"), "utf8");
  assert.doesNotMatch(modal, /dangerouslySetInnerHTML|innerHTML/);
  assert.match(modal, /<p>\{wording\.whyText\}<\/p>/, "the reason goes through React's text rendering");
});

test("REQ-APPROVALUI-003 the popup uses the helper for its heading, sender, badge and reason", () => {
  const modal = readFileSync(resolve(repo, "frontend/src/components/ApprovalModal.tsx"), "utf8");
  for (const piece of ["{wording.heading}", "{wording.action}", "{wording.badge}", "{wording.whyLabel}"]) assert.ok(modal.includes(piece), piece);
});
