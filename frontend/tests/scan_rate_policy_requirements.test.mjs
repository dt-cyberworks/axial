import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = read("docs/requirements/scan-rate-policy.md");
const settingsPage = read("frontend/src/pages/Settings.tsx");
const client = read("frontend/src/api/client.ts");
const settingsApi = read("control-plane/app/api/settings.py");
const settingsStore = read("control-plane/app/settings_store.py");
const gateway = read("control-plane/app/gateway/authorize.py");
const internalSchema = read("control-plane/app/schemas/internal.py");
const internalApi = read("control-plane/app/api/internal.py");
const fingerprint = read("worker/app/tasks/fingerprint.py");
const agent = read("worker/app/tasks/agent.py");
const audit = read("frontend/src/pages/Audit.tsx");
const runActivity = read("frontend/src/lib/runActivity.ts");

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

test("REQ-RATE-001 exposes configurable rate limit in Settings", () => {
  requirement("REQ-RATE-001");
  contains(settingsPage, "Scan rate policy", "Settings must contain a scan rate policy section");
  contains(settingsPage, "Maximum allowed tool calls per second", "Settings must expose max RPS input");
  contains(client, "getScanPolicy", "Frontend client must read scan policy");
  contains(client, "updateScanPolicy", "Frontend client must update scan policy");
  contains(settingsApi, '@router.get("/scan-policy"', "Backend must expose GET scan-policy");
  contains(settingsApi, '@router.put("/scan-policy"', "Backend must expose PUT scan-policy");
  contains(settingsStore, 'SCAN_POLICY_KEY = "scan_policy"', "Scan policy must persist via app_setting key");
});

test("REQ-RATE-002 auto slow down produces throttle retry path without bypass", () => {
  requirement("REQ-RATE-002");
  contains(settingsPage, "Automatically slow down and retry rate-limited tool calls", "Settings must expose auto slow down toggle");
  contains(gateway, 'THROTTLE("rate_limited_wait", reservation.retry_after_seconds)', "Gateway must return soft throttle when enabled");
  contains(gateway, 'audit_decision = "PENDING" if decision.is_pending else ("THROTTLE"', "Gateway audit must record THROTTLE distinctly");
  contains(gateway, 'payload["retry_after_seconds"]', "Gateway audit payload must include retry delay");
  contains(internalSchema, "is_throttled: bool = False", "Internal schema must expose throttled flag");
  contains(internalSchema, "retry_after_seconds: float | None = None", "Internal schema must expose retry delay");
  contains(internalApi, "is_throttled=decision.is_throttled", "Internal API must pass throttled flag to workers");
  contains(fingerprint, 'decision.get("is_throttled")', "Fingerprint worker must detect throttle responses");
  contains(fingerprint, "time.sleep(delay)", "Fingerprint worker must wait before retrying");
  contains(agent, 'decision.get("is_throttled")', "Agent must detect throttle responses");
  contains(agent, '"proposal_throttled"', "Agent must emit throttling telemetry");
  contains(agent, "time.sleep(delay)", "Agent must wait before retrying");
  contains(fingerprint, 'if decision["allowed"]:\n            return decision', "Fingerprint dispatch remains gated on a later ALLOW");
  contains(agent, 'if decision.get("allowed") or not decision.get("is_throttled"):', "Agent must not execute on THROTTLE itself");
});

test("REQ-RATE-003 hard deny remains available and UI explains both modes", () => {
  requirement("REQ-RATE-003");
  contains(gateway, 'DENY("rate_limited")', "Gateway must retain hard denial when auto slow down is disabled");
  contains(audit, "rate_limited_wait", "Audit must explain soft throttle decisions");
  contains(audit, "rate_limited", "Audit must explain hard rate-limit denials");
  contains(runActivity, 'entry.decision === "THROTTLE"', "Live Scan must display throttle activity");
  notContains(runActivity, /if \(entry\.decision === "THROTTLE"\) return `[^`]*started/, "THROTTLE must not be displayed as execution start");
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
