import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = read("docs/requirements/console-robustness.md");
const detail = read("frontend/src/pages/EngagementDetail.tsx");
const runDetail = read("frontend/src/pages/RunDetail.tsx");
const app = read("frontend/src/App.tsx");
const client = read("frontend/src/api/client.ts");
const dashboard = read("frontend/src/pages/Dashboard.tsx");
const wizard = read("frontend/src/pages/EngagementWizard.tsx");
const styles = read("frontend/src/styles.css");
const engagementsApi = read("control-plane/app/api/engagements.py");
const makefile = read("Makefile");

function requirement(id) {
  assert.match(requirementDoc, new RegExp(`## ${id}:`), `${id} must be documented before it is tested`);
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-CONSOLE-008 unknown engagements and runs render a not-found page", () => {
  requirement("REQ-CONSOLE-008");
  assert.match(client, /export class ApiError extends Error/);
  assert.match(client, /status === 404 \|\| error\.status === 422/);
  assert.match(detail, /isNotFound\(engagementQuery\.error\)[\s\S]*?<NotFound title="Engagement not found"/);
  assert.match(runDetail, /<NotFound title="Scan run not found"/);
});

test("REQ-CONSOLE-008 negative: the pre-flight banner is never green unless the server said ready", () => {
  // The success message may only sit in the branch after readiness failed/missing/not-ready were ruled out.
  const start = detail.indexOf("{readinessFailed ? (");
  const green = detail.indexOf('<div className="success-block">All pre-flight checks pass');
  assert.ok(start > 0 && green > start, "the green banner comes after the readiness checks");
  const banner = detail.slice(start, green);
  assert.match(banner, /readinessFailed \? \(/, "error state first");
  assert.match(banner, /: !readiness \? \(/, "loading state second");
  assert.match(banner, /: !readiness\.ready \? \(/, "blocked state third");
  assert.doesNotMatch(detail, /readiness && !readiness\.ready \? \(/, "the old two-state banner (green while loading) is gone");
});

test("REQ-CONSOLE-009 unknown paths get a 404 page", () => {
  requirement("REQ-CONSOLE-009");
  assert.match(app, /<Route path="\*" element=\{<NotFound \/>\} \/>/);
});

test("REQ-CONSOLE-010 the empty overview explains the first steps", () => {
  requirement("REQ-CONSOLE-010");
  assert.match(dashboard, /engagements\.length === 0 && \(\s*<section className="form-panel onboarding-panel">/);
  assert.match(dashboard, /Nothing is scanned until you have authorized and activated it/);
  assert.match(dashboard, /to="\/new">Create an engagement</);
});

test("REQ-CONSOLE-011 the wizard's first step says it saves a draft; expert options are folded", () => {
  requirement("REQ-CONSOLE-011");
  assert.match(wizard, /"Save draft and continue"/);
  assert.match(wizard, /This saves a draft\. Nothing is scanned until you authorize and activate/);
  assert.match(wizard, /<details className="advanced-options">/);
  assert.doesNotMatch(wizard, /<details className="advanced-options" open/, "collapsed by default");
});

test("REQ-CONSOLE-012 plain English activation errors, English make help, aligned logout", () => {
  requirement("REQ-CONSOLE-012");
  assert.doesNotMatch(engagementsApi, /Abschnitt \d/, "no references to retired spec chapters");
  assert.match(engagementsApi, /Cannot activate: add at least one in-scope target/);
  assert.doesNotMatch(makefile, /## (Diese|Scanner-Stack|Alle Tests|Reine|Verwundbare|Lab-Ziele|Isolations|Vollständiger|Operator-Konsole)/);
  assert.match(makefile, /down:  ## Stop the stack and DELETE its volumes/);
  assert.match(styles, /\.side-nav button\.nav-logout \{[\s\S]*?justify-content: flex-start;/);
  assert.doesNotMatch(detail, /risk_ampel/, "the German traffic-light value is not shown");
  assert.match(detail, /worstOpenSeverity\(summary\?\.counts_by_severity\)/);
  assert.match(detail, /"None open"/);
});

test("REQ-CONSOLE-008 nothing else is fetched for an engagement that has not loaded", () => {
  assert.match(detail, /const engagementLoaded = !!id && engagementQuery\.isSuccess;/);
  assert.doesNotMatch(detail.slice(detail.indexOf("const engagementLoaded")), /enabled: !!id\b/, "secondary queries wait for the engagement");
  assert.doesNotMatch(runDetail.slice(runDetail.indexOf("const engagementLoaded")), /enabled: !!id\b/);
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
