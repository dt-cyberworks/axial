import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { readRecord, record } from "./_records.mjs";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirements = readRecord("requirements", "operating-modes.md");
const app = read("frontend/src/App.tsx");
const client = read("frontend/src/api/client.ts");
const chooser = read("frontend/src/pages/NewEngagement.tsx");
const monitorWizard = read("frontend/src/pages/MonitorWizard.tsx");
const testWizard = read("frontend/src/pages/EngagementWizard.tsx");
const detail = read("frontend/src/pages/EngagementDetail.tsx");
const dashboard = read("frontend/src/pages/Dashboard.tsx");
const settings = read("frontend/src/pages/Settings.tsx");
const inbox = read("frontend/src/pages/Inbox.tsx");
const lifecycle = read("frontend/src/components/EngagementLifecycle.tsx");
const run = read("frontend/src/pages/RunDetail.tsx");

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-MODE-018 the first screen of a new engagement is a choice between the two uses", () => {
  record.match(requirements, /## REQ-MODE-018:/);
  assert.match(app, /<Route path="\/new" element=\{<NewEngagement \/>\} \/>/);
  assert.match(chooser, /Monitor an attack surface/);
  assert.match(chooser, /Test a target/);
  assert.match(chooser, /to="\/new\?mode=monitoring"/);
  assert.match(chooser, /to="\/new\?mode=assessment"/);
  // A draft resumes in the flow it was started in; a link without a choice shows the choice.
  assert.match(chooser, /if \(mode === "monitoring"\) return <MonitorWizard \/>;/);
  assert.match(chooser, /if \(mode === "assessment" \|\| draft\) return <EngagementWizard \/>;/);
  assert.match(testWizard, /eng\.operating_mode === "monitoring"[\s\S]{0,200}navigate\(`\/new\?mode=monitoring&draft=\$\{eng\.id\}`/);
});

test("REQ-MODE-018 the monitoring wizard has no approvals, no review gate and no supervision choice", () => {
  assert.match(monitorWizard, /operating_mode: "monitoring"/);
  assert.doesNotMatch(monitorWizard, /asset_review_enabled|manual_tools|requires_manual_approval|ToolGrantsEditor/);
  assert.doesNotMatch(monitorWizard, /semi_attended|<select[^>]*[Ss]upervision/);
  // The signed document and the review say what runs unattended and what cannot happen.
  assert.match(monitorWizard, /What will run without anyone watching/);
  assert.match(monitorWizard, /What can never happen/);
  assert.match(monitorWizard, /Credential and exploit testing are not part of monitoring/);
  assert.match(monitorWizard, /api\.downloadAuthorizationPdf\(engagementId\)/);
});

test("REQ-MODE-018 a monitoring page shows what changed first and has its own tabs", () => {
  assert.match(detail, /const MONITORING_TABS = \[/);
  assert.match(detail, /\{ id: "changes", label: "Changes" \}/);
  assert.match(detail, /\{ id: "setup", label: "Capabilities & alerts" \}/);
  assert.match(detail, /\{isMonitoring && !isDraft && activeTab === "findings" && <ChangesSection engagementId=\{id\} compact \/>\}/);
  assert.match(detail, /isMonitoring \? "Run now" : "Start run"/);
  // The test engagement's tabs are unchanged (REQ-CONSOLE-013).
  assert.match(detail, /const tabs = isMonitoring \? MONITORING_TABS : ENGAGEMENT_TABS;/);
});

test("REQ-MODE-002/018 supervision is chosen for a test at Start run and is sent only then", () => {
  assert.match(detail, /aria-label="Supervision of this run"/);
  assert.match(detail, /engagement\?\.operating_mode === "assessment" && supervision === "semi_attended"/);
  assert.match(client, /startScan: \(id: string, options\?: ScanStartOptions\)/);
  assert.match(run, /run\.supervision\.replace\("_", "-"\)/);
});

test("REQ-MODE-003 pause, resume, close and revoke are the owner's, and the destructive ones ask first", () => {
  for (const verb of ["pause", "resume", "close", "revoke"]) {
    assert.match(client, new RegExp(`${verb}Engagement: \\(id: string\\) => request<Engagement>\\(\`/engagements/\\$\\{id\\}/${verb}\``));
  }
  assert.match(detail, /\{canManage && !isDraft && <EngagementLifecycle engagement=\{engagement\} \/>\}/);
  assert.match(lifecycle, /confirming === "close"/);
  assert.match(lifecycle, /confirming === "revoke"/);
  assert.match(lifecycle, /cannot be undone/);
});

test("REQ-MODE-014 the inbox is in the navigation with a count, and routes to its page", () => {
  assert.match(app, /<Route path="\/inbox" element=\{<Inbox \/>\} \/>/);
  assert.match(app, /<NavLink to="\/inbox">/);
  assert.match(app, /api\.inboxCount/);
  assert.match(inbox, /api\.acknowledgeInboxItem/);
  assert.match(inbox, /Release all/);
});

test("REQ-MODE-006 the monitoring defaults are an administrator's setting and say they are copied", () => {
  assert.match(settings, /<MonitoringDefaultsPanel \/>/);
  const panel = read("frontend/src/components/MonitoringDefaultsPanel.tsx");
  assert.match(panel, /copied when the engagement is created/);
  assert.match(client, /updateMonitoringDefaults/);
});

test("REQ-MODE-018 the overview shows the mode of every engagement", () => {
  assert.match(dashboard, /<th>Mode<\/th>/);
  assert.match(dashboard, /e\.operating_mode === "monitoring" \? "Monitoring" : "Assessment"/);
});

test("REQ-MODE-013 the change feed names what changed and never says fixed for a short run", () => {
  const changes = read("frontend/src/components/ChangesSection.tsx");
  assert.match(changes, /asset_new: "New asset"/);
  assert.match(changes, /finding_resolved: "Finding fixed"/);
  assert.match(changes, /A run that had reduced coverage never reports something as gone or/);
});

test("REQ-MON-002 the signing secret is write-only and a failed delivery is visible", () => {
  const targets = read("frontend/src/components/NotificationTargets.tsx");
  assert.match(targets, /never shown again/);
  assert.match(targets, /type="password"/);
  assert.match(targets, /Last error/);
  assert.match(client, /has_secret: boolean/);
  assert.doesNotMatch(client, /secret_enc/);
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
