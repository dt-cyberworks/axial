import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { readRecord, record } from "./_records.mjs";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = readRecord("requirements", "engagement-visibility.md");
const client = read("frontend/src/api/client.ts");
const dashboard = read("frontend/src/pages/Dashboard.tsx");
const detail = read("frontend/src/pages/EngagementDetail.tsx");
const edit = read("frontend/src/pages/EngagementEdit.tsx");
const run = read("frontend/src/pages/RunDetail.tsx");
const allFindings = read("frontend/src/pages/AllFindings.tsx");
const findingDetail = read("frontend/src/components/FindingDetail.tsx");
const findingsSection = read("frontend/src/components/FindingsSection.tsx");
const notice = read("frontend/src/components/ReadOnlyNotice.tsx");

function requirement(id) {
  record.match(requirementDoc, new RegExp(`## ${id}:`), `${id} must be documented before it is tested`);
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-IAM-025 the API types carry the owner and whether the caller may change the engagement", () => {
  requirement("REQ-IAM-025");
  const engagement = client.match(/export interface Engagement \{([\s\S]*?)\n\}/)[1];
  assert.match(engagement, /owner_user_id: string;/, "an engagement always has an owner");
  assert.match(engagement, /owner_name: string \| null;/);
  assert.match(engagement, /owner_email: string \| null;/);
  assert.match(engagement, /can_manage: boolean;/);
  assert.match(client, /mine\?: boolean;/, "the findings overview can be narrowed to the caller's own");
});

test("REQ-IAM-025 the overview lists everyone's engagements with an Owner column and an Only mine filter", () => {
  assert.match(dashboard, /<th>Owner<\/th>/);
  assert.match(dashboard, /Only mine/);
  assert.match(dashboard, /owner_user_id === me\?\.id/, "'mine' means owned by the signed-in user, not 'may change'");
  assert.match(dashboard, /shown\.filter\(\(e\) => e\.status === "active"\)/, "the numbers follow the filter");
});

test("REQ-IAM-025 [negative] the overview offers Edit and Delete only where the caller may change the engagement", () => {
  assert.match(dashboard, /\{e\.can_manage && <Link to=\{`\/engagements\/\$\{e\.id\}\/edit`\}>Edit<\/Link>\}/);
  assert.match(dashboard, /\{e\.can_manage && <button className="danger-button"/);
});

test("REQ-IAM-025 [negative] every control that changes an engagement is behind canManage on the engagement page", () => {
  assert.match(detail, /const canManage = engagement\.can_manage;/);
  assert.match(detail, /\{canManage && <Link to=\{`\/engagements\/\$\{id\}\/edit`\}[^>]*>Edit<\/Link>\}/, "Edit");
  assert.match(detail, /\{!canManage && <ReadOnlyNotice engagement=\{engagement\} \/>\}/, "the read-only notice");
  assert.match(detail, /\{canManage && authorizationBlockers\.length > 0 && \(/, "attest authorization");
  assert.match(detail, /\{canManage && isDraft && <ToolGrantsEditor/, "tool grants of a draft");
  assert.match(detail, /\{canManage && isDraft && \(/, "activation");
  assert.match(detail, /\{canManage && b\.action === "tool_grants" && \(/, "the link into the tool grants");
  assert.match(detail, /\{canManage && \(\s*<button\s+className="primary-action"\s+disabled=\{!readiness\?\.ready/, "Start run");
  assert.match(detail, /\{canManage && \(\s*<button disabled=\{generateReport\.isPending\}/, "Generate report");
  assert.match(detail, /<FindingsSection engagementId=\{id\} canManage=\{canManage\} \/>/, "triage and Lens in the findings");
});

test("REQ-IAM-025 [negative] stopping a run and deciding an asset review are the owner's, on the run page", () => {
  assert.match(run, /const canManage = engagement\?\.can_manage \?\? false;/, "unknown means no, not yes");
  assert.match(run, /\{isRunning && canManage && \(/, "Stop scan");
  assert.match(run, /\{pendingReview && canManage && \(\s*<AssetReviewModal/, "the asset-review decision");
  assert.match(run, /\{engagement && !canManage && <ReadOnlyNotice engagement=\{engagement\} \/>\}/);
});

test("REQ-IAM-025 [negative] triage and the Lens request exist only for a caller who may change the engagement", () => {
  assert.match(findingDetail, /canManage: boolean/, "the prop is required: a caller cannot forget it");
  assert.doesNotMatch(findingDetail, /canManage\s*=\s*true/, "no default that grants it");
  assert.match(findingDetail, /\{canManage \? \(\s*<div className="triage-actions">/, "the triage buttons");
  assert.match(findingDetail, /\{canManage && \(\s*<button onClick=\{\(e\) => \{ e\.stopPropagation\(\); lensMutation\.mutate\(\); \}\}/, "the Lens button");
  assert.match(findingsSection, /canManage: boolean/);
  assert.match(allFindings, /canManageById\.get\(finding\.engagement_id\) \?\? false/, "unknown means no");
});

test("REQ-IAM-025 [negative] the audit log's one-click override is offered to the owner and admins only", () => {
  const audit = read("frontend/src/pages/Audit.tsx");
  assert.match(audit, /setCanManage\(e\.can_manage\)/);
  assert.match(audit, /const overrideLabel = canManage && entry\.decision === "DENY"/);
  assert.match(audit, /useState\(false\);\s*\n/, "unknown means no");
});

test("REQ-IAM-025 the edit page shows the notice instead of a form that could not be saved", () => {
  assert.match(edit, /if \(!engagement\.can_manage\) \{[\s\S]*?<ReadOnlyNotice engagement=\{engagement\} \/>/);
});

test("REQ-IAM-025 the findings overview can be narrowed to the caller's own engagements and shows whose they are", () => {
  assert.match(allFindings, /Only my engagements/);
  assert.match(allFindings, /searchParams\.get\("mine"\) === "1"/);
  assert.match(allFindings, /mine: mine \|\| undefined/);
  assert.match(allFindings, /Owner: \{finding\.engagement_owner\}/);
});

test("REQ-IAM-025 the notice names the owner, so the reader knows whom to ask", () => {
  assert.match(notice, /owner_name/);
  assert.match(notice, /owner_email/);
  assert.match(notice, /only \{owner\} or an administrator can change it/);
});

test("REQ-IAM-025 [negative] a new place that changes an engagement must be reviewed here first", () => {
  // Every client function that sends a change to /engagements/... may only be used by files that handle
  // can_manage (or by the wizard, which only ever edits the draft its own user just created).
  const writes = [...client.matchAll(/^\s{2}(\w+): \([^)]*\)[^\n]*=>\s*\n?\s*request<[^>]*>\(\s*`\/engagements\/[^`]*`,\s*\{\s*method: "(?:POST|PUT|PATCH|DELETE)"/gm)]
    .map((m) => m[1]);
  assert.ok(writes.length >= 8, `the scan must find the write helpers (found ${writes.length})`);
  const files = (dir) => readdirSync(resolve(repo, dir), { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? files(`${dir}/${entry.name}`) : [`${dir}/${entry.name}`]);
  const users = new Map();
  for (const file of files("frontend/src").filter((f) => /\.tsx?$/.test(f) && !f.endsWith("api/client.ts"))) {
    const text = read(file);
    for (const name of writes) {
      if (new RegExp(`api\\.${name}\\(`).test(text)) users.set(file, [...(users.get(file) ?? []), name]);
    }
  }
  const allowed = new Set([
    "frontend/src/pages/Dashboard.tsx", "frontend/src/pages/EngagementDetail.tsx", "frontend/src/pages/EngagementEdit.tsx",
    "frontend/src/pages/EngagementWizard.tsx", "frontend/src/pages/RunDetail.tsx", "frontend/src/components/FindingDetail.tsx",
    "frontend/src/components/ToolGrantsEditor.tsx", "frontend/src/pages/Audit.tsx",
    // Reviewed with REQ-MODE-003/006/014 (2026-10-14): each is mounted behind canManage or takes it as a
    // prop that disables its controls, and the API refuses a non-owner with 403 either way.
    "frontend/src/components/EngagementLifecycle.tsx", "frontend/src/components/CapabilitiesEditor.tsx",
    "frontend/src/components/NotificationTargets.tsx", "frontend/src/pages/Inbox.tsx",
    // Reviewed with REQ-MON-004 (2026-10-15): the controls render only for canManage, the API answers a
    // non-owner with 403 either way.
    "frontend/src/components/ScheduleControl.tsx",
    // The monitoring wizard, like the test wizard, only ever edits the draft its own user just created.
    "frontend/src/pages/MonitorWizard.tsx",
  ]);
  for (const [file] of users) assert.ok(allowed.has(file), `${file} changes an engagement: review REQ-IAM-025 and add it here`);
  // The files that sit behind a guard in their parent must still be mounted only behind it.
  assert.match(detail, /canManage && isDraft && <ToolGrantsEditor/);
  assert.match(detail, /\{canManage && !isDraft && <EngagementLifecycle engagement=\{engagement\} \/>\}/, "pause, close, revoke");
  assert.match(detail, /<CapabilitiesEditor engagementId=\{id\} active=\{engagement\.status === "active"\} canManage=\{canManage\} \/>/);
  assert.match(detail, /<NotificationTargets engagementId=\{id\} canManage=\{canManage\} \/>/);
  const caps = read("frontend/src/components/CapabilitiesEditor.tsx");
  assert.match(caps, /disabled=\{!canManage \|\| !!cap\.unavailable_reason\}/, "capability switches follow canManage");
  assert.match(caps, /\{canManage && \(\s*<div className="form-actions">/, "Save capabilities");
  const targets = read("frontend/src/components/NotificationTargets.tsx");
  assert.match(targets, /\{canManage && \(\s*<div className="form-grid">/, "add webhook");
  // REQ-MON-004: the schedule's controls are behind canManage, and the engagement page hands it the flag.
  const schedule = read("frontend/src/components/ScheduleControl.tsx");
  assert.match(schedule, /\{canManage \? \(\s*<div className="form-actions schedule-actions">/, "change / switch off the interval");
  assert.match(schedule, /Only the owner or an administrator can change this/);
  assert.match(detail, /<ScheduleControl engagementId=\{engagement\.id\} canManage=\{canManage\} \/>/);
  assert.match(edit, /if \(!engagement\.can_manage\)/);
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
