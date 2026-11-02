import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { readRecord, record } from "./_records.mjs";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirements = readRecord("requirements", "monitoring-target-baseline.md");
const page = read("frontend/src/pages/TargetSelection.tsx");
const wizard = read("frontend/src/pages/MonitorWizard.tsx");
const detail = read("frontend/src/pages/EngagementDetail.tsx");
const inbox = read("frontend/src/pages/Inbox.tsx");
const app = read("frontend/src/App.tsx");
const client = read("frontend/src/api/client.ts");
const defaults = read("frontend/src/components/MonitoringDefaultsPanel.tsx");

test("REQ-BASE-006 the wizard says what activation does before the owner activates", () => {
  record.match(requirements, /## REQ-BASE-006:/);
  assert.match(wizard, /Activating starts a <strong>passive discovery<\/strong>: public sources and DNS only/);
  assert.match(wizard, /It sends nothing to your\s+systems/);
  assert.match(wizard, /<strong>Nothing is scanned until you have chosen the targets<\/strong>/);
  assert.match(wizard, /"Activate and discover"/);
});

test("REQ-BASE-006 [negative] the old button text and the old 'run the first scan yourself' advice are gone", () => {
  assert.doesNotMatch(wizard, /Activate monitoring/);
  assert.doesNotMatch(wizard, /run the first scan: it becomes the baseline/);
});

test("REQ-BASE-006 the engagement page shows the state and offers the step; the inbox opens it", () => {
  assert.match(detail, /engagement\.target_review_state !== "confirmed"/);
  assert.match(detail, /Choose the targets to monitor/);
  assert.match(detail, /to=\{`\/engagements\/\$\{id\}\/targets`\}/);
  assert.match(detail, /Review targets/);
  assert.match(app, /path="\/engagements\/:id\/targets" element=\{<TargetSelection \/>\}/);
  assert.match(inbox, /targets_to_select: "Choose targets"/);
  assert.match(inbox, /discovery_failed: "Discovery did not finish"/);
  assert.match(client, /target_review_state: TargetReviewState \| null;/);
});

test("REQ-BASE-005 one policy for new hosts, and the wizard no longer asks whose systems they are", () => {
  record.match(requirements, /## REQ-BASE-005:/);
  assert.doesNotMatch(wizard, /customer's systems/);
  assert.doesNotMatch(wizard, /setCustomer|customer\b.*useState/);
  assert.match(client, /export interface MonitoringDefaults \{[^}]*new_asset_policy: "auto" \| "hold";/s);
  assert.doesNotMatch(client, /new_asset_policy_customer|new_asset_policy_other/);
  assert.doesNotMatch(defaults, /new_asset_policy_customer|new_asset_policy_other|holdCustomer|holdOther/);
  assert.match(defaults, /New hosts found after the baseline/);
});

test("REQ-BASE-002 the list shows address, provider, flag and source; unresolved names are hidden by default", () => {
  record.match(requirements, /## REQ-BASE-002:/);
  assert.match(page, /useState\(false\);\s*\n\s*const \[grouped/);
  assert.match(page, /Show names that do not resolve/);
  assert.match(page, /Group by address/);
  assert.match(page, /Select all shown/);
  assert.match(page, /Select none shown/);
  assert.match(page, /Select suggested \(same address as a root\)/);
  for (const flag of ["same_address", "other_address", "unresolved"]) assert.match(page, new RegExp(`${flag}:`));
  assert.match(page, /Resolves elsewhere/);
  assert.match(page, /Select it only if you are authorized to test whatever answers there/);
});

test("REQ-BASE-002 [negative] a root cannot be deselected in the console either", () => {
  assert.match(page, /disabled=\{c\.is_root \|\| !canManage\}/);
  assert.match(page, /if \(c\.is_root\) \{ next\.add\(c\.asset_id\); continue; \}/);
  assert.match(page, /A root of your scope cannot be left out/);
});

test("REQ-BASE-003 confirming sends the selection and the policy, and says what will be excluded", () => {
  record.match(requirements, /## REQ-BASE-003:/);
  assert.match(client, /confirmTargets: \(id: string, body: \{ selected_asset_ids: string\[\]; new_asset_policy\?: "auto" \| "hold"; confirm_widening\?: boolean \}\)/);
  assert.match(page, /selected_asset_ids: \[\.\.\.selected\], new_asset_policy: policy, confirm_widening: widening/);
  assert.match(page, /will be excluded \(a deny rule is added for each\)/);
  assert.match(page, /Your allow rules stay: they are the record of what you are authorized to test/);
  assert.match(page, /and start the first scan/);
});

test("REQ-BASE-003 [negative] only the owner or an administrator gets a confirm control; a read-only visitor is told", () => {
  assert.match(page, /\{canManage && \(\s*<div className="form-actions">\s*<button\s+className="primary-action"/);
  assert.match(page, /Only the owner of this engagement or an administrator can change the targets/);
  assert.match(page, /const canManage = engagementQuery\.data\?\.can_manage \?\? false;/);
});

test("REQ-BASE-004 including an excluded host again is a confirmed widening", () => {
  record.match(requirements, /## REQ-BASE-004:/);
  assert.match(page, /includedAgain = candidates\.filter\(\(c\) => c\.denied && selected\.has\(c\.asset_id\)\)/);
  assert.match(page, /disabled=\{confirm\.isPending \|\| \(needsWidening && !widening\)\}/);
  assert.match(page, /widens what is tested/);
  assert.match(page, /Discover again/);
});

test("REQ-BASE-001 the screen waits for a running discovery and offers a retry after a failed one", () => {
  record.match(requirements, /## REQ-BASE-001:/);
  assert.match(page, /state\?\.data\?\.state === "discovering" \? 4000 : false|query\.state\.data\?\.state === "discovering" \? 4000 : false/);
  assert.match(page, /The discovery did not finish/);
  assert.match(page, /The discovery used public sources and DNS only\. It sent nothing to your systems/);
});

test("REQ-BASE-007 the target screen marks held hosts and asks for the widening confirmation when one is chosen", () => {
  record.match(requirements, /## REQ-BASE-007:/);
  assert.match(client, /held\?: boolean;/);
  assert.match(client, /released\?: number;/);
  assert.match(page, /const releasedNow = candidates\.filter\(\(c\) => c\.held && selected\.has\(c\.asset_id\)\);/);
  assert.match(page, /const needsWidening = includedAgain\.length > 0 \|\| releasedNow\.length > 0;/, "a release is a widening");
  assert.match(page, /\{c\.held && <> <span className="pill warn"[^>]*>held<\/span><\/>\}/, "the row is marked");
  assert.match(page, /I confirm that including or releasing/);
  assert.match(page, /held host\{releasedNow\.length === 1 \? " is" : "s are"\} released and will be tested/);
  assert.match(page, /disabled=\{confirm\.isPending \|\| \(needsWidening && !widening\)\}/, "the button waits for the confirmation");
});

test("REQ-BASE-008 the Plan tab says which hosts in scope were not tested, and why", () => {
  record.match(requirements, /## REQ-BASE-008:/);
  assert.match(client, /untested_hosts\?: \{ host: string; reason: "held" \| "no_address" \| "no_open_port"; text: string \}\[\];/);
  const plan = read("frontend/src/components/ScanPlanView.tsx");
  assert.match(plan, /const untested = plan\.untested_hosts \?\? \[\];/);
  assert.match(plan, /in scope but \{untested\.length === 1 \? "was" : "were"\} not tested by this run/);
  assert.match(plan, /<li key=\{h\.host\}><code>\{h\.host\}<\/code>: \{h\.text\}<\/li>/);
});
