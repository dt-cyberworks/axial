import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = read("docs/requirements/tool-grants.md");
const wizard = read("frontend/src/pages/EngagementWizard.tsx");
const registry = read("control-plane/app/tools/registry.py");
const gateway = read("control-plane/app/gateway/authorize.py");
const audit = read("frontend/src/pages/Audit.tsx");

function requirement(id) {
  assert.match(requirementDoc, new RegExp(`## ${id}:`), `${id} must be documented before it is tested`);
}
function contains(source, pattern, message) {
  if (pattern instanceof RegExp) assert.match(source, pattern, message);
  else assert.equal(source.includes(pattern), true, message);
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-TOOL-001 offers passive only when passive tools exist", () => {
  requirement("REQ-TOOL-001");
  contains(wizard, "passiveToolsByCategory", "Wizard must derive passive availability by category");
  contains(wizard, 'tool.execution_class === "passive"', "Wizard must use the registry execution class for passive availability");
  contains(wizard, "No passive tools", "Wizard must say when a category has no passive tools");
  contains(wizard, "Passive OSINT only", "Wizard summary must explain passive availability with concrete tools");
  contains(wizard, "public or third-party data sources", "Wizard help text must explain what passive means");
});

test("REQ-TOOL-002 saves passive grants only for executable passive categories", () => {
  requirement("REQ-TOOL-002");
  contains(wizard, "grant.passive && passiveToolsByCategory[category].length > 0", "Wizard must not save passive grants without passive tools");
  contains(registry, 'ToolSpec("subfinder", "recon", "passive"', "Registry must expose subfinder as a real passive recon tool");
  contains(registry, 'ToolSpec("amass", "recon", "passive"', "Registry must expose amass as a real passive recon tool");
  contains(registry, 'ToolSpec("nmap", "fingerprint", "raw_network"', "Registry must not model nmap as passive");
  contains(registry, 'ToolSpec("nuclei", "vuln", "http_proxy"', "Registry must not model nuclei as passive");
});

test("REQ-TOOL-003 gateway enforces passive mode as a real permission", () => {
  requirement("REQ-TOOL-003");
  contains(gateway, 'call.mode == "passive"', "Gateway must have a passive-mode branch");
  contains(gateway, '_tool_grant_for(db, eng.id, call.category, "passive")', "Gateway must require a passive grant");
  contains(gateway, 'tool_spec.execution_class != "passive"', "Gateway must verify passive execution class");
  contains(gateway, 'DENY("passive_not_supported")', "Gateway must deny non-passive tools in passive mode");
  contains(audit, "passive_not_supported", "Audit UI must explain passive_not_supported denials");
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

// REQ-TOOL-006..008 (GitHub issue #48): grants after creation, removal, audit, explanation.
for (const id of ["REQ-TOOL-006", "REQ-TOOL-007", "REQ-TOOL-008"]) requirement(id);
{
  const editor = read("frontend/src/components/ToolGrantsEditor.tsx");
  const detail = read("frontend/src/pages/EngagementDetail.tsx");
  const edit = read("frontend/src/pages/EngagementEdit.tsx");
  const client = read("frontend/src/api/client.ts");
  const engagements = read("control-plane/app/api/engagements.py");

  // one editor, on the draft's page and on the Edit page for every status that can still change
  contains(detail, /<ToolGrantsEditor engagementId=\{id!\} status="draft" \/>/, "a draft keeps its grants editor");
  contains(edit, /engagement\.status !== "completed" && engagement\.status !== "revoked"[\s\S]{0,80}<ToolGrantsEditor/, "the Edit page offers grants until the engagement ends");
  contains(editor, /id="tool-grants"/, "the blocker link needs an anchor");

  // unticking a saved box takes the grant away; saving used to only add
  contains(editor, /api\.removeToolGrant\(/, "a saved grant can be removed");
  contains(client, /removeToolGrant: \(id: string, category: string, mode: string\)/);
  contains(editor, /removals\.push/, "the editor computes what to take away");

  // widening asks; a running scan blocks additions but never removals
  contains(editor, /confirm_widening: addition\.widening && confirmed/, "the confirmation is sent, never implied");
  contains(editor, /Confirm: this widens what the engagement is authorized to do/);
  contains(editor, /const lockedForAdding = \(isChecked: boolean\) => scanActive && !isChecked/, "while a scan runs only adding is locked");

  // the blocker says where to fix it
  contains(detail, /Go to tool grants/);
  contains(detail, /Open tool grants/);
  assert.doesNotMatch(detail, /<strong>\{b\.code\}<\/strong>/, "the raw blocker code is no longer the headline");

  // the Edit page explains the layers and why a tool cannot run
  contains(edit, /checked in this order/);
  contains(edit, /"Force on" cannot grant a category, cannot add scope and cannot enable a tool that is not\s+installed/);
  assert.doesNotMatch(edit, /capability registry floor/, "the unexplained phrase is gone");
  contains(edit, /category_not_granted: "Its category is not granted"/);
  contains(edit, /Grant \{t\.category\}/, "a tool with no grant links to the grants");

  // server side: confirmation, running-scan rule, audit actions, and the wipe fix
  contains(engagements, /confirmation_required:/);
  contains(engagements, /scan_run_active:/);
  contains(engagements, /action="tool_grant_added"/);
  contains(engagements, /action="tool_grant_removed"/);
  assert.doesNotMatch(engagements.slice(engagements.indexOf("def add_tool_grant"), engagements.indexOf("def remove_tool_grant")),
    /delete\(\s*ToolApprovalPolicy\s*\)/, "saving grants must not delete the campaign's per-tool rows");

  // the audit page explains the reasons and shows who changed a grant
  contains(audit, /tool_disabled: "The tool is switched off/);
  contains(audit, /case "tool_grant_added":/);
  contains(audit, /Grant it under Edit engagement/);
}
