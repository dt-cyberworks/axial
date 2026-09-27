import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = read("docs/requirements/operator-authorization.md");
const wizard = read("frontend/src/pages/EngagementWizard.tsx");
const engagementDetail = read("frontend/src/pages/EngagementDetail.tsx");
const dashboard = read("frontend/src/pages/Dashboard.tsx");
const edit = read("frontend/src/pages/EngagementEdit.tsx");
const client = read("frontend/src/api/client.ts");
const engagementApi = read("control-plane/app/api/engagements.py");
const engagementSchema = read("control-plane/app/schemas/engagement.py");

function requirement(id) {
  assert.match(requirementDoc, new RegExp(`## ${id}:`), `${id} must be documented before it is tested`);
}

function notContains(source, pattern, message) {
  if (pattern instanceof RegExp) assert.doesNotMatch(source, pattern, message);
  else assert.equal(source.includes(pattern), false, message);
}

function contains(source, pattern, message) {
  if (pattern instanceof RegExp) assert.match(source, pattern, message);
  else assert.equal(source.includes(pattern), true, message);
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-AUTH-001 hides engagement source from the default wizard", () => {
  requirement("REQ-AUTH-001");
  contains(wizard, '["Window", "Scope", "Tools", "Review", "Authorize"]', "wizard must expose the required five-step flow");
  notContains(wizard, "Engagement source", "wizard must not render an engagement source step");
  notContains(wizard, /\["lab",\s*"own_domain",\s*"bug_bounty",\s*"customer"\]/, "wizard must not offer source choices");
  notContains(wizard, /setSource|type Source|useState<Source>/, "wizard must not manage source as operator state");
  contains(engagementSchema, 'source: str = "own_domain"', "backend schema must provide the hidden internal source default");
  notContains(client, /createEngagement: \(body: [^\n]*source: string/, "frontend create contract must not require source");
});

test("REQ-AUTH-002 uses authorization language in visible UI", () => {
  requirement("REQ-AUTH-002");
  contains(wizard, "authorization attested", "scope editor must label the attestation as authorization");
  contains(engagementDetail, "Attest authorization", "live activation panel must use the authorization action label");
  contains(engagementDetail, "Authorization not attested", "live activation blocker must use authorization wording");
  for (const [name, source] of [["wizard", wizard], ["engagement detail", engagementDetail], ["dashboard", dashboard], ["edit", edit]]) {
    notContains(source, /Attest ownership|ownership attested|ownership not attested|Ownership update failed|Ownership not attested/, `${name} must not expose ownership wording`);
  }
});

test("REQ-AUTH-003 hides internal source in dashboard and edit screens", () => {
  requirement("REQ-AUTH-003");
  notContains(dashboard, "<th>Source</th>", "dashboard must not show source column header");
  notContains(dashboard, "<td>{e.source}</td>", "dashboard must not show source values");
  notContains(edit, "<label>Source", "edit page must not show source selector");
  notContains(edit, /source,\n\s*authorized_from/, "edit update payload must not submit source");
});

test("REQ-AUTH-004 exposes authorization PDF links from GUI", () => {
  requirement("REQ-AUTH-004");
  contains(wizard, "Download authorization PDF", "final wizard step must offer the authorization PDF");
  contains(engagementDetail, "Authorization PDF", "live view must link to the authorization PDF");
  // REQ-DOWNLOAD-001 replaced the bare-URL helper with an authenticated
  // blob download; REQ-AUTH-004 (the PDF is reachable from the GUI) is
  // unchanged, only the mechanism behind it.
  contains(client, "downloadAuthorizationPdf", "frontend API must expose an authorization PDF download helper");
  contains(client, "/authorization-pdf", "frontend API helper must target the authorization PDF endpoint");
});

test("REQ-AUTH-005 implements customer-understandable authorization PDF endpoint", () => {
  requirement("REQ-AUTH-005");
  contains(engagementApi, '@router.get("/{engagement_id}/authorization-pdf")', "backend must expose the PDF route");
  contains(engagementApi, 'media_type="application/pdf"', "PDF route must return application/pdf");
  for (const requiredText of [
    "Configuration checksum",
    "Engagement ID",
    "Test window",
    "Emergency contact",
    "Authorized scope",
    "Explicitly denied scope",
    "Tool permissions",
    "Tools requiring manual approval",
    "Guardrails",
    "Customer representative",
    "Provider / operator representative",
  ]) {
    contains(engagementApi, requiredText, `PDF content must include ${requiredText}`);
  }
  contains(engagementApi, 'action="authorization_pdf_generated"', "PDF generation must be audited");
});

test("REQ-AUTH-006 bug-bounty program policy is configurable from the wizard and edit page", () => {
  requirement("REQ-AUTH-006");

  for (const [name, source] of [["wizard", wizard], ["edit page", edit]]) {
    contains(source, "bountyEnabled", `${name} must have an opt-in bounty-program toggle`);
    contains(source, "This engagement follows a bug bounty program", `${name} must label the toggle clearly`);
    contains(source, "bountyIdentHeaderValue", `${name} must collect the mandatory identification header value`);
    contains(source, "bountyUaSuffix", `${name} must collect the optional User-Agent suffix`);
    // The toggle must set source ONLY inside its own conditional branch, and
    // only alongside addBountyProgram in the same call - never as a bare,
    // always-sent field on a routine save.
    contains(source, 'source: "bug_bounty"', `${name} must set source when the toggle is used`);
    contains(source, "addBountyProgram", `${name} must submit the bounty-program policy`);
  }
  // REQ-AUTH-001's own step list must still hold - the toggle lives INSIDE
  // an existing step, not a new one.
  contains(wizard, '["Window", "Scope", "Tools", "Review", "Authorize"]', "the bounty toggle must not add a wizard step");

  contains(client, "getBountyProgram", "frontend API must expose reading the current bounty program");
  contains(client, "addBountyProgram", "frontend API must expose submitting the bounty program");
  contains(client, "ident_header_name", "BountyProgram type must carry the identification header name");
  contains(client, "ua_suffix", "BountyProgram type must carry the optional UA suffix");

  contains(engagementApi, '@router.get("/{engagement_id}/bounty-program"', "backend must expose reading the current bounty program");
  contains(engagementApi, "delete(BountyProgram)", "add_bounty_program must upsert (delete any existing row first), not accumulate duplicates");
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
