import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { loadTs } from "./_ts.mjs";
import { readRecord, record } from "./_records.mjs";

// REQ-TESTACCT-010 (GitHub #89): the console makes the accounts, their state and their risk visible, and never shows or keeps a secret.
const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");
const requirements = readRecord("requirements", "credentialed-testing.md");
const rules = await loadTs("src/lib/testAccounts.ts");
const panel = read("frontend/src/components/TestAccounts.tsx");
const authorize = read("frontend/src/components/TestAccountsAuthorize.tsx");
const client = read("frontend/src/api/client.ts");
const wizard = read("frontend/src/pages/MonitorWizard.tsx");
const detail = read("frontend/src/pages/EngagementDetail.tsx");

const good = {
  label: "shop-user", role: "user", kind: "login_form", username: "alice", secret: ["S3cret", "Pass", "word", "4711"].join("-"), loginPath: "/login", headerName: "",
  hosts: { "shop.example.test": "", "blog.example.test": "/wp-login.php" }, attested: true,
};

test("REQ-TESTACCT-010 the form is complete only with a label, role, kind, secret and the attestation", () => {
  record.match(requirements, /## REQ-TESTACCT-010:/);
  assert.equal(rules.problemWithForm(good), null);
  for (const [field, value] of [["label", "has space"], ["role", " "], ["kind", ""], ["username", ""], ["secret", "short"], ["attested", false], ["loginPath", "login"]]) {
    assert.notEqual(rules.problemWithForm({ ...good, [field]: value }), null, field);
  }
  assert.equal(rules.problemWithForm({ ...good, kind: "header_token", username: "", loginPath: "" }), null, "a token needs no username or login path");
});

test("REQ-TESTACCT-010 negative: the secret is in the request body and nowhere else", () => {
  const body = rules.toRequest(good);
  assert.equal(body.secret, good.secret);
  assert.deepEqual(body.hosts, [{ host: "shop.example.test", login_path: null }, { host: "blog.example.test", login_path: "/wp-login.php" }]);
  const { secret, ...rest } = body;
  assert.ok(!JSON.stringify(rest).includes(good.secret), "no other field carries the secret");
});

test("REQ-TESTACCT-010 negative: no type the console reads has a field for the secret", () => {
  const types = client.slice(client.indexOf("export type TestAccountKind"), client.indexOf("export interface TestAccountCreate"));
  assert.ok(types.length > 400, "the read types were found");
  assert.doesNotMatch(types, /\bsecret\b(?!_set)/, "the read model has no secret field (only secret_set)");
});

test("REQ-TESTACCT-010 negative: the secret field is write-only and is cleared after saving", () => {
  assert.match(panel, /<input type="password" value=\{form\.secret\} autoComplete="new-password"/, "the new account's secret is a password field");
  assert.match(panel, /<input type="password" value=\{secret\} autoComplete="new-password"/, "a replacement secret is a password field");
  assert.match(panel, /onSuccess: \(\) => \{ setForm\(EMPTY_FORM\); setAdding\(false\)/, "the form is emptied after saving");
  assert.match(panel, /onSuccess: \(\) => \{ setSecret\(""\); onChange\(\); \}/, "a replacement is emptied after saving");
  assert.doesNotMatch(panel, /defaultValue=\{[^}]*secret/i, "a secret is never prefilled");
  assert.doesNotMatch(panel, /localStorage|sessionStorage/, "nothing is kept in the browser");
});

test("REQ-TESTACCT-010 the form says, before saving, that the provider receives the credentials", () => {
  const text = rules.disclosureText("api.edenai.run");
  assert.match(text, /sent to the language-model provider \(api\.edenai\.run\) with every request of a run/);
  assert.match(text, /dedicated test account/);
  assert.match(text, /without a second factor/);
  assert.match(text, /erased when the engagement ends/);
  assert.match(rules.disclosureText(null), /language-model provider with every request/);
  assert.match(panel, /data-testid="test-account-disclosure"/);
  assert.match(panel, /disclosureText\(provider\)/);
});

test("REQ-TESTACCT-010 the list shows the state, the hosts and where the account can and cannot be used", () => {
  for (const needle of ["Can be used on:", "Cannot be used on:", "stateLine(account)", "outcomeWords(h.last_outcome)", "no host", "cannot be used anywhere"]) {
    assert.ok(panel.includes(needle), needle);
  }
  assert.equal(rules.stateLine({ state: "active", hosts: [{ suspended: false }, { suspended: true }] }), "suspended on 1 of 2 hosts");
  assert.equal(rules.stateLine({ state: "suspended", hosts: [] }), "suspended on every host");
  assert.equal(rules.stateLine({ state: "erased", hosts: [] }), "erased");
  assert.equal(rules.outcomeWords("session_established"), "logged in");
  assert.equal(rules.outcomeWords("rejected"), "login rejected");
  assert.equal(rules.outcomeWords(null), "not tried yet");
});

test("REQ-TESTACCT-010 the attestation differs for a bug-bounty engagement and is required", () => {
  assert.match(rules.ATTESTATION, /dedicated test account that I am entitled to use on the hosts ticked above, without a second factor/);
  assert.match(rules.ATTESTATION_BOUNTY, /registered under the program's rules/);
  assert.match(panel, /isBounty \? ATTESTATION_BOUNTY : ATTESTATION/);
});

test("REQ-TESTACCT-010 every refusal code has a sentence", () => {
  for (const code of ["testaccount_label_invalid", "testaccount_attestation_required", "testaccount_host_not_allowed", "testaccount_cipher_unavailable",
    "testaccount_limit", "testaccount_engagement_closed", "login_consent_required", "login_consent_not_applicable", "testaccount_secret_invalid"]) {
    assert.ok(rules.TESTACCOUNT_REFUSALS[code], code);
    assert.equal(rules.testAccountRefusal(`PUT /x -> 422: ${code}`), rules.TESTACCOUNT_REFUSALS[code]);
  }
  assert.equal(rules.testAccountRefusal("something else"), "something else");
});

test("REQ-TESTACCT-006/010 a monitor gets the consent block, listing exactly what it covers, and activation reads the refusal in words", () => {
  const none = { applicable: true, current: false, given_at: null, wording_version: "v", pairs: [{ label: "shop", host: "a.test", login_path: "/login" }], uncovered: [{ label: "shop", host: "a.test", login_path: "/login" }] };
  assert.deepEqual(rules.consentSummary(none), { needed: true, text: "Not yet covered: shop on a.test." });
  assert.equal(rules.consentSummary({ ...none, uncovered: [] }).needed, false);
  assert.equal(rules.consentSummary({ ...none, applicable: false }).needed, false);
  assert.match(rules.CONSENT_WORDING, /on exactly these hosts, on each scheduled run/);
  assert.match(rules.CONSENT_WORDING, /will not change data through the session/);
  assert.match(panel, /operatingMode === "monitoring" && <LoginConsent/);
  assert.match(authorize, /<LoginConsent engagementId=\{engagementId\}/);
  assert.match(wizard, /<TestAccountsAuthorize engagementId=\{engagementId\} \/>/, "the monitor's Authorize step");
  assert.match(wizard, /setError\(testAccountRefusal\(\(e as Error\)\.message\)\)/, "login_consent_required reads as a sentence");
});

test("REQ-TESTACCT-010 the engagement page has the tab and mounts the panel behind canManage", () => {
  assert.match(detail, /\{ id: "accounts", label: "Test accounts" \}/);
  assert.match(detail, /<TestAccounts engagementId=\{id\} canManage=\{canManage\} operatingMode=/);
});

test("REQ-TESTACCT-003 the instruction fields warn that they are stored in plain text and must not hold a password", () => {
  for (const file of ["frontend/src/pages/EngagementEdit.tsx", "frontend/src/pages/Settings.tsx"]) {
    assert.match(read(file), /Never put a password or token/, file);
  }
  assert.match(read("frontend/src/pages/EngagementEdit.tsx"), /stored in plain text/);
});
