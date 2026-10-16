import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { readRecord, record } from "./_records.mjs";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const reset = readRecord("requirements", "backlog-self-service-password-reset.md");
const mail = readRecord("requirements", "outbound-email.md");
const app = read("frontend/src/App.tsx");
const login = read("frontend/src/pages/Login.tsx");
const forgot = read("frontend/src/pages/ForgotPassword.tsx");
const resetPage = read("frontend/src/pages/ResetPassword.tsx");
const panel = read("frontend/src/components/MailSettingsPanel.tsx");
const settings = read("frontend/src/pages/Settings.tsx");
const client = read("frontend/src/api/client.ts");

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-MAIL-001 the sign-in page offers Forgot password only when the server says it works", () => {
  record.match(mail, /## REQ-MAIL-001:/);
  record.match(reset, /## REQ-IAM-020:/);
  assert.match(login, /api\.recoveryOptions\(\)\.then\(\(o\) => setCanReset\(!!o\.self_service_reset\)\)\.catch\(\(\) => setCanReset\(false\)\)/);
  assert.match(login, /\{canReset && \(/);
  assert.match(login, /to="\/forgot-password"/);
  assert.match(login, /useState\(false\)/, "hidden until the server answers yes");
});

test("REQ-IAM-020 the two pages are reachable without a session", () => {
  assert.match(app, /<Route path="\/forgot-password" element=\{<ForgotPassword \/>\} \/>/);
  assert.match(app, /<Route path="\/reset-password" element=\{<ResetPassword \/>\} \/>/);
  const shellAt = app.indexOf('path="/*" element={<AuthenticatedShell />}');
  assert.ok(shellAt > app.indexOf('path="/forgot-password"'), "both are siblings of the signed-in shell, not inside it");
});

test("REQ-IAM-020 the request page says the same thing for every address", () => {
  assert.match(forgot, /If an account with that address can be reset, a message with a link is on its way/);
  assert.doesNotMatch(forgot, /no account|not found|unknown (e-?mail|address)|does not exist/i);
});

test("REQ-IAM-020 the token comes from the fragment and is removed from the address bar", () => {
  assert.match(resetPage, /window\.location\.hash/);
  assert.match(resetPage, /window\.history\.replaceState\(null, "", window\.location\.pathname\)/);
  assert.doesNotMatch(resetPage, /searchParams|useSearchParams|location\.search/, "never read from the query string");
  assert.doesNotMatch(client, /password-reset\/complete\?/);
});

test("REQ-IAM-020 completing asks for the authenticator code and does not sign in", () => {
  assert.match(resetPage, /Authenticator code \(or a backup code\)/);
  assert.match(resetPage, /api\.completePasswordReset\(token, password, code\.trim\(\)\)/);
  assert.match(resetPage, /navigate\("\/login", \{ replace: true \}\)/);
  assert.doesNotMatch(resetPage, /navigate\("\/"|navigate\(next/);
  assert.match(resetPage, /An administrator has to reset it for you; this link cannot/);
});

test("REQ-MAIL-002 the relay password is write-only in the console", () => {
  assert.match(panel, /type="password"/);
  assert.match(panel, /password: password \|\| undefined/);
  assert.match(panel, /leave empty to keep it/);
  assert.match(client, /password_set: boolean;/);
  assert.doesNotMatch(client.slice(client.indexOf("export interface MailConfig {"), client.indexOf("export interface MailConfigUpdate")), /password: string/);
  assert.match(settings, /<MailSettingsPanel \/>/);
});

test("REQ-MAIL-002 only TLS choices are offered", () => {
  assert.match(panel, /<option value="starttls">/);
  assert.match(panel, /<option value="tls">/);
  assert.doesNotMatch(panel, /value="none"|value="plain"/);
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
