import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// REQ-IAM-018 / REQ-IAM-019 (GitHub issue #41): the console never holds a
// session credential and marks every request as its own.
const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirement = read("docs/requirements/cookie-only-sessions.md");
const client = read("frontend/src/api/client.ts");
const login = read("frontend/src/pages/Login.tsx");
const account = read("frontend/src/pages/Account.tsx");

assert.match(requirement, /## REQ-IAM-018:/);
assert.match(requirement, /## REQ-IAM-019:/);

// No token handling left in the console.
for (const [name, source] of [["client.ts", client], ["Login.tsx", login], ["Account.tsx", account]]) {
  assert.doesNotMatch(source, /\.session_token|session_token:/, `${name} must not read a session token`);
  assert.doesNotMatch(source, /\bAuthorization\b|Bearer/, `${name} must not send an Authorization header`);
  assert.doesNotMatch(source, /setSessionToken|getSessionToken/, `${name} must not store or read a token`);
}
// The only remaining storage access removes an old token left by earlier versions.
const storageCalls = client.match(/(?:session|local)Storage\.\w+/g) ?? [];
assert.ok(storageCalls.length > 0 && storageCalls.every((call) => call.endsWith(".removeItem")),
  `only removeItem may touch web storage, found ${storageCalls}`);

// Every fetch() carries the anti-CSRF header and the cookie; so does the download helper.
assert.match(client, /const CONSOLE_HEADERS = \{ "X-Requested-With": "asm-console" \}/);
assert.match(client, /\.\.\.CONSOLE_HEADERS,\s+\.\.\.\(init\?\.headers/);
assert.match(client, /headers: CONSOLE_HEADERS,\s+credentials: "include"/);
assert.equal((client.match(/await fetch\(/g) ?? []).length, 2, "a new fetch() call must be reviewed for the CSRF header");
assert.equal((client.match(/credentials: "include",/g) ?? []).length, 2);
console.log("ok");
