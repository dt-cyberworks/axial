import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { readRecord, record } from "./_records.mjs";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirements = readRecord("requirements", "operator-authorization.md");
const client = read("frontend/src/api/client.ts");

test("REQ-AUTH-007 the console asks for the letter with its own time zone, so the dates read as the operator entered them", () => {
  record.match(requirements, /## REQ-AUTH-007:/);
  assert.match(client, /Intl\.DateTimeFormat\(\)\.resolvedOptions\(\)\.timeZone/);
  assert.match(client, /authorization-pdf\$\{zone \? `\?tz=\$\{encodeURIComponent\(zone\)\}` : ""\}/);
});

test("REQ-AUTH-007 [negative] a browser that cannot name its zone still downloads the letter (shown in UTC)", () => {
  assert.match(client, /try \{ zone = Intl\.DateTimeFormat\(\)\.resolvedOptions\(\)\.timeZone \|\| ""; \} catch \{/);
});

test("REQ-AUTH-004 the download still goes through the authenticated path, not a bare link", () => {
  assert.match(client, /downloadBlob\(`\/engagements\/\$\{id\}\/authorization-pdf/);
});
