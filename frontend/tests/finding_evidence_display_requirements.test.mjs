import assert from "node:assert/strict";
import test from "node:test";
import { loadTs } from "./_ts.mjs";
import { readRecord, record } from "./_records.mjs";

const requirements = readRecord("requirements", "operator-console-usability-fixes.md");
const findings = await loadTs("src/lib/findings.ts");
const format = findings.formatEvidenceValue;

const hit = { url: "https://omnisky.world/tools", word: "tools", length: 276, status: 301 };

test("REQ-EVIDENCE-001 a content-discovery hit reads as status, url and size", () => {
  record.match(requirements, /## REQ-EVIDENCE-001:/);
  assert.equal(format([hit], "hits"), "301  https://omnisky.world/tools  (276 bytes)");
  assert.equal(
    format([hit, { url: "https://omnisky.world/admin", status: 403 }], "hits"),
    "301  https://omnisky.world/tools  (276 bytes)\n403  https://omnisky.world/admin",
  );
});

test("REQ-EVIDENCE-001 [negative] no shape of evidence is shown as [object Object]", () => {
  const shapes = [
    [hit], [hit, hit], [{ a: 1 }, { b: [1, 2] }], [[1, 2], [3]], { nested: { deep: [hit] } }, [null, hit, undefined],
    [{ url: 5 }], ["a", { b: 1 }], [], "text", 7, true, null, undefined,
  ];
  for (const shape of shapes) {
    for (const key of [undefined, "hits", "other"]) {
      assert.doesNotMatch(format(shape, key), /\[object Object\]/, JSON.stringify(shape));
    }
  }
});

test("REQ-EVIDENCE-001 any other list of objects is one compact JSON line per entry", () => {
  assert.equal(format([{ a: 1 }, { b: "x" }], "findings"), '{"a":1}\n{"b":"x"}');
  assert.equal(format([{ url: 5, status: 200 }], "hits"), '{"url":5,"status":200}', "an entry without a url string is not a hit");
});

test("REQ-EVIDENCE-001 words, scalars and plain objects look as before", () => {
  assert.equal(format(["X-Frame-Options", "Strict-Transport-Security"], "missing_headers"), "X-Frame-Options, Strict-Transport-Security");
  assert.equal(format(443, "port"), "443");
  assert.equal(format("ffuf", "tool"), "ffuf");
  assert.equal(format({ a: 1 }, "x"), '{"a":1}');
  assert.equal(format([], "hits"), "");
});

test("REQ-EVIDENCE-001 the finding detail passes the key so a hit can be recognised, and keeps the lines apart", async () => {
  const { readFileSync } = await import("node:fs");
  const { resolve } = await import("node:path");
  const repo = resolve(import.meta.dirname, "../..");
  assert.match(readFileSync(resolve(repo, "frontend/src/components/FindingDetail.tsx"), "utf8"), /formatEvidenceValue\(value, key\)/);
  assert.match(readFileSync(resolve(repo, "frontend/src/styles.css"), "utf8"), /\.finding-evidence dd \{ white-space: pre-line; \}/);
});
