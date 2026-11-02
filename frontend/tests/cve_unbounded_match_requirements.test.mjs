import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { readRecord, record } from "./_records.mjs";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirements = readRecord("requirements", "live-vulnerability-correlation.md");
const findings = read("frontend/src/lib/findings.ts");
const detail = read("frontend/src/components/FindingDetail.tsx");

test("REQ-CORR-009 a correlation finding is attributed to the correlation, not to 'unknown tool'", () => {
  record.match(requirements, /## REQ-CORR-009:/);
  assert.match(findings, /nvd_correlation: "Live CVE correlation \(NVD\)"/);
});

test("REQ-CORR-009 a match with no version limit is labelled on the finding", () => {
  assert.match(findings, /finding\.evidence\?\.affected_versions !== "unbounded"/);
  assert.match(detail, /\{unboundedCveNote\(finding\) && \(\s*<div className="warning-block" role="note">/);
  assert.match(detail, /No version limit in NVD\./);
});

test("REQ-CORR-009 [negative] a documented-range match shows no such notice", () => {
  assert.match(findings, /if \(finding\.evidence\?\.affected_versions !== "unbounded"\) return null;/);
});
