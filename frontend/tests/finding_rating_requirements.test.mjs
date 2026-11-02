import assert from "node:assert/strict";
import test from "node:test";
import { loadTs } from "./_ts.mjs";
import { readRecord, record } from "./_records.mjs";

// REQ-SCORE-005 (GitHub #87): the console says why a finding is rated as it is, and does not show the platform's own note as a raw object.
const requirements = readRecord("requirements", "finding-rating.md");
const findings = await loadTs("src/lib/findings.ts");

const finding = (evidence) => ({ id: "f1", severity: "info", evidence });
const rating = { class: "hygiene", tool_label: "high", why: "A configuration or hygiene note with no demonstrated exploit, so it is rated informational." };

test("REQ-SCORE-005 the reason is available as one line", () => {
  record.match(requirements, /## REQ-SCORE-005:/);
  const note = findings.ratingNote(finding({ check: "cert_trust", rating }));
  assert.equal(note.rating_class, "hygiene");
  assert.equal(note.tool_label, "high");
  assert.match(note.why, /no demonstrated exploit/);
});

test("REQ-SCORE-005 negative: the rating is not listed as raw evidence", () => {
  const keys = findings.evidencePairs(finding({ check: "cert_trust", tool: "testssl", rating })).map(([k]) => k);
  assert.deepEqual(keys.sort(), ["check", "tool"]);
});

test("REQ-SCORE-005 negative: a finding without a rating, or with a malformed one, shows no note", () => {
  assert.equal(findings.ratingNote(finding({ check: "x" })), null);
  assert.equal(findings.ratingNote(finding({ rating: "high" })), null);
  assert.equal(findings.ratingNote(finding({ rating: { class: "hygiene" } })), null);
  assert.equal(findings.ratingNote(finding(null)), null);
});

test("REQ-SCORE-005 the tested name stays in the evidence list", () => {
  const keys = findings.evidencePairs(finding({ check: "cert_trust", tested_name: "mail.example.com", rating })).map(([k]) => k);
  assert.ok(keys.includes("tested_name"));
});
