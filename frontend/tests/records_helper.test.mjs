import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readRecordFrom, record } from "./_records.mjs";

// GitHub issue #56: records are private. In the public tree their assertions are skipped; in the
// private tree a missing record must fail, so a deleted record cannot pass silently.
function tree({ privateTree, withRecord }) {
  const root = mkdtempSync(join(tmpdir(), "axial-records-"));
  if (privateTree) writeFileSync(join(root, "CLAUDE.md"), "private instructions\n");
  if (withRecord) {
    mkdirSync(join(root, "docs", "requirements"), { recursive: true });
    writeFileSync(join(root, "docs", "requirements", "x.md"), "## REQ-X-001: documented\n");
  }
  return root;
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("a present record is read in both trees", () => {
  for (const privateTree of [true, false]) {
    const text = readRecordFrom(tree({ privateTree, withRecord: true }), "requirements", "x.md");
    assert.match(text, /## REQ-X-001:/);
  }
});

test("public tree: an absent record is null and its assertions are skipped", () => {
  const text = readRecordFrom(tree({ privateTree: false, withRecord: false }), "requirements", "x.md");
  assert.equal(text, null);
  record.match(text, /## REQ-NEVER-999:/);
  record.doesNotMatch(text, /anything/);
  record.contains(text, "anything");
  record.notContains(text, "anything");
});

test("negative: private tree: an absent record is a failure, never a skip", () => {
  const root = tree({ privateTree: true, withRecord: false });
  assert.throws(() => readRecordFrom(root, "requirements", "x.md"), /is missing from the private tree/);
});

test("negative: a present record's assertions are never skipped", () => {
  const text = readRecordFrom(tree({ privateTree: false, withRecord: true }), "requirements", "x.md");
  assert.throws(() => record.match(text, /## REQ-OTHER-001:/));
  assert.throws(() => record.doesNotMatch(text, /## REQ-X-001:/));
  assert.throws(() => record.contains(text, "not in the record"));
  assert.throws(() => record.notContains(text, "REQ-X-001"));
  record.match(text, /## REQ-X-001:/);
  record.contains(text, "documented");
});

let failed = 0;
for (const { name, fn } of tests) {
  try { fn(); } catch (error) { failed += 1; console.error(`FAIL ${name}\n${error.message}`); }
}
if (failed) { console.error(`${failed} records helper test(s) failed`); process.exit(1); }
console.log(`${tests.length} records helper test(s) passed`);
