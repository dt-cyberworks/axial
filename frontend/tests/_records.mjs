import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

// Requirement and design records live only in the private repository (GitHub issue #56): the
// public export leaves them out. A test that checks a record against the source therefore has
// two jobs, and both are decided here, in one place:
//   * private tree (CLAUDE.md exists): a missing record is a failure, so a deleted or renamed
//     record can never pass silently;
//   * public tree: the record is not published, the record assertions are skipped, and every
//     assertion on the source code still runs unchanged.
const repo = resolve(import.meta.dirname, "../..");

// kind is "requirements" (requirement records) or "design" (design records); name is the file.
export function readRecordFrom(root, kind, name) {
  const file = resolve(root, "docs", kind, name);
  if (existsSync(file)) return readFileSync(file, "utf8");
  if (existsSync(resolve(root, "CLAUDE.md"))) {
    throw new Error(`the ${kind} record ${name} is missing from the private tree: a record cannot be deleted silently`);
  }
  return null;
}

export const readRecord = (kind, name) => readRecordFrom(repo, kind, name);

// The assertions of a test against a record. `text === null` means the record is not published.
export const record = {
  match(text, pattern, message) {
    if (text !== null) assert.match(text, pattern, message);
  },
  doesNotMatch(text, pattern, message) {
    if (text !== null) assert.doesNotMatch(text, pattern, message);
  },
  contains(text, pattern, message) {
    if (text === null) return;
    if (pattern instanceof RegExp) assert.match(text, pattern, message);
    else assert.equal(text.includes(pattern), true, message);
  },
  notContains(text, pattern, message) {
    if (text === null) return;
    if (pattern instanceof RegExp) assert.doesNotMatch(text, pattern, message);
    else assert.equal(text.includes(pattern), false, message);
  },
};
