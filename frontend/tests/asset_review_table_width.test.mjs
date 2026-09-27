import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirement = read("docs/requirements/operator-console-usability-fixes.md");
const styles = read("frontend/src/styles.css");
const runDetail = read("frontend/src/pages/RunDetail.tsx");

assert.match(requirement, /## REQ-ASSETREVIEW-008:/);

// The asset-review table opts out of the shared wide-table minimum.
assert.match(
  runDetail,
  /<table className="data-table compact-table">/,
  "the asset-review table must use the compact modifier",
);
assert.match(
  styles,
  /\.data-table\.compact-table \{ min-width: 0; \}/,
  "compact-table must drop the shared min-width",
);

// ...without changing behavior for the app's genuinely wide tables.
assert.match(
  styles,
  /\.data-table \{ width: 100%; border-collapse: collapse; min-width: 760px; \}/,
  "the shared .data-table minimum must be unchanged",
);

console.log("ok - REQ-ASSETREVIEW-008 asset-review table fits inside the modal");
