import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirement = read("docs/requirements/operator-console-usability-fixes.md");
const client = read("frontend/src/api/client.ts");
const detail = read("frontend/src/pages/EngagementDetail.tsx");
const wizard = read("frontend/src/pages/EngagementWizard.tsx");

assert.match(requirement, /## REQ-DOWNLOAD-001:/);

// The helper authenticates the same way every other call does.
assert.match(client, /async function downloadBlob\(/, "a blob-download helper must exist");
assert.match(
  client,
  /headers: token \? \{ Authorization: `Bearer \$\{token\}` \} : \{\}/,
  "the download must attach the bearer token",
);
assert.match(client, /await res\.blob\(\)/, "the response must be read as a Blob");
assert.match(client, /URL\.createObjectURL\(blob\)/);
// Released on every path, including if click() throws.
assert.match(client, /finally \{[\s\S]*URL\.revokeObjectURL\(objectUrl\)/, "the object URL must always be revoked");
// A failure is an error with the status, not a blank page.
assert.match(client, /throw new Error\(`GET \$\{path\} -> \$\{res\.status\}/, "a non-OK response must throw with its status");
// Server-provided filename wins, so the saved file matches the audit record.
assert.match(client, /Content-Disposition/);
assert.match(client, /filename="\?\(\[\^";\]\+\)"\?/);

assert.match(client, /downloadAuthorizationPdf: \(id: string\) =>/);

// The broken pattern is gone from the codebase, not merely unused.
assert.doesNotMatch(client, /authorizationPdfUrl/, "the bare navigable-URL helper must be removed");
assert.doesNotMatch(detail, /authorizationPdfUrl/);
assert.doesNotMatch(wizard, /authorizationPdfUrl/);
for (const [name, source] of [["EngagementDetail", detail], ["EngagementWizard", wizard]]) {
  assert.doesNotMatch(
    source,
    /<a[^>]*authorization-pdf/,
    `${name} must not link to the PDF with a bare anchor`,
  );
}

// Both call sites show progress and surface failures.
assert.match(detail, /downloadAuthorizationPdf\.isPending \? "Preparing…"/);
assert.match(detail, /Authorization PDF download failed:/);
assert.match(wizard, /downloadingPdf \? "Preparing…"/);

console.log("ok - REQ-DOWNLOAD-001 authorization PDF downloads through the authenticated path");
