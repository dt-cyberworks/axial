import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirement = read("docs/requirements/generated-customer-report.md");
const client = read("frontend/src/api/client.ts");
const detail = read("frontend/src/pages/EngagementDetail.tsx");

assert.match(requirement, /## REQ-REPORT-004:/);

// The API surface: generate, list, download.
assert.match(client, /requestReport: \(id: string\) => request<ReportJob>/);
assert.match(client, /listReports: \(id: string\) => request<ReportJob\[\]>/);
assert.match(
  client,
  /downloadReport: \(id: string, reportId: string, filename: string\) =>\s*downloadBlob\(/,
  "report download must use the authenticated blob path (REQ-DOWNLOAD-001)",
);

// The button is a real mutation with a pending state - not fire-and-forget.
assert.match(detail, /const generateReport = useMutation\(\{/, "the button must run through a mutation");
assert.match(detail, /generateReport\.isPending \? "Generating…" : "Generate report"/);
assert.match(detail, /disabled=\{generateReport\.isPending\}/);
assert.doesNotMatch(detail, /onClick=\{\(\) => api\.requestReport\(id\)\}/, "the bare fire-and-forget call must be gone");

// All three outcomes are visible: request failure, backend failure, success.
assert.match(detail, /generateReport\.isError && \(/, "a failed request must be shown");
assert.match(
  detail,
  /generateReport\.data\.status === "failed"/,
  "a backend-reported failure must be shown, not read as success",
);
assert.match(detail, /generateReport\.data\.status === "done"/);
assert.match(detail, /downloadReport\.isError && \(/, "a failed download must be shown");

// Previous reports are listed and downloadable.
assert.match(detail, /queryKey: \["reports", id\]/);
assert.match(detail, /Download PDF/);

console.log("ok - REQ-REPORT-004 report generation is a visible action with a visible result");
