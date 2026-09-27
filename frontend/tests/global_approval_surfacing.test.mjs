import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirement = read("docs/requirements/global-approval-surfacing.md");
const app = read("frontend/src/App.tsx");
const watcher = read("frontend/src/components/GlobalApprovalWatcher.tsx");
const modal = read("frontend/src/components/ApprovalModal.tsx");
const run = read("frontend/src/pages/RunDetail.tsx");

// REQ-APPROVALUI-001: the popup is surfaced app-wide, not only on Run detail.
assert.match(requirement, /## REQ-APPROVALUI-001:/);
assert.match(requirement, /## REQ-APPROVALUI-002:/);

// Mounted once in the authenticated shell.
assert.match(app, /import GlobalApprovalWatcher from "\.\/components\/GlobalApprovalWatcher"/);
assert.match(app, /<GlobalApprovalWatcher \/>/);

// Watcher polls the (server-side caller-scoped) global approvals queue.
assert.match(watcher, /api\.listApprovals\("requested"\)/);
assert.match(watcher, /refetchInterval:\s*3000/);
assert.match(watcher, /import ApprovalModal from "\.\/ApprovalModal"/);

// REQ-APPROVALUI-002: approving navigates to the approval's own run so the
// operator watches it execute; rejecting does not navigate.
assert.match(watcher, /useNavigate/);
assert.match(watcher, /tool_call as \{ scan_run_id\?: string \}/);
assert.match(watcher, /\/engagements\/\$\{approval\.engagement_id\}\/runs\/\$\{scanRunId\}/);
assert.match(watcher, /if \(variables\.action === "approve"\)\s*\{\s*navigate\(/s);

// The shared modal names the engagement (operator may be elsewhere) and keeps
// What/Why/Risk + Approve/Reject.
assert.match(modal, /engagementTitle/);
assert.match(modal, /Risk assessment \(by the agent\)/);
assert.match(modal, /onDecide\("approve"\)/);
assert.match(modal, /onDecide\("reject"\)/);

// REQ-APPROVALUI-001: Run detail no longer renders its OWN approval popup.
assert.doesNotMatch(run, /function ApprovalModal\(/);
assert.doesNotMatch(run, /<ApprovalModal/);
assert.match(run, /GlobalApprovalWatcher/); // references the new single surface in a comment

// REQ-APPROVAL-006: not every gated tool is a crafted HTTP request - a
// scanner (testssl/nikto/nuclei/...) has no method/path/risk concept, and
// rendering "? →" / "(no risk description)" for those read as a broken
// popup rather than a genuinely different, lower-risk tool shape.
assert.match(modal, /isHttpShaped/, "modal must branch on whether the approval is HTTP-shaped");
assert.match(modal, /hasRiskAssessment/, "modal must not claim a risk assessment exists when the tool never provides one");
assert.match(modal, /tc\.tool[\s\S]*tc\.target/, "the non-HTTP branch must still show which tool and target");

console.log("ok - REQ-APPROVALUI-001/002 global approval surfacing + jump-to-run wired");
console.log("ok - REQ-APPROVAL-006 approval popup renders non-HTTP-shaped tool calls honestly");
