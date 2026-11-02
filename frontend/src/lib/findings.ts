import type { Finding, FindingStatus } from "../api/client";

/** Shared by the engagement findings list and the all-findings page (REQ-CONSOLE-016). */

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];

// REQ-TRIAGE-003: one tab per status; "open" is what needs attention.
export const STATUS_TABS: { status: FindingStatus; label: string; empty: string }[] = [
  { status: "open", label: "Open", empty: "No open findings for this filter." },
  { status: "accepted_risk", label: "Accepted risk", empty: "No accepted risks. Accept a finding's risk from its detail view." },
  { status: "false_positive", label: "False positive", empty: "No findings marked as false positive." },
  { status: "resolved", label: "Resolved", empty: "No findings marked as resolved." },
];
export const STATUS_LABEL: Record<FindingStatus, string> = {
  open: "Open", accepted_risk: "Accepted risk", false_positive: "False positive", resolved: "Resolved",
};

/** A status from the URL; anything unknown falls back to the default tab, "open". */
export function parseFindingStatus(value: string | null): FindingStatus {
  return STATUS_TABS.some((tab) => tab.status === value) ? (value as FindingStatus) : "open";
}

/**
 * REQ-TRIAGE-005: the OTHER findings in the same list that carry exactly the same title. Used
 * to select them together; the decision is still made for each of them, not as a rule.
 */
export function sameTitleIds(findings: Finding[], finding: Finding): string[] {
  return findings.filter((other) => other.id !== finding.id && other.title === finding.title).map((other) => other.id);
}

export function severityClass(severity: string | null | undefined) {
  return severity ? `sev-${severity}` : "sev-info";
}

export function targetLabel(finding: Finding) {
  const host = finding.asset_value || "unknown target";
  const ip = finding.target_ip && finding.target_ip !== host ? ` (${finding.target_ip})` : "";
  return `${host}${ip}`;
}

export function serviceLabel(finding: Finding) {
  const parts = [finding.service_protocol, finding.service_port ? String(finding.service_port) : undefined, finding.service_product, finding.service_version].filter(Boolean);
  return parts.length ? parts.join(" / ") : "No service record attached";
}

export function evidencePairs(finding: Finding) {
  // "rating" is the platform's own note on how the severity was decided (REQ-SCORE-005); it has its own line, not a raw object here.
  return Object.entries(finding.evidence ?? {}).filter(([key, value]) => key !== "lens_agent" && key !== "rating" && value !== null && value !== undefined && value !== "");
}

/** REQ-SCORE-005: why the finding is rated as it is, when the platform rated it by class instead of copying a tool's label. */
export function ratingNote(finding: Finding): { rating_class: string; tool_label: string | null; why: string } | null {
  const value = finding.evidence?.["rating"];
  if (typeof value !== "object" || value === null) return null;
  const note = value as Record<string, unknown>;
  if (typeof note.why !== "string" || !note.why) return null;
  return { rating_class: String(note.class ?? ""), tool_label: typeof note.tool_label === "string" ? note.tool_label : null, why: note.why };
}
function evidenceText(finding: Finding, key: string) {
  const value = finding.evidence?.[key];
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
}
function evidenceList(finding: Finding, key: string) {
  const value = finding.evidence?.[key];
  return Array.isArray(value) ? value.map(String).filter(Boolean) : [];
}
const TOOL_LABELS: Record<string, string> = { vector_agent: "Vector Agent", nvd_correlation: "Live CVE correlation (NVD)" };

/** REQ-CORR-009: NVD lists no version limit for this CVE; the console says so instead of presenting it as a precise match. */
export function unboundedCveNote(finding: Finding): string | null {
  if (finding.evidence?.affected_versions !== "unbounded") return null;
  const note = finding.evidence?.note;
  return typeof note === "string" && note ? note : "NVD lists no affected-version limit for this CVE, so every version of the product matches.";
}
export function evidenceTool(finding: Finding) {
  const tool = evidenceText(finding, "tool");
  return TOOL_LABELS[tool] || tool || "unknown tool";
}
export function evidenceLocation(finding: Finding) {
  return evidenceText(finding, "matched_at") || evidenceText(finding, "url") || evidenceText(finding, "endpoint") || evidenceText(finding, "path");
}
export function problemSummary(finding: Finding) {
  const missingHeaders = evidenceList(finding, "missing_headers");
  if (missingHeaders.length) return `Missing headers: ${missingHeaders.join(", ")}`;
  const template = evidenceText(finding, "template_id");
  if (template) return `Matched template: ${template}`;
  const location = evidenceLocation(finding);
  if (location) return `Observed at ${location}`;
  return `Detected by ${evidenceTool(finding)}`;
}
export function observedLocationLabel(finding: Finding) {
  const location = evidenceLocation(finding);
  if (!location) return serviceLabel(finding);
  return location === finding.asset_value ? serviceLabel(finding) : `Observed at ${location}`;
}
// REQ-EVIDENCE-001: one line for one entry of a list. `Array.join` turns an object into "[object Object]",
// so objects are never passed to it. A content-discovery hit reads "status  url  (size)"; any other object is one
// compact JSON line, so nothing an operator needs to see is replaced by a placeholder.
function evidenceLine(entry: unknown, key?: string): string {
  if (entry === null || entry === undefined) return "";
  if (typeof entry !== "object") return String(entry);
  const hit = entry as { url?: unknown; status?: unknown; length?: unknown };
  if (key === "hits" && typeof hit.url === "string") {
    const size = typeof hit.length === "number" ? `  (${hit.length} bytes)` : "";
    return `${hit.status ?? "?"}  ${hit.url}${size}`;
  }
  return JSON.stringify(entry);
}

export function formatEvidenceValue(value: unknown, key?: string): string {
  if (Array.isArray(value)) {
    const lines = value.map((entry) => evidenceLine(entry, key)).filter((line) => line !== "");
    // A list of plain words stays on one line; a list of objects gets one line per entry.
    return value.some((entry) => typeof entry === "object" && entry !== null) ? lines.join("\n") : lines.join(", ");
  }
  if (typeof value === "object" && value !== null) return JSON.stringify(value);
  return String(value);
}
