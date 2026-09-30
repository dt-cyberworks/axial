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
  return Object.entries(finding.evidence ?? {}).filter(([key, value]) => key !== "lens_agent" && value !== null && value !== undefined && value !== "");
}
function evidenceText(finding: Finding, key: string) {
  const value = finding.evidence?.[key];
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
}
function evidenceList(finding: Finding, key: string) {
  const value = finding.evidence?.[key];
  return Array.isArray(value) ? value.map(String).filter(Boolean) : [];
}
const TOOL_LABELS: Record<string, string> = { vector_agent: "Vector Agent" };
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
export function formatEvidenceValue(value: unknown) {
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "object" && value !== null) return JSON.stringify(value);
  return String(value);
}
