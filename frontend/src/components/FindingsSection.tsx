import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fragment, useState } from "react";

import { api, type Finding } from "../api/client";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export function severityClass(severity: string | null | undefined) {
  return severity ? `sev-${severity}` : "sev-info";
}

function targetLabel(finding: Finding) {
  const host = finding.asset_value || "unknown target";
  const ip = finding.target_ip && finding.target_ip !== host ? ` (${finding.target_ip})` : "";
  return `${host}${ip}`;
}

function serviceLabel(finding: Finding) {
  const parts = [finding.service_protocol, finding.service_port ? String(finding.service_port) : undefined, finding.service_product, finding.service_version].filter(Boolean);
  return parts.length ? parts.join(" / ") : "No service record attached";
}

function evidencePairs(finding: Finding) {
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
function evidenceTool(finding: Finding) {
  const tool = evidenceText(finding, "tool");
  return TOOL_LABELS[tool] || tool || "unknown tool";
}
function evidenceLocation(finding: Finding) {
  return evidenceText(finding, "matched_at") || evidenceText(finding, "url") || evidenceText(finding, "endpoint") || evidenceText(finding, "path");
}
function problemSummary(finding: Finding) {
  const missingHeaders = evidenceList(finding, "missing_headers");
  if (missingHeaders.length) return `Missing headers: ${missingHeaders.join(", ")}`;
  const template = evidenceText(finding, "template_id");
  if (template) return `Matched template: ${template}`;
  const location = evidenceLocation(finding);
  if (location) return `Observed at ${location}`;
  return `Detected by ${evidenceTool(finding)}`;
}
function observedLocationLabel(finding: Finding) {
  const location = evidenceLocation(finding);
  if (!location) return serviceLabel(finding);
  return location === finding.asset_value ? serviceLabel(finding) : `Observed at ${location}`;
}
function formatEvidenceValue(value: unknown) {
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "object" && value !== null) return JSON.stringify(value);
  return String(value);
}
function cachedLensExplanation(finding: Finding) {
  const value = finding.evidence?.["lens_agent"];
  if (!value || typeof value !== "object" || Array.isArray(value)) return "";
  const explanation = (value as Record<string, unknown>).explanation;
  return typeof explanation === "string" ? explanation : "";
}
function cachedLensTruncated(finding: Finding) {
  const value = finding.evidence?.["lens_agent"];
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return (value as Record<string, unknown>).truncated === true;
}

const LENS_SECTION_LABELS = ["What it is", "Where it was found", "Why it matters", "What to do"];
type LensBlock = { type: "heading"; text: string } | { type: "paragraph"; text: string } | { type: "ul"; items: string[] } | { type: "ol"; items: string[] };
function stripMarkdownFrame(text: string) { return text.replace(/^#{1,4}\s+/, "").replace(/^[-*]\s+/, "").trim(); }
function splitLensHeading(line: string): { heading: string; rest: string } | null {
  const cleaned = stripMarkdownFrame(line).replace(/^\*\*(.+?)\*\*/, "$1");
  for (const label of LENS_SECTION_LABELS) {
    if (cleaned === label) return { heading: label, rest: "" };
    if (cleaned.startsWith(`${label}:`)) return { heading: label, rest: cleaned.slice(label.length + 1).trim() };
    if (cleaned.startsWith(`${label} -`)) return { heading: label, rest: cleaned.slice(label.length + 2).trim() };
    if (cleaned.startsWith(`${label} `)) return { heading: label, rest: cleaned.slice(label.length).trim() };
  }
  return null;
}
function parseLensBlocks(text: string): LensBlock[] {
  const blocks: LensBlock[] = [];
  let paragraph: string[] = [];
  function flushParagraph() { const joined = paragraph.join(" ").replace(/\s+/g, " ").trim(); if (joined) blocks.push({ type: "paragraph", text: joined }); paragraph = []; }
  function appendList(type: "ul" | "ol", item: string) { flushParagraph(); const last = blocks.at(-1); if (last?.type === type) last.items.push(item); else blocks.push({ type, items: [item] }); }
  for (const rawLine of text.replace(/\r\n/g, "\n").split("\n")) {
    const line = rawLine.trim();
    if (!line) { flushParagraph(); continue; }
    const markdownHeading = line.match(/^#{1,4}\s+(.+)$/);
    if (markdownHeading) { flushParagraph(); const split = splitLensHeading(markdownHeading[1]); if (split) { blocks.push({ type: "heading", text: split.heading }); if (split.rest) paragraph.push(split.rest); } else { blocks.push({ type: "heading", text: stripMarkdownFrame(markdownHeading[1]) }); } continue; }
    const split = splitLensHeading(line);
    if (split) { flushParagraph(); blocks.push({ type: "heading", text: split.heading }); if (split.rest) paragraph.push(split.rest); continue; }
    const numbered = line.match(/^\d+[.)]\s+(.+)$/);
    if (numbered) { appendList("ol", numbered[1].trim()); continue; }
    const bullet = line.match(/^[-*]\s+(.+)$/);
    if (bullet) { appendList("ul", bullet[1].trim()); continue; }
    paragraph.push(line);
  }
  flushParagraph();
  return blocks;
}
function renderInlineMarkdown(text: string) {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).filter(Boolean);
  return parts.map((part, index) => {
    if (part.startsWith("**") && part.endsWith("**")) return <strong key={index}>{part.slice(2, -2)}</strong>;
    if (part.startsWith("`") && part.endsWith("`")) return <code key={index}>{part.slice(1, -1)}</code>;
    return <Fragment key={index}>{part}</Fragment>;
  });
}
function renderLensAnalysis(text: string) {
  return parseLensBlocks(text).map((block, index) => {
    if (block.type === "heading") return <h4 key={index}>{block.text}</h4>;
    if (block.type === "ul") return <ul key={index}>{block.items.map((item, i) => <li key={i}>{renderInlineMarkdown(item)}</li>)}</ul>;
    if (block.type === "ol") return <ol key={index}>{block.items.map((item, i) => <li key={i}>{renderInlineMarkdown(item)}</li>)}</ol>;
    return <p key={index}>{renderInlineMarkdown(block.text)}</p>;
  });
}

/** Engagement-wide findings: severity distribution + open findings table with Lens drill-down. */
export default function FindingsSection({ engagementId }: { engagementId: string }) {
  const queryClient = useQueryClient();
  const [severityFilter, setSeverityFilter] = useState<string | undefined>(undefined);
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [lensTextByFinding, setLensTextByFinding] = useState<Record<string, string>>({});
  const [lensTruncatedByFinding, setLensTruncatedByFinding] = useState<Record<string, boolean>>({});

  const { data: summary } = useQuery({ queryKey: ["summary", engagementId], queryFn: () => api.summary(engagementId), refetchInterval: 5000 });
  const { data: findings = [] } = useQuery({
    queryKey: ["findings", engagementId, severityFilter],
    queryFn: () => api.findings(engagementId, severityFilter ? { severity: severityFilter, status: "open" } : { status: "open" }),
    refetchInterval: 5000,
  });
  const lensMutation = useMutation({
    mutationFn: (findingId: string) => api.explainFindingWithLens(engagementId, findingId),
    onSuccess: (result) => {
      setLensTextByFinding((c) => ({ ...c, [result.finding_id]: result.explanation }));
      setLensTruncatedByFinding((c) => ({ ...c, [result.finding_id]: result.truncated }));
      queryClient.invalidateQueries({ queryKey: ["findings", engagementId] });
    },
  });

  return (
    <>
      <section className="table-panel">
        <div className="panel-heading">
          <div><h2>Severity distribution</h2><p>Filter the evidence list without changing server-side state.</p></div>
          <button onClick={() => setSeverityFilter(undefined)}>All</button>
        </div>
        <div className="severity-grid">
          {SEVERITIES.map((severity) => (
            <button key={severity} className={`severity-tile ${severityFilter === severity ? "selected" : ""}`}
              onClick={() => setSeverityFilter(severity === severityFilter ? undefined : severity)}>
              <span>{severity}</span><strong>{summary?.counts_by_severity?.[severity] ?? 0}</strong>
            </button>
          ))}
        </div>
      </section>

      <section className="table-panel">
        <div className="panel-heading"><div><h2>Open findings</h2><p>Engagement-wide evidence, de-duplicated across runs, prioritized by risk score.</p></div></div>
        <div className="responsive-table">
          <table className="data-table findings-table">
            <thead><tr><th>Severity</th><th>Finding</th><th>Found on</th><th>Category</th><th>Confidence</th><th>Score</th><th>First seen</th><th>Last seen</th></tr></thead>
            <tbody>
              {findings.map((finding) => {
                const expanded = expandedFindingId === finding.id;
                const evidence = evidencePairs(finding);
                return (
                  <Fragment key={finding.id}>
                    <tr className={`finding-row ${expanded ? "expanded" : ""}`} onClick={() => setExpandedFindingId(expanded ? null : finding.id)}>
                      <td><span className={`severity-badge ${severityClass(finding.severity)}`}>{finding.severity ?? "info"}</span></td>
                      <td><strong>{finding.title}</strong><span className="muted-line">{problemSummary(finding)}</span><span className="row-hint">Click for evidence and explanation</span></td>
                      <td><strong>{targetLabel(finding)}</strong><span className="muted-line">{observedLocationLabel(finding)}</span></td>
                      <td>{finding.category}</td>
                      <td><span className={`pill ${finding.confidence === "validated" ? "good" : "neutral"}`}>{finding.confidence}</span></td>
                      <td>{finding.risk_score?.toFixed(1) ?? "-"}</td>
                      <td>{new Date(finding.first_seen).toLocaleString()}</td>
                      <td>{finding.last_seen ? new Date(finding.last_seen).toLocaleString() : "-"}</td>
                    </tr>
                    {expanded && (
                      <tr className="finding-detail-row"><td colSpan={8}>
                        <div className="finding-detail-panel">
                          <section className="lens-panel">
                            <div className="lens-heading">
                              <div><h3>Lens Agent analysis</h3><p>Explains the finding, impact, and practical remediation from the recorded evidence.</p></div>
                              <button onClick={(e) => { e.stopPropagation(); lensMutation.mutate(finding.id); }} disabled={lensMutation.isPending}>
                                {lensMutation.isPending ? "Asking Lens..." : (cachedLensExplanation(finding) || lensTextByFinding[finding.id] ? "Show Lens analysis" : "Explain with Lens Agent")}
                              </button>
                            </div>
                            <div className="lens-output">
                              {(finding.id in lensTruncatedByFinding ? lensTruncatedByFinding[finding.id] : cachedLensTruncated(finding)) && (
                                <div className="warning-block">
                                  Lens Agent's analysis was cut off before it finished - the provider hit its
                                  response length limit. Some sections (often "What to do") may be missing or
                                  incomplete.
                                </div>
                              )}
                              {lensTextByFinding[finding.id] || cachedLensExplanation(finding)
                                ? renderLensAnalysis(lensTextByFinding[finding.id] || cachedLensExplanation(finding))
                                : <p className="muted-line">Lens Agent has not explained this finding yet.</p>}
                              {lensMutation.isError && <div className="error-block">Lens Agent failed: {(lensMutation.error as Error).message}</div>}
                            </div>
                          </section>
                          <dl className="finding-facts">
                            <dt>Target</dt><dd>{targetLabel(finding)}</dd>
                            <dt>Asset type</dt><dd>{finding.asset_type ?? "unknown"}</dd>
                            <dt>Service</dt><dd>{serviceLabel(finding)}</dd>
                            <dt>Evidence location</dt><dd>{evidenceLocation(finding) || "not recorded"}</dd>
                            <dt>Detected by</dt><dd>{evidenceTool(finding)}</dd>
                            <dt>Finding ID</dt><dd>{finding.id}</dd>
                            <dt>CVEs</dt><dd>{finding.cve_ids?.length ? finding.cve_ids.join(", ") : "none"}</dd>
                            <dt>CVSS / EPSS</dt><dd>{finding.cvss_base ?? "-"} / {finding.epss ?? "-"}</dd>
                            <dt>Raw reference</dt><dd>{finding.raw_ref ?? "none"}</dd>
                          </dl>
                          <section>
                            <h3>Evidence</h3>
                            {evidence.length > 0 ? (
                              <dl className="finding-evidence">{evidence.map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{formatEvidenceValue(value)}</dd></div>)}</dl>
                            ) : <p className="muted-line">No structured evidence was attached to this finding.</p>}
                          </section>
                        </div>
                      </td></tr>
                    )}
                  </Fragment>
                );
              })}
              {findings.length === 0 && <tr><td colSpan={8} className="empty-cell">No open findings for this filter.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
