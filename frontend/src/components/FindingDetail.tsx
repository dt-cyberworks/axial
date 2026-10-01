import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Fragment, useState } from "react";

import { api, type Finding, type FindingStatus } from "../api/client";
import {
  evidenceLocation, evidencePairs, evidenceTool, formatEvidenceValue, serviceLabel, STATUS_LABEL, targetLabel,
} from "../lib/findings";

const NOTE_REQUIRED: FindingStatus[] = ["accepted_risk", "false_positive"];

/** REQ-TRIAGE-001: decide what a finding is. Dismissing it needs a reason. */
function TriagePanel({ finding, canManage, pending, error, onDecide }: {
  finding: Finding; canManage: boolean; pending: boolean; error: Error | null;
  onDecide: (status: FindingStatus, note?: string) => void;
}) {
  const [choice, setChoice] = useState<FindingStatus | null>(null);
  const [note, setNote] = useState("");
  const actions: { status: FindingStatus; label: string }[] = finding.status === "open"
    ? [{ status: "resolved", label: "Mark resolved" }, { status: "accepted_risk", label: "Accept risk…" },
       { status: "false_positive", label: "Mark false positive…" }]
    : [{ status: "open", label: "Reopen" }];
  const changedBy = finding.status_changed_by === "scan" ? "a later scan" : finding.status_changed_by;
  return (
    <section className="triage-panel" onClick={(e) => e.stopPropagation()}>
      <h3>Triage</h3>
      <p>
        Status: <strong>{STATUS_LABEL[finding.status]}</strong>
        {finding.status_changed_at && <span className="muted-line">Changed by {changedBy} on {new Date(finding.status_changed_at).toLocaleString()}</span>}
      </p>
      {finding.status_note && <blockquote className="triage-note-text">{finding.status_note}</blockquote>}
      {canManage ? (
        <div className="triage-actions">
          {actions.map((action) => (
            <button key={action.status} disabled={pending}
              onClick={() => (NOTE_REQUIRED.includes(action.status) ? setChoice(action.status) : onDecide(action.status))}>
              {action.label}
            </button>
          ))}
        </div>
      ) : (
        <p className="muted-line">Only the owner of this engagement or an administrator can change the status.</p>
      )}
      {canManage && choice && (
        <div className="triage-reason">
          <label>
            {choice === "accepted_risk"
              ? "Why is this risk acceptable? (required - shown with the finding in the report)"
              : "Why is this a false positive? (required - kept in the audit log)"}
            <textarea value={note} maxLength={1000} rows={3} onChange={(e) => setNote(e.target.value)} />
          </label>
          <div className="form-actions">
            <button onClick={() => { setChoice(null); setNote(""); }}>Cancel</button>
            <button disabled={pending || note.trim().length < 3} onClick={() => onDecide(choice, note.trim())}>
              {choice === "accepted_risk" ? "Accept risk" : "Mark false positive"}
            </button>
          </div>
        </div>
      )}
      {error && <div className="error-block">Could not change the status: {error.message}</div>}
    </section>
  );
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

/**
 * One finding's detail: Lens Agent analysis, triage, facts, and evidence.
 * Used on the engagement page and on the all-findings page (REQ-CONSOLE-016);
 * triage always goes through the engagement's own endpoint (REQ-TRIAGE-001).
 */
export default function FindingDetail({ finding, canManage, onTriaged }: { finding: Finding; canManage: boolean; onTriaged?: () => void }) {
  const queryClient = useQueryClient();
  const engagementId = finding.engagement_id;
  const [lensTextByFinding, setLensTextByFinding] = useState<Record<string, string>>({});
  const [lensTruncatedByFinding, setLensTruncatedByFinding] = useState<Record<string, boolean>>({});
  const evidence = evidencePairs(finding);

  function refreshLists() {
    queryClient.invalidateQueries({ queryKey: ["findings", engagementId] });
    queryClient.invalidateQueries({ queryKey: ["summary", engagementId] });
    queryClient.invalidateQueries({ queryKey: ["all-findings"] });
  }
  const triageMutation = useMutation({
    mutationFn: ({ status, note }: { status: FindingStatus; note?: string }) =>
      api.triageFinding(engagementId, finding.id, { status, note }),
    onSuccess: () => { refreshLists(); onTriaged?.(); },
  });
  const lensMutation = useMutation({
    mutationFn: () => api.explainFindingWithLens(engagementId, finding.id),
    onSuccess: (result) => {
      setLensTextByFinding((c) => ({ ...c, [result.finding_id]: result.explanation }));
      setLensTruncatedByFinding((c) => ({ ...c, [result.finding_id]: result.truncated }));
      refreshLists();
    },
  });
  const lensText = lensTextByFinding[finding.id] || cachedLensExplanation(finding);

  return (
    <div className="finding-detail-panel">
      <section className="lens-panel">
        <div className="lens-heading">
          <div><h3>Lens Agent analysis</h3><p>Explains the finding, impact, and practical remediation from the recorded evidence.</p></div>
          {canManage && (
            <button onClick={(e) => { e.stopPropagation(); lensMutation.mutate(); }} disabled={lensMutation.isPending}>
              {lensMutation.isPending ? "Asking Lens..." : (lensText ? "Show Lens analysis" : "Explain with Lens Agent")}
            </button>
          )}
        </div>
        <div className="lens-output">
          {(finding.id in lensTruncatedByFinding ? lensTruncatedByFinding[finding.id] : cachedLensTruncated(finding)) && (
            <div className="warning-block">
              Lens Agent's analysis was cut off before it finished - the provider hit its
              response length limit. Some sections (often "What to do") may be missing or
              incomplete.
            </div>
          )}
          {lensText
            ? renderLensAnalysis(lensText)
            : <p className="muted-line">Lens Agent has not explained this finding yet.{!canManage && " Only the owner of the engagement or an administrator can ask for an explanation."}</p>}
          {lensMutation.isError && <div className="error-block">Lens Agent failed: {(lensMutation.error as Error).message}</div>}
        </div>
      </section>
      <TriagePanel finding={finding} canManage={canManage} pending={triageMutation.isPending}
        error={triageMutation.isError ? (triageMutation.error as Error) : null}
        onDecide={(status, note) => triageMutation.mutate({ status, note })} />
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
  );
}
