import { useQuery } from "@tanstack/react-query";
import { Fragment, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { api, type FindingStatus } from "../api/client";
import BulkTriageBar from "./BulkTriageBar";
import FindingDetail from "./FindingDetail";
import {
  observedLocationLabel, parseFindingStatus, problemSummary, sameTitleIds, SEVERITIES, severityClass, STATUS_TABS,
  targetLabel,
} from "../lib/findings";

// Kept as a re-export: RunDetail imports it from here.
export { severityClass };

/**
 * Engagement-wide findings: a table per status with a severity filter,
 * with triage and Lens drill-down. REQ-CONSOLE-013: the status tab and the
 * expanded finding are part of the URL (`?status=`, `?finding=`), so a link
 * from the all-findings page opens exactly that finding.
 */
export default function FindingsSection({ engagementId, canManage }: { engagementId: string; canManage: boolean }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const statusFilter = parseFindingStatus(searchParams.get("status"));
  const expandedFindingId = searchParams.get("finding");
  const [severityFilter, setSeverityFilter] = useState<string | undefined>(undefined);
  // Scroll only to the finding the page was opened with, not on every click.
  const deepLinkedFinding = useRef(expandedFindingId);
  // REQ-TRIAGE-005: the selection for a bulk action. It belongs to the list in view, so it is
  // dropped when the status tab or the severity filter changes.
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const { data: summary } = useQuery({ queryKey: ["summary", engagementId], queryFn: () => api.summary(engagementId), refetchInterval: 5000 });
  const { data: findings = [] } = useQuery({
    queryKey: ["findings", engagementId, severityFilter, statusFilter],
    queryFn: () => api.findings(engagementId, severityFilter ? { severity: severityFilter, status: statusFilter } : { status: statusFilter }),
    refetchInterval: 5000,
  });

  useEffect(() => { setSelected(new Set()); }, [statusFilter, severityFilter, engagementId]);

  useEffect(() => {
    const target = deepLinkedFinding.current;
    if (!target || !findings.some((finding) => finding.id === target)) return;
    deepLinkedFinding.current = null;
    document.getElementById(`finding-${target}`)?.scrollIntoView({ block: "start" });
  }, [findings]);

  // Expanding a row or switching the status filter replaces the URL entry:
  // Back returns to the previous page tab, not through every click.
  function updateParams(changes: Record<string, string | null>) {
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      for (const [key, value] of Object.entries(changes)) {
        if (value === null) next.delete(key);
        else next.set(key, value);
      }
      return next;
    }, { replace: true });
  }
  function selectStatus(status: FindingStatus) {
    updateParams({ status: status === "open" ? null : status, finding: null });
  }
  function toggleFinding(findingId: string) {
    updateParams({ finding: expandedFindingId === findingId ? null : findingId });
  }
  function toggleSelected(findingId: string) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(findingId)) next.delete(findingId);
      else next.add(findingId);
      return next;
    });
  }
  const allInViewSelected = findings.length > 0 && findings.every((finding) => selected.has(finding.id));
  const columns = canManage ? 9 : 8;

  return (
    <>
      <section className="table-panel">
        <div className="panel-heading"><div><h2>Findings</h2><p>De-duplicated across runs, most important first. Open a finding to see its evidence and triage it.</p></div></div>
        <div className="tab-bar findings-status-tabs" role="tablist" aria-label="Finding status">
          {STATUS_TABS.map((tab) => (
            <button key={tab.status} role="tab" aria-selected={statusFilter === tab.status}
              className={`tab ${statusFilter === tab.status ? "active" : ""}`}
              onClick={() => selectStatus(tab.status)}>
              {tab.label} <span className="tab-count">{summary?.counts_by_status?.[tab.status] ?? 0}</span>
            </button>
          ))}
        </div>
        {/* REQ-CONSOLE-013: the severity filter sits in the findings panel (it used to be a separate
            panel above it). Counts are for open findings, so they show on the Open tab only. */}
        <div className="severity-chips" role="group" aria-label="Filter by severity">
          <button className={`severity-chip ${severityFilter ? "" : "selected"}`} aria-pressed={!severityFilter}
            onClick={() => setSeverityFilter(undefined)}>All severities</button>
          {SEVERITIES.map((severity) => (
            <button key={severity} className={`severity-chip ${severityFilter === severity ? "selected" : ""}`}
              aria-pressed={severityFilter === severity}
              onClick={() => setSeverityFilter(severity === severityFilter ? undefined : severity)}>
              <span className={`severity-dot ${severityClass(severity)}`} aria-hidden="true" />
              {severity.charAt(0).toUpperCase() + severity.slice(1)}
              {statusFilter === "open" && <span className="tab-count">{summary?.counts_by_severity?.[severity] ?? 0}</span>}
            </button>
          ))}
        </div>
        {/* REQ-TRIAGE-005: owner or administrator only; the API refuses anyone else with 403. */}
        {canManage && (
          <BulkTriageBar engagementId={engagementId} selectedIds={[...selected]} listStatus={statusFilter}
            onClear={() => setSelected(new Set())} />
        )}
        <div className="responsive-table">
          <table className="data-table findings-table">
            <thead><tr>
              {canManage && (
                <th className="select-cell">
                  <input type="checkbox" aria-label="Select all findings in this view" checked={allInViewSelected}
                    disabled={findings.length === 0}
                    onChange={() => setSelected(allInViewSelected ? new Set() : new Set(findings.map((f) => f.id)))} />
                </th>
              )}
              <th>Severity</th><th>Finding</th><th>Found on</th><th>Category</th><th>Confidence</th><th>Score</th><th>First seen</th><th>Last seen</th></tr></thead>
            <tbody>
              {findings.map((finding) => {
                const expanded = expandedFindingId === finding.id;
                return (
                  <Fragment key={finding.id}>
                    <tr id={`finding-${finding.id}`} className={`finding-row ${expanded ? "expanded" : ""}`} onClick={() => toggleFinding(finding.id)}>
                      {canManage && (
                        <td className="select-cell" onClick={(e) => e.stopPropagation()}>
                          <input type="checkbox" aria-label={`Select finding: ${finding.title}`}
                            checked={selected.has(finding.id)} onChange={() => toggleSelected(finding.id)} />
                        </td>
                      )}
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
                      <tr className="finding-detail-row"><td colSpan={columns}>
                        {canManage && sameTitleIds(findings, finding).length > 0 && (
                          <p className="same-title-hint">
                            <button className="secondary-action"
                              onClick={(e) => { e.stopPropagation(); setSelected(new Set([finding.id, ...sameTitleIds(findings, finding)])); }}>
                              Select this and the {sameTitleIds(findings, finding).length} other finding{sameTitleIds(findings, finding).length === 1 ? "" : "s"} with the same title
                            </button>
                            <span className="muted-line">They are ticked in the list so you can review them; each is changed on its own.</span>
                          </p>
                        )}
                        <FindingDetail finding={finding} canManage={canManage} onTriaged={() => updateParams({ finding: null })} />
                      </td></tr>
                    )}
                  </Fragment>
                );
              })}
              {findings.length === 0 && <tr><td colSpan={columns} className="empty-cell">{STATUS_TABS.find((tab) => tab.status === statusFilter)?.empty}</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
