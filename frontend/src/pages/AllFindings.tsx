import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Fragment, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { api, type PortfolioFinding } from "../api/client";
import FindingDetail from "../components/FindingDetail";
import {
  observedLocationLabel, parseFindingStatus, problemSummary, SEVERITIES, severityClass, STATUS_LABEL, STATUS_TABS, targetLabel,
} from "../lib/findings";

const PAGE_SIZE = 50;

function capitalize(text: string) {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** Link into the finding's own engagement, with the finding opened (REQ-CONSOLE-013). */
function engagementFindingLink(finding: PortfolioFinding) {
  const params = new URLSearchParams({ finding: finding.id });
  if (finding.status !== "open") params.set("status", finding.status);
  return `/engagements/${finding.engagement_id}?${params}`;
}

/**
 * REQ-CONSOLE-016: every finding the user can see, across engagements, most
 * severe first. The server decides what is visible (REQ-PORTFOLIO-001); the
 * filters live in the URL so a view can be reloaded and shared.
 */
export default function AllFindings() {
  const [searchParams, setSearchParams] = useSearchParams();
  const status = parseFindingStatus(searchParams.get("status"));
  const severityParam = searchParams.get("severity") ?? "";
  const severity = SEVERITIES.includes(severityParam) ? severityParam : "";
  const engagementId = searchParams.get("engagement") ?? "";
  const q = searchParams.get("q") ?? "";
  const page = Math.max(1, Number.parseInt(searchParams.get("page") ?? "1", 10) || 1);
  const [searchText, setSearchText] = useState(q);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  function update(changes: Record<string, string | null>, keepPage = false) {
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      for (const [key, value] of Object.entries(changes)) {
        if (value === null || value === "") next.delete(key);
        else next.set(key, value);
      }
      if (!keepPage) next.delete("page");
      return next;
    }, { replace: true });
    setExpandedId(null);
  }

  // The search is applied 300 ms after the last keystroke; Back/Forward can change q from outside.
  useEffect(() => {
    setSearchText((current) => (current.trim() === q ? current : q));
  }, [q]);
  useEffect(() => {
    const text = searchText.trim();
    if (text === q) return;
    const timer = window.setTimeout(() => update({ q: text || null }), 300);
    return () => window.clearTimeout(timer);
    // update() is recreated each render; the effect only needs to follow the typed text and q.
  }, [searchText, q]);

  const { data: engagements = [], isSuccess: engagementsLoaded } = useQuery({ queryKey: ["engagements"], queryFn: api.listEngagements });
  const findingsQuery = useQuery({
    queryKey: ["all-findings", status, severity, engagementId, q, page],
    queryFn: () => api.allFindings({
      status, severity: severity || undefined, engagement_id: engagementId || undefined, q: q || undefined,
      limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE,
    }),
    placeholderData: keepPreviousData,
    refetchInterval: 15000,
  });
  const result = findingsQuery.data;
  const items = result?.items ?? [];
  const total = result?.total ?? 0;
  // The range describes the rows on screen (from the response), not the page
  // being loaded - with keepPreviousData those differ until the new page arrives.
  const from = result && items.length > 0 ? result.offset + 1 : 0;
  const to = result ? result.offset + items.length : 0;
  const updating = findingsQuery.isPlaceholderData;
  const filtered = !!(severity || engagementId || q);

  function emptyMessage() {
    if (engagementsLoaded && engagements.length === 0) {
      return <>You have no engagements yet. <Link to="/new">Create an engagement</Link> to start.</>;
    }
    if (total > 0) return <>This page is past the end of the list. <button onClick={() => update({})}>Go to the first page</button></>;
    if (filtered) return "No findings match these filters.";
    return status === "open"
      ? "No open findings in any of your engagements."
      : `No findings marked as ${STATUS_LABEL[status].toLowerCase()}.`;
  }

  return (
    <section className="page-stack">
      <header className="page-header">
        <div>
          <span className="eyebrow">Findings</span>
          <h1>All findings</h1>
          <p>Findings from every engagement you can see, most severe first. Open one to triage it, or to have the Lens Agent explain it.</p>
        </div>
      </header>

      <section className="table-panel">
        <div className="tab-bar findings-status-tabs" role="tablist" aria-label="Finding status">
          {STATUS_TABS.map((tab) => (
            <button key={tab.status} role="tab" aria-selected={status === tab.status}
              className={`tab ${status === tab.status ? "active" : ""}`}
              onClick={() => update({ status: tab.status === "open" ? null : tab.status })}>
              {tab.label} <span className="tab-count">{result?.counts_by_status?.[tab.status] ?? 0}</span>
            </button>
          ))}
        </div>

        <div className="findings-filters">
          <label>
            Severity
            <select value={severity} onChange={(e) => update({ severity: e.target.value })}>
              <option value="">All severities</option>
              {SEVERITIES.map((sev) => (
                <option key={sev} value={sev}>{capitalize(sev)} ({result?.counts_by_severity?.[sev] ?? 0})</option>
              ))}
            </select>
          </label>
          <label>
            Engagement
            <select value={engagementId} onChange={(e) => update({ engagement: e.target.value })}>
              <option value="">All engagements</option>
              {engagements.map((engagement) => <option key={engagement.id} value={engagement.id}>{engagement.title}</option>)}
            </select>
          </label>
          <label className="search-filter">
            Search
            <input type="search" value={searchText} placeholder="Finding or target" maxLength={200}
              onChange={(e) => setSearchText(e.target.value)} />
          </label>
        </div>

        {findingsQuery.isError && (
          <div className="error-block">Could not load findings: {(findingsQuery.error as Error).message}</div>
        )}

        <div className="responsive-table">
          <table className="data-table findings-table">
            <thead><tr><th>Severity</th><th>Finding</th><th>Engagement</th><th>Target</th><th>Last seen</th></tr></thead>
            <tbody>
              {items.map((finding) => {
                const expanded = expandedId === finding.id;
                return (
                  <Fragment key={finding.id}>
                    <tr className={`finding-row ${expanded ? "expanded" : ""}`} onClick={() => setExpandedId(expanded ? null : finding.id)}>
                      <td><span className={`severity-badge ${severityClass(finding.severity)}`}>{finding.severity ?? "info"}</span></td>
                      <td><strong>{finding.title}</strong><span className="muted-line">{problemSummary(finding)}</span><span className="row-hint">Click for evidence, explanation, and triage</span></td>
                      <td><Link to={`/engagements/${finding.engagement_id}`} onClick={(e) => e.stopPropagation()}>{finding.engagement_title}</Link></td>
                      <td><strong>{targetLabel(finding)}</strong><span className="muted-line">{observedLocationLabel(finding)}</span></td>
                      <td>{finding.last_seen ? new Date(finding.last_seen).toLocaleString() : "-"}</td>
                    </tr>
                    {expanded && (
                      <tr className="finding-detail-row"><td colSpan={5}>
                        <Link className="finding-open-link" to={engagementFindingLink(finding)}>Open in engagement →</Link>
                        <FindingDetail finding={finding} onTriaged={() => setExpandedId(null)} />
                      </td></tr>
                    )}
                  </Fragment>
                );
              })}
              {items.length === 0 && (
                <tr><td colSpan={5} className="empty-cell">{findingsQuery.isLoading ? "Loading findings…" : emptyMessage()}</td></tr>
              )}
            </tbody>
          </table>
        </div>

        {items.length > 0 && (
          <div className="pager">
            <span aria-live="polite">{updating ? "Loading…" : `${from}–${to} of ${total}`}</span>
            <button disabled={page <= 1 || updating} onClick={() => update({ page: page - 1 > 1 ? String(page - 1) : null }, true)}>Previous</button>
            <button disabled={to >= total || updating} onClick={() => update({ page: String(page + 1) }, true)}>Next</button>
          </div>
        )}
      </section>
    </section>
  );
}
