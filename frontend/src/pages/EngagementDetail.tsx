import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";

import { api, isNotFound, type ReportJob } from "../api/client";
import NotFound from "./NotFound";
import ChunkErrorBoundary from "../components/ChunkErrorBoundary";
import DnsSection from "../components/DnsSection";
import DiscoverySection from "../components/DiscoverySection";
import { discoveryFlagSummary } from "../components/DiscoverySwitches";
import FindingsSection from "../components/FindingsSection";
import ToolGrantsEditor from "../components/ToolGrantsEditor";
import { fmtDuration, fmtTime, runStatePill } from "../lib/runs";

// REQ-CONSOLE-015: the graph library is large and only this tab uses it.
const SurfaceGraph = lazy(() => import("../components/SurfaceGraph"));

// REQ-CONSOLE-013: findings first; the tab is part of the URL (?tab=assets).
const ENGAGEMENT_TABS = [
  { id: "findings", label: "Findings" },
  { id: "assets", label: "Assets" },
  { id: "runs", label: "Runs & reports" },
] as const;
type EngagementTab = typeof ENGAGEMENT_TABS[number]["id"];
function parseEngagementTab(value: string | null): EngagementTab {
  return ENGAGEMENT_TABS.some((tab) => tab.id === value) ? (value as EngagementTab) : "findings";
}

/** REQ-CONSOLE-012: the highest open severity in English, instead of the API's
 * internal traffic-light value (German "rot"/"gelb"/"blau"), which also merged
 * critical with high and low/info with "nothing open". */
function worstOpenSeverity(counts: Record<string, number> | undefined): string {
  if (!counts) return "…";
  const worst = ["critical", "high", "medium", "low", "info"].find((sev) => (counts[sev] ?? 0) > 0);
  return worst ? worst.charAt(0).toUpperCase() + worst.slice(1) : "None open";
}

/**
 * Engagement detail — the hub for one engagement (REQ-RUN-005).
 * Shows readiness + Start run above three tabs (REQ-CONSOLE-013): findings
 * (default), assets (graph, DNS), and runs & reports. Per-run detail
 * (progress, diff, agent, log) lives on the Run detail page.
 */
export default function EngagementDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = parseEngagementTab(searchParams.get("tab"));
  // A new history entry per tab, so Back returns to the previous tab.
  const selectTab = (tab: EngagementTab) => setSearchParams(tab === "findings" ? {} : { tab });

  const engagementQuery = useQuery({ queryKey: ["engagement", id], queryFn: () => api.getEngagement(id!), enabled: !!id, retry: (count, error) => !isNotFound(error) && count < 2 });
  const engagement = engagementQuery.data;
  // REQ-CONSOLE-008: nothing else is fetched (or polled) for an engagement that does not exist.
  const engagementLoaded = !!id && engagementQuery.isSuccess;
  const { data: readiness, isError: readinessFailed, error: readinessError } = useQuery({ queryKey: ["scan-readiness", id], queryFn: () => api.scanReadiness(id!), enabled: engagementLoaded, refetchInterval: 10000 });
  const { data: scanRuns = [] } = useQuery({ queryKey: ["scan-runs", id], queryFn: () => api.listScanRuns(id!), enabled: engagementLoaded, refetchInterval: 5000 });
  const { data: summary } = useQuery({ queryKey: ["summary", id], queryFn: () => api.summary(id!), enabled: engagementLoaded, refetchInterval: 5000 });
  const { data: scopeAssets = [] } = useQuery({ queryKey: ["scope-assets", id], queryFn: () => api.listScopeAssets(id!), enabled: engagementLoaded });

  const authorizationBlockers = scopeAssets.filter(
    (asset) => asset.rule === "allow" && asset.active_allowed && !asset.authorization_verified,
  );
  const attestAuthorization = useMutation({
    mutationFn: (assetId: string) => api.verifyScopeAuthorization(id!, assetId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scope-assets", id] });
      queryClient.invalidateQueries({ queryKey: ["scan-readiness", id] });
    },
  });

  // REQ-DOWNLOAD-001: authenticated blob download, not a bare anchor. Errors
  // become visible text instead of a blank tab.
  const downloadAuthorizationPdf = useMutation({ mutationFn: () => api.downloadAuthorizationPdf(id!) });

  // REQ-REPORT-004
  const { data: reports = [] } = useQuery({ queryKey: ["reports", id], queryFn: () => api.listReports(id!), enabled: engagementLoaded && activeTab === "runs" });
  const generateReport = useMutation({
    mutationFn: () => api.requestReport(id!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["reports", id] }),
  });
  const downloadReport = useMutation({
    mutationFn: (report: ReportJob) => api.downloadReport(id!, report.report_id, report.filename),
  });

  const activeRun = scanRuns.find((r) => r.state === "running" || r.state === "waiting_approval");
  const openFindings = Object.values(summary?.counts_by_severity ?? {}).reduce((a, b) => a + b, 0);

  const startScan = useMutation({
    mutationFn: () => api.startScan(id!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scan-runs", id] }),
  });

  // GitHub issue #16 / #48: a draft that never finished the wizard is activated from
  // here; its tool grants use the shared ToolGrantsEditor (also on the Edit page, where
  // grants can be changed after activation).
  const isDraft = engagement?.status === "draft";

  const activateEngagementMutation = useMutation({
    mutationFn: () => api.activateEngagement(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["engagement", id] });
      queryClient.invalidateQueries({ queryKey: ["scan-readiness", id] });
    },
  });

  if (!id) return null;
  // REQ-CONSOLE-008: never render a working-looking page for an engagement
  // that does not exist (or is not the caller's) - that page used to claim
  // "All pre-flight checks pass" for an id like "new".
  if (engagementQuery.isError && isNotFound(engagementQuery.error)) {
    return <NotFound title="Engagement not found" message="This engagement does not exist, or it belongs to another user." />;
  }
  if (engagementQuery.isError) {
    return (
      <section className="page-stack">
        <div className="error-block">Could not load this engagement: {(engagementQuery.error as Error).message}</div>
        <div className="form-actions"><button onClick={() => engagementQuery.refetch()}>Try again</button></div>
      </section>
    );
  }
  if (!engagement) return <section className="page-stack"><p className="muted-line">Loading engagement…</p></section>;

  return (
    <section className="page-stack">
      <nav className="breadcrumb"><Link to="/">Engagements</Link><span>/</span><span>{engagement?.title ?? "Engagement"}</span></nav>

      <header className="page-header">
        <div>
          <span className="eyebrow">Engagement</span>
          <h1>{engagement?.title ?? "Engagement"}</h1>
          <p>Status {engagement?.status ?? "?"} · Vector Agent {engagement?.ai_testing_allowed ? "enabled" : "disabled"} · Discovery extras: {engagement ? discoveryFlagSummary(engagement) : "?"} · {id}</p>
        </div>
        <div className="header-actions">
          <Link to={`/engagements/${id}/edit`} className="secondary-action">Edit</Link>
          <button
            className="secondary-action"
            disabled={downloadAuthorizationPdf.isPending}
            onClick={() => downloadAuthorizationPdf.mutate()}
          >
            {downloadAuthorizationPdf.isPending ? "Preparing…" : "Authorization PDF"}
          </button>
          <Link to={`/engagements/${id}/audit`} className="secondary-action">Audit</Link>
        </div>
      </header>

      {downloadAuthorizationPdf.isError && (
        <div className="error-block">
          Authorization PDF download failed: {(downloadAuthorizationPdf.error as Error).message}
        </div>
      )}

      <div className="status-band">
        <div><span>Risk signal</span><strong>{worstOpenSeverity(summary?.counts_by_severity)}</strong></div>
        <div><span>Runs</span><strong>{scanRuns.length}</strong></div>
        <div><span>Open findings</span><strong>{openFindings}</strong></div>
        <div><span>Scan readiness</span><strong>{readiness ? (readiness.ready ? "Ready" : "Blocked") : "…"}</strong></div>
      </div>

      {authorizationBlockers.length > 0 && (
        <section className="form-panel settings-panel">
          <h2>Authorization not attested</h2>
          <div className="warning-block">
            Active checks remain blocked until an operator confirms authorization for each target.
          </div>
          <div className="form-actions">
            {authorizationBlockers.map((asset) => (
              <button
                key={asset.id}
                disabled={attestAuthorization.isPending}
                onClick={() => attestAuthorization.mutate(asset.id)}
              >
                Attest authorization for {asset.value}
              </button>
            ))}
          </div>
          {attestAuthorization.isError && (
            <div className="error-block">Authorization update failed: {(attestAuthorization.error as Error).message}</div>
          )}
        </section>
      )}

      {isDraft && <ToolGrantsEditor engagementId={id!} status="draft" />}

      {isDraft && (
        <section className="form-panel settings-panel">
          <h2 style={{ marginTop: 18 }}>Activate engagement</h2>
          <div className="warning-block">
            Activation checks the same requirements as the wizard's authorization step (allow-scope assets,
            authorization attestation, time window, and - for bug-bounty engagements - a linked program policy).
            A failed check reports exactly which one is unmet.
          </div>
          <div className="form-actions">
            <button className="primary-action" disabled={activateEngagementMutation.isPending} onClick={() => activateEngagementMutation.mutate()}>
              {activateEngagementMutation.isPending ? "Activating…" : "Activate engagement"}
            </button>
          </div>
          {activateEngagementMutation.isError && (
            <div className="error-block">Activation failed: {(activateEngagementMutation.error as Error).message}</div>
          )}
          {activateEngagementMutation.isSuccess && <div className="success-block">Engagement activated.</div>}
        </section>
      )}

      {/* REQ-CONSOLE-013: one compact row (readiness left, action right), so the findings start high on the page. */}
      <section className="form-panel start-run-panel" aria-label="Start a scan run">
        <div className="start-run-status">
          {/* REQ-CONSOLE-008: green only when the server said ready - not while loading or after an error. */}
          {readinessFailed ? (
            <div className="error-block">Could not check whether this engagement can scan: {(readinessError as Error).message}</div>
          ) : !readiness ? (
            <p className="muted-line">Checking pre-flight requirements…</p>
          ) : !readiness.ready ? (
            <div className="warning-block">
              This engagement cannot scan yet. Resolve these first:
              <ul>
                {readiness.blockers.map((b) => (
                  <li key={b.code} title={b.code}>
                    {b.message}
                    {b.action === "tool_grants" && (
                      isDraft
                        ? <> <a href="#tool-grants">Go to tool grants</a></>
                        : <> <Link to={`/engagements/${id}/edit#tool-grants`}>Open tool grants</Link></>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <div className="success-block">All pre-flight checks pass. A new run will start the pipeline (discovery → report).</div>
          )}
        </div>
        <div className="start-run-actions">
          <button
            className="primary-action"
            disabled={!readiness?.ready || !!activeRun || startScan.isPending}
            onClick={() => startScan.mutate()}
          >
            {activeRun ? "A run is already active" : startScan.isPending ? "Starting…" : "Start run"}
          </button>
          {activeRun && <Link className="secondary-action" to={`/engagements/${id}/runs/${activeRun.id}`}>Open active run →</Link>}
        </div>
        {startScan.isError && <div className="error-block start-run-error">Start failed: {(startScan.error as Error).message}</div>}
      </section>

      <div className="page-tabs" role="tablist" aria-label="Engagement sections">
        {ENGAGEMENT_TABS.map((tab) => (
          <button key={tab.id} id={`engagement-tab-${tab.id}`} role="tab" aria-selected={activeTab === tab.id}
            aria-controls="engagement-tab-panel" className={`page-tab ${activeTab === tab.id ? "active" : ""}`}
            onClick={() => selectTab(tab.id)}>
            {tab.label}
            {tab.id === "findings" && <span className="tab-count">{openFindings}</span>}
            {tab.id === "runs" && <span className="tab-count">{scanRuns.length}</span>}
          </button>
        ))}
      </div>

      {/* Only the shown tab is mounted, so only its data is requested. */}
      <div id="engagement-tab-panel" role="tabpanel" aria-labelledby={`engagement-tab-${activeTab}`} className="page-stack">
        {activeTab === "findings" && <FindingsSection engagementId={id} />}

        {activeTab === "assets" && (
          <>
            <ChunkErrorBoundary what="attack-surface graph">
              <Suspense fallback={<section className="table-panel"><p className="muted-line lazy-placeholder">Loading graph…</p></section>}>
                <SurfaceGraph engagementId={id} />
              </Suspense>
            </ChunkErrorBoundary>
            <DnsSection engagementId={id} />
            {engagement && (
              <DiscoverySection engagementId={id} crawlingEnabled={engagement.crawling_enabled}
                screenshotsEnabled={engagement.screenshots_enabled} />
            )}
          </>
        )}

        {activeTab === "runs" && (
          <>
            <section className="table-panel">
              <div className="panel-heading"><div><h2>Runs</h2><p>Click a run to see its progress, diff, agent steps, and log. Findings accumulate across all runs; they are listed on the Findings tab.</p></div></div>
              <div className="responsive-table">
                <table className="data-table">
                  <thead><tr><th>Run</th><th>Started</th><th>Finished</th><th>Duration</th><th>Phase</th><th>State</th><th>Tool budget</th></tr></thead>
                  <tbody>
                    {scanRuns.map((run, index) => (
                      <tr key={run.id} className="finding-row" onClick={() => navigate(`/engagements/${id}/runs/${run.id}`)}>
                        <td>#{scanRuns.length - index}{index === 0 && <span className="muted-line">latest</span>}</td>
                        <td>{fmtTime(run.started_at)}</td>
                        <td>{fmtTime(run.finished_at)}</td>
                        <td>{fmtDuration(run.started_at, run.finished_at)}</td>
                        <td>{run.phase}</td>
                        <td><span className={`pill ${runStatePill(run.state)}`}>{run.cancel_requested && run.state === "running" ? "stopping…" : run.state}</span></td>
                        <td>{run.budget_tool_calls_used}/{run.budget_tool_calls_max}</td>
                      </tr>
                    ))}
                    {scanRuns.length === 0 && <tr><td className="empty-cell" colSpan={7}>No scan has run yet. Start one above.</td></tr>}
                  </tbody>
                </table>
              </div>
            </section>

            {/* REQ-REPORT-004: generating a report is a visible action with a
                result, not a fire-and-forget click. */}
            <section className="table-panel">
              <div className="panel-heading">
                <div>
                  <h2>Reports</h2>
                  <p>
                    The customer-facing PDF: executive summary, risk overview with the run-over-run diff, detailed
                    findings, asset inventory, and the methodology &amp; scope section that documents what was authorized.
                  </p>
                </div>
                <button disabled={generateReport.isPending} onClick={() => generateReport.mutate()}>
                  {generateReport.isPending ? "Generating…" : "Generate report"}
                </button>
              </div>
              {generateReport.isError && (
                <div className="error-block">Report generation failed: {(generateReport.error as Error).message}</div>
              )}
              {generateReport.isSuccess && generateReport.data.status === "failed" && (
                <div className="error-block">Report generation failed: {generateReport.data.error ?? "unknown error"}</div>
              )}
              {generateReport.isSuccess && generateReport.data.status === "done" && (
                <div className="success-block">Report generated — download it from the list below.</div>
              )}
              {downloadReport.isError && (
                <div className="error-block">Report download failed: {(downloadReport.error as Error).message}</div>
              )}
              <div className="responsive-table">
                <table className="data-table">
                  <thead><tr><th>Generated</th><th>Covers run</th><th>Status</th><th>Size</th><th></th></tr></thead>
                  <tbody>
                    {reports.map((report) => (
                      <tr key={report.report_id}>
                        <td>{fmtTime(report.created_at)}</td>
                        <td>
                          {report.scan_run_id
                            ? <Link to={`/engagements/${id}/runs/${report.scan_run_id}`}>run</Link>
                            : <span className="muted-line">no completed run</span>}
                        </td>
                        <td>
                          <span className={`pill ${report.status === "done" ? "good" : report.status === "failed" ? "bad" : "neutral"}`}>
                            {report.status}
                          </span>
                          {report.status === "failed" && report.error && <span className="muted-line">{report.error}</span>}
                        </td>
                        <td>{report.status === "done" ? `${Math.max(1, Math.round(report.byte_size / 1024))} KB` : "—"}</td>
                        <td>
                          {report.status === "done" && (
                            <button
                              className="secondary-action"
                              disabled={downloadReport.isPending}
                              onClick={() => downloadReport.mutate(report)}
                            >
                              Download PDF
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                    {reports.length === 0 && (
                      <tr><td className="empty-cell" colSpan={5}>No report generated yet.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        )}
      </div>
    </section>
  );
}
