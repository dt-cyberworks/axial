import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";

import { api, type ReportJob, type ToolCapability } from "../api/client";
import DnsSection from "../components/DnsSection";
import FindingsSection from "../components/FindingsSection";
import SurfaceGraph from "../components/SurfaceGraph";
import { fmtDuration, fmtTime, runStatePill } from "../lib/runs";

const TOOL_CATEGORIES = ["recon", "fingerprint", "vuln", "cred", "exploit"] as const;
type ToolCategory = typeof TOOL_CATEGORIES[number];
type GrantState = Record<ToolCategory, { passive: boolean; active: boolean; manualTools: string[] }>;

function emptyGrants(): GrantState {
  return {
    recon: { passive: false, active: false, manualTools: [] },
    fingerprint: { passive: false, active: false, manualTools: [] },
    vuln: { passive: false, active: false, manualTools: [] },
    cred: { passive: false, active: false, manualTools: [] },
    exploit: { passive: false, active: false, manualTools: [] },
  };
}

/**
 * Engagement detail — the hub for one engagement (REQ-RUN-005).
 * Shows readiness + Start run, the list of runs (click → run detail), and the
 * engagement-wide findings. Per-run detail (progress, diff, agent, log) lives on
 * the Run detail page.
 */
export default function EngagementDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data: engagement } = useQuery({ queryKey: ["engagement", id], queryFn: () => api.getEngagement(id!), enabled: !!id });
  const { data: readiness } = useQuery({ queryKey: ["scan-readiness", id], queryFn: () => api.scanReadiness(id!), enabled: !!id, refetchInterval: 10000 });
  const { data: scanRuns = [] } = useQuery({ queryKey: ["scan-runs", id], queryFn: () => api.listScanRuns(id!), enabled: !!id, refetchInterval: 5000 });
  const { data: summary } = useQuery({ queryKey: ["summary", id], queryFn: () => api.summary(id!), enabled: !!id, refetchInterval: 5000 });
  const { data: scopeAssets = [] } = useQuery({ queryKey: ["scope-assets", id], queryFn: () => api.listScopeAssets(id!), enabled: !!id });

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
  const { data: reports = [] } = useQuery({ queryKey: ["reports", id], queryFn: () => api.listReports(id!), enabled: !!id });
  const generateReport = useMutation({
    mutationFn: () => api.requestReport(id!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["reports", id] }),
  });
  const downloadReport = useMutation({
    mutationFn: (report: ReportJob) => api.downloadReport(id!, report.report_id, report.filename),
  });

  const activeRun = scanRuns.find((r) => r.state === "running" || r.state === "waiting_approval");

  const startScan = useMutation({
    mutationFn: () => api.startScan(id!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scan-runs", id] }),
  });

  // GitHub issue #16: granting tool categories and activating were only
  // reachable inside the one-time creation wizard - a draft engagement that
  // never finished the wizard (browser refresh, tab close, created via
  // API/script) had no GUI path forward at all. This mirrors
  // EngagementWizard.tsx's Tools/Authorize steps, but reads back what is
  // already granted instead of assuming a blank slate.
  const isDraft = engagement?.status === "draft";
  const { data: toolCapabilities } = useQuery({
    queryKey: ["tool-capabilities"], queryFn: api.listToolCapabilities, enabled: isDraft,
  });
  const { data: existingGrants } = useQuery({
    queryKey: ["tool-grants", id], queryFn: () => api.listToolGrants(id!), enabled: !!id && isDraft,
  });
  const [grants, setGrants] = useState<GrantState>(emptyGrants());
  const [grantsInitialized, setGrantsInitialized] = useState(false);

  const toolsByCategory = useMemo(() => {
    const grouped: Record<ToolCategory, ToolCapability[]> = { recon: [], fingerprint: [], vuln: [], cred: [], exploit: [] };
    for (const tool of toolCapabilities?.tools ?? []) {
      if ((TOOL_CATEGORIES as readonly string[]).includes(tool.category) && tool.enabled) {
        grouped[tool.category as ToolCategory].push(tool);
      }
    }
    for (const category of TOOL_CATEGORIES) grouped[category].sort((a, b) => a.name.localeCompare(b.name));
    return grouped;
  }, [toolCapabilities]);

  const passiveToolsByCategory = useMemo(() => {
    const grouped: Record<ToolCategory, ToolCapability[]> = { recon: [], fingerprint: [], vuln: [], cred: [], exploit: [] };
    for (const category of TOOL_CATEGORIES) {
      grouped[category] = toolsByCategory[category].filter((tool) => tool.execution_class === "passive");
    }
    return grouped;
  }, [toolsByCategory]);

  useEffect(() => {
    if (!existingGrants || grantsInitialized) return;
    const next = emptyGrants();
    for (const grant of existingGrants) {
      const category = grant.tool_category as ToolCategory;
      if (!(TOOL_CATEGORIES as readonly string[]).includes(category)) continue;
      if (grant.mode === "passive") next[category].passive = true;
      if (grant.mode === "active") { next[category].active = true; next[category].manualTools = grant.manual_tools; }
    }
    setGrants(next);
    setGrantsInitialized(true);
  }, [existingGrants, grantsInitialized]);

  function toggleManualTool(category: ToolCategory, toolName: string, checked: boolean) {
    setGrants((current) => {
      const existing = new Set(current[category].manualTools);
      if (checked) existing.add(toolName);
      else existing.delete(toolName);
      return { ...current, [category]: { ...current[category], manualTools: [...existing].sort() } };
    });
  }

  function categoryGrantSummary(category: ToolCategory) {
    const grant = grants[category];
    const passiveTools = passiveToolsByCategory[category];
    if (grant.active) {
      const manual = grant.manualTools.length;
      return `${toolsByCategory[category].length} active tool${toolsByCategory[category].length === 1 ? "" : "s"} available, ${manual} require${manual === 1 ? "s" : ""} approval`;
    }
    if (passiveTools.length > 0) return `Passive available: ${passiveTools.map((tool) => tool.name).join(", ")}.`;
    return "No passive tools in this category. Enable active only if target-touching checks are authorized.";
  }

  const saveGrants = useMutation({
    mutationFn: async () => {
      for (const category of TOOL_CATEGORIES) {
        const grant = grants[category];
        if (grant.passive && passiveToolsByCategory[category].length > 0) {
          await api.addToolGrant(id!, { tool_category: category, mode: "passive", requires_manual_approval: false });
        }
        if (grant.active) {
          await api.addToolGrant(id!, {
            tool_category: category, mode: "active", requires_manual_approval: false, manual_tools: grant.manualTools,
          });
        }
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tool-grants", id] });
      queryClient.invalidateQueries({ queryKey: ["scan-readiness", id] });
    },
  });

  const activateEngagementMutation = useMutation({
    mutationFn: () => api.activateEngagement(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["engagement", id] });
      queryClient.invalidateQueries({ queryKey: ["scan-readiness", id] });
    },
  });

  if (!id) return null;

  return (
    <section className="page-stack">
      <nav className="breadcrumb"><Link to="/">Engagements</Link><span>/</span><span>{engagement?.title ?? "Engagement"}</span></nav>

      <header className="page-header">
        <div>
          <span className="eyebrow">Engagement</span>
          <h1>{engagement?.title ?? "Engagement"}</h1>
          <p>Status {engagement?.status ?? "?"} · Vector Agent {engagement?.ai_testing_allowed ? "enabled" : "disabled"} · {id}</p>
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
        <div><span>Risk signal</span><strong>{summary?.risk_ampel?.toUpperCase() ?? "NONE"}</strong></div>
        <div><span>Runs</span><strong>{scanRuns.length}</strong></div>
        <div><span>Open findings</span><strong>{Object.values(summary?.counts_by_severity ?? {}).reduce((a, b) => a + b, 0)}</strong></div>
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

      {isDraft && (
        <section className="form-panel settings-panel">
          <h2>Tool grants</h2>
          <p className="muted-line">
            This draft engagement has no other GUI path to grant tool categories or activate outside the
            one-time creation wizard. Checked rows reflect what is already granted; saving only adds grants,
            it never revokes one.
          </p>
          <div className="responsive-table">
            <table className="data-table tool-grant-table">
              <thead>
                <tr>
                  <th>Category</th>
                  <th>Allow passive</th>
                  <th>Allow active</th>
                  <th>Require approval for these active tools</th>
                </tr>
              </thead>
              <tbody>
                {TOOL_CATEGORIES.map((category) => (
                  <tr key={category}>
                    <td>
                      <strong>{category}</strong>
                      <span className="muted-line">{categoryGrantSummary(category)}</span>
                    </td>
                    <td>
                      {passiveToolsByCategory[category].length > 0 ? (
                        <label className="grant-toggle">
                          <input
                            type="checkbox"
                            checked={grants[category].passive}
                            onChange={(e) => setGrants((g) => ({ ...g, [category]: { ...g[category], passive: e.target.checked } }))}
                          />
                          <span>Passive allowed</span>
                          <small>{passiveToolsByCategory[category].map((tool) => tool.name).join(", ")}</small>
                        </label>
                      ) : (
                        <span className="muted-line">No passive tools</span>
                      )}
                    </td>
                    <td>
                      <label className="grant-toggle">
                        <input
                          type="checkbox"
                          checked={grants[category].active}
                          onChange={(e) => setGrants((g) => ({ ...g, [category]: { ...g[category], active: e.target.checked } }))}
                        />
                        <span>Active allowed</span>
                      </label>
                    </td>
                    <td>
                      {grants[category].active ? (
                        <div className="tool-approval-grid">
                          {toolsByCategory[category].map((tool) => (
                            <label key={tool.name}>
                              <input
                                type="checkbox"
                                checked={grants[category].manualTools.includes(tool.name)}
                                onChange={(e) => toggleManualTool(category, tool.name, e.target.checked)}
                              />
                              <span>{tool.name}</span>
                              {!tool.dispatched && <small>catalog</small>}
                            </label>
                          ))}
                          {toolsByCategory[category].length === 0 && <span className="muted-line">No enabled tools in this category.</span>}
                        </div>
                      ) : (
                        <span className="muted-line">Not applicable until active is allowed.</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="form-actions">
            <button disabled={saveGrants.isPending} onClick={() => saveGrants.mutate()}>
              {saveGrants.isPending ? "Saving…" : "Save tool grants"}
            </button>
          </div>
          {saveGrants.isError && <div className="error-block">Save failed: {(saveGrants.error as Error).message}</div>}
          {saveGrants.isSuccess && <div className="success-block">Tool grants saved.</div>}

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

      <section className="form-panel settings-panel">
        <h2>Start a scan run</h2>
        {readiness && !readiness.ready ? (
          <div className="warning-block">
            This engagement cannot scan yet. Resolve these first:
            <ul>{readiness.blockers.map((b) => <li key={b.code}><strong>{b.code}</strong> — {b.message}</li>)}</ul>
          </div>
        ) : (
          <div className="success-block">All pre-flight checks pass. A new run will start the pipeline (discovery → report).</div>
        )}
        <div className="form-actions">
          <button
            className="primary-action"
            disabled={!readiness?.ready || !!activeRun || startScan.isPending}
            onClick={() => startScan.mutate()}
          >
            {activeRun ? "A run is already active" : startScan.isPending ? "Starting…" : "Start run"}
          </button>
          {activeRun && <Link className="secondary-action" to={`/engagements/${id}/runs/${activeRun.id}`}>Open active run →</Link>}
        </div>
        {startScan.isError && <div className="error-block">Start failed: {(startScan.error as Error).message}</div>}
      </section>

      <section className="table-panel">
        <div className="panel-heading"><div><h2>Runs</h2><p>Click a run to see its progress, diff, agent steps, and log. Findings below accumulate across all runs.</p></div></div>
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

      <SurfaceGraph engagementId={id} />

      <DnsSection engagementId={id} />

      <FindingsSection engagementId={id} />
    </section>
  );
}
