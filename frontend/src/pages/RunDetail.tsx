import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { api, isNotFound, type AgentStep, type AssetReview } from "../api/client";
import NotFound from "./NotFound";
import { severityClass } from "../components/FindingsSection";
import RunActivity from "../components/RunActivity";
import { activityKey, reasonExplanation, type RunLogEntry } from "../lib/runActivity";
import { PHASES, PHASE_META, fmtDuration, fmtTime, phaseStateFor, runNumber, runStatePill } from "../lib/runs";
import { useTicker } from "../lib/useTicker";

type Tab = "progress" | "diff" | "agent" | "activity";

// High-value run evidence only. Per-request proxy traffic remains on the Audit page.
const STREAM_ACTIONS = [
  "tool_call",
  "tool_execution",
  "dns_materialization",
  "raw_egress_lease",
  "agent_event",
  "approval",
  "approval_execution",
  "scan_run_cancel_requested",
  "gateway_override",
];

export default function RunDetail() {
  const { id, runId } = useParams<{ id: string; runId: string }>();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<Tab>("progress");
  const [log, setLog] = useState<RunLogEntry[]>([]);
  const [expandedStep, setExpandedStep] = useState<string | null>(null);

  const engagementQuery = useQuery({ queryKey: ["engagement", id], queryFn: () => api.getEngagement(id!), enabled: !!id, retry: (count, error) => !isNotFound(error) && count < 2 });
  const engagement = engagementQuery.data;
  const engagementLoaded = !!id && engagementQuery.isSuccess;
  const scanRunsQuery = useQuery({ queryKey: ["scan-runs", id], queryFn: () => api.listScanRuns(id!), enabled: engagementLoaded, refetchInterval: 4000 });
  const scanRuns = scanRunsQuery.data ?? [];
  const run = scanRuns.find((r) => r.id === runId);
  const isRunning = run?.state === "running" || run?.state === "waiting_approval";
  // REQ-RUNUI-001: drives the elapsed-time text below on its own 1s cadence.
  // The 4s data refetch cannot do this - an unchanged run row re-renders
  // nothing under react-query's structural sharing.
  const now = useTicker(isRunning);

  const { data: diff } = useQuery({ queryKey: ["scan-diff", id, runId], queryFn: () => api.scanRunDiff(id!, runId!), enabled: engagementLoaded && !!runId });
  const { data: agentSteps = [] } = useQuery({
    queryKey: ["agent-steps", id, runId], queryFn: () => api.agentSteps(id!, runId!),
    enabled: engagementLoaded && !!runId, refetchInterval: isRunning ? 4000 : false,
  });

  const cancelRun = useMutation({
    mutationFn: () => api.cancelScanRun(id!, runId!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scan-runs", id] }),
  });

  // REQ-APPROVALUI-001: pending write approvals are now surfaced app-wide by
  // GlobalApprovalWatcher (mounted in the app shell), so they reach the operator
  // on any page - not only here. This view no longer renders its own popup.

  // Live asset review popup (REQ-ASSETREVIEW-002): pending post-discovery
  // review for THIS run (one review per run, unlike approvals which are
  // per-engagement).
  const { data: assetReviews = [] } = useQuery({
    queryKey: ["asset-reviews", id], queryFn: () => api.listAssetReviews(id!),
    enabled: engagementLoaded, refetchInterval: 2500,
  });
  const pendingReview = assetReviews.find((r) => r.scan_run_id === runId);
  const decideAssetReview = useMutation({
    mutationFn: ({ reviewId, excludedValues }: { reviewId: string; excludedValues: string[] }) =>
      api.decideAssetReview(id!, reviewId, excludedValues),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["asset-reviews", id] }),
  });

  // Live log via SSE (engagement stream), scoped to THIS RUN specifically (not
  // just the engagement) with phase-transition noise excluded (REQ-RUN-004),
  // so an older run's Activity view isn't starved by a newer run's event
  // volume and events from a different run never leak in (REQ-FIDELITY-002).
  useEffect(() => {
    if (!id || !runId) return;
    setLog([]);
    const source = new EventSource(
      api.streamUrl(id, { actions: STREAM_ACTIONS, history: true, limit: 180, scanRunId: runId }),
      { withCredentials: true },
    );
    source.addEventListener("audit_entry", (evt) => {
      const entry = JSON.parse((evt as MessageEvent).data) as RunLogEntry;
      setLog((prev) => prev.some((current) => activityKey(current) === activityKey(entry))
        ? prev
        : [...prev.slice(-179), entry]);
    });
    return () => source.close();
  }, [id, runId]);

  if (!id || !runId) return null;
  const num = runNumber(scanRuns, runId);

  // REQ-CONSOLE-008: an unknown run (or an engagement that is not the caller's) gets a real not-found page.
  if ((engagementQuery.isError && isNotFound(engagementQuery.error)) || (scanRunsQuery.isSuccess && !run)) {
    return <NotFound title="Scan run not found" message="This run does not exist in this engagement, or the engagement belongs to another user." />;
  }

  return (
    <section className="page-stack">
      {pendingReview && (
        <AssetReviewModal
          review={pendingReview}
          busy={decideAssetReview.isPending}
          onSubmit={(excludedValues) => decideAssetReview.mutate({ reviewId: pendingReview.id, excludedValues })}
        />
      )}
      <nav className="breadcrumb">
        <Link to="/">Engagements</Link><span>/</span>
        <Link to={`/engagements/${id}`}>{engagement?.title ?? "Engagement"}</Link><span>/</span>
        <span>Run #{num || "?"}</span>
      </nav>

      <header className="page-header">
        <div>
          <span className="eyebrow">Scan run</span>
          <h1>Run #{num || "?"}</h1>
          <p>
            Phase {run?.phase ?? "?"} · {fmtDuration(run?.started_at ?? null, run?.finished_at ?? null, now)} ·
            Tool budget {run ? `${run.budget_tool_calls_used}/${run.budget_tool_calls_max}` : "?"}
            {run?.state_reason ? ` · ${run.state_reason}` : ""}
          </p>
        </div>
        <div className="header-actions">
          {/* REQ-SCAN-014: a "done" run that never got a load-bearing tool to
              succeed must not read as a clean scan. The state pill alone says
              "done", which is exactly the ambiguity this warns about. */}
          {run?.state_reason?.includes("coverage_degraded:") && (
            <span className="pill warn" title={reasonExplanation(run.state_reason)}>
              reduced coverage
            </span>
          )}
          <span className={`pill ${runStatePill(run?.state ?? "")}`}>
            {run?.cancel_requested && isRunning ? "stopping…" : run?.state ?? "?"}
          </span>
          {isRunning && (
            <button className="danger-button" disabled={run?.cancel_requested || cancelRun.isPending}
              onClick={() => cancelRun.mutate()}>
              {run?.cancel_requested ? "Stop requested" : cancelRun.isPending ? "Stopping…" : "Stop scan"}
            </button>
          )}
        </div>
      </header>

      {isRunning && run?.current_tool && (
        <div className="current-activity-banner">
          <span className="pulse-dot" aria-hidden="true" />
          <span>
            Running <code>{run.current_tool}</code> on <code>{run.current_target}</code>
            {run.current_started_at && ` · started ${fmtDuration(run.current_started_at, null, now)} ago`}
          </span>
        </div>
      )}

      <div className="tab-bar">
        {(["progress", "diff", "agent", "activity"] as Tab[]).map((t) => (
          <button key={t} className={`tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>
            {t === "progress" ? "Progress" : t === "diff" ? "Diff" : t === "agent" ? "Vector Agent" : "Activity"}
          </button>
        ))}
      </div>

      {tab === "progress" && (
        <section className="table-panel">
          <div className="panel-heading"><div><h2>Scan progress</h2><p>Each phase, the tools it can run, and its state for this run.</p></div></div>
          <div className="phase-list">
            {PHASES.map((phase, index) => {
              const meta = PHASE_META[phase];
              const state = phaseStateFor(run, phase, index);
              return (
                <div key={phase} className={`phase-item ${state}`}>
                  <div className="phase-item-head">
                    <div>
                      <strong>{meta.label}</strong>
                      <span className="muted-line">{meta.goal}</span>
                    </div>
                    <span className={`pill ${state === "complete" ? "good" : state === "running" ? "warn" : state === "failed" ? "bad" : "neutral"}`}>{state}</span>
                  </div>
                  <div className="phase-tools">
                    {meta.tools === "internal"
                      ? <span className="muted-line">Internal phase — no target-touching tools.</span>
                      : meta.tools.map((tool) => <span key={tool} className="tool-chip">{tool}</span>)}
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}

      {tab === "diff" && (
        <section className="table-panel">
          <div className="panel-heading"><div><h2>Changes vs previous run</h2>
            <p>{diff?.has_baseline
              ? `${diff.new.length} new, ${diff.resolved.length} no longer observed, ${diff.persisting_count} persisting.`
              : "No previous run to compare — this run is the baseline."}</p></div></div>
          {diff?.has_baseline && (
            <div className="diff-grid">
              <div>
                <h3 className="diff-title diff-new">▲ New ({diff.new.length})</h3>
                <ul className="diff-list">
                  {diff.new.map((f) => <li key={f.finding_id}><span className={`severity-badge ${severityClass(f.severity)}`}>{f.severity ?? "info"}</span><span className="diff-item-title">{f.title}</span>{f.target && <span className="muted-line">{f.target}</span>}</li>)}
                  {diff.new.length === 0 && <li className="muted">Nothing new.</li>}
                </ul>
              </div>
              <div>
                <h3 className="diff-title diff-resolved">▼ No longer observed ({diff.resolved.length})</h3>
                <ul className="diff-list">
                  {diff.resolved.map((f) => <li key={f.finding_id}><span className={`severity-badge ${severityClass(f.severity)}`}>{f.severity ?? "info"}</span><span className="diff-item-title">{f.title}</span>{f.target && <span className="muted-line">{f.target}</span>}</li>)}
                  {diff.resolved.length === 0 && <li className="muted">Nothing resolved.</li>}
                </ul>
              </div>
            </div>
          )}
        </section>
      )}

      {tab === "agent" && (
        <section className="table-panel">
          <div className="panel-heading"><div><h2>Vector Agent steps</h2><p>Each iteration: the exact context sent to the model and its response. Click a step to expand.</p></div></div>
          <div className="agent-steps">
            {agentSteps.map((step, i) => (
              <AgentStepRow key={step.id} step={step} previous={agentSteps[i - 1]} expanded={expandedStep === step.id} onToggle={() => setExpandedStep(expandedStep === step.id ? null : step.id)} />
            ))}
            {agentSteps.length === 0 && <p className="empty-cell">No agent steps recorded. The Vector Agent did not run for this run (no LLM provider configured, agent disabled, or the run stopped before the agent phase).</p>}
          </div>
        </section>
      )}

      {tab === "activity" && (
        <RunActivity engagementId={id} run={run} entries={log} />
      )}
    </section>
  );
}

function AgentStepRow({ step, previous, expanded, onToggle }: {
  step: AgentStep; previous?: AgentStep; expanded: boolean; onToggle: () => void;
}) {
  const proposed = (step.response_tool_calls ?? []).map((t) => t.name).join(", ") || "—";
  // The backend stores request_messages as the FULL cumulative conversation
  // at that iteration (system + every prior turn) so the audit record is
  // complete - but rendering that in full for every step reprints the same
  // early messages over and over. request_messages is strictly append-only
  // across iterations, so slicing off what the previous step already showed
  // turns this into a normal, growing conversation transcript: step 1 shows
  // the full initial context once, every later step shows only its own new
  // turn(s).
  const newMessages = step.request_messages.slice(previous?.request_messages.length ?? 0);
  return (
    <div className={`agent-step ${expanded ? "expanded" : ""}`}>
      <button className="agent-step-head" onClick={onToggle}>
        <span className="agent-step-num">#{step.iteration}</span>
        <span className="agent-step-summary">{step.response_text?.slice(0, 120) || "(no text)"}</span>
        <span className="muted-line">proposed: {proposed} · {step.stop_reason ?? ""}</span>
      </button>
      {expanded && (
        <div className="agent-step-body">
          <h4>{previous ? "New context since the previous step" : "Input sent to the model"}</h4>
          <div className="agent-messages">
            {newMessages.map((m, i) => (
              <div key={i} className={`agent-msg role-${m.role}`}>
                <span className="agent-msg-role">{m.role}</span>
                <pre>{typeof m.content === "string" ? m.content : JSON.stringify(m, null, 2)}</pre>
              </div>
            ))}
            {newMessages.length === 0 && <p className="empty-cell">No new context - identical input to the previous step.</p>}
          </div>
          <h4>Model response</h4>
          <pre className="agent-response">{step.response_text || (
            step.response_tool_calls?.length
              ? "(the model returned no text; structured tool calls are shown below)"
              : step.stop_reason === "length"
                ? "(incomplete model response: output limit reached; no answer or tool calls)"
                : "(the model returned no answer or tool calls)"
          )}</pre>
          {step.response_tool_calls && step.response_tool_calls.length > 0 && (
            <>
              <h4>Proposed tool calls</h4>
              <ul className="diff-list">
                {step.response_tool_calls.map((t, i) => <li key={i}><span className="tool-chip">{t.name}</span><code>{t.arguments}</code></li>)}
              </ul>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function AssetReviewModal({ review, busy, onSubmit }: {
  review: AssetReview;
  busy: boolean;
  onSubmit: (excludedValues: string[]) => void;
}) {
  // Opt-out model (REQ-ASSETREVIEW-002): every candidate starts selected
  // ("keep"); the operator deselects the ones that should NOT proceed.
  const [selected, setSelected] = useState<Record<string, boolean>>(
    () => Object.fromEntries(review.candidate_assets.map((c) => [c.value, true])),
  );

  return (
    <div className="modal-overlay">
      <div className="modal-card">
        <div className="panel-heading">
          <div>
            <h2>Review discovered assets</h2>
            <p>
              Discovery found {review.candidate_assets.length} in-scope host(s). Deselect any that should NOT be
              scanned (e.g. stale DNS pointing outside your control) before the rest of the pipeline runs.
            </p>
          </div>
        </div>

        <div className="modal-body">
          <div className="responsive-table">
            {/* REQ-ASSETREVIEW-008: compact-table drops the shared 760px
                minimum so all three columns fit the modal without scrolling. */}
            <table className="data-table compact-table">
              <thead><tr><th></th><th>Value</th><th>Type</th></tr></thead>
              <tbody>
                {review.candidate_assets.map((c) => (
                  <tr key={c.value}>
                    <td>
                      <input
                        type="checkbox"
                        checked={selected[c.value] ?? true}
                        onChange={(e) => setSelected((prev) => ({ ...prev, [c.value]: e.target.checked }))}
                      />
                    </td>
                    <td>{c.value}</td>
                    <td>{c.asset_type}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="muted-line">
            Deselected hosts are added as a deny rule for this engagement (visible/removable under Edit engagement →
            Scope assets) and are excluded from this and future runs.
          </p>
        </div>

        <div className="form-actions">
          <button
            className="primary-action"
            disabled={busy}
            onClick={() => {
              const excluded = review.candidate_assets.filter((c) => !(selected[c.value] ?? true)).map((c) => c.value);
              onSubmit(excluded);
            }}
          >
            {busy ? "…" : "Continue with selected"}
          </button>
        </div>
      </div>
    </div>
  );
}
