import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { type ScanRun } from "../api/client";
import {
  type HumanActivity,
  type RunLogEntry,
  phaseForEntry,
  scopeEntriesToRun,
  summarizeRun,
  translateActivity,
} from "../lib/runActivity";
import {
  PHASE_COPY,
  PHASE_META,
  PHASES,
  type PhaseId,
  phaseStateFor,
} from "../lib/runs";

interface RunActivityProps {
  engagementId: string;
  run?: ScanRun;
  entries: RunLogEntry[];
}

interface PhaseRow {
  phase: PhaseId;
  events: HumanActivity[];
  allowed: number;
  denied: number;
  approvals: number;
  throttled: number;
}

function isPhase(value: string | undefined): value is PhaseId {
  return Boolean(value && PHASES.includes(value as PhaseId));
}

function outcomePill(tone: HumanActivity["tone"]): string {
  if (tone === "success") return "good";
  if (tone === "danger") return "bad";
  if (tone === "attention") return "warn";
  return "neutral";
}

function statePill(state: ReturnType<typeof phaseStateFor>): string {
  if (state === "complete") return "good";
  if (state === "running") return "warn";
  if (state === "failed") return "bad";
  return "neutral";
}

export default function RunActivity({ engagementId, run, entries }: RunActivityProps) {
  const [showRoutine, setShowRoutine] = useState(false);
  const [expandedPhases, setExpandedPhases] = useState<Set<PhaseId>>(new Set());
  const fallbackPhase = isPhase(run?.phase) ? run.phase : "report";

  const scopedEntries = useMemo(
    () => scopeEntriesToRun(entries, run),
    [entries, run],
  );
  const activities = useMemo(
    () => scopedEntries.map((entry) => translateActivity(entry, fallbackPhase)),
    [fallbackPhase, scopedEntries],
  );
  const summary = useMemo(() => summarizeRun(run, activities), [activities, run]);
  const emphasizedPhaseKey = useMemo(() => {
    const phases = new Set<PhaseId>();
    activities
      .filter((activity) => activity.countsAsAttention || activity.countsAsBlocked)
      .forEach((activity) => phases.add(activity.phase));
    const latestRelevant = [...activities].reverse().find((activity) => !activity.routine);
    if (latestRelevant) phases.add(latestRelevant.phase);
    return [...phases].join("|");
  }, [activities]);

  const rows = useMemo<PhaseRow[]>(() => PHASES.map((phase) => {
    const phaseEntries = scopedEntries.filter((entry) => phaseForEntry(entry, fallbackPhase) === phase);
    const events = activities.filter((activity) => activity.phase === phase);
    return {
      phase,
      events,
      allowed: phaseEntries.filter((entry) => entry.action === "tool_call" && entry.decision === "ALLOW").length,
      denied: events.filter((event) => event.countsAsBlocked).length,
      approvals: phaseEntries.filter(
        (entry) => entry.decision === "PENDING" || ["approval", "approval_execution"].includes(entry.action),
      ).length,
      throttled: phaseEntries.filter((entry) => entry.decision === "THROTTLE").length,
    };
  }), [activities, fallbackPhase, scopedEntries]);

  useEffect(() => {
    if (!run?.id) return;
    const current = isPhase(run.phase) ? run.phase : "report";
    setExpandedPhases(new Set([current]));
  }, [run?.id]);

  useEffect(() => {
    if (!isPhase(run?.phase)) return;
    setExpandedPhases((previous) => {
      if (previous.has(run.phase as PhaseId)) return previous;
      const next = new Set(previous);
      next.add(run.phase as PhaseId);
      return next;
    });
  }, [run?.phase]);

  useEffect(() => {
    const emphasizedPhases = emphasizedPhaseKey.split("|").filter(isPhase);
    if (!emphasizedPhases.length) return;
    setExpandedPhases((previous) => {
      const next = new Set(previous);
      emphasizedPhases.forEach((phase) => next.add(phase));
      return next.size === previous.size ? previous : next;
    });
  }, [emphasizedPhaseKey, run?.id]);

  function togglePhase(phase: PhaseId) {
    setExpandedPhases((previous) => {
      const next = new Set(previous);
      if (next.has(phase)) next.delete(phase);
      else next.add(phase);
      return next;
    });
  }

  return (
    <section className="run-activity-layout" aria-labelledby="run-activity-title">
      <section className={`run-activity-overview ${run?.state === "failed" ? "danger" : run?.state === "waiting_approval" ? "attention" : ""}`}>
        <div className="run-activity-summary">
          <span className="eyebrow">Operator summary</span>
          <h2 id="run-activity-title">{summary.headline}</h2>
          <p>{summary.detail}</p>
          <div className="activity-legend" aria-label="Outcome meaning">
            <span><i className="legend-dot complete" />Completed = tool result received</span>
            <span><i className="legend-dot authorized" />Authorized = permission only</span>
            <span><i className="legend-dot blocked" />Blocked = nothing sent</span>
          </div>
        </div>
        <Link to={`/engagements/${engagementId}/audit`} className="secondary-action">View full audit evidence</Link>
      </section>

      <section className="activity-metric-strip" aria-label="Run activity summary">
        <div>
          <span>Tool executions completed</span>
          <strong>{summary.completedTools}</strong>
          <small>Terminal results, not authorizations</small>
        </div>
        <div>
          <span>Services discovered</span>
          <strong>{summary.discoveredServices}</strong>
          <small>Recorded by successful tool steps</small>
        </div>
        <div>
          <span>Actions safely blocked</span>
          <strong>{summary.blockedActions}</strong>
          <small>No target traffic was sent</small>
        </div>
        <div className={summary.attentionItems ? "needs-attention" : ""}>
          <span>Needs attention</span>
          <strong>{summary.attentionItems}</strong>
          <small>Failures or incomplete results</small>
        </div>
      </section>

      <section className="table-panel progress-tree-panel">
        <div className="panel-heading activity-panel-heading">
          <div>
            <h2>Activity by scan phase</h2>
            <p>Expand a phase to see human-readable results and how evidence moves to the next step.</p>
          </div>
          <label className="routine-toggle">
            <input
              type="checkbox"
              checked={showRoutine}
              onChange={(event) => setShowRoutine(event.target.checked)}
            />
            Show routine checks
          </label>
        </div>

        <div className="progress-tree">
          {rows.map((row, index) => {
            const meta = PHASE_META[row.phase];
            const copy = PHASE_COPY[row.phase];
            const state = phaseStateFor(run, row.phase, index);
            const expanded = expandedPhases.has(row.phase);
            const visibleEvents = showRoutine ? row.events : row.events.filter((event) => !event.routine);
            const recentEvents = visibleEvents.slice(-12).reverse();
            const hiddenCount = Math.max(0, visibleEvents.length - recentEvents.length);

            return (
              <article key={row.phase} className={`progress-node ${state}`}>
                <button
                  type="button"
                  className="progress-node-header"
                  aria-expanded={expanded}
                  aria-controls={`phase-${row.phase}-activity`}
                  onClick={() => togglePhase(row.phase)}
                >
                  <span className="progress-chevron" aria-hidden="true">{expanded ? "−" : "+"}</span>
                  <span className="progress-dot" aria-hidden="true" />
                  <span className="progress-title">
                    <strong>{meta.label}</strong>
                    <small>{meta.goal}</small>
                  </span>
                  <span className="progress-counts" aria-label={`${meta.label} event counts`}>
                    <span>{row.events.length} event{row.events.length === 1 ? "" : "s"}</span>
                    {row.allowed > 0 && <span>{row.allowed} authorized</span>}
                    {row.denied > 0 && <span className="bad-text">{row.denied} blocked</span>}
                    {row.approvals > 0 && <span>{row.approvals} approval{row.approvals === 1 ? "" : "s"}</span>}
                    {row.throttled > 0 && <span>{row.throttled} paused</span>}
                  </span>
                  <span className={`pill ${statePill(state)}`}>{state}</span>
                </button>

                {expanded && (
                  <div id={`phase-${row.phase}-activity`} className="progress-node-body">
                    <div className="phase-handoff">
                      <div><span>Uses</span><strong>{copy.uses}</strong></div>
                      <div><span>Produces</span><strong>{copy.produces}</strong></div>
                      <div>
                        <span>Next step</span>
                        <strong>{copy.next ?? "Final output — no downstream phase"}</strong>
                      </div>
                    </div>

                    <div className="progress-events">
                      {hiddenCount > 0 && (
                        <div className="progress-event muted-event">
                          {hiddenCount} older event{hiddenCount === 1 ? " is" : "s are"} hidden to keep this view responsive.
                        </div>
                      )}
                      {recentEvents.map((activity) => (
                        <HumanActivityRow key={activity.id} activity={activity} />
                      ))}
                      {recentEvents.length === 0 && (
                        <div className="progress-event empty-progress-event">
                          {row.events.length && !showRoutine
                            ? "Only routine checks were recorded. Enable “Show routine checks” to inspect them."
                            : state === "pending"
                              ? "This phase has not started."
                              : "No operator-relevant activity was recorded for this phase."}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </article>
            );
          })}
        </div>
      </section>
    </section>
  );
}

function HumanActivityRow({ activity }: { activity: HumanActivity }) {
  const hasDetails = Boolean(
    activity.facts.length || activity.reasonCode || activity.errorSummary || activity.source || activity.rawDetail,
  );
  return (
    <article className={`human-activity-event ${activity.tone}`}>
      <time dateTime={activity.ts}>{new Date(activity.ts).toLocaleTimeString()}</time>
      <div className="human-activity-main">
        <div className="human-activity-title">
          <strong>{activity.title}</strong>
          <span className={`pill ${outcomePill(activity.tone)}`}>{activity.outcome}</span>
        </div>
        <p>{activity.summary}</p>
        {(activity.tool || activity.target) && (
          <div className="activity-chips">
            {activity.tool && <span className="tool-chip">{activity.tool}</span>}
            {activity.target && <span className="target-chip">{activity.target}</span>}
            {activity.routine && <span className="routine-chip">Routine</span>}
          </div>
        )}
        {hasDetails && (
          <details className="activity-details">
            <summary>Technical details</summary>
            {activity.facts.length > 0 && (
              <dl className="activity-facts">
                {activity.facts.map((fact, index) => (
                  <div key={`${fact.label}-${index}`}>
                    <dt>{fact.label}</dt>
                    <dd>{fact.value}</dd>
                  </div>
                ))}
              </dl>
            )}
            <div className="activity-technical-meta">
              <span>Source: {activity.source}</span>
              {activity.reasonCode && <span>Reason code: <code>{activity.reasonCode}</code></span>}
              {activity.decision && <span>Audit decision: {activity.decision}</span>}
            </div>
            {activity.errorSummary && <pre className="activity-error-summary">{activity.errorSummary}</pre>}
            {activity.rawDetail && (
              <div className="activity-raw-detail">
                <span>Full response (secret values redacted)</span>
                <pre>{activity.rawDetail}</pre>
              </div>
            )}
          </details>
        )}
      </div>
    </article>
  );
}

