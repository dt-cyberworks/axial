import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { api, type CheckState, type OpenItem, type ScanPlan, type ScanPlanCheck, type ScanPlanSurface } from "../api/client";
import { openItemId } from "../lib/runReview";
import RunReview from "./RunReview";
import { scanDepthLabel } from "./ScanDepth";

// REQ-PIPE-010: what this run planned, per surface, and what became of each check.

const STATE_PILL: Record<CheckState, string> = {
  planned: "neutral", running: "warn", complete: "good", partial: "warn", failed: "bad", skipped: "neutral",
};

const CLASS_LABEL: Record<ScanPlanSurface["service_class"], string> = {
  web: "Web", web_alias: "Web (redirect only)", tls_service: "TLS service", service: "Service", unknown: "Unknown",
};

export function reasonText(reason: string): string {
  if (reason.startsWith("web_alias_of:")) return `Only redirects to ${reason.slice("web_alias_of:".length)}, which is scanned`;
  if (reason.startsWith("duplicate_vhost_of:")) return `Same site as ${reason.slice("duplicate_vhost_of:".length)}, scanned once there`;
  if (reason.startsWith("product:")) return `Templates for ${reason.slice("product:".length).split(",").join(", ")}`;
  if (reason.startsWith("gateway_denied:")) return `Refused by the Scope Gateway (${reason.slice("gateway_denied:".length)})`;
  const known: Record<string, string> = {
    web: "Web service", web_over_tls: "Web service over TLS", generic_web: "Generic web templates",
    "thorough:every_template": "Thorough depth: all non-intrusive web templates", "thorough:deep_content_discovery": "Thorough depth: deep sweep of about 30,000 likely paths", technology_profile: "Identify the technologies",
    switch_off: "Switched off for this engagement", tool_disabled: "Tool switched off in this engagement's tool list", switch_on: "Switched on for this engagement",
    "no_product_identified:common_products": "No product identified: templates of common web products",
    crawled_endpoints: "Test the crawled URLs that carry parameters", not_a_tls_service: "Plain HTTP, no TLS layer",
    not_a_web_service: "Not a web service", tls_service: "Encrypted service", oob_unavailable: "Interaction server not deployed: the callback templates did not run",
    no_endpoints: "The crawl found no URL with parameters", no_matching_templates: "No template matches",
    dependency_never_finished: "A check it depends on never finished", cancelled_by_operator: "Stopped by the operator",
    cancellation_status_unavailable: "Stopped as a safety measure: the cancel status could not be read",
    materialized_ip_missing: "The name has no DNS address, so nothing was sent to it",
    not_in_this_run: "Left out: this run only ran the checks that were chosen. It says nothing about this check",
  };
  return known[reason] ?? reason.replace(/[_:]+/g, " ");
}

function fmtSeconds(seconds: number | null): string {
  if (seconds == null) return "—";
  if (seconds < 90) return `${Math.round(seconds)} s`;
  return `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} s`;
}

function CheckRow({ check, rerun }: { check: ScanPlanCheck; rerun?: () => void }) {
  const templates = check.outcome_summary?.templates;
  const detail = typeof check.outcome_summary?.detail === "string" ? check.outcome_summary.detail : null;
  return (
    <tr className={`plan-check plan-${check.state}`}>
      <td>
        <code>{check.check_id}</code>
        {check.template_class && <span className="muted-line"> {check.template_class}</span>}
        {rerun && <button type="button" className="secondary-action plan-rerun" onClick={rerun}>Run this step again</button>}
      </td>
      <td><span className={`pill ${STATE_PILL[check.state]}`}>{check.state}</span></td>
      <td>{reasonText(check.reason)}{detail && check.state !== "complete" && <span className="muted-line"> · {detail.replace(/[_:]+/g, " ")}</span>}</td>
      <td>{typeof templates === "number" ? templates.toLocaleString() : "—"}</td>
      <td>{fmtSeconds(check.duration_s)}</td>
      <td>{check.findings > 0 ? check.findings : "—"}</td>
    </tr>
  );
}

function SurfaceBlock({ surface, openById, onRerun }: {
  surface: ScanPlanSurface; openById: Map<string, OpenItem>; onRerun: (item: OpenItem) => void;
}) {
  const [open, setOpen] = useState(surface.service_class === "web");
  const counts = surface.checks.reduce<Record<string, number>>((acc, c) => ({ ...acc, [c.state]: (acc[c.state] ?? 0) + 1 }), {});
  const tech = surface.profile.length ? surface.profile.join(", ") : "none identified";
  return (
    <div className="plan-surface">
      <button className="plan-surface-head" onClick={() => setOpen(!open)} aria-expanded={open}>
        <span className="plan-surface-title">
          <strong>{surface.host}:{surface.port}</strong>
          <span className="pill neutral">{CLASS_LABEL[surface.service_class]}</span>
        </span>
        <span className="muted-line">Technologies: {tech}</span>
        <span className="plan-counts">
          {(["complete", "partial", "failed", "running", "planned", "skipped"] as CheckState[])
            .filter((s) => counts[s]).map((s) => <span key={s} className={`pill ${STATE_PILL[s]}`}>{counts[s]} {s}</span>)}
        </span>
      </button>
      {surface.alias_of && <p className="muted-line">Alias of {surface.alias_of}: this port only redirects there.</p>}
      {open && (
        <div className="responsive-table">
          <table className="data-table">
            <thead><tr><th>Check</th><th>State</th><th>Why</th><th>Templates</th><th>Time</th><th>Findings</th></tr></thead>
            <tbody>{surface.checks.map((c) => {
              const item = openById.get(openItemId(surface.host, surface.port, c.check_id));
              return <CheckRow key={c.id} check={c} rerun={item ? () => onRerun(item) : undefined} />;
            })}</tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default function ScanPlanView({ plan, engagementId, runId, canManage = false }: {
  plan: ScanPlan | undefined; engagementId?: string; runId?: string; canManage?: boolean;
}) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [rerun, setRerun] = useState<OpenItem | null>(null);
  // REQ-RETEST-003: a step of THIS run that is still open (its latest result is not complete) can be run again.
  const openQuery = useQuery({
    queryKey: ["open-items", engagementId], queryFn: () => api.getOpenItems(engagementId!), enabled: !!engagementId && canManage,
  });
  const openById = new Map(
    (openQuery.data?.items ?? []).filter((i) => i.kind === "check" && (!runId || i.run_id === runId)).map((i) => [i.id, i] as const),
  );
  if (!plan || plan.surfaces.length === 0) {
    return (
      <section className="table-panel">
        <div className="panel-heading"><div><h2>Scan plan</h2>
          <p>The plan appears once the scan has found which ports are open and what runs on them.</p></div></div>
        <p className="empty-cell">No plan yet.</p>
      </section>
    );
  }
  const { by_state: by, checks } = plan.summary;
  const notClean = (by.partial ?? 0) + (by.failed ?? 0);
  const untested = plan.untested_hosts ?? [];
  const notRun = plan.not_run_classes ?? [];
  return (
    <section className="table-panel">
      <div className="panel-heading">
        <div>
          <h2>Scan plan</h2>
          <p>
            Scan depth: <strong>{scanDepthLabel(plan.scan_profile)}</strong> · {plan.summary.surfaces} services · {checks} checks
            ({by.complete ?? 0} complete, {by.partial ?? 0} partial, {by.failed ?? 0} failed, {by.skipped ?? 0} skipped,
            {" "}{(by.planned ?? 0) + (by.running ?? 0)} to do). Every check is still authorized by the Scope Gateway when it runs.
          </p>
        </div>
      </div>
      {notClean > 0 && (
        <div className="warning-block">
          {by.partial ?? 0} check(s) stopped at their time budget and {by.failed ?? 0} failed: a short findings list for those
          does not mean the service is clean.
        </div>
      )}
      {notRun.length > 0 && (
        <div className="warning-block" role="note" aria-label="Template classes not run">
          <strong>Out-of-band testing is on, but this installation has no interaction server, so these template classes did not run:</strong>
          <ul>
            {notRun.map((c) => <li key={c.label}>{c.label} (on {c.services} service{c.services === 1 ? "" : "s"})</li>)}
          </ul>
          Templates that do not need a callback are not affected. A short findings list does not mean the targets are free of blind vulnerabilities.
        </div>
      )}
      {untested.length > 0 && (
        <div className="warning-block" role="note" aria-label="Hosts not tested">
          <strong>{untested.length} host{untested.length === 1 ? " is" : "s are"} in scope but {untested.length === 1 ? "was" : "were"} not tested by this run:</strong>
          <ul>
            {untested.map((h) => <li key={h.host}><code>{h.host}</code>: {h.text}</li>)}
          </ul>
        </div>
      )}
      <div className="plan-surfaces">
        {plan.surfaces.map((s) => <SurfaceBlock key={s.id} surface={s} openById={openById} onRerun={setRerun} />)}
      </div>
      {rerun && engagementId && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Run this step again">
          <div className="modal-card">
            <RunReview
              engagementId={engagementId} items={[rerun]} canManage={canManage} onCancel={() => setRerun(null)}
              onStarted={(newRunId) => {
                queryClient.invalidateQueries({ queryKey: ["scan-runs", engagementId] });
                navigate(newRunId ? `/engagements/${engagementId}/runs/${newRunId}` : `/engagements/${engagementId}`);
              }}
            />
          </div>
        </div>
      )}
    </section>
  );
}
