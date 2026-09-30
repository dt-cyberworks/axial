import { useState } from "react";

import type { CheckState, ScanPlan, ScanPlanCheck, ScanPlanSurface } from "../api/client";
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
    "thorough:every_template": "Thorough depth: every template", technology_profile: "Identify the technologies",
    switch_off: "Switched off for this engagement", tool_disabled: "Tool switched off in this engagement's tool list", switch_on: "Switched on for this engagement",
    "no_product_identified:common_products": "No product identified: templates of common web products",
    crawled_endpoints: "Test the crawled URLs that carry parameters", not_a_tls_service: "Plain HTTP, no TLS layer",
    not_a_web_service: "Not a web service", tls_service: "Encrypted service", oob_unavailable: "Interaction server not deployed",
    no_endpoints: "The crawl found no URL with parameters", no_matching_templates: "No template matches",
    dependency_never_finished: "A check it depends on never finished", cancelled_by_operator: "Stopped by the operator",
    materialized_ip_missing: "The name did not resolve",
  };
  return known[reason] ?? reason.replace(/[_:]+/g, " ");
}

function fmtSeconds(seconds: number | null): string {
  if (seconds == null) return "—";
  if (seconds < 90) return `${Math.round(seconds)} s`;
  return `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} s`;
}

function CheckRow({ check }: { check: ScanPlanCheck }) {
  const templates = check.outcome_summary?.templates;
  const detail = typeof check.outcome_summary?.detail === "string" ? check.outcome_summary.detail : null;
  return (
    <tr className={`plan-check plan-${check.state}`}>
      <td><code>{check.check_id}</code></td>
      <td><span className={`pill ${STATE_PILL[check.state]}`}>{check.state}</span></td>
      <td>{reasonText(check.reason)}{detail && check.state !== "complete" && <span className="muted-line"> · {detail.replace(/[_:]+/g, " ")}</span>}</td>
      <td>{typeof templates === "number" ? templates.toLocaleString() : "—"}</td>
      <td>{fmtSeconds(check.duration_s)}</td>
      <td>{check.findings > 0 ? check.findings : "—"}</td>
    </tr>
  );
}

function SurfaceBlock({ surface }: { surface: ScanPlanSurface }) {
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
            <tbody>{surface.checks.map((c) => <CheckRow key={c.id} check={c} />)}</tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default function ScanPlanView({ plan }: { plan: ScanPlan | undefined }) {
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
      <div className="plan-surfaces">
        {plan.surfaces.map((s) => <SurfaceBlock key={s.id} surface={s} />)}
      </div>
    </section>
  );
}
