import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { api, type ChangeEvent } from "../api/client";
import { fmtTime } from "../lib/runs";

/** REQ-MODE-013: the plain-language name of each kind of change. */
const KIND_LABEL: Record<string, string> = {
  asset_new: "New asset",
  asset_gone: "Asset no longer seen",
  port_opened: "New open port",
  port_closed: "Port closed",
  service_changed: "Service changed",
  finding_new: "New finding",
  finding_resolved: "Finding fixed",
  finding_regressed: "Regression",
  target_degraded: "Target degraded",
};

/** What an event is, in one sentence an operator can act on. */
function eventNote(event: ChangeEvent): string | null {
  if (event.kind === "asset_new" && event.detail.held) return "Held: not tested until you release it.";
  if (event.kind === "service_changed") {
    const from = event.detail.from as { product?: string; version?: string } | undefined;
    const to = event.detail.to as { product?: string; version?: string } | undefined;
    return `${from?.product ?? "?"} ${from?.version ?? ""} → ${to?.product ?? "?"} ${to?.version ?? ""}`.replace(/\s+/g, " ");
  }
  if (event.kind === "port_opened" || event.kind === "port_closed") {
    const product = event.detail.product as string | undefined;
    return product ? String(product) : null;
  }
  return null;
}

function pillClass(event: ChangeEvent): string {
  if (event.kind === "finding_resolved" || event.kind === "asset_gone" || event.kind === "port_closed") return "good";
  if (event.severity === "critical" || event.severity === "high" || event.kind === "target_degraded") return "bad";
  if (event.kind === "finding_new" || event.kind === "finding_regressed") return "warn";
  return "neutral";
}

/**
 * REQ-MODE-013: what changed between healthy runs. The baseline is the last healthy
 * run, so a run that was cut short never reports things as "new" or "gone" that it
 * simply did not look at.
 */
export default function ChangesSection({ engagementId, compact = false }: { engagementId: string; compact?: boolean }) {
  const { data: events = [], isLoading, isError, error } = useQuery({
    queryKey: ["changes", engagementId, compact ? "recent" : "all"],
    queryFn: () => api.listChanges(engagementId, { limit: compact ? 6 : 200 }),
    refetchInterval: 15000,
  });

  return (
    <section className="table-panel" aria-label="Changes since the last healthy run">
      <div className="panel-heading">
        <div>
          <h2>{compact ? "What changed" : "Changes"}</h2>
          <p>
            Differences between healthy runs. A run that had reduced coverage never reports something as gone or
            fixed, and is never the baseline of the next comparison.
          </p>
        </div>
        {compact && events.length > 0 && <Link className="secondary-action" to={`/engagements/${engagementId}?tab=changes`}>All changes</Link>}
      </div>
      {isError && <div className="error-block">Could not load the changes: {(error as Error).message}</div>}
      <div className="responsive-table">
        <table className="data-table">
          <thead><tr><th>When</th><th>Change</th><th>What</th><th>Note</th>{!compact && <th>Run</th>}</tr></thead>
          <tbody>
            {events.map((event) => (
              <tr key={event.id}>
                <td>{fmtTime(event.created_at)}</td>
                <td><span className={`pill ${pillClass(event)}`}>{KIND_LABEL[event.kind] ?? event.kind}</span></td>
                <td>{event.subject}{event.severity && event.kind.startsWith("finding") ? <span className="muted-line"> {event.severity}</span> : null}</td>
                <td>{eventNote(event) ?? ""}</td>
                {!compact && (
                  <td>{event.scan_run_id ? <Link to={`/engagements/${engagementId}/runs/${event.scan_run_id}`}>run</Link> : ""}</td>
                )}
              </tr>
            ))}
            {!isLoading && events.length === 0 && (
              <tr>
                <td className="empty-cell" colSpan={compact ? 4 : 5}>
                  Nothing has changed yet. The first healthy run is the baseline and reports no changes; the next
                  one shows what is different.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
