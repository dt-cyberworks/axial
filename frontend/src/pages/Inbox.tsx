import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { api, type InboxEntry } from "../api/client";
import { fmtTime } from "../lib/runs";

const KIND_LABEL: Record<string, string> = {
  approval: "Approval needed",
  asset_review: "Review needed",
  held_asset: "Held host",
  suggestion: "Suggested manual test",
  run_degraded: "Reduced coverage",
  run_failed: "Run did not finish",
  missed_run: "Monitor went quiet",
  authorization_expiring: "Authorization review",
  schedule_stopped: "Schedule stopped",
  schedule_blocked: "Run could not start",
  target_degraded: "Target degraded",
  run_needs_you: "A run is waiting for you",
};

/**
 * REQ-MODE-014: everything that needs a person, in one list. A monitor never waits
 * for anyone during a run; what it could not decide for itself ends up here.
 */
export default function Inbox() {
  const queryClient = useQueryClient();
  const { data: entries = [], isLoading, isError, error } = useQuery({
    queryKey: ["inbox"], queryFn: api.listInbox, refetchInterval: 15000,
  });
  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["inbox"] });
    queryClient.invalidateQueries({ queryKey: ["inbox-count"] });
  };
  const acknowledge = useMutation({ mutationFn: (entry: InboxEntry) => api.acknowledgeInboxItem(entry.id), onSuccess: refresh });
  const releaseAll = useMutation({ mutationFn: (engagementId: string) => api.releaseHeldAssets(engagementId), onSuccess: refresh });

  const heldByEngagement = new Map<string, { title: string; count: number }>();
  for (const e of entries) {
    if (e.kind !== "held_asset") continue;
    const current = heldByEngagement.get(e.engagement_id) ?? { title: e.engagement_title, count: 0 };
    heldByEngagement.set(e.engagement_id, { ...current, count: current.count + 1 });
  }

  return (
    <section className="page-stack">
      <header className="page-header">
        <div>
          <span className="eyebrow">Needs you</span>
          <h1>Inbox</h1>
          <p>Across the engagements you own. Administrators see all.</p>
        </div>
      </header>

      {isError && <div className="error-block">Could not load the inbox: {(error as Error).message}</div>}
      {acknowledge.isError && <div className="error-block">{(acknowledge.error as Error).message}</div>}

      {[...heldByEngagement.entries()].filter(([, v]) => v.count > 1).map(([engagementId, v]) => (
        <section key={engagementId} className="form-panel settings-panel">
          <p>{v.count} hosts of <strong>{v.title}</strong> are held until you release them.</p>
          <div className="form-actions">
            <button className="primary-action" disabled={releaseAll.isPending} onClick={() => releaseAll.mutate(engagementId)}>
              Release all {v.count}
            </button>
          </div>
        </section>
      ))}

      <section className="table-panel">
        <div className="responsive-table">
          <table className="data-table">
            <thead><tr><th>What</th><th>Engagement</th><th>Since</th><th></th></tr></thead>
            <tbody>
              {entries.map((entry) => (
                <tr key={`${entry.source}-${entry.id}`}>
                  <td>
                    <span className="pill neutral">{KIND_LABEL[entry.kind] ?? entry.kind}</span>{" "}
                    {entry.summary}
                  </td>
                  <td><Link to={entry.link}>{entry.engagement_title}</Link></td>
                  <td>{fmtTime(entry.created_at)}</td>
                  <td>
                    {entry.can_acknowledge ? (
                      <button className="secondary-action" disabled={acknowledge.isPending} onClick={() => acknowledge.mutate(entry)}>
                        {entry.kind === "held_asset" ? "Release" : "Acknowledge"}
                      </button>
                    ) : (
                      <Link className="secondary-action" to={entry.link}>Open</Link>
                    )}
                  </td>
                </tr>
              ))}
              {!isLoading && entries.length === 0 && (
                <tr><td className="empty-cell" colSpan={4}>Nothing needs you. A monitor reports here what it could not decide for itself.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </section>
  );
}
