import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, type NotificationTarget } from "../api/client";
import { fmtTime } from "../lib/runs";

const SEVERITIES: NotificationTarget["min_severity"][] = ["critical", "high", "medium", "low", "info"];

/**
 * REQ-MON-002: where alerts go. A signed webhook in this version; the URL must be
 * https and public, and the secret is write-only (the API only says one is set).
 * An alert names what changed and links here: no evidence, no raw tool output.
 */
export default function NotificationTargets({ engagementId, canManage }: { engagementId: string; canManage: boolean }) {
  const queryClient = useQueryClient();
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [minSeverity, setMinSeverity] = useState<NotificationTarget["min_severity"]>("high");

  const { data: targets = [] } = useQuery({
    queryKey: ["notification-targets", engagementId],
    queryFn: () => api.listNotificationTargets(engagementId),
  });
  const { data: alerts = [] } = useQuery({
    queryKey: ["alerts", engagementId],
    queryFn: () => api.listAlerts(engagementId),
    refetchInterval: 30000,
  });

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["notification-targets", engagementId] });
    queryClient.invalidateQueries({ queryKey: ["alerts", engagementId] });
  };
  const add = useMutation({
    mutationFn: () => api.addNotificationTarget(engagementId, { url: url.trim(), secret: secret || undefined, min_severity: minSeverity }),
    onSuccess: () => { setUrl(""); setSecret(""); refresh(); },
  });
  const remove = useMutation({ mutationFn: (targetId: string) => api.deleteNotificationTarget(engagementId, targetId), onSuccess: refresh });

  return (
    <section className="table-panel" aria-label="Alerts">
      <div className="panel-heading">
        <div>
          <h2>Alerts</h2>
          <p>
            New assets and ports, new findings at or above the threshold, regressions, a degraded target, a run that
            did not finish, a monitor that went quiet, and an authorization that needs review. Critical and
            known-exploited findings are sent at once; the rest as a daily digest. Findings you triaged never alert.
          </p>
        </div>
      </div>
      <div className="responsive-table">
        <table className="data-table">
          <thead><tr><th>Webhook</th><th>Findings from</th><th>Signed</th><th></th></tr></thead>
          <tbody>
            {targets.map((t) => (
              <tr key={t.id}>
                <td>{t.url}</td>
                <td>{t.min_severity}</td>
                <td>{t.has_secret ? "yes (HMAC-SHA256)" : "no"}</td>
                <td>{canManage && <button className="secondary-action" disabled={remove.isPending} onClick={() => remove.mutate(t.id)}>Remove</button>}</td>
              </tr>
            ))}
            {targets.length === 0 && (
              <tr><td className="empty-cell" colSpan={4}>No webhook yet. Without one, changes are only visible in the console.</td></tr>
            )}
          </tbody>
        </table>
      </div>
      {canManage && (
        <div className="form-grid">
          <label>Webhook URL (https)
            <input value={url} placeholder="https://hooks.example.org/axial" onChange={(e) => setUrl(e.target.value)} />
          </label>
          <label>Signing secret (optional, never shown again)
            <input type="password" value={secret} autoComplete="new-password" onChange={(e) => setSecret(e.target.value)} />
          </label>
          <label>Findings from severity
            <select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value as NotificationTarget["min_severity"])}>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          <div className="form-actions">
            <button className="primary-action" disabled={!url.trim() || add.isPending} onClick={() => add.mutate()}>Add webhook</button>
          </div>
        </div>
      )}
      {add.isError && <div className="error-block">Could not add the webhook: {(add.error as Error).message}</div>}

      <h3>Recent alerts</h3>
      <div className="responsive-table">
        <table className="data-table">
          <thead><tr><th>Created</th><th>Alert</th><th>State</th><th>Attempts</th><th>Last error</th></tr></thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.id}>
                <td>{fmtTime(a.created_at)}</td>
                <td>{a.title ?? a.event}</td>
                <td><span className={`pill ${a.state === "delivered" ? "good" : a.state === "failed" ? "bad" : "neutral"}`}>{a.state}</span></td>
                <td>{a.attempts}</td>
                <td>{a.last_error ?? ""}</td>
              </tr>
            ))}
            {alerts.length === 0 && <tr><td className="empty-cell" colSpan={5}>No alert has been raised.</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  );
}
