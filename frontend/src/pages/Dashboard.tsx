import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";

import { api, type Engagement } from "../api/client";

const STATUS_LABEL: Record<string, string> = {
  draft: "Draft",
  awaiting_signature: "Awaiting signature",
  active: "Active",
  paused: "Paused",
  completed: "Completed",
  revoked: "Revoked",
};

function statusClass(status: string) {
  if (status === "active") return "good";
  if (status === "paused" || status === "awaiting_signature") return "warn";
  if (status === "revoked") return "bad";
  return "neutral";
}

function formatWindow(e: Engagement) {
  const from = new Date(e.authorized_from).toLocaleDateString();
  const until = new Date(e.authorized_until).toLocaleDateString();
  return `${from} to ${until}`;
}

export default function Dashboard() {
  const queryClient = useQueryClient();
  const { data: engagements = [], isLoading, error } = useQuery({
    queryKey: ["engagements"],
    queryFn: api.listEngagements,
    refetchInterval: 5000,
  });

  const { data: me } = useQuery({ queryKey: ["me"], queryFn: api.me, retry: false });
  // REQ-IAM-025: every engagement is listed; "Only mine" narrows it (and the numbers above it) to the user's own.
  const [onlyMine, setOnlyMine] = useState(false);

  const deleteEngagement = useMutation({
    mutationFn: (id: string) => api.deleteEngagement(id),
    onSuccess: (_result, deletedId) => {
      queryClient.setQueryData<Engagement[]>(["engagements"], (current = []) =>
        current.filter((engagement) => engagement.id !== deletedId),
      );
      queryClient.removeQueries({ queryKey: ["engagement", deletedId] });
      queryClient.removeQueries({ queryKey: ["scan-runs", deletedId] });
      queryClient.invalidateQueries({ queryKey: ["engagements"] });
    },
  });

  if (isLoading) return <div className="loading-block">Loading engagements...</div>;
  if (error) return <div className="error-block">Failed to load engagements: {(error as Error).message}</div>;

  function requestDelete(e: Engagement) {
    const confirmed = window.confirm(`Delete engagement "${e.title}"? This removes its scope, scan runs, approvals, assets, services, and findings. Audit entries are retained.`);
    if (confirmed) deleteEngagement.mutate(e.id);
  }

  const shown = onlyMine ? engagements.filter((e) => e.owner_user_id === me?.id) : engagements;
  const active = shown.filter((e) => e.status === "active").length;
  const agentReady = shown.filter((e) => e.ai_testing_allowed).length;
  const drafts = shown.filter((e) => e.status === "draft" || e.status === "awaiting_signature").length;

  return (
    <section className="page-stack">
      <header className="page-header">
        <div>
          <span className="eyebrow">Attack surface management</span>
          <h1>Operator overview</h1>
        </div>
        <Link to="/new" className="primary-action">New engagement</Link>
      </header>

      <div className="metric-strip">
        <div className="metric-cell">
          <span>Engagements</span>
          <strong>{shown.length}</strong>
        </div>
        <div className="metric-cell">
          <span>Active scans</span>
          <strong>{active}</strong>
        </div>
        <div className="metric-cell">
          <span>Agent armed</span>
          <strong>{agentReady}</strong>
        </div>
        <div className="metric-cell">
          <span>Needs setup</span>
          <strong>{drafts}</strong>
        </div>
      </div>

      {deleteEngagement.isError && <div className="error-block">Delete failed: {(deleteEngagement.error as Error).message}</div>}

      {/* REQ-CONSOLE-010: a first-time user learns what an engagement is and what to do first. */}
      {engagements.length === 0 && (
        <section className="form-panel onboarding-panel">
          <h2>Start with your first engagement</h2>
          <p>
            An engagement is one authorized assessment: what you may test (the scope), when (the test window), and
            with which tools. Nothing is scanned until you have authorized and activated it.
          </p>
          <ol>
            <li><strong>Create a draft</strong> — a title and the test window.</li>
            <li><strong>Define the scope</strong> — the domains, hosts, or IP ranges you are allowed to test.</li>
            <li><strong>Authorize and activate</strong>, then start a scan run and work through the findings.</li>
          </ol>
          <div className="form-actions"><Link className="primary-action" to="/new">Create an engagement</Link></div>
        </section>
      )}

      <section className="table-panel">
        <div className="panel-heading">
          <div>
            <h2>Engagement queue</h2>
            <p>Every engagement in this installation. You can read all of them; only an engagement's owner or an administrator can change it.</p>
          </div>
          <label className="checkbox-filter">
            <input type="checkbox" checked={onlyMine} onChange={(e) => setOnlyMine(e.target.checked)} />
            Only mine
          </label>
        </div>
        <div className="responsive-table">
          <table className="data-table">
            <thead>
              <tr>
                <th>Engagement</th>
                <th>Owner</th>
                <th>Status</th>
                <th>Agent</th>
                <th>Authorized window</th>
                <th>Views</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((e) => (
                <tr key={e.id}>
                  <td>
                    <strong>{e.title}</strong>
                    <span className="muted-line">{e.id}</span>
                  </td>
                  <td title={e.owner_email ?? undefined}>{e.owner_name ?? "-"}</td>
                  <td><span className={`pill ${statusClass(e.status)}`}>{STATUS_LABEL[e.status] ?? e.status}</span></td>
                  <td><span className={`pill ${e.ai_testing_allowed ? "good" : "neutral"}`}>{e.ai_testing_allowed ? "Enabled" : "Disabled"}</span></td>
                  <td>{formatWindow(e)}</td>
                  <td className="row-actions">
                    <Link to={`/engagements/${e.id}`} className="primary-action">Open</Link>
                    {e.can_manage && <Link to={`/engagements/${e.id}/edit`}>Edit</Link>}
                    <Link to={`/engagements/${e.id}/audit`}>Audit</Link>
                    {e.can_manage && <button className="danger-button" onClick={() => requestDelete(e)} disabled={deleteEngagement.isPending}>Delete</button>}
                  </td>
                </tr>
              ))}
              {shown.length === 0 && (
                <tr><td colSpan={6} className="empty-cell">{onlyMine ? "You do not own an engagement yet." : "No engagements yet — create one above."}</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </section>
  );
}
