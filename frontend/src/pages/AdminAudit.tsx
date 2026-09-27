import { useQuery } from "@tanstack/react-query";

import { api } from "../api/client";

export default function AdminAudit() {
  const { data: rows = [] } = useQuery({ queryKey: ["admin-audit"], queryFn: () => api.adminListAudit(200) });

  return (
    <section className="page-stack">
      <header className="page-header">
        <div><span className="eyebrow">Admin</span><h1>Account audit</h1><p>Tamper-evident, hash-chained security trail (REQ-IAM-009): logins, MFA, sessions, and admin actions.</p></div>
      </header>
      <section className="table-panel">
        <div className="responsive-table">
          <table className="data-table">
            <thead><tr><th>Time</th><th>Action</th><th>Outcome</th><th>Actor</th><th>IP</th><th>Details</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td>{new Date(r.ts).toLocaleString()}</td>
                  <td>{r.action}</td>
                  <td><span className={`pill ${r.outcome === "success" ? "good" : "bad"}`}>{r.outcome}</span></td>
                  <td>{r.actor_user_id ?? "-"}</td>
                  <td>{r.ip_address ?? "-"}</td>
                  <td>{Object.keys(r.payload).length ? JSON.stringify(r.payload) : "-"}</td>
                </tr>
              ))}
              {rows.length === 0 && <tr><td className="empty-cell" colSpan={6}>No events yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </section>
  );
}
