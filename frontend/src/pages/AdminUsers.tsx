import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { api } from "../api/client";

export default function AdminUsers() {
  const qc = useQueryClient();
  const { data: users = [] } = useQuery({ queryKey: ["admin-users"], queryFn: api.adminListUsers });

  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [role, setRole] = useState<"admin" | "operator">("operator");
  const [createdCreds, setCreatedCreds] = useState<{ email: string; temporary_password: string } | null>(null);
  const [resetCreds, setResetCreds] = useState<{ email: string; temporary_password: string } | null>(null);

  const createMutation = useMutation({
    mutationFn: () => api.adminCreateUser(email.trim(), displayName.trim(), role),
    onSuccess: (r) => {
      setCreatedCreds({ email: r.user.email, temporary_password: r.temporary_password });
      setEmail(""); setDisplayName(""); setRole("operator");
      qc.invalidateQueries({ queryKey: ["admin-users"] });
    },
  });
  const updateMutation = useMutation({
    mutationFn: (vars: { id: string; body: { role?: string; status?: string } }) => api.adminUpdateUser(vars.id, vars.body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin-users"] }),
  });
  const resetPasswordMutation = useMutation({
    mutationFn: (id: string) => api.adminResetPassword(id),
    onSuccess: (r, id) => {
      const user = users.find((u) => u.id === id);
      setResetCreds({ email: user?.email ?? "?", temporary_password: r.temporary_password });
    },
  });
  const resetMfaMutation = useMutation({ mutationFn: (id: string) => api.adminResetMfa(id) });

  return (
    <section className="page-stack">
      <header className="page-header">
        <div><span className="eyebrow">Admin</span><h1>Users</h1><p>Invite-only accounts — there is no public sign-up (REQ-IAM-008).</p></div>
      </header>

      <section className="form-panel settings-panel">
        <h2>Invite a new user</h2>
        <label>Email<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} /></label>
        <label>Display name<input value={displayName} onChange={(e) => setDisplayName(e.target.value)} /></label>
        <label>Role
          <select value={role} onChange={(e) => setRole(e.target.value as "admin" | "operator")}>
            <option value="operator">Operator</option>
            <option value="admin">Admin</option>
          </select>
        </label>
        <div className="form-actions">
          <button onClick={() => createMutation.mutate()} disabled={!email || !displayName || createMutation.isPending}>
            {createMutation.isPending ? "Creating..." : "Create account"}
          </button>
        </div>
        {createdCreds && (
          <div className="success-block">
            Account created for <strong>{createdCreds.email}</strong>. One-time temporary password
            (relay it out-of-band — it will not be shown again): <code>{createdCreds.temporary_password}</code>
          </div>
        )}
      </section>

      {resetCreds && (
        <div className="success-block">
          New temporary password for <strong>{resetCreds.email}</strong>: <code>{resetCreds.temporary_password}</code>
        </div>
      )}

      <section className="table-panel">
        <div className="panel-heading"><div><h2>All users</h2></div></div>
        <div className="responsive-table">
          <table className="data-table">
            <thead><tr><th>Email</th><th>Name</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td>{u.email}</td>
                  <td>{u.display_name}</td>
                  <td>
                    <select value={u.role} onChange={(e) => updateMutation.mutate({ id: u.id, body: { role: e.target.value } })}>
                      <option value="operator">operator</option>
                      <option value="admin">admin</option>
                    </select>
                  </td>
                  <td><span className={`pill ${u.status === "active" ? "good" : u.status === "disabled" ? "bad" : "neutral"}`}>{u.status}</span></td>
                  <td style={{ display: "flex", gap: 6 }}>
                    <button onClick={() => updateMutation.mutate({ id: u.id, body: { status: u.status === "disabled" ? "active" : "disabled" } })}>
                      {u.status === "disabled" ? "Enable" : "Disable"}
                    </button>
                    <button onClick={() => resetPasswordMutation.mutate(u.id)} disabled={resetPasswordMutation.isPending}>Reset password</button>
                    <button onClick={() => resetMfaMutation.mutate(u.id)} disabled={resetMfaMutation.isPending}>Reset MFA</button>
                  </td>
                </tr>
              ))}
              {users.length === 0 && <tr><td className="empty-cell" colSpan={5}>No users yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </section>
  );
}
