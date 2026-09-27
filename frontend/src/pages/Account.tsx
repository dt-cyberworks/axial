import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import QRCode from "qrcode";

import { api, setSessionToken } from "../api/client";
import { useLogout } from "../lib/useLogout";

export default function Account() {
  const logout = useLogout();
  const qc = useQueryClient();
  const { data: me } = useQuery({ queryKey: ["me"], queryFn: api.me });
  const { data: sessions = [] } = useQuery({ queryKey: ["sessions"], queryFn: api.listSessions });

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [pwError, setPwError] = useState<string | null>(null);
  const [pwSuccess, setPwSuccess] = useState(false);

  const [reenrollPassword, setReenrollPassword] = useState("");
  const [reenroll, setReenroll] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState("");
  const [reenrollCode, setReenrollCode] = useState("");
  const [newBackupCodes, setNewBackupCodes] = useState<string[] | null>(null);
  const [mfaError, setMfaError] = useState<string | null>(null);

  useEffect(() => {
    if (reenroll) QRCode.toDataURL(reenroll.otpauth_uri, { width: 200 }).then(setQrDataUrl).catch(() => setQrDataUrl(""));
  }, [reenroll]);

  const changePasswordMutation = useMutation({
    mutationFn: () => api.changePassword(currentPassword, newPassword),
    // GitHub issue #26: this action revokes every other session and issues
    // this tab a fresh one - without picking up the new token here, the
    // next request would 401 on the now-revoked old one.
    onSuccess: (r) => {
      setSessionToken(r.session_token);
      setPwSuccess(true); setPwError(null); setCurrentPassword(""); setNewPassword("");
      qc.invalidateQueries({ queryKey: ["sessions"] });
    },
    onError: () => setPwError("Current password is incorrect, or the new one is too short (min. 12 characters)."),
  });

  const reenrollStartMutation = useMutation({
    mutationFn: () => api.mfaReenrollStart(reenrollPassword),
    onSuccess: (r) => { setReenroll(r); setMfaError(null); },
    onError: () => setMfaError("Incorrect password."),
  });

  const reenrollConfirmMutation = useMutation({
    mutationFn: () => api.mfaReenrollConfirm(reenrollCode),
    // GitHub issue #26: same reasoning as changePasswordMutation above.
    onSuccess: (r) => {
      setSessionToken(r.session_token);
      setNewBackupCodes(r.backup_codes); setReenroll(null); setMfaError(null);
      qc.invalidateQueries({ queryKey: ["sessions"] });
    },
    onError: () => setMfaError("Invalid code."),
  });

  const revokeMutation = useMutation({
    mutationFn: (id: string) => api.revokeSession(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["sessions"] }),
  });

  return (
    <section className="page-stack">
      <header className="page-header">
        <div><span className="eyebrow">Account</span><h1>{me?.display_name ?? "My account"}</h1><p>{me?.email} &middot; {me?.role}</p></div>
        <div className="header-actions"><button className="danger-button" onClick={logout}>Log out</button></div>
      </header>

      <section className="form-panel settings-panel">
        <h2>Change password</h2>
        <label>Current password
          <input type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} />
        </label>
        <label>New password (min. 12 characters)
          <input type="password" minLength={12} value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
        </label>
        {pwError && <div className="error-block">{pwError}</div>}
        {pwSuccess && <div className="success-block">Password changed.</div>}
        <div className="form-actions">
          <button onClick={() => changePasswordMutation.mutate()} disabled={!currentPassword || newPassword.length < 12 || changePasswordMutation.isPending}>
            {changePasswordMutation.isPending ? "Saving..." : "Change password"}
          </button>
        </div>
      </section>

      <section className="form-panel settings-panel">
        <h2>Two-factor authentication</h2>
        <div className="warning-block">Re-enrolling (e.g. new phone) replaces your current authenticator secret and backup codes immediately.</div>
        {newBackupCodes ? (
          <>
            <div className="success-block">MFA re-enrolled. Save these new backup codes — the old ones no longer work.</div>
            <div className="auth-backup-codes">{newBackupCodes.map((c) => <span key={c}>{c}</span>)}</div>
            <button onClick={() => setNewBackupCodes(null)}>Done</button>
          </>
        ) : reenroll ? (
          <>
            {qrDataUrl && <img src={qrDataUrl} alt="New MFA QR code" style={{ display: "block", margin: "0 auto 12px" }} />}
            <p className="muted-line" style={{ wordBreak: "break-all", textAlign: "center" }}>Manual entry: <code>{reenroll.secret}</code></p>
            <label>6-digit code
              <input inputMode="numeric" maxLength={6} value={reenrollCode} onChange={(e) => setReenrollCode(e.target.value)} />
            </label>
            {mfaError && <div className="error-block">{mfaError}</div>}
            <div className="form-actions">
              <button onClick={() => reenrollConfirmMutation.mutate()} disabled={reenrollCode.length < 6 || reenrollConfirmMutation.isPending}>Confirm</button>
              <button onClick={() => setReenroll(null)}>Cancel</button>
            </div>
          </>
        ) : (
          <>
            <label>Current password
              <input type="password" value={reenrollPassword} onChange={(e) => setReenrollPassword(e.target.value)} />
            </label>
            {mfaError && <div className="error-block">{mfaError}</div>}
            <div className="form-actions">
              <button onClick={() => reenrollStartMutation.mutate()} disabled={!reenrollPassword || reenrollStartMutation.isPending}>
                Re-enroll two-factor authentication
              </button>
            </div>
          </>
        )}
      </section>

      <section className="table-panel">
        <div className="panel-heading"><div><h2>Active sessions</h2><p>Devices/browsers currently signed in as you.</p></div></div>
        <div className="responsive-table">
          <table className="data-table">
            <thead><tr><th>Started</th><th>Last active</th><th>IP</th><th>Device</th><th></th></tr></thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={s.id}>
                  <td>{new Date(s.created_at).toLocaleString()}</td>
                  <td>{new Date(s.last_seen_at).toLocaleString()}</td>
                  <td>{s.ip_address ?? "-"}</td>
                  <td>{s.user_agent ?? "-"}{s.is_current && <span className="pill good" style={{ marginLeft: 6 }}>this device</span>}</td>
                  <td>{!s.is_current && <button onClick={() => revokeMutation.mutate(s.id)} disabled={revokeMutation.isPending}>Revoke</button>}</td>
                </tr>
              ))}
              {sessions.length === 0 && <tr><td className="empty-cell" colSpan={5}>No active sessions.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </section>
  );
}
