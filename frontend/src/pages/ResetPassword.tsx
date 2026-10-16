import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { api, ApiError } from "../api/client";
import AuthLayout from "../components/AuthLayout";

/**
 * REQ-IAM-020: choose a new password with the link from the e-mail. The token is the URL
 * fragment, which a browser never sends to a server, so it is not in a request path, an
 * access log or a Referer header. It is removed from the address bar as soon as it is read.
 * The authenticator code is asked for here: a reset never touches the second factor.
 */
export default function ResetPassword() {
  const navigate = useNavigate();
  const [token, setToken] = useState("");
  const [password, setPassword] = useState("");
  const [again, setAgain] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  useEffect(() => {
    const fromFragment = window.location.hash.replace(/^#/, "").trim();
    if (fromFragment) {
      setToken(fromFragment);
      // Keep the token out of the address bar, history and any shared screenshot.
      window.history.replaceState(null, "", window.location.pathname);
    }
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (password !== again) {
      setError("The two passwords are not the same.");
      return;
    }
    setBusy(true);
    try {
      await api.completePasswordReset(token, password, code.trim());
      setDone(true);
      window.setTimeout(() => navigate("/login", { replace: true }), 2500);
    } catch (err) {
      const text = err instanceof ApiError ? err.message : "";
      if (/422/.test(text)) setError("Choose a password of at least 12 characters.");
      else if (/429/.test(text)) setError("Too many attempts from your network. Wait a few minutes, then try again.");
      else if (/code was not accepted/.test(text)) setError("That code was not accepted. Check your authenticator app and try again.");
      else setError("This link is invalid or has expired. Request a new one from the sign-in page.");
    } finally {
      setBusy(false);
    }
  };

  if (done) {
    return (
      <AuthLayout title="Password changed" subtitle="You can sign in with the new password and your authenticator now.">
        <p style={{ textAlign: "center" }}><Link to="/login">Go to sign in</Link></p>
      </AuthLayout>
    );
  }

  if (!token) {
    return (
      <AuthLayout title="This link is not complete" subtitle="Open the link from the e-mail exactly as it was sent, or request a new one.">
        <p style={{ textAlign: "center" }}><Link to="/forgot-password">Request a new link</Link></p>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout title="Choose a new password" subtitle="Enter a new password and a code from your authenticator app.">
      <form onSubmit={submit}>
        <div className="auth-field">
          <label htmlFor="reset-pw">New password (min. 12 characters)</label>
          <input id="reset-pw" type="password" autoFocus minLength={12} autoComplete="new-password"
            value={password} onChange={(e) => setPassword(e.target.value)} required />
        </div>
        <div className="auth-field">
          <label htmlFor="reset-pw2">Repeat the new password</label>
          <input id="reset-pw2" type="password" minLength={12} autoComplete="new-password"
            value={again} onChange={(e) => setAgain(e.target.value)} required />
        </div>
        <div className="auth-field">
          <label htmlFor="reset-code">Authenticator code (or a backup code)</label>
          <input id="reset-code" maxLength={11} autoComplete="one-time-code" value={code}
            onChange={(e) => setCode(e.target.value)} required />
        </div>
        {error && <div className="error-block">{error}</div>}
        <button type="submit" disabled={busy} style={{ width: "100%" }}>{busy ? "Saving..." : "Set new password"}</button>
      </form>
      <p className="muted-line" style={{ marginTop: 12 }}>
        Lost your authenticator as well? An administrator has to reset it for you; this link cannot.
      </p>
    </AuthLayout>
  );
}
