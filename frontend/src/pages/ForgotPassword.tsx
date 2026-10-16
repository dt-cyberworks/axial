import { useState } from "react";
import { Link } from "react-router-dom";

import { api, ApiError } from "../api/client";
import AuthLayout from "../components/AuthLayout";

/**
 * REQ-IAM-020: ask for a reset link. The answer is the same whether or not the address
 * belongs to an account, so this page never says which it was.
 */
export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      await api.requestPasswordReset(email.trim());
      setSent(true);
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 429
          ? "Too many attempts from your network. Wait a few minutes, then try again."
          : "The request could not be sent. Try again in a moment.",
      );
    } finally {
      setBusy(false);
    }
  };

  if (sent) {
    return (
      <AuthLayout title="Check your e-mail" subtitle="If an account with that address can be reset, a message with a link is on its way.">
        <p className="muted-line">
          The link works once and expires in 30 minutes. You will need a code from your authenticator app to finish.
          If nothing arrives, ask an administrator to reset your password.
        </p>
        <p style={{ textAlign: "center" }}><Link to="/login">Back to sign in</Link></p>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout title="Forgot your password?" subtitle="Enter the e-mail address of your account. We will send a link if it can be reset.">
      <form onSubmit={submit}>
        <div className="auth-field">
          <label htmlFor="reset-email">Email</label>
          <input id="reset-email" type="email" autoFocus value={email} onChange={(e) => setEmail(e.target.value)} required />
        </div>
        {error && <div className="error-block">{error}</div>}
        <button type="submit" disabled={busy || !email.trim()} style={{ width: "100%" }}>
          {busy ? "Sending..." : "Send reset link"}
        </button>
      </form>
      <p style={{ textAlign: "center", marginTop: 12 }}><Link to="/login">Back to sign in</Link></p>
    </AuthLayout>
  );
}
