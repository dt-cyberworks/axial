import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import QRCode from "qrcode";

import { api, setSessionToken } from "../api/client";
import AuthLayout from "../components/AuthLayout";

type Step =
  | { name: "password" }
  | { name: "set_password"; challengeId: string }
  | { name: "mfa_enroll"; challengeId: string; secret: string; otpauthUri: string }
  | { name: "mfa_verify"; challengeId: string }
  | { name: "backup_codes"; codes: string[] };

export default function Login() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const next = params.get("next") || "/";

  const [step, setStep] = useState<Step>({ name: "password" });
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [code, setCode] = useState("");
  const [qrDataUrl, setQrDataUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (step.name === "mfa_enroll") {
      QRCode.toDataURL(step.otpauthUri, { width: 200 }).then(setQrDataUrl).catch(() => setQrDataUrl(""));
    }
  }, [step]);

  const finishWithSession = (token: string, backupCodes?: string[] | null) => {
    setSessionToken(token);
    if (backupCodes && backupCodes.length) {
      setStep({ name: "backup_codes", codes: backupCodes });
    } else {
      navigate(next, { replace: true });
    }
  };

  const submitPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      const challenge = await api.login(email.trim(), password);
      if (challenge.status === "set_password") {
        setStep({ name: "set_password", challengeId: challenge.challenge_id });
      } else if (challenge.status === "mfa_enroll") {
        const enroll = await api.mfaEnroll(challenge.challenge_id);
        setStep({ name: "mfa_enroll", challengeId: challenge.challenge_id, secret: enroll.secret, otpauthUri: enroll.otpauth_uri });
      } else {
        setStep({ name: "mfa_verify", challengeId: challenge.challenge_id });
      }
    } catch {
      setError("Invalid email or password.");
    } finally {
      setBusy(false);
    }
  };

  const submitNewPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (step.name !== "set_password") return;
    setBusy(true); setError(null);
    try {
      const challenge = await api.setFirstPassword(step.challengeId, newPassword);
      if (challenge.status === "mfa_enroll") {
        const enroll = await api.mfaEnroll(challenge.challenge_id);
        setStep({ name: "mfa_enroll", challengeId: challenge.challenge_id, secret: enroll.secret, otpauthUri: enroll.otpauth_uri });
      } else {
        setStep({ name: "mfa_verify", challengeId: challenge.challenge_id });
      }
    } catch {
      setError("Could not set that password (must be at least 12 characters).");
    } finally {
      setBusy(false);
    }
  };

  const submitEnrollConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    if (step.name !== "mfa_enroll") return;
    setBusy(true); setError(null);
    try {
      const result = await api.mfaEnrollConfirm(step.challengeId, code);
      finishWithSession(result.session_token, result.backup_codes);
    } catch {
      setError("Invalid code. Check your authenticator app and try again.");
    } finally {
      setBusy(false);
    }
  };

  const submitMfaVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (step.name !== "mfa_verify") return;
    setBusy(true); setError(null);
    try {
      const result = await api.loginMfa(step.challengeId, code);
      finishWithSession(result.session_token);
    } catch {
      setError("Invalid code.");
    } finally {
      setBusy(false);
    }
  };

  if (step.name === "password") {
    return (
      <AuthLayout title="Sign in" subtitle="Axial — Attack Surface Management console">
        <form onSubmit={submitPassword}>
          <div className="auth-field">
            <label htmlFor="email">Email</label>
            <input id="email" type="email" autoFocus value={email} onChange={(e) => setEmail(e.target.value)} required />
          </div>
          <div className="auth-field">
            <label htmlFor="password">Password</label>
            <input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </div>
          {error && <div className="error-block">{error}</div>}
          <button type="submit" disabled={busy} style={{ width: "100%" }}>{busy ? "Signing in..." : "Continue"}</button>
        </form>
      </AuthLayout>
    );
  }

  if (step.name === "set_password") {
    return (
      <AuthLayout title="Set your password" subtitle="This is your first sign-in — replace the temporary password.">
        <form onSubmit={submitNewPassword}>
          <div className="auth-field">
            <label htmlFor="newpw">New password (min. 12 characters)</label>
            <input id="newpw" type="password" autoFocus minLength={12} value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required />
          </div>
          {error && <div className="error-block">{error}</div>}
          <button type="submit" disabled={busy} style={{ width: "100%" }}>{busy ? "Saving..." : "Continue"}</button>
        </form>
      </AuthLayout>
    );
  }

  if (step.name === "mfa_enroll") {
    return (
      <AuthLayout title="Set up two-factor authentication" subtitle="Scan with Google Authenticator, 1Password, Authy, or any TOTP app.">
        {qrDataUrl && <img src={qrDataUrl} alt="MFA QR code" style={{ display: "block", margin: "0 auto 12px" }} />}
        <p className="muted-line" style={{ wordBreak: "break-all", textAlign: "center" }}>
          Can't scan? Enter manually: <code>{step.secret}</code>
        </p>
        <form onSubmit={submitEnrollConfirm}>
          <div className="auth-field">
            <label htmlFor="enrollcode">6-digit code</label>
            <input id="enrollcode" inputMode="numeric" autoFocus maxLength={6} value={code} onChange={(e) => setCode(e.target.value)} required />
          </div>
          {error && <div className="error-block">{error}</div>}
          <button type="submit" disabled={busy} style={{ width: "100%" }}>{busy ? "Confirming..." : "Confirm and sign in"}</button>
        </form>
      </AuthLayout>
    );
  }

  if (step.name === "mfa_verify") {
    return (
      <AuthLayout title="Enter your authentication code" subtitle="From your authenticator app, or a backup code.">
        <form onSubmit={submitMfaVerify}>
          <div className="auth-field">
            <label htmlFor="code">Code</label>
            <input id="code" autoFocus maxLength={11} value={code} onChange={(e) => setCode(e.target.value)} required />
          </div>
          {error && <div className="error-block">{error}</div>}
          <button type="submit" disabled={busy} style={{ width: "100%" }}>{busy ? "Verifying..." : "Sign in"}</button>
        </form>
      </AuthLayout>
    );
  }

  // backup_codes
  return (
    <AuthLayout title="Save your backup codes" subtitle="Each code works once, if you lose access to your authenticator. Store them somewhere safe — they won't be shown again.">
      <div className="auth-backup-codes">
        {step.codes.map((c) => <span key={c}>{c}</span>)}
      </div>
      <button onClick={() => navigate(next, { replace: true })} style={{ width: "100%" }}>I've saved these codes — continue</button>
    </AuthLayout>
  );
}
