import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "../api/client";

/**
 * REQ-MAIL-002/004 (GitHub issue #45): the outbound e-mail relay. Off by default; with it
 * off, nothing that needs e-mail is offered anywhere and the administrator's own reset keeps
 * working. The password is write-only: the field stays empty to keep the stored one.
 */
export default function MailSettingsPanel() {
  const queryClient = useQueryClient();
  const { data } = useQuery({ queryKey: ["mail-config"], queryFn: api.getMailConfig, refetchInterval: 15000 });
  const [enabled, setEnabled] = useState(false);
  const [host, setHost] = useState("");
  const [port, setPort] = useState(587);
  const [security, setSecurity] = useState<"starttls" | "tls">("starttls");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [fromAddress, setFromAddress] = useState("");
  const [fromName, setFromName] = useState("");

  useEffect(() => {
    if (!data) return;
    setEnabled(data.enabled); setHost(data.host); setPort(data.port); setSecurity(data.security);
    setUsername(data.username); setFromAddress(data.from_address); setFromName(data.from_name);
  }, [data]);

  const save = useMutation({
    mutationFn: () => api.updateMailConfig({
      enabled, host: host.trim(), port, security, username: username.trim(),
      password: password || undefined, from_address: fromAddress.trim(), from_name: fromName.trim(),
    }),
    onSuccess: () => { setPassword(""); queryClient.invalidateQueries({ queryKey: ["mail-config"] }); },
  });
  const test = useMutation({
    mutationFn: api.sendTestMail,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["mail-config"] }),
  });

  return (
    <section className="form-panel settings-panel" aria-label="E-mail">
      <h2>E-mail (SMTP relay)</h2>
      <div className="warning-block">
        Optional and off by default. With it on, a user can ask for a password-reset link on the sign-in page. Without
        it, an administrator resets a password under Users, exactly as before. The relay must use TLS; the password is
        stored encrypted and never shown again.
      </div>
      <label className="toggle-row">
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        <span>Send e-mail</span>
      </label>
      <div className="form-grid">
        <label>Relay host<input value={host} placeholder="smtp.example.org" onChange={(e) => setHost(e.target.value)} /></label>
        <label>Port<input type="number" min={1} max={65535} value={port} onChange={(e) => setPort(Number(e.target.value))} /></label>
        <label>Security
          <select value={security} onChange={(e) => setSecurity(e.target.value as "starttls" | "tls")}>
            <option value="starttls">STARTTLS (usually port 587)</option>
            <option value="tls">TLS from the start (usually port 465)</option>
          </select>
        </label>
        <label>Username<input value={username} autoComplete="off" onChange={(e) => setUsername(e.target.value)} /></label>
        <label>Password {data?.password_set ? "(set; leave empty to keep it)" : ""}
          <input type="password" value={password} autoComplete="new-password" onChange={(e) => setPassword(e.target.value)} />
        </label>
        <label>Sender address<input value={fromAddress} placeholder="axial@example.org" onChange={(e) => setFromAddress(e.target.value)} /></label>
        <label>Sender name<input value={fromName} placeholder="Axial" onChange={(e) => setFromName(e.target.value)} /></label>
      </div>
      <div className="form-actions">
        <button onClick={() => save.mutate()} disabled={save.isPending}>{save.isPending ? "Saving..." : "Save e-mail settings"}</button>
        <button className="secondary-action" onClick={() => test.mutate()} disabled={test.isPending || !data?.available}
          title={data?.available ? "Sends one message to your own address" : "Save the settings with Send e-mail on first"}>
          {test.isPending ? "Queuing..." : "Send a test message to me"}
        </button>
      </div>
      {save.isError && <div className="error-block">Save failed: {(save.error as Error).message}</div>}
      {save.isSuccess && <div className="success-block">Saved.</div>}
      {test.isError && <div className="error-block">Test failed: {(test.error as Error).message}</div>}
      {data?.last_test && (
        <p className="muted-line">
          Last test: <strong>{data.last_test.state}</strong>
          {data.last_test.state === "failed" && data.last_test.error ? ` (${data.last_test.error})` : ""}
          {data.last_test.state === "pending" ? ", waiting for the worker" : ""}
        </p>
      )}
    </section>
  );
}
