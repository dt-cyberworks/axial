import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type TestAccountView } from "../api/client";
import {
  ATTESTATION, ATTESTATION_BOUNTY, CONSENT_WORDING, EMPTY_FORM, KIND_LABEL, LOGIN_KINDS, consentSummary, disclosureText, outcomeWords,
  problemWithForm, stateLine, testAccountRefusal, toRequest, type AccountForm,
} from "../lib/testAccounts";

/**
 * REQ-TESTACCT-010 (GitHub #89): the test accounts of an engagement. The secret field is write-only: it is never prefilled, never shown
 * after saving and never part of what the server sends back. The same component serves an assessment and a monitor.
 */
export default function TestAccounts({ engagementId, canManage, operatingMode, source }: {
  engagementId: string; canManage: boolean; operatingMode: "monitoring" | "assessment"; source: string;
}) {
  const queryClient = useQueryClient();
  const overview = useQuery({ queryKey: ["test-accounts", engagementId], queryFn: () => api.listTestAccounts(engagementId) });
  const choices = useQuery({ queryKey: ["test-account-hosts", engagementId], queryFn: () => api.testAccountHostChoices(engagementId), enabled: canManage });
  const llm = useQuery({ queryKey: ["llm-provider-name"], queryFn: () => api.getLlmConfig().then((c) => c.base_url ?? null).catch(() => null), staleTime: 300000 });
  const [form, setForm] = useState<AccountForm>(EMPTY_FORM);
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isBounty = source === "bug_bounty";
  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["test-accounts", engagementId] });
    queryClient.invalidateQueries({ queryKey: ["engagement", engagementId] });
  };
  const fail = (e: unknown) => setError(testAccountRefusal((e as Error).message));

  const create = useMutation({
    mutationFn: () => api.createTestAccount(engagementId, toRequest(form)),
    onSuccess: () => { setForm(EMPTY_FORM); setAdding(false); setError(null); refresh(); },
    onError: fail,
  });

  const data = overview.data;
  const hostList = choices.data ?? [];
  const problem = problemWithForm(form);
  const provider = useMemo(() => {
    const url = llm.data;
    if (!url) return null;
    try { return new URL(url).host; } catch { return url; }
  }, [llm.data]);

  if (overview.isLoading) return <p className="muted-line">Loading test accounts…</p>;
  if (overview.isError || !data) return <div className="error-block">Test accounts could not be loaded: {(overview.error as Error)?.message}</div>;

  return (
    <section className="form-panel wide test-accounts" aria-label="Test accounts">
      <h2>Test accounts</h2>
      <p>
        A test account lets the Vector Agent log in and test what sits behind the login. You assign it to specific hosts; it is bound to those
        hosts only and can never be used anywhere else. Nothing here is a default-credential check: you supply the account.
      </p>
      <div className="warning-block" role="note" data-testid="test-account-disclosure">{disclosureText(provider)}</div>
      {!data.cipher_available && (
        <div className="error-block">The server has no encryption key for test accounts. Nothing can be saved until an administrator sets TESTACCOUNT_ENCRYPTION_KEY.</div>
      )}
      {error && <div className="error-block" role="alert">{error}</div>}

      {data.accounts.length === 0 && <p className="muted-line">No test account has been entered for this engagement.</p>}
      <ul className="account-list">
        {data.accounts.map((a) => (
          <AccountCard key={a.id} account={a} engagementId={engagementId} canManage={canManage} isMonitor={operatingMode === "monitoring"}
            hostChoices={hostList.map((h) => h.host)} onChange={refresh} onError={fail} attestation={isBounty ? ATTESTATION_BOUNTY : ATTESTATION} />
        ))}
      </ul>

      {operatingMode === "monitoring" && <LoginConsent engagementId={engagementId} canManage={canManage} consent={data.consent} hasAccounts={data.accounts.length > 0}
        onChange={refresh} onError={fail} />}

      {canManage && !adding && data.accounts.length < 4 && (
        <div className="form-actions"><button onClick={() => { setAdding(true); setError(null); }}>Add a test account</button></div>
      )}
      {canManage && adding && (
        <div className="form-grid account-form">
          <label>Label<input value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} placeholder="shop-user" /></label>
          <label>Role<input value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })} placeholder="user, admin, …" /></label>
          <label>How the target logs in
            <select value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value as AccountForm["kind"] })}>
              <option value="">Choose…</option>
              {Object.entries(KIND_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </label>
          {LOGIN_KINDS.includes(form.kind as never) && (
            <label>Login path (POST)<input value={form.loginPath} onChange={(e) => setForm({ ...form, loginPath: e.target.value })} /></label>
          )}
          {form.kind === "header_token" && (
            <label>Header name<input value={form.headerName} onChange={(e) => setForm({ ...form, headerName: e.target.value })} placeholder="Authorization" /></label>
          )}
          {form.kind !== "header_token" && (
            <label>Username<input value={form.username} autoComplete="off" onChange={(e) => setForm({ ...form, username: e.target.value })} /></label>
          )}
          <label>{form.kind === "header_token" ? "Token" : "Password"}
            <input type="password" value={form.secret} autoComplete="new-password" onChange={(e) => setForm({ ...form, secret: e.target.value })} />
          </label>
          <fieldset className="host-picker">
            <legend>Hosts this account is valid on</legend>
            {hostList.length === 0 && <p className="muted-line">This engagement has no concrete host yet. Add a target first, or save the account now and assign hosts later.</p>}
            {hostList.map((h) => {
              const checked = form.hosts[h.host] !== undefined;
              return (
                <div key={h.host} className="host-row">
                  <label>
                    <input type="checkbox" checked={checked} disabled={!!h.denied_by}
                      onChange={(e) => {
                        const next = { ...form.hosts };
                        if (e.target.checked) next[h.host] = ""; else delete next[h.host];
                        setForm({ ...form, hosts: next });
                      }} />
                    {h.host}
                  </label>
                  {h.denied_by && <span className="muted-line"> blocked by the deny rule {h.denied_by}</span>}
                  {h.held && <span className="muted-line"> held for review: it is assigned, but not used until released</span>}
                  {h.takeover_suspected && <span className="muted-line"> possible subdomain takeover: not used</span>}
                  {checked && LOGIN_KINDS.includes(form.kind as never) && (
                    <input className="host-login-path" aria-label={`Login path on ${h.host}`} placeholder={`login path on this host (default ${form.loginPath || "/login"})`}
                      value={form.hosts[h.host]} onChange={(e) => setForm({ ...form, hosts: { ...form.hosts, [h.host]: e.target.value } })} />
                  )}
                </div>
              );
            })}
            {hostList.length > 1 && (
              <button type="button" className="link-button" onClick={() => setForm({ ...form, hosts: Object.fromEntries(hostList.filter((h) => !h.denied_by).map((h) => [h.host, form.hosts[h.host] ?? ""])) })}>
                Select all shown (hosts found later are not added)
              </button>
            )}
          </fieldset>
          <label className="checkbox-label">
            <input type="checkbox" checked={form.attested} onChange={(e) => setForm({ ...form, attested: e.target.checked })} />
            {isBounty ? ATTESTATION_BOUNTY : ATTESTATION}
          </label>
          {Object.keys(form.hosts).length === 0 && <p className="muted-line">With no host ticked this account cannot be used anywhere yet.</p>}
          <div className="form-actions">
            <button onClick={() => { setAdding(false); setForm(EMPTY_FORM); setError(null); }}>Cancel</button>
            <button className="primary-action" disabled={create.isPending || problem !== null || !data.cipher_available} title={problem ?? undefined} onClick={() => create.mutate()}>
              {create.isPending ? "Saving…" : "Save account"}
            </button>
          </div>
          {problem && <p className="muted-line">{problem}</p>}
        </div>
      )}
    </section>
  );
}

function AccountCard({ account, engagementId, canManage, isMonitor, hostChoices, onChange, onError, attestation }: {
  account: TestAccountView; engagementId: string; canManage: boolean; isMonitor: boolean; hostChoices: string[];
  onChange: () => void; onError: (e: unknown) => void; attestation: string;
}) {
  const [secret, setSecret] = useState("");
  const [editingHosts, setEditingHosts] = useState(false);
  const [picked, setPicked] = useState<Record<string, string>>({});
  const [attested, setAttested] = useState(false);
  const [alsoConsent, setAlsoConsent] = useState(false);
  const replace = useMutation({ mutationFn: () => api.replaceTestAccountSecret(engagementId, account.id, secret), onSuccess: () => { setSecret(""); onChange(); }, onError });
  const resume = useMutation({ mutationFn: () => api.resumeTestAccount(engagementId, account.id), onSuccess: onChange, onError });
  const remove = useMutation({ mutationFn: () => api.deleteTestAccount(engagementId, account.id), onSuccess: onChange, onError });
  const saveHosts = useMutation({
    mutationFn: () => api.setTestAccountHosts(engagementId, account.id, Object.entries(picked).map(([host, p]) => ({ host, login_path: p.trim() || null })), attested, alsoConsent),
    onSuccess: () => { setEditingHosts(false); onChange(); }, onError,
  });
  const erased = account.state === "erased";
  return (
    <li className="account-card" data-testid={`account-${account.label}`}>
      <header>
        <strong>{account.label}</strong> <span className="muted-line">role {account.role} · {KIND_LABEL[account.kind]} · {stateLine(account)}</span>
      </header>
      <dl className="definition-grid">
        {account.username && <><dt>Username</dt><dd>{account.username}</dd></>}
        <dt>Secret</dt>
        <dd>{erased ? "erased" : account.secret_set ? `set${account.secret_set_at ? `, replaced ${account.secret_set_at.slice(0, 16).replace("T", " ")}` : ""}` : "not set"}</dd>
        {account.login_path && <><dt>Login</dt><dd>POST {account.login_path}</dd></>}
        <dt>Hosts</dt>
        <dd>{account.hosts.length === 0 ? "none: this account cannot be used anywhere" : account.hosts.map((h) => `${h.host} (${outcomeWords(h.last_outcome)}${h.suspended ? ", suspended" : ""})`).join("; ")}</dd>
      </dl>
      <div className="where-works">
        <p><strong>Can be used on:</strong> {account.can_use_on.length ? account.can_use_on.join(", ") : "nowhere yet"}</p>
        {account.cannot_use_on.length > 0 && (
          <p><strong>Cannot be used on:</strong> {account.cannot_use_on.map((c) => `${c.host} (${c.reason_text ?? c.reason})`).join("; ")}</p>
        )}
      </div>
      {account.suspended_reason && (
        <div className="warning-block">Suspended: {account.suspended_reason}. The target may be locking the account. Replace the secret or resume.</div>
      )}
      {canManage && !erased && (
        <div className="account-actions">
          <input type="password" value={secret} autoComplete="new-password" aria-label={`New secret for ${account.label}`} placeholder="new password or token" onChange={(e) => setSecret(e.target.value)} />
          <button disabled={secret.length < 8 || replace.isPending} onClick={() => replace.mutate()}>Replace secret</button>
          {(account.state === "suspended" || account.hosts.some((h) => h.suspended)) && <button onClick={() => resume.mutate()}>Resume</button>}
          <button onClick={() => { setEditingHosts(!editingHosts); setPicked(Object.fromEntries(account.hosts.map((h) => [h.host, h.login_path ?? ""]))); }}>Edit hosts</button>
          <button className="danger-action" onClick={() => { if (window.confirm(`Delete test account ${account.label}? Its secret is deleted.`)) remove.mutate(); }}>Delete</button>
        </div>
      )}
      {canManage && editingHosts && (
        <fieldset className="host-picker">
          <legend>Hosts for {account.label}</legend>
          {Array.from(new Set([...hostChoices, ...Object.keys(picked)])).sort().map((host) => (
            <label key={host} className="host-row">
              <input type="checkbox" checked={picked[host] !== undefined}
                onChange={(e) => { const next = { ...picked }; if (e.target.checked) next[host] = ""; else delete next[host]; setPicked(next); }} />
              {host}
            </label>
          ))}
          <label className="checkbox-label"><input type="checkbox" checked={attested} onChange={(e) => setAttested(e.target.checked)} />{attestation}</label>
          {isMonitor && (
            <label className="checkbox-label">
              <input type="checkbox" checked={alsoConsent} onChange={(e) => setAlsoConsent(e.target.checked)} />
              Cover the changed hosts with my login consent now. {CONSENT_WORDING}
            </label>
          )}
          <div className="form-actions"><button onClick={() => setEditingHosts(false)}>Cancel</button><button className="primary-action" onClick={() => saveHosts.mutate()}>Save hosts</button></div>
        </fieldset>
      )}
    </li>
  );
}

/** REQ-TESTACCT-006: a monitor logs in unattended, so the owner consents once, here, to exactly the (account, host) pairs. */
export function LoginConsent({ engagementId, canManage, consent, hasAccounts, onChange, onError }: {
  engagementId: string; canManage: boolean; consent: import("../api/client").LoginConsentView; hasAccounts: boolean;
  onChange: () => void; onError: (e: unknown) => void;
}) {
  const [agreed, setAgreed] = useState(false);
  const give = useMutation({ mutationFn: () => api.giveLoginConsent(engagementId), onSuccess: () => { setAgreed(false); onChange(); }, onError });
  const revoke = useMutation({ mutationFn: () => api.revokeLoginConsent(engagementId), onSuccess: onChange, onError });
  if (!hasAccounts) return null;
  const summary = consentSummary(consent);
  return (
    <div className="login-consent" data-testid="login-consent">
      <h3>Login consent</h3>
      <p>{CONSENT_WORDING}</p>
      <ul>{consent.pairs.map((p) => <li key={`${p.label}@${p.host}`}>{p.label} on {p.host}{p.login_path ? ` (POST ${p.login_path})` : ""}</li>)}</ul>
      <p className={summary.needed ? "warning-block" : "muted-line"}>{summary.text}{consent.given_at ? ` Given ${consent.given_at.slice(0, 16).replace("T", " ")}.` : ""}</p>
      {canManage && summary.needed && (
        <>
          <label className="checkbox-label"><input type="checkbox" checked={agreed} onChange={(e) => setAgreed(e.target.checked)} />I give this consent for the accounts and hosts listed.</label>
          <div className="form-actions"><button className="primary-action" disabled={!agreed || give.isPending} onClick={() => give.mutate()}>Give login consent</button></div>
        </>
      )}
      {canManage && consent.current && <div className="form-actions"><button onClick={() => revoke.mutate()}>Revoke login consent</button></div>}
    </div>
  );
}
