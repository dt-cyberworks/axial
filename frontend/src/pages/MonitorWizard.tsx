import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";

import { api, type ScopeAsset } from "../api/client";
import CapabilitiesEditor from "../components/CapabilitiesEditor";
import NotificationTargets from "../components/NotificationTargets";
import ScheduleControl from "../components/ScheduleControl";

// REQ-MODE-018: the setup of an engagement that watches an attack surface on its own.
// A separate flow from the test wizard: no tool grants with approvals, no asset review,
// no supervision choice - those do not exist in an unattended run.

type ScopeRow = Pick<ScopeAsset, "asset_type" | "value" | "active_allowed" | "authorization_verified"> & { rule: "allow" | "deny" };

function dateOnlyToIso(value: string, endOfDay = false) {
  const [y, m, d] = value.split("-").map(Number);
  return (endOfDay ? new Date(y, m - 1, d, 23, 59, 59, 999) : new Date(y, m - 1, d, 0, 0, 0, 0)).toISOString();
}
function today(offsetDays = 0) {
  const d = new Date();
  d.setDate(d.getDate() + offsetDays);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

const STEPS = ["Scope", "Capabilities", "Alerts", "Authorize"];
const DEFAULT_EVERY_DAYS = 7;

export default function MonitorWizard() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const draftParam = searchParams.get("draft");
  const [step, setStep] = useState(1);
  const [engagementId, setEngagementId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [title, setTitle] = useState("");
  const [contact, setContact] = useState("");
  const [from, setFrom] = useState(today());
  const [until, setUntil] = useState(today(365));
  const [rows, setRows] = useState<ScopeRow[]>([
    { rule: "allow", asset_type: "domain", value: "", active_allowed: true, authorization_verified: false },
  ]);
  const [savedScopeIds, setSavedScopeIds] = useState<string[]>([]);
  const [customer, setCustomer] = useState(false);

  // Resume a draft of this flow after a reload.
  useEffect(() => {
    if (!draftParam || engagementId) return;
    let cancelled = false;
    (async () => {
      try {
        const [eng, scope] = await Promise.all([api.getEngagement(draftParam), api.listScopeAssets(draftParam)]);
        if (cancelled) return;
        if (eng.status !== "draft" || eng.operating_mode !== "monitoring") {
          setError("That engagement is not a monitoring draft. Open it from the overview instead.");
          return;
        }
        setEngagementId(eng.id);
        setTitle(eng.title);
        setContact(eng.emergency_contact ?? "");
        setFrom(eng.authorized_from.slice(0, 10));
        setUntil(eng.authorized_until.slice(0, 10));
        if (scope.length > 0) {
          setRows(scope.map((s) => ({ rule: s.rule, asset_type: s.asset_type, value: s.value, active_allowed: s.active_allowed, authorization_verified: s.authorization_verified })));
          setSavedScopeIds(scope.map((s) => s.id));
        }
        setStep(2);
      } catch {
        if (!cancelled) setError("Could not resume that draft. Start a new one instead.");
      }
    })();
    return () => { cancelled = true; };
  }, [draftParam, engagementId]);

  const filled = rows.filter((r) => r.value.trim());
  const allow = filled.filter((r) => r.rule === "allow");
  const unattested = allow.filter((r) => r.active_allowed && !r.authorization_verified);

  const { data: capabilities } = useQuery({
    queryKey: ["capabilities", engagementId],
    queryFn: () => api.getCapabilities(engagementId!),
    enabled: !!engagementId && step === 4,
  });
  const { data: targets = [] } = useQuery({
    queryKey: ["notification-targets", engagementId],
    queryFn: () => api.listNotificationTargets(engagementId!),
    enabled: !!engagementId && step === 4,
  });

  async function saveScope() {
    if (busy) return;
    setError(null);
    if (!title.trim()) return setError("Give the engagement a name you will recognise.");
    if (from > until) return setError("The start of the authorization must not be after its end.");
    if (allow.length === 0) return setError("Add at least one allow row: the domain, address or range you may monitor.");
    if (unattested.length > 0) {
      return setError(`Confirm that you are authorized to test: ${unattested.map((r) => r.value).join(", ")}`);
    }
    setBusy(true);
    try {
      const fields = {
        title: title.trim(), authorized_from: dateOnlyToIso(from), authorized_until: dateOnlyToIso(until, true),
        emergency_contact: contact.trim() || null,
      };
      let id = engagementId;
      if (id) {
        await api.updateEngagement(id, fields);
      } else {
        const created = await api.createEngagement({ ...fields, emergency_contact: contact.trim() || undefined, operating_mode: "monitoring" } as any);
        id = created.id;
        setEngagementId(id);
        setSearchParams({ mode: "monitoring", draft: id }, { replace: true });
        // REQ-MON-004: a monitor runs by itself every 7 days unless you change it in step 2.
        await api.putSchedule(id, DEFAULT_EVERY_DAYS);
        // A customer's systems start with new hosts held until you release them.
        if (customer) {
          await api.updateCapabilities(id, { new_asset_policy: "hold" });
        }
      }
      for (const old of savedScopeIds) await api.deleteScopeAsset(id, old);
      const created: string[] = [];
      for (const row of filled) {
        const made = await api.addScopeAsset(id, {
          rule: row.rule, asset_type: row.asset_type, value: row.value.trim(),
          active_allowed: row.rule === "allow" && row.active_allowed,
          authorization_verified: row.authorization_verified,
          authorization_method: row.authorization_verified ? "operator_authorization_attestation" : null,
        } as any);
        created.push(made.id);
      }
      setSavedScopeIds(created);
      setStep(2);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function activate() {
    if (!engagementId || busy) return;
    setBusy(true);
    setError(null);
    try {
      await api.activateEngagement(engagementId);
      navigate(`/engagements/${engagementId}`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const enabled = capabilities?.capabilities.filter((c) => c.enabled) ?? [];

  return (
    <section className="page-stack">
      <header className="page-header">
        <div>
          <span className="eyebrow">Monitor an attack surface</span>
          <h1>New monitoring engagement</h1>
          <p>Step {step} of {STEPS.length}</p>
        </div>
      </header>
      {error && <div className="error-block">{error}</div>}

      <div className="wizard-layout">
        <aside className="wizard-steps">
          {STEPS.map((label, index) => (
            <button key={label} className={step === index + 1 ? "selected" : ""} onClick={() => engagementId && index + 1 < step && setStep(index + 1)}>
              <span>{index + 1}</span>{label}
            </button>
          ))}
        </aside>

        {step === 1 && (
          <section className="form-panel wide">
            <h2>What to monitor</h2>
            <div className="form-grid">
              <label>Name<input value={title} onChange={(e) => setTitle(e.target.value)} /></label>
              <label>Emergency contact<input value={contact} placeholder="Who to call if a test causes problems (name, phone)" onChange={(e) => setContact(e.target.value)} /></label>
              <label>Authorized from<input type="date" value={from} onChange={(e) => setFrom(e.target.value)} /></label>
              <label>Authorized until<input type="date" value={until} onChange={(e) => setUntil(e.target.value)} /></label>
            </div>
            <p className="muted-line">
              A monitoring authorization is standing: it runs until the end date and is reviewed once a year.
              Automatic runs stop by themselves when the authorization ends or its review date passes.
            </p>
            <h3>Scope</h3>
            <div className="scope-editor">
              {rows.map((row, index) => (
                <div key={index} className="scope-row">
                  <select value={row.rule} onChange={(e) => setRows((r) => r.map((x, i) => i === index ? { ...x, rule: e.target.value as "allow" | "deny" } : x))}>
                    <option value="allow">allow</option><option value="deny">deny</option>
                  </select>
                  <select value={row.asset_type} onChange={(e) => setRows((r) => r.map((x, i) => i === index ? { ...x, asset_type: e.target.value as ScopeRow["asset_type"] } : x))}>
                    <option value="domain">domain</option><option value="wildcard">wildcard</option>
                    <option value="ip">ip</option><option value="cidr">cidr</option>
                  </select>
                  <input placeholder="example.com" value={row.value} onChange={(e) => setRows((r) => r.map((x, i) => i === index ? { ...x, value: e.target.value } : x))} />
                  {row.rule === "allow" && (
                    <label>
                      <input type="checkbox" checked={row.authorization_verified}
                        onChange={(e) => setRows((r) => r.map((x, i) => i === index ? { ...x, authorization_verified: e.target.checked } : x))} />
                      {" "}I am authorized to test this
                    </label>
                  )}
                </div>
              ))}
            </div>
            <label className="toggle-row">
              <input type="checkbox" checked={customer} onChange={(e) => setCustomer(e.target.checked)} />
              <span>These are a customer's systems: hold new hosts until I release them</span>
            </label>
            <div className="form-actions">
              <button onClick={() => setRows((r) => [...r, { rule: "allow", asset_type: "domain", value: "", active_allowed: true, authorization_verified: false }])}>Add row</button>
              <button className="primary-action" disabled={busy} onClick={saveScope}>
                {busy ? "Saving…" : engagementId ? "Save changes and continue" : "Save draft and continue"}
              </button>
            </div>
          </section>
        )}

        {step === 2 && engagementId && (
          <section className="wide">
            <ScheduleControl engagementId={engagementId} canManage />
            <CapabilitiesEditor engagementId={engagementId} active={false} canManage />
            <div className="form-actions">
              <button onClick={() => setStep(1)}>Back</button>
              <button className="primary-action" onClick={() => setStep(3)}>Continue</button>
            </div>
          </section>
        )}

        {step === 3 && engagementId && (
          <section className="wide">
            <NotificationTargets engagementId={engagementId} canManage />
            <div className="form-actions">
              <button onClick={() => setStep(2)}>Back</button>
              <button className="primary-action" onClick={() => setStep(4)}>Continue</button>
            </div>
          </section>
        )}

        {step === 4 && engagementId && (
          <section className="form-panel wide">
            <h2>Authorize</h2>
            <h3>What will run without anyone watching</h3>
            <dl className="definition-grid">
              <dt>Scope</dt><dd>{allow.map((r) => r.value).join(", ")}</dd>
              <dt>Authorized</dt><dd>{from} to {until}, reviewed once a year</dd>
              <dt>Capabilities</dt><dd>{enabled.length > 0 ? enabled.map((c) => c.label).join(", ") : "none"}</dd>
              <dt>Scan depth</dt><dd>{capabilities?.scan_profile ?? "…"}</dd>
              <dt>New hosts</dt><dd>{capabilities?.new_asset_policy === "hold" ? "held until you release them" : "tested as soon as the scope covers them"}</dd>
              <dt>Alerts</dt><dd>{targets.length > 0 ? `${targets.length} webhook${targets.length === 1 ? "" : "s"}` : "none (changes are visible in the console only)"}</dd>
            </dl>
            <h3>What can never happen</h3>
            <ul>
              <li>Nothing waits for a person during a run. A call that would need a decision is not made; it is listed in the inbox as a suggestion.</li>
              <li>Nothing outside the scope above is touched, and a deny row always wins.</li>
              <li>Credential and exploit testing are not part of monitoring.</li>
            </ul>
            <p className="muted-line">
              The authorization document states exactly this. Download it for signature before you activate. After
              activation, run the first scan: it becomes the baseline and reports no changes; the next one shows what
              is different.
            </p>
            <div className="form-actions">
              <button onClick={() => setStep(3)}>Back</button>
              <button className="secondary-action" onClick={async () => {
                try { await api.downloadAuthorizationPdf(engagementId); } catch (e) { setError((e as Error).message); }
              }}>Download authorization PDF</button>
              <button className="primary-action" disabled={busy || allow.length === 0 || unattested.length > 0} onClick={activate}>
                {busy ? "Activating…" : "Activate monitoring"}
              </button>
            </div>
          </section>
        )}
      </div>
    </section>
  );
}
