import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { api, type ScanProfile, type ScopeAsset } from "../api/client";
import DiscoverySwitches, { DEFAULT_DISCOVERY_FLAGS, discoveryFlagSummary, type DiscoveryFlags } from "../components/DiscoverySwitches";
import ScanDepth from "../components/ScanDepth";

type EnabledChoice = "inherit" | "on" | "off";
interface ToolOverrideState { enabled: EnabledChoice; approval: boolean; }

function isoToDateInput(value: string) {
  const date = new Date(value);
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function dateOnlyToIso(dateValue: string, endOfDay = false) {
  const [year, month, day] = dateValue.split("-").map(Number);
  const date = endOfDay
    ? new Date(year, month - 1, day, 23, 59, 59, 999)
    : new Date(year, month - 1, day, 0, 0, 0, 0);
  return date.toISOString();
}

export default function EngagementEdit() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [title, setTitle] = useState("");
  const [authorizedFrom, setAuthorizedFrom] = useState("");
  const [authorizedUntil, setAuthorizedUntil] = useState("");
  const [emergencyContact, setEmergencyContact] = useState("");
  const [aiTestingAllowed, setAiTestingAllowed] = useState(false);
  const [assetReviewEnabled, setAssetReviewEnabled] = useState(false);
  const [tcpPortFrom, setTcpPortFrom] = useState("1");
  const [tcpPortTo, setTcpPortTo] = useState("65535");
  const [udpDiscoveryEnabled, setUdpDiscoveryEnabled] = useState(false);
  const [discoveryFlags, setDiscoveryFlags] = useState<DiscoveryFlags>(DEFAULT_DISCOVERY_FLAGS);
  const [scanProfile, setScanProfile] = useState<ScanProfile>("standard");
  const [formError, setFormError] = useState<string | null>(null);

  const { data: engagement, isLoading, error } = useQuery({
    queryKey: ["engagement", id],
    queryFn: () => api.getEngagement(id!),
    enabled: !!id,
  });

  useEffect(() => {
    if (!engagement) return;
    setTitle(engagement.title);
    setAuthorizedFrom(isoToDateInput(engagement.authorized_from));
    setAuthorizedUntil(isoToDateInput(engagement.authorized_until));
    setEmergencyContact(engagement.emergency_contact ?? "");
    setAiTestingAllowed(engagement.ai_testing_allowed);
    setAssetReviewEnabled(engagement.asset_review_enabled);
    setTcpPortFrom(String(engagement.tcp_port_from));
    setTcpPortTo(String(engagement.tcp_port_to));
    setUdpDiscoveryEnabled(engagement.udp_discovery_enabled);
    setScanProfile(engagement.scan_profile ?? "standard");
    setDiscoveryFlags({
      subfinder_enabled: engagement.subfinder_enabled,
      crawling_enabled: engagement.crawling_enabled,
      oob_enabled: engagement.oob_enabled,
      screenshots_enabled: engagement.screenshots_enabled,
    });
  }, [engagement]);

  const isDraft = engagement?.status === "draft";

  const mutation = useMutation({
    mutationFn: () => {
      if (!id) throw new Error("missing engagement id");
      if (authorizedFrom > authorizedUntil) throw new Error("Authorized from date must be on or before authorized until date.");
      return api.updateEngagement(id, {
        title,
        authorized_from: dateOnlyToIso(authorizedFrom),
        authorized_until: dateOnlyToIso(authorizedUntil, true),
        emergency_contact: emergencyContact || null,
        ai_testing_allowed: aiTestingAllowed,
        asset_review_enabled: assetReviewEnabled,
        // Editable at any status: they can only narrow what scope and grants allow.
        ...discoveryFlags,
        scan_profile: scanProfile,
        // The scan envelope can only change while draft (control-plane 409s
        // otherwise) - only send it then, so a save on an active engagement
        // never fails purely because these unrelated fields were included.
        ...(isDraft ? {
          tcp_port_from: Number(tcpPortFrom),
          tcp_port_to: Number(tcpPortTo),
          udp_discovery_enabled: udpDiscoveryEnabled,
        } : {}),
      });
    },
    onSuccess: (updated) => {
      queryClient.invalidateQueries({ queryKey: ["engagements"] });
      queryClient.invalidateQueries({ queryKey: ["engagement", id] });
      navigate(`/engagements/${updated.id}/live`);
    },
  });

  // --- Per-campaign config overrides (layers 4/5) ---
  const { data: config } = useQuery({
    queryKey: ["engagement-config", id],
    queryFn: () => api.getEngagementConfig(id!),
    enabled: !!id,
  });
  const [overrides, setOverrides] = useState<Record<string, ToolOverrideState>>({});
  const [promptOverride, setPromptOverride] = useState("");
  const [promptDirty, setPromptDirty] = useState(false);
  const [maxIterationsOverride, setMaxIterationsOverride] = useState<number | "">("");
  const [approvalTimeoutOverride, setApprovalTimeoutOverride] = useState<number | "">("");

  useEffect(() => {
    if (!config) return;
    const next: Record<string, ToolOverrideState> = {};
    for (const t of config.tools) {
      next[t.tool] = {
        enabled: t.enabled_source === "campaign" ? (t.enabled ? "on" : "off") : "inherit",
        approval: t.approval_source === "campaign",
      };
    }
    setOverrides(next);
    // Always show the EFFECTIVE prompt (campaign override, else global/built-in
    // default) so the box never appears empty - the operator sees exactly what
    // the agent actually runs with and can edit it in place. promptDirty tracks
    // whether they actually touched it, so saving other campaign fields (e.g. a
    // tool toggle) never silently freezes an unedited default as an override.
    setPromptOverride(config.agent_prompt);
    setPromptDirty(false);
    setMaxIterationsOverride(config.agent_max_iterations_overridden ? config.agent_max_iterations : "");
    setApprovalTimeoutOverride(config.approval_timeout_seconds_overridden ? config.approval_timeout_seconds : "");
  }, [config]);

  const configMutation = useMutation({
    mutationFn: () => {
      if (!id) throw new Error("missing engagement id");
      const tools = Object.entries(overrides).map(([tool, o]) => ({
        tool,
        enabled: o.enabled === "inherit" ? null : o.enabled === "on",
        requires_approval: o.approval,
      }));
      return api.updateEngagementConfig(id, {
        tools,
        ...(promptDirty ? { agent_prompt_override: promptOverride } : {}),
        agent_max_iterations_override: maxIterationsOverride === "" ? null : maxIterationsOverride,
        approval_timeout_seconds_override: approvalTimeoutOverride === "" ? null : approvalTimeoutOverride,
      });
    },
    onSuccess: (updated) => queryClient.setQueryData(["engagement-config", id], updated),
  });
  const setOverride = (tool: string, patch: Partial<ToolOverrideState>) =>
    setOverrides((prev) => ({ ...prev, [tool]: { ...prev[tool], ...patch } }));

  // --- Scope assets (REQ-ASSETREVIEW-005): viewable/editable after creation, ---
  // --- not only in the wizard. Also where auto-generated deny rules from an ---
  // --- asset review show up and can be removed. ---
  const { data: scopeAssets = [] } = useQuery({
    queryKey: ["scope-assets", id],
    queryFn: () => api.listScopeAssets(id!),
    enabled: !!id,
  });
  const [newAsset, setNewAsset] = useState<Partial<ScopeAsset>>({
    rule: "allow", asset_type: "domain", value: "", active_allowed: false,
  });
  const addAssetMutation = useMutation({
    mutationFn: () => api.addScopeAsset(id!, newAsset),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scope-assets", id] });
      setNewAsset({ rule: "allow", asset_type: "domain", value: "", active_allowed: false });
    },
  });
  const deleteAssetMutation = useMutation({
    mutationFn: (assetId: string) => api.deleteScopeAsset(id!, assetId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scope-assets", id] }),
  });

  // --- Bug bounty program policy (REQ-AUTH-006, GitHub issue #12) ---
  const { data: bountyProgram } = useQuery({
    queryKey: ["bounty-program", id],
    queryFn: () => api.getBountyProgram(id!),
    enabled: !!id,
  });
  const alreadyBugBounty = engagement?.source === "bug_bounty";
  const [bountyEnabled, setBountyEnabled] = useState(false);
  const [bountyPlatform, setBountyPlatform] = useState("");
  const [bountyProgramRef, setBountyProgramRef] = useState("");
  const [bountyAutomationAllowed, setBountyAutomationAllowed] = useState(false);
  const [bountyMaxRps, setBountyMaxRps] = useState("2");
  const [bountyMaxConcurrency, setBountyMaxConcurrency] = useState("2");
  const [bountyIdentHeaderName, setBountyIdentHeaderName] = useState("X-Bug-Bounty");
  const [bountyIdentHeaderValue, setBountyIdentHeaderValue] = useState("");
  const [bountyUaSuffix, setBountyUaSuffix] = useState("");
  // GitHub issue #37: explicit, opt-in network-scan capability tier - "none"
  // (default) preserves the pre-existing host-discovery-only raw-nmap policy.
  const [bountyTcpSynScanProfile, setBountyTcpSynScanProfile] = useState<"none" | "common" | "full">("none");
  const [bountyRawMaxPps, setBountyRawMaxPps] = useState("");
  const [bountyNetworkScanEvidence, setBountyNetworkScanEvidence] = useState("");

  useEffect(() => {
    if (alreadyBugBounty) setBountyEnabled(true);
    if (!bountyProgram) return;
    setBountyPlatform(bountyProgram.platform);
    setBountyProgramRef(bountyProgram.program_ref);
    setBountyAutomationAllowed(bountyProgram.automation_allowed);
    setBountyMaxRps(String(bountyProgram.max_rps));
    setBountyMaxConcurrency(String(bountyProgram.max_concurrency));
    setBountyIdentHeaderName(bountyProgram.ident_header_name);
    setBountyIdentHeaderValue(bountyProgram.ident_header_value ?? "");
    setBountyUaSuffix(bountyProgram.ua_suffix ?? "");
    setBountyTcpSynScanProfile(bountyProgram.tcp_syn_scan_profile ?? "none");
    setBountyRawMaxPps(bountyProgram.raw_max_packets_per_second != null ? String(bountyProgram.raw_max_packets_per_second) : "");
    setBountyNetworkScanEvidence(bountyProgram.network_scan_authorization_evidence ?? "");
  }, [alreadyBugBounty, bountyProgram]);

  const bountyMutation = useMutation({
    mutationFn: async () => {
      if (!id) throw new Error("missing engagement id");
      if (!bountyPlatform.trim() || !bountyProgramRef.trim()) {
        throw new Error("Platform and program reference are required.");
      }
      if (bountyTcpSynScanProfile === "full" && !bountyNetworkScanEvidence.trim()) {
        throw new Error("The 'full' network-scan tier requires a recorded authorization reason.");
      }
      // REQ-AUTH-003 (amended): source is sent here, and ONLY here - never
      // from the Metadata panel's routine save above.
      if (!alreadyBugBounty) await api.updateEngagement(id, { source: "bug_bounty" });
      await api.addBountyProgram(id, {
        platform: bountyPlatform.trim(),
        program_ref: bountyProgramRef.trim(),
        automation_allowed: bountyAutomationAllowed,
        ai_testing_allowed: aiTestingAllowed,
        max_rps: Number(bountyMaxRps) || 2,
        max_concurrency: Number(bountyMaxConcurrency) || 2,
        ident_header_name: bountyIdentHeaderName.trim() || "X-Bug-Bounty",
        ident_header_value: bountyIdentHeaderValue.trim() || null,
        ua_suffix: bountyUaSuffix.trim() || null,
        tcp_syn_scan_profile: bountyTcpSynScanProfile,
        raw_max_packets_per_second: bountyRawMaxPps.trim() ? Number(bountyRawMaxPps) : null,
        network_scan_authorization_evidence: bountyNetworkScanEvidence.trim() || null,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["engagement", id] });
      queryClient.invalidateQueries({ queryKey: ["bounty-program", id] });
    },
  });

  if (isLoading) return <div className="loading-block">Loading engagement...</div>;
  if (error) return <div className="error-block">Failed to load engagement: {(error as Error).message}</div>;
  if (!engagement || !id) return null;


  return (
    <section className="page-stack">
      <header className="page-header">
        <div>
          <span className="eyebrow">Engagement settings</span>
          <h1>Edit engagement</h1>
          <p>{id}</p>
        </div>
        <div className="header-actions">
          <Link to={`/engagements/${id}/live`} className="secondary-action">Live</Link>
          <Link to="/" className="secondary-action">Overview</Link>
        </div>
      </header>

      {(formError || mutation.isError) && (
        <div className="error-block">{formError ?? `Save failed: ${(mutation.error as Error).message}`}</div>
      )}

      <section className="form-panel settings-panel">
        <h2>Metadata</h2>
        <div className="form-grid">
          <label>Title<input value={title} onChange={(e) => setTitle(e.target.value)} /></label>
          <label>Emergency contact<input value={emergencyContact} onChange={(e) => setEmergencyContact(e.target.value)} /></label>
          <label>Status<input value={engagement.status} disabled /></label>
          <label>Authorized from<input type="date" value={authorizedFrom} onChange={(e) => setAuthorizedFrom(e.target.value)} /></label>
          <label>Authorized until<input type="date" value={authorizedUntil} onChange={(e) => setAuthorizedUntil(e.target.value)} /></label>
        </div>
        <label className="toggle-row">
          <input type="checkbox" checked={aiTestingAllowed} onChange={(e) => setAiTestingAllowed(e.target.checked)} />
          <span>Allow Vector Agent autonomous proposals for this engagement</span>
        </label>
        <label className="toggle-row">
          <input type="checkbox" checked={assetReviewEnabled} onChange={(e) => setAssetReviewEnabled(e.target.checked)} />
          <span>Pause after discovery for manual asset review before scanning continues</span>
        </label>

        <h2 style={{ marginTop: 18 }}>Discovery extras</h2>
        <p className="muted-line">
          Each switch applies from the next scan. Scope, tool grants and the Scope Gateway still decide what may run;
          turning a switch off only ever narrows it.
        </p>
        <DiscoverySwitches flags={discoveryFlags} onChange={setDiscoveryFlags} />

        <h2 style={{ marginTop: 18 }}>Scan depth</h2>
        <p className="muted-line">
          Applies from the next scan. It only changes how many checks run on each web service; scope, tool grants and
          the switches above still decide what is allowed.
        </p>
        <ScanDepth value={scanProfile} onChange={setScanProfile} />

        <h2 style={{ marginTop: 18 }}>Scan envelope</h2>
        <div className="warning-block">
          {isDraft
            ? "The TCP port range and UDP discovery opt-in bind the signed raw-egress lease used for nmap - editable only while this engagement is in draft."
            : "Scan envelope can only be changed while this engagement is in draft. Currently read-only."}
        </div>
        <div className="form-grid">
          <label>
            TCP port from
            <input type="number" min="1" max="65535" value={tcpPortFrom} disabled={!isDraft}
              onChange={(e) => setTcpPortFrom(e.target.value)} />
          </label>
          <label>
            TCP port to
            <input type="number" min="1" max="65535" value={tcpPortTo} disabled={!isDraft}
              onChange={(e) => setTcpPortTo(e.target.value)} />
          </label>
        </div>
        <label className="toggle-row">
          <input type="checkbox" checked={udpDiscoveryEnabled} disabled={!isDraft}
            onChange={(e) => setUdpDiscoveryEnabled(e.target.checked)} />
          <span>UDP discovery (fixed nine-port profile)</span>
        </label>

        <div className="form-actions">
          <button onClick={() => navigate(-1)}>Cancel</button>
          <button
            onClick={() => { setFormError(null); mutation.mutate(); }}
            disabled={mutation.isPending || !title || !authorizedFrom || !authorizedUntil}
          >
            {mutation.isPending ? "Saving..." : "Save changes"}
          </button>
        </div>
      </section>

      <section className="form-panel settings-panel">
        <h2>Campaign tool overrides</h2>
        <div className="warning-block">
          Overrides the global tool policy for this campaign only. "Inherit" uses the global default; the capability registry floor and scope/arg-safety always apply.
        </div>
        <div className="responsive-table">
          <table className="data-table">
            <thead>
              <tr><th>Tool</th><th>Category</th><th>Effective</th><th>This campaign</th><th>Approval</th></tr>
            </thead>
            <tbody>
              {(config?.tools ?? []).map((t) => (
                <tr key={t.tool}>
                  <td>{t.tool}{t.installed === false && <span className="muted-line">not installed</span>}</td>
                  <td>{t.category}</td>
                  <td>
                    <span className={`pill ${t.enabled ? "good" : "neutral"}`}>{t.enabled ? "enabled" : "disabled"}</span>
                    <span className="muted-line">via {t.enabled_source}</span>
                  </td>
                  <td>
                    <select
                      value={overrides[t.tool]?.enabled ?? "inherit"}
                      disabled={t.installed === false}
                      onChange={(e) => setOverride(t.tool, { enabled: e.target.value as EnabledChoice })}
                    >
                      <option value="inherit">Inherit global</option>
                      <option value="on">Force on</option>
                      <option value="off">Force off</option>
                    </select>
                  </td>
                  <td>
                    <input type="checkbox" checked={overrides[t.tool]?.approval ?? false}
                      onChange={(e) => setOverride(t.tool, { approval: e.target.checked })} />
                  </td>
                </tr>
              ))}
              {(config?.tools ?? []).length === 0 && <tr><td className="empty-cell" colSpan={5}>Loading tools…</td></tr>}
            </tbody>
          </table>
        </div>

        <h2 style={{ marginTop: 18 }}>Vector Agent instructions (campaign override)</h2>
        <div className="warning-block">
          {config?.agent_prompt_overridden
            ? "This campaign has its own override, shown below. Clear the box and save to revert to the global default."
            : "Showing the effective (global/built-in) instructions. Edit and save to set a campaign-specific override; leave untouched and other saves on this page won't affect it."}
          {" "}Safe to edit either way: the Scope Gateway decides every action regardless of the prompt.
        </div>
        <textarea
          rows={12}
          value={promptOverride}
          onChange={(e) => { setPromptOverride(e.target.value); setPromptDirty(true); }}
          style={{ width: "100%", fontFamily: "ui-monospace, monospace", fontSize: "0.82rem", padding: "10px", borderRadius: 6 }}
        />
        <h2 style={{ marginTop: 18 }}>Vector Agent iteration budget (campaign override)</h2>
        <div className="warning-block">
          Leave empty to inherit the global iteration budget ({config?.agent_max_iterations ?? 50} effective now).
        </div>
        <label>
          Max iterations
          <input
            type="number"
            min={1}
            max={500}
            value={maxIterationsOverride}
            placeholder="(inherits global default)"
            onChange={(e) => setMaxIterationsOverride(e.target.value === "" ? "" : Number(e.target.value))}
          />
        </label>

        <h2 style={{ marginTop: 18 }}>Manual approval timeout (campaign override)</h2>
        <div className="warning-block">
          Leave empty to inherit the global approval timeout ({config?.approval_timeout_seconds ?? 900}s effective now). A state-changing request auto-rejects if nobody decides within this window.
        </div>
        <label>
          Timeout (seconds)
          <input
            type="number"
            min={60}
            max={86400}
            value={approvalTimeoutOverride}
            placeholder="(inherits global default)"
            onChange={(e) => setApprovalTimeoutOverride(e.target.value === "" ? "" : Number(e.target.value))}
          />
        </label>

        <div className="form-actions">
          <button onClick={() => configMutation.mutate()} disabled={configMutation.isPending}>
            {configMutation.isPending ? "Saving..." : "Save campaign config"}
          </button>
        </div>
        {configMutation.isError && <div className="error-block">Save failed: {(configMutation.error as Error).message}</div>}
        {configMutation.isSuccess && <div className="success-block">Saved.</div>}

        <div className="form-panel-section">
          <h2 style={{ marginTop: 0 }}>Bug bounty program policy</h2>
          <label className="grant-toggle">
            <input
              type="checkbox" checked={bountyEnabled} disabled={alreadyBugBounty}
              onChange={(e) => setBountyEnabled(e.target.checked)}
            />
            <span>This engagement follows a bug bounty program's rules of engagement</span>
          </label>
          <p className="muted-line">
            {alreadyBugBounty
              ? "Already enabled for this engagement. Edit the policy below and save to update it (e.g. correcting a typo) - it cannot be turned back off from here."
              : "Enable this only for a real bug-bounty/VDP program that requires self-identification and a request-rate cap. The platform then sends the identification below on every automated request to the target, including HTTPS."}
          </p>
          {bountyEnabled && (
            <>
              <div className="form-grid">
                <label>Platform<input value={bountyPlatform} onChange={(e) => setBountyPlatform(e.target.value)} placeholder="intigriti / hackerone / …" /></label>
                <label>Program reference<input value={bountyProgramRef} onChange={(e) => setBountyProgramRef(e.target.value)} placeholder="the program's slug/ID on that platform" /></label>
                <label className="grant-toggle">
                  <input type="checkbox" checked={bountyAutomationAllowed} onChange={(e) => setBountyAutomationAllowed(e.target.checked)} />
                  <span>Program terms explicitly permit automated (not only manual) testing</span>
                </label>
                <label>Max requests/second<input type="number" min="0.1" step="0.1" value={bountyMaxRps} onChange={(e) => setBountyMaxRps(e.target.value)} /></label>
                <label>Max concurrency<input type="number" min="1" step="1" value={bountyMaxConcurrency} onChange={(e) => setBountyMaxConcurrency(e.target.value)} /></label>
                <label>Identification header name (optional)<input value={bountyIdentHeaderName} onChange={(e) => setBountyIdentHeaderName(e.target.value)} /></label>
                <label>Identification header value (optional)<input value={bountyIdentHeaderValue} onChange={(e) => setBountyIdentHeaderValue(e.target.value)} placeholder="leave blank if the program doesn't require a custom header; e.g. your researcher handle/contact otherwise" /></label>
                <label>User-Agent suffix (optional)<input value={bountyUaSuffix} onChange={(e) => setBountyUaSuffix(e.target.value)} placeholder="appended identification for tools that support a custom User-Agent" /></label>
                <label>
                  Network (TCP SYN) scan tier
                  <select value={bountyTcpSynScanProfile} onChange={(e) => setBountyTcpSynScanProfile(e.target.value as "none" | "common" | "full")}>
                    <option value="none">None - discovery-only (default, matches every other program unless changed)</option>
                    <option value="common">Common - the engagement's own configured port ranges</option>
                    <option value="full">Full - all 65535 TCP ports</option>
                  </select>
                </label>
                <label>Raw scan packet rate cap, packets/second (optional)<input type="number" min="1" max="1000" step="1" value={bountyRawMaxPps} onChange={(e) => setBountyRawMaxPps(e.target.value)} placeholder="leave blank to fall back to the max requests/second cap above" /></label>
                {bountyTcpSynScanProfile === "full" && (
                  <label>
                    Network-scan authorization evidence (required for the Full tier)
                    <textarea
                      value={bountyNetworkScanEvidence} onChange={(e) => setBountyNetworkScanEvidence(e.target.value)}
                      placeholder="e.g. a quote/link from the program's own scope policy explicitly permitting full-port TCP scanning - not inferred from automation_allowed alone"
                    />
                  </label>
                )}
                <p className="muted-line">
                  Every tier still only reaches host discovery (a liveness sweep) unless raised here - a deliberate,
                  separate opt-in from "automated testing is permitted" above, since most bug-bounty programs do not
                  authorize raw TCP port scanning even when they permit automated HTTP-level testing.
                </p>
              </div>
              <div className="form-actions">
                <button onClick={() => bountyMutation.mutate()} disabled={bountyMutation.isPending}>
                  {bountyMutation.isPending ? "Saving..." : "Save bounty program policy"}
                </button>
              </div>
              {bountyMutation.isError && <div className="error-block">Save failed: {(bountyMutation.error as Error).message}</div>}
              {bountyMutation.isSuccess && <div className="success-block">Saved.</div>}
            </>
          )}
        </div>
      </section>

      <section className="form-panel settings-panel">
        <h2>Scope assets</h2>
        <div className="warning-block">
          Allow/deny rules for this engagement. Deny always wins over allow. Rows
          created automatically by an asset review (excluded hosts) appear here
          too and can be removed to re-include a host.
        </div>
        {scopeAssets.some((a) => a.asset_type === "cidr") && (
          <div className="warning-block">
            Host discovery for a CIDR range only probes TCP 80/443 (SYN, no ICMP) -
            this is a deliberate, bounded raw-egress policy, not a bug. A host that
            answers on neither port (e.g. SSH-only, or a web service on another
            port) will not be found by the sweep, and is indistinguishable from a
            genuinely dead address in the results. Individual hosts already known
            in scope remain fully scannable on any authorized port regardless.
          </div>
        )}
        <div className="responsive-table">
          <table className="data-table">
            <thead>
              <tr><th>Rule</th><th>Type</th><th>Value</th><th>Ports</th><th>Active-allowed</th><th></th></tr>
            </thead>
            <tbody>
              {scopeAssets.map((a) => (
                <tr key={a.id}>
                  <td><span className={`pill ${a.rule === "deny" ? "bad" : "good"}`}>{a.rule}</span></td>
                  <td>{a.asset_type}</td>
                  <td>{a.value}</td>
                  <td>{a.port_from != null ? `${a.port_from}-${a.port_to}` : "engagement ceiling"}</td>
                  <td>{a.active_allowed ? "yes" : "no"}</td>
                  <td>
                    <button onClick={() => deleteAssetMutation.mutate(a.id)} disabled={deleteAssetMutation.isPending}>
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
              {scopeAssets.length === 0 && <tr><td className="empty-cell" colSpan={6}>No scope assets yet.</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="form-grid" style={{ marginTop: 12 }}>
          <label>
            Rule
            <select value={newAsset.rule} onChange={(e) => setNewAsset((a) => ({ ...a, rule: e.target.value as ScopeAsset["rule"] }))}>
              <option value="allow">allow</option>
              <option value="deny">deny</option>
            </select>
          </label>
          <label>
            Type
            <select value={newAsset.asset_type} onChange={(e) => setNewAsset((a) => ({ ...a, asset_type: e.target.value as ScopeAsset["asset_type"] }))}>
              <option value="domain">domain</option>
              <option value="wildcard">wildcard</option>
              <option value="ip">ip</option>
              <option value="cidr">cidr</option>
            </select>
          </label>
          <label>
            Value
            <input value={newAsset.value ?? ""} onChange={(e) => setNewAsset((a) => ({ ...a, value: e.target.value }))} placeholder="example.com" />
          </label>
          <label>
            Port from
            <input
              type="number" min="1" max="65535" placeholder="engagement ceiling"
              title="Leave blank to inherit the engagement's maximum authorized port range"
              value={newAsset.port_from ?? ""}
              onChange={(e) => setNewAsset((a) => ({ ...a, port_from: e.target.value === "" ? null : Number(e.target.value) }))}
            />
          </label>
          <label>
            Port to
            <input
              type="number" min="1" max="65535" placeholder="engagement ceiling"
              title="Leave blank to inherit the engagement's maximum authorized port range"
              value={newAsset.port_to ?? ""}
              onChange={(e) => setNewAsset((a) => ({ ...a, port_to: e.target.value === "" ? null : Number(e.target.value) }))}
            />
          </label>
          <label className="toggle-row">
            <input type="checkbox" checked={!!newAsset.active_allowed} onChange={(e) => setNewAsset((a) => ({ ...a, active_allowed: e.target.checked }))} />
            <span>active</span>
          </label>
        </div>
        <p className="muted-line">Port from/to are optional - leave blank to inherit the engagement's maximum authorized port range (below). A target's range can only narrow that ceiling, never widen it.</p>
        <div className="form-actions">
          <button onClick={() => addAssetMutation.mutate()} disabled={addAssetMutation.isPending || !newAsset.value}>
            {addAssetMutation.isPending ? "Adding..." : "Add scope asset"}
          </button>
        </div>
        {addAssetMutation.isError && <div className="error-block">Add failed: {(addAssetMutation.error as Error).message}</div>}
        {deleteAssetMutation.isError && <div className="error-block">Remove failed: {(deleteAssetMutation.error as Error).message}</div>}
      </section>
    </section>
  );
}
