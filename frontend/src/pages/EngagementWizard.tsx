import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";

import { api, type ScanProfile, type ScopeAsset, type ToolCapability } from "../api/client";
import DiscoverySwitches, { DEFAULT_DISCOVERY_FLAGS, discoveryFlagSummary, type DiscoveryFlags } from "../components/DiscoverySwitches";
import ScanDepth, { scanDepthLabel } from "../components/ScanDepth";


const TOOL_CATEGORIES = ["recon", "fingerprint", "vuln", "cred", "exploit"] as const;
type ToolCategory = typeof TOOL_CATEGORIES[number];
type GrantState = Record<ToolCategory, { passive: boolean; active: boolean; manualTools: string[] }>;

const DEFAULT_GRANTS: GrantState = {
  recon: { passive: true, active: false, manualTools: [] },
  fingerprint: { passive: false, active: true, manualTools: [] },
  vuln: { passive: false, active: false, manualTools: [] },
  cred: { passive: false, active: false, manualTools: [] },
  exploit: { passive: false, active: false, manualTools: [] },
};
const DEFAULT_MANUAL_TOOL_CATEGORIES = new Set<ToolCategory>(["vuln", "cred", "exploit"]);

function dateOnlyToIso(dateValue: string, endOfDay = false) {
  const [year, month, day] = dateValue.split("-").map(Number);
  const date = endOfDay
    ? new Date(year, month - 1, day, 23, 59, 59, 999)
    : new Date(year, month - 1, day, 0, 0, 0, 0);
  return date.toISOString();
}

// Inverse of dateOnlyToIso: the local calendar day the stored instant falls on.
function isoToDateOnly(iso: string) {
  const date = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

// GitHub issue #46: what makes two scope rows "the same" once saved, so a
// second save of step 3 only sends rows that are new or were edited.
function assetKey(asset: Partial<ScopeAsset>) {
  return JSON.stringify([
    asset.rule, asset.asset_type, (asset.value ?? "").trim(), asset.path_pattern ?? null,
    !!asset.active_allowed, !!asset.authorization_verified, asset.port_from ?? null, asset.port_to ?? null,
  ]);
}

export default function EngagementWizard() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const draftParam = searchParams.get("draft");
  const [step, setStep] = useState(1);
  // GitHub issue #46: one wizard session owns exactly one draft. Once this is
  // set, step 1 edits that draft (PATCH) and never creates another (POST); the
  // id also lives in the URL (?draft=) so a reload resumes the draft.
  const [engagementId, setEngagementId] = useState<string | null>(null);
  const ownDraftRef = useRef<string | null>(null);
  const [savedAssets, setSavedAssets] = useState<{ id: string; key: string }[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [isCreating, setIsCreating] = useState(false);
  const [downloadingPdf, setDownloadingPdf] = useState(false);

  const [title, setTitle] = useState("");
  const [authorizedFrom, setAuthorizedFrom] = useState("");
  const [authorizedUntil, setAuthorizedUntil] = useState("");
  const [emergencyContact, setEmergencyContact] = useState("");
  const [aiTestingAllowed, setAiTestingAllowed] = useState(false);
  const [tcpPortFrom, setTcpPortFrom] = useState("1");
  const [tcpPortTo, setTcpPortTo] = useState("65535");
  const [udpDiscoveryEnabled, setUdpDiscoveryEnabled] = useState(false);
  const [assetReviewEnabled, setAssetReviewEnabled] = useState(false);
  const [discoveryFlags, setDiscoveryFlags] = useState<DiscoveryFlags>(DEFAULT_DISCOVERY_FLAGS);
  const [scanProfile, setScanProfile] = useState<ScanProfile>("standard");

  const [assets, setAssets] = useState<Partial<ScopeAsset>[]>([
    { rule: "allow", asset_type: "domain", value: "", active_allowed: true, authorization_verified: false },
  ]);
  const [grants, setGrants] = useState(DEFAULT_GRANTS);
  const [manualDefaultsApplied, setManualDefaultsApplied] = useState(false);

  // REQ-AUTH-006 (GitHub issue #12): opt-in only, inside the existing Tools
  // step - never a source picker, never a new step. Checking this sets
  // source="bug_bounty" internally when scope/tools are saved.
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

  const { data: toolCapabilities } = useQuery({
    queryKey: ["tool-capabilities"],
    queryFn: api.listToolCapabilities,
  });

  const toolsByCategory = useMemo(() => {
    const grouped: Record<ToolCategory, ToolCapability[]> = { recon: [], fingerprint: [], vuln: [], cred: [], exploit: [] };
    for (const tool of toolCapabilities?.tools ?? []) {
      if (TOOL_CATEGORIES.includes(tool.category as ToolCategory) && tool.enabled) {
        grouped[tool.category as ToolCategory].push(tool);
      }
    }
    for (const category of TOOL_CATEGORIES) grouped[category].sort((a, b) => a.name.localeCompare(b.name));
    return grouped;
  }, [toolCapabilities]);

  const passiveToolsByCategory = useMemo(() => {
    const grouped: Record<ToolCategory, ToolCapability[]> = { recon: [], fingerprint: [], vuln: [], cred: [], exploit: [] };
    for (const category of TOOL_CATEGORIES) {
      grouped[category] = toolsByCategory[category].filter((tool) => tool.execution_class === "passive");
    }
    return grouped;
  }, [toolsByCategory]);

  useEffect(() => {
    if (!toolCapabilities || manualDefaultsApplied) return;
    setGrants((current) => {
      const next = { ...current } as GrantState;
      for (const category of TOOL_CATEGORIES) {
        if (DEFAULT_MANUAL_TOOL_CATEGORIES.has(category)) {
          next[category] = { ...next[category], manualTools: toolsByCategory[category].map((tool) => tool.name) };
        }
      }
      return next;
    });
    setManualDefaultsApplied(true);
  }, [manualDefaultsApplied, toolCapabilities, toolsByCategory]);

  const filledAssets = assets.filter((asset) => asset.value?.trim());
  const allowAssets = filledAssets.filter((asset) => asset.rule === "allow");
  const activeAllowAssets = allowAssets.filter((asset) => asset.active_allowed);
  const requiresAllowAssets = true;
  const activeAuthorizationBlockers = activeAllowAssets.filter((asset) => !asset.authorization_verified);

  async function handleCreateEngagement() {
    // Found live 2026-08-09: the button had no submission-in-progress guard
    // at all, only form-validity checks - two impatient clicks (or one
    // double-click) fired two full POST /engagements before the first
    // response ever arrived to advance the wizard past step 1, silently
    // creating duplicate draft engagements with the identical title. This
    // early-return is defense in depth on top of the button's own
    // disabled={isCreating} below, in case anything ever dispatches this
    // handler a second way.
    if (isCreating) return;
    setError(null);
    if (authorizedFrom > authorizedUntil) {
      setError("Authorized from date must be on or before authorized until date.");
      return;
    }
    const firstPort = Number(tcpPortFrom);
    const lastPort = Number(tcpPortTo);
    if (!Number.isInteger(firstPort) || !Number.isInteger(lastPort) || firstPort < 1 || lastPort > 65535 || firstPort > lastPort) {
      setError("TCP ports must be an inclusive range from 1 to 65535; use the same value for one port.");
      return;
    }
    setIsCreating(true);
    try {
      const fields = {
        title,
        ai_testing_allowed: aiTestingAllowed,
        authorized_from: dateOnlyToIso(authorizedFrom),
        authorized_until: dateOnlyToIso(authorizedUntil, true),
        tcp_port_from: firstPort,
        tcp_port_to: lastPort,
        udp_discovery_enabled: udpDiscoveryEnabled,
        asset_review_enabled: assetReviewEnabled,
        ...discoveryFlags,
        scan_profile: scanProfile,
      };
      // GitHub issue #46: going back to step 1 and saving again used to POST a
      // second draft and orphan the first. A draft that already exists in this
      // session is edited in place. PATCH only applies fields that are sent,
      // so a cleared contact is sent as null (undefined would never clear it).
      const eng = engagementId
        ? await api.updateEngagement(engagementId, { ...fields, emergency_contact: emergencyContact || null })
        : await api.createEngagement({ ...fields, emergency_contact: emergencyContact || undefined } as any);
      ownDraftRef.current = eng.id; // this session made the draft: nothing to resume from the URL
      setEngagementId(eng.id);
      setSearchParams({ draft: eng.id }, { replace: true });
      setStep(2);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setIsCreating(false);
    }
  }

  // GitHub issue #46: resume a draft from ?draft=<id> after a reload or a
  // navigation away, instead of starting over and creating another draft. The
  // server enforces ownership (other users' ids answer 404) and only a draft
  // is resumable.
  useEffect(() => {
    if (!draftParam || engagementId || ownDraftRef.current === draftParam) return;
    let cancelled = false;
    (async () => {
      try {
        const [eng, scope, existingGrants] = await Promise.all([
          api.getEngagement(draftParam), api.listScopeAssets(draftParam), api.listToolGrants(draftParam),
        ]);
        if (cancelled) return;
        if (eng.status !== "draft") {
          setSearchParams({}, { replace: true });
          setError("That engagement is no longer a draft. Open it from the dashboard instead.");
          return;
        }
        setEngagementId(eng.id);
        setTitle(eng.title);
        setAuthorizedFrom(isoToDateOnly(eng.authorized_from));
        setAuthorizedUntil(isoToDateOnly(eng.authorized_until));
        setEmergencyContact(eng.emergency_contact ?? "");
        setAiTestingAllowed(eng.ai_testing_allowed);
        setTcpPortFrom(String(eng.tcp_port_from));
        setTcpPortTo(String(eng.tcp_port_to));
        setUdpDiscoveryEnabled(eng.udp_discovery_enabled);
        setAssetReviewEnabled(eng.asset_review_enabled);
        setDiscoveryFlags({
          subfinder_enabled: eng.subfinder_enabled, crawling_enabled: eng.crawling_enabled,
          oob_enabled: eng.oob_enabled, screenshots_enabled: eng.screenshots_enabled,
        });
        setScanProfile(eng.scan_profile);
        if (scope.length > 0) {
          setAssets(scope);
          setSavedAssets(scope.map((asset) => ({ id: asset.id, key: assetKey(asset) })));
        }
        if (existingGrants.length > 0) {
          const next = Object.fromEntries(
            TOOL_CATEGORIES.map((category) => [category, { passive: false, active: false, manualTools: [] as string[] }]),
          ) as GrantState;
          for (const grant of existingGrants) {
            const category = grant.tool_category as ToolCategory;
            if (!TOOL_CATEGORIES.includes(category)) continue;
            if (grant.mode === "passive") next[category].passive = true;
            if (grant.mode === "active") { next[category].active = true; next[category].manualTools = grant.manual_tools; }
          }
          setGrants(next);
          setManualDefaultsApplied(true); // the saved manual-approval choices win over the defaults
        }
        setStep(2);
      } catch {
        if (cancelled) return;
        setSearchParams({}, { replace: true });
        setError("Could not resume that draft. Start a new engagement instead.");
      }
    })();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draftParam]);

  function addAssetRow() {
    setAssets((current) => [...current, { rule: "allow", asset_type: "domain", value: "", active_allowed: false, authorization_verified: false }]);
  }

  function toggleManualTool(category: ToolCategory, toolName: string, checked: boolean) {
    setGrants((current) => {
      const existing = new Set(current[category].manualTools);
      if (checked) existing.add(toolName);
      else existing.delete(toolName);
      return { ...current, [category]: { ...current[category], manualTools: [...existing].sort() } };
    });
  }

  function manualToolCount() {
    return TOOL_CATEGORIES.reduce((count, category) => count + (grants[category].active ? grants[category].manualTools.length : 0), 0);
  }

  function categoryGrantSummary(category: ToolCategory) {
    const grant = grants[category];
    const passiveTools = passiveToolsByCategory[category];
    if (grant.active) {
      const manual = grant.manualTools.length;
      return `${toolsByCategory[category].length} active tool${toolsByCategory[category].length === 1 ? "" : "s"} available, ${manual} require${manual === 1 ? "s" : ""} approval`;
    }
    if (grant.passive && passiveTools.length > 0) return `Passive OSINT only: ${passiveTools.map((tool) => tool.name).join(", ")}.`;
    if (passiveTools.length > 0) return `Passive available: ${passiveTools.map((tool) => tool.name).join(", ")}.`;
    return "No passive tools in this category. Enable active only if target-touching checks are authorized.";
  }

  // GitHub issue #46: POST /scope-assets does not deduplicate, so saving step 3
  // a second time (after going back) used to duplicate every scope row. Only
  // rows that are new or were edited since the last save are sent; a saved row
  // that was edited is replaced (delete + add, there is no PATCH for scope
  // rows). Progress is recorded even when a call fails part-way, so a retry
  // never re-sends what already went through.
  async function syncScopeAssets(id: string) {
    const stale = [...savedAssets];
    const toAdd: Partial<ScopeAsset>[] = [];
    for (const asset of assets) {
      if (!asset.value?.trim()) continue;
      const at = stale.findIndex((saved) => saved.key === assetKey(asset));
      if (at >= 0) stale.splice(at, 1); // saved and unchanged
      else toAdd.push(asset);
    }
    let tracked = savedAssets;
    try {
      for (const old of stale) {
        await api.deleteScopeAsset(id, old.id);
        tracked = tracked.filter((saved) => saved.id !== old.id);
      }
      for (const asset of toAdd) {
        const created = await api.addScopeAsset(id, asset);
        tracked = [...tracked, { id: created.id, key: assetKey(asset) }];
      }
    } finally {
      setSavedAssets(tracked);
    }
  }

  async function handleSaveAssetsAndGrants() {
    if (!engagementId) return;
    setError(null);
    if (requiresAllowAssets && allowAssets.length === 0) {
      setError("Add at least one allow-scope asset with a domain, IP, CIDR, wildcard, or cloud account value before activation.");
      setStep(2);
      return;
    }
    if (activeAuthorizationBlockers.length > 0) {
      setError(`Active checks require authorization attestation for: ${activeAuthorizationBlockers.map((asset) => asset.value).join(", ")}`);
      setStep(2);
      return;
    }
    if (bountyEnabled && (!bountyPlatform.trim() || !bountyProgramRef.trim())) {
      setError("Bug bounty program: platform and program reference are required.");
      return;
    }
    if (bountyEnabled && bountyTcpSynScanProfile === "full" && !bountyNetworkScanEvidence.trim()) {
      setError("Bug bounty program: the 'full' network-scan tier requires a recorded authorization reason.");
      return;
    }
    try {
      await syncScopeAssets(engagementId);
      for (const category of TOOL_CATEGORIES) {
        const grant = grants[category];
        if (grant.passive && passiveToolsByCategory[category].length > 0) await api.addToolGrant(engagementId, { tool_category: category, mode: "passive", requires_manual_approval: false });
        if (grant.active) await api.addToolGrant(engagementId, {
          tool_category: category,
          mode: "active",
          requires_manual_approval: false,
          manual_tools: grant.manualTools,
        });
      }
      // REQ-AUTH-006: source is set here, internally, only as a side effect
      // of this one explicit opt-in - never a standalone picker.
      if (bountyEnabled) {
        await api.updateEngagement(engagementId, { source: "bug_bounty" });
        await api.addBountyProgram(engagementId, {
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
      }
      setStep(4);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function handleActivate() {
    if (!engagementId) return;
    setError(null);
    try {
      await api.activateEngagement(engagementId);
      navigate(`/engagements/${engagementId}/live`);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <section className="page-stack">
      <header className="page-header">
        <div>
          <span className="eyebrow">Rules of engagement</span>
          <h1>New engagement</h1>
          <p>Step {step} of 5</p>
        </div>
      </header>

      {error && <div className="error-block">{error}</div>}

      <div className="wizard-layout">
        <aside className="wizard-steps">
          {["Window", "Scope", "Tools", "Review", "Authorize"].map((label, index) => (
            <button key={label} className={step === index + 1 ? "selected" : ""} onClick={() => index + 1 < step && setStep(index + 1)}>
              <span>{index + 1}</span>{label}
            </button>
          ))}
        </aside>

        {step === 1 && (
          <section className="form-panel">
            <h2>Parties and test window</h2>
            <div className="form-grid">
              <label>Title<input value={title} onChange={(e) => setTitle(e.target.value)} /></label>
              <label>Emergency contact<input value={emergencyContact} placeholder="Who to call if a test causes problems (name, phone)" onChange={(e) => setEmergencyContact(e.target.value)} /></label>
              <label>Authorized from<input type="date" value={authorizedFrom} onChange={(e) => setAuthorizedFrom(e.target.value)} /></label>
              <label>Authorized until<input type="date" value={authorizedUntil} onChange={(e) => setAuthorizedUntil(e.target.value)} /></label>
            </div>
            <div className="form-grid">
              <label>Maximum authorized port range (from)<input type="number" min="1" max="65535" value={tcpPortFrom} onChange={(e) => setTcpPortFrom(e.target.value)} /></label>
              <label>Maximum authorized port range (to)<input type="number" min="1" max="65535" value={tcpPortTo} onChange={(e) => setTcpPortTo(e.target.value)} /></label>
            </div>
            <p className="muted-line">Default: all TCP ports (1-65535). Use the same start and end value to authorize one port only. This is a ceiling for the whole engagement - individual targets can narrow it further in the next step (Scope assets), but never widen it.</p>
            {/* REQ-CONSOLE-011: expert switches are optional and folded away; all default to off. */}
            <details className="advanced-options">
            <summary>Advanced options (discovery extras, UDP discovery, Vector Agent, asset review)</summary>
            <p className="muted-line">Discovery extras. Each one only ever works inside your scope and tool grants.</p>
            <DiscoverySwitches flags={discoveryFlags} onChange={setDiscoveryFlags} />
            <p className="muted-line">Scan depth. It only changes how many checks run on each web service.</p>
            <ScanDepth value={scanProfile} onChange={setScanProfile} />
            <label className="toggle-row">
              <input type="checkbox" checked={udpDiscoveryEnabled} onChange={(e) => setUdpDiscoveryEnabled(e.target.checked)} />
              <span>Enable bounded UDP discovery (53, 123, 161, 443, 500, 1900, 4500, 5060, 5353)</span>
            </label>
            <label className="toggle-row">
              <input type="checkbox" checked={aiTestingAllowed} onChange={(e) => setAiTestingAllowed(e.target.checked)} />
              <span>Allow Vector Agent autonomous proposals for this engagement</span>
            </label>
            <label className="toggle-row">
              <input type="checkbox" checked={assetReviewEnabled} onChange={(e) => setAssetReviewEnabled(e.target.checked)} />
              <span>Pause after discovery for manual asset review before scanning continues</span>
            </label>
            </details>
            <p className="muted-line">This saves a draft. Nothing is scanned until you authorize and activate the engagement in step 5.</p>
            <div className="form-actions">
              <button onClick={handleCreateEngagement} disabled={isCreating || !title || !authorizedFrom || !authorizedUntil}>
                {isCreating ? (engagementId ? "Saving…" : "Creating…") : engagementId ? "Save changes and continue" : "Save draft and continue"}
              </button>
            </div>
          </section>
        )}

        {step === 2 && (
          <section className="form-panel wide">
            <h2>Scope assets</h2>
            <div className="warning-block">Enter at least one allow-scope value before saving. Active scans require explicit authorization attestation for each active allow asset. Domain scope includes discovered subdomains automatically.</div>
            {assets.some((a) => a.asset_type === "cidr") && (
              <div className="warning-block">
                Host discovery for a CIDR range only probes TCP 80/443 (SYN, no ICMP) -
                a deliberate, bounded raw-egress policy. A host that answers on
                neither port will not be found by the sweep, and reads the same as a
                dead address in the results.
              </div>
            )}
            {requiresAllowAssets && allowAssets.length === 0 && (
              <div className="error-block">Missing allow-scope asset: enter a domain, IP, CIDR, wildcard, or cloud account value.</div>
            )}
            {activeAuthorizationBlockers.length > 0 && (
              <div className="error-block">Missing authorization attestation: {activeAuthorizationBlockers.map((asset) => asset.value).join(", ")}</div>
            )}
            <div className="scope-editor">
              {assets.map((asset, index) => (
                <div key={index} className="scope-row">
                  <select value={asset.rule} onChange={(e) => setAssets((rows) => rows.map((row, i) => i === index ? { ...row, rule: e.target.value as any } : row))}>
                    <option value="allow">allow</option>
                    <option value="deny">deny</option>
                  </select>
                  <select value={asset.asset_type} onChange={(e) => setAssets((rows) => rows.map((row, i) => i === index ? { ...row, asset_type: e.target.value as any } : row))}>
                    <option value="domain">domain</option>
                    <option value="wildcard">wildcard</option>
                    <option value="ip">ip</option>
                    <option value="cidr">cidr</option>
                    <option value="cloud_account">cloud_account</option>
                  </select>
                  <input placeholder="example.com" value={asset.value} onChange={(e) => setAssets((rows) => rows.map((row, i) => i === index ? { ...row, value: e.target.value } : row))} />
                  <input
                    className="port-input" type="number" min="1" max="65535" placeholder="port from"
                    title="Leave blank to inherit the engagement's maximum authorized port range"
                    value={asset.port_from ?? ""}
                    onChange={(e) => setAssets((rows) => rows.map((row, i) => i === index ? { ...row, port_from: e.target.value === "" ? null : Number(e.target.value) } : row))}
                  />
                  <input
                    className="port-input" type="number" min="1" max="65535" placeholder="port to"
                    title="Leave blank to inherit the engagement's maximum authorized port range"
                    value={asset.port_to ?? ""}
                    onChange={(e) => setAssets((rows) => rows.map((row, i) => i === index ? { ...row, port_to: e.target.value === "" ? null : Number(e.target.value) } : row))}
                  />
                  <label><input type="checkbox" checked={!!asset.active_allowed} onChange={(e) => setAssets((rows) => rows.map((row, i) => i === index ? { ...row, active_allowed: e.target.checked } : row))} /> active</label>
                  <label><input type="checkbox" checked={!!asset.authorization_verified} onChange={(e) => setAssets((rows) => rows.map((row, i) => i === index ? { ...row, authorization_verified: e.target.checked, authorization_method: e.target.checked ? "operator_authorization_attestation" : null } : row))} /> authorization attested</label>
                </div>
              ))}
            </div>
            <p className="muted-line">Port from/to are optional per target - leave blank to inherit the engagement's maximum authorized port range from step 1. A target's range can only narrow that ceiling, never widen it.</p>
            <div className="form-actions">
              <button onClick={addAssetRow}>Add scope row</button>
              <button onClick={() => setStep(3)}>Continue</button>
            </div>
          </section>
        )}

        {step === 3 && (
          <section className="form-panel wide">
            <h2>Tool grants</h2>
            <div className="mode-guide">
              <div><strong>Passive</strong><span>Allows OSINT/enrichment tools that query public or third-party data sources, such as certificate transparency or passive subdomain sources. It does not run target-touching checks.</span></div>
              <div><strong>Active</strong><span>Allows target-touching tools in that category after scope, time window, allowlist, and argument checks pass.</span></div>
              <div><strong>Manual approval</strong><span>Applies only to active tools. Selected tools stop at the gateway until an operator approves that exact call.</span></div>
            </div>
            <div className="responsive-table">
              <table className="data-table tool-grant-table">
                <thead>
                  <tr>
                    <th>Category</th>
                    <th>Allow passive</th>
                    <th>Allow active</th>
                    <th>Require approval for these active tools</th>
                  </tr>
                </thead>
                <tbody>
                  {TOOL_CATEGORIES.map((category) => (
                    <tr key={category}>
                      <td>
                        <strong>{category}</strong>
                        <span className="muted-line">{categoryGrantSummary(category)}</span>
                      </td>
                      <td>
                        {passiveToolsByCategory[category].length > 0 ? (
                          <label className="grant-toggle">
                            <input type="checkbox" checked={grants[category].passive} onChange={(e) => setGrants((g) => ({ ...g, [category]: { ...g[category], passive: e.target.checked } }))} />
                            <span>Passive allowed</span>
                            <small>{passiveToolsByCategory[category].map((tool) => tool.name).join(", ")}</small>
                          </label>
                        ) : (
                          <span className="muted-line">No passive tools</span>
                        )}
                      </td>
                      <td>
                        <label className="grant-toggle">
                          <input type="checkbox" checked={grants[category].active} onChange={(e) => setGrants((g) => ({ ...g, [category]: { ...g[category], active: e.target.checked } }))} />
                          <span>Active allowed</span>
                        </label>
                      </td>
                      <td>
                        {grants[category].active ? (
                          <div className="tool-approval-grid">
                            {toolsByCategory[category].map((tool) => (
                              <label key={tool.name}>
                                <input
                                  type="checkbox"
                                  checked={grants[category].manualTools.includes(tool.name)}
                                  onChange={(e) => toggleManualTool(category, tool.name, e.target.checked)}
                                />
                                <span>{tool.name}</span>
                                {!tool.dispatched && <small>catalog</small>}
                              </label>
                            ))}
                            {toolsByCategory[category].length === 0 && <span className="muted-line">No enabled tools in this category.</span>}
                          </div>
                        ) : (
                          <span className="muted-line">Not applicable until active is allowed.</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="warning-block">Manual approval is not a separate permission to run a category. A tool can ask for approval only after its category is active, the target is in scope, and the Scope Gateway would otherwise allow the call.</div>

            <div className="form-panel-section">
              <label className="grant-toggle">
                <input type="checkbox" checked={bountyEnabled} onChange={(e) => setBountyEnabled(e.target.checked)} />
                <span>This engagement follows a bug bounty program's rules of engagement</span>
              </label>
              <p className="muted-line">
                Enable this only for a real bug-bounty/VDP program (Intigriti, HackerOne, …) that requires
                self-identification and a request-rate cap. The platform then sends the identification below on
                every automated request to the target, including HTTPS.
              </p>
              {bountyEnabled && (
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
              )}
            </div>

            <div className="form-actions"><button onClick={() => setStep(2)}>Back</button><button onClick={handleSaveAssetsAndGrants}>Save scope and tools</button></div>
          </section>
        )}


        {step === 4 && (
          <section className="form-panel">
            <h2>Agent and guardrail review</h2>
            <dl className="definition-grid">
              <dt>Scope enforcement</dt><dd>Scope Gateway authorizes every active tool call</dd>
              <dt>Vector Agent opt-in</dt><dd>{aiTestingAllowed ? "enabled" : "disabled"}</dd>
              <dt>TCP discovery</dt><dd>{tcpPortFrom === tcpPortTo ? `port ${tcpPortFrom}` : `ports ${tcpPortFrom}-${tcpPortTo}`}</dd>
              <dt>UDP discovery</dt><dd>{udpDiscoveryEnabled ? "bounded profile enabled" : "disabled"}</dd>
              <dt>Asset review pause</dt><dd>{assetReviewEnabled ? "enabled (pauses after discovery)" : "disabled"}</dd>
              <dt>Discovery extras</dt><dd>{discoveryFlagSummary(discoveryFlags)}</dd>
              <dt>Scan depth</dt><dd>{scanDepthLabel(scanProfile)}</dd>
              <dt>Default posture</dt><dd>Bug-bounty style: non-destructive, scoped, budgeted checks</dd>
              <dt>Manual approvals</dt><dd>{manualToolCount()} explicit tools require approval</dd>
            </dl>
            <div className="form-actions"><button onClick={() => setStep(3)}>Back</button><button onClick={() => setStep(5)}>Review authorization</button></div>
          </section>
        )}

        {step === 5 && (
          <section className="form-panel">
            <h2>Authorization checklist</h2>
            <dl className="definition-grid">
              <dt>Engagement</dt><dd>{engagementId}</dd>
              <dt>Agent proposals</dt><dd>{aiTestingAllowed ? "enabled" : "disabled"}</dd>
              <dt>TCP discovery</dt><dd>{tcpPortFrom === tcpPortTo ? `port ${tcpPortFrom}` : `ports ${tcpPortFrom}-${tcpPortTo}`}</dd>
              <dt>UDP discovery</dt><dd>{udpDiscoveryEnabled ? "enabled (fixed bounded profile)" : "disabled"}</dd>
              <dt>Discovery extras</dt><dd>{discoveryFlagSummary(discoveryFlags)}</dd>
              <dt>Scan depth</dt><dd>{scanDepthLabel(scanProfile)}</dd>
              <dt>Allow scope assets</dt><dd>{allowAssets.length}</dd>
              <dt>Active allow assets</dt><dd>{activeAllowAssets.length}</dd>
              <dt>Manual approvals</dt><dd>{manualToolCount()} explicit tools</dd>
            </dl>
            {requiresAllowAssets && allowAssets.length === 0 && (
              <div className="error-block">Activation is blocked until at least one allow-scope asset has a value and has been saved.</div>
            )}
            {activeAuthorizationBlockers.length > 0 && (
              <div className="error-block">Activation is blocked until authorization is attested for: {activeAuthorizationBlockers.map((asset) => asset.value).join(", ")}</div>
            )}
            <div className="form-actions">
              {/* REQ-DOWNLOAD-001: authenticated fetch + Blob, not a bare anchor. */}
              {engagementId && (
                <button
                  className="secondary-action"
                  disabled={downloadingPdf}
                  onClick={async () => {
                    setDownloadingPdf(true);
                    setError(null);
                    try {
                      await api.downloadAuthorizationPdf(engagementId);
                    } catch (e) {
                      setError((e as Error).message);
                    } finally {
                      setDownloadingPdf(false);
                    }
                  }}
                >
                  {downloadingPdf ? "Preparing…" : "Download authorization PDF"}
                </button>
              )}
              <button onClick={handleActivate} disabled={(requiresAllowAssets && allowAssets.length === 0) || activeAuthorizationBlockers.length > 0}>Activate engagement</button>
            </div>
          </section>
        )}
      </div>
    </section>
  );
}
