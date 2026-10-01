// Reiner Client der bestehenden control-plane-API (Operator-Konsole UI Kap. 5.2).
// Die UI erzwingt nichts - alle Scope-/Freigabe-Entscheidungen bleiben im
// Scope Gateway serverseitig (Kap. 5.2 "UI erzwingt nichts - sie spiegelt").

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

export type ScanProfile = "standard" | "thorough";

export interface Engagement {
  id: string;
  title: string;
  source: "lab" | "own_domain" | "bug_bounty" | "customer";
  status: "draft" | "awaiting_signature" | "active" | "paused" | "completed" | "revoked";
  ai_testing_allowed: boolean;
  // The outer authorized ceiling for every target in this engagement.
  // Individual scope assets (see ScopeAsset.port_from/port_to) can narrow
  // this further per target; they can never widen it.
  tcp_port_from: number;
  tcp_port_to: number;
  udp_discovery_enabled: boolean;
  asset_review_enabled: boolean;
  // REQ-COVER-007: extended-discovery switches (subfinder on by default).
  subfinder_enabled: boolean;
  crawling_enabled: boolean;
  oob_enabled: boolean;
  screenshots_enabled: boolean;
  // REQ-PIPE-005: how deep a scan goes. Never widens scope, grants or switches.
  scan_profile: ScanProfile;
  authorized_from: string;
  authorized_until: string;
  emergency_contact: string | null;
  created_at: string;
  owner_user_id: string | null;
}

export interface EngagementUpdate {
  title?: string;
  authorized_from?: string;
  authorized_until?: string;
  emergency_contact?: string | null;
  ai_testing_allowed?: boolean;
  tcp_port_from?: number;
  tcp_port_to?: number;
  udp_discovery_enabled?: boolean;
  asset_review_enabled?: boolean;
  subfinder_enabled?: boolean;
  crawling_enabled?: boolean;
  oob_enabled?: boolean;
  screenshots_enabled?: boolean;
  scan_profile?: ScanProfile;
  // REQ-AUTH-001/003 (amended, GitHub issue #12): source stays hidden from
  // every ROUTINE edit - this field exists only so the one explicit "this
  // engagement follows a bug bounty program" toggle can set it. No other
  // save path in EngagementEdit.tsx may include it.
  source?: Engagement["source"];
}

// REQ-AUTH-006: a bug-bounty program's rules-of-engagement policy - the
// identification the platform is contractually required to send on every
// automated request once an operator opts an engagement into this.
export interface BountyProgram {
  id: string;
  engagement_id: string;
  platform: string;
  program_ref: string;
  automation_allowed: boolean;
  ai_testing_allowed: boolean;
  max_rps: number;
  max_concurrency: number;
  ident_header_name: string;
  ident_header_value: string | null;
  ua_suffix: string | null;
  // GitHub issue #37: explicit, opt-in per-program network-scan capability
  // tier - "none" (default) preserves the pre-existing host-discovery-only
  // raw-nmap policy exactly.
  tcp_syn_scan_profile: "none" | "common" | "full";
  raw_max_packets_per_second: number | null;
  network_scan_authorization_evidence: string | null;
}

export type BountyProgramInput = Omit<BountyProgram, "id" | "engagement_id">;

// REQ-COVER-003/006: what crawling and screenshots found.
export interface DiscoveredEndpoint {
  id: string;
  url: string;
  host: string;
  port: number;
  method: string;
  source: string;
  param_names: string[];
  first_seen_at: string | null;
}

export interface WebScreenshotMeta {
  id: string;
  url: string;
  host: string;
  port: number;
  byte_size: number;
  created_at: string | null;
}

// REQ-COVER-001: provider keys are write-only; the API only says whether one is set.
export interface SubfinderProvider { name: string; key_set: boolean }

export interface ScopeAsset {
  id: string;
  engagement_id: string;
  rule: "allow" | "deny";
  asset_type: "domain" | "wildcard" | "ip" | "cidr" | "cloud_account";
  value: string;
  path_pattern: string | null;
  active_allowed: boolean;
  authorization_verified: boolean;
  authorization_method: string | null;
  // null = inherit the engagement's tcp_port_from/to ceiling in full.
  port_from?: number | null;
  port_to?: number | null;
}

export type FindingStatus = "open" | "accepted_risk" | "false_positive" | "resolved";

/** An API call that got an HTTP error response; `status` lets callers tell
 * "does not exist / not yours" (404, or 422 for a malformed id) from a
 * network or server failure. The message is unchanged from before. */
export class ApiError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
    this.name = "ApiError";
  }
}

export function isNotFound(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 404 || error.status === 422);
}

export interface Finding {
  id: string;
  engagement_id: string;
  asset_id: string | null;
  service_id: string | null;
  asset_value: string | null;
  asset_type: string | null;
  target_ip: string | null;
  service_port: number | null;
  service_protocol: string | null;
  service_product: string | null;
  service_version: string | null;
  category: "cve" | "misconfig" | "exposure" | "logic";
  title: string;
  cve_ids: string[] | null;
  cvss_base: number | null;
  epss: number | null;
  confidence: "inferred" | "validated";
  status: FindingStatus;
  // REQ-TRIAGE-001: the last status change - why, when, and by whom ("scan" = reopened by a later scan).
  status_note: string | null;
  status_changed_at: string | null;
  status_changed_by: string | null;
  severity: "info" | "low" | "medium" | "high" | "critical" | null;
  risk_score: number | null;
  evidence: Record<string, unknown> | null;
  raw_ref: string | null;
  first_seen: string;
  last_seen: string | null;
}

// REQ-PORTFOLIO-001: GET /findings - findings across every engagement the
// caller can see. The server applies the ownership rule; the console only
// shows what it gets.
export interface PortfolioFinding extends Finding {
  engagement_title: string;
}

export interface FindingPage {
  items: PortfolioFinding[];
  total: number;
  limit: number;
  offset: number;
  counts_by_status: Record<FindingStatus, number>;
  counts_by_severity: Record<string, number>;
}

export interface FindingPageQuery {
  status?: FindingStatus;
  severity?: string;
  engagement_id?: string;
  q?: string;
  limit?: number;
  offset?: number;
}

export interface DnsRecord {
  id: string;
  asset_id: string | null;
  fqdn: string;
  cname_chain: string[];
  terminal_target: string | null;
  terminal_ips: string[];
  hosting_provider: string | null;
  is_cdn: boolean;
  is_saas: boolean;
  is_idp: boolean;
  is_shared_infra: boolean;
  dns_status: "resolved" | "dangling" | "unresolved";
  takeover_suspected: boolean;
  resolved_at: string;
}

// Attack-surface graph (REQ-GRAPH-004): a typed, relationship-native view of
// one engagement's discovered surface. Read-only - the graph never widens scope.
export interface SurfaceNode {
  id: string;
  node_type: "engagement" | "domain" | "subdomain" | "ip" | "service" | "technology" | "cve" | "finding" | "dns_artifact";
  ref_table: string;
  ref_id: string;
  label: string;
  scannable: boolean;
  attrs: Record<string, unknown>;
}

export interface SurfaceEdge {
  src: string;
  dst: string;
  edge_type: "HAS_SUBDOMAIN" | "RESOLVES_TO" | "HAS_SERVICE" | "RUNS_TECHNOLOGY" | "HAS_CVE" | "FINDING_AT" | "SHARES_INFRA";
  attrs: Record<string, unknown>;
}

export interface SurfaceGraph {
  nodes: SurfaceNode[];
  edges: SurfaceEdge[];
}

export interface ScanRun {
  id: string;
  engagement_id: string;
  phase: string;
  state: "running" | "done" | "failed" | "aborted" | string;
  budget_tool_calls_max: number;
  budget_tool_calls_used: number;
  started_at: string | null;
  finished_at: string | null;
  cancel_requested: boolean;
  state_reason: string | null;
  current_tool: string | null;
  current_target: string | null;
  current_started_at: string | null;
  scan_profile?: ScanProfile | null;
}

// REQ-PIPE-003/010: what a run planned, and what became of each check.
export type CheckState = "planned" | "running" | "complete" | "partial" | "failed" | "skipped";

export interface ScanPlanCheck {
  id: string;
  seq: number;
  check_id: string;
  tool: string;
  state: CheckState;
  reason: string;
  args: Record<string, unknown>;
  depends_on: string | null;
  budget_s: number | null;
  attempt: number;
  started_at: string | null;
  finished_at: string | null;
  duration_s: number | null;
  findings: number;
  outcome_summary: Record<string, unknown>;
}

export interface ScanPlanSurface {
  id: string;
  asset_id: string | null;
  host: string;
  ip: string | null;
  port: number;
  scheme: string | null;
  service_class: "web" | "web_alias" | "tls_service" | "service" | "unknown";
  alias_of: string | null;
  profile: string[];
  fingerprint: Record<string, unknown>;
  checks: ScanPlanCheck[];
}

export interface ScanPlan {
  scan_run_id: string;
  scan_profile: ScanProfile;
  state: string;
  summary: { checks: number; surfaces: number; by_state: Partial<Record<CheckState, number>> };
  surfaces: ScanPlanSurface[];
}

export interface ScanReadiness {
  ready: boolean;
  // GitHub issue #48: `action` names the GUI section where it is fixed ("tool_grants"), or null.
  blockers: { code: string; message: string; action?: string | null }[];
}

export interface AgentStep {
  id: string;
  iteration: number;
  request_messages: { role: string; content?: string; tool_calls?: unknown; tool_call_id?: string }[];
  response_text: string | null;
  response_tool_calls: { name: string; arguments: string }[] | null;
  stop_reason: string | null;
  created_at: string | null;
}

export interface ScanDiffItem {
  finding_id: string;
  title: string;
  severity: string | null;
  category: string | null;
  target: string | null;
  status: string | null;
  first_seen?: string | null;
}

export interface ScanDiff {
  run_id: string;
  previous_run_id: string | null;
  has_baseline: boolean;
  observed_count: number;
  new: ScanDiffItem[];
  resolved: ScanDiffItem[];
  persisting_count: number;
}


export interface FindingExplanation {
  finding_id: string;
  explanation: string;
  source: "cached" | "llm" | string;
  generated_at: string;
  model: string | null;
  truncated: boolean;
}

// REQ-REPORT-001: a generated customer report, in the job shape documented
// in the architecture (Kap. 6.3). job_id and report_id are the same value.
export interface ReportJob {
  job_id: string;
  report_id: string;
  status: "queued" | "done" | "failed" | string;
  scan_run_id: string | null;
  filename: string;
  byte_size: number;
  sha256: string | null;
  error: string | null;
  created_at: string | null;
}

export interface EngagementSummary {
  risk_ampel: string;
  counts_by_severity: Record<string, number>;
  counts_by_status: Partial<Record<FindingStatus, number>>;
  top_actions: string[];
}

export interface GatewayOverrideResult {
  applied: string[];
  message: string;
}

export interface ApprovalRequest {
  id: string;
  engagement_id: string;
  tool_call: Record<string, unknown>;
  state: string;
  approved_by: string | null;
  expires_at: string;
  approved_at?: string | null;
  execution_started_at?: string | null;
  execution_finished_at?: string | null;
  execution_error?: string | null;
}

export interface AssetReviewCandidate {
  asset_id: string;
  value: string;
  asset_type: string;
}

export interface AssetReview {
  id: string;
  engagement_id: string;
  scan_run_id: string;
  candidate_assets: AssetReviewCandidate[];
  state: string;
  excluded_values: string[] | null;
  expires_at: string;
  decided_at?: string | null;
  decided_by?: string | null;
}

export interface ToolCapability {
  name: string;
  category: string;
  execution_class: string;
  installed: boolean;
  enabled: boolean;
  worker_mapped: boolean;
  dispatched: boolean;
  has_parser: boolean;
  proxy_flag: string | null;
  proxy_verified: boolean;
  max_runtime_seconds: number;
  notes: string;
}

export interface ToolCapabilitiesResponse {
  tools: ToolCapability[];
  whitelist: Record<string, string[]>;
  enabled_but_not_installed: string[];
}

export interface ToolGrant {
  engagement_id: string;
  tool_category: string;
  mode: "passive" | "active";
  requires_manual_approval: boolean;
  manual_tools: string[];
}

// OpenAI-compatible provider shared by Vector Agent and Lens Agent.
// api_key wird nie zurueckgegeben (nur api_key_set) - das Formular sendet ihn
// nur, wenn er geaendert wird.
export interface LlmConfig {
  base_url: string;
  model: string;
  api_key_set: boolean;
  source: "db" | "env" | "unset";
  is_usable: boolean;
}


export interface ScanPolicy {
  max_rps: number;
  auto_throttle_enabled: boolean;
  source: "db" | "env";
}

export interface ScanPolicyUpdate {
  max_rps: number;
  auto_throttle_enabled: boolean;
}

export interface LlmConfigUpdate {
  base_url: string;
  model: string;
  api_key?: string; // weglassen -> gespeicherten Schluessel unveraendert lassen
}

// Optional NVD API key (REQ-CORR-008) - raises NVD's rate limit for live CVE
// correlation from 5/30s to 50/30s. Absent is a fully supported state.
export interface NvdConfig {
  api_key_set: boolean;
  source: "db" | "env" | "unset";
}

export interface NvdConfigUpdate {
  api_key?: string; // weglassen -> gespeicherten Schluessel unveraendert lassen
}

// Layered tool/agent configuration (global defaults + per-campaign overrides).
export interface ToolPolicyEntry {
  tool: string;
  category: string | null;
  installed: boolean | null;
  enabled: boolean;
  requires_approval: boolean;
}

export interface AgentPrompt {
  prompt: string;
  is_set: boolean;
}

export interface AgentMaxTokens {
  value: number;
}

export interface AgentMaxIterations {
  value: number;
}

export interface ApprovalTimeoutSeconds {
  value: number;
}

export interface EngagementToolConfig {
  tool: string;
  enabled: boolean;
  requires_approval: boolean;
  enabled_source: "registry" | "global" | "campaign";
  approval_source: "registry" | "global" | "campaign";
  category: string | null;
  installed: boolean;
  // GitHub issue #48: "enabled" says nothing about whether the category is granted here.
  granted: boolean;
  unavailable_reason: "not_installed" | "category_not_granted" | "off_for_campaign" | "off_in_settings" | "off_by_default" | null;
}

export interface EngagementConfig {
  tools: EngagementToolConfig[];
  agent_prompt: string;
  agent_prompt_overridden: boolean;
  agent_max_iterations: number;
  agent_max_iterations_overridden: boolean;
  approval_timeout_seconds: number;
  approval_timeout_seconds_overridden: boolean;
}

export interface EngagementConfigUpdate {
  tools: { tool: string; enabled: boolean | null; requires_approval: boolean }[];
  agent_prompt_override?: string | null;
  agent_max_iterations_override?: number | null;
  approval_timeout_seconds_override?: number | null;
}

// --- Auth (REQ-IAM-002..011) ------------------------------------------------

export interface UserInfo {
  id: string;
  email: string;
  display_name: string;
  role: "admin" | "operator";
  status: "invited" | "active" | "disabled";
}

export interface LoginChallenge {
  status: "set_password" | "mfa_enroll" | "mfa_verify";
  challenge_id: string;
}

export interface SessionResult {
  user: UserInfo;
  backup_codes?: string[] | null;
}

export interface MfaEnrollResult {
  challenge_id: string;
  secret: string;
  otpauth_uri: string;
}

export interface SessionInfo {
  id: string;
  ip_address: string | null;
  user_agent: string | null;
  created_at: string;
  last_seen_at: string;
  is_current: boolean;
}

export interface AdminUserCreateResult {
  user: UserInfo;
  temporary_password: string;
}

export interface AccountAuditRow {
  id: string;
  ts: string;
  actor_user_id: string | null;
  action: string;
  outcome: string;
  ip_address: string | null;
  payload: Record<string, unknown>;
}

export interface AuditRow {
  id: string;
  ts: string;
  actor: string;
  action: string;
  decision: string | null;
  reason: string | null;
  payload: Record<string, unknown>;
}

export interface AuditListResponse {
  entries: AuditRow[];
  has_more: boolean;
  next_before: string | null;
}

export interface AuditFacets {
  actors: string[];
  actions: string[];
}

export interface AuditQuery {
  q?: string;
  // REQ-AUDITUI-003: repeatable filters. An empty/omitted array means "no
  // actor/action filter" (show all), matching the backend, which only
  // narrows when at least one value is supplied.
  actor?: string[];
  action?: string[];
  decision?: string;
  limit?: number;
  before?: string;
}

// REQ-IAM-018/019: the session lives only in an HttpOnly cookie the browser
// sends by itself (credentials: "include"); no script ever sees the token.
// Earlier versions kept it in sessionStorage - purge any that is still there.
const LEGACY_SESSION_TOKEN_KEY = "asm_session_token";

export function clearSession(): void {
  try {
    sessionStorage.removeItem(LEGACY_SESSION_TOKEN_KEY);
    localStorage.removeItem(LEGACY_SESSION_TOKEN_KEY);
  } catch {
    // Storage can be blocked; there is nothing to clear then.
  }
}
clearSession();

// REQ-IAM-019: every request proves it comes from the console. A cross-site
// page cannot add this header without a CORS preflight, which the API refuses.
const CONSOLE_HEADERS = { "X-Requested-With": "asm-console" };

async function request<T>(path: string, init?: RequestInit, isRetry = false): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...CONSOLE_HEADERS,
      ...(init?.headers ?? {}),
    },
    credentials: "include",
  });
  if (res.status === 401 && !isRetry && path !== "/auth/login" && !path.startsWith("/auth/login/") && window.location.pathname !== "/login") {
    clearSession();
    window.location.assign(`/login?next=${encodeURIComponent(window.location.pathname)}`);
    // Navigation is async; throw so callers don't act on a bogus response.
    throw new Error("session expired - redirecting to /login");
  }
  if (!res.ok) {
    let detail = "";
    try {
      const payload = await res.json();
      if (typeof payload.detail === "string") detail = payload.detail;
      else if (Array.isArray(payload.detail)) detail = payload.detail.map((item: { msg?: string }) => item.msg ?? JSON.stringify(item)).join("; ");
    } catch {
      // Keep the status-only message if the response body is not JSON.
    }
    const suffix = detail ? `: ${detail}` : "";
    throw new ApiError(`${init?.method ?? "GET"} ${path} -> ${res.status}${suffix}`, res.status);
  }
  return res.status === 204 ? (undefined as T) : res.json();
}

/**
 * REQ-DOWNLOAD-001: fetch a binary document through the SAME authenticated
 * path as every other call, then hand the browser a Blob to save.
 *
 * A plain `<a href={url} target="_blank">` is not a fetch(): a 401 rendered
 * as a blank tab with no error anywhere. Going through fetch() surfaces the
 * real status and reason.
 */
async function downloadBlob(path: string, fallbackFilename: string): Promise<void> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: CONSOLE_HEADERS,
    credentials: "include",
  });
  if (!res.ok) {
    // Surface the real reason instead of a blank tab. The body is JSON for
    // FastAPI errors, but must not be assumed to be.
    let detail = "";
    try {
      const payload = await res.json();
      if (typeof payload.detail === "string") detail = payload.detail;
    } catch {
      // Non-JSON error body: the status alone is the message.
    }
    throw new Error(`GET ${path} -> ${res.status}${detail ? `: ${detail}` : ""}`);
  }

  // Prefer the server's own filename (Content-Disposition) so the saved file
  // matches what the audit trail recorded being generated.
  const disposition = res.headers.get("Content-Disposition") ?? "";
  const match = /filename="?([^";]+)"?/.exec(disposition);
  const filename = match?.[1] ?? fallbackFilename;

  const blob = await res.blob();
  const objectUrl = URL.createObjectURL(blob);
  try {
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
  } finally {
    // Always release the object URL, including if click() throws - otherwise
    // the blob stays pinned in memory for the lifetime of the document.
    URL.revokeObjectURL(objectUrl);
  }
}

export const api = {
  listEngagements: () => request<Engagement[]>("/engagements"),
  createEngagement: (body: Partial<Engagement> & { title: string; source?: Engagement["source"]; authorized_from: string; authorized_until: string; tcp_port_from?: number; tcp_port_to?: number; udp_discovery_enabled?: boolean }) =>
    request<Engagement>("/engagements", { method: "POST", body: JSON.stringify(body) }),
  getEngagement: (id: string) => request<Engagement>(`/engagements/${id}`),
  updateEngagement: (id: string, body: EngagementUpdate) =>
    request<Engagement>(`/engagements/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteEngagement: (id: string) => request<void>(`/engagements/${id}`, { method: "DELETE" }),
  activateEngagement: (id: string) => request<Engagement>(`/engagements/${id}/activate`, { method: "POST" }),
  startScan: (id: string) => request<{ task_id: string }>(`/engagements/${id}/scan`, { method: "POST" }),
  scanReadiness: (id: string) => request<ScanReadiness>(`/engagements/${id}/scan-readiness`),
  cancelScanRun: (id: string, runId: string) =>
    request<{ scan_run_id: string; cancel_requested: boolean; state: "aborted"; state_reason: string }>(
      `/engagements/${id}/scan-runs/${runId}/cancel`, { method: "POST" },
    ),
  agentSteps: (id: string, runId: string) => request<AgentStep[]>(`/engagements/${id}/scan-runs/${runId}/agent-steps`),
  listScanRuns: (id: string) => request<ScanRun[]>(`/engagements/${id}/scan-runs`),
  scanRunDiff: (id: string, runId: string) => request<ScanDiff>(`/engagements/${id}/scan-runs/${runId}/diff`),
  scanRunPlan: (id: string, runId: string) => request<ScanPlan>(`/engagements/${id}/scan-runs/${runId}/plan`),

  listScopeAssets: (id: string) => request<ScopeAsset[]>(`/engagements/${id}/scope-assets`),
  addScopeAsset: (id: string, body: Partial<ScopeAsset>) =>
    request<ScopeAsset>(`/engagements/${id}/scope-assets`, { method: "POST", body: JSON.stringify(body) }),
  deleteScopeAsset: (id: string, assetId: string) =>
    request<void>(`/engagements/${id}/scope-assets/${assetId}`, { method: "DELETE" }),
  verifyScopeAuthorization: (id: string, assetId: string, body = { method: "operator_authorization_attestation", verified_by: "operator" }) =>
    request<ScopeAsset>(`/engagements/${id}/scope-assets/${assetId}/verify-authorization`, { method: "POST", body: JSON.stringify(body) }),

  listAssetReviews: (id: string, state = "pending") =>
    request<AssetReview[]>(`/engagements/${id}/asset-reviews?state=${state}`),
  decideAssetReview: (id: string, reviewId: string, excludedValues: string[]) =>
    request<AssetReview>(`/engagements/${id}/asset-reviews/${reviewId}/decide`, {
      method: "POST", body: JSON.stringify({ excluded_values: excludedValues }),
    }),

  addToolGrant: (id: string, body: {
    tool_category: string; mode: string; requires_manual_approval: boolean; manual_tools?: string[];
    // GitHub issue #48: required when an ACTIVE category is added after the engagement left draft.
    confirm_widening?: boolean;
  }) =>
    request<ToolGrant>(`/engagements/${id}/tool-grants`, { method: "POST", body: JSON.stringify(body) }),
  removeToolGrant: (id: string, category: string, mode: string) =>
    request<void>(`/engagements/${id}/tool-grants/${category}/${mode}`, { method: "DELETE" }),
  listToolGrants: (id: string) => request<ToolGrant[]>(`/engagements/${id}/tool-grants`),
  listToolCapabilities: () => request<ToolCapabilitiesResponse>("/tools/capabilities"),

  // REQ-AUTH-006: upsert (not just create) - resubmitting corrects a typo'd
  // policy value without deleting/recreating the whole engagement.
  getBountyProgram: (id: string) => request<BountyProgram | null>(`/engagements/${id}/bounty-program`),
  addBountyProgram: (id: string, body: BountyProgramInput) =>
    request<BountyProgram>(`/engagements/${id}/bounty-program`, { method: "POST", body: JSON.stringify(body) }),
  applyGatewayOverride: (id: string, body: { reason: string; tool_call: Record<string, unknown>; approved_by?: string; comment?: string }) =>
    request<GatewayOverrideResult>(`/engagements/${id}/gateway-overrides`, { method: "POST", body: JSON.stringify(body) }),

  summary: (id: string) => request<EngagementSummary>(`/engagements/${id}/summary`),
  surfaceGraph: (id: string) => request<SurfaceGraph>(`/engagements/${id}/surface-graph`),
  discoveredEndpoints: (id: string) => request<DiscoveredEndpoint[]>(`/engagements/${id}/endpoints`),
  webScreenshots: (id: string) => request<WebScreenshotMeta[]>(`/engagements/${id}/screenshots`),
  screenshotImageUrl: (id: string, screenshotId: string) => `${BASE_URL}/engagements/${id}/screenshots/${screenshotId}/image`,
  getSubfinderKeys: () => request<{ providers: SubfinderProvider[] }>("/settings/subfinder"),
  setSubfinderKeys: (keys: Record<string, string | null>) =>
    request<{ providers: SubfinderProvider[] }>("/settings/subfinder", { method: "PUT", body: JSON.stringify({ keys }) }),
  dnsRecords: (id: string) => request<DnsRecord[]>(`/engagements/${id}/dns-records`),
  findings: (id: string, params?: { severity?: string; status?: string }) => {
    const qs = new URLSearchParams(params as Record<string, string>).toString();
    return request<Finding[]>(`/engagements/${id}/findings${qs ? `?${qs}` : ""}`);
  },
  allFindings: (query: FindingPageQuery) => {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== "") params.set(key, String(value));
    }
    const qs = params.toString();
    return request<FindingPage>(`/findings${qs ? `?${qs}` : ""}`);
  },
  // REQ-TRIAGE-001: a note is required for accepted_risk and false_positive.
  triageFinding: (id: string, findingId: string, body: { status: FindingStatus; note?: string }) =>
    request<Finding>(`/engagements/${id}/findings/${findingId}`, { method: "PATCH", body: JSON.stringify(body) }),
  explainFindingWithLens: (id: string, findingId: string) =>
    request<FindingExplanation>(`/engagements/${id}/findings/${findingId}/lens-explanation`, { method: "POST" }),
  // REQ-REPORT-001: generation is synchronous, so the returned job is already
  // terminal ("done" or "failed"). The job shape is the documented contract.
  requestReport: (id: string) => request<ReportJob>(`/engagements/${id}/report`, { method: "POST" }),
  listReports: (id: string) => request<ReportJob[]>(`/engagements/${id}/reports`),
  downloadReport: (id: string, reportId: string, filename: string) =>
    downloadBlob(`/engagements/${id}/reports/${reportId}`, filename),
  // REQ-DOWNLOAD-001: goes through the authenticated fetch path. The old
  // bare-URL helper was deliberately removed rather than left alongside this -
  // a plain navigable URL is exactly the broken pattern (no bearer header),
  // and leaving it exported invites its reuse.
  downloadAuthorizationPdf: (id: string) =>
    downloadBlob(`/engagements/${id}/authorization-pdf`, `axial-authorization-${id}.pdf`),

  listApprovals: (state = "requested") => request<ApprovalRequest[]>(`/approvals?state=${state}`),
  approveApproval: (id: string) =>
    request<ApprovalRequest>(`/approvals/${id}/approve`, { method: "POST", body: "{}" }),
  rejectApproval: (id: string) =>
    request<ApprovalRequest>(`/approvals/${id}/reject`, { method: "POST", body: "{}" }),

  // REQ-AUDITUI-001/002: unified searchable chronological audit log.
  listAudit: (id: string, query: AuditQuery = {}) => {
    const qs = new URLSearchParams();
    if (query.q) qs.set("q", query.q);
    // Repeated params (?actor=a&actor=b) - FastAPI reads these as a list.
    for (const value of query.actor ?? []) qs.append("actor", value);
    for (const value of query.action ?? []) qs.append("action", value);
    if (query.decision) qs.set("decision", query.decision);
    if (query.limit !== undefined) qs.set("limit", String(query.limit));
    if (query.before) qs.set("before", query.before);
    const suffix = qs.toString();
    return request<AuditListResponse>(`/engagements/${id}/audit${suffix ? `?${suffix}` : ""}`);
  },
  auditFacets: (id: string) => request<AuditFacets>(`/engagements/${id}/audit/facets`),

  streamUrl: (id: string, options?: { actions?: string[]; history?: boolean; limit?: number; scanRunId?: string }) => {
    const qs = new URLSearchParams();
    if (options?.actions?.length) qs.set("actions", options.actions.join(","));
    if (options?.history !== undefined) qs.set("history", String(options.history));
    if (options?.limit !== undefined) qs.set("limit", String(options.limit));
    if (options?.scanRunId) qs.set("scan_run_id", options.scanRunId);
    const suffix = qs.toString();
    return `${BASE_URL}/engagements/${id}/stream${suffix ? `?${suffix}` : ""}`;
  },

  getLlmConfig: () => request<LlmConfig>("/settings/llm"),
  updateLlmConfig: (body: LlmConfigUpdate) =>
    request<LlmConfig>("/settings/llm", { method: "PUT", body: JSON.stringify(body) }),
  getNvdConfig: () => request<NvdConfig>("/settings/nvd"),
  updateNvdConfig: (body: NvdConfigUpdate) =>
    request<NvdConfig>("/settings/nvd", { method: "PUT", body: JSON.stringify(body) }),
  getScanPolicy: () => request<ScanPolicy>("/settings/scan-policy"),
  updateScanPolicy: (body: ScanPolicyUpdate) =>
    request<ScanPolicy>("/settings/scan-policy", { method: "PUT", body: JSON.stringify(body) }),

  // Global tool policy (layer 2) + agent instructions (layer 3)
  getToolPolicy: () => request<ToolPolicyEntry[]>("/settings/tool-policy"),
  updateToolPolicy: (body: ToolPolicyEntry[]) =>
    request<ToolPolicyEntry[]>("/settings/tool-policy", { method: "PUT", body: JSON.stringify(body) }),
  getAgentPrompt: () => request<AgentPrompt>("/settings/agent-prompt"),
  updateAgentPrompt: (prompt: string) =>
    request<AgentPrompt>("/settings/agent-prompt", { method: "PUT", body: JSON.stringify({ prompt }) }),
  getAgentMaxIterations: () => request<AgentMaxIterations>("/settings/agent-max-iterations"),
  // REQ-AGENT-026
  getAgentMaxTokens: () => request<AgentMaxTokens>("/settings/agent-max-tokens"),
  updateAgentMaxTokens: (value: number) =>
    request<AgentMaxTokens>("/settings/agent-max-tokens", { method: "PUT", body: JSON.stringify({ value }) }),
  updateAgentMaxIterations: (value: number) =>
    request<AgentMaxIterations>("/settings/agent-max-iterations", { method: "PUT", body: JSON.stringify({ value }) }),
  getApprovalTimeoutSeconds: () => request<ApprovalTimeoutSeconds>("/settings/approval-timeout-seconds"),
  updateApprovalTimeoutSeconds: (value: number) =>
    request<ApprovalTimeoutSeconds>("/settings/approval-timeout-seconds", { method: "PUT", body: JSON.stringify({ value }) }),

  // Per-campaign config (layers 4/5): effective view + overrides
  getEngagementConfig: (id: string) => request<EngagementConfig>(`/engagements/${id}/config`),
  updateEngagementConfig: (id: string, body: EngagementConfigUpdate) =>
    request<EngagementConfig>(`/engagements/${id}/config`, { method: "PUT", body: JSON.stringify(body) }),

  // --- Auth (REQ-IAM-002..011) ---
  login: (email: string, password: string) =>
    request<LoginChallenge>("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  setFirstPassword: (challenge_id: string, new_password: string) =>
    request<LoginChallenge>("/auth/password/set-first", { method: "POST", body: JSON.stringify({ challenge_id, new_password }) }),
  mfaEnroll: (challenge_id: string) =>
    request<MfaEnrollResult>("/auth/mfa/enroll", { method: "POST", body: JSON.stringify({ challenge_id }) }),
  mfaEnrollConfirm: (challenge_id: string, code: string) =>
    request<SessionResult>("/auth/mfa/enroll/confirm", { method: "POST", body: JSON.stringify({ challenge_id, code }) }),
  loginMfa: (challenge_id: string, code: string) =>
    request<SessionResult>("/auth/login/mfa", { method: "POST", body: JSON.stringify({ challenge_id, code }) }),
  logout: () => request<void>("/auth/logout", { method: "POST" }),
  me: () => request<UserInfo>("/auth/me"),
  // GitHub issue #26: both revoke every OTHER session for this account and
  // rotate this one - the browser picks up the new session cookie by itself.
  changePassword: (current_password: string, new_password: string) =>
    request<SessionResult>("/auth/change-password", { method: "POST", body: JSON.stringify({ current_password, new_password }) }),
  listSessions: () => request<SessionInfo[]>("/auth/sessions"),
  revokeSession: (id: string) => request<void>(`/auth/sessions/${id}`, { method: "DELETE" }),
  mfaReenrollStart: (current_password: string) =>
    request<{ secret: string; otpauth_uri: string }>("/auth/mfa/reenroll/start", { method: "POST", body: JSON.stringify({ current_password }) }),
  mfaReenrollConfirm: (code: string) =>
    request<{ backup_codes: string[] }>("/auth/mfa/reenroll/confirm", { method: "POST", body: JSON.stringify({ code }) }),

  // --- Admin (REQ-IAM-008/009) ---
  adminListUsers: () => request<UserInfo[]>("/admin/users"),
  adminCreateUser: (email: string, display_name: string, role: "admin" | "operator") =>
    request<AdminUserCreateResult>("/admin/users", { method: "POST", body: JSON.stringify({ email, display_name, role }) }),
  adminUpdateUser: (id: string, body: { role?: string; status?: string }) =>
    request<UserInfo>(`/admin/users/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  adminResetPassword: (id: string) =>
    request<{ temporary_password: string }>(`/admin/users/${id}/reset-password`, { method: "POST" }),
  adminResetMfa: (id: string) => request<void>(`/admin/users/${id}/reset-mfa`, { method: "POST" }),
  adminListAudit: (limit = 200) => request<AccountAuditRow[]>(`/admin/audit?limit=${limit}`),

  // Admin-only engagement ownership reassignment (REQ-IAM-007)
  reassignEngagementOwner: (id: string, owner_user_id: string) =>
    request<Engagement>(`/engagements/${id}/owner`, { method: "PUT", body: JSON.stringify({ owner_user_id }) }),
};
