import { type ScanRun } from "../api/client";
import { PHASE_META, PHASES, type PhaseId } from "./runs";

export interface RunLogEntry {
  ts: string;
  actor: string;
  action: string;
  decision: string | null;
  reason: string | null;
  payload?: Record<string, unknown>;
}

export type ActivityTone = "success" | "attention" | "danger" | "info" | "neutral";

export interface ActivityFact {
  label: string;
  value: string;
}

export interface HumanActivity {
  id: string;
  phase: PhaseId;
  title: string;
  summary: string;
  outcome: string;
  tone: ActivityTone;
  routine: boolean;
  tool?: string;
  target?: string;
  facts: ActivityFact[];
  reasonCode?: string;
  errorSummary?: string;
  // The full, worker-redacted request/response text for a tool step where
  // the raw exchange itself is the evidence (currently only http_request) -
  // shown verbatim in Technical details, never summarized further.
  rawDetail?: string;
  source: string;
  decision: string | null;
  ts: string;
  countsAsCompletedTool?: boolean;
  countsAsBlocked?: boolean;
  countsAsAttention?: boolean;
}

export interface RunActivitySummary {
  headline: string;
  detail: string;
  completedTools: number;
  discoveredServices: number;
  blockedActions: number;
  attentionItems: number;
}

const PHASE_SET = new Set<string>(PHASES);

const REASON_COPY: Record<string, string> = {
  all_checks_passed: "Scope, authorization, schedule, tool, and rate checks passed.",
  gateway_allowed: "The Scope Gateway confirmed that the target and action are authorized.",
  completed: "The tool returned a successful terminal result.",
  explicit_out_of_scope: "A deny rule matched this target. Nothing was sent to it.",
  target_out_of_scope: "No active allow-scope matched this target. Nothing was sent to it.",
  active_not_allowed: "The target is in scope, but active testing is not authorized.",
  no_tool_grant: "This engagement does not grant the tool category and mode this call needs. Add the grant under Edit engagement → Tool grants.",
  tool_not_whitelisted: "The requested tool is not enabled by the safety registry.",
  unsafe_arguments: "The proposed arguments did not pass the deterministic safety policy.",
  outside_time_window: "The authorized testing window is not currently open.",
  engagement_not_active: "The engagement is not active.",
  asset_held_for_review: "This host is held: the monitor found it and keeps it out of the tests until the owner releases it. Nothing was sent to it, by the scan or by the Vector Agent. Release it from its inbox item or choose it on Review targets.",
  ai_testing_not_enabled: "Vector Agent proposals are not enabled for this engagement.",
  credential_tool_not_allowed: "A test account's credential may only be used in an HTTP request, never in another tool. Nothing was sent.",
  credential_host_not_usable: "A test account may only be used on the hosts it is assigned to, and only while they are usable (not held, denied, flagged as a possible takeover or suspended). Nothing was sent.",
  credential_wrong_use: "A test account's password is only for its own login request. Nothing was sent.",
  login_attempt_limit: "The login of this test account was already tried the allowed number of times on this host in this run, so it is not tried again. Nothing was sent.",
  testaccount_login: "The monitor's declared login, covered by the owner's login consent, was allowed without a per-call approval.",
  credential_unresolvable: "The test account was no longer available when the request was about to go out, so it was not sent.",
  rate_limited: "The configured request rate is exhausted. The action was not sent.",
  rate_limited_wait: "The worker paused for the configured rate limit and will retry.",
  budget_exhausted: "The run used its configured tool-call budget.",
  pending_approval: "The action is waiting for a one-time operator decision.",
  awaiting_operator_approval: "The action is waiting for a one-time operator decision.",
  manual_approval: "The operator approved this one stored action.",
  manual_rejection: "The operator rejected this action. It was not sent.",
  llm_provider_usable: "The configured model endpoint and model are available.",
  llm_provider_missing: "Vector Agent was skipped because its provider configuration is incomplete.",
  openai_sdk_missing: "Vector Agent was skipped because the required client library is unavailable.",
  no_in_scope_assets: "Vector Agent had no in-scope discovered assets to evaluate.",
  requesting_next_action: "Vector Agent is choosing the next check from the available evidence.",
  llm_proposed_tool: "Vector Agent proposed a scoped validation tool.",
  llm_proposed_http_request: "Vector Agent proposed an HTTP request.",
  llm_proposed_content_discovery: "Vector Agent proposed bounded content discovery.",
  tool_observed: "The executed tool result was returned to Vector Agent.",
  tool_observed_after_approval: "The approved tool result was returned to Vector Agent.",
  empty_proposal: "The model proposal contained no executable action, so it was skipped.",
  unknown_tool: "The model proposed a tool outside the supported safety registry. Nothing was executed.",
  not_in_scope_list: "The proposed target was not in the agent evidence scope. Nothing was sent.",
  reauthorized: "The approved stored action passed a fresh Scope Gateway check.",
  runner_execution_failed: "The isolated tool runner could not complete the approved action.",
  agent_reported: "Vector Agent recorded a validated finding from the available evidence.",
  llm_finished_without_tool: "Vector Agent returned a complete text conclusion without another tool call.",
  llm_finish: "Vector Agent requested the end of its analysis.",
  agent_phase_started: "Vector Agent started attack-path validation from deterministic scan evidence.",
  agent_phase_finished: "Vector Agent completed its attack-path validation phase.",
  finish_reason_length: "The model output limit was reached. The incomplete response was not executed.",
  empty_response: "The model returned no answer or tool calls. No action was executed.",
  llm_call_failed: "The model provider request failed. Deterministic scan results remain available.",
  cancelled_by_operator: "The operator requested a cooperative stop.",
  // GitHub issue #49 (REQ-PIPE-021): safety stops and internal errors say what really happened.
  cancellation_status_unavailable:
    "The control plane could not say whether the operator had cancelled the run, so target-facing work was stopped as a safety measure. " +
    "Nothing was left out on purpose; start the scan again.",
  task_time_limit_exceeded: "The scan ran into the worker's task time limit and was stopped.",
  pipeline_error: "The scan stopped because of an internal error; this older run did not record which one.",
  deterministic_full_scan_only: "Full Nmap discovery is pipeline-owned and was not repeated by Vector Agent.",
  raw_egress_unavailable: "The raw network path (the lease gateway) was unavailable.",
  lease_issued: "A short-lived scope-bound network rule was issued for Nmap.",
  raw_egress_lease_denied: "The scope-bound raw network rule was not issued, so Nmap was not started.",
  // REQ-SCAN-016/017 (GitHub #77)
  resolved_target_blocked_address: "The name resolves to an address that can never be a scan target (this machine itself, a link-local or cloud-metadata address, a multicast or reserved address), so no network rule was issued and nothing was sent. Check the name's DNS records.",
  ipv6_scanning_off: "IPv6 port scanning is switched off on this installation, so this IPv6 address of the host was not scanned. Its IPv4 address was. An administrator can switch it on again.",
  raw_egress_queue_timeout: "The shared Nmap gateway queue did not become available within its bounded wait time.",
  raw_egress_queue_cancelled: "The queued Nmap request was removed because this run was stopped.",
  raw_egress_queue_or_dispatch_failed: "The shared Nmap gateway could not safely schedule or start this scan.",
  raw_egress_heartbeat_failed: "The active Nmap network lease lost its heartbeat and was closed.",
  raw_egress_reservation_release_failed: "The Nmap queue slot could not be confirmed as released.",
  probes_dropped: "The scanner's own firewall refused to send some of nmap's probes, so ports that are open may have looked silent. Treat this port list as incomplete and scan again.",
  ports_no_longer_open: "Ports that earlier runs found open were not found this time, even after a second, slower check. They may have been closed, or the target may be blocking the scanner. Check the target before relying on this list.",
  udp_results_ambiguous: "UDP returned only filtered or open-or-filtered states. This is inconclusive, not a clean target.",
  udp_no_port_states: "UDP returned no port states. This is incomplete, not a clean target.",
  udp_discovery_not_enabled: "Bounded UDP discovery is not enabled for this engagement.",
  scan_run_missing: "No valid scan-run context was available, so the tool was not started.",
  // REQ-EXPLAIN-003: the cause is the NAME (it has no DNS address), for raw and HTTP tools alike.
  materialized_ip_missing: "This name has no DNS address, so nothing was sent to it. Usually nothing needs doing (an old, internal or retired name). If it should resolve, fix its DNS record; if it should not be scanned, add a deny rule or remove it from the scope.",
  dns_resolution_failed: "The target name could not be resolved to an audited IP.",
  zero_targets_scanned: "Nmap did not scan a target. This is a failed result, not a clean target.",
  runner_dispatch_failed: "The isolated tool runner could not execute the request.",
  nonzero_exit: "The tool exited with an error.",
  runner_reported_failure: "The isolated runner reported an unsuccessful execution.",
  egress_proxy_blocked: "The network egress policy blocked the request.",
  egress_proxy_unreachable: "The scanner could not reach its own egress proxy, so nothing was sent. This is a failed check, not a clean result: run it again once an administrator has confirmed that the scanner is healthy.",
  cancelled: "The waiting approval or action was cancelled.",
  rejected: "The operator rejected the requested action.",
  expired: "The approval expired before execution.",
  // REQ-EXPLAIN-001: refusals by the Scope Gateway. Nothing was sent in any of these.
  ai_testing_forbidden: "This bug-bounty program does not allow AI-driven testing, so the Vector Agent's proposal was refused. Only the program's own policy can change that: check Edit engagement → Bug bounty program policy.",
  approval_call_mismatch: "The approved action no longer matches the stored request, so it was not run. Request it again.",
  approval_expired: "The approval ran out before the action started. Request the action again.",
  approval_not_found: "No approval exists for this action on this engagement, so it was not run.",
  automation_forbidden: "This bug-bounty program does not allow automated tools, so the call was refused. Check the program policy under Edit engagement.",
  bounty_program_missing: "A bug-bounty engagement needs its program policy before anything is sent. Fill in Bug bounty program policy under Edit engagement.",
  crawling_not_enabled: "Crawling and URL history are switched off for this engagement. Switch them on under Edit engagement → Discovery extras if you want them.",
  endpoint_out_of_scope: "The URL, or the address it points to, is not covered by an allow rule, or a deny rule matches it. Change the scope only if you are authorized to test it.",
  engagement_not_found: "The engagement for this call does not exist, so the call was refused.",
  oob_not_enabled: "Out-of-band testing is switched off for this engagement. Switch it on under Edit engagement → Discovery extras if you want it.",
  passive_not_supported: "This tool cannot run in passive mode, so the call was refused.",
  risk_statement_required: "A request that changes state needs a stated reason before an operator can approve it. This proposal had none, so it was not made.",
  scan_run_cancelled: "The run was stopped, so it accepts no further calls.",
  scan_run_not_active: "The run was not doing work at that moment (it had finished or stopped, was parked for a decision, or was paused for a review of discovered hosts), so this call was refused.",
  scan_run_not_found: "There is no such run on this engagement, so the call was refused.",
  scan_run_required: "This kind of call must belong to a running scan. It had no run attached, so it was refused.",
  screenshots_not_enabled: "Web screenshots are switched off for this engagement. Switch them on under Edit engagement → Discovery extras if you want them.",
  screenshots_not_permitted_for_bounty: "Screenshots are not taken where a bug-bounty program requires an identification header, because the browser cannot attach it to every request.",
  subfinder_not_enabled: "Passive subdomain sources (subfinder) are switched off for this engagement. Switch them on under Edit engagement → Discovery extras.",
  target_is_range_not_permitted_for_tool: "Only Nmap may be pointed at an address range. This tool was refused for a range.",
  tool_disabled: "This tool is switched off, in this engagement's tool list or in the admin settings. Switch it on under Edit engagement → Campaign tool overrides, or ask an administrator.",
  tool_not_agent_callable: "This tool belongs to the fixed scan pipeline; the Vector Agent cannot call it, so nothing was executed.",
  // Why a tool did not finish.
  content_discovery_catch_all: "The site answers every path with the same page, so content discovery cannot tell hits from misses. Read \"no hits\" as not checked, not as clean.",
  dns_rematerialization_failed: "The names could not be looked up again just before the tool started, so it did not run. Check that DNS answers, then run again.",
  not_a_tls_service: "The port speaks plain HTTP or another protocol, so there is no TLS to test. Nothing to do.",
  raw_egress_revoke_failed: "The short-lived network rule for Nmap could not be confirmed as closed. An administrator should check the raw egress gateway.",
  budget_reached: "The check stopped at its own time budget. Everything it printed before that is real, but it did not finish, so it is not a clean result. Run it again or raise the budget if the target is slow.",
  raw_egress_activation_or_dispatch_failed: "The short-lived network rule for the port scan could not be opened or the scan could not be started, so nothing was sent. Run the scan again; if it repeats, an administrator should check the raw egress gateway.",
  raw_egress_reservation_failed: "The scan could not reserve its slot at the raw egress gateway, so nothing was sent. Run it again; if it repeats, an administrator should check the gateway.",
  udp_port_profile_invalid: "The UDP port list of this engagement is not valid, so the UDP discovery did not run. Correct the UDP settings under Edit engagement.",
  raw_scan_incomplete: "The port scan did not run to the end, so its port list is incomplete. Run the scan again.",
  runner_error: "The isolated tool runner reported an error while executing the tool. Open the technical details; if it repeats, an administrator should check that the runner is up.",
  screenshot_empty: "The browser produced no screenshot of this page. The page may need a login or may block automated browsers.",
  selection_unavailable: "The template selection for this check could not be read from the scanner image, so the check did not run. An administrator should check that the tool runner image is current.",
  subfinder_not_installed: "Subfinder is not installed in the tool runner. An administrator needs to rebuild the runner image.",
  subfinder_timeout: "Subfinder did not finish within its time limit. Public sources can be slow; run again later.",
  unsafe_domain: "The domain name did not pass the safety check for tool arguments, so the tool was not started.",
  approval_claim_denied: "The action was approved, but the Scope Gateway checked it again before running and no longer allowed it (for example the window ended, the scope changed or the engagement was paused). It was not run.",
  approval_not_claimable: "The approval could not be used (it was already used, rejected or has run out), so the action was not run. Request it again.",
  handler_error: "The scan's own handler for this check stopped with an error. Results found before that are kept. Run the scan again; if it repeats, report it with the technical details.",
  oob_unavailable: "The platform's interaction server is not set up, so the templates that confirm through a callback (blind injection, SSRF, XXE and the CVE templates that call back) could not run. The Plan tab names them. Templates that do not need a callback ran as usual. Nothing to do unless you need it; ask an administrator.",
  // Why a run stopped.
  asset_review_expired: "Nobody confirmed the discovered hosts in time, so the run stopped. Start it again and decide before the timeout.",
  asset_review_pending: "The run waits for you to confirm which discovered hosts may be scanned. Open the run and confirm them.",
  // REQ-APPROVAL-008: the run shows this while one action waits for a decision; its other actions go on.
  approval_wait: "One action of this run is waiting for your decision. The rest of the scan carries on. The waiting action runs only if you approve it.",
  reaped_stale_heartbeat: "The run stopped reporting progress (the worker probably restarted), so it was closed. Start the scan again.",
  // Retest and open items (REQ-RETEST-002/003/007).
  not_in_this_run: "This run only ran the checks that were chosen, so it did not look at this one. That says nothing about the check: it is not a failure and nothing is missing.",
  run_ended_early: "The run ended before this check ran, so nothing is known about it. Run it again from the Not done yet page.",
  not_sent: "The request you confirmed was not sent. The Scope Gateway checked it again and refused it, or the confirmation ran out. It is open again, nothing was lost",
};

const TOOL_LABELS: Record<string, string> = {
  nmap: "Nmap",
  httpx: "HTTPX",
  http_request: "HTTP request",
  testssl: "TLS test",
  nuclei: "Nuclei",
  nikto: "Nikto",
  katana: "Crawler",
  screenshot: "Screenshot",
  wafw00f: "WAF detection",
  ffuf: "Content discovery",
  subfinder: "Subdomain discovery",
  amass: "Asset discovery",
};

function text(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return "";
}

function numberValue(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() && Number.isFinite(Number(value))) return Number(value);
  return 0;
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function capitalize(value: string): string {
  return value ? value.charAt(0).toUpperCase() + value.slice(1) : value;
}

function toolLabel(value: unknown): string {
  const raw = text(value);
  if (!raw) return "Tool";
  return TOOL_LABELS[raw] ?? humanize(raw);
}

export function humanize(value: string | null | undefined): string {
  const raw = (value ?? "").trim();
  if (!raw) return "System event";
  return raw
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

// A run's state_reason may carry one or more compound, prefixed warnings
// (e.g. "coverage_degraded:nmap=zero_targets_scanned; agent_incomplete:...").
// Exact REASON_COPY lookup cannot match those, so they are expanded here.
function compoundReasonExplanation(reason: string): string | null {
  if (reason.startsWith("coverage_degraded:")) {
    const detail = reason.slice("coverage_degraded:".length);
    const items = detail.split(",").map((part) => part.trim()).filter(Boolean);
    // REQ-BUDGET-002: the run used up its tool-call budget; this is not a tool failing.
    const budgetItem = items.find((part) => /^tool_call_budget=exhausted_\d+_denied/.test(part));
    const denied = budgetItem ? Number(/exhausted_(\d+)_denied/.exec(budgetItem)?.[1] ?? 0) : 0;
    // REQ-TESTACCT-008: a login that was rejected, or an account that never got a session.
    const authLost = items.includes("authenticated_coverage_lost");
    const tools = items
      .filter((part) => part !== budgetItem && part !== "authenticated_coverage_lost")
      .map((part) => part.split("=")[0])
      .filter(Boolean)
      .join(", ");
    const budgetText = budgetItem
      ? `The run used up its tool-call budget: ${denied} planned call${denied === 1 ? " was" : "s were"} refused, ` +
        `so the checks behind them did not run. A short findings list does NOT mean those services are clean. ` +
        `An administrator can raise the budget in Admin → Operational settings. `
      : "";
    const toolText = tools
      ? `Reduced detection coverage: ${tools} was attempted but never once succeeded during this run, ` +
        `so this result is NOT a clean bill of health — parts of the attack surface were never actually examined. `
      : "";
    const authText = authLost
      ? "Authenticated coverage was lost: a test account's login was rejected, or never produced a session, so what sits behind the login was " +
        "NOT tested. This is not a clean result. Check the account under Test accounts. "
      : "";
    return `${budgetText}${toolText}${authText}Technical detail: ${detail}.`;
  }
  if (reason.startsWith("coverage_partial:")) {
    const detail = reason.slice("coverage_partial:".length);
    const tools = detail
      .split(",")
      .map((part) => part.split("=")[0])
      .filter(Boolean)
      .join(", ");
    const portScan = detail.split(",").some((part) => part.startsWith("nmap="));
    return (
      `Partial coverage: at least one ${tools || "check"} check stopped at its time budget before it finished` +
      (portScan ? ", or a port scan has gaps (lost probes, an address of a host that could not be scanned, or ports no longer found)" : "") +
      `. Everything it reported before that is real, but a short findings list does NOT mean the ` +
      `examined surface is clean. Technical detail: ${detail}.`
    );
  }
  if (reason.startsWith("pipeline_error:")) {
    const [, type = "an error", phase = "an unknown"] = reason.split(":");
    return (
      `The scan stopped because of an internal error (${type}) while it was in the ${phase} phase. ` +
      `Results found before that are kept. Technical detail: ${reason}.`
    );
  }
  if (reason.startsWith("agent_incomplete:")) {
    return (
      `The Vector Agent phase ended before it finished its plan ` +
      `(${humanize(reason.slice("agent_incomplete:".length))}). Deterministic phases are unaffected.`
    );
  }
  return null;
}

// REQ-EXPLAIN-002: a reason the console has no text for is shown as unexplained, with its code, and logged. It
// is never dressed up as an explanation ("Gateway Denied:No Tool Grant" reads like one and is not).
export const UNEXPLAINED = "Unexplained reason";
const reportedUnexplained = new Set<string>();

function explainPart(part: string): string {
  const exact = REASON_COPY[part];
  if (exact) return exact;
  const compound = compoundReasonExplanation(part);
  if (compound) return compound;
  // A code with a detail after a colon: the Scope Gateway's refusal of a call, or a family such as
  // approval_claim_denied:<why>, handler_error:<type>.
  const colon = part.indexOf(":");
  if (colon > 0) {
    const head = part.slice(0, colon);
    const detail = part.slice(colon + 1);
    if (head === "gateway_denied") return `The Scope Gateway refused this call. ${explainPart(detail)}`;
    if (REASON_COPY[head]) return `${REASON_COPY[head]} (${detail}).`;
  }
  if (!reportedUnexplained.has(part)) {
    reportedUnexplained.add(part);
    console.warn(`The console has no description for the reason code "${part}".`);
  }
  return `${UNEXPLAINED}: ${part}. The console has no description for this code yet.`;
}

export function reasonExplanation(reason: string | null | undefined): string {
  if (!reason) return "No additional explanation was recorded.";
  // Independent warnings are joined with "; " and each is explained on its own.
  const parts = reason.split(";").map((p) => p.trim()).filter(Boolean);
  if (parts.length === 0) return "No additional explanation was recorded.";
  return parts.map(explainPart).join(" ");
}

export function activityKey(entry: RunLogEntry): string {
  return [
    entry.ts,
    entry.actor,
    entry.action,
    entry.decision ?? "",
    entry.reason ?? "",
    JSON.stringify(entry.payload ?? {}),
  ].join("|");
}

export function scopeEntriesToRun(entries: RunLogEntry[], run: ScanRun | undefined): RunLogEntry[] {
  if (!run?.started_at) return [];
  const started = new Date(run.started_at).getTime();
  const finished = run.finished_at ? new Date(run.finished_at).getTime() : Number.POSITIVE_INFINITY;
  const seen = new Set<string>();

  return entries.filter((entry) => {
    const at = new Date(entry.ts).getTime();
    if (!Number.isFinite(at) || at < started || at > finished) return false;
    const payloadRunId = text(entry.payload?.scan_run_id);
    if (payloadRunId && payloadRunId !== run.id) return false;
    const key = activityKey(entry);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function phaseForEntry(entry: RunLogEntry, fallback: PhaseId): PhaseId {
  const payload = entry.payload ?? {};
  const direct = text(payload.phase);
  if (PHASE_SET.has(direct)) return direct as PhaseId;

  const nestedCall = record(payload.tool_call);
  const nestedPhase = text(nestedCall.phase);
  if (PHASE_SET.has(nestedPhase)) return nestedPhase as PhaseId;

  if (entry.action === "agent_event" || entry.action === "approval" || entry.action === "approval_execution") {
    return "agent";
  }
  if (entry.action === "dns_materialization") return "discovery";
  if (entry.action === "raw_egress_lease") return "fingerprint";
  return fallback;
}

function baseFacts(entry: RunLogEntry): ActivityFact[] {
  const payload = entry.payload ?? {};
  const facts: ActivityFact[] = [];
  const tool = text(payload.tool);
  const target = text(payload.authorized_target) || text(payload.target);
  const resolved = text(payload.resolved_target);
  const ports = text(payload.port_range);
  if (tool) facts.push({ label: "Tool", value: toolLabel(tool) });
  if (target) facts.push({ label: "Target", value: target });
  if (resolved) facts.push({ label: "Audited IP", value: resolved });
  if (ports) facts.push({ label: "Ports", value: ports });
  return facts;
}

function proposalDetails(payload: Record<string, unknown>, reason: string | null): {
  tool: string;
  target: string;
  description: string;
} {
  const proposal = record(payload.proposal);
  let tool = text(proposal.tool);
  if (!tool && reason === "llm_proposed_http_request") tool = "http_request";
  if (!tool && reason === "llm_proposed_content_discovery") tool = "ffuf";
  const target = text(proposal.target);
  const method = text(proposal.method);
  const path = text(proposal.path);
  const action = toolLabel(tool);
  const destination = target ? ` for ${target}` : "";
  const request = method || path ? ` (${[method, path].filter(Boolean).join(" ")})` : "";
  return { tool, target, description: `${action}${destination}${request}` };
}

function dnsCounts(payload: Record<string, unknown>): {
  hosts: number;
  ips: number;
  denied: number;
  unresolved: number;
} {
  // The control-plane audits `resolved` as a list of {hostname, ip_address}
  // pairs (one per resolved A/AAAA record), not a {hostname: ip} map - a host
  // with multiple IPs appears as multiple entries.
  const resolved = Array.isArray(payload.resolved) ? payload.resolved : [];
  const uniqueHosts = new Set<string>();
  const uniqueIps = new Set<string>();
  for (const entry of resolved) {
    const row = record(entry);
    const hostname = text(row.hostname);
    const ip = text(row.ip_address);
    if (hostname) uniqueHosts.add(hostname);
    if (ip) uniqueIps.add(ip);
  }
  const denied = Array.isArray(payload.denied_ips) ? payload.denied_ips.length : 0;
  const unresolved = Array.isArray(payload.unresolved) ? payload.unresolved.length : 0;
  return { hosts: uniqueHosts.size, ips: uniqueIps.size, denied, unresolved };
}

function translateToolCall(entry: RunLogEntry, phase: PhaseId): HumanActivity {
  const payload = entry.payload ?? {};
  const tool = text(payload.tool);
  const target = text(payload.target);
  const label = toolLabel(tool);
  const explanation = reasonExplanation(entry.reason);
  const retry = numberValue(payload.retry_after_seconds);
  const common = {
    id: activityKey(entry),
    phase,
    tool: label,
    target,
    facts: baseFacts(entry),
    reasonCode: entry.reason ?? undefined,
    source: entry.actor,
    decision: entry.decision,
    ts: entry.ts,
  };

  if (entry.decision === "DENY") {
    // REQ-GRANT-001 (#58): a missing grant names the category and mode the call needed, so the reader
    // knows which box to tick under Tool grants.
    const category = text(payload.category);
    const mode = text(payload.mode);
    const needsGrant = entry.reason === "no_tool_grant" && !!category && !!mode;
    return {
      ...common,
      title: `${label} request blocked`,
      summary: needsGrant
        ? `This engagement has no ${category} / ${mode} grant, which ${label} needs. Tick ${capitalize(mode)} for ${capitalize(category)} under Edit engagement → Tool grants. Nothing was sent.`
        : explanation,
      facts: needsGrant ? [...common.facts, { label: "Needs grant", value: `${category} / ${mode}` }] : common.facts,
      outcome: "Not executed",
      tone: "danger",
      routine: false,
      countsAsBlocked: true,
    };
  }
  if (entry.decision === "PENDING") {
    return {
      ...common,
      title: `${label} is waiting for approval`,
      summary: `${target || "The target action"} will not run until an operator decides.`,
      outcome: "Waiting",
      tone: "attention",
      routine: false,
      facts: retry ? [...common.facts, { label: "Retry", value: `${retry}s` }] : common.facts,
      countsAsAttention: true,
    };
  }
  if (entry.decision === "THROTTLE") {
    return {
      ...common,
      title: `${label} paused to respect the rate limit`,
      summary: retry ? `The worker will retry after ${retry.toFixed(1)} seconds.` : explanation,
      outcome: "Paused",
      tone: "attention",
      routine: false,
      facts: retry ? [...common.facts, { label: "Retry after", value: `${retry.toFixed(1)}s` }] : common.facts,
    };
  }
  return {
    ...common,
    title: `${label} passed the safety checks`,
    summary: `${explanation} This records authorization only; execution is reported separately.`,
    outcome: "Authorized",
    tone: "success",
    routine: true,
  };
}

// The worker's own list of failures that really mean "this did not apply / was not possible" (SKIP_REASONS in
// tool_execution.py). Older records carry no outcome, so the codes are repeated here; a test keeps both lists equal.
export const SKIPPED_CODES = ["not_a_tls_service", "materialized_ip_missing", "oob_unavailable", "no_tool_grant", "raw_egress_unavailable", "scan_run_missing"];

function isSkippedExecution(payload: Record<string, unknown>, errorCode: string): boolean {
  const outcome = text(record(payload.outcome_summary).outcome);
  if (outcome) return outcome.startsWith("skipped");
  return SKIPPED_CODES.includes(errorCode) || errorCode.startsWith("gateway_denied:");
}

function translateToolExecution(entry: RunLogEntry, phase: PhaseId): HumanActivity {
  const payload = entry.payload ?? {};
  const tool = text(payload.tool);
  const label = toolLabel(tool);
  const target = text(payload.authorized_target);
  const services = numberValue(payload.discovered_services);
  const hasServiceCount = payload.discovered_services !== undefined && payload.discovered_services !== null;
  const successful = payload.success === true;
  const ports = text(payload.port_range);
  const exit = text(payload.exit_code);
  const outcomeSummary = record(payload.outcome_summary);
  const protocol = text(outcomeSummary.protocol).toUpperCase();
  const states = record(outcomeSummary.states);
  const facts = baseFacts(entry);
  if (protocol) facts.push({ label: "Protocol", value: protocol });
  if (hasServiceCount) facts.push({ label: "Services found", value: String(services) });
  if (Object.keys(states).length) {
    facts.push({
      label: protocol === "UDP" ? "UDP states" : `${protocol || "Port"} states`,
      value: Object.entries(states).map(([state, count]) => `${state}: ${numberValue(count)}`).join(", "),
    });
  }
  // GitHub issue #60: what the scan itself reported about its own completeness.
  const dropped = numberValue(outcomeSummary.dropped_probes);
  if (dropped) facts.push({ label: "Probes refused by the local firewall", value: `${dropped} or more` });
  const reprobed = record(outcomeSummary.reprobed);
  if (Object.keys(reprobed).length) {
    facts.push({
      label: "Checked again",
      value: Object.entries(reprobed).map(([port, state]) => `${port}: ${text(state)}`).join(", "),
    });
  }
  const partialReasons = Array.isArray(outcomeSummary.partial_reasons)
    ? (outcomeSummary.partial_reasons as unknown[]).map((reason) => String(reason))
    : [];
  if (exit) facts.push({ label: "Exit code", value: exit });
  // REQ-AUDIT-006/007: http_request's response IS the evidence (status,
  // headers, body) - full and worker-redacted, shown under Technical details.
  const rawDetail = text(payload.response) || undefined;

  let title = `${label} completed`;
  if (tool === "nmap") title = `Nmap completed ${protocol || "configured"} discovery`;
  const resultParts = [
    services ? `${services} service${services === 1 ? "" : "s"} discovered` : "No services recorded by this step",
    target ? `on ${target}` : "",
    ports ? `across ${ports}` : "",
  ].filter(Boolean);

  const errorCode = text(payload.error_reason);
  if (!successful && isSkippedExecution(payload, errorCode)) {
    const denied = errorCode.startsWith("gateway_denied:") || errorCode === "no_tool_grant";
    return {
      id: activityKey(entry),
      phase,
      title: `${label} was skipped`,
      summary: reasonExplanation(errorCode || entry.reason),
      outcome: "Skipped",
      tone: denied ? "attention" : "neutral",
      routine: false,
      tool: label,
      target,
      facts,
      reasonCode: errorCode || entry.reason || undefined,
      source: entry.actor,
      decision: entry.decision,
      ts: entry.ts,
      countsAsAttention: denied,
    };
  }
  if (!successful) {
    return {
      id: activityKey(entry),
      phase,
      title: `${label} did not complete successfully`,
      summary: reasonExplanation(text(payload.error_reason) || entry.reason),
      outcome: "Failed",
      tone: "danger",
      routine: false,
      tool: label,
      target,
      facts,
      reasonCode: text(payload.error_reason) || entry.reason || undefined,
      errorSummary: text(payload.stderr_summary) || undefined,
      source: entry.actor,
      decision: entry.decision,
      ts: entry.ts,
      countsAsAttention: true,
    };
  }

  if (partialReasons.length) {
    return {
      id: activityKey(entry),
      phase,
      title: `${title}, but the result is incomplete`,
      summary: [
        `${resultParts.join(" ")}.`,
        ...partialReasons.map((reason) => explainPart(reason)),
      ].join(" "),
      outcome: "Partial",
      tone: "attention",
      routine: false,
      tool: label,
      target,
      facts,
      reasonCode: partialReasons[0],
      errorSummary: text(payload.stderr_summary) || undefined,
      source: entry.actor,
      decision: entry.decision,
      ts: entry.ts,
      countsAsCompletedTool: true,
      countsAsAttention: true,
    };
  }

  return {
    id: activityKey(entry),
    phase,
    title,
    summary: `${resultParts.join(" ")}.`,
    outcome: "Completed",
    tone: "success",
    routine: false,
    tool: label,
    target,
    facts,
    reasonCode: entry.reason ?? undefined,
    rawDetail,
    source: entry.actor,
    decision: entry.decision,
    ts: entry.ts,
    countsAsCompletedTool: true,
  };
}

function translateAgentEvent(entry: RunLogEntry): HumanActivity {
  const payload = entry.payload ?? {};
  const event = text(payload.event) || entry.reason || "event";
  const proposal = proposalDetails(payload, entry.reason);
  const facts: ActivityFact[] = [];
  const iteration = numberValue(payload.iteration);
  if (iteration) facts.push({ label: "Iteration", value: String(iteration) });
  if (text(payload.model)) facts.push({ label: "Model", value: text(payload.model) });
  if (proposal.tool) facts.push({ label: "Tool", value: toolLabel(proposal.tool) });
  if (proposal.target) facts.push({ label: "Target", value: proposal.target });

  const base = {
    id: activityKey(entry),
    phase: "agent" as PhaseId,
    facts,
    reasonCode: entry.reason ?? undefined,
    source: entry.actor,
    decision: entry.decision,
    ts: entry.ts,
    tool: proposal.tool ? toolLabel(proposal.tool) : undefined,
    target: proposal.target || undefined,
  };

  if (event === "started") {
    const budget = numberValue(payload.budget_max_iterations);
    return {
      ...base,
      title: "Vector Agent started attack-path validation",
      summary: budget
        ? `It can evaluate up to ${budget} bounded iterations using the evidence already collected.`
        : reasonExplanation(entry.reason),
      outcome: "Started",
      tone: "info",
      routine: false,
    };
  }
  if (event === "provider_configured") {
    return {
      ...base,
      title: "Vector Agent provider is ready",
      summary: reasonExplanation(entry.reason),
      outcome: "Ready",
      tone: "success",
      routine: true,
    };
  }
  if (event === "llm_request") {
    return {
      ...base,
      title: `Vector Agent requested action ${iteration || ""}`.trim(),
      summary: reasonExplanation(entry.reason),
      outcome: "Thinking",
      tone: "info",
      routine: true,
    };
  }
  if (event === "proposal") {
    return {
      ...base,
      title: `Vector Agent proposed ${proposal.description}`,
      summary: "The proposal is advisory and must still pass the deterministic Scope Gateway.",
      outcome: "Proposed",
      tone: "info",
      routine: false,
    };
  }
  if (["proposal_allowed", "approval_claimed"].includes(event)) {
    return {
      ...base,
      title: `${proposal.description} was authorized`,
      summary: "Authorization passed. A separate terminal event reports whether execution succeeded.",
      outcome: "Authorized",
      tone: "success",
      routine: true,
    };
  }
  if (["proposal_denied", "proposal_rejected", "approval_claim_denied", "approval_not_granted"].includes(event)) {
    return {
      ...base,
      title: `${proposal.description} was not executed`,
      summary: reasonExplanation(entry.reason),
      outcome: "Blocked",
      tone: "danger",
      routine: false,
      countsAsBlocked: true,
    };
  }
  if (event === "test_account_login") {
    // REQ-TESTACCT-008: what a test account's login came to on one host. Never the value.
    const account = text((payload.proposal as Record<string, unknown> | undefined)?.account);
    const ok = entry.reason === "session_established";
    return {
      ...base,
      title: `Test account ${account || "login"} ${ok ? "logged in" : "was rejected"}`,
      summary: ok ? "The target accepted the login and a session was established for this host."
        : "The target did not accept the login (or sent no session). The account is not tried again on this host in this run.",
      outcome: ok ? "Logged in" : "Rejected",
      tone: ok ? "success" : "attention",
      routine: ok,
    };
  }
  if (event === "agent_phase_skipped") {
    // REQ-AGENT-028: a deliberate setting, not a failure: no request was made to the language model.
    return {
      ...base,
      title: "Vector Agent: off for this engagement",
      summary: `${reasonExplanation(entry.reason)} The Vector Agent was not started and no request was made to the language model.`,
      outcome: "Skipped",
      tone: "neutral",
      routine: false,
    };
  }
  if (event === "proposal_skipped") {
    return {
      ...base,
      title: `${proposal.description} was skipped`,
      summary: reasonExplanation(entry.reason),
      outcome: "Skipped",
      tone: "neutral",
      routine: entry.reason === "deterministic_full_scan_only",
    };
  }
  if (event === "proposal_throttled") {
    const retry = numberValue(payload.retry_after_seconds);
    return {
      ...base,
      title: "Vector Agent paused to respect the rate limit",
      summary: retry ? `The proposal will be checked again after ${retry.toFixed(1)} seconds.` : reasonExplanation(entry.reason),
      outcome: "Paused",
      tone: "attention",
      routine: false,
      facts: retry ? [...facts, { label: "Retry after", value: `${retry.toFixed(1)}s` }] : facts,
    };
  }
  if (event === "proposal_pending_approval") {
    return {
      ...base,
      title: `${proposal.description} needs operator approval`,
      summary: "The action remains stopped until the exact stored request is approved.",
      outcome: "Waiting",
      tone: "attention",
      routine: false,
      countsAsAttention: true,
    };
  }
  // REQ-RETEST-007: a request a person confirmed one by one on the review step, sent in a restricted run.
  if (event === "open_request_sending") {
    return {
      ...base,
      title: `Sending the request you confirmed: ${proposal.description}`,
      summary: "You chose to send this exact request. The Scope Gateway checked it again before it goes out.",
      outcome: "Sending",
      tone: "info",
      routine: false,
    };
  }
  if (event === "open_request_sent") {
    const response = text(payload.observation);
    return {
      ...base,
      title: `The request you confirmed was sent: ${proposal.description}`,
      summary: response.slice(0, 260) || "The request was sent. The full response is under Technical details.",
      outcome: "Sent",
      tone: "success",
      routine: false,
      rawDetail: response || undefined,
    };
  }
  if (event === "open_request_not_sent") {
    return {
      ...base,
      title: `Not sent, still open: ${proposal.description}`,
      summary: reasonExplanation(entry.reason),
      outcome: "Not sent",
      tone: "attention",
      routine: false,
      countsAsAttention: true,
    };
  }
  if (event === "observation") {
    const services = Array.isArray(payload.services) ? payload.services.length : 0;
    const findings = Array.isArray(payload.findings) ? payload.findings.length : 0;
    const observation = text(payload.observation);
    const result = [
      services ? `${services} service${services === 1 ? "" : "s"}` : "",
      findings ? `${findings} finding${findings === 1 ? "" : "s"}` : "",
    ].filter(Boolean).join(" and ");
    // REQ-AUDIT-006/007: for http_request/register_test_identity, `observation`
    // IS the full redacted target response (status + headers + body), not a
    // summary - shown in full under Technical details rather than cut to the
    // headline's 260-char preview.
    const isRawResponse = proposal.tool === "http_request";
    return {
      ...base,
      title: `Result returned to Vector Agent${proposal.target ? ` for ${proposal.target}` : ""}`,
      summary: result
        ? `The observation contains ${result} for the next reasoning step.`
        : observation.slice(0, 260) || reasonExplanation(entry.reason),
      outcome: "Observed",
      tone: "info",
      routine: false,
      rawDetail: isRawResponse && observation ? observation : undefined,
    };
  }
  if (["conclusion", "finish_requested"].includes(event)) {
    const conclusion = text(payload.conclusion) || text(payload.summary);
    return {
      ...base,
      title: "Vector Agent produced its conclusion",
      summary: conclusion.slice(0, 500) || reasonExplanation(entry.reason),
      outcome: "Concluded",
      tone: "success",
      routine: false,
    };
  }
  if (event === "finished") {
    const iterations = numberValue(payload.iterations);
    const observations = numberValue(payload.observations);
    const denied = numberValue(payload.denied);
    return {
      ...base,
      title: "Vector Agent phase finished",
      summary: `${iterations} iteration${iterations === 1 ? "" : "s"}, ${observations} observation${observations === 1 ? "" : "s"}, and ${denied} blocked proposal${denied === 1 ? "" : "s"}.`,
      outcome: "Completed",
      tone: "success",
      routine: false,
      facts: [
        { label: "Iterations", value: String(iterations) },
        { label: "Observations", value: String(observations) },
        { label: "Blocked", value: String(denied) },
      ],
    };
  }
  if (["llm_incomplete", "incomplete"].includes(event)) {
    const willRetry = payload.will_retry === true;
    const maxTokens = numberValue(payload.max_tokens);
    return {
      ...base,
      title: willRetry
        ? "Model response was incomplete; retrying with a larger output budget"
        : "Vector Agent received an incomplete model response",
      summary: willRetry
        ? `The partial response was not executed.${maxTokens ? ` The previous output budget was ${maxTokens} tokens.` : ""}`
        : reasonExplanation(entry.reason),
      outcome: willRetry ? "Retrying" : "Incomplete",
      tone: willRetry ? "attention" : "danger",
      routine: false,
      countsAsAttention: !willRetry,
    };
  }
  if (event === "llm_call_failed") {
    return {
      ...base,
      title: "Vector Agent provider call failed",
      summary: reasonExplanation(entry.reason),
      outcome: "Failed",
      tone: "danger",
      routine: false,
      errorSummary: text(payload.error) || undefined,
      countsAsAttention: true,
    };
  }
  if (event === "finding_reported") {
    const findingTitle = text(payload.title);
    const severity = text(payload.severity);
    return {
      ...base,
      title: findingTitle ? `Vector Agent recorded finding: ${findingTitle}` : "Vector Agent recorded a finding",
      summary: severity
        ? `The finding was stored with ${humanize(severity).toLowerCase()} severity for validation and reporting.`
        : reasonExplanation(entry.reason),
      outcome: "Recorded",
      tone: "success",
      routine: false,
      facts: severity ? [...facts, { label: "Severity", value: humanize(severity) }] : facts,
    };
  }
  if (event === "skipped") {
    return {
      ...base,
      title: "Vector Agent phase was skipped",
      summary: reasonExplanation(entry.reason),
      outcome: "Skipped",
      tone: "attention",
      routine: false,
      countsAsAttention: true,
    };
  }
  if (event === "cancelled") {
    return {
      ...base,
      title: "Vector Agent stopped by the operator",
      summary: reasonExplanation(entry.reason),
      outcome: "Stopped",
      tone: "attention",
      routine: false,
    };
  }
  if (event === "approval_execution_failed") {
    return {
      ...base,
      title: "Approved action could not be executed",
      summary: reasonExplanation(entry.reason),
      outcome: "Failed",
      tone: "danger",
      routine: false,
      countsAsAttention: true,
    };
  }

  return {
    ...base,
    title: entry.reason === "all_checks_passed" ? "Safety checks passed" : `Vector Agent: ${humanize(event)}`,
    summary: reasonExplanation(entry.reason),
    outcome: entry.decision === "DENY" ? "Not executed" : "Information",
    tone: entry.decision === "DENY" ? "attention" : "neutral",
    routine: entry.reason === "all_checks_passed" || entry.decision === "ALLOW",
  };
}

function translateDns(entry: RunLogEntry): HumanActivity {
  const payload = entry.payload ?? {};
  const counts = dnsCounts(payload);
  const problems = counts.denied + counts.unresolved;
  return {
    id: activityKey(entry),
    phase: "discovery",
    title: "Target names were resolved to audited IP addresses",
    summary: `${counts.hosts} hostname${counts.hosts === 1 ? "" : "s"} produced ${counts.ips} unique IP address${counts.ips === 1 ? "" : "es"}.${problems ? ` ${counts.unresolved} unresolved and ${counts.denied} excluded by scope.` : ""}`,
    outcome: counts.ips ? "Resolved" : "No target IP",
    tone: counts.ips ? (problems ? "attention" : "success") : "danger",
    routine: false,
    facts: [
      { label: "Resolved hosts", value: String(counts.hosts) },
      { label: "Unique IPs", value: String(counts.ips) },
      { label: "Unresolved", value: String(counts.unresolved) },
      { label: "Scope-denied IPs", value: String(counts.denied) },
    ],
    reasonCode: entry.reason ?? undefined,
    source: entry.actor,
    decision: entry.decision,
    ts: entry.ts,
    countsAsAttention: counts.ips === 0,
  };
}

function translateLease(entry: RunLogEntry): HumanActivity {
  const payload = entry.payload ?? {};
  const target = text(payload.target) || text(payload.authorized_target);
  const resolved = text(payload.resolved_target);
  const signedRanges = Array.isArray(payload.ports)
    ? payload.ports
      .filter((range) => Array.isArray(range) && range.length === 2)
      .map((range) => `${text(range[0])}-${text(range[1])}`)
      .filter(Boolean)
      .join(",")
    : "";
  const portRange = text(payload.port_range) || signedRanges;
  const protocol = text(payload.protocol).toUpperCase() || "TCP";
  const allowed = entry.decision === "ALLOW";
  const maxRate = numberValue(payload.max_rate);
  const facts: ActivityFact[] = [
    ...(target ? [{ label: "Target", value: target }] : []),
    ...(resolved ? [{ label: "Audited IP", value: resolved }] : []),
    ...(portRange ? [{ label: `${protocol} ports`, value: portRange }] : []),
    ...(maxRate ? [{ label: "Maximum rate", value: `${maxRate} packets/s` }] : []),
  ];
  return {
    id: activityKey(entry),
    phase: "fingerprint",
    title: allowed ? "Restricted Nmap network access was opened" : "Restricted Nmap network access was denied",
    summary: allowed
      ? `A short-lived rule permits only ${resolved || "the audited IP"}${portRange ? ` on ${protocol} ports ${portRange}` : ""}.`
      : reasonExplanation(entry.reason),
    outcome: allowed ? "Lease active" : "Not available",
    tone: allowed ? "success" : "danger",
    routine: allowed,
    tool: "Nmap",
    target,
    facts,
    reasonCode: entry.reason ?? undefined,
    source: entry.actor,
    decision: entry.decision,
    ts: entry.ts,
    countsAsAttention: !allowed,
  };
}

function translateApproval(entry: RunLogEntry, phase: PhaseId): HumanActivity {
  const payload = entry.payload ?? {};
  const call = record(payload.tool_call);
  const tool = toolLabel(call.tool);
  const target = text(call.target);
  const approved = entry.decision === "ALLOW";
  return {
    id: activityKey(entry),
    phase,
    title: approved ? `Operator approved ${tool}` : `Operator rejected ${tool}`,
    summary: approved
      ? `The exact stored action for ${target || "the target"} may now be reauthorized once before execution.`
      : `${target || "The action"} was not sent.`,
    outcome: approved ? "Approved" : "Rejected",
    tone: approved ? "success" : "attention",
    routine: false,
    tool,
    target,
    facts: [
      ...(tool ? [{ label: "Tool", value: tool }] : []),
      ...(target ? [{ label: "Target", value: target }] : []),
    ],
    reasonCode: entry.reason ?? undefined,
    source: entry.actor,
    decision: entry.decision,
    ts: entry.ts,
    countsAsBlocked: !approved,
  };
}

export function translateActivity(entry: RunLogEntry, fallbackPhase: PhaseId): HumanActivity {
  const phase = phaseForEntry(entry, fallbackPhase);
  if (entry.action === "tool_call") return translateToolCall(entry, phase);
  if (entry.action === "tool_execution") return translateToolExecution(entry, phase);
  if (entry.action === "agent_event") return translateAgentEvent(entry);
  if (entry.action === "dns_materialization") return translateDns(entry);
  if (entry.action === "raw_egress_lease") return translateLease(entry);
  if (entry.action === "approval") return translateApproval(entry, phase);

  if (entry.action === "approval_execution") {
    const successful = entry.decision === "ALLOW";
    return {
      id: activityKey(entry),
      phase,
      title: successful ? "Approved action completed" : "Approved action failed",
      summary: successful
        ? "The one-time approved action was consumed and cannot be replayed."
        : reasonExplanation(entry.reason),
      outcome: successful ? "Consumed" : "Failed",
      tone: successful ? "success" : "danger",
      routine: false,
      facts: [],
      reasonCode: entry.reason ?? undefined,
      source: entry.actor,
      decision: entry.decision,
      ts: entry.ts,
      countsAsAttention: !successful,
    };
  }

  if (entry.action === "scan_run_cancel_requested") {
    return {
      id: activityKey(entry),
      phase,
      title: "Operator requested a safe stop",
      summary: "The worker will stop cooperatively before starting another action.",
      outcome: "Stopping",
      tone: "attention",
      routine: false,
      facts: [],
      reasonCode: entry.reason ?? undefined,
      source: entry.actor,
      decision: entry.decision,
      ts: entry.ts,
    };
  }

  if (entry.action === "gateway_override") {
    return {
      id: activityKey(entry),
      phase,
      title: "Operator changed a gateway prerequisite",
      summary: "The policy change is recorded in Audit and applies only to subsequent authorization checks.",
      outcome: "Policy updated",
      tone: "attention",
      routine: false,
      facts: [],
      reasonCode: entry.reason ?? undefined,
      source: entry.actor,
      decision: entry.decision,
      ts: entry.ts,
    };
  }

  return {
    id: activityKey(entry),
    phase,
    title: humanize(entry.action),
    summary: reasonExplanation(entry.reason),
    outcome: "Information",
    tone: "neutral",
    routine: true,
    facts: [],
    reasonCode: entry.reason ?? undefined,
    source: entry.actor,
    decision: entry.decision,
    ts: entry.ts,
  };
}

const SECONDS_TO_PAIR = 15;

/**
 * REQ-EXPLAIN-004: one cause is one row.
 *  - Every tool that skipped the same name because it has no DNS address becomes ONE row for that name,
 *    listing the tools, instead of one row per tool.
 *  - A refusal by the Scope Gateway is recorded twice (the gateway's own entry and the tool's result
 *    "gateway_denied:<why>"); the second is dropped when the first is in the list.
 * Nothing is hidden: the underlying entries stay in the audit log, and a run in which a load-bearing tool
 * never succeeded still carries its coverage warning (REQ-SCAN-014).
 */
export function consolidateActivities(activities: HumanActivity[]): HumanActivity[] {
  const denials = activities.filter((a) => a.decision === "DENY" && a.title.endsWith("request blocked"));
  const pairedWithDenial = (a: HumanActivity) =>
    !!a.reasonCode?.startsWith("gateway_denied:") && denials.some((d) =>
      d.tool === a.tool && d.target === a.target
      && Math.abs(new Date(d.ts).getTime() - new Date(a.ts).getTime()) <= SECONDS_TO_PAIR * 1000);

  const noAddress = new Map<string, HumanActivity[]>();
  const kept: HumanActivity[] = [];
  const firstIndex = new Map<string, number>();
  for (const activity of activities) {
    if (pairedWithDenial(activity)) continue;
    if (activity.reasonCode === "materialized_ip_missing" && activity.outcome === "Skipped" && activity.target) {
      const group = noAddress.get(activity.target) ?? [];
      group.push(activity);
      noAddress.set(activity.target, group);
      if (!firstIndex.has(activity.target)) {
        firstIndex.set(activity.target, kept.length);
        kept.push(activity); // placeholder, replaced below
      }
      continue;
    }
    kept.push(activity);
  }
  for (const [target, group] of noAddress) {
    const tools = [...new Set(group.map((a) => a.tool).filter(Boolean))] as string[];
    const first = group[0];
    kept[firstIndex.get(target)!] = {
      ...first,
      id: `${first.id}|no-address`,
      title: `${target} has no DNS address`,
      summary: `${reasonExplanation("materialized_ip_missing")}`,
      tool: tools.join(", ") || undefined,
      facts: [
        { label: "Name", value: target },
        { label: group.length === 1 ? "Skipped" : "Skipped checks", value: tools.join(", ") || "none named" },
      ],
    };
  }
  return kept;
}

export function summarizeRun(run: ScanRun | undefined, activities: HumanActivity[]): RunActivitySummary {
  const completedTools = activities.filter((activity) => activity.countsAsCompletedTool).length;
  const discoveredServices = activities
    .filter((activity) => activity.countsAsCompletedTool)
    .flatMap((activity) => activity.facts)
    .filter((fact) => fact.label === "Services found")
    .reduce((sum, fact) => sum + numberValue(fact.value), 0);
  const blockedActions = activities.filter((activity) => activity.countsAsBlocked).length;
  const attentionItems = activities.filter((activity) => activity.countsAsAttention).length;
  const phase = run && PHASE_SET.has(run.phase) ? PHASE_META[run.phase as PhaseId].label : humanize(run?.phase);

  if (!run) {
    return {
      headline: "Loading run activity",
      detail: "Waiting for the selected run and its bounded audit history.",
      completedTools,
      discoveredServices,
      blockedActions,
      attentionItems,
    };
  }
  if (run.state === "done") {
    return {
      headline: "The scan completed",
      detail: `${completedTools} tool execution${completedTools === 1 ? "" : "s"} completed and ${discoveredServices} service${discoveredServices === 1 ? "" : "s"} were recorded.${blockedActions ? ` ${blockedActions} unsafe or unauthorized action${blockedActions === 1 ? " was" : "s were"} safely blocked.` : ""}`,
      completedTools,
      discoveredServices,
      blockedActions,
      attentionItems,
    };
  }
  if (run.state === "failed") {
    return {
      headline: `The scan failed in ${phase}`,
      detail: reasonExplanation(run.state_reason),
      completedTools,
      discoveredServices,
      blockedActions,
      attentionItems: Math.max(1, attentionItems),
    };
  }
  if (run.state === "aborted") {
    return {
      headline: `The scan stopped in ${phase}`,
      detail: reasonExplanation(run.state_reason),
      completedTools,
      discoveredServices,
      blockedActions,
      attentionItems,
    };
  }
  if (run.state === "waiting_approval") {
    // REQ-APPROVAL-008: with this reason only ONE action waits; a parked run or a review pause has stopped altogether.
    const oneAction = run.state_reason === "approval_wait";
    return {
      headline: oneAction ? "One action is waiting for your decision, the scan carries on" : "The scan is waiting for an operator decision",
      detail: oneAction
        ? `The rest of ${phase} keeps running. The waiting action runs only if you approve it; it is skipped if you reject it, cancel the run, or it expires.`
        : `The current action remains stopped in ${phase} until it is approved, rejected, cancelled, or expires.`,
      completedTools,
      discoveredServices,
      blockedActions,
      attentionItems: Math.max(1, attentionItems),
    };
  }
  return {
    headline: `The scan is running: ${phase}`,
    detail: `${PHASE_META[run.phase as PhaseId]?.goal ?? "The current phase is processing its inputs"} No action can bypass the Scope Gateway.`,
    completedTools,
    discoveredServices,
    blockedActions,
    attentionItems,
  };
}

