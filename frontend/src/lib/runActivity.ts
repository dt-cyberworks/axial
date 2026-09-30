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
  no_tool_grant: "This engagement does not grant the required tool category.",
  tool_not_whitelisted: "The requested tool is not enabled by the safety registry.",
  unsafe_arguments: "The proposed arguments did not pass the deterministic safety policy.",
  outside_time_window: "The authorized testing window is not currently open.",
  engagement_not_active: "The engagement is not active.",
  ai_testing_not_enabled: "Vector Agent proposals are not enabled for this engagement.",
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
  deterministic_full_scan_only: "Full Nmap discovery is pipeline-owned and was not repeated by Vector Agent.",
  raw_egress_unavailable: "The scope-restricted raw network path was unavailable.",
  lease_issued: "A short-lived scope-bound network rule was issued for Nmap.",
  raw_egress_lease_denied: "The scope-bound raw network rule was not issued, so Nmap was not started.",
  raw_egress_queue_timeout: "The shared Nmap gateway queue did not become available within its bounded wait time.",
  raw_egress_queue_cancelled: "The queued Nmap request was removed because this run was stopped.",
  raw_egress_queue_or_dispatch_failed: "The shared Nmap gateway could not safely schedule or start this scan.",
  raw_egress_heartbeat_failed: "The active Nmap network lease lost its heartbeat and was closed.",
  raw_egress_reservation_release_failed: "The Nmap queue slot could not be confirmed as released.",
  udp_results_ambiguous: "UDP returned only filtered or open-or-filtered states. This is inconclusive, not a clean target.",
  udp_no_port_states: "UDP returned no port states. This is incomplete, not a clean target.",
  udp_discovery_not_enabled: "Bounded UDP discovery is not enabled for this engagement.",
  scan_run_missing: "No valid scan-run context was available, so the tool was not started.",
  materialized_ip_missing: "No current audited target IP was available, so raw scanning stayed blocked.",
  dns_resolution_failed: "The target name could not be resolved to an audited IP.",
  zero_targets_scanned: "Nmap did not scan a target. This is a failed result, not a clean target.",
  runner_dispatch_failed: "The isolated tool runner could not execute the request.",
  nonzero_exit: "The tool exited with an error.",
  runner_reported_failure: "The isolated runner reported an unsuccessful execution.",
  egress_proxy_blocked: "The network egress policy blocked the request.",
  cancelled: "The waiting approval or action was cancelled.",
  rejected: "The operator rejected the requested action.",
  expired: "The approval expired before execution.",
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
    const tools = detail
      .split(",")
      .map((part) => part.split("=")[0])
      .filter(Boolean)
      .join(", ");
    return (
      `Reduced detection coverage: ${tools || "a core tool"} was attempted but never once succeeded ` +
      `during this run, so this result is NOT a clean bill of health — parts of the attack surface ` +
      `were never actually examined. Technical detail: ${detail}.`
    );
  }
  if (reason.startsWith("coverage_partial:")) {
    const detail = reason.slice("coverage_partial:".length);
    const tools = detail
      .split(",")
      .map((part) => part.split("=")[0])
      .filter(Boolean)
      .join(", ");
    return (
      `Partial coverage: at least one ${tools || "check"} check stopped at its time budget before it finished. ` +
      `Everything it reported before that is real, but a short findings list does NOT mean the ` +
      `examined surface is clean. Technical detail: ${detail}.`
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

export function reasonExplanation(reason: string | null | undefined): string {
  if (!reason) return "No additional explanation was recorded.";
  const exact = REASON_COPY[reason];
  if (exact) return exact;
  // Independent warnings are joined with "; " and each is explained on its own.
  const parts = reason.split(";").map((p) => p.trim()).filter(Boolean);
  if (parts.length > 1 || compoundReasonExplanation(parts[0] ?? "")) {
    return parts
      .map((part) => REASON_COPY[part] ?? compoundReasonExplanation(part) ?? `Technical reason: ${humanize(part)}.`)
      .join(" ");
  }
  return `Technical reason: ${humanize(reason)}.`;
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
    return {
      ...common,
      title: `${label} request blocked`,
      summary: explanation,
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
      label: "UDP states",
      value: Object.entries(states).map(([state, count]) => `${state}: ${numberValue(count)}`).join(", "),
    });
  }
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
    return {
      headline: "The scan is waiting for an operator decision",
      detail: `The current action remains stopped in ${phase} until it is approved, rejected, cancelled, or expires.`,
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

