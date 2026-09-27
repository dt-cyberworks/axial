import { type ScanRun } from "../api/client";

export type PhaseId = "discovery" | "fingerprint" | "correlate" | "agent" | "validate" | "score" | "report";

export const PHASES: PhaseId[] = ["discovery", "fingerprint", "correlate", "agent", "validate", "score", "report"];

/** Per-phase description + the tools it may run (REQ-RUN-003). "internal" = no target-touching tools. */
export const PHASE_META: Record<PhaseId, { label: string; goal: string; tools: string[] | "internal" }> = {
  discovery:   { label: "Discovery",    goal: "Find candidate assets and normalize them into the engagement inventory.", tools: ["crt.sh (passive OSINT)"] },
  fingerprint: { label: "Fingerprint",  goal: "Resolve in-scope names and run allowed service and web fingerprint checks.", tools: ["httpx", "nmap", "nikto", "wafw00f", "testssl"] },
  correlate:   { label: "Correlate",    goal: "Connect observed services and evidence into de-duplicated findings.", tools: "internal" },
  agent:       { label: "Vector Agent", goal: "Use the evidence map to propose the next scoped attack-path validation checks.", tools: ["httpx", "nmap", "nikto", "wafw00f", "testssl", "nuclei", "http_request", "ffuf"] },
  validate:    { label: "Validate",     goal: "Confirm inferred signals without destructive exploitation.", tools: "internal" },
  score:       { label: "Risk scoring", goal: "Rank open findings by severity, exploitability, KEV, and exposure.", tools: "internal" },
  report:      { label: "Report",       goal: "Package the results into operator and customer-facing output.", tools: "internal" },
};

export interface PhaseCopy {
  uses: string;
  produces: string;
  next?: string;
}

/** Stable operator copy explaining evidence handoffs between pipeline phases (REQ-LIVE-002). */
export const PHASE_COPY: Record<PhaseId, PhaseCopy> = {
  discovery: {
    uses: "Authorized scope and passive discovery sources",
    produces: "Normalized asset names and audited target IPs",
    next: "Fingerprint consumes the in-scope target inventory",
  },
  fingerprint: {
    uses: "In-scope hosts, audited IPs, and permitted scan profiles",
    produces: "Open services, technologies, and bounded tool evidence",
    next: "Correlate turns observations into candidate findings",
  },
  correlate: {
    uses: "Service inventory and deterministic tool evidence",
    produces: "De-duplicated candidate findings and evidence links",
    next: "Vector Agent uses the evidence map for attack-path validation",
  },
  agent: {
    uses: "Deterministic evidence, in-scope assets, and enabled tools",
    produces: "Scoped validation observations, blocks, and an agent conclusion",
    next: "Validate confirms or suppresses inferred signals",
  },
  validate: {
    uses: "Candidate findings and supporting observations",
    produces: "Confirmed findings with confidence and evidence",
    next: "Risk scoring prioritizes the validated findings",
  },
  score: {
    uses: "Validated findings, exposure, severity, KEV, and exploitability",
    produces: "Prioritized risk scores and recommended actions",
    next: "Report packages the ranked results",
  },
  report: {
    uses: "Prioritized findings, services, and run-over-run changes",
    produces: "Operator and customer-facing results",
  },
};

export function phaseIndex(run?: ScanRun): number {
  if (!run) return -1;
  return PHASES.indexOf(run.phase as PhaseId);
}

export type PhaseState = "pending" | "running" | "complete" | "failed";

export function phaseStateFor(run: ScanRun | undefined, phase: PhaseId, index: number): PhaseState {
  if (!run) return "pending";
  const current = phaseIndex(run);
  const terminalFail = run.state === "failed" || run.state === "aborted";
  if (index < current) return "complete";
  if (index === current) {
    if (run.state === "done") return "complete";
    if (terminalFail) return "failed";
    return "running";
  }
  // future phase
  if (run.state === "done") return "complete";
  return "pending";
}

export function fmtTime(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString() : "—";
}

/**
 * `now` (REQ-RUNUI-001) makes the "still running" clock an explicit input
 * instead of a hidden `Date.now()` read: a caller rendering a live elapsed
 * time passes a value that changes on its own cadence (see lib/useTicker.ts),
 * so the text actually advances. It is ignored entirely when `endIso` is set,
 * which is why finished runs need no ticker.
 */
export function fmtDuration(startIso: string | null, endIso: string | null, now: number = Date.now()): string {
  if (!startIso) return "—";
  const start = new Date(startIso).getTime();
  const end = endIso ? new Date(endIso).getTime() : now;
  let s = Math.max(0, Math.round((end - start) / 1000));
  const h = Math.floor(s / 3600); s -= h * 3600;
  const m = Math.floor(s / 60); s -= m * 60;
  return [h ? `${h}h` : "", m ? `${m}m` : "", `${s}s`].filter(Boolean).join(" ");
}

export function runStatePill(state: string): string {
  if (state === "done") return "good";
  if (state === "failed" || state === "aborted") return "bad";
  if (state === "running") return "warn";
  return "neutral";
}

export function runNumber(runs: ScanRun[], runId: string): number {
  const index = runs.findIndex((r) => r.id === runId);
  return index < 0 ? 0 : runs.length - index;
}
