// REQ-HANDOVER-001..007 (GitHub #84): "Test deeper" - a draft assessment started from a monitor. The pure rules of the
// dialog live here so a test can run them without a browser: what may be submitted, what is sent, how a refusal reads.

import type { HandoverHost, HandoverRequest } from "../api/client";

/** A refusal of the handover endpoints, in words. The code is what the server sends as `detail`. */
export const HANDOVER_REFUSALS: Record<string, string> = {
  handover_monitor_not_active:
    "Only an active or paused monitoring engagement can start a deeper test. A draft, a closed or a revoked one cannot: its authorization is not in force.",
  handover_source_unsupported:
    "This monitor belongs to a bug-bounty program, whose rules are not carried over. Create the assessment from the wizard instead.",
  handover_host_unknown: "One of the hosts is not known to the monitor and is not covered by its scope. Pick hosts from the list.",
  handover_host_denied: "One of the hosts is denied by the monitor's scope. A denied host can never be tested; pick another.",
  handover_window_invalid: "The test window must end after it starts.",
  handover_hosts_required: "Pick at least one host to test.",
  handover_hosts_not_allowed: "You chose the monitor's whole scope, so no individual hosts can be sent as well.",
  handover_forbidden: "Only the owner of the monitor or an administrator can start a deeper test.",
};

/** The code inside an error message such as `POST /x -> 422: handover_host_denied`, or null. */
export function handoverCode(message: string): string | null {
  const match = /\b(handover_[a-z_]+)\b/.exec(message);
  return match ? match[1] : null;
}

export function handoverRefusal(message: string): string {
  const code = handoverCode(message);
  return code && HANDOVER_REFUSALS[code] ? HANDOVER_REFUSALS[code] : message;
}

export interface HandoverForm {
  title: string;
  /** `datetime-local` values; empty until the owner chooses (the monitor's window is never reused). */
  from: string;
  until: string;
  emergencyContact: string;
  wholeScope: boolean;
  /** The owner's confirmation of the whole-scope choice. */
  wholeScopeConfirmed: boolean;
  chosen: string[];
}

export const emptyForm = (suggestedTitle = "", emergencyContact: string | null = null): HandoverForm => ({
  title: suggestedTitle, from: "", until: "", emergencyContact: emergencyContact ?? "",
  wholeScope: false, wholeScopeConfirmed: false, chosen: [],
});

/** Hosts that can be ticked: a host a deny rule matches never can. */
export const selectable = (host: HandoverHost): boolean => host.denied_by === null;

const toMillis = (local: string): number => (local ? new Date(local).getTime() : NaN);

export function windowValid(form: Pick<HandoverForm, "from" | "until">): boolean {
  const from = toMillis(form.from), until = toMillis(form.until);
  return Number.isFinite(from) && Number.isFinite(until) && until > from;
}

/** Why the button is disabled, in words, or null when the form can be sent. */
export function blocker(form: HandoverForm, hosts: HandoverHost[]): string | null {
  if (!form.from || !form.until) return "Give the test window: when it starts and when it ends.";
  if (!windowValid(form)) return "The test window must end after it starts.";
  if (form.wholeScope) return form.wholeScopeConfirmed ? null : "Confirm that the whole scope of the monitor is meant.";
  const allowed = new Set(hosts.filter(selectable).map((h) => h.host));
  if (!form.chosen.some((h) => allowed.has(h))) return "Pick at least one host to test.";
  return null;
}

export function buildRequest(form: HandoverForm, hosts: HandoverHost[]): HandoverRequest {
  const allowed = new Set(hosts.filter(selectable).map((h) => h.host));
  const request: HandoverRequest = {
    authorized_from: new Date(form.from).toISOString(),
    authorized_until: new Date(form.until).toISOString(),
    scope_mode: form.wholeScope ? "same_scope" : "hosts",
    hosts: form.wholeScope ? [] : form.chosen.filter((h) => allowed.has(h)),
  };
  if (form.title.trim()) request.title = form.title.trim();
  if (form.emergencyContact.trim()) request.emergency_contact = form.emergencyContact.trim();
  return request;
}

/** What the dialog says about running both engagements at once (REQ-HANDOVER-006). */
export function overlapSentence(overlap: "both_may_run" | "monitor_must_pause"): string {
  return overlap === "both_may_run"
    ? "The monitor keeps running while the assessment is active. Each request is judged by the authorization of its own engagement, and the target will see traffic from both."
    : "This installation does not run two engagements on the same host: activating the assessment will be refused while the monitor is active. You can pause the monitor with Pause engagement. Nothing here pauses it for you.";
}

/** Notes shown on the held-host row: the monitor's hold is not released by choosing it here. */
export const HELD_NOTE = "Held on the monitor - you are choosing to test it here. The monitor's hold is not released.";

/** Who sees the action: the owner or an administrator, on a monitor that is active or paused. */
export function canStartHandover(e: { operating_mode: string; status: string; can_manage: boolean }): boolean {
  return e.can_manage && e.operating_mode === "monitoring" && (e.status === "active" || e.status === "paused");
}
