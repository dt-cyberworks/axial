import type { OpenItem, RetestItemIn, ScanStartOptions } from "../api/client";

// REQ-RETEST-005/006: the "Review before you run" step. The logic lives here, apart from the screen, so that the
// rules that protect the person can be tested directly: nothing that changes data is ever preselected, there is no
// "send all", and the button says exactly what will be started.

export interface ReviewGroups {
  /** Checks whose tool needs no approval: they run without asking. */
  readOnly: OpenItem[];
  /** Held-back requests, and checks whose tool needs a person's approval: they are sent or run only if chosen. */
  needsConfirmation: OpenItem[];
  /** Held back too long ago to send; shown, never selectable. */
  expired: OpenItem[];
}

export function groupItems(items: OpenItem[]): ReviewGroups {
  const groups: ReviewGroups = { readOnly: [], needsConfirmation: [], expired: [] };
  for (const item of items) {
    if (item.expired) groups.expired.push(item);
    else if (item.needs_confirmation) groups.needsConfirmation.push(item);
    else groups.readOnly.push(item);
  }
  return groups;
}

/**
 * What is chosen when the step opens. A read-only check is included (the person asked to run it and can untick it);
 * anything that needs a confirmation is NOT: the person has to choose it, one item at a time.
 */
export function initialChoice(items: OpenItem[]): Record<string, boolean> {
  const chosen: Record<string, boolean> = {};
  for (const item of items) chosen[item.id] = !item.expired && !item.needs_confirmation;
  return chosen;
}

export function chosenItems(items: OpenItem[], chosen: Record<string, boolean>): OpenItem[] {
  return items.filter((item) => !item.expired && chosen[item.id] === true);
}

export interface ReviewCounts {
  checks: number;
  /** Requests that change data (a held-back POST, PUT, PATCH, DELETE or anything with a body). */
  requests: number;
  /** Checks of a tool that asks for the person's approval while it runs. */
  approvals: number;
}

export function countChosen(items: OpenItem[], chosen: Record<string, boolean>): ReviewCounts {
  const picked = chosenItems(items, chosen);
  return {
    checks: picked.filter((i) => i.kind === "check").length,
    requests: picked.filter((i) => i.kind === "request").length,
    approvals: picked.filter((i) => i.kind === "check" && i.needs_confirmation).length,
  };
}

const SHARD = /^(.*):\d+of\d+$/;

/** Shards of one check ("nuclei:generic:2of5") are the same check ("nuclei:generic"). */
export function checkFamily(checkId: string): string {
  const match = SHARD.exec(checkId);
  return match ? match[1] : checkId;
}

/** The id the control plane gives the open item of a plan check (REQ-RETEST-003). */
export function openItemId(host: string, port: number, checkId: string): string {
  return `check:${host.toLowerCase()}:${port}:${checkFamily(checkId)}`;
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** The button names what it starts: "Run 2 checks and 1 request that changes data". */
export function runLabel(items: OpenItem[], chosen: Record<string, boolean>): string {
  const { checks, requests } = countChosen(items, chosen);
  if (checks === 0 && requests === 0) return "Nothing chosen to run";
  const parts: string[] = [];
  if (checks > 0) parts.push(plural(checks, "check", "checks"));
  if (requests > 0) parts.push(plural(requests, "request that changes data", "requests that change data"));
  const verb = checks > 0 ? "Run" : "Send";
  return `${verb} ${parts.join(" and ")}`;
}

function checkItem(item: OpenItem): RetestItemIn {
  const entry: RetestItemIn = { host: item.host };
  if (item.port != null) entry.port = item.port;
  if (item.check) entry.check = item.check;
  else if (item.tool) entry.tool = item.tool;
  return entry;
}

/**
 * The request body of the start call, or null when nothing is chosen. A held-back request goes in `send_requests`
 * only when it is chosen, which is the person's confirmation of exactly that request. The run is always attended: a
 * person is here to see it.
 */
export function buildStartOptions(
  items: OpenItem[], chosen: Record<string, boolean>, extra: { retestFindingId?: string } = {},
): ScanStartOptions | null {
  const picked = chosenItems(items, chosen);
  const checks = picked.filter((i) => i.kind === "check").map(checkItem);
  const requests = picked.filter((i) => i.kind === "request").map((i) => i.id);
  if (checks.length === 0 && requests.length === 0) return null;
  const options: ScanStartOptions = { supervision: "attended" };
  if (checks.length > 0) options.items = checks;
  if (requests.length > 0) options.send_requests = requests;
  if (extra.retestFindingId) options.retest_finding_id = extra.retestFindingId;
  return options;
}

const METHOD_PHRASE: Record<string, string> = {
  POST: "sends data to the target (POST)",
  PUT: "replaces data on the target (PUT)",
  PATCH: "changes data on the target (PATCH)",
  DELETE: "deletes data on the target (DELETE)",
};

/** What a request does, in plain words. Anything with a body sends data, whatever its method. */
export function describeRequest(method: string | null | undefined, hasBody: boolean): string {
  const m = (method ?? "GET").toUpperCase();
  if (METHOD_PHRASE[m]) return `This ${METHOD_PHRASE[m]}.`;
  if (hasBody) return `This sends data to the target (${m} with a body).`;
  return `This reads from the target (${m}).`;
}

export function ageText(days: number | null | undefined): string {
  if (days == null) return "";
  if (days < 1) return "today";
  const whole = Math.floor(days);
  return `${whole} day${whole === 1 ? "" : "s"} ago`;
}

/** The decision label of a not-yet-chosen item and of a chosen one, by kind. */
export function choiceLabels(item: OpenItem): { off: string; on: string } {
  return item.kind === "request"
    ? { off: "Do not send", on: "Send this request" }
    : { off: "Do not run", on: "Run this check" };
}

export const MONITOR_NEVER_SENDS = "A monitor never sends requests that change data. It kept this for you.";
