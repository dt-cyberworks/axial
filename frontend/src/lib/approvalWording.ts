// REQ-APPROVALUI-003: what the approval popup says about the request in front of the person, decided by what the
// request IS (its method and body) and WHO raised it (the Vector Agent or the automatic scan), so that the heading,
// the sender, the badge and the reason never contradict each other or the request.

export interface ApprovalCall {
  tool?: string;
  target?: string;
  phase?: string;
  args?: { method?: string; path?: string; headers?: Record<string, string>; body?: string };
  rationale?: string | null;
  risk?: { level?: string; description?: string } | null;
}

const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export interface ApprovalWording {
  heading: string;
  /** "The Vector Agent wants to send a read-only request" - without the engagement and the closing sentence. */
  action: string;
  /** The text of the badge in the corner. */
  badge: string;
  /** write: the badge shows the agent's risk level; read: a neutral badge. */
  badgeKind: "risk" | "read-only";
  isWrite: boolean;
  isHttp: boolean;
  fromAgent: boolean;
  whyLabel: string;
  whyText: string;
}

const toolName = (tool: string | undefined) => tool ?? "a tool";

/** A request is a write when its method writes or it carries a body, whatever anybody says about its risk. */
export function isWriteRequest(tc: ApprovalCall): boolean {
  const method = (tc.args?.method ?? "").toUpperCase();
  return WRITE_METHODS.has(method) || !!tc.args?.body;
}

export function approvalWording(tc: ApprovalCall): ApprovalWording {
  const isHttp = tc.args?.method != null;
  const isWrite = isHttp && isWriteRequest(tc);
  const fromAgent = tc.phase === "agent";
  const sender = fromAgent ? "The Vector Agent" : "The automatic scan";
  const reason = (tc.rationale ?? "").trim();

  let heading: string;
  let action: string;
  if (isWrite) {
    heading = "Approval required — state-changing request";
    action = `${sender} wants to send a write request`;
  } else if (isHttp) {
    heading = "Approval required — request";
    action = `${sender} wants to send a read-only request`;
  } else {
    heading = "Approval required — check";
    action = `${sender} wants to run ${toolName(tc.tool)}`;
  }

  const hasRisk = isWrite && (tc.risk?.level != null || tc.risk?.description != null);
  return {
    heading,
    action,
    badge: isWrite ? `risk: ${hasRisk ? (tc.risk?.level ?? "?") : "not assessed"}` : isHttp ? "read-only request" : "read-only check",
    badgeKind: isWrite ? "risk" : "read-only",
    isWrite,
    isHttp,
    fromAgent,
    whyLabel: fromAgent ? "Why (agent rationale)" : "Why (automatic scan)",
    whyText: reason || (fromAgent
      ? "The agent gave no reason for this request."
      : "No reason was recorded for this check."),
  };
}
