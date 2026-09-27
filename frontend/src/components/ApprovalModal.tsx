import { type ApprovalRequest } from "../api/client";

/**
 * Live approval popup for a state-changing agent request (REQ-APPROVAL-002/003):
 * shows What (method/path/headers/body), Why (rationale), and the LLM's Risk
 * assessment, with Approve / Reject. Rendered globally (REQ-APPROVALUI-001) by
 * GlobalApprovalWatcher, so it also names which engagement the request belongs
 * to and how many more are queued.
 */
export default function ApprovalModal({
  approval,
  busy,
  onDecide,
  engagementTitle,
  moreCount = 0,
  overlayClassName = "",
}: {
  approval: ApprovalRequest;
  busy: boolean;
  onDecide: (action: "approve" | "reject") => void;
  engagementTitle?: string;
  moreCount?: number;
  overlayClassName?: string;
}) {
  const tc = approval.tool_call as {
    tool?: string;
    target?: string;
    args?: { method?: string; path?: string; headers?: Record<string, string>; body?: string };
    rationale?: string;
    risk?: { level?: string; description?: string };
  };
  const args = tc.args ?? {};
  const risk = tc.risk ?? {};
  const headers = args.headers ?? {};
  const riskClass = risk.level === "high" ? "bad" : risk.level === "medium" ? "warn" : "neutral";
  // REQ-APPROVAL-006: not every gated tool is a crafted HTTP request - a
  // scanner (testssl/nikto/nuclei/...) has no method/path/risk concept at
  // all. Rendering "? →" and "(no risk description)" for those read as a
  // broken popup rather than a genuinely different, lower-risk tool shape.
  const isHttpShaped = args.method != null;
  const hasRiskAssessment = risk.level != null || risk.description != null;

  return (
    <div className={`modal-overlay ${overlayClassName}`.trim()}>
      <div className="modal-card">
        <div className="panel-heading">
          <div>
            <h2>Approval required — state-changing request</h2>
            <p>
              The Vector Agent wants to send a write request
              {engagementTitle ? <> on <strong>{engagementTitle}</strong></> : null}. It will not run
              until you approve it.
            </p>
          </div>
          <span className={`pill ${riskClass}`}>{hasRiskAssessment ? `risk: ${risk.level ?? "?"}` : "read-only check"}</span>
        </div>

        <div className="modal-body">
          <h4>What it will do</h4>
          {isHttpShaped ? (
            <pre className="agent-response">{`${args.method ?? "?"} ${args.path ?? ""}  →  ${tc.target ?? ""}`}
{Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("\n")}{args.body ? `\n\n${args.body}` : ""}</pre>
          ) : (
            <pre className="agent-response">{`${tc.tool ?? "?"}  →  ${tc.target ?? ""}`}</pre>
          )}

          <h4>Why (agent rationale)</h4>
          <p>{tc.rationale || "(no rationale provided)"}</p>

          {hasRiskAssessment && (
            <>
              <h4>Risk assessment (by the agent)</h4>
              <p>{risk.description || "(no risk description)"}</p>
            </>
          )}
        </div>

        <div className="form-actions">
          {moreCount > 0 && (
            <span className="muted-line approval-more">{moreCount} more approval{moreCount > 1 ? "s" : ""} waiting</span>
          )}
          <button className="danger-button" disabled={busy} onClick={() => onDecide("reject")}>Reject</button>
          <button className="primary-action" disabled={busy} onClick={() => onDecide("approve")}>
            {busy ? "…" : "Approve & open run"}
          </button>
        </div>
      </div>
    </div>
  );
}
