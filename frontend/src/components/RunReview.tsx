import { useEffect, useMemo, useState } from "react";
import { useMutation } from "@tanstack/react-query";

import { api, type OpenItem } from "../api/client";
import { reasonExplanation } from "../lib/runActivity";
import {
  MONITOR_NEVER_SENDS, ageText, buildStartOptions, choiceLabels, countChosen, describeRequest, groupItems,
  initialChoice, runLabel,
} from "../lib/runReview";

// REQ-RETEST-005/006/007: "Review before you run". Every way of running only what is open (Retest this finding,
// Run this step again, Run the open items) opens this step, and nothing starts before its button is pressed. A
// request that changes data is in its own group, starts as "Do not send", has no bulk control, and is sent only if the
// person chooses it - that choice is the approval for exactly that request.

interface Props {
  engagementId: string;
  items: OpenItem[];
  canManage: boolean;
  /** Set for a retest of one finding: the finding is resolved when the run did not see it again. */
  retestFindingId?: string;
  /** Said when no single check produced the finding and the retest runs the whole host. */
  fallbackNote?: string | null;
  onStarted: (runId: string | undefined) => void;
  onCancel?: () => void;
  onChanged?: () => void;
}

function itemWhy(item: OpenItem): string {
  if (item.kind === "request") {
    if (item.reason === "approval_unavailable_unattended") return MONITOR_NEVER_SENDS;
    if (item.reason.startsWith("not_sent:")) return `It was confirmed once but not sent. ${reasonExplanation(item.reason)}`;
    return reasonExplanation(item.reason);
  }
  if (item.state === "retest") return "Runs again to see whether the finding is still there.";
  if (item.state === "did_not_run") return reasonExplanation("run_ended_early");
  if (item.state === "failed") return `It failed. ${reasonExplanation(item.reason)}`;
  if (item.state === "partial") return `It stopped at its time limit. ${reasonExplanation(item.reason)}`;
  return reasonExplanation(item.reason);
}

const location = (item: OpenItem) => `${item.host}${item.port ? `:${item.port}` : ""}`;

export default function RunReview({ engagementId, items, canManage, retestFindingId, fallbackNote, onStarted, onCancel, onChanged }: Props) {
  const [chosen, setChosen] = useState<Record<string, boolean>>(() => initialChoice(items));
  useEffect(() => setChosen(initialChoice(items)), [items]);
  const groups = useMemo(() => groupItems(items), [items]);
  const counts = countChosen(items, chosen);
  const options = buildStartOptions(items, chosen, { retestFindingId });

  const start = useMutation({
    mutationFn: () => api.startScan(
      engagementId,
      // A retest with nothing restricted runs the whole host, as retest_finding_id always did.
      options ?? (retestFindingId ? { retest_finding_id: retestFindingId, supervision: "attended" } : undefined),
    ),
    onSuccess: (res) => onStarted(res.scan_run_id),
  });
  const reject = useMutation({
    mutationFn: (requestId: string) => api.rejectOpenRequest(engagementId, requestId),
    onSuccess: () => onChanged?.(),
  });

  const hostFallback = items.length === 0 && !!retestFindingId;
  const nothing = !hostFallback && options === null;
  const set = (id: string, value: boolean) => setChosen((prev) => ({ ...prev, [id]: value }));

  return (
    <section className="form-panel settings-panel run-review" aria-label="Review before you run">
      <div className="panel-heading">
        <div>
          <h2>Review before you run</h2>
          <p className="muted-line">
            Nothing starts until you press the button at the bottom. Only what you choose here runs, not the whole engagement.
          </p>
        </div>
        <span className="pill neutral">{items.length} item{items.length === 1 ? "" : "s"}</span>
      </div>

      {!canManage && <div className="warning-block">Only the owner of this engagement or an administrator can run these. You can read them.</div>}
      {fallbackNote && <div className="warning-block">{fallbackNote}</div>}

      {groups.readOnly.length > 0 && (
        <div className="review-group" data-group="read-only">
          <h3>Runs without asking (read-only)</h3>
          <ul className="review-list">
            {groups.readOnly.map((item) => (
              <li key={item.id}>
                <label className="check-row">
                  <input type="checkbox" checked={chosen[item.id] === true} disabled={!canManage} onChange={(e) => set(item.id, e.target.checked)} />
                  <span><strong>{item.title}</strong> <span className="muted-line">reads pages only</span></span>
                </label>
                <p className="muted-line">{itemWhy(item)}{item.age_days != null && ` Last seen ${ageText(item.age_days)}.`}</p>
              </li>
            ))}
          </ul>
        </div>
      )}

      {groups.needsConfirmation.length > 0 && (
        <div className="review-group review-confirm" data-group="needs-confirmation">
          <h3>Needs your confirmation - this sends data to the target</h3>
          <ul className="review-list">
            {groups.needsConfirmation.map((item) => {
              const labels = choiceLabels(item);
              const req = item.request;
              return (
                <li key={item.id} className="review-confirm-item">
                  <fieldset>
                    <legend><strong>{item.title}</strong></legend>
                    {req && (
                      <>
                        <p>{describeRequest(req.method, !!req.body)}</p>
                        <pre className="agent-response">{[
                          `${req.method ?? "GET"} ${req.path ?? "/"}  →  ${req.target}`,
                          ...Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`),
                        ].join("\n")}{req.body ? `\n\n${req.body}` : ""}</pre>
                        {req.body_hidden && <p className="muted-line">The body is shown only to the engagement's owner and administrators.</p>}
                        {req.rationale && <p><strong>Why the agent wanted it:</strong> {req.rationale}</p>}
                        {req.risk?.description && (
                          <p><strong>The agent's own risk rating ({req.risk.level ?? "?"}):</strong> {req.risk.description}</p>
                        )}
                      </>
                    )}
                    {item.kind === "check" && (
                      <p>This check's tool asks for your approval. Each of its calls still asks you while it runs.</p>
                    )}
                    <p className="muted-line">
                      {itemWhy(item)}
                      {item.age_days != null && ` Held back ${ageText(item.age_days)}.`}
                    </p>
                    <div className="choice-row" role="radiogroup" aria-label={`Decision for ${item.title}`}>
                      <label className="check-row">
                        <input type="radio" name={`decision-${item.id}`} checked={chosen[item.id] !== true} disabled={!canManage}
                          onChange={() => set(item.id, false)} />
                        <span>{labels.off}</span>
                      </label>
                      <label className="check-row">
                        <input type="radio" name={`decision-${item.id}`} checked={chosen[item.id] === true} disabled={!canManage}
                          onChange={() => set(item.id, true)} />
                        <span>{labels.on}</span>
                      </label>
                      {item.kind === "request" && canManage && (
                        <button type="button" className="secondary-action" disabled={reject.isPending} onClick={() => reject.mutate(item.id)}>
                          Never send this
                        </button>
                      )}
                    </div>
                  </fieldset>
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {groups.expired.length > 0 && (
        <div className="review-group" data-group="expired">
          <h3>Too old to send</h3>
          <ul className="review-list">
            {groups.expired.map((item) => (
              <li key={item.id}>
                <strong>{item.title}</strong>
                <p className="muted-line">
                  Held back {ageText(item.age_days)}. A page, a session or the data it was made for may have changed, so it cannot be sent.
                  The monitor proposes it again if it still matters.
                </p>
              </li>
            ))}
          </ul>
        </div>
      )}

      {start.isError && <div className="error-block">{start.error instanceof Error ? start.error.message : "The run could not be started."}</div>}
      {reject.isError && <div className="error-block">{reject.error instanceof Error ? reject.error.message : "The request could not be rejected."}</div>}

      <div className="form-actions">
        {onCancel && <button className="secondary-action" onClick={onCancel}>Cancel</button>}
        <button className="primary-action" disabled={!canManage || nothing || start.isPending} onClick={() => start.mutate()}>
          {start.isPending ? "Starting…" : hostFallback ? "Retest all checks for this host" : runLabel(items, chosen)}
        </button>
      </div>
      {counts.approvals > 0 && <p className="muted-line">{counts.approvals} chosen check{counts.approvals === 1 ? "" : "s"} will ask for your approval during the run.</p>}
    </section>
  );
}
