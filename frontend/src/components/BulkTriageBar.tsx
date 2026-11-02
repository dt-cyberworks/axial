import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { api, type BulkTriageResult, type FindingStatus } from "../api/client";
import { STATUS_LABEL } from "../lib/findings";

const NOTE_REQUIRED: FindingStatus[] = ["accepted_risk", "false_positive"];

/**
 * REQ-TRIAGE-005/006: one decision for the findings selected in the list, with one shared
 * reason. Each finding is still changed and audited on its own, and nothing here is a rule: a
 * finding that does not exist yet is never affected. Mounted only for the owner or an
 * administrator. "Undo" restores what this one action changed.
 */
export default function BulkTriageBar({
  engagementId, selectedIds, listStatus, onClear,
}: { engagementId: string; selectedIds: string[]; listStatus: FindingStatus; onClear: () => void }) {
  const queryClient = useQueryClient();
  const [choice, setChoice] = useState<FindingStatus | null>(null);
  const [note, setNote] = useState("");
  const [last, setLast] = useState<BulkTriageResult | null>(null);
  const [undoneMessage, setUndoneMessage] = useState<string | null>(null);

  function refresh() {
    queryClient.invalidateQueries({ queryKey: ["findings", engagementId] });
    queryClient.invalidateQueries({ queryKey: ["summary", engagementId] });
    queryClient.invalidateQueries({ queryKey: ["all-findings"] });
  }
  const apply = useMutation({
    mutationFn: (status: FindingStatus) =>
      api.bulkTriageFindings(engagementId, { finding_ids: selectedIds, status, note: note.trim() || undefined }),
    onSuccess: (result) => {
      setLast(result);
      setUndoneMessage(null);
      setChoice(null);
      setNote("");
      onClear();
      refresh();
    },
  });
  const undo = useMutation({
    mutationFn: (bulkId: string) => api.undoBulkTriage(engagementId, bulkId),
    onSuccess: (result) => {
      setUndoneMessage(
        `Restored ${result.restored} finding${result.restored === 1 ? "" : "s"}` +
        (result.skipped ? `; ${result.skipped} changed again since and were left as they are.` : "."),
      );
      setLast(null);
      refresh();
    },
  });

  const count = selectedIds.length;
  const actions: { status: FindingStatus; label: string }[] = listStatus === "open"
    ? [{ status: "false_positive", label: "Mark false positive…" }, { status: "accepted_risk", label: "Accept risk…" },
       { status: "resolved", label: "Mark resolved…" }]
    : [{ status: "open", label: "Reopen…" }];
  const needsNote = choice !== null && NOTE_REQUIRED.includes(choice);

  if (count === 0 && !last && !undoneMessage && !apply.isError && !undo.isError) return null;

  return (
    <section className="bulk-bar" role="region" aria-label="Bulk triage" onClick={(e) => e.stopPropagation()}>
      {count > 0 && (
        <>
          <div className="bulk-bar-row">
            <strong>{count} finding{count === 1 ? "" : "s"} selected</strong>
            {actions.map((action) => (
              <button key={action.status} disabled={apply.isPending} onClick={() => setChoice(action.status)}>
                {action.label}
              </button>
            ))}
            <button className="secondary-action" onClick={() => { setChoice(null); setNote(""); onClear(); }}>
              Clear selection
            </button>
          </div>
          {choice && (
            <div className="triage-reason">
              <p>
                This sets <strong>{count} finding{count === 1 ? "" : "s"}</strong> to <strong>{STATUS_LABEL[choice]}</strong>.
                Each finding is changed and recorded on its own. It applies to these findings only: the same
                vulnerability on a host that is not listed here is still reported as open.
              </p>
              {needsNote && (
                <label>
                  {choice === "accepted_risk"
                    ? "Why is this risk acceptable? (required - shown with each finding in the report)"
                    : "Why are these false positives? (required - kept in the audit log for each finding)"}
                  <textarea value={note} maxLength={1000} rows={3} onChange={(e) => setNote(e.target.value)} />
                </label>
              )}
              <div className="form-actions">
                <button onClick={() => { setChoice(null); setNote(""); }}>Cancel</button>
                <button className="primary-action"
                  disabled={apply.isPending || (needsNote && note.trim().length < 3)}
                  onClick={() => apply.mutate(choice)}>
                  {apply.isPending ? "Applying…" : `Apply to ${count} finding${count === 1 ? "" : "s"}`}
                </button>
              </div>
            </div>
          )}
        </>
      )}
      {last && (
        <div className="success-block" role="status">
          {last.changed} finding{last.changed === 1 ? "" : "s"} set to {STATUS_LABEL[last.status]}
          {last.unchanged > 0 && `; ${last.unchanged} already had that status`}.{" "}
          <button disabled={undo.isPending} onClick={() => undo.mutate(last.bulk_id)}>
            {undo.isPending ? "Undoing…" : "Undo"}
          </button>
        </div>
      )}
      {undoneMessage && <div className="success-block" role="status">{undoneMessage}</div>}
      {apply.isError && <div className="error-block">Could not change the findings: {(apply.error as Error).message}</div>}
      {undo.isError && <div className="error-block">Could not undo: {(undo.error as Error).message}</div>}
    </section>
  );
}
