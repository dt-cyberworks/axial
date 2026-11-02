import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { api, type Finding } from "../api/client";
import RunReview from "./RunReview";

// REQ-RETEST-001: "Retest this finding" runs only the check that produced it, on its host, after the person has
// seen what that is. A finding no single check produced says so and retests the host.

export default function RetestControl({ finding, canManage }: { finding: Finding; canManage: boolean }) {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const engagementId = finding.engagement_id;
  const plan = useQuery({
    queryKey: ["retest-plan", engagementId, finding.id],
    queryFn: () => api.getRetestPlan(engagementId, finding.id),
    enabled: open,
  });
  if (!canManage || finding.status !== "open") return null;

  return (
    <section className="triage-panel" onClick={(e) => e.stopPropagation()}>
      <h3>Retest</h3>
      <p className="muted-line">Runs only the check that found this, on this host, to see whether it is still there. Nothing else is tested.</p>
      <button className="secondary-action" onClick={() => setOpen(true)}>Retest this finding</button>
      {open && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Retest this finding">
          <div className="modal-card">
            {plan.isLoading && <p className="muted-line">Working out what a retest would run…</p>}
            {plan.isError && <div className="error-block">The retest plan could not be loaded.</div>}
            {plan.data && (
              <RunReview
                engagementId={engagementId}
                items={plan.data.items}
                canManage={canManage}
                retestFindingId={finding.id}
                fallbackNote={plan.data.fallback ? plan.data.explanation : null}
                onCancel={() => setOpen(false)}
                onStarted={(runId) => {
                  queryClient.invalidateQueries({ queryKey: ["scan-runs", engagementId] });
                  navigate(runId ? `/engagements/${engagementId}/runs/${runId}` : `/engagements/${engagementId}`);
                }}
              />
            )}
          </div>
        </div>
      )}
    </section>
  );
}
