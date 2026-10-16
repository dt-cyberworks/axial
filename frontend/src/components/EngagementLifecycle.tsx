import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { api, type Engagement } from "../api/client";

/**
 * REQ-MODE-003: the controls that stop work on an engagement and end it, as one compact
 * row. Pause stops the active run and makes the gateway deny every call until it is
 * resumed; Close ends a finished test; Revoke is the kill switch and cannot be undone.
 * Close and Revoke ask first.
 */
export default function EngagementLifecycle({ engagement }: { engagement: Engagement }) {
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState<"close" | "revoke" | null>(null);
  const done = () => {
    setConfirming(null);
    queryClient.invalidateQueries({ queryKey: ["engagement", engagement.id] });
    queryClient.invalidateQueries({ queryKey: ["scan-runs", engagement.id] });
    queryClient.invalidateQueries({ queryKey: ["scan-readiness", engagement.id] });
    queryClient.invalidateQueries({ queryKey: ["engagements"] });
  };
  const pause = useMutation({ mutationFn: () => api.pauseEngagement(engagement.id), onSuccess: done });
  const resume = useMutation({ mutationFn: () => api.resumeEngagement(engagement.id), onSuccess: done });
  const close = useMutation({ mutationFn: () => api.closeEngagement(engagement.id), onSuccess: done });
  const revoke = useMutation({ mutationFn: () => api.revokeEngagement(engagement.id), onSuccess: done });
  const error = [pause, resume, close, revoke].find((m) => m.isError)?.error as Error | undefined;
  const busy = pause.isPending || resume.isPending || close.isPending || revoke.isPending;
  const { status } = engagement;
  if (status === "completed" || status === "revoked") return null;

  return (
    <section className="lifecycle-bar" aria-label="Engagement controls">
      <span className="muted-line">Controls</span>
      {status === "active" && (
        <button className="secondary-action" disabled={busy} onClick={() => pause.mutate()}
          title="Stops the active run and denies every call until you resume">
          Pause engagement
        </button>
      )}
      {status === "paused" && (
        <button className="primary-action" disabled={busy} onClick={() => resume.mutate()}>
          Resume engagement
        </button>
      )}
      {(status === "active" || status === "paused") && (
        <button className="secondary-action" disabled={busy} onClick={() => setConfirming("close")}
          title="Ends a finished engagement; it cannot be resumed">
          Close engagement
        </button>
      )}
      <button className="danger-button" disabled={busy} onClick={() => setConfirming("revoke")}
        title="The kill switch: stops everything now; it cannot be undone">
        Revoke authorization
      </button>
      {confirming === "close" && (
        <div className="warning-block lifecycle-confirm">
          Close this engagement? It cannot be resumed afterwards. Its findings, runs and reports stay.
          <div className="form-actions">
            <button className="primary-action" disabled={busy} onClick={() => close.mutate()}>Close engagement</button>
            <button className="secondary-action" onClick={() => setConfirming(null)}>Cancel</button>
          </div>
        </div>
      )}
      {confirming === "revoke" && (
        <div className="warning-block lifecycle-confirm">
          Revoke the authorization? Every run stops now and the engagement can never scan again. This cannot be undone.
          <div className="form-actions">
            <button className="danger-button" disabled={busy} onClick={() => revoke.mutate()}>Revoke authorization</button>
            <button className="secondary-action" onClick={() => setConfirming(null)}>Cancel</button>
          </div>
        </div>
      )}
      {error && <div className="error-block lifecycle-confirm">{error.message}</div>}
    </section>
  );
}
