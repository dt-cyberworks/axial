import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, type RunDepth } from "../api/client";

const DEPTH_OPTIONS: { value: RunDepth; label: string; hint: string }[] = [
  { value: "passive", label: "Passive", hint: "Public sources only. Nothing is sent to your systems." },
  { value: "light", label: "Light", hint: "Fingerprint, TLS, security headers and takeover checks. Cheap enough to run daily." },
  { value: "standard", label: "Standard", hint: "Template checks chosen from what was found. The default." },
  { value: "thorough", label: "Thorough", hint: "All non-intrusive web templates and a deep content sweep. Slow." },
];

/**
 * REQ-MODE-006: what a monitoring engagement does, chosen once and held for every run.
 * One view over the grants, tool switches and discovery switches the gateway already
 * reads, so a change applies from the next call of any run, scheduled or manual.
 * It can only select among what the scope and grants allow.
 */
export default function CapabilitiesEditor({ engagementId, active, canManage }: {
  engagementId: string; active: boolean; canManage: boolean;
}) {
  const queryClient = useQueryClient();
  const { data, isError, error } = useQuery({
    queryKey: ["capabilities", engagementId],
    queryFn: () => api.getCapabilities(engagementId),
  });
  const [draft, setDraft] = useState<Record<string, boolean>>({});
  const [depth, setDepth] = useState<RunDepth>("standard");
  const [policy, setPolicy] = useState<"auto" | "hold">("auto");
  const [confirm, setConfirm] = useState(false);

  useEffect(() => {
    if (!data) return;
    setDraft(Object.fromEntries(data.capabilities.map((c) => [c.id, c.enabled])));
    setDepth(data.scan_profile);
    setPolicy(data.new_asset_policy);
    setConfirm(false);
  }, [data]);

  const save = useMutation({
    mutationFn: () => {
      const changes: Record<string, boolean> = {};
      for (const cap of data?.capabilities ?? []) {
        if (draft[cap.id] !== cap.enabled) changes[cap.id] = draft[cap.id];
      }
      return api.updateCapabilities(engagementId, {
        capabilities: changes,
        scan_profile: depth !== data?.scan_profile ? depth : undefined,
        new_asset_policy: policy !== data?.new_asset_policy ? policy : undefined,
        confirm_widening: confirm,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["capabilities", engagementId] });
      queryClient.invalidateQueries({ queryKey: ["engagement", engagementId] });
    },
  });

  if (isError) return <div className="error-block">Could not load the capabilities: {(error as Error).message}</div>;
  if (!data) return <p className="muted-line">Loading capabilities…</p>;

  const order = ["passive", "light", "standard", "thorough"];
  const widens =
    data.capabilities.some((c) => draft[c.id] && !c.enabled) ||
    order.indexOf(depth) > order.indexOf(data.scan_profile) ||
    (policy === "auto" && data.new_asset_policy === "hold");
  const changed =
    data.capabilities.some((c) => draft[c.id] !== c.enabled) || depth !== data.scan_profile || policy !== data.new_asset_policy;
  const needsConfirm = active && widens;

  return (
    <section className="form-panel settings-panel" aria-label="Capabilities">
      <h2>Capabilities</h2>
      <p className="muted-line">
        What this engagement does on every run, scheduled or started by a person. A run that is already going
        picks a change up on its next call. Nothing here goes beyond the scope, the grants and the authorization
        you attested; a capability can only select among them.
      </p>
      <div className="check-grid">
        {data.capabilities.map((cap) => (
          <label key={cap.id} className="check-row" title={cap.unavailable_reason ?? undefined}>
            <input
              type="checkbox"
              checked={!!draft[cap.id]}
              disabled={!canManage || !!cap.unavailable_reason}
              onChange={(e) => setDraft({ ...draft, [cap.id]: e.target.checked })}
            />
            <span>
              <strong>{cap.label}</strong>
              <span className="muted-line">{cap.unavailable_reason ? ` (${cap.unavailable_reason})` : ` ${cap.description}`}</span>
            </span>
          </label>
        ))}
      </div>

      <div className="form-grid">
        <label>
          Scan depth
          <select value={depth} disabled={!canManage} onChange={(e) => setDepth(e.target.value as RunDepth)}>
            {DEPTH_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          <span className="muted-line">{DEPTH_OPTIONS.find((o) => o.value === depth)?.hint}</span>
        </label>
        <label>
          New hosts
          <select value={policy} disabled={!canManage} onChange={(e) => setPolicy(e.target.value as "auto" | "hold")}>
            <option value="auto">Test as soon as the scope covers them</option>
            <option value="hold">Hold until I release them</option>
          </select>
          <span className="muted-line">
            A held host is listed and alerted but not tested. It is the unattended form of the asset review.
          </span>
        </label>
      </div>

      {needsConfirm && (
        <label className="check-row">
          <input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} />
          <span>I understand this widens what the engagement does without anyone watching.</span>
        </label>
      )}
      {canManage && (
        <div className="form-actions">
          <button
            className="primary-action"
            disabled={!changed || save.isPending || (needsConfirm && !confirm)}
            onClick={() => save.mutate()}
          >
            {save.isPending ? "Saving…" : "Save capabilities"}
          </button>
        </div>
      )}
      {save.isError && <div className="error-block">Could not save: {(save.error as Error).message}</div>}
      {save.isSuccess && !save.isPending && <div className="success-block">Saved. It holds for every run from the next call.</div>}
    </section>
  );
}
