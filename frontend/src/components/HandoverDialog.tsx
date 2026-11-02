import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";

import { api, type Engagement } from "../api/client";
import {
  HELD_NOTE, blocker, buildRequest, emptyForm, handoverRefusal, overlapSentence, selectable, type HandoverForm,
} from "../lib/handover";

/**
 * REQ-HANDOVER-001..006: "Test this target in depth". One screen that creates a DRAFT assessment from a monitor. It
 * authorizes nothing: the window is given here, and the attestation, the tool permissions and the activation are done in
 * the wizard it opens. The monitor itself is never changed.
 */
export default function HandoverDialog({ engagement, onClose }: { engagement: Engagement; onClose: () => void }) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const preview = useQuery({ queryKey: ["handover-preview", engagement.id], queryFn: () => api.handoverPreview(engagement.id) });
  const [form, setForm] = useState<HandoverForm | null>(null);
  const data = preview.data;
  const current: HandoverForm = form ?? emptyForm(data?.suggested_title ?? `Test: ${engagement.title}`, data?.emergency_contact ?? null);
  const set = (patch: Partial<HandoverForm>) => setForm({ ...current, ...patch });
  const start = useMutation({
    mutationFn: () => api.startHandover(engagement.id, buildRequest(current, data?.hosts ?? [])),
    onSuccess: (created) => {
      queryClient.invalidateQueries({ queryKey: ["engagements"] });
      queryClient.invalidateQueries({ queryKey: ["handovers", engagement.id] });
      navigate(`/new?mode=assessment&draft=${created.id}`);
    },
  });
  const why = data ? blocker(current, data.hosts) : "Loading what the monitor knows.";
  const toggle = (host: string) =>
    set({ chosen: current.chosen.includes(host) ? current.chosen.filter((h) => h !== host) : [...current.chosen, host] });

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Test this target in depth">
      <div className="modal-card handover-card">
        <div className="panel-heading">
          <div><span className="eyebrow">From the monitor "{engagement.title}"</span><h3>Test this target in depth</h3></div>
        </div>
        <div className="modal-body">
          {preview.isLoading && <div className="loading-block">Loading what the monitor knows…</div>}
          {preview.isError && <div className="error-block">{handoverRefusal((preview.error as Error).message)}</div>}
          {data && (
            <>
              <div className="handover-lists">
                <div>
                  <h4>What carries over</h4>
                  <ul className="plain-list">{data.carried.map((line) => <li key={line}>{line}</li>)}</ul>
                </div>
                <div>
                  <h4>What does not</h4>
                  <ul className="plain-list">{data.not_carried.map((line) => <li key={line}>{line}</li>)}</ul>
                </div>
              </div>

              <h4>The test</h4>
              <label>Title<input value={current.title} onChange={(e) => set({ title: e.target.value })} /></label>
              <div className="form-row">
                <label>Test window starts<input type="datetime-local" value={current.from} onChange={(e) => set({ from: e.target.value })} /></label>
                <label>Test window ends<input type="datetime-local" value={current.until} onChange={(e) => set({ until: e.target.value })} /></label>
              </div>
              <label>Emergency contact<input value={current.emergencyContact} onChange={(e) => set({ emergencyContact: e.target.value })} /></label>

              <h4>Hosts to test</h4>
              {!current.wholeScope && (
                data.hosts.length === 0
                  ? <p className="muted-line">The monitor has not recorded any host of its own scope yet. Run it first, or use the monitor's whole scope below.</p>
                  : (
                    <table className="data-table handover-hosts">
                      <thead><tr><th /><th>Host</th><th>Services</th><th>Open findings</th><th>Note</th></tr></thead>
                      <tbody>
                        {data.hosts.map((h) => (
                          <tr key={h.host} className={selectable(h) ? "" : "muted-row"}>
                            <td><input type="checkbox" aria-label={`Test ${h.host}`} disabled={!selectable(h)}
                              checked={current.chosen.includes(h.host)} onChange={() => toggle(h.host)} /></td>
                            <td>{h.host}</td><td>{h.services}</td><td>{h.open_findings}</td>
                            <td>{!selectable(h) ? `Denied by the rule "${h.denied_by}"` : h.held ? HELD_NOTE : ""}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )
              )}
              <label className="inline-check">
                <input type="checkbox" checked={current.wholeScope} onChange={(e) => set({ wholeScope: e.target.checked, wholeScopeConfirmed: false })} />
                Use the monitor's whole scope instead
              </label>
              {current.wholeScope && (
                <div className="warning-block">
                  This copies every allow rule of the monitor ({data.allow_rows.map((r) => r.value).join(", ") || "none"}), subdomains included.
                  A test is normally commissioned for named hosts.
                  <label className="inline-check">
                    <input type="checkbox" checked={current.wholeScopeConfirmed} onChange={(e) => set({ wholeScopeConfirmed: e.target.checked })} />
                    I mean the whole scope
                  </label>
                </div>
              )}
              {data.deny_rows.length > 0 && (
                <p className="muted-line">The monitor's deny rules are always carried: {data.deny_rows.map((r) => r.value).join(", ")}.</p>
              )}

              <h4>What you do next</h4>
              <p>{overlapSentence(data.overlap)}</p>
              <p>Nothing is authorized yet. You will set the window's details, attest your authorization, choose the tools and activate in the next steps.
                The assessment starts with the Vector Agent on and the depth "{data.defaults.scan_profile}".</p>
            </>
          )}
          {start.isError && <div className="error-block">{handoverRefusal((start.error as Error).message)}</div>}
        </div>
        <div className="form-actions">
          {why && <span className="muted-line">{why}</span>}
          <button className="primary-action" disabled={!!why || start.isPending} onClick={() => start.mutate()}>
            {start.isPending ? "Creating…" : "Create draft assessment"}
          </button>
          <button className="secondary-action" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}
