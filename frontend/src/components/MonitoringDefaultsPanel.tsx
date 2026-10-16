import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, type RunDepth } from "../api/client";

const LABELS: Record<string, string> = {
  public_discovery: "Public-source discovery",
  port_service_scan: "Port and service scan",
  web_fingerprint: "Web fingerprint, TLS and security headers",
  vulnerability_templates: "Vulnerability templates",
  content_discovery: "Content discovery",
  crawling: "Crawling and URL history",
  screenshots: "Web screenshots",
  out_of_band: "Out-of-band interaction testing",
  agent: "Vector Agent",
};

/**
 * REQ-MODE-006: what a NEW monitoring engagement starts with. The values are copied
 * into the engagement when it is created, so changing them here never changes an
 * engagement whose authorization someone already signed.
 */
export default function MonitoringDefaultsPanel() {
  const queryClient = useQueryClient();
  const { data } = useQuery({ queryKey: ["monitoring-defaults"], queryFn: api.getMonitoringDefaults });
  const [caps, setCaps] = useState<Record<string, boolean>>({});
  const [depth, setDepth] = useState<RunDepth>("standard");
  const [holdCustomer, setHoldCustomer] = useState("hold");
  const [holdOther, setHoldOther] = useState("auto");
  const [breaker, setBreaker] = useState(true);
  const [concurrent, setConcurrent] = useState(1);

  useEffect(() => {
    if (!data) return;
    setCaps(data.capabilities);
    setDepth(data.scan_profile);
    setHoldCustomer(data.new_asset_policy_customer);
    setHoldOther(data.new_asset_policy_other);
    setBreaker(data.fragility_breaker);
    setConcurrent(data.max_concurrent_monitoring_runs);
  }, [data]);

  const save = useMutation({
    mutationFn: () => api.updateMonitoringDefaults({
      capabilities: caps, scan_profile: depth,
      new_asset_policy_customer: holdCustomer as "auto" | "hold", new_asset_policy_other: holdOther as "auto" | "hold",
      fragility_breaker: breaker, max_concurrent_monitoring_runs: concurrent,
    }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["monitoring-defaults"] }),
  });

  return (
    <section className="form-panel settings-panel" aria-label="Monitoring defaults">
      <h2>Monitoring defaults</h2>
      <div className="warning-block">
        What a new monitoring engagement starts with. The values are copied when the engagement is created: a
        change here does not alter an engagement that already exists.
      </div>
      <div className="check-grid">
        {Object.keys(LABELS).map((id) => (
          <label key={id} className="check-row">
            <input type="checkbox" checked={!!caps[id]} onChange={(e) => setCaps({ ...caps, [id]: e.target.checked })} />
            <span><strong>{LABELS[id]}</strong></span>
          </label>
        ))}
      </div>
      <div className="form-grid">
        <label>Scan depth
          <select value={depth} onChange={(e) => setDepth(e.target.value as RunDepth)}>
            <option value="passive">Passive</option><option value="light">Light</option>
            <option value="standard">Standard</option><option value="thorough">Thorough</option>
          </select>
        </label>
        <label>New hosts of a customer's systems
          <select value={holdCustomer} onChange={(e) => setHoldCustomer(e.target.value)}>
            <option value="hold">Hold until released</option><option value="auto">Test when in scope</option>
          </select>
        </label>
        <label>New hosts of your own systems
          <select value={holdOther} onChange={(e) => setHoldOther(e.target.value)}>
            <option value="auto">Test when in scope</option><option value="hold">Hold until released</option>
          </select>
        </label>
        <label>Monitoring runs at the same time
          <input type="number" min={1} max={4} value={concurrent} onChange={(e) => setConcurrent(Number(e.target.value))} />
        </label>
      </div>
      <label className="toggle-row">
        <input type="checkbox" checked={breaker} onChange={(e) => setBreaker(e.target.checked)} />
        <span>Pause a monitor whose target starts failing</span>
      </label>
      <div className="form-actions">
        <button onClick={() => save.mutate()} disabled={save.isPending}>{save.isPending ? "Saving..." : "Save monitoring defaults"}</button>
      </div>
      {save.isError && <div className="error-block">Save failed: {(save.error as Error).message}</div>}
      {save.isSuccess && <div className="success-block">Saved.</div>}
    </section>
  );
}
