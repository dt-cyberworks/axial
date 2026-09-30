import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "../api/client";

// REQ-COVER-001: optional API keys for subfinder's data sources. Keys are
// write-only: the API says whether one is set, never what it is.
export default function SubfinderKeys() {
  const qc = useQueryClient();
  const { data, error } = useQuery({ queryKey: ["subfinder-keys"], queryFn: api.getSubfinderKeys });
  const [entered, setEntered] = useState<Record<string, string>>({});

  const save = useMutation({
    mutationFn: (keys: Record<string, string | null>) => api.setSubfinderKeys(keys),
    onSuccess: (updated) => {
      qc.setQueryData(["subfinder-keys"], updated);
      setEntered({});
    },
  });

  const pending = Object.fromEntries(
    Object.entries(entered).filter(([, v]) => v.trim()).map(([k, v]) => [k, v.trim()]),
  );

  return (
    <section className="form-panel settings-panel">
      <h2>Subdomain source keys (optional)</h2>
      <div className="warning-block">
        subfinder asks public data sources for subdomains of in-scope domains. It works without keys; some sources
        return more with a free key. Keys are stored encrypted, never shown again, and used only for these lookups.
      </div>
      {error && <div className="error-block">Failed to load: {(error as Error).message}</div>}
      <form
        className="form-grid single-column"
        onSubmit={(e) => { e.preventDefault(); if (Object.keys(pending).length) save.mutate(pending); }}
      >
        {(data?.providers ?? []).map((p) => (
          <div key={p.name} className="key-row" style={{ display: "flex", gap: 8, alignItems: "end" }}>
            <label style={{ flex: 1 }}>
              {p.name} <span className="muted-line">{p.key_set ? "(key set)" : "(no key)"}</span>
              <input
                type="password"
                autoComplete="off"
                placeholder={p.key_set ? "set; leave empty to keep" : "not set"}
                value={entered[p.name] ?? ""}
                onChange={(e) => setEntered((cur) => ({ ...cur, [p.name]: e.target.value }))}
              />
            </label>
            {p.key_set && (
              <button type="button" disabled={save.isPending} onClick={() => save.mutate({ [p.name]: "" })}>Remove</button>
            )}
          </div>
        ))}
        <div className="form-actions">
          <button type="submit" disabled={save.isPending || Object.keys(pending).length === 0}>
            {save.isPending ? "Saving..." : "Save keys"}
          </button>
        </div>
        {save.isError && <div className="error-block">Save failed: {(save.error as Error).message}</div>}
        {save.isSuccess && <div className="success-block">Saved.</div>}
      </form>
    </section>
  );
}
