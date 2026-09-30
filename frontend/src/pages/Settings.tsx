import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, LlmConfig, NvdConfig, ToolPolicyEntry } from "../api/client";
import SubfinderKeys from "../components/SubfinderKeys";

const SOURCE_LABEL: Record<LlmConfig["source"], string> = {
  db: "configured in console",
  env: "from environment",
  unset: "not configured",
};

const NVD_SOURCE_LABEL: Record<NvdConfig["source"], string> = {
  db: "configured in console",
  env: "from environment",
  unset: "not configured (public rate limit)",
};

function looksLikeResponsesUrl(value: string) {
  return /\/responses\/?$/.test(value.trim());
}

export default function Settings() {
  const qc = useQueryClient();
  const { data, isLoading, error } = useQuery({
    queryKey: ["llm-config"],
    queryFn: api.getLlmConfig,
  });
  const { data: scanPolicy, isLoading: policyLoading, error: policyError } = useQuery({
    queryKey: ["scan-policy"],
    queryFn: api.getScanPolicy,
  });
  const { data: nvdConfig } = useQuery({ queryKey: ["nvd-config"], queryFn: api.getNvdConfig });

  const { data: toolPolicy } = useQuery({ queryKey: ["tool-policy"], queryFn: api.getToolPolicy });
  const { data: agentPromptData } = useQuery({ queryKey: ["agent-prompt"], queryFn: api.getAgentPrompt });
  const { data: agentMaxIterationsData } = useQuery({ queryKey: ["agent-max-iterations"], queryFn: api.getAgentMaxIterations });
  const { data: agentMaxTokensData } = useQuery({ queryKey: ["agent-max-tokens"], queryFn: api.getAgentMaxTokens });
  const { data: approvalTimeoutData } = useQuery({ queryKey: ["approval-timeout-seconds"], queryFn: api.getApprovalTimeoutSeconds });

  const [baseUrl, setBaseUrl] = useState("");
  const [model, setModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [maxRps, setMaxRps] = useState(5);
  const [autoThrottleEnabled, setAutoThrottleEnabled] = useState(false);
  const [tools, setTools] = useState<ToolPolicyEntry[]>([]);
  const [agentPrompt, setAgentPrompt] = useState("");
  const [agentMaxIterations, setAgentMaxIterations] = useState(50);
  const [agentMaxTokens, setAgentMaxTokens] = useState(8192);
  const [approvalTimeoutSeconds, setApprovalTimeoutSeconds] = useState(900);
  const [nvdApiKey, setNvdApiKey] = useState("");

  useEffect(() => { if (toolPolicy) setTools(toolPolicy); }, [toolPolicy]);
  useEffect(() => { if (agentPromptData) setAgentPrompt(agentPromptData.prompt); }, [agentPromptData]);
  useEffect(() => { if (agentMaxIterationsData) setAgentMaxIterations(agentMaxIterationsData.value); }, [agentMaxIterationsData]);
  useEffect(() => { if (agentMaxTokensData) setAgentMaxTokens(agentMaxTokensData.value); }, [agentMaxTokensData]);
  useEffect(() => { if (approvalTimeoutData) setApprovalTimeoutSeconds(approvalTimeoutData.value); }, [approvalTimeoutData]);

  const toolMutation = useMutation({
    mutationFn: () => api.updateToolPolicy(tools),
    onSuccess: (u) => qc.setQueryData(["tool-policy"], u),
  });
  const promptMutation = useMutation({
    mutationFn: () => api.updateAgentPrompt(agentPrompt),
    onSuccess: (u) => qc.setQueryData(["agent-prompt"], u),
  });
  const maxIterationsMutation = useMutation({
    mutationFn: () => api.updateAgentMaxIterations(agentMaxIterations),
    onSuccess: (u) => qc.setQueryData(["agent-max-iterations"], u),
  });
  const maxTokensMutation = useMutation({
    mutationFn: () => api.updateAgentMaxTokens(agentMaxTokens),
    onSuccess: (u) => qc.setQueryData(["agent-max-tokens"], u),
  });
  const approvalTimeoutMutation = useMutation({
    mutationFn: () => api.updateApprovalTimeoutSeconds(approvalTimeoutSeconds),
    onSuccess: (u) => qc.setQueryData(["approval-timeout-seconds"], u),
  });
  const setTool = (name: string, patch: Partial<ToolPolicyEntry>) =>
    setTools((prev) => prev.map((t) => (t.tool === name ? { ...t, ...patch } : t)));

  useEffect(() => {
    if (data) {
      setBaseUrl(data.base_url);
      setModel(data.model);
      setApiKey("");
    }
  }, [data]);

  useEffect(() => {
    if (scanPolicy) {
      setMaxRps(scanPolicy.max_rps);
      setAutoThrottleEnabled(scanPolicy.auto_throttle_enabled);
    }
  }, [scanPolicy]);

  const mutation = useMutation({
    mutationFn: () =>
      api.updateLlmConfig({
        base_url: baseUrl,
        model,
        ...(apiKey.trim() ? { api_key: apiKey.trim() } : {}),
      }),
    onSuccess: (updated) => {
      qc.setQueryData(["llm-config"], updated);
      setApiKey("");
    },
  });

  const policyMutation = useMutation({
    mutationFn: () => api.updateScanPolicy({ max_rps: maxRps, auto_throttle_enabled: autoThrottleEnabled }),
    onSuccess: (updated) => qc.setQueryData(["scan-policy"], updated),
  });

  const nvdMutation = useMutation({
    mutationFn: () => api.updateNvdConfig(nvdApiKey.trim() ? { api_key: nvdApiKey.trim() } : {}),
    onSuccess: (updated) => {
      qc.setQueryData(["nvd-config"], updated);
      setNvdApiKey("");
    },
  });

  if (isLoading || policyLoading) return <div className="loading-block">Loading settings...</div>;
  if (error) return <div className="error-block">Failed to load settings: {(error as Error).message}</div>;
  if (policyError) return <div className="error-block">Failed to load scan policy: {(policyError as Error).message}</div>;

  const warning = looksLikeResponsesUrl(baseUrl);

  return (
    <section className="page-stack">
      <header className="page-header">
        <div>
          <span className="eyebrow">Operational guardrails</span>
          <h1>Settings</h1>
          <p>Configure provider access and traffic policy. Scope Gateway still decides every action.</p>
        </div>
      </header>

      <div className="status-band">
        <div><span>Provider source</span><strong>{data ? SOURCE_LABEL[data.source] : "unknown"}</strong></div>
        <div><span>API key</span><strong>{data?.api_key_set ? "set" : "missing"}</strong></div>
        <div><span>Max RPS</span><strong>{scanPolicy?.max_rps ?? maxRps}</strong></div>
        <div><span>Auto slow down</span><strong>{scanPolicy?.auto_throttle_enabled ? "enabled" : "disabled"}</strong></div>
      </div>


      <section className="form-panel settings-panel">
        <h2>Scan rate policy</h2>
        <div className="warning-block">
          The gateway always enforces the rate limit. When auto slow down is enabled, workers wait for the gateway retry delay and ask again instead of treating the rate limit as a hard denial.
        </div>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            policyMutation.mutate();
          }}
          className="form-grid single-column"
        >
          <label>
            Maximum allowed tool calls per second
            <input
              type="number"
              min="0.1"
              max="100"
              step="0.1"
              value={maxRps}
              onChange={(e) => setMaxRps(Number(e.target.value))}
            />
          </label>
          <label className="toggle-row">
            <input type="checkbox" checked={autoThrottleEnabled} onChange={(e) => setAutoThrottleEnabled(e.target.checked)} />
            <span>Automatically slow down and retry rate-limited tool calls</span>
          </label>
          <div className="form-actions">
            <button type="submit" disabled={policyMutation.isPending}>{policyMutation.isPending ? "Saving..." : "Save scan policy"}</button>
          </div>
          {policyMutation.isError && <div className="error-block">Save failed: {(policyMutation.error as Error).message}</div>}
          {policyMutation.isSuccess && <div className="success-block">Saved.</div>}
        </form>
      </section>

      <section className="form-panel settings-panel">
        <h2>Provider</h2>
        {warning && (
          <div className="warning-block">
            Vector Agent and Lens Agent use a Chat Completions-compatible client. A base URL ending in /responses is normalized before use, but the provider must still expose a compatible /chat/completions endpoint.
          </div>
        )}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
          className="form-grid single-column"
        >
          <label>
            Base URL
            <input type="url" placeholder="https://api.openai.com/v1" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} />
          </label>
          <label>
            Model
            <input type="text" placeholder="gpt-4o-mini" value={model} onChange={(e) => setModel(e.target.value)} />
          </label>
          <label>
            API key
            <input
              type="password"
              placeholder={data?.api_key_set ? "set; leave empty to keep" : "not set"}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
            />
          </label>
          <div className="form-actions">
            <button type="submit" disabled={mutation.isPending}>{mutation.isPending ? "Saving..." : "Save provider"}</button>
          </div>
          {mutation.isError && <div className="error-block">Save failed: {(mutation.error as Error).message}</div>}
          {mutation.isSuccess && <div className="success-block">Saved.</div>}
        </form>
      </section>

      <section className="form-panel settings-panel">
        <h2>NVD API key (optional)</h2>
        <div className="warning-block">
          Used by live CVE correlation (NVD/EPSS/CISA-KEV) for fingerprinted services. Works without a key at NVD's public rate limit (5 requests/30s); a free NVD API key raises this to 50/30s. Never required.
        </div>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            nvdMutation.mutate();
          }}
          className="form-grid single-column"
        >
          <div className="status-band">
            <div><span>Source</span><strong>{nvdConfig ? NVD_SOURCE_LABEL[nvdConfig.source] : "unknown"}</strong></div>
            <div><span>API key</span><strong>{nvdConfig?.api_key_set ? "set" : "not set"}</strong></div>
          </div>
          <label>
            NVD API key
            <input
              type="password"
              placeholder={nvdConfig?.api_key_set ? "set; leave empty to keep" : "not set"}
              value={nvdApiKey}
              onChange={(e) => setNvdApiKey(e.target.value)}
            />
          </label>
          <div className="form-actions">
            <button type="submit" disabled={nvdMutation.isPending}>{nvdMutation.isPending ? "Saving..." : "Save NVD key"}</button>
          </div>
          {nvdMutation.isError && <div className="error-block">Save failed: {(nvdMutation.error as Error).message}</div>}
          {nvdMutation.isSuccess && <div className="success-block">Saved.</div>}
        </form>
      </section>

      <SubfinderKeys />

      <section className="form-panel settings-panel">
        <h2>Tool policy (global defaults)</h2>
        <div className="warning-block">
          The capability registry is the floor: tools that are not installed can never be enabled here, and scope plus argument-safety stay enforced regardless. This only tunes which tools are available and which require one-time approval. Campaigns can override these per engagement.
        </div>
        <div className="responsive-table">
          <table className="data-table">
            <thead>
              <tr><th>Tool</th><th>Category</th><th>Enabled</th><th>Needs approval</th></tr>
            </thead>
            <tbody>
              {tools.map((t) => (
                <tr key={t.tool}>
                  <td>{t.tool}{t.installed === false && <span className="muted-line">not installed</span>}</td>
                  <td>{t.category}</td>
                  <td>
                    <input type="checkbox" disabled={t.installed === false} checked={t.enabled}
                      onChange={(e) => setTool(t.tool, { enabled: e.target.checked })} />
                  </td>
                  <td>
                    <input type="checkbox" checked={t.requires_approval}
                      onChange={(e) => setTool(t.tool, { requires_approval: e.target.checked })} />
                  </td>
                </tr>
              ))}
              {tools.length === 0 && <tr><td className="empty-cell" colSpan={4}>No tools</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="form-actions">
          <button onClick={() => toolMutation.mutate()} disabled={toolMutation.isPending}>
            {toolMutation.isPending ? "Saving..." : "Save tool policy"}
          </button>
        </div>
        {toolMutation.isError && <div className="error-block">Save failed: {(toolMutation.error as Error).message}</div>}
        {toolMutation.isSuccess && <div className="success-block">Saved.</div>}
      </section>

      <section className="form-panel settings-panel">
        <h2>Vector Agent iteration budget (global default)</h2>
        <div className="warning-block">
          The maximum number of LLM tool-call round-trips the agent may make per run before it must conclude. Higher values let the agent investigate more but cost more time/tokens; a malformed or rejected proposal still consumes one iteration. Campaigns can override this per engagement.
        </div>
        <label>
          Max iterations
          <input
            type="number"
            min={1}
            max={500}
            value={agentMaxIterations}
            onChange={(e) => setAgentMaxIterations(Number(e.target.value))}
          />
        </label>
        <div className="form-actions">
          <button onClick={() => maxIterationsMutation.mutate()} disabled={maxIterationsMutation.isPending}>
            {maxIterationsMutation.isPending ? "Saving..." : "Save iteration budget"}
          </button>
        </div>
        {maxIterationsMutation.isError && <div className="error-block">Save failed: {(maxIterationsMutation.error as Error).message}</div>}
        {maxIterationsMutation.isSuccess && <div className="success-block">Saved.</div>}
      </section>

      {/* REQ-AGENT-026 */}
      <section className="form-panel settings-panel">
        <h2>Vector Agent max tokens (global default)</h2>
        <div className="warning-block">
          The completion token cap for a single LLM turn. This bounds the agent's <em>output</em> — its reasoning
          plus the tool-call JSON itself — not the context window. Setting it too low truncates a turn mid-JSON, so
          the tool call fails to parse and the agent stalls for no visible reason rather than simply answering more
          briefly. Campaigns can override this per engagement.
        </div>
        <label>
          Max tokens
          <input
            type="number"
            min={1024}
            max={32768}
            value={agentMaxTokens}
            onChange={(e) => setAgentMaxTokens(Number(e.target.value))}
          />
        </label>
        <div className="form-actions">
          <button onClick={() => maxTokensMutation.mutate()} disabled={maxTokensMutation.isPending}>
            {maxTokensMutation.isPending ? "Saving..." : "Save max tokens"}
          </button>
        </div>
        {maxTokensMutation.isError && <div className="error-block">Save failed: {(maxTokensMutation.error as Error).message}</div>}
        {maxTokensMutation.isSuccess && <div className="success-block">Saved.</div>}
      </section>

      <section className="form-panel settings-panel">
        <h2>Manual approval timeout (global default)</h2>
        <div className="warning-block">
          How long a state-changing request waits for an operator decision before it auto-rejects. Keeps a scan from hanging indefinitely if nobody is at the desk to approve or reject in time. Campaigns can override this per engagement.
        </div>
        <label>
          Timeout (seconds)
          <input
            type="number"
            min={60}
            max={86400}
            value={approvalTimeoutSeconds}
            onChange={(e) => setApprovalTimeoutSeconds(Number(e.target.value))}
          />
        </label>
        <div className="form-actions">
          <button onClick={() => approvalTimeoutMutation.mutate()} disabled={approvalTimeoutMutation.isPending}>
            {approvalTimeoutMutation.isPending ? "Saving..." : "Save approval timeout"}
          </button>
        </div>
        {approvalTimeoutMutation.isError && <div className="error-block">Save failed: {(approvalTimeoutMutation.error as Error).message}</div>}
        {approvalTimeoutMutation.isSuccess && <div className="success-block">Saved.</div>}
      </section>

      <section className="form-panel settings-panel">
        <h2>Vector Agent instructions (global default)</h2>
        <div className="warning-block">
          This is the agent's system prompt. Editing it is safe: the Scope Gateway decides every action deterministically, so no prompt — however aggressive — can cause an out-of-scope or destructive action. Leave empty to use the built-in default. Campaigns can override this per engagement.
        </div>
        <textarea
          rows={16}
          value={agentPrompt}
          onChange={(e) => setAgentPrompt(e.target.value)}
          placeholder="(empty = built-in default prompt)"
          style={{ width: "100%", fontFamily: "ui-monospace, monospace", fontSize: "0.82rem", padding: "10px", borderRadius: 6 }}
        />
        <div className="form-actions">
          <button onClick={() => promptMutation.mutate()} disabled={promptMutation.isPending}>
            {promptMutation.isPending ? "Saving..." : "Save agent instructions"}
          </button>
        </div>
        {promptMutation.isError && <div className="error-block">Save failed: {(promptMutation.error as Error).message}</div>}
        {promptMutation.isSuccess && <div className="success-block">Saved.</div>}
      </section>
    </section>
  );
}
