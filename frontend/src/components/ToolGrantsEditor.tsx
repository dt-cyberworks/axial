import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, type Engagement, type ToolCapability, type ToolGrant } from "../api/client";

// GitHub issue #48 (REQ-TOOL-006..008): the tool categories an engagement is authorized
// for can be changed until it is completed or revoked - not only while it is a draft.
// One editor, used on the draft's detail page and on the Edit page next to the per-tool
// switches, so all tool settings sit together.

export const TOOL_CATEGORIES = ["recon", "fingerprint", "vuln", "cred", "exploit"] as const;
type ToolCategory = typeof TOOL_CATEGORIES[number];
type GrantState = Record<ToolCategory, { passive: boolean; active: boolean; manualTools: string[] }>;

function emptyGrants(): GrantState {
  return {
    recon: { passive: false, active: false, manualTools: [] },
    fingerprint: { passive: false, active: false, manualTools: [] },
    vuln: { passive: false, active: false, manualTools: [] },
    cred: { passive: false, active: false, manualTools: [] },
    exploit: { passive: false, active: false, manualTools: [] },
  };
}

const sameSet = (a: string[], b: string[]) => a.length === b.length && [...a].sort().join("\n") === [...b].sort().join("\n");

interface Addition { category: ToolCategory; mode: "passive" | "active"; manualTools: string[]; widening: boolean }
interface Removal { category: ToolCategory; mode: "passive" | "active" }

/** The server answers 409 with "<code>: <sentence>"; show the sentence. */
export function grantErrorText(message: string): string {
  return message.replace(/^(scan_run_active|confirmation_required):\s*/, "");
}

export default function ToolGrantsEditor({ engagementId, status }: { engagementId: string; status: Engagement["status"] }) {
  const queryClient = useQueryClient();
  const isDraft = status === "draft";
  const { data: toolCapabilities } = useQuery({ queryKey: ["tool-capabilities"], queryFn: api.listToolCapabilities });
  const { data: savedGrants } = useQuery({ queryKey: ["tool-grants", engagementId], queryFn: () => api.listToolGrants(engagementId) });
  const { data: runs } = useQuery({
    queryKey: ["scan-runs", engagementId], queryFn: () => api.listScanRuns(engagementId), enabled: !isDraft,
  });
  const scanActive = (runs ?? []).some((run) => run.state === "running" || run.state === "waiting_approval");

  const [grants, setGrants] = useState<GrantState>(emptyGrants());
  const [synced, setSynced] = useState(false);
  const [confirming, setConfirming] = useState<Addition[] | null>(null);

  const toolsByCategory = useMemo(() => {
    const grouped: Record<ToolCategory, ToolCapability[]> = { recon: [], fingerprint: [], vuln: [], cred: [], exploit: [] };
    for (const tool of toolCapabilities?.tools ?? []) {
      if ((TOOL_CATEGORIES as readonly string[]).includes(tool.category) && tool.enabled) {
        grouped[tool.category as ToolCategory].push(tool);
      }
    }
    for (const category of TOOL_CATEGORIES) grouped[category].sort((a, b) => a.name.localeCompare(b.name));
    return grouped;
  }, [toolCapabilities]);

  const passiveToolsByCategory = useMemo(() => {
    const grouped: Record<ToolCategory, ToolCapability[]> = { recon: [], fingerprint: [], vuln: [], cred: [], exploit: [] };
    for (const category of TOOL_CATEGORIES) grouped[category] = toolsByCategory[category].filter((tool) => tool.execution_class === "passive");
    return grouped;
  }, [toolsByCategory]);

  // What the server has, as the editor's state. Re-read after every save.
  useEffect(() => {
    if (!savedGrants || synced) return;
    const next = emptyGrants();
    for (const grant of savedGrants) {
      const category = grant.tool_category as ToolCategory;
      if (!(TOOL_CATEGORIES as readonly string[]).includes(category)) continue;
      if (grant.mode === "passive") next[category].passive = true;
      if (grant.mode === "active") { next[category].active = true; next[category].manualTools = grant.manual_tools; }
    }
    setGrants(next);
    setSynced(true);
  }, [savedGrants, synced]);

  const saved = (category: ToolCategory, mode: "passive" | "active"): ToolGrant | undefined =>
    savedGrants?.find((g) => g.tool_category === category && g.mode === mode);

  // The difference between the editor and the server: what to add, what to take away.
  const plan = useMemo(() => {
    const additions: Addition[] = [];
    const removals: Removal[] = [];
    for (const category of TOOL_CATEGORIES) {
      const want = grants[category];
      const savedPassive = saved(category, "passive");
      const savedActive = saved(category, "active");
      if (want.passive && passiveToolsByCategory[category].length > 0 && !savedPassive) {
        additions.push({ category, mode: "passive", manualTools: [], widening: false });
      }
      if (!want.passive && savedPassive) removals.push({ category, mode: "passive" });
      if (want.active) {
        if (!savedActive || !sameSet(savedActive.manual_tools, want.manualTools)) {
          additions.push({ category, mode: "active", manualTools: want.manualTools, widening: !savedActive && !isDraft });
        }
      } else if (savedActive) {
        removals.push({ category, mode: "active" });
      }
    }
    return { additions, removals };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [grants, savedGrants, passiveToolsByCategory, isDraft]);
  const changes = plan.additions.length + plan.removals.length;

  const save = useMutation({
    mutationFn: async (confirmed: boolean) => {
      // Take away first (it only narrows), then add.
      for (const removal of plan.removals) await api.removeToolGrant(engagementId, removal.category, removal.mode);
      for (const addition of plan.additions) {
        await api.addToolGrant(engagementId, {
          tool_category: addition.category, mode: addition.mode, requires_manual_approval: false,
          manual_tools: addition.mode === "active" ? addition.manualTools : [],
          confirm_widening: addition.widening && confirmed,
        });
      }
    },
    onSettled: async () => {
      // Whatever went through is real: show the server's state, not the editor's guess.
      // Wait for the refetch first, or the editor would re-adopt the OLD state.
      setConfirming(null);
      queryClient.invalidateQueries({ queryKey: ["scan-readiness", engagementId] });
      queryClient.invalidateQueries({ queryKey: ["engagement-config", engagementId] });
      await queryClient.invalidateQueries({ queryKey: ["tool-grants", engagementId] });
      setSynced(false);
    },
  });

  function requestSave() {
    const widening = plan.additions.filter((a) => a.widening);
    if (widening.length > 0) setConfirming(widening);
    else save.mutate(false);
  }

  function toggleManualTool(category: ToolCategory, toolName: string, checked: boolean) {
    setGrants((current) => {
      const existing = new Set(current[category].manualTools);
      if (checked) existing.add(toolName);
      else existing.delete(toolName);
      return { ...current, [category]: { ...current[category], manualTools: [...existing].sort() } };
    });
  }

  function categoryGrantSummary(category: ToolCategory) {
    const grant = grants[category];
    const passiveTools = passiveToolsByCategory[category];
    if (grant.active) {
      const manual = grant.manualTools.length;
      return `${toolsByCategory[category].length} active tool${toolsByCategory[category].length === 1 ? "" : "s"} available, ${manual} require${manual === 1 ? "s" : ""} approval`;
    }
    if (passiveTools.length > 0) return `Passive available: ${passiveTools.map((tool) => tool.name).join(", ")}.`;
    return "No passive tools in this category. Enable active only if target-touching checks are authorized.";
  }

  // While a scan runs, nothing may be added or changed - but anything can be taken away.
  const lockedForAdding = (isChecked: boolean) => scanActive && !isChecked;

  return (
    <section className="form-panel settings-panel" id="tool-grants">
      <h2>Tool grants</h2>
      <p className="muted-line">
        Which kinds of testing this engagement is authorized for. The Scope Gateway checks these on every tool call,
        so a change applies from the next call. A grant never widens the scope you defined, and the per-tool
        switches below can only narrow what is granted here. Without an active grant no scan can start.
      </p>
      {!isDraft && (
        <div className="warning-block">
          This engagement is already authorized. Granting an active category widens what it may do, so you are asked to
          confirm it. Removing a grant narrows it and always works.
        </div>
      )}
      {scanActive && (
        <div className="warning-block">
          A scan is running on this engagement. You can remove a grant now (it stops that category from the next tool
          call), but adding or changing one has to wait until the scan finishes or is cancelled.
        </div>
      )}
      <div className="responsive-table">
        <table className="data-table tool-grant-table">
          <thead>
            <tr>
              <th>Category</th>
              <th>Allow passive</th>
              <th>Allow active</th>
              <th>Require approval for these active tools</th>
            </tr>
          </thead>
          <tbody>
            {TOOL_CATEGORIES.map((category) => (
              <tr key={category}>
                <td>
                  <strong>{category}</strong>
                  <span className="muted-line">{categoryGrantSummary(category)}</span>
                </td>
                <td>
                  {passiveToolsByCategory[category].length > 0 ? (
                    <label className="grant-toggle">
                      <input
                        type="checkbox"
                        checked={grants[category].passive}
                        disabled={lockedForAdding(grants[category].passive)}
                        onChange={(e) => setGrants((g) => ({ ...g, [category]: { ...g[category], passive: e.target.checked } }))}
                      />
                      <span>Passive allowed</span>
                      <small>{passiveToolsByCategory[category].map((tool) => tool.name).join(", ")}</small>
                    </label>
                  ) : (
                    <span className="muted-line">No passive tools</span>
                  )}
                </td>
                <td>
                  <label className="grant-toggle">
                    <input
                      type="checkbox"
                      checked={grants[category].active}
                      disabled={lockedForAdding(grants[category].active)}
                      onChange={(e) => setGrants((g) => ({ ...g, [category]: { ...g[category], active: e.target.checked } }))}
                    />
                    <span>Active allowed</span>
                  </label>
                </td>
                <td>
                  {grants[category].active ? (
                    <div className="tool-approval-grid">
                      {toolsByCategory[category].map((tool) => (
                        <label key={tool.name}>
                          <input
                            type="checkbox"
                            checked={grants[category].manualTools.includes(tool.name)}
                            disabled={scanActive}
                            onChange={(e) => toggleManualTool(category, tool.name, e.target.checked)}
                          />
                          <span>{tool.name}</span>
                          {!tool.dispatched && <small>catalog</small>}
                        </label>
                      ))}
                      {toolsByCategory[category].length === 0 && <span className="muted-line">No enabled tools in this category.</span>}
                    </div>
                  ) : (
                    <span className="muted-line">Not applicable until active is allowed.</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {confirming && (
        <div className="warning-block" role="alertdialog" aria-label="Confirm wider authorization">
          <strong>Confirm: this widens what the engagement is authorized to do.</strong>
          <p>
            Active testing will be allowed for: <strong>{confirming.map((a) => a.category).join(", ")}</strong>. The tools of
            {confirming.length === 1 ? " that category" : " those categories"} can then send requests to your in-scope
            targets from the next tool call. The change is written to the audit log with your name.
          </p>
          <div className="form-actions">
            <button className="primary-action" disabled={save.isPending} onClick={() => save.mutate(true)}>
              {save.isPending ? "Saving…" : "Confirm and save"}
            </button>
            <button disabled={save.isPending} onClick={() => setConfirming(null)}>Cancel</button>
          </div>
        </div>
      )}

      <div className="form-actions">
        <button disabled={save.isPending || changes === 0 || confirming !== null} onClick={requestSave}>
          {save.isPending && !confirming ? "Saving…" : "Save tool grants"}
        </button>
        {changes === 0 && synced && <span className="muted-line">No changes.</span>}
      </div>
      {save.isError && <div className="error-block">Save failed: {grantErrorText((save.error as Error).message)}</div>}
      {save.isSuccess && <div className="success-block">Tool grants saved. They apply from the next tool call.</div>}
    </section>
  );
}
