import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "../api/client";

/**
 * REQ-BUDGET-001: how many tool calls one scan run may make. One global value; there is
 * deliberately no per-engagement override. A new value applies to the runs that start after it.
 * REQ-BUDGET-002: a run that uses it up is marked reduced coverage, never a clean run.
 */
export default function ToolCallBudgetPanel() {
  const qc = useQueryClient();
  const { data, isError, error } = useQuery({ queryKey: ["tool-call-budget"], queryFn: api.getToolCallBudget });
  const [value, setValue] = useState("200");
  useEffect(() => { if (data) setValue(String(data.value)); }, [data]);

  const save = useMutation({
    mutationFn: (next: number) => api.updateToolCallBudget(next),
    onSuccess: (updated) => qc.setQueryData(["tool-call-budget"], updated),
  });

  if (isError) {
    return (
      <section className="form-panel settings-panel" aria-label="Tool-call budget">
        <h2>Tool-call budget per run (global)</h2>
        <div className="error-block">Could not read the budget: {(error as Error).message}</div>
      </section>
    );
  }
  const min = data?.min ?? 20;
  const max = data?.max ?? 5000;
  const parsed = Number(value);
  const valid = Number.isInteger(parsed) && parsed >= min && parsed <= max;

  return (
    <section className="form-panel settings-panel" aria-label="Tool-call budget">
      <h2>Tool-call budget per run (global)</h2>
      <div className="warning-block">
        The most tool calls one scan run may make, planned checks and the Vector Agent together. When a run uses
        it up, the Scope Gateway refuses further calls: the checks behind them do not run, and the run is marked
        <strong> reduced coverage</strong> instead of clean. A scan with many web services, and the Thorough depth in
        particular, needs a higher number than a small site. The value applies to runs that start after you save it;
        a run that is already going keeps the budget it started with. It is not set per engagement, and raising it
        never widens scope or any other rule.
      </div>
      <label>
        Tool calls per run
        <input
          type="number" min={min} max={max} step={1} value={value}
          onChange={(e) => setValue(e.target.value)}
        />
      </label>
      <div className="form-actions">
        <button onClick={() => save.mutate(parsed)} disabled={!valid || save.isPending}>
          {save.isPending ? "Saving..." : "Save tool-call budget"}
        </button>
        {!valid && <span className="muted-line">Whole number, {min} to {max}.</span>}
      </div>
      {save.isError && <div className="error-block">Save failed: {(save.error as Error).message}</div>}
      {save.isSuccess && <div className="success-block">Saved. It applies to the next run.</div>}
    </section>
  );
}
