import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "../api/client";

/**
 * REQ-MON-004: "Run every N days" for a monitoring engagement, as one compact panel.
 *
 * The interval is the whole schedule: no time of day, no windows. The next run is N days
 * after the last run started (yours included) or after the engagement last became active, so
 * the first run of a new monitor is the one you start yourself with Run now. When a due run
 * cannot start, the reason is shown here, not only in a log.
 */
export default function ScheduleControl({ engagementId, canManage }: { engagementId: string; canManage: boolean }) {
  const queryClient = useQueryClient();
  const { data: schedule, isError, error } = useQuery({
    queryKey: ["schedule", engagementId],
    queryFn: () => api.getSchedule(engagementId),
    refetchInterval: 30000,
  });
  const [days, setDays] = useState("7");
  useEffect(() => {
    if (schedule?.every_days) setDays(String(schedule.every_days));
  }, [schedule?.every_days]);

  const save = useMutation({
    mutationFn: (every: number | null) => api.putSchedule(engagementId, every),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["schedule", engagementId] });
      queryClient.invalidateQueries({ queryKey: ["monitor-health", engagementId] });
    },
  });

  if (isError) {
    return <section className="form-panel schedule-panel" aria-label="Automatic runs">
      <div className="error-block">Could not read the schedule: {(error as Error).message}</div>
    </section>;
  }
  if (!schedule) return null;

  const min = schedule.min_days;
  const max = schedule.max_days;
  const parsed = Number(days);
  const valid = Number.isInteger(parsed) && parsed >= min && parsed <= max;
  const on = schedule.every_days !== null;
  const next = schedule.next_run_at ? new Date(schedule.next_run_at) : null;
  const due = next !== null && next.getTime() <= Date.now();

  return (
    <section className="form-panel schedule-panel" aria-label="Automatic runs">
      <h2>Automatic runs</h2>
      {on ? (
        <p>
          Runs by itself every <strong>{schedule.every_days} {schedule.every_days === 1 ? "day" : "days"}</strong>.{" "}
          {next && (due && !schedule.skip_message
            ? <>The next run is due now and starts within a minute.</>
            : <>Next run: <strong>{next.toLocaleString()}</strong>.</>)}
        </p>
      ) : (
        <p>Off. A run starts only when you press Run now.</p>
      )}
      {schedule.skip_message && (
        <div className="warning-block" role="status">
          A run is due but did not start: {schedule.skip_message}
        </div>
      )}
      <p className="muted-line">
        The count starts when the engagement becomes active and again with every run, yours included. Start the
        first run yourself with Run now. A scheduled run uses the same checks, scope and limits as one you start,
        and it never waits for a person.
      </p>
      {canManage ? (
        <div className="form-actions schedule-actions">
          <label>
            Every{" "}
            <input
              type="number" min={min} max={max} step={1} value={days} style={{ width: "5em" }}
              aria-label="Days between automatic runs"
              onChange={(e) => setDays(e.target.value)}
            />{" "}days
          </label>
          <button className="primary-action" disabled={!valid || save.isPending || (on && parsed === schedule.every_days)}
            onClick={() => save.mutate(parsed)}>
            {on ? "Change" : "Switch on"}
          </button>
          {on && (
            <button className="secondary-action" disabled={save.isPending} onClick={() => save.mutate(null)}>
              Switch off
            </button>
          )}
          {!valid && <span className="muted-line">Whole days, {min} to {max}.</span>}
        </div>
      ) : (
        <p className="muted-line">Only the owner or an administrator can change this.</p>
      )}
      {save.isError && <div className="error-block">{(save.error as Error).message}</div>}
    </section>
  );
}
