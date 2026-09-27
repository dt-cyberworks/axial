import { useEffect, useState } from "react";

/**
 * Re-renders the calling component on a fixed cadence while `active`
 * (REQ-RUNUI-001).
 *
 * Elapsed-time text is derived from `Date.now()` at render time
 * (`fmtDuration(start, null)` in lib/runs.ts). Without something driving
 * re-renders on its own schedule, that text only advances when some *other*
 * state happens to change - so a "started 14s ago" banner sits frozen until a
 * reload or a tab switch, which is precisely what a live run view must not do.
 *
 * Deliberately independent of the data-refetch interval: refetching run rows
 * every 4s is about data freshness, and a returned row that is byte-identical
 * to the previous one produces no re-render at all under react-query's
 * structural sharing. The clock is a rendering concern, so it gets its own
 * timer.
 *
 * The interval only exists while `active` is true, so a finished run stops
 * scheduling work.
 */
export function useTicker(active: boolean, intervalMs = 1000): number {
  const [tick, setTick] = useState(() => Date.now());

  useEffect(() => {
    if (!active) return;
    const timer = setInterval(() => setTick(Date.now()), intervalMs);
    return () => clearInterval(timer);
  }, [active, intervalMs]);

  return tick;
}
