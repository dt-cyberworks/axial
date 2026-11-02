import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";

import { api, isNotFound, type TargetCandidate, type TargetFlag } from "../api/client";
import NotFound from "./NotFound";
import { fmtTime } from "../lib/runs";

// REQ-BASE-002..006: the owner of a monitor chooses which discovered hosts are monitored. Activation
// started a passive discovery that sent nothing to the engagement's systems; nothing is scanned until
// this is confirmed. Unselected hosts become explicit deny rows, so the decision is on the record.

const FLAG_TEXT: Record<TargetFlag, { label: string; pill: "good" | "warn" | "neutral"; note: string }> = {
  same_address: { label: "Same address as a root", pill: "good", note: "Resolves to the same address as an allowed root." },
  other_address: { label: "Resolves elsewhere", pill: "warn", note: "Resolves to an address no allowed root uses. Select it only if you are authorized to test whatever answers there." },
  unresolved: { label: "Does not resolve", pill: "neutral", note: "Has no DNS address. Nothing can be tested on it today." },
};

const SOURCE_TEXT: Record<string, string> = {
  "scope-direct": "Your scope rule",
  "lab-direct": "Your scope rule",
  known: "Seen in an earlier run",
  "passive-osint": "Public sources (certificate logs, passive DNS)",
  subfinder: "Passive subdomain sources",
  "cidr-sweep": "Address-range sweep",
};
const sourceLabel = (via: string) => SOURCE_TEXT[via] ?? via;

function groupKey(c: TargetCandidate): string {
  return c.addresses.length > 0 ? c.addresses.slice().sort().join(", ") : "No address";
}

export default function TargetSelection() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const engagementQuery = useQuery({ queryKey: ["engagement", id], queryFn: () => api.getEngagement(id!), enabled: !!id });
  const targetsQuery = useQuery({
    queryKey: ["targets", id], queryFn: () => api.getTargets(id!), enabled: !!id,
    // The discovery is a run: look again until it has reported.
    refetchInterval: (query) => (query.state.data?.state === "discovering" ? 4000 : false),
  });
  const view = targetsQuery.data;
  const canManage = engagementQuery.data?.can_manage ?? false;

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [policy, setPolicy] = useState<"auto" | "hold">("hold");
  const [search, setSearch] = useState("");
  const [showUnresolved, setShowUnresolved] = useState(false);
  const [grouped, setGrouped] = useState(false);
  const [widening, setWidening] = useState(false);
  const initialised = useRef<string | null>(null);

  // The initial selection: what the owner has (a confirmed monitor) or what is suggested (a first choice).
  useEffect(() => {
    if (!view) return;
    const key = `${view.state}:${view.baseline_run?.id ?? ""}:${view.candidates.length}`;
    if (initialised.current === key) return;
    initialised.current = key;
    const initial = new Set<string>();
    for (const c of view.candidates) {
      if (c.is_root) initial.add(c.asset_id);
      else if (view.state === "confirmed" ? !c.denied : c.suggested && !c.denied) initial.add(c.asset_id);
    }
    setSelected(initial);
    setPolicy(view.new_asset_policy);
    setWidening(false);
  }, [view]);

  const candidates = view?.candidates ?? [];
  const visible = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return candidates.filter((c) => {
      if (!showUnresolved && c.flag === "unresolved" && !selected.has(c.asset_id)) return false;
      if (!needle) return true;
      return c.value.toLowerCase().includes(needle) || c.addresses.some((a) => a.includes(needle))
        || (c.provider ?? "").toLowerCase().includes(needle);
    });
  }, [candidates, search, showUnresolved, selected]);
  const hiddenUnresolved = candidates.filter((c) => c.flag === "unresolved" && !selected.has(c.asset_id)).length;

  const groups = useMemo(() => {
    if (!grouped) return [{ key: "", rows: visible }];
    const byKey = new Map<string, TargetCandidate[]>();
    for (const c of visible) byKey.set(groupKey(c), [...(byKey.get(groupKey(c)) ?? []), c]);
    return [...byKey.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, rows]) => ({ key, rows }));
  }, [visible, grouped]);

  const toggle = (c: TargetCandidate) => {
    if (c.is_root || !canManage) return;
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(c.asset_id)) next.delete(c.asset_id); else next.add(c.asset_id);
      return next;
    });
  };
  const setMany = (rows: TargetCandidate[], on: boolean) => {
    if (!canManage) return;
    setSelected((prev) => {
      const next = new Set(prev);
      for (const c of rows) {
        if (c.is_root) { next.add(c.asset_id); continue; }
        if (on) next.add(c.asset_id); else next.delete(c.asset_id);
      }
      return next;
    });
  };

  const invalidate = () => {
    for (const key of ["engagement", "targets", "scan-readiness", "scan-runs", "inbox", "inbox-count", "scope-assets"]) {
      queryClient.invalidateQueries({ queryKey: [key, ...(key === "inbox" || key === "inbox-count" ? [] : [id])] });
    }
  };
  const discover = useMutation({ mutationFn: () => api.discoverTargets(id!), onSuccess: invalidate });
  const confirm = useMutation({
    mutationFn: () => api.confirmTargets(id!, {
      selected_asset_ids: [...selected], new_asset_policy: policy, confirm_widening: widening,
    }),
    onSuccess: (result) => {
      invalidate();
      navigate(result.first_run_id ? `/engagements/${id}/runs/${result.first_run_id}` : `/engagements/${id}`);
    },
  });

  if (!id) return null;
  if (engagementQuery.isError && isNotFound(engagementQuery.error)) {
    return <NotFound title="Engagement not found" message="This engagement does not exist." />;
  }
  if (targetsQuery.isError) {
    return (
      <section className="page-stack">
        <div className="error-block">Could not load the targets: {(targetsQuery.error as Error).message}</div>
        <div className="form-actions"><button onClick={() => targetsQuery.refetch()}>Try again</button></div>
      </section>
    );
  }
  if (!view || !engagementQuery.data) return <section className="page-stack"><p className="muted-line">Loading targets…</p></section>;

  const title = engagementQuery.data.title;
  const state = view.state;
  const isConfirmed = state === "confirmed";
  const selectable = candidates.filter((c) => !c.is_root);
  const includedAgain = candidates.filter((c) => c.denied && selected.has(c.asset_id));
  // REQ-BASE-007: a held host that is chosen is released, which is a widening like including an excluded one.
  const releasedNow = candidates.filter((c) => c.held && selected.has(c.asset_id));
  const excludedNow = candidates.filter((c) => !c.is_root && !c.denied && !selected.has(c.asset_id));
  const needsWidening = includedAgain.length > 0 || releasedNow.length > 0;
  const wideningHosts = [...includedAgain, ...releasedNow.filter((c) => !includedAgain.includes(c))];
  const stateLabel = state === "discovering" ? "Discovering"
    : state === "awaiting_selection" ? "Choose targets"
    : state === "discovery_failed" ? "Discovery did not finish"
    : state === "confirmed" ? "Confirmed" : "Not applicable";

  return (
    <section className="page-stack">
      <nav className="breadcrumb">
        <Link to="/">Engagements</Link><span>/</span><Link to={`/engagements/${id}`}>{title}</Link><span>/</span><span>Targets</span>
      </nav>
      <header className="page-header">
        <div>
          <span className="eyebrow">Monitoring targets</span>
          <h1>{isConfirmed ? "Review targets" : "Choose the targets to monitor"}</h1>
          <p>
            {stateLabel}
            {view.confirmed_at && <> · confirmed {fmtTime(view.confirmed_at)}{view.confirmed_by ? ` by ${view.confirmed_by}` : ""}</>}
          </p>
        </div>
      </header>

      {view.operating_mode !== "monitoring" && (
        <div className="warning-block">Only a monitoring engagement has a target baseline. An assessment is scoped by its scope rows.</div>
      )}

      {!canManage && view.operating_mode === "monitoring" && (
        <div className="warning-block">Only the owner of this engagement or an administrator can change the targets. You can read them.</div>
      )}

      <div className="warning-block">
        The discovery used public sources and DNS only. It sent nothing to your systems.
        {!isConfirmed && " Nothing is scanned until you confirm the targets below, and the first scan then runs on exactly those."}
      </div>

      {state === "discovering" && (
        <section className="form-panel settings-panel">
          <h2>Discovery is running</h2>
          <p className="muted-line">
            This page refreshes by itself. Large domains can take a few minutes.
            {view.baseline_run && <> <Link to={`/engagements/${id}/runs/${view.baseline_run.id}`}>Open the discovery run</Link></>}
          </p>
        </section>
      )}

      {state === "discovery_failed" && (
        <section className="form-panel settings-panel">
          <h2>The discovery did not finish</h2>
          <div className="error-block">
            {view.baseline_run?.state_reason ?? view.baseline_run?.state ?? "The discovery run did not report."}
          </div>
          {canManage && (
            <div className="form-actions">
              <button className="primary-action" disabled={discover.isPending} onClick={() => discover.mutate()}>
                {discover.isPending ? "Starting…" : "Discover again"}
              </button>
            </div>
          )}
        </section>
      )}

      {(state === "awaiting_selection" || isConfirmed) && (
        <>
          <div className="status-band">
            <div><span>Found</span><strong>{view.counts.candidates ?? candidates.length}</strong></div>
            <div><span>Same address as a root</span><strong>{view.counts.same_address ?? 0}</strong></div>
            <div><span>Resolve elsewhere</span><strong>{view.counts.other_address ?? 0}</strong></div>
            <div><span>Do not resolve</span><strong>{view.counts.unresolved ?? 0}</strong></div>
          </div>

          <section className="table-panel" aria-label="Discovered hosts">
            <div className="bulk-bar">
              <div className="bulk-bar-row">
                <input
                  type="search" aria-label="Search hosts" placeholder="Search host, address or provider"
                  value={search} onChange={(e) => setSearch(e.target.value)}
                />
                <label className="check-row">
                  <input type="checkbox" checked={grouped} onChange={(e) => setGrouped(e.target.checked)} />
                  <span>Group by address</span>
                </label>
                <label className="check-row">
                  <input type="checkbox" checked={showUnresolved} onChange={(e) => setShowUnresolved(e.target.checked)} />
                  <span>Show names that do not resolve{!showUnresolved && hiddenUnresolved > 0 ? ` (${hiddenUnresolved} hidden)` : ""}</span>
                </label>
              </div>
              {canManage && (
                <div className="bulk-bar-row">
                  <button className="secondary-action" onClick={() => setMany(visible, true)}>Select all shown</button>
                  <button className="secondary-action" onClick={() => setMany(visible, false)}>Select none shown</button>
                  <button className="secondary-action" onClick={() => setMany(candidates.filter((c) => c.suggested && !c.denied), true)}>
                    Select suggested (same address as a root)
                  </button>
                  {isConfirmed && (
                    <button className="secondary-action" disabled={discover.isPending} onClick={() => discover.mutate()}>
                      {discover.isPending ? "Starting…" : "Discover again"}
                    </button>
                  )}
                </div>
              )}
            </div>
            <div className="responsive-table">
              <table className="data-table">
                <thead>
                  <tr>
                    <th className="select-cell" />
                    <th>Host</th><th>Address</th><th>Provider</th><th>Where it points</th><th>Found by</th>
                  </tr>
                </thead>
                <tbody>
                  {groups.map((group) => (
                    <GroupRows
                      key={group.key || "all"} group={group} showHeader={grouped} selected={selected}
                      canManage={canManage} toggle={toggle} setMany={setMany}
                    />
                  ))}
                  {visible.length === 0 && (
                    <tr><td className="empty-cell" colSpan={6}>
                      {candidates.length === 0 ? "The discovery found nothing besides your scope rows." : "No host matches the filter."}
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <section className="form-panel settings-panel" aria-label="Decision">
            <h2>New hosts after this baseline</h2>
            <div className="radio-group">
              <label className="check-row">
                <input type="radio" name="policy" checked={policy === "hold"} disabled={!canManage} onChange={() => setPolicy("hold")} />
                <span><strong>Hold until I release them</strong> (recommended): a host that appears later is listed in the inbox and not tested.</span>
              </label>
              <label className="check-row">
                <input type="radio" name="policy" checked={policy === "auto"} disabled={!canManage} onChange={() => setPolicy("auto")} />
                <span><strong>Test as soon as the scope covers them</strong>: nobody looks at a new host before it is tested.</span>
              </label>
            </div>

            <h2>Your decision</h2>
            <p>
              {selected.size} of {candidates.length} hosts are monitored
              {excludedNow.length > 0 && <>; <strong>{excludedNow.length}</strong> will be excluded (a deny rule is added for each)</>}
              {includedAgain.length > 0 && <>; <strong>{includedAgain.length}</strong> excluded before will be included again</>}
              {releasedNow.length > 0 && <>; <strong>{releasedNow.length}</strong> held host{releasedNow.length === 1 ? " is" : "s are"} released and will be tested</>}
              .
              Your allow rules stay: they are the record of what you are authorized to test.
              {selectable.length === 0 && " There is nothing to choose besides the roots."}
            </p>

            {needsWidening && canManage && (
              <label className="check-row">
                <input type="checkbox" checked={widening} onChange={(e) => setWidening(e.target.checked)} />
                <span>
                  I confirm that including or releasing {wideningHosts.length === 1 ? "this host" : "these hosts"} widens what is tested:
                  {" "}{wideningHosts.slice(0, 5).map((c) => c.value).join(", ")}{wideningHosts.length > 5 ? ", …" : ""}
                </span>
              </label>
            )}

            {canManage && (
              <div className="form-actions">
                <button
                  className="primary-action"
                  disabled={confirm.isPending || (needsWidening && !widening)}
                  onClick={() => confirm.mutate()}
                >
                  {confirm.isPending ? "Saving…"
                    : isConfirmed ? "Save the targets"
                    : `Confirm ${selected.size} target${selected.size === 1 ? "" : "s"} and start the first scan`}
                </button>
                <Link className="secondary-action" to={`/engagements/${id}`}>Cancel</Link>
              </div>
            )}
            {confirm.isError && <div className="error-block">Could not confirm: {(confirm.error as Error).message}</div>}
            {discover.isError && <div className="error-block">Could not start the discovery: {(discover.error as Error).message}</div>}
          </section>
        </>
      )}
    </section>
  );
}

function GroupRows({
  group, showHeader, selected, canManage, toggle, setMany,
}: {
  group: { key: string; rows: TargetCandidate[] };
  showHeader: boolean;
  selected: Set<string>;
  canManage: boolean;
  toggle: (c: TargetCandidate) => void;
  setMany: (rows: TargetCandidate[], on: boolean) => void;
}) {
  const allOn = group.rows.every((c) => selected.has(c.asset_id));
  return (
    <>
      {showHeader && (
        <tr className="group-row">
          <td className="select-cell">
            {canManage && (
              <input type="checkbox" aria-label={`Select all hosts at ${group.key}`} checked={allOn} onChange={(e) => setMany(group.rows, e.target.checked)} />
            )}
          </td>
          <td colSpan={5}><strong>{group.key}</strong> <span className="muted-line">{group.rows.length} host{group.rows.length === 1 ? "" : "s"}</span></td>
        </tr>
      )}
      {group.rows.map((c) => {
        const flag = FLAG_TEXT[c.flag];
        return (
          <tr key={c.asset_id}>
            <td className="select-cell">
              <input
                type="checkbox" aria-label={`Monitor ${c.value}`} checked={selected.has(c.asset_id)}
                disabled={c.is_root || !canManage} onChange={() => toggle(c)}
                title={c.is_root ? "A root of your scope cannot be left out" : undefined}
              />
            </td>
            <td>
              {c.value}
              {c.is_root && <> <span className="pill neutral">root</span></>}
              {c.denied && <> <span className="pill bad">excluded</span></>}
              {c.held && <> <span className="pill warn" title="Held back by the hold policy and not tested. Choosing it releases it, and it is tested from the next run.">held</span></>}
            </td>
            <td>{c.addresses.length > 0 ? c.addresses.join(", ") : "—"}</td>
            <td>{c.provider ?? "—"}</td>
            <td title={flag.note}>
              <span className={`pill ${flag.pill}`}>{flag.label}</span>
              {c.flag === "other_address" && <span className="muted-line">{flag.note}</span>}
            </td>
            <td>{sourceLabel(c.discovered_via)}{c.first_seen ? <span className="muted-line">{fmtTime(c.first_seen)}</span> : null}</td>
          </tr>
        );
      })}
    </>
  );
}
