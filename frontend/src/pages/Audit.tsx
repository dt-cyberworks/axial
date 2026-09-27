import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { api, AuditRow } from "../api/client";
import MultiSelectFilter from "../components/MultiSelectFilter";

const PAGE_SIZE = 120;
const REFRESH_MS = 4000;

function decisionClass(decision: string | null) {
  if (decision === "ALLOW") return "good";
  if (decision === "DENY") return "bad";
  if (decision === "PENDING" || decision === "THROTTLE") return "warn";
  return "neutral";
}

function str(payload: Record<string, unknown> | undefined, key: string): string {
  const value = payload?.[key];
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
}

// One plain-language line describing what the system did (REQ-AUDITUI-002).
function summarize(entry: AuditRow): string {
  const p = entry.payload || {};
  switch (entry.action) {
    case "tool_call": {
      const tool = str(p, "tool") || "tool call";
      const target = str(p, "target");
      const meta = [str(p, "category"), str(p, "mode")].filter(Boolean).join("/");
      return `${tool}${target ? ` on ${target}` : ""}${meta ? ` (${meta})` : ""}`;
    }
    case "network_request": {
      const method = str(p, "method") || "request";
      const host = str(p, "host");
      const tail = str(p, "path") || (str(p, "port") ? `:${str(p, "port")}` : "");
      return `${method} ${host}${tail}`.trim();
    }
    case "tool_execution": {
      const tool = str(p, "tool") || "tool";
      const target = str(p, "resolved_target") || str(p, "authorized_target");
      const verb = entry.decision === "ALLOW" ? "completed" : "failed";
      // REQ-AUDIT-003: the exact invocation is the point of this entry - show a
      // prefix inline so it is visible while scanning the log, with the full
      // (already worker-side redacted) command in the expanded payload.
      const command = str(p, "command");
      const invocation = command ? ` — ${command.slice(0, 120)}${command.length > 120 ? "…" : ""}` : "";
      return `${tool} ${verb}${target ? ` on ${target}` : ""}${invocation}`;
    }
    case "agent_event": {
      const event = str(p, "event") || entry.reason || "event";
      const proposal = p["proposal"];
      let detail = "";
      if (proposal && typeof proposal === "object") {
        const pr = proposal as Record<string, unknown>;
        detail = [pr.tool, pr.target].filter((v) => typeof v === "string").join(" → ");
      }
      return `agent ${event}${detail ? `: ${detail}` : ""}`;
    }
    case "scan_run_transition":
      return `scan run → ${str(p, "phase")}/${str(p, "state")}`;
    case "approval_execution":
      return `approval ${entry.reason || ""}`.trim();
    case "gateway_override":
      return `operator override${entry.reason ? ` (${entry.reason.replace("manual_override:", "")})` : ""}`;
    default: {
      const label = entry.action.replace(/_/g, " ");
      return entry.reason ? `${label} — ${entry.reason}` : label;
    }
  }
}

// Short actor label shown as a chip.
function actorLabel(actor: string): string {
  if (actor.startsWith("user:")) return actor.slice(5);
  return actor;
}

// Keyed by reason code, shown for both DENY (a hard block, permanent for this
// call) and THROTTLE (a soft, retrying pause) entries - the two decisions an
// operator needs a plain-language reason for, as opposed to ALLOW/PENDING
// which are already self-explanatory from the summary line alone.
const REASON_EXPLANATIONS: Record<string, string> = {
  target_out_of_scope: "No allow-scope matched this target. A domain scope includes its subdomains; add an explicit allow only for a separately authorized domain/IP.",
  active_not_allowed: "The target is in scope, but active testing is not allowed for the matched scope asset.",
  no_tool_grant: "The engagement does not currently grant this active tool category.",
  ai_testing_not_enabled: "The Vector Agent is not enabled for autonomous proposals on this engagement.",
  explicit_out_of_scope: "A deny rule matched this target. Deny rules take precedence and are not bypassed from the audit view.",
  unsafe_arguments: "The tool arguments failed the registry safety policy. This needs code/registry changes, not an operator override.",
  tool_not_whitelisted: "The selected tool is not enabled in the capability registry.",
  passive_not_supported: "This tool has no passive execution path. Enable active testing only when target-touching checks are authorized.",
  rate_limited: "The engagement rate limit is currently exhausted.",
  rate_limited_wait: "The configured request rate is exhausted. The worker paused and will automatically retry rather than failing the call.",
  budget_exhausted: "The scan-run tool-call budget is exhausted.",
  blocked_link_local_address: "The target resolved to a link-local / cloud-metadata address (169.254.0.0/16). The egress proxy refuses these regardless of scope (SSRF containment).",
  blocked_loopback_address: "The target resolved to a loopback address. The egress proxy refuses these regardless of scope (SSRF containment).",
  ambiguous_host: "Two active engagements both scope this host, so the proxy cannot attribute the request and fails closed.",
  out_of_scope_port: "The target port is outside the engagement's authorized TCP port window.",
};

const OVERRIDE_LABELS: Record<string, string> = {
  target_out_of_scope: "Override: add scope",
  active_not_allowed: "Override: allow active target",
  no_tool_grant: "Override: add grant",
  ai_testing_not_enabled: "Override: enable agent",
};

const DECISION_FILTERS = [
  { key: "", label: "All" },
  { key: "ALLOW", label: "Allow" },
  { key: "DENY", label: "Deny" },
  { key: "PENDING", label: "Pending" },
];

export default function Audit() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();

  const [engagementTitle, setEngagementTitle] = useState<string>("");
  const [entries, setEntries] = useState<AuditRow[]>([]);
  const [facets, setFacets] = useState<{ actors: string[]; actions: string[] }>({ actors: [], actions: [] });
  const [hasMore, setHasMore] = useState(false);
  const [nextBefore, setNextBefore] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchInput, setSearchInput] = useState("");
  const [q, setQ] = useState("");
  const [decision, setDecision] = useState("");
  // REQ-AUDITUI-003: excluded-value sets, not selected-value sets - see
  // MultiSelectFilter for why a live log must default new values to visible.
  const [excludedActors, setExcludedActors] = useState<Set<string>>(new Set());
  const [excludedActions, setExcludedActions] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [overrideStatus, setOverrideStatus] = useState<string | null>(null);

  // Sending nothing means "all" to the backend, so only send an explicit list
  // once something is actually excluded - this keeps the common case a short
  // URL instead of enumerating every facet value on every poll.
  const actor = useMemo(
    () => (excludedActors.size ? facets.actors.filter((a) => !excludedActors.has(a)) : []),
    [facets.actors, excludedActors],
  );
  const action = useMemo(
    () => (excludedActions.size ? facets.actions.filter((a) => !excludedActions.has(a)) : []),
    [facets.actions, excludedActions],
  );
  // "Clear all" can leave zero values selected. That must show nothing, but an
  // empty list on the wire is indistinguishable from "no filter" - so this
  // case is handled here rather than being sent to the backend at all.
  const actorsAllExcluded = excludedActors.size > 0 && actor.length === 0;
  const actionsAllExcluded = excludedActions.size > 0 && action.length === 0;
  const nothingSelectable = actorsAllExcluded || actionsAllExcluded;

  // Auto-refresh pauses once the operator has paged into history, so newly
  // arriving head events never create a gap above already-loaded older ones.
  const [pagedIntoHistory, setPagedIntoHistory] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const filtersRef = useRef({ q, decision, actor, action, nothingSelectable });
  filtersRef.current = { q, decision, actor, action, nothingSelectable };

  useEffect(() => {
    if (!id) return;
    api.getEngagement(id).then((e) => setEngagementTitle(e.title)).catch(() => {});
    api.auditFacets(id).then(setFacets).catch(() => {});
  }, [id]);

  // Debounce the search box into the actual query.
  useEffect(() => {
    const t = setTimeout(() => setQ(searchInput.trim()), 300);
    return () => clearTimeout(t);
  }, [searchInput]);

  const loadHead = useCallback(
    async (opts?: { silent?: boolean }) => {
      if (!id) return;
      if (nothingSelectable) {
        // Every value of a facet was unchecked: the honest result is nothing.
        setEntries([]);
        setHasMore(false);
        setNextBefore(null);
        setPagedIntoHistory(false);
        setError(null);
        return;
      }
      if (!opts?.silent) setLoading(true);
      try {
        const res = await api.listAudit(id, { q, actor, action, decision, limit: PAGE_SIZE });
        setEntries(res.entries);
        setHasMore(res.has_more);
        setNextBefore(res.next_before);
        setPagedIntoHistory(false);
        setError(null);
      } catch (e) {
        setError((e as Error).message);
      } finally {
        if (!opts?.silent) setLoading(false);
      }
    },
    [id, q, actor, action, decision, nothingSelectable],
  );

  // (Re)load the head whenever filters change.
  useEffect(() => {
    loadHead();
  }, [loadHead]);

  // Live-ish tail: refresh the head on an interval while at the top of history.
  useEffect(() => {
    if (!autoRefresh || pagedIntoHistory) return;
    const timer = setInterval(() => {
      const f = filtersRef.current;
      if (f.nothingSelectable) return;
      api
        .listAudit(id!, { q: f.q, actor: f.actor, action: f.action, decision: f.decision, limit: PAGE_SIZE })
        .then((res) => {
          setEntries(res.entries);
          setHasMore(res.has_more);
          setNextBefore(res.next_before);
        })
        .catch(() => {});
    }, REFRESH_MS);
    return () => clearInterval(timer);
  }, [autoRefresh, pagedIntoHistory, id]);

  async function loadOlder() {
    if (!id || !nextBefore) return;
    setLoading(true);
    setPagedIntoHistory(true);
    try {
      const res = await api.listAudit(id, { q, actor, action, decision, limit: PAGE_SIZE, before: nextBefore });
      setEntries((prev) => {
        const seen = new Set(prev.map((e) => e.id));
        return [...prev, ...res.entries.filter((e) => !seen.has(e.id))];
      });
      setHasMore(res.has_more);
      setNextBefore(res.next_before);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  function toggle(entryId: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(entryId) ? next.delete(entryId) : next.add(entryId);
      return next;
    });
  }

  async function applyOverride(entry: AuditRow) {
    if (!id || !entry.reason || !entry.payload) return;
    setOverrideStatus("Applying override…");
    try {
      const result = await api.applyGatewayOverride(id, {
        reason: entry.reason,
        tool_call: entry.payload,
        approved_by: "operator",
      });
      setOverrideStatus(result.message);
      queryClient.invalidateQueries({ queryKey: ["engagement", id] });
      queryClient.invalidateQueries({ queryKey: ["scan-runs", id] });
      loadHead({ silent: true });
    } catch (e) {
      setOverrideStatus(`Override rejected: ${(e as Error).message}`);
    }
  }

  const denies = useMemo(() => entries.filter((e) => e.decision === "DENY").length, [entries]);
  const filtersActive = Boolean(q || decision || excludedActors.size || excludedActions.size);

  function clearFilters() {
    setSearchInput("");
    setQ("");
    setDecision("");
    setExcludedActors(new Set());
    setExcludedActions(new Set());
  }

  if (!id) return null;

  return (
    <section className="page-stack">
      <header className="page-header">
        <div>
          <span className="eyebrow">Audit log</span>
          <h1>{engagementTitle || "Engagement audit"}</h1>
          <p>Everything the system did, in order. Search a host, tool, target, or reason.</p>
        </div>
        <div className="header-actions">
          <Link to={`/engagements/${id}/live`} className="secondary-action">Live scan</Link>
          <Link to={`/engagements/${id}/results`} className="secondary-action">Results</Link>
        </div>
      </header>

      <div className="status-band">
        <div><span>Loaded events</span><strong>{entries.length}</strong></div>
        <div><span>Denies (loaded)</span><strong>{denies}</strong></div>
        <div><span>Auto-refresh</span><strong>{autoRefresh && !pagedIntoHistory ? "on" : "paused"}</strong></div>
      </div>

      <section className="table-panel">
        <div className="audit-toolbar">
          <input
            type="search"
            className="audit-search"
            placeholder="Search actor, action, reason, host, tool, target…"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            aria-label="Search audit log"
          />
          <div className="audit-decision-filter" role="group" aria-label="Filter by decision">
            {DECISION_FILTERS.map((f) => (
              <button
                key={f.key || "all"}
                className={`chip ${decision === f.key ? "chip-on" : ""}`}
                onClick={() => setDecision(f.key)}
              >
                {f.label}
              </button>
            ))}
          </div>
          <MultiSelectFilter
            label="Actors"
            options={facets.actors}
            excluded={excludedActors}
            onChange={setExcludedActors}
            renderOption={actorLabel}
          />
          <MultiSelectFilter
            label="Actions"
            options={facets.actions}
            excluded={excludedActions}
            onChange={setExcludedActions}
            renderOption={(a) => a.replace(/_/g, " ")}
          />
          {filtersActive && (
            <button className="secondary-action" onClick={clearFilters}>Clear</button>
          )}
          <label className="audit-autorefresh">
            <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} />
            Live
          </label>
        </div>

        {overrideStatus && <div className="inline-status">{overrideStatus}</div>}
        {error && <div className="inline-status error">{error}</div>}

        <ol className="audit-log">
          {entries.map((entry) => {
            const isOpen = expanded.has(entry.id);
            const overrideLabel = entry.decision === "DENY" && entry.reason ? OVERRIDE_LABELS[entry.reason] : undefined;
            const explanation = (entry.decision === "DENY" || entry.decision === "THROTTLE") && entry.reason
              ? REASON_EXPLANATIONS[entry.reason]
              : undefined;
            return (
              <li key={entry.id} className={`audit-line ${entry.decision === "DENY" ? "denied" : ""}`}>
                <button className="audit-line-main" onClick={() => toggle(entry.id)} aria-expanded={isOpen}>
                  <time className="audit-ts">{new Date(entry.ts).toLocaleString()}</time>
                  <span className={`pill ${decisionClass(entry.decision)}`}>{entry.decision ?? "INFO"}</span>
                  <span className="audit-actor" title={entry.actor}>{actorLabel(entry.actor)}</span>
                  <span className="audit-summary">{summarize(entry)}</span>
                  <span className="audit-caret">{isOpen ? "▾" : "▸"}</span>
                </button>
                {isOpen && (
                  <div className="audit-detail">
                    {explanation && (
                      <p className="audit-explain"><strong>{entry.reason}:</strong> {explanation}</p>
                    )}
                    <dl className="audit-facts">
                      <dt>Action</dt><dd>{entry.action}</dd>
                      <dt>Actor</dt><dd>{entry.actor}</dd>
                      {entry.reason && (<><dt>Reason</dt><dd>{entry.reason}</dd></>)}
                    </dl>
                    {entry.payload && Object.keys(entry.payload).length > 0 && (
                      <details className="payload-details" open>
                        <summary>Payload</summary>
                        <pre>{JSON.stringify(entry.payload, null, 2)}</pre>
                      </details>
                    )}
                    {overrideLabel && (
                      <div className="audit-override">
                        <button className="primary-action" onClick={() => applyOverride(entry)}>{overrideLabel}</button>
                      </div>
                    )}
                  </div>
                )}
              </li>
            );
          })}
          {entries.length === 0 && !loading && (
            <li className="empty-cell">{filtersActive ? "No audit events match these filters." : "No audit events yet."}</li>
          )}
        </ol>

        <div className="audit-footer">
          {loading && <span className="muted-line">Loading…</span>}
          {hasMore && !loading && (
            <button className="secondary-action" onClick={loadOlder}>Load older events</button>
          )}
          {!hasMore && entries.length > 0 && <span className="muted-line">Beginning of log.</span>}
        </div>
      </section>
    </section>
  );
}
