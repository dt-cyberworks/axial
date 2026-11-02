import { Link } from "react-router-dom";

import type { InventoryDiff } from "../api/client";

// REQ-DIFF-001/002: the hosts and ports that appeared, vanished or changed since the previous full run. The same
// run the findings comparison uses, named here. A run that did not look everywhere never says something is gone.

const WHY_NOT: Record<string, string> = {
  no_baseline: "There is no earlier full run to compare with, so hosts and ports have no baseline yet.",
  no_snapshot: "Hosts and ports were not recorded for this run or for the run it would be compared with (it finished before they were stored for every engagement). The next run can be compared.",
};

function service(product?: string | null, version?: string | null): string {
  return [product, version].filter(Boolean).join(" ") || "unidentified service";
}

function Group({ title, tone, items, empty }: { title: string; tone: string; items: { key: string; note?: string }[]; empty: string }) {
  return (
    <div>
      <h3 className={`diff-title ${tone}`}>{title} ({items.length})</h3>
      <ul className="diff-list">
        {items.map((item) => (
          <li key={item.key}><span className="diff-item-title">{item.key}</span>{item.note && <span className="muted-line">{item.note}</span>}</li>
        ))}
        {items.length === 0 && <li className="muted">{empty}</li>}
      </ul>
    </div>
  );
}

export default function InventoryDiffPanel({ inventory, engagementId }: { inventory: InventoryDiff | undefined; engagementId: string }) {
  if (!inventory) return null;
  const summary = inventory.available
    ? `${inventory.assets_new.length} new host${inventory.assets_new.length === 1 ? "" : "s"}, ` +
      `${inventory.ports_opened.length} newly open port${inventory.ports_opened.length === 1 ? "" : "s"}, ` +
      `${inventory.services_changed.length} changed service${inventory.services_changed.length === 1 ? "" : "s"}` +
      (inventory.run_coverage_reduced ? "." : `, ${inventory.assets_gone.length} host${inventory.assets_gone.length === 1 ? "" : "s"} no longer seen, ${inventory.ports_closed.length} closed port${inventory.ports_closed.length === 1 ? "" : "s"}.`)
    : WHY_NOT[inventory.reason ?? "no_snapshot"];
  return (
    <section className="table-panel" aria-label="Hosts and ports">
      <div className="panel-heading">
        <div>
          <h2>Hosts and ports</h2>
          <p>
            {summary}
            {inventory.available && inventory.previous_run_id && (
              <> Compared with <Link to={`/engagements/${engagementId}/runs/${inventory.previous_run_id}`}>the previous full run</Link>.</>
            )}
          </p>
        </div>
      </div>
      {inventory.available && inventory.run_coverage_reduced && (
        <div className="warning-block" role="note">
          This run did not look everywhere (reduced coverage, or limited to some hosts), so it does not say that a host or
          port is gone: that may only mean it was not looked at. New and changed items are real.
        </div>
      )}
      {inventory.available && (
        <div className="diff-grid">
          <Group title="▲ New hosts" tone="diff-new" empty="No new hosts."
            items={inventory.assets_new.map((a) => ({ key: a.key, note: a.held ? "Held: not tested until you release it." : undefined }))} />
          <Group title="▲ Newly open ports" tone="diff-new" empty="No newly open ports."
            items={inventory.ports_opened.map((p) => ({ key: p.key, note: service(p.product, p.version) }))} />
          <Group title="Changed services" tone="diff-new" empty="No service changed its product or version."
            items={inventory.services_changed.map((s) => ({ key: s.key, note: `${service(s.from.product, s.from.version)} → ${service(s.to.product, s.to.version)}` }))} />
          {!inventory.run_coverage_reduced && (
            <>
              <Group title="▼ Hosts no longer seen" tone="diff-resolved" empty="Every earlier host was seen again."
                items={inventory.assets_gone.map((a) => ({ key: a.key }))} />
              <Group title="▼ Ports no longer open" tone="diff-resolved" empty="Every earlier port was found again."
                items={inventory.ports_closed.map((p) => ({ key: p.key, note: service(p.product, p.version) }))} />
            </>
          )}
        </div>
      )}
    </section>
  );
}
