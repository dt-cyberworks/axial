import { useQuery } from "@tanstack/react-query";

import { api, type DnsRecord } from "../api/client";

function providerFlags(record: DnsRecord): string {
  const flags = [
    record.is_cdn && "CDN",
    record.is_saas && "SaaS",
    record.is_idp && "IdP",
    record.is_shared_infra && "shared infra",
  ].filter(Boolean);
  return flags.join(" · ");
}

function statusPill(record: DnsRecord): string {
  if (record.takeover_suspected) return "sev-high";
  if (record.dns_status === "unresolved") return "sev-low";
  return "sev-info";
}

export default function DnsSection({ engagementId }: { engagementId: string }) {
  const { data: records = [] } = useQuery({
    queryKey: ["dns-records", engagementId],
    queryFn: () => api.dnsRecords(engagementId),
    enabled: !!engagementId,
    refetchInterval: 10000,
  });

  const dangling = records.filter((r) => r.takeover_suspected).length;

  return (
    <section className="table-panel">
      <div className="panel-heading">
        <div>
          <h2>DNS &amp; hosting</h2>
          <p>
            How each in-scope name resolves (CNAME chain, hosting provider). Metadata only — a
            CNAME target is never scanned. A <strong>dangling</strong> row is a possible subdomain
            takeover; it is also raised as a finding for you to verify.
            {dangling > 0 && <> {" "}<span className="pill sev-high">{dangling} dangling</span></>}
          </p>
        </div>
      </div>
      <div className="responsive-table">
        <table className="data-table">
          <thead>
            <tr><th>Name</th><th>Resolves to</th><th>Provider</th><th>Status</th></tr>
          </thead>
          <tbody>
            {records.map((r) => (
              <tr key={r.id}>
                <td>{r.fqdn}</td>
                <td>
                  {r.cname_chain.length > 1 ? (
                    <span className="muted-line">{r.cname_chain.join(" → ")}</span>
                  ) : null}
                  {r.terminal_ips.length ? <div>{r.terminal_ips.join(", ")}</div> : null}
                  {!r.terminal_ips.length && r.cname_chain.length <= 1 ? <span className="muted-line">no address</span> : null}
                </td>
                <td>{r.hosting_provider ? <>{r.hosting_provider}{providerFlags(r) && <span className="muted-line">{providerFlags(r)}</span>}</> : <span className="muted-line">direct / unknown</span>}</td>
                <td><span className={`pill ${statusPill(r)}`}>{r.takeover_suspected ? "dangling — takeover?" : r.dns_status}</span></td>
              </tr>
            ))}
            {records.length === 0 && <tr><td className="empty-cell" colSpan={4}>No DNS records yet. Run a scan to resolve in-scope names.</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  );
}
