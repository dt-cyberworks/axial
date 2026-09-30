import { useQuery } from "@tanstack/react-query";

import { api } from "../api/client";

// REQ-COVER-003/006: endpoints found by crawling / URL history, and web screenshots.
export default function DiscoverySection({
  engagementId, crawlingEnabled, screenshotsEnabled,
}: { engagementId: string; crawlingEnabled: boolean; screenshotsEnabled: boolean }) {
  const { data: endpoints = [] } = useQuery({
    queryKey: ["endpoints", engagementId],
    queryFn: () => api.discoveredEndpoints(engagementId),
    enabled: !!engagementId,
  });
  const { data: shots = [] } = useQuery({
    queryKey: ["screenshots", engagementId],
    queryFn: () => api.webScreenshots(engagementId),
    enabled: !!engagementId,
  });

  if (!crawlingEnabled && !screenshotsEnabled && endpoints.length === 0 && shots.length === 0) return null;
  const withParams = endpoints.filter((e) => e.param_names.length > 0).length;

  return (
    <>
      {(crawlingEnabled || endpoints.length > 0) && (
        <section className="table-panel">
          <div className="panel-heading">
            <div>
              <h2>Crawled endpoints</h2>
              <p>
                URLs found by crawling in-scope sites and from web-archive history, kept only when they
                are inside your scope. {endpoints.length} found, {withParams} with query parameters.
              </p>
            </div>
          </div>
          {endpoints.length === 0 ? (
            <p className="muted-line">Nothing found yet. Endpoints appear after the next scan.</p>
          ) : (
            <div className="responsive-table">
              <table className="data-table">
                <thead><tr><th>URL</th><th>Method</th><th>Parameters</th><th>Source</th></tr></thead>
                <tbody>
                  {endpoints.map((e) => (
                    <tr key={e.id}>
                      <td style={{ wordBreak: "break-all" }}>{e.url}</td>
                      <td>{e.method}</td>
                      <td>{e.param_names.length ? e.param_names.join(", ") : <span className="muted-line">none</span>}</td>
                      <td>{e.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {(screenshotsEnabled || shots.length > 0) && (
        <section className="table-panel">
          <div className="panel-heading">
            <div>
              <h2>Web screenshots</h2>
              <p>One screenshot per in-scope web page from the latest scan. Evidence of what the page showed; never a finding on its own.</p>
            </div>
          </div>
          {shots.length === 0 ? (
            <p className="muted-line">No screenshots yet. They appear after the next scan.</p>
          ) : (
            <div className="screenshot-grid" style={{ display: "grid", gap: 12, gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))" }}>
              {shots.map((s) => (
                <figure key={s.id} style={{ margin: 0 }}>
                  <a href={api.screenshotImageUrl(engagementId, s.id)} target="_blank" rel="noopener noreferrer">
                    <img
                      src={api.screenshotImageUrl(engagementId, s.id)}
                      alt={`Screenshot of ${s.url}`}
                      loading="lazy"
                      style={{ width: "100%", border: "1px solid var(--border, #ccc)", borderRadius: 6 }}
                    />
                  </a>
                  <figcaption className="muted-line" style={{ wordBreak: "break-all" }}>{s.url}</figcaption>
                </figure>
              ))}
            </div>
          )}
        </section>
      )}
    </>
  );
}
