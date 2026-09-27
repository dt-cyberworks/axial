import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import dagre from "cytoscape-dagre";

import { api, type SurfaceNode } from "../api/client";

// REQ-GRAPH-004: read-only attack-surface graph. Cytoscape.js with a
// deterministic dagre (layered, left-to-right) layout - real engagements run
// well past the "small graph" assumption the original hand-rolled SVG made
// (up to ~120 nodes, 60% concentrated in one node type), and a fixed-height
// pan/zoomable canvas reads better at that density than an ever-growing page.
// The graph is derived metadata: it never widens scope, and non-scannable
// (context-only) nodes are drawn visually distinct (dashed).

cytoscape.use(dagre);

const NODE_TYPES: SurfaceNode["node_type"][] = [
  "engagement", "domain", "subdomain", "ip", "service", "technology", "cve", "finding", "dns_artifact",
];

// Cytoscape draws to canvas, which can't resolve CSS custom properties, so
// the palette is read once from the live stylesheet (docs/design/axial-brand-design.md
// is the source of truth for the values) rather than duplicated as literals.
function cssVar(name: string, fallback: string): string {
  if (typeof window === "undefined") return fallback;
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

function truncate(label: string, max = 22): string {
  return label.length > max ? label.slice(0, max - 1) + "…" : label;
}

export default function SurfaceGraph({ engagementId }: { engagementId: string }) {
  const { data: graph } = useQuery({
    queryKey: ["surface-graph", engagementId],
    queryFn: () => api.surfaceGraph(engagementId),
    enabled: !!engagementId,
    refetchInterval: 10000,
  });
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const nodeColor = useMemo<Record<SurfaceNode["node_type"], string>>(() => ({
    engagement: cssVar("--ink-soft", "#c7d0dc"),
    domain: cssVar("--teal", "#00d1b2"),
    subdomain: cssVar("--blue", "#3d8bff"),
    ip: cssVar("--purple", "#6c5ce7"),
    service: cssVar("--teal-dark", "#00a892"),
    technology: cssVar("--muted", "#8a97a8"),
    cve: cssVar("--red", "#ff5c6c"),
    finding: cssVar("--yellow", "#ffb020"),
    dns_artifact: cssVar("--green", "#33d17a"),
  }), []);

  const byId = useMemo(() => {
    const m = new Map<string, SurfaceNode>();
    for (const n of graph?.nodes ?? []) m.set(n.id, n);
    return m;
  }, [graph]);

  const elements = useMemo<ElementDefinition[]>(() => {
    const nodes = graph?.nodes ?? [];
    const edges = graph?.edges ?? [];
    const nodeEls: ElementDefinition[] = nodes.map((n) => ({
      data: {
        id: n.id,
        label: truncate(n.label),
        color: nodeColor[n.node_type],
        scannable: n.scannable,
      },
      classes: n.scannable ? "" : "context-only",
    }));
    const edgeEls: ElementDefinition[] = edges
      .filter((e) => byId.has(e.src) && byId.has(e.dst))
      .map((e, i) => ({
        data: { id: `e${i}`, source: e.src, target: e.dst },
        classes: e.edge_type === "SHARES_INFRA" ? "shares-infra" : "",
      }));
    return [...nodeEls, ...edgeEls];
  }, [graph, byId, nodeColor]);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);

  // Mount/update the graph. Layout is deterministic (dagre, no randomized
  // initial positions) so the diagram doesn't reshuffle on every refetch.
  useEffect(() => {
    const container = containerRef.current;
    if (!container || elements.length === 0) return;

    const lineColor = cssVar("--line-strong", "#34445a");
    const purple = cssVar("--purple", "#6c5ce7");
    const textColor = cssVar("--text", "#eef3f8");
    const surface = cssVar("--surface", "#151a23");

    const cy = cytoscape({
      container,
      elements,
      minZoom: 0.2,
      maxZoom: 2.5,
      wheelSensitivity: 0.25,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "data(color)",
            label: "data(label)",
            color: "#fff",
            "font-size": 10,
            "text-valign": "center",
            "text-halign": "center",
            "text-wrap": "ellipsis",
            "text-max-width": "90px",
            shape: "round-rectangle",
            width: 110,
            height: 28,
            "border-width": 1,
            "border-color": surface,
          },
        },
        {
          selector: "node.context-only",
          style: { "border-style": "dashed", "border-width": 1.5, opacity: 0.85 },
        },
        {
          selector: "node:selected",
          style: { "border-color": textColor, "border-width": 2.5 },
        },
        {
          selector: "node.dimmed",
          style: { opacity: 0.2 },
        },
        {
          selector: "edge",
          style: {
            width: 1.2,
            "line-color": lineColor,
            "target-arrow-color": lineColor,
            "target-arrow-shape": "triangle",
            "arrow-scale": 0.6,
            "curve-style": "bezier",
            opacity: 0.85,
          },
        },
        {
          selector: "edge.shares-infra",
          style: { "line-color": purple, "target-arrow-color": purple, "line-style": "dashed" },
        },
        {
          selector: "edge.dimmed",
          style: { opacity: 0.12 },
        },
        {
          selector: "edge.highlighted",
          style: { width: 2.2, opacity: 1 },
        },
      ],
      layout: {
        name: "dagre",
        // @ts-expect-error cytoscape-dagre extends the base layout options
        rankDir: "LR",
        nodeSep: 14,
        rankSep: 90,
        animate: false,
      },
    });

    cy.on("tap", "node", (evt) => setSelectedId(evt.target.id()));
    cy.on("tap", (evt) => {
      if (evt.target === cy) setSelectedId(null);
    });
    cy.on("mouseover", "node", (evt) => {
      const incident = evt.target.closedNeighborhood();
      cy.elements().not(incident).addClass("dimmed");
      incident.edges().addClass("highlighted");
    });
    cy.on("mouseout", "node", () => {
      cy.elements().removeClass("dimmed").removeClass("highlighted");
    });

    cy.fit(undefined, 24);
    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [elements]);

  // Selection dimming is layered on top of the mounted graph rather than
  // rebuilt into it, so clicking a node doesn't re-run layout.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().removeClass("dimmed").unselect();
    if (selectedId) {
      const node = cy.getElementById(selectedId);
      if (node.nonempty()) {
        node.select();
        const incident = node.closedNeighborhood();
        cy.elements().not(incident).addClass("dimmed");
      }
    }
  }, [selectedId]);

  const selected = selectedId ? byId.get(selectedId) ?? null : null;

  return (
    <section className="table-panel">
      <div className="panel-heading">
        <div>
          <h2>Attack-surface graph</h2>
          <p>
            How this engagement's discovered surface connects — hosts, IPs, services, technologies,
            CVEs and findings. Derived metadata only: it <strong>never widens scope</strong>. Solid
            nodes are in-scope assets; <span className="muted-line">dashed nodes are context, not targets</span>.
            Click a node for details, scroll to zoom, drag to pan.
          </p>
        </div>
      </div>

      <div className="surface-graph-legend">
        {NODE_TYPES.map((t) => (
          <span key={t} className="surface-graph-legend-item">
            <span className="surface-graph-swatch" style={{ background: nodeColor[t] }} />
            {t}
          </span>
        ))}
      </div>

      <div className="surface-graph-body">
        {elements.length === 0 ? (
          <p className="empty-cell">No graph yet. Run a scan — the graph builds as discovery, fingerprinting and correlation complete.</p>
        ) : (
          <div className="surface-graph-canvas-wrap">
            <div className="surface-graph-controls">
              <button type="button" aria-label="Zoom in" onClick={() => cyRef.current?.zoom(cyRef.current.zoom() * 1.25)}>+</button>
              <button type="button" aria-label="Zoom out" onClick={() => cyRef.current?.zoom(cyRef.current.zoom() / 1.25)}>−</button>
              <button type="button" aria-label="Fit to screen" onClick={() => cyRef.current?.fit(undefined, 24)}>⛶</button>
            </div>
            <div ref={containerRef} className="surface-graph-canvas-cy" role="img" aria-label="Attack-surface graph" />
          </div>
        )}

        {selected && (
          <aside className="surface-graph-detail">
            <button className="surface-graph-detail-close" onClick={() => setSelectedId(null)} aria-label="Close">×</button>
            <h3>{selected.label}</h3>
            <dl>
              <dt>Type</dt><dd>{selected.node_type}</dd>
              <dt>In scope</dt><dd>{selected.scannable ? "yes — valid target" : "no — context only"}</dd>
              <dt>Source</dt><dd>{selected.ref_table}</dd>
              {Object.entries(selected.attrs ?? {})
                .filter(([, v]) => v !== null && v !== undefined && v !== "")
                .map(([k, v]) => (
                  <div key={k} style={{ display: "contents" }}>
                    <dt>{k}</dt>
                    <dd>{String(v)}</dd>
                  </div>
                ))}
            </dl>
          </aside>
        )}
      </div>
    </section>
  );
}
