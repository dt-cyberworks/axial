import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirement = read("docs/requirements/attack-surface-graph.md");
const client = read("frontend/src/api/client.ts");
const graph = read("frontend/src/components/SurfaceGraph.tsx");
const detail = read("frontend/src/pages/EngagementDetail.tsx");

// REQ-GRAPH-004/005 exist as requirements.
assert.match(requirement, /## REQ-GRAPH-004:/);
assert.match(requirement, /## REQ-GRAPH-005:/);

// The client exposes the scoped, read-only graph endpoint and its types.
assert.match(client, /surfaceGraph:\s*\(id: string\)/);
assert.match(client, /\/engagements\/\$\{id\}\/surface-graph/);
assert.match(client, /interface SurfaceNode/);
assert.match(client, /interface SurfaceEdge/);

// The component renders the graph, distinguishes node types, marks non-scannable
// nodes visually, and reveals node details on selection (REQ-GRAPH-004).
assert.match(graph, /useQuery/);
assert.match(graph, /surfaceGraph/);
assert.match(graph, /nodeColor/);
assert.match(graph, /"border-style":\s*"dashed"/, "non-scannable nodes must be drawn distinct (dashed)");
assert.match(graph, /context-only/, "non-scannable nodes must carry a distinct, selectable class");
assert.match(graph, /setSelectedId/, "selecting a node must reveal its details");
assert.match(graph, /surface-graph-detail/);
assert.match(graph, /never widens scope/i, "the UI must state the graph does not widen scope");
// Interactive, not a static image: pan/zoom controls and a real layout engine.
assert.match(graph, /cytoscape/);
assert.match(graph, /name:\s*"dagre"/, "layout must be deterministic (layered), not randomized force-directed");

// The engagement detail page mounts the graph section.
// REQ-CONSOLE-015: loaded on demand, so the graph library is not in the main bundle.
assert.match(detail, /const SurfaceGraph = lazy\(\(\) => import\("\.\.\/components\/SurfaceGraph"\)\)/);
assert.match(detail, /<SurfaceGraph engagementId=\{id\}/);

console.log("ok - REQ-GRAPH-004/005 attack-surface graph dashboard is wired and scoped");
