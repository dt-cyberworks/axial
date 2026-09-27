"""Attack-surface graph (REQ-GRAPH-001..006).

Materializes a typed, relationship-native view of one engagement's discovered
surface from data the deterministic scan phases already collect. Graph-in-Postgres
by design; the control-plane is the sole writer. The graph is derived metadata
and never widens scope - see docs/requirements/attack-surface-graph.md.
"""

from app.graph.builder import materialize_graph  # noqa: F401
