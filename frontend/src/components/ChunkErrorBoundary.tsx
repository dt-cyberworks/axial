import { Component, type ReactNode } from "react";

/**
 * REQ-CONSOLE-015: a lazily loaded part of the console (for example the graph)
 * can fail to load - typically right after a deploy replaced the hashed files
 * this page still points at. Show that, with a way out, instead of an empty area.
 */
export default class ChunkErrorBoundary extends Component<{ children: ReactNode; what: string }, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <section className="table-panel">
        <div className="error-block">
          The {this.props.what} could not be loaded. The console may have been updated since this page was opened.
        </div>
        <div className="form-actions" style={{ padding: "0 16px 16px" }}>
          <button onClick={() => window.location.reload()}>Reload page</button>
        </div>
      </section>
    );
  }
}
