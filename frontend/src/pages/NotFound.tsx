import { Link } from "react-router-dom";

/** REQ-CONSOLE-008/009: an honest "not found" instead of an empty or invented page. */
export default function NotFound({
  title = "Page not found",
  message = "There is nothing at this address. It may have moved, or the link is mistyped.",
}: { title?: string; message?: string }) {
  return (
    <section className="page-stack">
      <header className="page-header">
        <div>
          <span className="eyebrow">Not found</span>
          <h1>{title}</h1>
          <p>{message}</p>
        </div>
      </header>
      <div className="form-actions"><Link className="primary-action" to="/">Back to the overview</Link></div>
    </section>
  );
}
