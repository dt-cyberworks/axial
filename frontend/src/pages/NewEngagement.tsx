import { Link, useSearchParams } from "react-router-dom";

import EngagementWizard from "./EngagementWizard";
import MonitorWizard from "./MonitorWizard";

/**
 * REQ-MODE-018: the first screen of a new engagement is a choice, because the two uses
 * differ in setup and in how a run is handled: a monitor runs without anyone watching,
 * a test is started by a person who decides sensitive steps. Drafts resume in the flow
 * they were started in; a link without a choice shows the choice.
 */
export default function NewEngagement() {
  const [params] = useSearchParams();
  const mode = params.get("mode");
  const draft = params.get("draft");

  if (mode === "monitoring") return <MonitorWizard />;
  if (mode === "assessment" || draft) return <EngagementWizard />;

  return (
    <section className="page-stack">
      <header className="page-header">
        <div>
          <span className="eyebrow">New engagement</span>
          <h1>What do you want to do?</h1>
          <p>The choice decides how the engagement is set up and how its runs are handled. It cannot be changed once it is active.</p>
        </div>
      </header>
      <div className="mode-cards">
        <Link className="mode-card" to="/new?mode=monitoring">
          <span className="mode-tag">Unattended</span>
          <h2>Monitor an attack surface</h2>
          <p>
            Axial checks your scope again and again and tells you what changed. Nobody has to be at the screen:
            nothing waits for a person during a run, and what it could not decide for itself lands in your inbox.
          </p>
        </Link>
        <Link className="mode-card" to="/new?mode=assessment">
          <span className="mode-tag">Attended or semi-attended</span>
          <h2>Test a target</h2>
          <p>
            You start a run, decide the sensitive steps and review the findings. For a penetration test, a customer
            assessment or a bug-bounty hunt. You can walk away and be notified when a decision is needed.
          </p>
        </Link>
      </div>
    </section>
  );
}
