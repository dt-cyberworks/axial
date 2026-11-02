import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { api } from "../api/client";
import { fmtTime } from "../lib/runs";

/** REQ-HANDOVER-007: the assessments that were started from this monitor, each an authorization of its own. */
export default function HandoverList({ engagementId }: { engagementId: string }) {
  const { data } = useQuery({ queryKey: ["handovers", engagementId], queryFn: () => api.listHandovers(engagementId) });
  return (
    <section className="panel handover-list" aria-label="Assessments from this monitor">
      <div className="panel-heading"><h3>Assessments from this monitor</h3></div>
      {!data || data.length === 0 ? (
        <p className="muted-line">No assessment has been started from this monitor.</p>
      ) : (
        <table className="data-table">
          <thead><tr><th>Title</th><th>Status</th><th>Owner</th><th>Test window</th></tr></thead>
          <tbody>
            {data.map((a) => (
              <tr key={a.id}>
                <td><Link to={`/engagements/${a.id}`}>{a.title}</Link></td>
                <td>{a.status}</td>
                <td>{a.owner_name}</td>
                <td>{fmtTime(a.authorized_from)} to {fmtTime(a.authorized_until)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
