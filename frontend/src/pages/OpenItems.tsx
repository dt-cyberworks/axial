import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";

import { api, isNotFound } from "../api/client";
import RunReview from "../components/RunReview";
import NotFound from "./NotFound";

// REQ-RETEST-003/005: what is still open on an engagement - checks that are not settled and the requests a monitor
// held back - and the step that runs exactly those, not the whole engagement again.

export default function OpenItems() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const engagementQuery = useQuery({ queryKey: ["engagement", id], queryFn: () => api.getEngagement(id!), enabled: !!id, retry: (count, error) => !isNotFound(error) && count < 2 });
  const itemsQuery = useQuery({ queryKey: ["open-items", id], queryFn: () => api.getOpenItems(id!), enabled: !!id });

  if (!id) return null;
  if (isNotFound(engagementQuery.error)) return <NotFound />;
  const engagement = engagementQuery.data;
  const data = itemsQuery.data;
  const title = engagement?.title ?? "Engagement";

  return (
    <section className="page-stack">
      <nav className="breadcrumb">
        <Link to="/">Engagements</Link><span>/</span><Link to={`/engagements/${id}`}>{title}</Link><span>/</span><span>Not done yet</span>
      </nav>
      <header className="page-header">
        <div>
          <span className="eyebrow">Open items</span>
          <h1>Not done yet</h1>
          <p>
            Checks that failed, stopped early or could not run, and requests a monitor held back for you. Run only these, not the whole engagement again.
          </p>
        </div>
      </header>

      {engagement?.operating_mode === "monitoring" && (
        <div className="warning-block">A monitor never sends requests that change data. A request it held back is sent only if you choose it here, one request at a time.</div>
      )}

      {itemsQuery.isLoading && <p className="muted-line">Loading…</p>}
      {itemsQuery.isError && <div className="error-block">The open items could not be loaded.</div>}
      {data && data.items.length === 0 && (
        <section className="form-panel settings-panel">
          <h2>Nothing is open</h2>
          <p className="muted-line">Every check of the latest runs completed or does not apply, and no request is held back.</p>
        </section>
      )}
      {data && data.items.length > 0 && (
        <RunReview
          engagementId={id}
          items={data.items}
          canManage={!!engagement?.can_manage}
          onStarted={(runId) => {
            queryClient.invalidateQueries({ queryKey: ["scan-runs", id] });
            navigate(runId ? `/engagements/${id}/runs/${runId}` : `/engagements/${id}`);
          }}
          onChanged={() => queryClient.invalidateQueries({ queryKey: ["open-items", id] })}
        />
      )}
    </section>
  );
}
