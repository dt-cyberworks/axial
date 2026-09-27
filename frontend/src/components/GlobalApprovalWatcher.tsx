import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";

import { api, type ApprovalRequest } from "../api/client";
import ApprovalModal from "./ApprovalModal";

/**
 * REQ-APPROVALUI-001/002: a single, app-wide watcher for pending state-changing
 * approvals. Mounted once in the authenticated shell so the popup reaches the
 * operator no matter which page they are on. On approve it navigates straight
 * to the approval's own run so the operator watches the write execute.
 */
function runPathForApproval(approval: ApprovalRequest): string {
  const scanRunId = (approval.tool_call as { scan_run_id?: string }).scan_run_id;
  return scanRunId
    ? `/engagements/${approval.engagement_id}/runs/${scanRunId}`
    : `/engagements/${approval.engagement_id}`;
}

export default function GlobalApprovalWatcher() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const { data: approvals = [] } = useQuery({
    queryKey: ["approvals", "global"],
    queryFn: () => api.listApprovals("requested"),
    refetchInterval: 3000,
    retry: false,
  });

  const active = approvals[0];

  // Name the engagement the request belongs to (the operator may be elsewhere).
  const { data: engagement } = useQuery({
    queryKey: ["engagement", active?.engagement_id],
    queryFn: () => api.getEngagement(active!.engagement_id),
    enabled: !!active,
  });

  const decide = useMutation({
    mutationFn: ({ approval, action }: { approval: ApprovalRequest; action: "approve" | "reject" }) =>
      action === "approve" ? api.approveApproval(approval.id) : api.rejectApproval(approval.id),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["approvals"] });
      queryClient.invalidateQueries({ queryKey: ["scan-runs", variables.approval.engagement_id] });
      // REQ-APPROVALUI-002: after approving, take the operator to the run so they
      // see the approved request actually execute. Rejects stay put.
      if (variables.action === "approve") {
        navigate(runPathForApproval(variables.approval));
      }
    },
  });

  if (!active) return null;

  return (
    <ApprovalModal
      approval={active}
      busy={decide.isPending}
      engagementTitle={engagement?.title}
      moreCount={approvals.length - 1}
      overlayClassName="approval-global"
      onDecide={(action) => decide.mutate({ approval: active, action })}
    />
  );
}
