-- Finalize cancellation requests created by the former cooperative-only stop.
--
-- Older workers could disappear or remain blocked in a long tool call after the
-- API set cancel_requested=true, leaving the row active forever. The new runtime
-- transition is immediate; this idempotent data migration reconciles only those
-- historical active rows during the first deployment of that behavior.

UPDATE approval_request AS approval
SET state = 'cancelled',
    execution_finished_at = COALESCE(approval.execution_finished_at, now()),
    execution_error = COALESCE(approval.execution_error, 'scan_cancelled_by_operator')
FROM scan_run AS run
WHERE run.cancel_requested = true
  AND run.state IN ('running', 'waiting_approval')
  AND approval.engagement_id = run.engagement_id
  AND approval.state IN ('requested', 'approved', 'executing')
  AND approval.tool_call ->> 'scan_run_id' = run.id::text;

UPDATE scan_run
SET state = 'aborted',
    state_reason = 'cancelled_by_operator',
    finished_at = COALESCE(finished_at, now())
WHERE cancel_requested = true
  AND state IN ('running', 'waiting_approval');
