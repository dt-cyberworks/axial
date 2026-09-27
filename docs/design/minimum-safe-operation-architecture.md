# Minimum Safe Operation Architecture

Risk class: `R4`.

## Deployment assumption

One trusted operator uses one deployment behind localhost or a private VPN.
This is not a multi-tenant security claim. Network isolation remains the
temporary compensating control for the runner until runner-bound authorization
artifacts are implemented.

## Approval execution protocol

```text
requested → approved → executing → consumed
                    ↘ execution_failed
requested → rejected | expired
```

The worker never converts `approved` directly into execution. It asks the
control plane to claim the approval. In one transaction, the control plane
locks the approval, reconstructs the stored tool call, performs current gateway
checks, and changes the state to `executing`. Only the exact stored call is
returned for dispatch.

After dispatch, the worker reports success or failure. A completion failure is
not swallowed: an approval left in `executing` is visible and recoverable, not
silently reusable.

## Public authentication

The minimum model uses one operator bearer credential configured at deployment.
It is separate from the internal workload credential. Role-based and
multi-tenant authorization are deliberately deferred.

## Audit ingestion

The proxy retains independent read access for scope enforcement but submits
network decisions to an internal control-plane audit endpoint. Per-engagement
chain appends are serialized with a PostgreSQL transaction advisory lock.

## Deferred controls

- RBAC and customer/tenant authorization
- workload-specific internal identity
- runner-enforced signed dispatch artifacts
- ephemeral per-engagement runner orchestration

