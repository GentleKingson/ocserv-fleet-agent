# ADR: Retention Apply Atomicity And Replay

## Status

Accepted.

## Context

Retention previously committed each delete batch and wrote one summary audit
after all batches. A process or audit failure could therefore delete history
without an audit. Retrying a limited apply could also delete a second set of
rows because the command had no stable operation identity.

Retention covers only the fixed observation-history scopes. Controller audit,
node, trust, enrollment, policy, hook, and credential tables are not targets.

## Decision

- Policy changes use an explicit-actor `StoreWriter` transaction containing the
  policy upsert and its low-sensitive before/after audit.
- A non-dry-run apply uses one immediate SQLite transaction per fixed scope. All
  bounded delete batches for that scope and one `retention.apply` audit commit
  together. Audit failure rolls back every batch in that scope.
- Every apply has a `retention-<uuid>` operation ID. The CLI generates one when
  omitted and accepts `--operation-id` for retry. The same ID may identify one
  event per fixed scope so a multi-scope retry can skip completed scopes and
  continue after a later-scope failure.
- Exact replay requires the same actor, scope, explicit-cutoff intent, policy
  age/row bounds, limit, and batch size. It returns the original bounded report
  without deleting or auditing again. Divergent or ambiguous provenance fails
  closed.
- Policy-derived cutoffs are computed inside the first transaction and stored
  in audit. Replay matches the policy inputs and returns that original effective
  cutoff instead of recomputing wall-clock time.
- Limits, batch sizes, policy ages, and policy row counts have closed upper
  bounds. Legacy unaudited prune entry points are removed and the production
  mutation guard covers both retention writers.
- `explain` and `apply --dry-run` remain query-only and write no audit. An
  operation ID is rejected with dry-run because no durable operation exists.

## Consequences

An apply may hold a local SQLite write transaction while deleting up to the
bounded command limit, but it never spans network or agent work. A multi-scope
command can commit earlier scopes before a later scope fails; each committed
scope is independently audited and exact replay resumes deterministically.

No SQLite migration, RPC protocol change, HTTP API route, agent capability, or
controlled-write feature is added. The default network product remains
read-only and retention remains controller-local.
