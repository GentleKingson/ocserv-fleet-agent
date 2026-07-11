# ADR: Alert Delivery Persistence Atomicity

## Status

Accepted for the A1 atomic mutation-audit milestone.

## Context

Alert delivery performs external JSONL filesystem or HTTPS work. That I/O must
not occur while a SQLite transaction is open. Previously webhook attempt rows,
alert `last_sent_at` updates, and delivery audits were separate transactions, so
audit failure could leave unaudited history or a partially updated alert set.

## Decision

- Every persisted webhook attempt uses its `attempt-...` ID as a replay
  identity and commits the attempt row with one `alert.delivery.attempt` audit
  in an immediate transaction.
- A delivery command generates one `delivery-<uuid>` finalization identity.
  After external I/O succeeds, it supplies the complete bounded before/after
  alert set. The writer verifies every current row, permits only
  `last_sent_at` changes, writes all rows and the `alert.delivery` audit, and
  commits once.
- Dry-run and failed/rejected commands write only the replay-safe delivery
  summary audit. They cannot update alerts.
- Attempts and finalizations are actor/input-bound. Exact retries are no-ops;
  divergent provenance or stale alert state fails closed.
- The production mutation guard rejects direct alert upserts and bypasses of
  attempt/finalization writers outside the reviewed store/backend boundary.

## Consequences

Audit failure rolls back attempt history or every final alert update. No SQLite
transaction spans file or network I/O. External delivery cannot be rolled back:
if final persistence fails after a file append or HTTPS success, the external
side effect may exist while `last_sent_at` remains unchanged. Durable delivery
claims and end-to-end sink idempotency remain A5 reliability work.

The audit stores fixed hook/status classes, bounded counts, identifiers, and
error codes. It does not store webhook URLs, paths, HMAC secrets, payloads, or
response bodies.

No schema, protocol, API route, agent capability, feature default, or network
authorization changes. API and dashboard remain read-only.
