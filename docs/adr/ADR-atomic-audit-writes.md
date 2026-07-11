# ADR: Atomic Audit Writes

- Status: accepted, incremental rollout in progress
- Date: 2026-07-10
- Decision owners: controller storage and security maintainers
- Tracking issue: [#33](https://github.com/GentleKingson/ocserv-fleet-agent/issues/33)

## Context

Controller-local commands change durable fleet state. An audit row written after
the business transaction cannot prove the change: a process exit, full disk,
constraint failure, or injected database error can leave the business row
committed without its audit record.

The schema already supports transactions and several enrollment, endpoint, and
health-policy operations use them correctly. Other legacy mutations still use a
business transaction followed by a separate `insert_audit` transaction. That
split is not an acceptable production invariant.

## Decision

Every controller mutation is exposed through `StoreWriter` (or a backend-neutral
equivalent) and takes an explicit, validated actor. The writer must:

1. validate all inputs before opening the transaction when possible;
2. load any bounded before-state needed by the audit projection;
3. apply the business change;
4. insert a low-sensitive audit event through the transaction-scoped helper;
5. commit exactly once, after both writes succeed.

An audit insertion error is a business-operation error. Dropping the transaction
at any point before the final commit rolls back both writes. Callers must not add
a second success audit for the same mutation.

The first rollout slice covers node add, enable, disable, and remove. The second
slice covers scheduler job add, enable, and disable. The third slice covers
scheduler run starts, bounded observation/RPC outcome batches, run finishes,
and owning-job clock updates. The fourth slice closes endpoint lifecycle
transitions: rotation moves the node registry pointer with both trust rows,
revocation and quarantine disable the current node, and removal terminalizes
the unique active trust. Enrollment and retention slices add their closed,
idempotent atomic writers. Later slices cover health/alert/delivery and other
remaining mutations. Read-only events may continue to
use the standalone audit writer because they have no paired business mutation.

Scheduler execution uses several short transaction boundaries rather than one
transaction around a run. The start row and start audit commit before dispatch;
each bounded task outcome commits its observations and matching audits; and the
terminal run state, job clock, and finish audit commit together. No SQLite
transaction crosses an RPC, semaphore wait, or other `.await`. If outcome or
finish persistence fails, the run stays `running` and the job clock stays
unchanged. Recovery of that durable incomplete-run marker belongs to scheduler
reliability work rather than being hidden by a false terminal result.

## Audit Projection

Audit events use fixed event names and bounded fields. They may contain stable
node and endpoint identifiers already allowed by the controller audit contract,
stable scheduler job identifiers and fixed job kinds, plus closed before/after
state such as `enabled`. They do not contain secrets, tokens, raw RPC bodies,
local paths, commands, stdout, stderr, or arbitrary database JSON.
Scheduler job projections reduce selectors to a fixed class and omit free-form
job names and selector values, including when legacy rows contain unsafe text.

## Enforcement

- Backend contracts identify actor-bearing mutation entry points.
- Integration tests install failing audit, observation, and job-clock triggers
  and prove that affected node, endpoint-trust, scheduler-job, run, outcome, and
  clock changes roll back as one unit. Endpoint tests additionally inject
  failures between lineage and registry updates.
- Transaction-drop and audit-failure tests exercise the pre-commit boundary,
  including rollback of all bounded retention batches in a scope.
- A repository check restricts controller mutation SQL to reviewed storage and
  migration modules; it is a guardrail, not a substitute for code review.
- SQLite and future Postgres implementations must pass the same atomic-writer
  contract tests.

## Consequences

Mutation APIs become more explicit and may return an audit-related database
error where older code appeared to succeed. This fail-closed behavior is
intentional. Multi-step operations that cannot fit in one transaction must be
modeled as durable, individually audited state transitions rather than a late
summary audit.

No protocol, API, or agent capability changes result from this decision. The
default build remains read-only at the network boundary, and the read-only API
continues to open SQLite with read-only and query-only enforcement.

## Rollback

The node, scheduler, endpoint, enrollment, and retention slices
have no schema migration. Reverting one restores its previous call structure
but also restores the known audit or integrity gap, so rollback is appropriate
only as an emergency source rollback before production use. Stored rows and
existing audits remain compatible; no protocol or API contract changes are
involved.
