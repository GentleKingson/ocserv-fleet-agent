# ADR: Scheduler Maintenance Window

## Status

Accepted for A3.

## Decision

Schema 20 stores at most one controller-wide scheduler maintenance window with
bounded RFC 3339 start/end timestamps, a bounded operator reason, and update
time. `ocfleet schedule maintenance set`, `show`, and `clear` are actor-bound
CLI operations. Set and clear commit their audit row in the same transaction.

While `starts_at <= now < ends_at`, due execution reports every due job as
skipped, writes one bounded `scheduler.maintenance.skip` audit, performs no
claim or RPC, and leaves job clocks unchanged. Explicit targeted execution also
fails closed. Once the window ends or is cleared, the normal misfire policy
coalesces the backlog into at most one run per job.

Maintenance changes scheduling only. It cannot mutate nodes, endpoint trust,
path authorization, selectors, observations, health state, alert state, or the
read-only API surface.

## Failure And Rollback

Invalid, reversed, unbounded, or contaminated windows fail closed. Audit
failure rolls back set/clear. Restore the private schema-19 migration backup to
roll back the schema; older binaries must not open a schema-20 database.
