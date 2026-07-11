# ADR: Fenced Scheduler Job Claims

## Status

Accepted as the first A3 reliability slice.

## Decision

SQLite schema version `19` adds `scheduler_job_claims`. Each job has at most one
claim row containing a bounded opaque owner ID, monotonically increasing fence
token, claim/expiry timestamps, and an optional active run ID. Claim acquisition
uses an immediate transaction. Due claims are rechecked against enabled state
and parsed RFC3339 time inside that transaction, so two scheduler processes
cannot acquire the same due job concurrently.

Acquire, renew, release, and expired-run recovery are actor-bearing
`StoreWriter` operations. Their state change and low-sensitive audit record
commit atomically. Production `run --once` and daemon paths acquire before run
start and release after terminal persistence. A claimed run binds its run ID to
the claim; outcomes and finish require that binding and a live lease.

An expired takeover increments the fence token, terminalizes the abandoned
running row as failed with `SCHEDULER_LEASE_EXPIRED`, and writes a recovery audit
in the same transaction. The previous owner can no longer persist outcomes,
finish, renew, or release. A backward recovery timestamp is clamped to the
stored start time rather than creating a negative-duration run.

## Security Consequences

- Concurrent instances suppress duplicate job execution at the persistence
  boundary; stale workers fail closed after takeover.
- Claims do not change selectors, infer path pairs, enumerate peers, authorize
  RPC, or expand the fixed method catalog.
- Owner IDs and fence tokens are controller-local coordination metadata, not
  API principals or trust identities.
- Claim mutations remain inside reviewed store/backend boundaries and the
  source guard rejects direct production bypasses.

## Current Limit

This slice uses the bounded maximum lease while a job is active. Periodic lease
renewal, shorter crash-detection windows, misfire/retry policy, maintenance,
graceful in-flight shutdown, and the final A3 completion matrix remain work on
issue `#35`. A3 is not operationally mature from this slice alone.

## Rollback

Restore the private schema-18 migration backup. Older binaries must not open a
schema-19 database. The new table has no effect on agent protocol, API routes,
or persisted job selectors.
