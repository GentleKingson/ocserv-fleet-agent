# ADR: Scheduler Retry Policy

## Status

Accepted for A3 read-only RPC execution.

## Decision

Each resolved read-only scheduler task receives at most three RPC attempts.
Attempts use bounded exponential delays of 100 ms and 200 ms. A retry occurs
only when every observation in the attempt failed with one of these transient
codes:

- `CONNECT_FAILED`
- `RPC_TIMEOUT`
- `SQLITE_BUSY_TIMEOUT`
- `RESOURCE_EXHAUSTED`

Permanent authorization, trust, configuration, validation, response-shape, and
mixed partial outcomes are never retried. Audit records from every attempted
RPC are retained and persisted with the terminal task outcome.

The per-tick RPC budget reserves all three possible attempts before admitting a
task. This keeps the configured budget a hard upper bound even when every task
exhausts its retries. Unused reservations are not transferred into unbounded
late work.

## Security Consequences

- Retries cannot invoke controlled writes; the scheduler catalog remains fixed
  to read-only methods.
- Partial success is not replayed, avoiding duplicate successful subrequests.
- Backoff and attempt count are constants rather than remotely supplied values.
- Existing claim fencing and heartbeat apply across the complete retry window.

## Remaining Work

Maintenance policy, graceful shutdown/restart, and the final A3 acceptance
matrix remain tracked by issue `#35`.
