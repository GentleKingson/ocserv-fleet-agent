# ADR: Scheduler Timeout And Jitter

## Status

Accepted for A3.

## Decision

Each job stores an operator-selected RPC attempt timeout from 1,000 through
30,000 milliseconds and optional jitter from zero through 3,600 seconds. Jitter
must not exceed the job interval. CLI creation validates the same bounds as the
actor-bound store writer and SQLite constraints.

Every production attempt is wrapped in the job timeout. Expiry cancels the
attempt future and produces a typed `RPC_TIMEOUT` observation plus bounded RPC
audit; the existing transient retry policy may make the next reserved attempt.

After terminal execution, `next_run_at` is the actual finish time plus interval
plus deterministic jitter in the inclusive range `0..=jitter_seconds`. The
jitter derives only from the job ID and finish timestamp, is reproducible for
tests and recovery, and cannot be influenced by an agent response. It never
creates early execution or unbounded delay.

## Security Consequences

- Timeout bounds cap occupied concurrency permits and lease-renewal duration.
- Jitter spreads synchronized schedules without changing selectors or trust.
- Timeout failures retain fixed low-sensitive summaries and audit every attempt.
