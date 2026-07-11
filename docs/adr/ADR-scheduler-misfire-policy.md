# ADR: Scheduler Misfire Policy

## Status

Accepted for the A3 SQLite scheduler implementation.

## Decision

When an enabled job is at least one full interval late, the scheduler coalesces
the entire backlog into exactly one execution. It never replays one invocation
per missed interval. Before execution it writes an actor-bound
`scheduler.job.misfire` audit with reason `MISFIRE_COALESCED`, the bounded count
of omitted invocations, and result `run_once_without_catch_up`.

The reported omitted count is capped at 10,000. Successful or terminal
execution advances `next_run_at` from the actual finish time, so a delayed job
cannot remain immediately due and create a catch-up loop. Backward clock skew
does not manufacture a misfire. Failure to persist the misfire audit releases
the claim and runs no work.

An explicitly targeted `schedule run --once --job-id` is an operator-triggered
execution and is not classified as a clock misfire.

## Security And Scale Consequences

- Restart after a long outage produces at most one execution per due job.
- The policy cannot expand selectors, infer path pairs, or multiply RPC work.
- Audit payload size and missed-count cardinality remain bounded.
- Claiming and fencing still provide duplicate suppression between schedulers.

## Remaining Work

Bounded retry/backoff, maintenance policy, and graceful shutdown remain part of
issue `#35`.
