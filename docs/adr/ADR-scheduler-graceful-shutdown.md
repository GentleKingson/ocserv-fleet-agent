# ADR: Scheduler Graceful Shutdown

## Status

Accepted for A3.

## Decision

The scheduler daemon handles SIGINT and SIGTERM in both idle and active-tick
states. A signal atomically closes the job-admission gate, writes a bounded
`scheduler.daemon.shutdown.requested` audit, and waits for the admitted job to
finish. Its task set, retry attempts, outcome persistence, run finalization,
and claim release therefore drain before `scheduler.daemon.stop` records state
`drained` and the process exits successfully.

No new job is claimed after the gate closes. Existing heartbeat and fencing
remain active during the drain. A restarted daemon receives a new opaque owner
ID and can immediately process due work; crash recovery remains the fallback
for SIGKILL or host loss, where graceful code cannot run.

## Evidence

Tests prove a pre-closed gate admits no claim or run, SIGTERM produces requested
and drained audits with no live claim, and a second daemon starts and stops
cleanly against the same database.
