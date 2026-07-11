# ADR: Durable Health Evaluator Runs

## Status

Accepted for A4.

## Context

Interactive health commands currently compute and replace the latest snapshot
for each node. An independent evaluator needs a durable identity for each input
set so restart, replay, and failure handling do not depend on dashboard reads or
random process-local identifiers.

## Decision

Schema 21 adds `health_evaluation_runs`. Each run records a bounded evaluation
ID, a 64-character input watermark, a 64-character policy version, a fixed
bounded computation version, lifecycle timestamps, terminal status, snapshot
count, and an optional fixed failure code.

The tuple `(input_watermark, policy_version, computation_version)` is unique.
It is the durable idempotency boundary: an unchanged observation input, policy,
and evaluator algorithm cannot create a second evaluation. Database checks
make running, completed, and failed rows internally consistent and cap a batch
at 1,000 snapshots.

The table stores no observation bodies, addresses, trust material, endpoint
secrets, commands, paths, or arbitrary errors. Later A4 slices will atomically
bind completed runs to snapshot writes, recover abandoned running rows, and add
the independent evaluator loop. The evaluator remains observation-only and
cannot contact agents or mutate nodes, trust, scheduler jobs, or maintenance.

## Compatibility And Rollback

The migration creates an empty table and two indexes; it does not rewrite
existing snapshots or trigger evaluation. Older binaries must not open schema
21. Rollback requires restoring the private pre-migration backup.
