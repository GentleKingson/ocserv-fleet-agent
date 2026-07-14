# A4 Independent Health Evaluator Completion Inventory

## Scope

This inventory audits issue `#36` and the A4 roadmap row against merged source
at `dd84350`. It covers controller-local derived health evaluation only. It does
not claim Postgres runtime parity, alert delivery, or controlled-write behavior.

## Acceptance Evidence

| Requirement | Implementation evidence | Test evidence | Result |
| --- | --- | --- | --- |
| Independent evaluation | `ocfleet health evaluator run` and `daemon` execute from stored controller state without an API or dashboard request | `health_evaluator_run_is_independent_idempotent_and_persists_snapshots` | proven |
| Durable run identity | Schema 21 `health_evaluation_runs` records a bounded evaluation ID and lifecycle | `migration_tests_health_evaluation_runs_upgrade_schema_20`; `health_evaluation_lifecycle_is_atomic_idempotent_and_actor_bound` | proven |
| Input watermark | Deterministic one-minute evaluation input digest includes the derived node input projection and evaluation time bucket | `health_evaluator_run_is_independent_idempotent_and_persists_snapshots` | proven |
| Policy and computation versions | Threshold values are hashed independently; fixed `health-v1` participates in the unique replay tuple | `health_evaluation_lifecycle_is_atomic_idempotent_and_actor_bound`; schema unique-index assertions | proven |
| Repeatable idempotency | The watermark/policy/computation tuple is unique; deterministic IDs replay without a second run or audit | `health_evaluator_run_is_independent_idempotent_and_persists_snapshots`; `health_evaluation_lifecycle_is_atomic_idempotent_and_actor_bound` | proven |
| Atomic snapshots | Completed run state, latest per-node snapshots, and finish audit commit in one immediate transaction | `health_evaluation_mutations_roll_back_when_audit_fails`; `health_evaluation_lifecycle_is_atomic_idempotent_and_actor_bound` | proven |
| Bounded failures | Invalid computation input records only fixed `HEALTH_EVALUATION_FAILED`; no raw input or error text enters run/audit state | `health_evaluator_persists_bounded_failure_without_raw_input` | proven |
| Crash recovery | Startup recovery terminalizes at most 100 abandoned runs per transaction with fixed `HEALTH_EVALUATION_ABANDONED` | `health_evaluation_recovery_is_bounded_atomic_and_instant_ordered` | proven |
| Clock correctness | Recovery parses RFC 3339 instants and handles equivalent offset timestamps instead of text ordering | `health_evaluation_recovery_is_bounded_atomic_and_instant_ordered` | proven |
| Graceful shutdown and restart | Signal handlers precede evaluation; admitted work finishes; restart reuses durable replay and leaves no running row | `health_evaluator_daemon_drains_on_sigterm_and_restarts_cleanly` | proven |
| Backend-neutral mutations | Start, finish, failure, and recovery are actor-bound `StoreWriter` methods | SQLite compiler coverage; controller mutation guard | proven for contract; the experimental Postgres snapshot foundation remains C1 |

## Security Invariants

- Evaluation reads controller nodes, endpoint trust, policy, and bounded stored
  observations only. It never loads a controller secret key or opens agent RPC.
- Evaluation cannot mutate nodes, endpoint trust, jobs, scheduler claims, or
  maintenance state.
- Run metadata contains only digests, fixed versions, timestamps, counts,
  lifecycle state, and fixed failure codes. It contains no raw RPC body,
  address, path, command, secret, certificate, log, or arbitrary error.
- Every lifecycle mutation uses an actor-bearing audited writer and rolls back
  if audit insertion fails.
- The API and dashboard remain GET-only. They read latest snapshots and do not
  start or control the evaluator.

## Compatibility And Rollback

PRs `#88` through `#90` deliver A4. Schema 21 creates an empty run table and two
indexes without rewriting snapshots or starting background work. Migration
tests cover schema-20 upgrade, private backup, constraints, idempotent reopen,
current object inventory, and future-schema rejection. Rollback requires the
private pre-migration backup; older binaries must not open schema 21.

## Completion Gate

The implementation branches passed local formatting, all-feature clippy,
default/all-feature workspace tests, focused migration/lifecycle/daemon tests,
documentation claims, and controller mutation guards. Issue `#36` remains open
until the completion pull request passes required GitHub CodeQL, supply-chain,
test, clippy, format, and four-platform install-smoke checks and is merged.
