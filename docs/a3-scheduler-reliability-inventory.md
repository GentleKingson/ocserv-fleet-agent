# A3 Scheduler Reliability Completion Inventory

## Scope

This inventory audits issue `#35` and the A3 row in `docs/next-roadmap.md`
against merged source at `7f73c7783e652debf0e59248d72396243adda0d2`.
It covers controller scheduling only. It does not claim Postgres runtime parity,
multi-operator governance, or controlled-write capability.

## Acceptance Evidence

| Requirement | Implementation evidence | Test evidence | Result |
| --- | --- | --- | --- |
| SQLite leasing and deterministic claims | Schema 19 `scheduler_job_claims`; immediate actor-bound `StoreWriter` claim methods; ordered due selection | `scheduler_claims_are_deterministic_exclusive_expiring_and_fenced` | proven |
| Two schedulers and duplicate suppression | owner/fence conditional writes on independent SQLite connections | `competing_scheduler_instances_claim_one_due_job_exactly_once`; `scheduler_tests_repeated_run_once_dedupes_alert_events` | proven |
| Expiry and stale fence | monotonic fence increment; renew/release/outcome/finish require current owner, fence, active run, and live lease | `scheduler_claims_are_deterministic_exclusive_expiring_and_fenced`; `scheduler_stale_fence_cannot_persist_run_outcomes_after_takeover` | proven |
| Crash recovery | expired takeover atomically fails the abandoned run and emits `SCHEDULER_LEASE_EXPIRED` recovery audit | `scheduler_stale_fence_cannot_persist_run_outcomes_after_takeover` | proven |
| Lease heartbeat | two-minute production lease renewed every 30 seconds on an independent connection; renewal loss cancels execution | `scheduler_claim_heartbeat_renews_during_execution` | proven |
| Clock skew and monotonic clocks | RFC 3339 instants are parsed rather than text-compared; backward updates and false backward-skew misfires fail closed | `scheduler_clock_order_uses_rfc3339_instants_not_text_order`; `scheduler_clock_update_rejects_regression_and_rolls_back_outcome_pair`; `scheduler_misfire_coalesces_and_bounds_missed_intervals` | proven |
| Bounded misfire | arbitrarily old backlog coalesces into one run; reported omission count caps at 10,000; finish-based clock prevents catch-up loop | `scheduler_tests_misfire_coalesces_unbounded_backlog_into_one_run`; `scheduler_tests_misfire_audit_failure_releases_claim_without_running`; `scheduler_misfire_coalesces_and_bounds_missed_intervals` | proven |
| Bounded retry/backoff | transient-only three-attempt policy with 100/200 ms delays; partial and permanent outcomes do not retry; all attempt audits retained | `scheduler_executor_retries_only_transient_failures_with_a_hard_cap`; `scheduler_executor_keeps_partial_failures_and_stable_order` | proven |
| Timeout | validated 1,000-30,000 ms per-attempt deadline; timeout future is canceled and typed observation/audit is persisted | `scheduler_task_timeout_is_bounded_and_audited`; `scheduler_tests_invalid_jitter_and_timeout_are_rejected` | proven |
| Jitter | deterministic finish-time jitter in `0..=jitter_seconds`; maximum 3,600 seconds and never above interval | `scheduler_jitter_is_deterministic_bounded_and_advances_the_clock`; `scheduler_tests_schedule_job_add_and_list`; `scheduler_tests_invalid_jitter_and_timeout_are_rejected` | proven |
| Concurrency and hard RPC budget | global, per-node, and per-method semaphores; worst-case retry attempts reserved before admission | `scheduler_executor_enforces_global_max_concurrency`; `scheduler_executor_enforces_per_node_concurrency_one`; `scheduler_executor_enforces_per_method_cap`; `scheduler_rpc_budget_truncates_tasks_and_reports_skipped_work` | proven |
| Maintenance | Schema 20 singleton window; set/clear mutation and audit share a transaction; active window performs no claim, RPC, or clock update | `scheduler_tests_maintenance_suppresses_due_and_targeted_work_until_cleared`; `scheduler_tests_maintenance_set_rolls_back_when_audit_fails`; `migration_tests_scheduler_maintenance_upgrades_schema_19` | proven |
| Graceful shutdown and restart | SIGINT/SIGTERM closes admission, drains admitted work under heartbeat/fence, releases claim, records requested/drained audits; new process uses fresh owner | `scheduler_shutdown_gate_stops_new_job_admission`; `scheduler_tests_daemon_sigterm_audits_and_exits_after_drain` | proven |
| Backend-neutral contract | claim, renewal, release, maintenance, run, outcome, and finish mutations are defined on `StoreWriter`; scheduler production code uses the trait boundary | compiler coverage for the SQLite `StoreWriter` implementation; controller mutation source guard | proven for contract, Postgres runtime remains C1 |

## Security Invariants

- Scheduler job kinds and RPC methods remain a fixed read-only catalog.
- Claims, maintenance, retry, timeout, jitter, and shutdown do not create or
  change node, endpoint-trust, peer, path, or authorization records.
- Path jobs still require one explicit stored pair. There is no pair inference,
  wildcard, role-derived target, peer mesh, or fleet-wide path enumeration.
- Trust and binding are rechecked after concurrency waits by the
  `scheduler_dispatch_rechecks_*` test family.
- Misfire coalescing and retry reservation prevent unbounded catch-up or retry
  multiplication. Role selectors remain capped by `MAX_TARGETS_PER_JOB`.
- Every production mutation goes through an actor-bearing audited writer; the
  controller mutation guard rejects direct SQL or mutator bypasses elsewhere.
- The HTTP API and dashboard remain GET-only and cannot trigger scheduler work.

## Compatibility And Rollback

PRs `#80` through `#86` delivered the A3 behavior. Schema 19 adds claims and
schema 20 adds maintenance without activating a window or rewriting jobs.
Migration tests cover schema-18 and schema-19 upgrades, private backup,
idempotent reopen, current object inventory, and future-schema rejection.
Rollback requires the corresponding private pre-migration backup; older
binaries must not open a newer database.

## Completion Gate

The completion branch passed the local acceptance matrix:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace`
- `cargo test --workspace --all-features`
- documentation-claim and controller-mutation guards

Issue `#35` remains open until the completion pull request also passes required
GitHub CodeQL, supply-chain, test, clippy, format, and four-platform
install-smoke checks and is merged.
