# A8 Migration And Failure-Injection Inventory

## Migration Corpus

`crates/ocfleet-cli/tests/migration_tests.rs` is the executable migration
corpus. `migration_tests_legacy_fixtures_upgrade_to_current` deterministically
constructs every historical schema from version 1 through the version before
`CURRENT_SCHEMA_VERSION`, inserts version-appropriate representative rows, and
opens each fixture through the production migrator. Every case proves current
schema, integrity, foreign keys, preserved core row counts, required indexes,
one private checksum-backed pre-migration backup, and idempotent reopen.

Additional corpus cases cover future-schema refusal, large legacy datasets,
retention constraint rebuild, every versioned JSON payload family, invalid and
contaminated legacy payload refusal, scheduler claims/maintenance, health
evaluation runs, and alert delivery queue migration. Fixtures are generated
from checked-in deterministic SQL rather than opaque binary databases so schema
and contamination review remains possible and the loop automatically includes
new schema versions. The tests operate only in private temporary directories.

## Failure Injection

| Boundary | Evidence | Required invariant |
| --- | --- | --- |
| Migration backup/write | `migration_tests_invalid_legacy_observability_data_is_refused_after_backup` and payload contamination cases | Backup exists; original schema/data remain; partial migration rolls back. |
| Controller atomic writers | `cli_store_tests.rs`, `observability_store_tests.rs`, `retention_tests.rs`, `alert_hooks_tests.rs` audit-trigger injections | State transition and audit commit together or neither commits. |
| Scheduler | Start/bundle/observation/clock/finish trigger failures plus competing claims and expired-lease recovery | No partial observation bundle, clock advance, duplicate owner, or unfenced completion. |
| Health evaluator | Start/finish/recovery audit failures and stale-running recovery | Durable run/snapshot/failure state remains internally consistent. |
| Alert delivery | Enqueue/claim/outcome audit failures, retryable transport failure, retry exhaustion, and dead-letter tests | Bounded retry and one fenced terminal outcome; secrets never enter errors. |
| Agent audit | `audit.rs` primary/spool failures, exhaustion, replay, and metrics tests | No unaudited success; bounded durable fallback; explicit failure on exhaustion. |
| Restore | `backup_tests.rs` injected post-replacement failure and restore drill | Original database and WAL/SHM state are restored after replacement failure. |
| API/dashboard | API mutation guard and Playwright GET-only request capture | Reads cannot dispatch RPC or mutate controller state. |

These suites run in the default/all-feature CI gates. Each injected failure is
local and deterministic; no production fault-injection switch, remote trigger,
or unbounded retry path is compiled into runtime dispatch.
