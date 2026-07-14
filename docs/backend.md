# Controller Backends

SQLite remains the default controller backend. An experimental
Postgres-wrapped SQLite snapshot backend is available only when the binary is
built with `postgres-backend` and the caller explicitly supplies an approved
connection source. It is not a native Postgres data layer. No command silently
selects it and no Postgres dependency is present in the default feature set.

## Current SQLite Contract

SQLite is the default because it supports the read-only MVP and small-fleet
operator model with simple deployment:

- private controller database file
- additive or safe rebuild migrations
- pre-migration backup and checksum
- local controller audit table
- no external service dependency

The existing SQLite safety checks remain in place when Postgres support is
compiled.

## Future Native Postgres Goals

A future native relational Postgres backend could provide:

- larger fleet query capacity
- longer observation/run/alert history
- centralized audit archival
- multi-operator API deployments with authenticated RBAC
- explicit migration/export tooling from SQLite without forcing migration

It must not introduce unauthenticated writes, automatic trust, raw secrets in
tables, or ocserv write operations.

The current snapshot backend does not satisfy these scale goals. It deliberately
reuses SQLite storage and stores the complete database image in one Postgres
row; the distinction is part of its public contract rather than an invisible
implementation detail.

## Store Abstraction Assessment

The current controller `Store` API still mixes:

- schema migration and backup
- SQLite-specific queries
- controller mutation helpers that also write audit
- read projections for CLI/API observability

A future abstraction should split these concerns:

| Layer | Responsibility |
| --- | --- |
| `StoreReader` | Bounded read queries for node registry, trust, jobs, runs, observations, health, alerts, and audit export. |
| `StoreWriter` | Controller-local mutations with mandatory actor/audit input. |
| `MigrationManager` | Backend-specific schema lifecycle, backup, and integrity checks. |
| `AuditWriter` | Append audited mutation events with redaction guarantees. |

`ocfleet_cli::backend` now defines backend-neutral `StoreReader`, `StoreWriter`,
`MigrationManager`, and `AuditWriter` contracts. The SQLite implementation uses
SQL-level limits for bounded history reads and fails closed when dynamic JSON in
legacy rows does not satisfy the bounded low-sensitive validator. The returned
records are internal store records, not presentation DTOs; every CLI/API output
consumer must still use its typed projection. `StoreWriter` deliberately
exposes only mutation methods that bind actor and audit in one transaction. The
first A2 storage slice advances SQLite to schema version 9 and replaces open
scheduler selector/pair objects with closed schema-tagged v1 payloads. Migration
9 canonicalizes exact legacy objects, disables ambiguous empty selectors, and
fails on unknown or contaminated data. Both the CLI store and independent API
read adapter deserialize these types before projection, so raw persisted job
JSON is never an output contract.

The second A2 slice advances SQLite to schema version 10 and applies the same
closed-reader rule to health degraded-method and summary payloads. Relational
snapshot status and typed summary status must agree. Alert evaluation consumes
the typed fields, while CLI/API projections unwrap only the established public
shape.

The third A2 slice advances SQLite to schema version 11 and closes probe
observation summaries over a fixed field DTO bound to method and result class.
The SQLite and independent API readers validate persisted envelopes and return
only public summary fields.

The fourth A2 slice advances SQLite to schema version 12 and closes
observability run summaries over fixed job, kind, status, trigger, and bounded
count fields. Writers and both read adapters bind those fields to the
relational run and never expose the persisted schema wrapper.

The fifth A2 slice advances SQLite to schema version 13 and closes endpoint
trust bundles over relational endpoint, generation, and lifecycle state plus
bounded explicit controller, peer, and path-pair allowlists. Store readers
validate the envelope and expose only the established public bundle fields.

The sixth A2 slice advances SQLite to schema version 14 and closes alert detail
storage over fixed methods, bounded summary fields, and optional silence or
resolution metadata. Writers canonicalize before persistence; CLI and API
readers require the typed envelope and expose only its public projection.

The seventh A2 slice advances SQLite to schema version 15 and closes alert
webhook host-allow storage over a canonical bounded host list bound to the
relational endpoint host. Writers persist the typed envelope; readers reject
contamination or relationship mismatches before hook output or delivery.

The eighth A2 slice advances SQLite to schema version 16 and closes enrollment
token label/scope and join-request requested/approved-label storage over typed,
kind-bound scalar maps. Writers persist closed envelopes; readers unwrap only
validated public objects and reject kind, contamination, or decision mismatches.

The ninth A2 slice advances SQLite to schema version 17 and adds a closed
delivery-attempt detail payload bound to every relational attempt field. The
table is rebuilt with its foreign keys and index; readers reject envelope or
relational contamination before returning delivery history.

The tenth A2 slice advances SQLite to schema version 18 and closes controller
audit detail storage over a typed, bounded field vocabulary bound to every
relational audit column. The table is rebuilt with required versioned detail;
controller and independent API readers reject contamination and expose only the
validated public fields.

The first A3 slice advances SQLite to schema version 19 and adds a
backend-neutral scheduler claim contract: immediate deterministic acquisition,
bounded expiry, monotonic fences, active-run binding, and atomic abandoned-run
recovery. Production scheduler paths acquire before starting work and release
after terminal persistence; stale owners fail closed after takeover.

The B1 health-history slices advance SQLite through schema version 25. Schema
23 stores append-only evaluation-bound health samples, schema 24 stores
reproducible 5-minute/hourly/daily projections, and schema 25 rebuilds only the
derived rollup table with one latest status per covered five-minute slot.
History and rollup retention are independent. Refresh uses input-watermark-bound
operation IDs through the actor-bearing SQLite writer; the API receives only
bounded projections through its read-only adapter.

The first production-hardening slice added node add/enable/disable/remove to this
contract and removed the CLI's post-commit success audits. Audit-trigger failure
tests prove both `nodes` and `endpoint_trust` changes roll back. The second slice
added scheduler job add/enable/disable to the same contract; audit-trigger
failure rolls back the affected `observability_jobs` insert or enabled-state
update. The scheduler-run expansion adds three closed writer boundaries: run
start plus audit, one-to-four observation/audit pairs, and run finish plus the
owning job clock and audit. The writer rejects mixed actors, jobs, run IDs,
terminal runs, and unbounded batches. Endpoint rotation, revocation, and
quarantine also route through `StoreWriter`; a source guard rejects direct
production calls to inherent node/endpoint lifecycle mutators outside
`store.rs` and the reviewed backend adapter. Enrollment approval now uses an
immediate actor-bearing writer transaction to insert the explicit operator node,
bound generation-1 trust, request decision, and audit together. A separate
writer claims only the strict legacy approved-unbound shape. Exact retries do
not change enabled state, timestamps, trust data, or audit count, and the source
guard rejects production bypasses of both enrollment writers.
Token creation/use, lazy expiry, revocation, and request rejection now use the
same actor-bearing writer contract. Caller-visible `join-<uuid>` IDs provide
submission idempotency, token usage uses a compare-and-set counter, and terminal
retries require exact actor/reason audit provenance. Audit failures roll back
token/request state and counters. Token material and submitted identity values
are excluded from audit detail and redacted from secret-bearing `Debug` output.

The API retains a narrower `ApiReadStore` adapter for API projections;
`ReadOnlyStore` opens SQLite with read-only/query-only flags, validates private
database/sidecar files, checks schema version/tables/integrity, and never exposes
a writer to routes. Consolidating this adapter with the neutral reader remains
future work; the API still uses SQLite even when the experimental controller
Postgres snapshot backend is compiled.

The controller `Store` also retains the absolute path it actually opened. A
crate-private scheduler dispatch gate uses that bound path to open a short-lived
read-only/query-only SQLite connection and read one closed dispatch-binding
snapshot after concurrency waits. The snapshot requires an enabled registry
node, the requested node/EndpointID pair, an Active trust row pointing back to
that node, and exactly one Active binding for the node. It validates the database
and WAL/SHM files, never runs migrations, executes through `spawn_blocking`, and
closes before key loading or network I/O. Callers cannot substitute an unrelated
authorization database.

Scheduler RPC work occurs outside database transactions. A committed start row
is followed by short bounded outcome transactions and one finish transaction;
an outcome or finish persistence failure leaves the run `running` and does not
advance the job clock. Retention policy writes and each scope apply now commit
through actor-bearing writers. Apply uses a stable operation ID, one immediate
transaction for all bounded batches in a scope, and exact audit-backed replay;
legacy unaudited prune entry points are removed. Health summary/node commands
commit bounded snapshot batches and audit through replay-safe writers. Alert
candidate evaluation does the same and compares each persisted before-state in
the immediate transaction so a concurrent silence or resolve is never
overwritten. Alert silence/resolve use a compare-before transition writer, and
webhook-hook creation commits configuration with redacted audit. Each webhook
attempt commits history and audit together; finalization compare-checks the
bounded alert set and commits all `last_sent_at` changes with its audit. External
I/O never occurs inside SQLite transactions. Legacy raw mutation helpers are
fixture-only and source-guarded from production use. Future writer
interfaces must keep actor/audit input mandatory and must not loosen private
file checks or redaction. The scheduler writer expansions change no schema,
protocol, agent capability, or API route; neither does the binding/lifecycle
hardening. The API remains read-only.

## Experimental Postgres Snapshot Backend

The `postgres-backend` feature is default-off. `PostgresConnectionSource`
accepts only `OCFLEET_POSTGRES_URL`, `OCFLEET_TEST_POSTGRES_URL`, or an absolute
private TOML file containing `dsn` and an optional bounded `pool_size`. Debug and
error output never includes the DSN, password, or private path.

The experimental backend uses an r2d2 pool and a Postgres migration transaction
protected by `pg_advisory_xact_lock`. The complete SQLite database is stored as
one checksummed `BYTEA` in the singleton `ocfleet_runtime_state` row. It is
therefore named `PostgresSnapshot` in the backend contract and reports
`backend_kind=postgres-wrapped-sqlite-snapshot` from `doctor`.

Startup checks the highest existing `ocfleet_backend_migrations` version before
running any DDL or initializing state. A database created by a newer backend
schema fails closed, so an older binary cannot silently downgrade or replace its
snapshot under obsolete assumptions.

Every mutation globally serializes and performs this full-image sequence:

1. acquire the writer advisory lock and lock the current controller lease;
2. lock and download the singleton SQLite image;
3. write and verify a private local SQLite file;
4. execute one existing SQLite `StoreWriter` operation and its atomic audit;
5. read and verify the complete updated file;
6. replace the complete Postgres `BYTEA` and commit.

This preserves the existing typed projections, retention rules, and atomic
SQLite mutation/audit behavior. It does **not** provide concurrent writes,
row-level Postgres updates, horizontal write scaling, or native Postgres query
capacity. Postgres WAL and vacuum pressure, transaction duration, network I/O,
temporary disk use, and process memory all grow with the complete image. A
single mutation may temporarily require the Postgres value, multiple Rust byte
buffers, and one or more local SQLite staging files.

The recommended state image ceiling is 64 MiB. The 512 MiB value is a defensive
hard rejection limit, not a production sizing recommendation. Images above the
recommendation remain accepted only to support explicit testing and recovery;
`doctor`, import, and export report `above_recommended_state_size=true`. This
backend is intended only for low-write-frequency foundation evaluation, backup
mobility, and fencing experiments. It is unsuitable for high-frequency
observation, health, scheduler, or alert ingestion.

Each successful state replacement increments a persistent `state_revision` and
updates `state_updated_at` and `state_sha256`. Idempotent imports do not advance
the revision. `doctor` exposes these fields, current image size, its own download
and materialization timings, and process-local last-operation metrics for read,
write, download, materialization, upload/commit, advisory-lock wait, and lease
remaining time. The write metric also reports the high-water sum of Rust-owned
snapshot `Vec` lengths; it deliberately does not claim to measure allocator,
Postgres-driver, SQLite, or total RSS overhead. Import/export reports include
their operation timings. These fixed fields contain no actor, node, DSN, path,
or other high-cardinality label.

Reads use one MVCC-consistent singleton row selected at query start, then query
that immutable local image. They never observe a partial `BYTEA`, but they may
return an older revision after a concurrent writer has committed. The contract
is snapshot-at-query-start eventual consistency: it does not guarantee
cross-request read-after-write or that a result is still current when returned.
Callers that need freshness must compare `state_revision`/`state_sha256` from
their operation report or a subsequent `doctor` result.

Each write requires a bound controller lease and validates its owner and fencing
token while holding the lease row. PostgreSQL `now()` transaction-start
semantics are not used for the safety decision: initial and final checks use
`clock_timestamp()`. After the complete image upload, the transaction checks
the lease again immediately before commit. A lease that expires during local
materialization or upload makes the transaction fail with `StaleFence` and
rolls back the image and revision. Takeover remains blocked by the row lock only
until that transaction rolls back or commits.

The container-backed regression suite imports and rewrites a 96 MiB image. It
asserts the recommendation warning, revision behavior, operation timings,
owned-image-buffer high-water mark, commit-time lease expiry rollback, unchanged
state after the rejected write, and a later writer takeover with a higher
fencing token. Exact filesystem `ENOSPC` and process-RSS fault-injection tests
remain part of C3/C-READY deployment testing; they are not represented as
completed by this Draft foundation.

The current client uses `NoTls` only for Unix sockets and loopback addresses.
Remote hosts fail closed and must be reached through a certificate-verifying TLS
implementation in a later reviewed change, not by weakening this restriction.
State images are capped at 512 MiB before import, database retrieval, checksum,
or replacement. Production deployments should prefer a private config file or
secret mount; an environment DSN can be exposed through process environments,
crash dumps, or orchestration metadata.

`import_sqlite(path, true)` opens the source read-only and uses SQLite's online
backup API to create a transactionally consistent snapshot, including committed
records that are still in an active WAL. Import accepts only the current schema;
validation reads `schema_migrations` directly and never migrates the source or
the snapshot. It also checks the SQLite header, `quick_check`, bounded logical
size, and bounded table counts without changing Postgres. A non-dry-run import
holds the migration advisory lock and replaces the state only after full
checksum/schema verification. Interrupted imports leave the previous singleton
state valid. Import report size and checksum fields describe this consistent
snapshot rather than an incomplete main-file-only copy. `doctor()` verifies
that the relational schema metadata matches the schema recorded inside a
checksum-valid SQLite image, then reports connection, format/schema, pool size,
and checksum status without connection details.

Back up Postgres with the deployment's normal encrypted `pg_dump` workflow and
restore into a separate database before validation. Do not copy the private DSN
file into a backup or place `pg_dump` command lines containing passwords in
shell history; use a private password file or secret injection supported by the
deployment platform.

## SQLite-only Assumptions To Isolate

- SQL syntax using SQLite `strftime` and `json` storage as text.
- In-process `rusqlite::Connection` lifetime.
- File permission checks for `controller.sqlite`.
- Backup sidecars written next to the database.
- Tests that inspect SQLite tables directly.

Compatibility tests around low-sensitive projections and audit semantics keep
SQLite and Postgres behavior aligned as the neutral contract expands.

## Explicit Lifecycle Commands

The feature-enabled CLI never discovers or silently selects Postgres. An
operator selects it with the `postgres` command and an absolute private config
path:

```text
ocfleet postgres doctor --config /run/secrets/ocfleet-postgres.toml --json
ocfleet postgres import --config /run/secrets/ocfleet-postgres.toml --source controller.sqlite --dry-run --json
ocfleet postgres import --config /run/secrets/ocfleet-postgres.toml --source controller.sqlite --lease-owner controller-a --json
ocfleet postgres export --config /run/secrets/ocfleet-postgres.toml --output /var/lib/ocfleet/export/controller.sqlite --json
```

Non-dry-run import requires the bounded `controller-writer` lease and validates
its fencing token inside the replacing transaction. Export writes a new private
SQLite file only after the stored image checksum, schema, bounds, and selected
table counts pass. Existing output files are never overwritten. Legacy CLI
commands and `ocfleet-api` still open SQLite; broad command/API backend
selection is not implemented. This module is independently mergeable only as
default-off experimental foundation code, not independently deployable as the
production controller backend. C3 HA failure/recovery work and the `C-READY`
gate remain required before production use. Controlled-write D0 is a durable
local approval/CLI state machine; D1-D4 dispatch remains intentionally absent,
so this backend does not make any controlled operation reachable.
