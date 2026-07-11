# Backend Plan

`ocfleet` currently implements one controller backend: local SQLite. Postgres is
planned as an optional backend for larger fleets, longer history windows, and
centralized audit queries, but it is not required. The optional feature in this
slice is intentionally a compile-only scaffold whose `connect` function always
returns unavailable.

## Current SQLite Contract

SQLite is the default because it supports the read-only MVP and small-fleet
operator model with simple deployment:

- private controller database file
- additive or safe rebuild migrations
- pre-migration backup and checksum
- local controller audit table
- no external service dependency

The existing SQLite safety checks must remain in place even if Postgres support
is added later.

## Optional Postgres Goals

An optional Postgres backend should provide:

- larger fleet query capacity
- longer observation/run/alert history
- centralized audit archival
- multi-operator API deployments with authenticated RBAC
- explicit migration/export tooling from SQLite without forcing migration

It must not introduce unauthenticated writes, automatic trust, raw secrets in
tables, or ocserv write operations.

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
first production-hardening slice added node add/enable/disable/remove to this
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
future work; SQLite is the only runtime backend.

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
I/O never occurs inside SQLite transactions. Other legacy mutations are not all
migrated to the writer trait. Future writer
interfaces must keep actor/audit input mandatory and must not loosen private
file checks or redaction. The scheduler writer expansions change no schema,
protocol, agent capability, or API route; neither does the binding/lifecycle
hardening. The API remains read-only.

## Postgres Scaffold

The `postgres-backend` feature is default-off. It defines only redacted
connection-source configuration and an always-unavailable connection stub. It
does not add a client dependency, SQL schema, migration, import, secret logging,
or runtime selection. SQLite remains required for all current commands.

## SQLite-only Assumptions To Isolate

- SQL syntax using SQLite `strftime` and `json` storage as text.
- In-process `rusqlite::Connection` lifetime.
- File permission checks for `controller.sqlite`.
- Backup sidecars written next to the database.
- Tests that inspect SQLite tables directly.

Before adding Postgres, create compatibility tests around low-sensitive
projections and audit semantics so SQLite and Postgres behavior stays aligned.
