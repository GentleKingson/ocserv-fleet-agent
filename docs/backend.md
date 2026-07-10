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
first production-hardening slice adds node add/enable/disable/remove to this
contract and removes the CLI's post-commit success audits. Audit-trigger failure
tests prove both `nodes` and `endpoint_trust` changes roll back. The next slice
adds scheduler job add/enable/disable to the same contract; audit-trigger
failure rolls back the affected `observability_jobs` insert or enabled-state
update. Scheduler run/outcome/observation writes are not part of this slice.

The API retains a narrower `ApiReadStore` adapter for API projections;
`ReadOnlyStore` opens SQLite with read-only/query-only flags, validates private
database/sidecar files, checks schema version/tables/integrity, and never exposes
a writer to routes. Consolidating this adapter with the neutral reader remains
future work; SQLite is the only runtime backend.

Scheduler run/outcome/observation, health/alert/delivery, retention, and some
enrollment lifecycle flows are not all migrated to the writer trait. Future
writer interfaces must keep actor/audit input mandatory and must not loosen
private file checks or redaction. The scheduler-job writer expansion changes no
schema, protocol, agent capability, or API route; the API remains read-only.

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
