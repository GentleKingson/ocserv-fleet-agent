# Backend Plan

`ocfleet` currently implements one controller backend: local SQLite. Postgres is
planned as an optional backend for larger fleets, longer history windows, and
centralized audit queries, but it is not required and is not implemented in this
slice.

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

The current `Store` API mixes:

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

The API should depend only on read interfaces where possible. Scheduler,
retention, alert silence/resolve, enrollment, and endpoint lifecycle flows need
writer interfaces and must keep audit mandatory.

## SQLite-only Assumptions To Isolate

- SQL syntax using SQLite `strftime` and `json` storage as text.
- In-process `rusqlite::Connection` lifetime.
- File permission checks for `controller.sqlite`.
- Backup sidecars written next to the database.
- Tests that inspect SQLite tables directly.

Before adding Postgres, create compatibility tests around low-sensitive
projections and audit semantics so SQLite and Postgres behavior stays aligned.
