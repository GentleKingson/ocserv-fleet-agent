# C1 Native Postgres Completion Inventory

Issue `#49` requires a production relational Postgres backend with full
`StoreReader`/`StoreWriter` parity. The merged snapshot backend is retained as
an explicitly experimental migration and fencing tool; it is not counted as
native parity.

## Delivery Slices

| Slice | Scope | Status |
| --- | --- | --- |
| C1.1 Native core | Private connection source reuse, advisory-locked and future-version-safe native migrations, relational nodes/endpoint trust/audit, atomic node-add audit, Docker failure injection | merged |
| C1.2 Registry and trust | Node metadata/maintenance/capability, enrollment, endpoint lifecycle, and atomic audit surface | implemented on the Issue #49 branch; shared contract gate remains C1.5 |
| C1.3 Scheduler and observations | Jobs, claims, runs, outcomes, observations, maintenance, retention, fencing, and indexes | pending |
| C1.4 Health and alerts | Health policy/evaluation/history/rollups, alerts, webhook queue/delivery, recovery, and retention | pending |
| C1.5 Migration and parity gate | Verified SQLite-to-native import/export, full shared contract suite, TLS remote connections, backup/restore, performance and failure tests | pending |

## C1.1 Safety Boundary

The native module is compiled only with the explicit
`postgres-native-experimental` feature (which enables `postgres-backend`) and
deliberately has no CLI, API, scheduler, or controller selection path. Its
public Rust API is experimental and absent from ordinary `postgres-backend`
builds. A source-boundary test keeps it unreachable from production entry
points until all backend contracts pass. This prevents a partial backend from
being mistaken for a deployable runtime.

The first native migration:

- takes a transaction-scoped advisory lock;
- rejects a migration version newer than the binary before any DDL;
- rejects inconsistent migration names and incompatible pre-existing objects;
- uses the fixed `ocfleet_native` schema and fully qualified relation names,
  independent of the connection `search_path`;
- creates relational `ocfleet_native.nodes`,
  `ocfleet_native.endpoint_trust`, and
  `ocfleet_native.controller_audit_log` tables;
- stores trust and typed audit payloads as `JSONB`, not a SQLite image;
- commits node, initial active trust, and audit atomically.

Until C1.5 supplies verified TLS, native connections reuse the snapshot
backend's fail-closed transport policy: `NoTls` is accepted only for Unix
sockets and loopback hosts.

The Docker regression starts two concurrent migration clients, proves one
native node maps to relational node/trust rows, injects an audit trigger failure
and verifies complete rollback, and verifies a future schema marker causes a
read-only fail-closed connect with all row counts unchanged. It also covers a
hostile `search_path`, an unrelated `public.nodes`, inconsistent migration
history, and an incompatible pre-existing native relation.

## C1.2 Registry And Trust Boundary

Native migration `0002_registry_trust` upgrades the C1.1 endpoint model without
discarding its data, then adds relational metadata, maintenance, capability,
enrollment-token, and join-request tables. It retains the fixed
`ocfleet_native` namespace and validates both migration names before applying
new DDL.

The dormant native store now covers:

- bounded node reads by role and metadata, node enable/disable/remove, metadata
  upsert, maintenance set/clear, and version-governance inputs;
- capability snapshots bound to the node's current endpoint with the RPC audit
  inserted in the same transaction;
- endpoint lookup/snapshot, rotation lineage, revocation, quarantine, automatic
  node disabling, and legacy enrollment reconciliation;
- enrollment token create/revoke, constant-shape credential rejection audits,
  atomic usage counters, join submit/reject/approve, and typed redacted audit;
- atomic node, endpoint trust, join-state, and audit writes during enrollment.

The Docker regression exercises a v1-to-v2 upgrade, hostile `search_path`,
metadata selectors, maintenance, capability projection, endpoint rotation and
quarantine, successful/rejected/legacy enrollment flows, and trigger-injected
audit failures that must roll back every registry and trust mutation.

## Completion Rule

Issue `#49` must remain open until C1.2-C1.5 are complete and the same bounded,
redacted, actor-bound contract suite passes against SQLite and native Postgres.
Only then may runtime selection report `postgres-native` or the roadmap advance
C1 beyond active implementation.
