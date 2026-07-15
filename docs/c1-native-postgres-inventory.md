# C1 Native Postgres Completion Inventory

Issue `#49` requires a production relational Postgres backend with full
`StoreReader`/`StoreWriter` parity. The merged snapshot backend is retained as
an explicitly experimental migration and fencing tool; it is not counted as
native parity.

## Delivery Slices

| Slice | Scope | Status |
| --- | --- | --- |
| C1.1 Native core | Private connection source reuse, advisory-locked and future-version-safe native migrations, relational nodes/endpoint trust/audit, atomic node-add audit, Docker failure injection | merged |
| C1.2 Registry and trust | Node metadata/maintenance/capability, enrollment, endpoint lifecycle, and atomic audit surface | merged; shared contract gate remains C1.5 |
| C1.3 Scheduler and observations | Jobs, claims, runs, outcomes, observations, maintenance, retention, fencing, and indexes | merged; shared contract gate remains C1.5 |
| C1.4 Health and alerts | Health policy/evaluation/history/rollups, alerts, webhook queue/delivery, recovery, and retention | implemented on the Issue #49 branch; shared contract gate remains C1.5 |
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

Native `TIMESTAMPTZ` values use typed Postgres/time conversion. Inputs are
normalized to UTC RFC3339 at Postgres' microsecond precision, so equivalent
offset forms and retry requests compare by instant without discarding
fractional seconds. Full trust snapshots read one row beyond the 1,000-row
bound and fail closed rather than returning an apparently complete prefix.

The Docker regression exercises a v1-to-v2 upgrade, hostile `search_path`,
metadata selectors, maintenance, capability projection, endpoint rotation and
quarantine, successful/rejected/legacy enrollment flows, and trigger-injected
audit failures that must roll back every registry and trust mutation. It also
covers offset and fractional timestamp retries plus a 1,001-row trust snapshot
overflow.

## C1.3 Scheduler And Observations Boundary

Native migration `0003_scheduler_observations` adds fully qualified relational
jobs, runs, observations, claims, scheduler maintenance, retention policies,
and retention-operation provenance. Typed selector, pair, run-summary, and
observation-summary payloads remain closed versioned `JSONB` values and are
validated against their relational columns when read.

The dormant native store now covers:

- bounded job, run, and observation readers plus atomic job state/audit writes;
- transactionally fenced job acquisition, renewal, guarded release,
  expired-lease takeover, and abandoned-run recovery with monotonic fence
  tokens and actor-bound ownership;
- claimed run start, bounded multi-observation outcomes, run completion, job
  clocks, and audit records in the same Postgres transaction;
- scheduler maintenance set/clear with atomic audit;
- observation/run retention policy, candidate reporting, bounded batched
  deletion, and actor/request-bound idempotent operation replay.

Postgres claims use row locks and `SKIP LOCKED` for concurrent due-job selection.
Postgres `clock_timestamp()` is authoritative for acquisition, renewal,
takeover, release, outcome, and finish lease decisions; caller timestamps are
event metadata only. Scheduler runs can start only with an actor-bound owner
and fence token, and every run-bound outcome and finish revalidates that same
owner, actor, fence, active run, and live database-time lease. Release refuses
expired claims or claims with active runs, so it cannot erase abandoned-run
recovery state.

The native outcome API requires a claim even for runless invalid-job records;
there is no unfenced scheduler outcome or scheduler-run start entry point.

Retention excludes running runs, actively claimed runs, and observations whose
parent run is running or actively claimed. Candidate reports and deletes use
the same eligibility predicates under a write-excluding target lock. Retention
operation provenance is stored atomically with the deletion result and audit,
so exact retries return the original result and mismatched actors or inputs
fail closed.

The Docker regression covers typed fractional timestamps, claim contention,
fence increments, caller-clock skew, stale-owner rejection, actor/fence-bound
start/outcome/finish, guarded release and recovery, bounded observation reads,
scheduler maintenance, protected running-state retention, deletion, and exact
replay.
Migration concurrency, future-schema rejection, and the dormant runtime
boundary continue to run with the complete native integration suite.

## C1.4 Health And Alerts Boundary

Native migration `0004_health_alerts` adds relational health policy,
evaluation-run, snapshot, append-only history, rollup, alert, webhook,
delivery-attempt, and delivery-queue tables. Health, alert, allowlist, and
delivery-attempt documents remain closed versioned `JSONB` values and are
validated against their relational projections on every read.

The dormant native store now covers:

- health policy changes, evaluation start/finish/failure/recovery, current
  snapshots, history windows, rollup source/read/write, and atomic audit;
- optimistic alert evaluation and operator transitions with actor/request-bound
  replay and stale-before-state rejection;
- webhook creation and enable state, typed host allowlists, delivery attempts,
  durable queue enqueue/claim/renew/defer/outcome, and queue health;
- health snapshot/history/rollup and alert-event retention under the existing
  bounded, actor-bound retention operation model; alert retention excludes
  events referenced by a claimed delivery so it cannot erase live recovery
  state.

Delivery claims use `SKIP LOCKED`, monotonic fence tokens, actor-bound owner
records, and Postgres `clock_timestamp()` for all ownership decisions. Caller
timestamps remain event metadata only. Renewal, defer, and outcome require the
same queue ID, owner ID, audit actor, fence token, and a live database-time
lease. Expired claims are recovered to retry in the same transaction as the
next claim and each recovery receives an audit record.

Health evaluation completion updates the durable run, current snapshot,
append-only history, and audit in one transaction. Alert evaluation and
delivery outcome likewise update relational state and audit atomically; an
injected audit failure therefore cannot leave a partial health or alert
transition.

The Docker regression covers fractional and offset health timestamps, exact
evaluation replay, history and rollup projection, typed alert storage, webhook
queue delivery, wrong-actor claim rejection, successful fenced outcome, queue
health, and the expanded retention scope. The module remains unavailable to
CLI, API, scheduler, and controller runtime selection.

## Completion Rule

Issue `#49` must remain open until C1.5 is complete and the same bounded,
redacted, actor-bound contract suite passes against SQLite and native Postgres.
Only then may runtime selection report `postgres-native` or the roadmap advance
C1 beyond active implementation.
