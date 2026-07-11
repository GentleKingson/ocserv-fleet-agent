# A2 Typed Storage Completion Inventory

Issue `#34` is complete at SQLite schema version `18`. This inventory is the
closure evidence for the core JSON persistence families named by the issue.

## Payload Families

| Requested family | Persisted schema | Relational binding | Migration | Public read boundary | Evidence |
| --- | --- | --- | --- | --- | --- |
| `JobSelectorV1` | `ocfleet.scheduler.selector.v1` | job kind and pair presence | `0009` | controller and API unwrap validated selector | PR `#69` |
| `PairSelectorV1` | `ocfleet.scheduler.pair.v1` | path-probe kind and explicit source/target pair | `0009` | controller and API unwrap validated pair | PR `#69` |
| `HealthSummaryV1` | `ocfleet.health.summary.v1`; closed degraded-method companion | snapshot status | `0010` | health, alert, CLI, and API projections only | PR `#70` |
| `ObservationSummaryV1` | `ocfleet.observation.summary.v1` | method and result class | `0011` | fixed per-method public fields only | PR `#71` |
| `RunSummaryV1` | `ocfleet.run.summary.v1` | job, kind, status, and trigger | `0012` | controller and API unwrap validated summary | PR `#72` |
| `TrustBundleV1` | `ocfleet.trust.bundle.v1` | endpoint, generation, and lifecycle status | `0013` | trust logic consumes validated allowlists/pairs | PR `#73` |
| `AlertDetailV1` | `ocfleet.alert.detail.v1` | fixed alert-detail contract | `0014` | alert delivery, CLI, and API public detail only | PR `#74` |
| `DeliveryAttemptDetailV1` | `ocfleet.delivery-attempt.detail.v1` | every delivery-attempt column | `0017` | controller delivery history only | PR `#77` |
| `AuditDetailV1` | `ocfleet.audit.detail.v1` | every audit column | `0018` | controller export and independent API unwrap public fields | PR `#78` |

A2 also closed two adjacent persisted JSON families discovered by the inventory:
webhook host allowlists in schema `15`/PR `#75`, and enrollment labels/scope in
schema `16`/PR `#76`.

## Acceptance Evidence

**All new writes are typed.** Production writers construct payload DTOs before
SQL persistence. The controller mutation guard permits persistence SQL only in
the reviewed store and migration modules. There is no raw production writer for
the listed columns.

**Legacy migration fails closed.** Migrations `0009` through `0018` run after a
private checksummed backup. Exact legacy values are canonicalized; unknown,
future-version, malformed, oversized, nested where forbidden, secret-like,
address-bearing, impossible, or relationally inconsistent fixtures abort the
transaction and leave the preceding schema intact. Ambiguous legacy scheduler
selectors are disabled for operator review rather than activated.

**Raw stored JSON does not cross the CLI/API boundary.** Controller readers and
the independent API adapter deserialize the expected schema, validate bounds
and relational agreement, and return only explicit public projections. The
audit storage `_audit` record and every other storage envelope are stripped.
Current-schema contamination returns a read error; API routes respond with a
generic error and do not reflect contaminated values.

**Compatibility and security matrices pass.** Payload unit tests cover closed
round trips and relationship mismatch. Migration tests cover successful upgrade,
backup creation, invalid legacy values, idempotent reopen, large-fixture upgrade,
and future-schema rejection. Store, CLI export, alert delivery, scheduler, and
API tests cover current-schema contamination and no-leak behavior. Both default
and all-feature workspace matrices, Clippy, formatting, documentation claims,
and controller mutation guard/self-test pass for the schema-18 completion.

## Boundary

A2 changes persistence validation only. It adds no RPC, scheduler execution,
API mutation route, trust inference, agent provider, shell/command adapter,
feature-default change, or controlled-write dispatch. SQLite remains the sole
runtime backend. Scheduler leasing/recovery semantics begin at A3 issue `#35`.
