# A1 Controller Mutation Inventory

This is the completion inventory for issue `#33`. It covers production
controller SQLite mutations in the default and all-feature builds. Migration
DDL remains confined to the reviewed migration/store boundary. Read-only audit
events with no paired business mutation may use `AuditWriter` directly.

## Production Boundaries

| Family | Production writer boundary | Atomic state and audit | Primary rollback/conflict evidence | Merged evidence |
| --- | --- | --- | --- | --- |
| Node registry | `write_node_add/enable/disable/remove` | Node and effective trust lifecycle | audit-trigger rollback, transaction-drop, ambiguous binding rejection | PR `#57` |
| Scheduler jobs | `write_scheduler_job_add/enable/disable` | Job configuration and audit | audit-trigger rollback and closed selector projection | PR `#58` |
| Scheduler execution | `write_scheduler_run_start/outcome/finish` | Run start; bounded observation/audit pairs; finish/job clock | audit/observation/clock failure injection, terminal rewrite rejection | PR `#60` |
| Endpoint lifecycle | `write_endpoint_rotation/revocation/quarantine` | Trust lineage, registry pointer/node enabled state, audit | mid-transition and audit failure rollback, exact retry, contaminated-state rejection | PR `#61` |
| Enrollment binding | `write_enrollment_approval`, `write_legacy_enrollment_claim` | Request decision, explicit node, Active trust, audit | audit rollback, immediate-writer races, strict legacy provenance | PR `#62` |
| Enrollment token/request | token create/revoke and request submit/reject writers | Token counters/status, request state, audit | final-use race, lazy-expiry rollback, divergent actor/reason/input replay | PR `#63` |
| Retention | `write_retention_policy/apply` | Policy or all bounded deletes for one scope, audit | audit rollback, concurrent replay, multi-scope partial resume | PR `#64` |
| Health | `write_health_policy/snapshots` | Policy or bounded snapshot batch, audit | audit rollback, actor/input replay conflicts | PR `#65` |
| Alert evaluation | `write_alert_evaluation` | Bounded candidate batch and audit | audit rollback, stale-before conflict preserving operator decisions | PR `#65` |
| Alert operator/hook | transition and webhook-hook-create writers | Silence/resolve or hook configuration, audit | audit rollback, stale-before, actor/input replay | PR `#66` |
| Alert delivery | attempt and finalization writers | Attempt history/audit; bounded `last_sent_at` set/summary audit | audit rollback, stale-before, exact/divergent replay | PR `#67` |

## Enforcement Audit

- `scripts/check-controller-mutations.sh` rejects mutation SQL outside store and
  migrations.
- It rejects direct production calls to node, endpoint, enrollment, scheduler
  config, legacy scheduler persistence, retention, health, alert evaluation,
  alert action/hook, alert upsert, and delivery persistence mutators outside the
  reviewed store/backend adapters.
- `scripts/tests/test-controller-mutation-guard.sh` proves every guarded family
  is accepted at its reviewed boundary and rejected from an unsafe production
  module.
- API routes receive only `ApiReadStore`; all fourteen declared routes are
  `GET` and API tests prove forbidden methods do not write.

Legacy raw scheduler/observation/alert helpers remain only as integration-test
fixture APIs. Production source calls are rejected by the guard. They are not
reachable from CLI command dispatch, scheduler execution, API routes, or agent
RPC.

## Transaction And I/O Rules

- Actor validation precedes every production business writer.
- Business state and its low-sensitive success audit commit once or roll back
  together. An audit insertion error is a business-operation failure.
- Exact replay is a no-op only when actor, event, and canonical input hash or
  closed before-state match. Divergence and ambiguity fail closed.
- No transaction crosses RPC, semaphore, filesystem delivery, HTTPS delivery,
  or other external I/O. External delivery cannot be rolled back; attempt and
  finalization persistence are separate durable atomic boundaries.
- No slice changed schema version 8, protocol version 1, API routes, agent
  capabilities, feature defaults, or the network read-only authorization
  boundary.

## Verification Gate

The A1 merge train requires and has passed both default and all-feature format,
Clippy, and workspace tests; mutation guard and guard self-test; doc claims;
supply-chain checks; CodeQL; and four Linux install smoke jobs. Individual PR
and issue `#33` comments retain the run links and exact merge SHAs.
