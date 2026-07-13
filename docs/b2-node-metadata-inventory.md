# B2 Node Metadata And Maintenance Inventory

Issue `#42` is operationally mature at SQLite schema version 26. Node metadata is
controller-local advisory data and is deliberately stored separately from node
identity and endpoint trust.

| Requirement | Implementation and evidence |
| --- | --- |
| Environment, site, owner/team, service tier | `node_metadata` stores bounded printable identifiers; `ocfleet node metadata set|show` provides an audited CLI projection. |
| Bounded labels | At most 32 scalar labels are accepted. Keys and values use closed ASCII character sets and fixed byte limits; duplicate CLI keys are rejected. |
| Expected agent version | An optional bounded value is stored for later B8 version-readiness analysis. It cannot start an upgrade or agent RPC. |
| Atomic audit | Metadata replacement and maintenance set/clear use one SQLite transaction with before/after or bounded advisory audit detail. Audit failure rolls back the mutation. |
| Restricted selectors | Scheduler selectors accept only node ID, role, environment, site, owner team, service tier, or one exact string label. Role and metadata predicates run in SQLite before `LIMIT 51`, so a large fleet with a small match remains valid while more than 50 matches fail closed. Metadata rows are closed-validated on read and SQLite/contamination errors fail the job instead of silently skipping nodes. |
| Maintenance | Per-node half-open UTC windows suppress scheduler target resolution only. They do not change health history, trust, enrollment, peer, or path authorization. |
| Trust isolation | Metadata tables have only a foreign key to `nodes`; their writers never update `endpoint_trust`, enrollment, or controller authorization tables. |

The metadata selector, trust-policy diff, and CLI/API projection work remains read-only with
respect to agents. No field is interpreted as an endpoint ID, trust state,
method name, path target, or command.
