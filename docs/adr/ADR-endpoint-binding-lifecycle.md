# ADR: Endpoint Binding And Lifecycle

- Status: accepted
- Date: 2026-07-10
- Decision owners: controller storage and security maintainers
- Tracking issue: [#33](https://github.com/GentleKingson/ocserv-fleet-agent/issues/33)

## Context

An active EndpointID is necessary but not sufficient to authorize an RPC. The
controller also has to prove that the trust row is bound to the exact node being
targeted and that the node still points back to that EndpointID. Treating status
alone as authorization lets an active but unbound, orphaned, or mismatched row
authorize a registered endpoint.

Endpoint rotation previously changed the old and new trust rows without moving
the node registry pointer. Repeating that operation could create more than one
active descendant, and endpoint status commands accepted transitions out of
terminal states. Node removal could also leave an active trust row behind.

## Decision

RPC authorization requires one closed binding snapshot:

- the registered node exists and is enabled;
- its current EndpointID is the EndpointID being contacted;
- that trust row is `active` and names the same node;
- exactly one active trust row is bound to the node.

Missing, inactive, unbound, mismatched, stale, disabled, and ambiguous states
fail closed before controller key loading, connection setup, or dispatch. A
scheduler worker repeats the same query-only snapshot after concurrency waits.
An active unbound row created by the legacy enrollment flow remains data to be
reconciled explicitly; it is never dispatch authorization.

The lifecycle graph is closed:

| Current state | Rotate | Revoke | Quarantine |
| --- | --- | --- | --- |
| `active` | apply | apply | apply |
| `quarantined` | apply | apply | no-op |
| `revoked` | reject | no-op | reject |
| `rotated` | exact linked retry only | reject | reject |

An exact no-op does not change the generation, trust bundle, timestamp, or
audit count. Every effective transition increments the generation with checked
arithmetic. Exhausted or contaminated generation and lineage state is rejected
without a write.

Rotation updates the old trust row, inserts the new active row, moves the bound
node registry pointer, and writes one closed audit in one SQLite transaction.
An exact retry may repair only the deterministic legacy stale registry pointer;
that repair is audited without another generation increment. Quarantine and
revocation disable a currently bound node in the same transaction. Node enable
requires a clean active bidirectional binding. Node removal revokes its unique
active current or legacy descendant trust before deleting the registry row;
ambiguous active candidates fail closed rather than being selected implicitly.

## Diagnostics

`ocfleet doctor` reports aggregate counts for active unbound rows, active
orphans, current binding mismatches, enabled nodes with inactive current
endpoints, and extra active bindings. It does not list node or EndpointID
values. Disabled revoked/quarantined nodes and historical inactive tombstones
may persist and are not integrity failures.

## Consequences

Existing databases need no schema migration for this slice. A later migration
may add partial uniqueness and lifecycle constraints only after contaminated
legacy rows have an explicit reconciliation workflow. Startup never repairs or
trusts legacy state automatically.

The controller protocol and read-only HTTP API do not change. Rejected RPCs
retain the protocol-level `ENDPOINT_NOT_ALLOWED` result while controller-local
observations distinguish missing, inactive, unbound, and mismatched trust with
fixed low-sensitive codes.

## Rollback

The implementation is source-compatible with schema version 8. An emergency
source rollback needs no database downgrade, but a database rotated by the new
implementation correctly points its node at the replacement EndpointID. Older
code can read that state. Rolling back also restores status-only authorization
and unsafe lifecycle transitions, so it is not an acceptable steady state.
