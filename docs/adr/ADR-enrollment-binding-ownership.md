# ADR: Operator-owned Enrollment Binding

## Status

Accepted for the A1 atomic mutation-audit milestone.

## Context

Enrollment approval historically inserted an Active generation-1 trust row
without a `node_id`. Dispatch correctly rejected that row because authority
requires an enabled registry node and one bidirectional Active binding. The
manual `node add` command could not complete the workflow because the approved
EndpointID already existed in `endpoint_trust`.

Agent-supplied hostname and labels are untrusted enrollment metadata. Treating
either as controller identity would create an implicit registration and
trust-on-first-use path. Startup repair or state-dependent adoption by `node
add` would have the same problem and would make the authority transition hard
to audit or retry safely.

## Decision

New approvals require the operator to supply `node_id`, `region`, and the fixed
`ocserv` role. One immediate SQLite transaction:

1. validates the pending request and operator-owned metadata;
2. inserts the enabled registry node with `name = node_id`;
3. inserts the request fingerprint as a bound Active generation-1 trust row;
4. marks the request approved with the resolved actor; and
5. writes one low-sensitive `enrollment.approve` audit event.

An audit failure, constraint failure, compare-and-set failure, or dropped
transaction rolls back every business row. Exact retries return the already
approved request without changing timestamps, enabled state, trust data, or
audit count. A divergent retry fails closed.

`enroll claim` is a separate compatibility operation for legacy approved rows.
It accepts the request ID, its exact assigned EndpointID, and explicit operator
node metadata. It binds only the unique historical approval shape: an Active,
unbound, generation-1 trust row with matching fingerprint, no lineage, and the
empty typed trust bundle. Contaminated, ambiguous, advanced, or already-owned
state is rejected. The command never scans for candidates or repairs state at
startup.

Both paths use explicit actor-bearing `StoreWriter` methods. Audit projections
record request, node, EndpointID, lifecycle state, and fingerprint presence;
they never include token material, token hashes, agent keys, fingerprints,
hostnames, versions, or labels.

## Consequences

- A successful new approval is immediately eligible for the existing dispatch
  gate, subject to the agent-side controller allowlist.
- Legacy approvals have a deterministic manual repair path without weakening
  dispatch authorization.
- Approval CLI callers must now provide operator-owned node metadata.
- There is no schema, protocol, HTTP API, agent capability, or feature change.
- SQLite remains the only runtime writer backend; a future Postgres writer must
  preserve the same serialization, compare-and-set, idempotency, and audit
  contract.

## Rejected Alternatives

- Derive `node_id`, region, or role from enrollment hostname or labels.
- Automatically bind approved rows during startup or dispatch.
- Make `node add` silently adopt an existing unbound trust row.
- Leave all new approvals unbound and require an avoidable second authority
  transition.
