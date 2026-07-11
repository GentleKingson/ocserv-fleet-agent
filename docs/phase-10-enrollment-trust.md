# Phase 10: Enrollment And Trust Management

Phase 10 adds token-gated, approval-based enrollment alongside the manual bound
registration path and provides explicit EndpointID lifecycle controls. New
approvals create the operator-owned registry node and its trust binding in the
same audited transaction. A separate explicit claim command repairs only the
strict legacy approved-unbound shape.

## Enrollment Flow

1. A controller operator creates a one-time enrollment token:

   ```bash
   ocfleet enroll token create --ttl 24h --max-uses 1 --description "prod node onboarding"
   ```

   The plaintext token is printed once. The controller database stores only a
   BLAKE3 hash, token metadata, usage counters, and audit records.

2. An agent or operator submits a join request:

   ```bash
   install -m 0600 /dev/null ./enrollment.token
   # Put the plaintext token printed above into ./enrollment.token.
   ocfleet enroll request create \
     --token-file ./enrollment.token \
     --agent-public-key <agent-public-key> \
     --fingerprint <agent-fingerprint> \
     --requested-endpoint-id <agent-endpoint-id> \
     --hostname hk-ocserv-01 \
     --agent-version 0.1.0
   ```

   A valid token creates a `pending` join request only. It does not grant peer
   or path-probe trust. Prefer `--token-file` or `--token-stdin`; `--token`
   remains available for compatibility but is discouraged because command-line
   arguments can leak through shell history, process listings, and audit tools.

3. A controller operator approves the request:

   ```bash
   ocfleet enroll approve <join-request-id> \
     --endpoint-id <endpoint-id> \
     --node-id hk-ocserv-01 \
     --region hk \
     --role ocserv \
     --reason "ticket-123"
   ```

   Approval inserts an enabled registry node, records a bound Active endpoint
   trust entry with generation `1` and the submitted fingerprint, marks the join
   request approved by the resolved operator, and writes one composite audit
   event. Those changes commit in one SQLite transaction. `node_id`, region, and
   role are operator inputs; hostname and labels never select controller
   identity.

### Legacy Binding Claim

Controller and scheduler dispatch require all of the following:

- an enabled controller registry node;
- the node's current EndpointID equals the EndpointID being contacted;
- the Active trust row points back to that exact node;
- exactly one Active trust row is bound to the node.

Approvals written by older binaries can contain an Active generation-1 trust
row without a node binding. They remain rejected by the dispatch gate until an
operator explicitly claims the exact approved request:

```bash
ocfleet enroll claim <join-request-id> \
  --endpoint-id <endpoint-id> \
  --node-id hk-ocserv-01 \
  --region hk \
  --role ocserv \
  --reason "ticket-123 legacy binding"
```

Claim accepts only one approved request for that EndpointID and the unchanged
legacy trust shape: Active, unbound, generation `1`, matching fingerprint, no
rotation lineage, and an empty typed trust bundle. It inserts the operator-owned
node, compare-and-set binds the trust row, and writes `enrollment.claim` in one
immediate transaction. Exact retries are no-ops; ambiguous, contaminated,
advanced, or differently bound state fails closed. The controller never infers
a binding from agent-supplied hostname or labels and never repairs rows during
startup or dispatch.

## Endpoint Lifecycle

Rotate an EndpointID:

```bash
ocfleet endpoint rotate <old-endpoint-id> \
  --new-endpoint-id <new-endpoint-id> \
  --reason "key rotation"
```

Revoke an EndpointID:

```bash
ocfleet endpoint revoke <endpoint-id> --reason "lost host"
```

Quarantine an EndpointID:

```bash
ocfleet endpoint quarantine <endpoint-id> --reason "suspicious traffic"
```

Rotated, revoked, and quarantined endpoints are excluded from normal controller
RPC and path-probe authorization. Quarantine does not add any diagnostic command
or management shell.

Lifecycle transitions are closed:

| Current state | Rotate | Revoke | Quarantine |
| --- | --- | --- | --- |
| `active` | apply | apply | apply |
| `quarantined` | apply | apply | exact no-op |
| `revoked` | reject | exact no-op | reject |
| `rotated` | exact linked retry only | reject | reject |

Every effective transition uses checked generation arithmetic. An exact no-op
does not change generation, trust bundle, timestamp, or audit count. Rotation
updates the old/new trust rows and moves the bound node's EndpointID pointer in
one SQLite transaction. Revocation and quarantine disable the currently bound
node in that transaction. Rotation from quarantine keeps that node disabled
until an operator explicitly enables the clean replacement binding. An exact
linked retry that finds an already-correct pointer is a no-op; repairing the one
deterministic legacy stale-pointer case writes a reconciliation audit without
another generation increment. Node removal revokes its unique Active trust
before deleting the registry row; ambiguous Active candidates are rejected
rather than chosen implicitly. Historical inactive trust rows remain as
lifecycle tombstones.

## Trust Diff

Inspect controller registry trust state:

```bash
ocfleet trust diff
ocfleet trust diff --endpoint <endpoint-id>
ocfleet trust diff --endpoint <endpoint-id> --format json
ocfleet trust diff --strict
```

`--strict` exits non-zero when high-severity trust drift is present, including
revoked endpoints still trusted or quarantined endpoints still allowed.

## Audit

The controller audit log records:

- `enrollment.token.create`
- `enrollment.token.use`
- `enrollment.token.reject`
- `enrollment.approve`
- `enrollment.claim`
- `endpoint.rotate`
- `endpoint.revoke`
- `endpoint.quarantine`

Audit detail includes actor type, target type/id, before and after state where
applicable, reason, and request/correlation context.

Enrollment approval/claim plus node and endpoint lifecycle commands enter
through actor-bearing `StoreWriter` methods. A production source guard rejects
direct mutator calls outside the reviewed SQLite store/backend boundary. Exact
approval, claim, and lifecycle no-ops do not create misleading audit events.

## Safety Boundary

Phase 10 does not add shell execution, raw command execution, `systemctl`,
`occtl`, `journalctl`, reload/restart operations, generic RPC methods, relay
probes, or unsafe diagnostics.

This enrollment binding and lifecycle hardening changes no SQLite schema
version, RPC protocol, read-only HTTP API route, agent capability, or default
read-only behavior. The decision and rejected automatic-binding alternatives
are recorded in
[ADR-enrollment-binding-ownership](adr/ADR-enrollment-binding-ownership.md).
