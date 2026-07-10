# Phase 10: Enrollment And Trust Management

Phase 10 adds a token-gated, approval-based enrollment record alongside the
manual bound registration path and provides explicit EndpointID lifecycle
controls. The current approval flow does not yet complete a dispatch-authorized
node binding.

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
     --reason "ticket-123"
   ```

   Approval records an Active endpoint trust entry with generation `1`, stores
   the agent fingerprint, records approved labels, and writes before/after audit
   detail. The entry has no operator-selected `node_id`; Active status alone does
   not authorize RPC dispatch.

### Current Binding Limitation

Controller and scheduler dispatch require all of the following:

- an enabled controller registry node;
- the node's current EndpointID equals the EndpointID being contacted;
- the Active trust row points back to that exact node;
- exactly one Active trust row is bound to the node.

The current enrollment approval produces a legacy Active unbound row, so it
fails this gate with `ENDPOINT_NOT_ALLOWED`. The controller does not infer a
binding from agent-supplied hostname or labels and does not repair the row at
startup. There is not yet an operator reconciliation command. Manual `node add`
remains the usable path for creating a bound dispatch identity; an already
approved EndpointID is retained rather than overwritten by `node add`.

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
- `endpoint.rotate`
- `endpoint.revoke`
- `endpoint.quarantine`

Audit detail includes actor type, target type/id, before and after state where
applicable, reason, and request/correlation context.

Node and endpoint lifecycle commands enter through actor-bearing `StoreWriter`
methods. A production source guard rejects direct node/endpoint mutator calls
outside the reviewed SQLite store/backend boundary. Exact lifecycle no-ops do
not create misleading audit events.

## Safety Boundary

Phase 10 does not add shell execution, raw command execution, `systemctl`,
`occtl`, `journalctl`, reload/restart operations, generic RPC methods, relay
probes, or unsafe diagnostics.

This binding/lifecycle hardening changes no SQLite schema version, RPC protocol,
read-only HTTP API route, agent capability, or default read-only behavior.
