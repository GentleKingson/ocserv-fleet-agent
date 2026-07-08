# Phase 10: Enrollment And Trust Management

Phase 10 replaces the manual-only registration path with a token-gated,
approval-based onboarding flow and explicit EndpointID lifecycle controls.

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

   Approval records an active endpoint trust entry with generation `1`, stores
   the agent fingerprint, records approved labels, and writes before/after audit
   detail.

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

## Safety Boundary

Phase 10 does not add shell execution, raw command execution, `systemctl`,
`occtl`, `journalctl`, reload/restart operations, generic RPC methods, relay
probes, or unsafe diagnostics.
