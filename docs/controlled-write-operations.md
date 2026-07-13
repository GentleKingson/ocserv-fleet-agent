# Controlled Write Operations Design

This document is a safety review draft for future controlled operations. The
current implementation remains read-only by default. This phase adds no working
reload, restart, config apply, config rollback, or session disconnect RPC.

## Threat Model

Controlled operations change the project from passive observability to active
fleet control. The main risks are:

- turning a typed control plane into shell, raw command, raw file, or raw log
  access;
- accidental or malicious outage through reload/restart/config changes;
- bypassing operator approval or RBAC through API/dashboard paths;
- leaking usernames, client IPs, session IDs, raw config, certificates, secrets,
  stdout/stderr, or raw RPC bodies into audit, history, alerting, or dashboard
  output;
- replaying or forging write intents;
- applying unreviewed config or rolling back to an unknown state;
- enabling write behavior on an agent because the controller asked for it rather
  than because the local operator explicitly enabled agent policy.

The safe default is fail-closed: no controlled write method is dispatched unless
the binary is built with a future `controlled-writes` feature, the agent local
config enables controlled writes, the specific operation policy is enabled, the
controller request is signed and approved, and the operation supports dry-run.

## Non-goals

This design does not implement:

- `ocserv.reload`
- `ocserv.restart`
- `ocserv.config.apply`
- `ocserv.config.rollback`
- `ocserv.session.disconnect`
- any dashboard/API mutation route
- any agent command executor
- any raw config upload

The current repo must continue to pass the existing read-only safety tests.

## Allowed Future Operations

These operation names are draft method names only. They are known but not
allowed in the default build.

| Operation | Future intent | Required constraints |
| --- | --- | --- |
| `ocserv.reload` | Reload one locally configured ocserv service identity. | Service identity is bound in agent local config. The controller must not provide a unit name, command, path, or selector. Dry-run reports only whether local policy and signed intent would allow the operation. |
| `ocserv.restart` | Emergency restart of one locally configured ocserv service identity. | Disabled by default even when controlled writes are enabled. Requires explicit emergency policy, higher approval role, reason, change ticket, dry-run, and outage acknowledgement. |
| `ocserv.config.apply` | Apply a reviewed ocserv config bundle. | Accepts only signed bundle metadata and a bundle ID known to the agent. No raw config body or raw command in RPC. Dry-run validates signature, schema, expected previous bundle, and local policy. |
| `ocserv.config.rollback` | Roll back to a known previous signed bundle. | Target must be an agent-known signed previous bundle. Rollback cannot accept arbitrary file paths or config content. |
| `ocserv.session.disconnect` | Future design placeholder only. | The scaffold carries no token or selector and always rejects validation because no selector design currently satisfies the low-sensitive boundary. |

## Forbidden Forever Operations

These remain outside the project scope:

- shell execution (`shell.exec`)
- raw command execution (`command.run`)
- raw file read/write (`file.read`, raw config upload, arbitrary path write)
- raw `occtl`, `systemctl`, or `journalctl` passthrough
- arbitrary script hooks
- remote package install or upgrade
- controller-provided service unit names, journal selectors, local paths,
  command names, scripts, provider selectors, or agent-to-agent payloads
- dashboard/API direct mutation without complete authentication, RBAC, approval,
  CSRF protection, and audit design

## Approval Workflow

Every future operation request must have:

- `operation_id`
- authenticated operator `actor`
- human `reason`
- external `change_ticket`
- `approval_id`
- request UUID
- `dry_run` flag
- signed intent
- target operation kind
- rollback plan or explicit irreversible explanation

The controller creates a pending change request in SQLite. A different
authorized actor with sufficient role approves it. The final dispatch uses the
approved signed intent; the agent verifies both the signature and local policy.
Trust policy and enrollment flows must not auto-generate approvals.

## Dry-run Workflow

Dry-run is mandatory for all operation kinds:

1. Controller records a dry-run change request.
2. Agent validates local policy, signed intent, operation kind, and target
   metadata.
3. Agent returns a typed low-sensitive summary.
4. Controller records dry-run audit before any non-dry-run approval can be used.

Dry-run must not reload, restart, apply config, roll back config, disconnect a
session, write raw config, or call a raw command.

## Rollback Workflow

Rollback handling is operation-specific:

- reload: normally no rollback, but the operation must report whether local
  health checks should be observed after reload.
- restart: not inherently reversible; requires explicit irreversible outage
  acknowledgement.
- config apply: must identify the previous signed bundle and rollback bundle
  before apply.
- config rollback: target is the rollback plan.
- session disconnect: irreversible; must state that the session cannot be
  restored.

Non-reversible operations require a stronger approval record and an explicit
`irreversible_reason` in the response/audit summary.

## Protocol Draft

Draft DTOs live behind the `controlled-writes` feature in
`ocfleet-protocol::controlled_write`. They are not wired into dispatch. Their
validation accepts dry-run only, bounds every string/hash/signature, requires
operation/params agreement, requires restart outage acknowledgement, redacts
actor/reason/signed material/params from request `Debug`, and uses a closed
typed response summary instead of arbitrary JSON. Response validation rejects
inconsistent policy decisions and missing rollback or irreversibility metadata.

Request fields:

```json
{
  "operation_id": "op_...",
  "operation_kind": "ocserv_config_apply",
  "actor": "alice@example.com",
  "reason": "Rotate reviewed ocserv config bundle",
  "change_ticket": "CHG-1234",
  "approval_id": "approval_...",
  "request_id": "uuid",
  "dry_run": true,
  "signed_intent": {
    "key_id": "controller-signing-key-v1",
    "algorithm": "Ed25519",
    "payload_sha256": "hex",
    "signature": "base64"
  },
  "params": {
    "kind": "ocserv_config_apply",
    "bundle_id": "bundle_...",
    "bundle_sha256": "hex",
    "expected_previous_bundle_id": "bundle_previous"
  }
}
```

Responses contain only low-sensitive summaries:

```json
{
  "operation_id": "op_...",
  "request_id": "uuid",
  "status": "accepted_dry_run",
  "dry_run": true,
  "summary": {
    "operation_kind": "ocserv_config_apply",
    "policy_decision": "would_allow",
    "validation_code": "POLICY_ALLOWED"
  },
  "rollback_available": true,
  "rollback_plan_id": "rollback_...",
  "irreversible_reason": null
}
```

Responses must not contain raw stdout/stderr, raw occtl/systemctl/journalctl
output, raw config, raw certificate material, username, client IP, session ID, or
secret values.

## SQLite State Schema

Schema migration `0028_controlled_write_state` implements the additive D0
tables. The default build cannot access the state-machine module and the agent
still has no write dispatch. The abbreviated schema below documents the core
relationships; the migration is authoritative for constraints and indexes.

Intent verification never accepts a caller-supplied public key. The controller
loads a private TOML keyring whose entries bind a `key_id` and Ed25519 public
key to an explicit set of actors. The canonical signed payload includes actor,
reason, exact EndpointID, operation, ticket, nonce, expiry, and typed parameter
summary. Storage retains the signature, payload digest, key ID, and public-key
fingerprint so the decision can be reverified without trusting request input.

```sql
CREATE TABLE change_requests (
  request_id TEXT PRIMARY KEY,
  operation_id TEXT NOT NULL,
  operation_kind TEXT NOT NULL,
  actor TEXT NOT NULL,
  reason TEXT NOT NULL,
  change_ticket TEXT NOT NULL,
  dry_run INTEGER NOT NULL,
  signed_intent_json TEXT NOT NULL,
  params_summary_json TEXT NOT NULL,
  state TEXT NOT NULL,
  rollback_plan_json TEXT,
  irreversible_reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE approvals (
  approval_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  approver_actor TEXT NOT NULL,
  approver_role TEXT NOT NULL,
  decision TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE write_operation_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  request_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  operation_kind TEXT NOT NULL,
  actor TEXT NOT NULL,
  approval_id TEXT,
  state_from TEXT,
  state_to TEXT NOT NULL,
  ok INTEGER,
  error_code TEXT,
  detail_json TEXT NOT NULL
);

CREATE TABLE signed_bundles (
  bundle_id TEXT PRIMARY KEY,
  bundle_sha256 TEXT NOT NULL,
  signer_key_id TEXT NOT NULL,
  signature_algorithm TEXT NOT NULL,
  created_at TEXT NOT NULL,
  supersedes_bundle_id TEXT
);
```

Audit detail must contain only low-sensitive summaries and redacted identifiers.
No raw secrets, raw config, or complete URL/path/query values are allowed.

## Agent-local Policy

Agent config defaults:

```toml
[controlled_writes]
enabled = false

[controlled_writes.ocserv_reload]
enabled = false
local_identity = "ocserv-primary"

[controlled_writes.ocserv_restart]
enabled = false
emergency_only = true
local_identity = "ocserv-primary"
```

The current default build rejects `enabled = true` because the
`controlled-writes` feature is off. A feature-enabled build validates local
policy and dry-run DTOs, but the agent still rejects every controlled-write RPC
as not allowed because no dispatch exists. The controller must never supply
local service units, paths, commands, selectors, scripts, or package names.
Feature-enabled config also requires `ocserv_restart.emergency_only = true` and
rejects enabling session disconnect because no safe opaque selector exists.

## Safety Gates

- Compile-time feature: `controlled-writes`, default off.
- Agent local config: `controlled_writes.enabled = false`, default off.
- Per-operation local policy: disabled by default.
- Request type: fixed DTO only.
- Dispatch: not wired in this phase.
- API/dashboard: no mutation routes.
- Audit: required for every state transition.
- Dry-run: mandatory for every operation.
- Rollback: required or explicitly marked irreversible.

## Phase 1 Acceptance

This phase is complete only if:

- default build remains pure read-only;
- controlled write method names are known but not allowed;
- unknown/dangerous raw methods remain rejected;
- controlled write config is default disabled and feature-gated;
- docs are clear enough for security review;
- no code path executes reload, restart, apply, rollback, disconnect, shell,
  raw command, raw file read/write, or script hooks.
