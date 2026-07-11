# Security Hardening

`ocserv-fleet-agent` is a read-only observability/control-plane. Hardening should preserve that boundary: do not add shell execution, raw command forwarding, arbitrary file reads, ocserv reload/restart, config apply/rollback, or user management RPCs.

## systemd Service

The checked-in unit at `deploy/systemd/ocfleet-agent.service` is the baseline. Keep these properties when copying or templating it:

```ini
[Service]
User=ocfleet
Group=ocfleet
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
StateDirectory=ocfleet-agent
StateDirectoryMode=0700
LogsDirectory=ocfleet-agent
LogsDirectoryMode=0700
ReadWritePaths=/var/lib/ocfleet-agent /var/log/ocfleet-agent
```

Only add writable paths for agent-owned audit, spool, metrics, and SecretKey state. Do not add ocserv config directories, arbitrary log directories, or system service directories as writable paths.

## Private Files And Directories

Use private permissions by default:

```bash
sudo install -d -o root -g ocfleet -m 0750 /etc/ocfleet-agent
sudo install -d -o ocfleet -g ocfleet -m 0700 /var/lib/ocfleet-agent /var/log/ocfleet-agent
sudo install -d -o "$USER" -g "$USER" -m 0700 /var/lib/ocfleet-controller
```

Recommended file modes:

- Controller SQLite: `0600`, owned by the operator account that runs `ocfleet`.
- Controller SecretKey: `0600`, owned by the operator account that runs `ocfleet`.
- Agent SecretKey: `0600`, owned by `ocfleet:ocfleet`.
- Agent config: `0640`, owned by `root:ocfleet`, with `/etc/ocfleet-agent` not group/world writable.
- Agent audit log, spool, and metrics files: `0600`, under `0700` agent-owned directories.

The agent and controller reject unsafe private-file paths where supported. Treat any symlink, hardlink, non-regular file, world-writable parent, or group/world-writable private file as a deployment error.

## SecretKey Handling

The iroh SecretKey defines the local EndpointID. Back it up as a secret, not as a normal config artifact:

```bash
sudo install -d -m 0700 /var/backups/ocfleet
backup="/var/backups/ocfleet/agent.$(hostname).iroh.secret.$(date -u +%Y%m%dT%H%M%SZ)"
sudo cp -a /var/lib/ocfleet-agent/iroh.secret "$backup"
sudo chmod 0600 "$backup"
```

Never paste SecretKey contents into tickets, CI logs, chat, audit exports, or dashboards. EndpointIDs are identifiers and can be logged at low sensitivity, but they still define trust relationships and should not be used for automatic trust-on-first-use.

## Agent Config Risks

Keep `/etc/ocfleet-agent/agent.toml` explicit and small:

- Use fixed `[[security.controllers]]` entries for approved controller EndpointIDs.
- Use fixed `[[security.peers]]` and `[[security.path_probes]]` entries only for approved source/target pairs.
- Do not introduce generic provider selectors, local path selectors from the controller, script hooks, or host/port override flags.
- Keep ocserv read-only providers disabled unless they use the current fixed, low-sensitive provider configuration.

The config must not be a symlink or hardlink. Replace it atomically with a private temporary file and verify owner/mode before restarting the service.

## EndpointID Lifecycle

Endpoint trust is explicit. There is no TOFU and no automatic path-probe trust.
An Active trust row is not sufficient by itself: the controller also requires an
enabled registry node, matching node-to-endpoint and trust-to-node pointers, and
exactly one Active trust binding for that node. Scheduler source and path-target
bindings are checked again after concurrency waits.

- Rotate: use `ocfleet endpoint rotate <old-endpoint-id> --new-endpoint-id <new-endpoint-id> --reason <reason>` after the replacement agent identity is known and approved.
- Revoke: use `ocfleet endpoint revoke <endpoint-id> --reason <reason>` when a key is compromised or a node is retired.
- Quarantine: use `ocfleet endpoint quarantine <endpoint-id> --reason <reason>` when investigation is needed before a permanent revoke or rotation.
- Review: use `ocfleet trust diff --format json` after any lifecycle change.

The accepted transition table is deliberately closed:

| Current state | Rotate | Revoke | Quarantine |
| --- | --- | --- | --- |
| `active` | apply | apply | apply |
| `quarantined` | apply | apply | exact no-op |
| `revoked` | reject | exact no-op | reject |
| `rotated` | exact linked retry only | reject | reject |

Exact no-ops do not increment generation or write another audit row. Rotation
atomically changes the old/new trust rows and the bound node pointer. Revoke and
quarantine disable the current bound node. Node removal revokes its unique Active
trust before deleting the registry row; ambiguous state fails closed. These
commands update only controller-local SQLite registry/trust state and audit. They
do not modify ocserv, restart services, disconnect users, or push config to
agents.

Run `ocfleet doctor --json` after lifecycle changes. The
`registry.endpoint_trust.bindings` check reports counts only for
`active_unbound`, `active_orphan`, `current_binding_mismatch`,
`inactive_current`, and `active_extra_for_node`; it does not expose raw node or
EndpointID values. `inactive_current` counts only enabled nodes, so disabled
revoked or quarantined lifecycle state and historical inactive tombstones are
valid. A legacy enrollment approval may leave Active unbound trust. It remains
rejected until `ocfleet enroll claim` verifies the exact approved request,
EndpointID, fingerprint, generation, lineage, trust bundle, and approval audit,
then binds explicit operator-owned node metadata in one transaction. Never bind
from agent hostname or labels, scan for candidates, or repair at startup.

Use a stable `--request-id join-<uuid>` when an enrollment submission may be
retried. Exact same-actor retries do not consume another token use. Revoke an
unused token with `ocfleet enroll token revoke` and close an unwanted pending
request with `ocfleet enroll request reject`; both require a reason and use
closed, atomically audited transitions. A changed actor, reason, or submission
input is not treated as an idempotent retry. Token plaintext/hash and submitted
key, fingerprint, hostname, and label values are excluded from audit detail and
secret-bearing `Debug` output.

## Audit And Observability

- Keep controller audit exports redacted by default.
- Keep agent audit primary log and spool on monitored storage.
- Treat `audit_dropped` or repeated audit write failures as operational incidents, because affected RPCs should fail closed when neither primary nor spool can record the event.
- Use `ocfleet-api` only as the experimental read-only API/dashboard surface.
  Keep it on loopback by default, require `--auth-token-file` for non-loopback
  listeners, and do not expose SQLite or audit files through ad hoc HTTP
  servers.
