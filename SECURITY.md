# Security Policy

## Supported Versions

This repository is a read-only MVP that currently includes the Phase 1 base RPCs,
Phase 10 enrollment/trust workflow, Phase 11 low-sensitive ocserv read-only
adapters, and Phase 12 scheduled observability. Security fixes are applied to
the current `main` branch and any explicitly maintained release branch.

| Version | Supported |
| ------- | --------- |
| `main` | Yes |
| Older snapshots | No |

No production support window is promised until a release policy is published.

## Reporting a Vulnerability

Use GitHub Security Advisories when available for private disclosure. If that is
not available, contact the maintainers through the project's private repository
or organization channel.

Do not disclose exploitable details in public issues before maintainers have had
time to triage and prepare a fix.

## Current Security Boundary

The agent is intentionally read-only. The allowed agent RPC methods are fixed:

- `node.ping`
- `node.info`
- `probe.controller.ping`
- `probe.peer.echo`
- `probe.path.echo`
- `ocserv.service.summary`
- `ocserv.version`
- `ocserv.sessions.summary`
- `ocserv.cert.expiry`
- `ocserv.config.fingerprint`

`node.info` may return only configuration/runtime identity fields:

- `node_id`
- `region`
- `role`
- `agent_version`
- `current_time_utc`
- `agent_endpoint_id`

It must not read host metadata such as `/etc/os-release`, `/proc`, kernel
details, hostnames, local users, process tables, logs, or raw ocserv runtime
state.

The ocserv methods are low-sensitive summaries only. They must not return raw
certificate content, raw config content, command output, local file paths, or
local operating-system error details.

## Read-Only API, Dashboard, and Collector

`ocfleet-api` exposes a `GET`-only observation surface. Loopback listeners may
support local operator use without a token; non-loopback startup requires a
private bearer-token file. The API and dashboard cannot trigger agent RPC,
scheduler work, trust/registry changes, retention changes, or alert mutations.

`ocfleet-ocserv-collector` is an operator-run local snapshot normalizer. It is
not callable through agent RPC, the controller, the scheduler, the API, or the
dashboard. Its output is the fixed low-sensitive aggregate snapshot schema; it
must not emit raw source material, user/session/network identifiers,
certificate identity, config, logs, command text, stdout, or stderr.

## Forbidden Capabilities

The agent must not expose generic local execution or raw local
inspection. In particular, these capabilities are out of scope:

- shell or arbitrary command execution
- raw file reads
- `shell.exec`
- `command.run`
- `occtl.raw`
- `journalctl.raw`
- `systemctl`, `occtl`, or `journalctl` adapters
- ocserv reload, restart, disconnect, user management, or configuration apply
- log scraping adapters
- raw certificate or config adapters
- TOFU or automatic active trust on first contact

Future local capabilities must be added only as fixed, narrowly typed RPC
methods with explicit authorization, tests, audit coverage, and documentation.

## Identity and Authorization

Request-body identity fields are never authentication sources. The agent must
derive caller identity from iroh connection metadata and compare it with the
configured controller EndpointID allowlist.

Controller and node EndpointIDs must parse as real iroh EndpointIDs before they
are accepted or persisted.

Enrollment tokens create pending join requests only. Approval is manual, audited,
and does not grant peer or path-probe authorization by itself.

Path probes require both source-side controller/target authorization and
peer allowlists. A path-probe target must be an enabled peer in the source
agent configuration.

Agent configuration files are security-sensitive because they define controller,
peer, and path-probe trust. On Unix, production config loading fails closed for
symlinks, hardlinks, non-regular files, group/world-writable config files, or
group/world-writable parent directories.

## Audit Policy

Controller business mutations and their success audit rows must commit in the
same database transaction. An audit insertion failure fails the mutation and
rolls back its business rows. Node lifecycle, scheduler job configuration, and
scheduler run start/outcome/finish transitions implement this contract through
actor-bearing `StoreWriter` transactions. Each bounded scheduler outcome pairs
its observations with RPC or scheduler audits; run finish updates the owning
job clock in the same transaction. No database transaction spans RPC or other
network I/O. A failed outcome or finish write leaves the committed `running`
row and unchanged job clock as an explicit incomplete-run marker rather than
claiming success. Health/alert/delivery, retention, and other remaining legacy
mutation families are tracked in
[#33](https://github.com/GentleKingson/ocserv-fleet-agent/issues/33) and must not
be described as fully atomic until migrated. Read-only command audits do not
have a paired business mutation and may use the standalone audit writer.

Agent audit records are security-relevant. The agent uses a bounded audit queue,
a dedicated writer thread, and a bounded local durability spool so disk I/O does
not block async RPC handling and temporary primary audit sink failures do not
silently lose events.

If both the primary audit sink and local durability spool fail, the RPC must fail
closed with a generic remote error. Local filesystem paths and operating-system
error details may be logged locally, but must not be returned to the remote
caller.

Operators should monitor audit spool growth, audit flush failures, and disk
capacity. A full or unavailable audit destination can make RPCs fail closed by
design.

## Endpoint Trust Gate

Controller and scheduler RPC paths require more than an Active
`endpoint_trust` row. The registry node must exist and be enabled, its current
EndpointID must be the EndpointID being contacted, the trust row must point back
to that node, and exactly one Active trust row may be bound to the node. Missing,
inactive, unbound, mismatched, stale, disabled, or ambiguous state is rejected
with bounded error metadata before controller key loading, connection setup, or
RPC dispatch.

Scheduler workers repeat the complete source and path-target binding snapshot
after concurrency waits. That lookup uses a separate read-only/query-only SQLite
connection, and no database transaction is held across network I/O. Protocol
responses remain `ENDPOINT_NOT_ALLOWED`; controller-local observations use fixed
codes including `ENDPOINT_TRUST_UNBOUND`, `ENDPOINT_TRUST_BINDING_MISMATCH`, and
their `TARGET_` variants.

Endpoint lifecycle is closed. Active trust may rotate, revoke, or quarantine;
quarantined trust may rotate or revoke; revoked trust is terminal; and a rotated
row accepts only an exact retry of its recorded successor. Exact no-ops do not
change generation, timestamps, trust bundles, or audit count. Rotation moves the
bound node pointer atomically. Revoke and quarantine disable the current bound
node, while node removal revokes its unique Active trust before deleting the
registry row. Contaminated or ambiguous state fails closed instead of selecting
a row implicitly.

Health computation is advisory and never creates trust. `ocfleet doctor` reports
aggregate-only `active_unbound`, `active_orphan`, `current_binding_mismatch`,
`inactive_current`, and `active_extra_for_node` counts. `inactive_current`
counts enabled nodes only; a deliberately disabled revoked or quarantined node
is valid. Historical inactive tombstones are allowed to outlive a removed node.
The legacy enrollment approval flow can leave an Active unbound row; it remains
rejected pending an explicit reconciliation workflow and is never bound from
agent-supplied hostname data.
This hardening changes no SQLite schema, RPC protocol, agent capability,
read-only HTTP API route, or default read-only behavior.

## CI Security Gates

GitHub Actions workflows must use least-privilege permissions. Pull request
workflows must not use `pull_request_target`, and checkout credentials must not
persist unless a workflow explicitly requires writes.

The Rust CI gate runs formatting, Clippy, tests, `cargo-deny`, and `cargo-audit`.
CodeQL runs separately with read-only repository permissions plus
`security-events: write` for uploading analysis results. GitHub Actions should
use least-privilege permissions, fixed tool versions, and full-length commit SHA
pinning for third-party actions where practical.

The controller mutation guard also rejects production calls that bypass the
reviewed `StoreWriter` boundary for node and endpoint lifecycle methods. Only the
SQLite store implementation and backend adapter may call those inherent
mutators directly; test-only and integration fixtures remain outside the
production scan.

The release workflow accepts only bounded version input, requires an existing
matching tag, verifies the compiled version of all four release binaries, and
creates a draft release with a combined `SHA256SUMS`. It does not create tags or
publish crates.io packages.
