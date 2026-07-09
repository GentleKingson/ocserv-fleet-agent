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

## CI Security Gates

GitHub Actions workflows must use least-privilege permissions. Pull request
workflows must not use `pull_request_target`, and checkout credentials must not
persist unless a workflow explicitly requires writes.

The Rust CI gate runs formatting, Clippy, tests, `cargo-deny`, and `cargo-audit`.
CodeQL runs separately with read-only repository permissions plus
`security-events: write` for uploading analysis results. GitHub Actions should
use least-privilege permissions, fixed tool versions, and full-length commit SHA
pinning for third-party actions where practical.
