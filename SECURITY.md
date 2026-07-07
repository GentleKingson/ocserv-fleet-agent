# Security Policy

## Supported Versions

This repository is a Phase 1 read-only MVP. Security fixes are applied to the
current `main` branch and any explicitly maintained Phase 1 release branch.

| Version | Supported |
| ------- | --------- |
| `main` / Phase 1 | Yes |
| Older snapshots | No |

No production support window is promised until a release policy is published.

## Reporting a Vulnerability

Private disclosure contact: TODO before any public production release.

Until a private intake channel is published, do not disclose exploitable details
in public issues. Contact the maintainers through the project's private
repository or organization channel.

## Phase 1 Security Boundary

Phase 1 is intentionally read-only. The only allowed agent RPC methods are:

- `node.ping`
- `node.info`

`node.info` may return only configuration/runtime identity fields:

- `node_id`
- `region`
- `role`
- `agent_version`
- `current_time_utc`
- `agent_endpoint_id`

It must not read host metadata such as `/etc/os-release`, `/proc`, kernel
details, hostnames, local users, process tables, logs, or ocserv runtime state.

## Forbidden Capabilities

The Phase 1 agent must not expose generic local execution or raw local
inspection. In particular, these capabilities are out of scope:

- shell or arbitrary command execution
- raw file reads
- `shell.exec`
- `command.run`
- `occtl.raw`
- `journalctl.raw`
- `systemctl`, `occtl`, or `journalctl` adapters
- ocserv reload, restart, disconnect, user management, or configuration apply
- certificate, config-summary, or log scraping adapters
- enrollment tokens, TOFU, or automatic node registration

Future local capabilities must be added only as fixed, narrowly typed RPC
methods with explicit authorization, tests, audit coverage, and documentation.

## Identity and Authorization

Request-body identity fields are never authentication sources. The agent must
derive caller identity from iroh connection metadata and compare it with the
configured controller EndpointID allowlist.

Controller and node EndpointIDs must parse as real iroh EndpointIDs before they
are accepted or persisted.

## Audit Policy

Agent audit records are security-relevant. The agent uses a bounded audit queue,
a dedicated writer thread, and a bounded local durability spool so disk I/O does
not block async RPC handling and temporary primary audit sink failures do not
silently lose events.

If both the primary audit sink and local durability spool fail, the RPC must fail
closed with a generic remote error. Local filesystem paths and operating-system
error details may be logged locally, but must not be returned to the remote
caller.

## CI Security Gates

GitHub Actions workflows must use least-privilege permissions. Pull request
workflows must not use `pull_request_target`, and checkout credentials must not
persist unless a workflow explicitly requires writes.

The Rust CI gate runs formatting, Clippy, tests, `cargo-deny`, and `cargo-audit`.
CodeQL runs separately with read-only repository permissions plus
`security-events: write` for uploading analysis results.
