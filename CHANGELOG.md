# Changelog

## Unreleased

- No unreleased changes yet.

## v0.1.0 - 2026-07-07

- Ships the read-only MVP controller CLI and node agent.
- Adds fixed RPCs for `node.ping`, `node.info`, `probe.controller.ping`, `probe.peer.echo`, and `probe.path.echo`.
- Stores controller registry and controller audit records in SQLite.
- Uses persistent iroh SecretKeys and EndpointID allowlists.
- Adds `ocfleet doctor` with human and JSON output for read-only controller diagnostics.
- Adds durable agent audit fallback with append-only spool replay and metrics snapshots.
- Adds local E2E coverage for controller-to-agent, one-hop source-to-target path probes, EndpointID mismatch, nonce replay, expired requests, unknown peers, and missing path authorization.
- Adds install, troubleshooting, release notes, and repeatable release checksum scripts.
