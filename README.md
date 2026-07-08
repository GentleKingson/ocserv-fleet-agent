# ocfleet

Read-only Rust control plane for ocserv fleets, with iroh EndpointID trust, a SQLite-backed CLI controller, and audited node agents.

## Status

`ocfleet` is currently a read-only MVP vertical slice. It is useful for validating the management channel, identity model, controller state, agent audit path, basic node discovery RPCs, and fixed Direction-Two probe RPCs.

It is not a production-complete ocserv management platform yet.

## What It Does

- Runs `ocfleet-agent` on each ocserv node.
- Uses the `ocfleet` CLI as the controller.
- Stores controller node registry and audit records in local SQLite.
- Uses persistent iroh SecretKeys so agent and controller EndpointIDs stay stable.
- Requires explicit bidirectional trust:
  - the controller registers the agent EndpointID.
  - the agent allowlists trusted controller EndpointIDs.
- Supports Phase 10 enrollment and trust management:
  - one-time enrollment tokens stored as hashes.
  - pending join requests with manual approval.
  - EndpointID rotate, revoke, and quarantine lifecycle states.
  - controller-side trust diff reporting.
- Supports Phase 11 fixed low-sensitive ocserv read-only RPCs:
  - service summary
  - version
  - sessions summary
  - certificate expiry
  - config fingerprint
- Supports fixed RPC methods:
  - `node.ping`
  - `node.info`
  - `probe.controller.ping`
  - `probe.peer.echo`
  - `probe.path.echo`
- Writes audit records for successful, failed, and rejected RPC paths.
- Falls back to an append-only agent audit spool when the primary audit log is temporarily unavailable.

## What It Does Not Do

The current implementation is intentionally narrow. It does not provide:

- shell or arbitrary command execution
- raw file reads
- ocserv reload or restart
- configuration apply, rollback, or distribution
- user disconnect or user management
- generic agent-to-agent payloads, relay probes, mesh discovery, or multi-hop path probes
- `systemctl`, `occtl`, or `journalctl` passthrough adapters
- certificate or config content output
- automatic active trust on first contact or TOFU registration

All local capabilities must be exposed through fixed RPC methods. There is no `shell.exec`, `command.run`, `occtl.raw`, `journalctl.raw`, or equivalent generic execution interface.

## Quick Start

Build the workspace:

```bash
cargo build --workspace
```

Initialize the controller:

```bash
target/debug/ocfleet init
```

This creates or reuses:

- `controller.secret`
- `controller.sqlite`

It also prints the controller EndpointID:

```text
controller_endpoint_id=<controller_endpoint_id>
```

Run read-only diagnostics:

```bash
target/debug/ocfleet doctor
target/debug/ocfleet doctor --json
```

Create an agent config:

```toml
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "./agent-state/iroh.secret"

[audit]
path = "./agent-logs/audit.log"

[security]

[[security.controllers]]
endpoint_id = "<controller_endpoint_id>"
role = "viewer"
```

Start the agent:

```bash
target/debug/ocfleet-agent --config ./agent.toml
```

The agent prints its EndpointID and a suggested join command:

```text
agent_endpoint_id=<agent_endpoint_id>
join_command=ocfleet node add hk-ocserv-01 --endpoint-id <agent_endpoint_id> --region hk --role ocserv
```

Register the agent in the controller database:

```bash
target/debug/ocfleet node add hk-ocserv-01 \
  --endpoint-id <agent_endpoint_id> \
  --region hk \
  --role ocserv
```

Or use the Phase 10 approval flow:

```bash
target/debug/ocfleet enroll token create \
  --ttl 24h \
  --max-uses 1 \
  --description "prod node onboarding"

target/debug/ocfleet enroll request create \
  --token <plaintext-token> \
  --agent-public-key <agent-public-key> \
  --fingerprint <agent-fingerprint> \
  --hostname hk-ocserv-01 \
  --agent-version 0.1.0

target/debug/ocfleet enroll approve <join-request-id> \
  --endpoint-id <agent_endpoint_id> \
  --reason "ticket-123"
```

Enrollment tokens only create pending join requests. Agents do not receive
peer or path-probe authorization until approval.

Call the Phase 1 RPCs:

```bash
target/debug/ocfleet ping hk-ocserv-01
target/debug/ocfleet node info hk-ocserv-01
target/debug/ocfleet probe ping hk-ocserv-01
```

Call a one-hop controller-orchestrated path probe only after the source agent explicitly authorizes the controller/target pair in `security.path_probes` and the target agent explicitly allowlists the source in `security.peers`:

```bash
target/debug/ocfleet probe path source-ocserv-01 target-ocserv-01
```

Print a read-only Direction-Two path observation summary from the controller registry without running a probe:

```bash
target/debug/ocfleet probe summary source-ocserv-01 target-ocserv-01
```

The summary is inventory/UX only. It does not authorize path probing, modify trust configuration, contact agents, or infer `security.path_probes` / `security.peers`.

Print a read-only topology observation summary from the controller registry without discovery or probing:

```bash
target/debug/ocfleet probe topology
```

The topology summary groups existing registry nodes by region and role. It does not discover topology, infer trust, generate peer/path configuration, or contact agents.

Print recent explicit probe RPC history from existing controller audit records without running probes:

```bash
target/debug/ocfleet probe history
target/debug/ocfleet probe history source-ocserv-01
```

Probe history is read-only audit observation. It does not schedule probes, compute behavior-affecting health scores, contact agents, or modify controller state beyond the local read audit entry.

Print a read-only route/path observation from the controller registry and existing path-probe audit history without running a probe:

```bash
target/debug/ocfleet probe observe source-ocserv-01 target-ocserv-01
```

Path observation reports registry status and the most recent matching `probe.path.echo` audit result when one exists. It does not perform route discovery, traceroute, network probing, forwarding, relay, mesh, or multi-hop analysis.

Call the Phase 11 low-sensitive ocserv read-only RPCs:

```bash
target/debug/ocfleet ocserv status hk-ocserv-01
target/debug/ocfleet ocserv cert hk-ocserv-01
target/debug/ocfleet ocserv sessions summary hk-ocserv-01
```

Phase 11 uses fixed RPC methods only. It does not add shell execution, raw
command execution, raw file read RPCs, service reload/restart, session details,
or `systemctl` / `occtl` / `journalctl` passthrough output. See
[`docs/ocserv-readonly-spec.md`](docs/ocserv-readonly-spec.md).

Inspect controller trust drift:

```bash
target/debug/ocfleet trust diff
target/debug/ocfleet trust diff --endpoint <endpoint-id>
target/debug/ocfleet trust diff --endpoint <endpoint-id> --format json
target/debug/ocfleet trust diff --strict
```

Manage EndpointID lifecycle:

```bash
target/debug/ocfleet endpoint rotate <old-endpoint-id> \
  --new-endpoint-id <new-endpoint-id> \
  --reason "key rotation"

target/debug/ocfleet endpoint revoke <endpoint-id> --reason "lost host"
target/debug/ocfleet endpoint quarantine <endpoint-id> --reason "suspicious traffic"
```

Rotated, revoked, and quarantined endpoints are rejected for normal controller
RPC and path-probe authorization. These lifecycle commands are registry/trust
operations only; they do not add diagnostic shell or service-control entry
points.

Phase 7 ocserv-aware read-only checks remain reserved because the current codebase has no approved safe fixed ocserv metadata source. See [`docs/direction-two-phase-7-ocserv-aware-readonly.md`](docs/direction-two-phase-7-ocserv-aware-readonly.md).

Networking must allow the controller to reach the agent through iroh using the registered EndpointID.

## Repository Layout

- `crates/ocfleet-protocol`: protocol version, RPC envelope, frames, methods, and error codes.
- `crates/ocfleet-config`: static TOML config loading and validation.
- `crates/ocfleet-agent`: node-side agent, iroh server, allowlist, RPC handling, nonce checks, and JSONL audit.
- `crates/ocfleet-cli`: controller CLI, SQLite state, controller audit, and RPC client.
- `docs/install.md`: install, upgrade, SecretKey, systemd, and smoke-test guide.
- `docs/troubleshooting.md`: operational failure modes and `ocfleet doctor` interpretation.
- `docs/release-notes/v0.1.0.md`: v0.1.0 release notes and known limitations.
- `docs/phase-10-enrollment-trust.md`: Phase 10 onboarding and trust lifecycle guide.
- `docs/ocserv-readonly-spec.md`: Phase 11 ocserv read-only RPC contract.

## Security Notes

- Request-body identity fields are not authentication sources.
- Caller identity comes from iroh connection metadata: the remote EndpointID.
- SecretKey, SQLite, and agent audit files are expected to be private on Unix systems.
- Unsafe existing sensitive files fail closed instead of being automatically chmodded.
- Resource limits protect handshake tasks, connections, streams, nonce cache size, and repeated rejection audit logs.
- Agent audit durability metrics are written to the configured metrics path. The default runtime path is derived from `audit.path`.

## Development

Run the standard checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -j1 -- --test-threads=1
```

Docker can be used when the local Rust toolchain is unavailable:

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  -w /workspace \
  rust:1.96 \
  cargo test --workspace -j1 -- --test-threads=1
```

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT license
