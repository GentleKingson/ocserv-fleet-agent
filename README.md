# ocfleet

Read-only Rust control plane for ocserv fleets, with iroh EndpointID trust, a SQLite-backed CLI controller, and audited node agents.

## Status

`ocfleet` is currently a Phase 1 read-only MVP vertical slice. It is useful for validating the management channel, identity model, controller state, agent audit path, and basic node discovery RPCs.

It is not a production-complete ocserv management platform yet.

## What It Does

- Runs `ocfleet-agent` on each ocserv node.
- Uses the `ocfleet` CLI as the controller.
- Stores controller node registry and audit records in local SQLite.
- Uses persistent iroh SecretKeys so agent and controller EndpointIDs stay stable.
- Requires explicit bidirectional trust:
  - the controller registers the agent EndpointID.
  - the agent allowlists trusted controller EndpointIDs.
- Supports Phase 1 RPC methods:
  - `node.ping`
  - `node.info`
- Writes audit records for successful, failed, and rejected RPC paths.

## What It Does Not Do

Phase 1 is intentionally narrow. It does not provide:

- shell or arbitrary command execution
- raw file reads
- ocserv reload or restart
- configuration apply, rollback, or distribution
- user disconnect or user management
- `systemctl`, `occtl`, `journalctl`, certificate, or config-summary adapters
- enrollment tokens, TOFU, or automatic node registration

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

Call the Phase 1 RPCs:

```bash
target/debug/ocfleet ping hk-ocserv-01
target/debug/ocfleet node info hk-ocserv-01
```

Networking must allow the controller to reach the agent through iroh using the registered EndpointID.

## Repository Layout

- `crates/ocfleet-protocol`: protocol version, RPC envelope, frames, methods, and error codes.
- `crates/ocfleet-config`: static TOML config loading and validation.
- `crates/ocfleet-agent`: node-side agent, iroh server, allowlist, RPC handling, nonce checks, and JSONL audit.
- `crates/ocfleet-cli`: controller CLI, SQLite state, controller audit, and RPC client.

## Security Notes

- Request-body identity fields are not authentication sources.
- Caller identity comes from iroh connection metadata: the remote EndpointID.
- SecretKey, SQLite, and agent audit files are expected to be private on Unix systems.
- Unsafe existing sensitive files fail closed instead of being automatically chmodded.
- Resource limits protect handshake tasks, connections, streams, nonce cache size, and repeated rejection audit logs.

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
