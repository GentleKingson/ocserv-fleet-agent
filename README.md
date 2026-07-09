# ocfleet

Read-only Rust control plane for ocserv fleets, with iroh EndpointID trust, a SQLite-backed CLI controller, and audited node agents.

## Status

`ocfleet` is a read-only ocserv fleet observability/control-plane project. The
current source tree is beyond the initial MVP slice, but it is still not
production-complete.

- Phase 10 enrollment/trust is implemented.
- Phase 11 ocserv low-sensitive read-only RPCs are implemented.
- Phase 12 CLI observability is partially implemented / active implementation.
- Web/API dashboard is experimentally implemented as a read-only observation surface.
- The project is not production-complete.

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
- Supports Phase 12 CLI observability partially:
  - `ocfleet schedule` for controller-local observation jobs using fixed job
    kinds: `controller-ping`, `ocserv-status`, `ocserv-cert`,
    `ocserv-sessions`, and `path-probe`; current query surfaces include job
    show/validate, targeted `run --once --job-id <job-id>`, run list/show, and
    JSON status output
  - `ocfleet observation` list/show queries for bounded low-sensitive stored
    observations
  - `ocfleet health` summaries, node health views, and local health policy
    thresholds derived from stored observations; `health snapshot list` reports
    the latest stored snapshot per node
  - `ocfleet alert` filtered list, silence, resolve, test, private
    `jsonl_file` delivery, and explicitly configured HTTPS webhook delivery for
    bounded low-sensitive alert events
  - `ocfleet retention` policy, dry-run explanation, and pruning for
    observability history tables
  - `ocfleet audit export` for bounded redacted JSONL controller audit windows
- Supports experimental read-only `ocfleet-api` / Web dashboard access for
  health snapshots, jobs, runs, observations, alerts, and bounded redacted audit
  export views.
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
- Web/API endpoints that trigger agent RPCs, run scheduler jobs, resolve or
  silence alerts, mutate retention policy, modify trust, or change node state

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

Optionally start the experimental read-only API/dashboard against an existing
controller database:

```bash
target/debug/ocfleet-api \
  --database controller.sqlite \
  --read-only \
  --listen 127.0.0.1:8080
```

The API opens SQLite in read-only mode and serves only `GET` observation routes.
Non-loopback listeners require `--auth-token-file`.

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

install -m 0600 /dev/null ./enrollment.token
# Put the plaintext token printed above into ./enrollment.token, then run:
target/debug/ocfleet enroll request create \
  --token-file ./enrollment.token \
  --agent-public-key <agent-public-key> \
  --fingerprint <agent-fingerprint> \
  --requested-endpoint-id <agent_endpoint_id> \
  --hostname hk-ocserv-01 \
  --agent-version 0.1.0

target/debug/ocfleet enroll approve <join-request-id> \
  --endpoint-id <agent_endpoint_id> \
  --reason "ticket-123"
```

Enrollment tokens only create pending join requests. Agents do not receive
peer or path-probe authorization until approval.
Avoid passing enrollment tokens as command-line arguments; use `--token-file` or
`--token-stdin` so the token is less likely to leak through shell history,
process listings, or audit collection.

Call the Phase 1 RPCs:

```bash
target/debug/ocfleet ping hk-ocserv-01
target/debug/ocfleet node info hk-ocserv-01
target/debug/ocfleet probe ping hk-ocserv-01
```

Call a one-hop controller-orchestrated path probe only after the source agent explicitly authorizes the controller/target pair in `security.path_probes`, the source agent lists the target as an enabled `security.peers` entry, and the target agent explicitly allowlists the source in `security.peers`:

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
target/debug/ocfleet ocserv status hk-ocserv-01 --json
target/debug/ocfleet ocserv cert hk-ocserv-01
target/debug/ocfleet ocserv cert hk-ocserv-01 --json
target/debug/ocfleet ocserv sessions summary hk-ocserv-01
target/debug/ocfleet ocserv sessions summary hk-ocserv-01 --json
```

Agent-side deployable example:

```toml
[ocserv_readonly]
enabled = true
provider = "snapshot"
snapshot_path = "/var/lib/ocfleet-agent/ocserv-readonly.json"

[ocserv_readonly.config_fingerprint]
name = "main"
config_path = "/etc/ocserv/ocserv.conf"

[[ocserv_readonly.certificates]]
name = "server"
cert_path = "/etc/ocserv/server-cert.pem"
```

Snapshot document example:

```json
{
  "service": {
    "state": "running",
    "enabled": "enabled",
    "since": "2026-07-07T12:00:00Z"
  },
  "version": "1.3.0",
  "sessions": {
    "total": 12
  },
  "collected_at": "2026-07-07T12:00:00Z"
}
```

With `provider = "snapshot"`, service summary, version, and session summary are
read from the fixed local snapshot document. Certificate expiry and config
fingerprint are collected from fixed local paths declared in the agent config.
For richer low-sensitive live metadata, agents can use
`provider = "collector_snapshot"` with a fixed v2 JSON snapshot file; see
[`docs/ocserv-live-readonly-provider.md`](docs/ocserv-live-readonly-provider.md).
The controller cannot supply paths, commands, service names, unit names, or
journal selectors. Human output shortens fingerprints; use `--json` for the full
typed SHA-256 values.
On Unix, snapshot files must be private to owner and all ocserv provider files
must be regular, single-link files owned by root or the agent user and not
group/world writable.

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

Use the Phase 12 CLI observability surface:

```bash
target/debug/ocfleet schedule job add \
  --kind controller-ping \
  --selector node_id=hk-ocserv-01 \
  --interval 60s

target/debug/ocfleet schedule job add \
  --kind path-probe \
  --source-node-id source-ocserv-01 \
  --target-node-id target-ocserv-01 \
  --interval 300s

target/debug/ocfleet schedule job list
target/debug/ocfleet schedule job show <job-id> --json
target/debug/ocfleet schedule job validate <job-id> --json
target/debug/ocfleet schedule run --once
target/debug/ocfleet schedule run --once --job-id <job-id> --json
target/debug/ocfleet schedule run list --limit 50 --json
target/debug/ocfleet schedule status
target/debug/ocfleet schedule status --json
target/debug/ocfleet observation list \
  --node hk-ocserv-01 \
  --method probe.controller.ping \
  --limit 50 \
  --json
target/debug/ocfleet health summary
target/debug/ocfleet health snapshot list --limit 50 --json
target/debug/ocfleet alert list
target/debug/ocfleet alert list --state open --severity critical --json
target/debug/ocfleet alert hook add-webhook \
  --name ops-alerts \
  --url https://alerts.example.com/ocfleet \
  --hmac-secret-file ./webhook.secret \
  --host-allow alerts.example.com
target/debug/ocfleet alert hook list --json
target/debug/ocfleet alert deliver --hook webhook:<hook-id> --limit 100 --dry-run
target/debug/ocfleet retention show
target/debug/ocfleet retention explain --scope observations --json
target/debug/ocfleet audit export \
  --from 2026-07-01T00:00:00Z \
  --to 2026-07-08T00:00:00Z \
  --format jsonl \
  --output ./audit-export.jsonl
```

These commands operate inside the controller boundary. Scheduler jobs use only
fixed job kinds; non-path jobs target `role=<role>` or `node_id=<node-id>`
selectors, and path jobs require an explicit source/target node pair. Health,
alerts, retention, and audit export use controller SQLite state and bounded
low-sensitive summaries. Webhook alert hooks require explicit HTTPS endpoints,
host allowlists, private HMAC secret files, bounded retries, and no redirect
following.

The historical Phase 7 ocserv-aware read-only document remains as the
conservative pre-Phase-11 boundary record. The implemented ocserv-aware surface is
now the Phase 11 fixed read-only RPC contract. See
[`docs/direction-two-phase-7-ocserv-aware-readonly.md`](docs/direction-two-phase-7-ocserv-aware-readonly.md)
and [`docs/ocserv-readonly-spec.md`](docs/ocserv-readonly-spec.md).

Networking must allow the controller to reach the agent through iroh using the registered EndpointID.

## Repository Layout

- `crates/ocfleet-protocol`: protocol version, RPC envelope, frames, methods, and error codes.
- `crates/ocfleet-config`: static TOML config loading and validation.
- `crates/ocfleet-agent`: node-side agent, iroh server, allowlist, RPC handling, nonce checks, and JSONL audit.
- `crates/ocfleet-cli`: controller CLI, SQLite state, controller audit, and RPC client.
- `docs/install.md`: install, upgrade, SecretKey, systemd, and smoke-test guide.
- `docs/troubleshooting.md`: operational failure modes and `ocfleet doctor` interpretation.
- `docs/release-notes/v0.1.0.md`: v0.1.0 release notes and known limitations.
- `docs/status.md`: implementation status by feature and CLI surface.
- `docs/roadmap.md`: forward roadmap from the current documentation baseline.
- `docs/alert-webhook.md`: HTTPS webhook alert delivery security model and HMAC contract.
- `docs/phase-10-enrollment-trust.md`: Phase 10 onboarding and trust lifecycle guide.
- `docs/ocserv-readonly-spec.md`: Phase 11 ocserv read-only RPC contract.
- `docs/phase-12-scheduled-observability.md`: Phase 12 CLI observability and read-only API/dashboard status.
- `docs/api.md`: experimental read-only HTTP API routes, auth, and redaction rules.
- `docs/dashboard.md`: experimental static dashboard behavior and limits.

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
