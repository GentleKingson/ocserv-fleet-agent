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
- Governance foundation work has started: actor identity, trust policy
  validation/diff, and optional signed audit export are implemented.
- Production hardening is active: enrollment approval/legacy claim, node
  lifecycle, enrollment token/request transitions, retention, scheduler job
  configuration, scheduler run/outcome/observation/job-clock writes, health
  snapshot batches, and alert candidate evaluation use actor-bearing
  `StoreWriter` transactions for state and audit. Alert silence/resolve and
  webhook-hook creation also use compare-before or replay-safe atomic writers.
  Webhook attempts each commit with their audit, and successful delivery
  finalization atomically updates all `last_sent_at` values with its summary
  audit. The A1 production controller-mutation inventory is complete and
  guarded; fixture-only raw helpers are unreachable from production dispatch.
- Controller dispatch requires an enabled node and one Active trust row bound
  bidirectionally to that node. Active status by itself is not authorization;
  scheduler workers repeat the same binding check after concurrency waits.
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
  - pending join requests with manual, operator-owned node binding at approval.
  - explicit strict repair for legacy approved-unbound enrollment rows.
  - EndpointID rotate, revoke, and quarantine lifecycle states.
  - closed lifecycle transitions that keep the node registry and its unique
    Active EndpointID binding consistent.
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
    JSON status output. Job configuration and each scheduler run start, bounded
    outcome, and run finish bind the resolved actor and commit their state with
    the matching audit in one SQLite transaction. Run finish commits the job
    clock at the same boundary.
  - `ocfleet observation` list/show queries for bounded low-sensitive stored
    observations
  - `ocfleet health` summaries, node health views, and local health policy
    thresholds derived from stored observations; snapshot batches and their
    evaluation audit commit atomically, and `health snapshot list` reports the
    latest stored snapshot per node
  - `ocfleet alert` atomically persists bounded candidate batches with
    compare-before conflict checks, plus filtered list, silence, resolve, test, private
    `jsonl_file` delivery, and explicitly configured HTTPS webhook delivery for
    bounded low-sensitive alert events
  - `ocfleet retention` policy, dry-run explanation, and pruning for
    observability history tables
  - `ocfleet audit export` for bounded redacted JSONL controller audit windows
    with optional checksum and Ed25519 signature sidecars
- Supports experimental read-only `ocfleet-api` / Web dashboard access for
  health snapshots, jobs, runs, observations, alerts, and bounded redacted audit
  export views.
- Supports a local `ocfleet-ocserv-collector` snapshot normalizer for
  operator-managed low-sensitive ocserv aggregate metadata consumed by the
  agent `collector_snapshot` provider.
- Supports governance foundation commands:
  - `--actor` and `OCFLEET_ACTOR` for consistent controller audit identity
  - `ocfleet trust policy validate <file>` for TOML/YAML policy schema checks
  - `ocfleet trust policy diff <file>` for advisory registry/trust drift review
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
- a Postgres controller backend; SQLite remains the implemented backend, while
  Postgres is an optional future design track

All local capabilities must be exposed through fixed RPC methods. There is no `shell.exec`, `command.run`, `occtl.raw`, `journalctl.raw`, or equivalent generic execution interface.

## Quick Start

Build the workspace:

```bash
cargo build --workspace
```

Initialize the controller:

```bash
target/debug/ocfleet --actor alice@example.com init
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

Optionally generate a local ocserv metadata collector config and write a private
snapshot for the agent `collector_snapshot` provider:

```bash
umask 077
install -d -m 0700 ./agent-state
target/debug/ocfleet-ocserv-collector --print-example-config > ./ocserv-collector.toml
chmod 0600 ./ocserv-collector.toml

# Set collected_at to the producer time for the exact aggregate values before
# the real write. Collector reruns preserve it and cannot refresh stale data.

target/debug/ocfleet-ocserv-collector \
  --check \
  --config ./ocserv-collector.toml \
  --output ./agent-state/ocserv-live-snapshot.json

target/debug/ocfleet-ocserv-collector \
  --config ./ocserv-collector.toml \
  --output ./agent-state/ocserv-live-snapshot.json
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

Phase 10 approval is an alternative to the manual bound `node add` path:

```bash
target/debug/ocfleet enroll token create \
  --ttl 24h \
  --max-uses 1 \
  --description "prod node onboarding"

install -m 0600 /dev/null ./enrollment.token
# Put the plaintext token printed above into ./enrollment.token, then run:
target/debug/ocfleet enroll request create \
  --request-id join-<uuid> \
  --token-file ./enrollment.token \
  --agent-public-key <agent-public-key> \
  --fingerprint <agent-fingerprint> \
  --requested-endpoint-id <agent_endpoint_id> \
  --hostname hk-ocserv-01 \
  --agent-version 0.2.0

target/debug/ocfleet enroll approve <join-request-id> \
  --endpoint-id <agent_endpoint_id> \
  --node-id hk-ocserv-01 \
  --region hk \
  --role ocserv \
  --reason "ticket-123"

# Alternatively, close a pending request and revoke an unused token:
target/debug/ocfleet enroll request reject <join-request-id> \
  --reason "identity mismatch"
target/debug/ocfleet enroll token revoke <token-id> \
  --reason "onboarding cancelled"
```

Enrollment tokens only create pending join requests. Approval uses the resolved
operator actor and explicit node metadata to insert the registry node, bound
generation-1 trust row, request decision, and audit event in one transaction.
It never derives controller identity from the submitted hostname or labels.
`--request-id` is optional and defaults to a generated `join-<uuid>`. Replaying
the exact request with the same actor neither consumes another token use nor
writes another success audit. Token use, expiry, revocation, and request
decisions commit with their low-sensitive audit in one transaction; divergent
terminal retries fail closed.

Rows approved by older binaries remain unbound and rejected for dispatch. Repair
one only by naming its exact approved request and assigned EndpointID:

```bash
target/debug/ocfleet enroll claim <join-request-id> \
  --endpoint-id <agent_endpoint_id> \
  --node-id hk-ocserv-01 \
  --region hk \
  --role ocserv \
  --reason "ticket-123 legacy binding"
```

Claim rejects ambiguous, modified, advanced, or already differently bound state;
there is no hostname-based adoption, startup repair, or trust-on-first-use path.
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

Missing, rotated, revoked, and quarantined endpoint-trust records are rejected
before normal controller RPC or path-probe network I/O. Only an explicit active
trust row authorizes the controller to contact the registered EndpointID.
Scheduler workers recheck source and path-target trust after concurrency waits,
and rejected methods write bounded RPC audits. `ocfleet doctor` reports any
node without a trust row. These lifecycle commands are registry/trust operations
only; they do not add diagnostic shell or service-control entry points.

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
target/debug/ocfleet schedule job disable <job-id>
target/debug/ocfleet schedule job enable <job-id>
target/debug/ocfleet schedule run --once
target/debug/ocfleet schedule run --once --job-id <job-id> --json
target/debug/ocfleet schedule run list --limit 50 --json
target/debug/ocfleet schedule maintenance set \
  --from 2026-07-12T01:00:00Z \
  --to 2026-07-12T02:00:00Z \
  --reason "planned controller maintenance"
target/debug/ocfleet schedule maintenance show --json
target/debug/ocfleet schedule maintenance clear
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
target/debug/ocfleet retention apply \
  --scope observations \
  --before 2026-07-01T00:00:00Z \
  --operation-id retention-<uuid> \
  --limit 10000 \
  --batch-size 1000 \
  --json
target/debug/ocfleet audit export \
  --from 2026-07-01T00:00:00Z \
  --to 2026-07-08T00:00:00Z \
  --format jsonl \
  --output ./audit-export.jsonl \
  --include-checksum
target/debug/ocfleet trust policy validate ./trust-policy.toml --json
target/debug/ocfleet trust policy validate ./trust-policy.yaml --json
target/debug/ocfleet trust policy diff ./trust-policy.toml --json
install -d -m 0700 ./trust-policy-review
target/debug/ocfleet trust policy diff ./trust-policy.toml \
  --format markdown --output ./trust-policy-review/trust-policy-diff.md
```

These commands operate inside the controller boundary. Scheduler jobs use only
fixed job kinds; non-path jobs target `role=<role>` or `node_id=<node-id>`
selectors, and path jobs require an explicit source/target node pair. Scheduler
job configuration, run starts, bounded outcomes, observations, RPC audits, run
finishes, and job clocks use actor-bound atomic writer boundaries. No database
transaction remains open across an RPC or semaphore wait. Health, alerts,
retention, and audit export use controller SQLite state and bounded
low-sensitive summaries.
Retention `explain` and `apply --dry-run` are query-only. Policy changes and
non-dry-run applies use actor-bound transactions; every scope's bounded batches
commit with its audit or roll back. Supply a stable `--operation-id` when an
apply may be retried; exact replays return the original report without deleting
again. The CLI generates and prints an operation ID when it is omitted.
Before any manual or scheduled RPC, the controller requires the registry node to
be enabled, to point to the requested EndpointID, and to have exactly one Active
trust row pointing back to that node. Source and path-target bindings are checked
again after scheduler concurrency waits. Missing, inactive, unbound, mismatched,
or ambiguous trust fails closed with protocol-level `ENDPOINT_NOT_ALLOWED`.
This hardening does not change the SQLite schema, RPC protocol, agent method
allowlist, read-only HTTP API, or default read-only product boundary.
Webhook alert hooks require explicit HTTPS endpoints, host allowlists, private
HMAC secret files, bounded retries, and no redirect following.

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
- `docs/release-notes/v0.2.0.md`: v0.2.0 read-only release-candidate notes and known limitations.
- `docs/release-notes/v0.1.0.md`: v0.1.0 release notes and known limitations.
- `docs/status.md`: implementation status by feature and CLI surface.
- `docs/roadmap.md`: historical Phase 12 staging roadmap.
- `docs/alert-webhook.md`: HTTPS webhook alert delivery security model and HMAC contract.
- `docs/phase-10-enrollment-trust.md`: Phase 10 onboarding and trust lifecycle guide.
- `docs/ocserv-readonly-spec.md`: Phase 11 ocserv read-only RPC contract.
- `docs/phase-12-scheduled-observability.md`: Phase 12 CLI observability and read-only API/dashboard status.
- `docs/api.md`: experimental read-only HTTP API routes, auth, and redaction rules.
- `docs/dashboard.md`: experimental static dashboard behavior and limits.
- `docs/governance.md`: operator identity, RBAC roles, audit model, and trust policy workflow.
- `docs/next-roadmap.md`: authoritative implementation DAG, milestone issues,
  dependencies, acceptance gates, and completion evidence.
- `docs/a1-mutation-inventory.md`: A1 controller writer, failure-injection, and
  static-enforcement completion inventory.
- `docs/adr/ADR-atomic-audit-writes.md`: fail-closed controller mutation and
  audit transaction decision.
- `docs/adr/ADR-enrollment-transition-atomicity.md`: enrollment token/request
  transition, idempotency, and audit-provenance decision.
- `docs/adr/ADR-retention-apply-atomicity.md`: retention transaction, bounded
  batching, and durable replay decision.
- `docs/adr/ADR-derived-state-evaluation-atomicity.md`: atomic health snapshot
  batches and compare-before alert candidate evaluation.
- `docs/adr/ADR-alert-operator-transition-atomicity.md`: atomic alert operator
  state transitions and webhook-hook creation.
- `docs/adr/ADR-alert-delivery-persistence-atomicity.md`: durable delivery
  attempt and finalization boundaries around external I/O.
- `docs/adr/ADR-versioned-scheduler-storage.md`: schema-v9 scheduler selector
  and explicit-pair storage, migration, quarantine, and fail-closed decision.
- `docs/adr/ADR-versioned-health-snapshot-storage.md`: schema-v10 health
  snapshot storage, legacy canonicalization, and fail-closed reader decision.
- `docs/adr/ADR-versioned-observation-summary-storage.md`: schema-v11 closed
  observation summaries and method/result-class binding.
- `docs/adr/ADR-versioned-run-summary-storage.md`: schema-v12 closed run
  summaries and relational job/kind/status/trigger binding.
- `docs/adr/ADR-versioned-trust-bundle-storage.md`: schema-v13 closed trust
  bundles, bounded explicit allowlists, and relational lifecycle binding.
- `docs/adr/ADR-versioned-alert-detail-storage.md`: schema-v14 closed alert
  details, legacy canonicalization, and fail-closed reader behavior.
- `docs/adr/ADR-versioned-alert-host-allow-storage.md`: schema-v15 closed
  webhook host allowlists and endpoint-host relationship validation.
- `docs/adr/ADR-versioned-enrollment-metadata-storage.md`: schema-v16 closed
  kind-bound enrollment label and scope storage.
- `docs/adr/ADR-versioned-delivery-attempt-storage.md`: schema-v17 closed
  delivery-attempt details bound to relational history.
- `docs/adr/ADR-versioned-audit-detail-storage.md`: schema-v18 closed typed
  audit details bound to the complete relational record.
- `docs/adr/ADR-scheduler-job-claims.md`: schema-v19 deterministic scheduler
  claims, fencing, expiry, and abandoned-run recovery.
- `docs/adr/ADR-scheduler-maintenance-window.md`: schema-v20 audited global
  maintenance suppression without clock, selector, or trust mutation.
- `docs/adr/ADR-scheduler-graceful-shutdown.md`: SIGINT/SIGTERM admission stop,
  in-flight drain, claim release, and restart behavior.
- `docs/a2-storage-inventory.md`: A2 payload-family closure inventory and
  migration/read-boundary evidence.
- `docs/trust-policy.md`: trust policy as code schema, validation, and diff behavior.
- `docs/backend.md`: SQLite contract and optional Postgres backend plan.
- `docs/archive-export.md`: long-term history archive and signed audit export guidance.

## Security Notes

- Request-body identity fields are not authentication sources.
- Caller identity comes from iroh connection metadata: the remote EndpointID.
- SecretKey, SQLite, and agent audit files are expected to be private on Unix systems.
- Unsafe existing sensitive files fail closed instead of being automatically chmodded.
- Resource limits protect handshake tasks, connections, streams, nonce cache size, and repeated rejection audit logs.
- Endpoint lifecycle changes and node removal keep registry/trust state in one
  audited `StoreWriter` transaction. Exact lifecycle no-ops do not increment the
  trust generation or add an audit row.
- Agent audit durability metrics are written to the configured metrics path. The default runtime path is derived from `audit.path`.

## Development

Run the standard checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace -j1 -- --test-threads=1
cargo test --workspace --all-features -j1 -- --test-threads=1
bash scripts/check-doc-claims.sh
./scripts/tests/test-controller-mutation-guard.sh
./scripts/check-controller-mutations.sh
./scripts/check-github-actions-pinning.sh
./scripts/test-release-version-validation.sh
```

Docker can be used when the local Rust toolchain is unavailable:

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  -w /workspace \
  rust:1.96.1 \
  cargo test --workspace -j1 -- --test-threads=1
```

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT license
