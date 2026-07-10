# Troubleshooting

Run doctor before changing state:

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret doctor
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret doctor --json
```

Exit codes are stable:

- `0`: all doctor checks passed or warnings only.
- `1`: unhealthy state; at least one check is `error`.
- `2`: reserved for CLI usage or invocation failures.

JSON fields `status`, `exit_code`, `schema_version_expected`, `schema_version_actual`, `checks[].id`, `checks[].status`, and `checks[].details` are stable for scripts.

## Doctor Common Failures

### Symptoms

`doctor` exits `1`, or `doctor --json` reports one or more checks with `status="error"`.

### Common Causes

- Controller SQLite file is missing, unreadable, not private, or has unsafe WAL/SHM sidecars.
- Controller SecretKey is missing, invalid, symlinked, hardlinked, or group/world accessible.
- The recorded schema version is newer than this binary supports.
- A previous migration could not create its private backup or checksum.
- Registry rows contain invalid or duplicated EndpointIDs.
- `registry.endpoint_trust.bindings` reports Active unbound/orphan trust, a
  current node/trust pointer mismatch, an enabled node with an inactive current
  endpoint, or an extra Active binding.

### Verification Commands

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret doctor --json
ls -ld /var/lib/ocfleet-controller
ls -l /var/lib/ocfleet-controller/controller.sqlite /var/lib/ocfleet-controller/controller.secret
sqlite3 /var/lib/ocfleet-controller/controller.sqlite 'PRAGMA integrity_check;'
```

### Fix Steps

Fix permissions first; do not delete or rewrite state to make `doctor` pass:

```bash
chmod 0700 /var/lib/ocfleet-controller
chmod 0600 /var/lib/ocfleet-controller/controller.sqlite /var/lib/ocfleet-controller/controller.secret
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret doctor
```

If a migration backup failed, inspect disk space and parent directory permissions, then rerun the same binary. Restore from a verified backup only if the database itself is damaged.

### Endpoint Trust Binding Counts

The `registry.endpoint_trust.bindings` doctor check exposes only aggregate
counts:

- `active_unbound`: Active trust has no node binding.
- `active_orphan`: Active trust names a node that no longer exists.
- `current_binding_mismatch`: a node and its current trust row do not point to
  each other.
- `inactive_current`: an enabled node points to non-Active trust.
- `active_extra_for_node`: a node has another Active bound endpoint.

Disabled nodes may intentionally point to revoked or quarantined trust.
Historical inactive tombstones that outlive a node are also valid and are not
counted as Active orphans. Do not edit SQLite directly or bind from
agent-reported hostname to clear these counts. Preserve the database and audit
log, identify the last audited node/endpoint lifecycle operation, and use only
an allowed explicit transition. Legacy enrollment approvals can account for
`active_unbound`; there is currently no safe reconciliation command, and those
rows remain rejected for dispatch.

## EndpointID Mismatch

### Symptoms

`ocfleet ping <node>` or `ocfleet node info <node>` fails with `ENDPOINT_MISMATCH`, or the controller reports an actual remote EndpointID that differs from the registry.

### Common Causes

- The agent SecretKey was rotated or recreated.
- The controller registry has the wrong `endpoint_id`.
- A stale node entry points to another agent.

### Verification Commands

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret node list
journalctl -u ocfleet-agent -n 50 --no-pager | grep 'agent_endpoint_id='
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret doctor --json
```

### Fix Steps

If the running agent has a newly generated and reviewed replacement EndpointID
that is not already present in `endpoint_trust`, rotate from the registry's
current EndpointID so the trust rows and node pointer move atomically:

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret endpoint rotate "$OLD_ENDPOINT_ID" --new-endpoint-id "$AGENT_ENDPOINT_ID" --reason "approved key replacement"
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret doctor --json
```

Do not remove and re-add the same EndpointID. Removal revokes the unique Active
trust tombstone, and node add does not overwrite existing trust. For contaminated
or ambiguous bindings, preserve state and investigate the audit trail rather
than selecting a row manually.

An EndpointID already inserted by the legacy enrollment approval flow cannot be
used as a rotation destination because it already exists as Active unbound trust.
It remains rejected and awaits the explicit reconciliation follow-up.

### Logs And Metrics

- Controller audit: `event=rpc.completed`, `error_code=ENDPOINT_MISMATCH`.
- Error details: `expected_endpoint_id`, `actual_remote_endpoint_id`.
- Doctor checks: `registry.endpoint_id.parse`, `registry.peer_relationships`.

## Node Disabled Or `NODE_DISABLED`

### Symptoms

`ocfleet ping <node>`, ocserv read-only commands, or scheduled jobs skip a registry entry with `NODE_DISABLED`.

### Common Causes

- The node was intentionally disabled with `ocfleet node disable <node-id>`.
- A restored controller database contains older disabled state.
- The wrong node ID was selected by a scheduler selector.

### Verification Commands

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret node list
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret node info hk-ocserv-01
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret schedule job list
```

### Fix Steps

Re-enable only after confirming the EndpointID is still trusted and expected:

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret trust diff --format json
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret node enable hk-ocserv-01
```

`node enable` also requires a clean bidirectional binding and exactly one Active
trust row. If it rejects the node, use the doctor binding counts and lifecycle
audit trail; do not bypass the check with direct SQL.

### Logs And Metrics

- Controller audit: `event=node.enable`, `event=node.disable`, or `error_code=NODE_DISABLED`.
- Scheduler observations: skipped jobs retain low-sensitive node/method summaries only.

## Nonce Replay

### Symptoms

RPC response contains `REPLAYED_NONCE`.

### Common Causes

- A request frame was retried verbatim.
- A client or test reused a full `RpcRequest`.
- Clock or timeout settings caused a request to remain live long enough to be replayed.

### Verification Commands

```bash
journalctl -u ocfleet-agent -n 100 --no-pager | grep REPLAYED_NONCE || true
grep REPLAYED_NONCE /var/log/ocfleet-agent/audit.jsonl || true
```

### Fix Steps

Generate a fresh request by rerunning the CLI command instead of replaying a saved frame:

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret ping hk-ocserv-01
```

If this appears during custom integration tests, create a new nonce per request and keep `deadline_ms` short.

### Logs And Metrics

- Agent audit: `event=rpc_request`, `stage=dispatch`, `error_code=REPLAYED_NONCE`.
- Audit field `nonce_hash` identifies the repeated nonce without exposing the nonce.

## Deadline Or Expired Request

### Symptoms

RPC response contains `REQUEST_EXPIRED`, `INVALID_DEADLINE`, `CLOCK_SKEW_EXCEEDED`, or `RPC_TIMEOUT`.

### Common Causes

- Controller and agent clocks differ.
- Request `deadline_ms` is too low for the environment.
- The request was delayed beyond its deadline before reaching the agent.
- The agent hit `max_rpc_timeout_ms`, `max_handshake_duration_ms`, or `max_connection_idle_ms`.

### Verification Commands

```bash
date -u
timedatectl status || true
grep -E 'REQUEST_EXPIRED|INVALID_DEADLINE|CLOCK_SKEW_EXCEEDED|RPC_TIMEOUT' /var/log/ocfleet-agent/audit.jsonl || true
cat /etc/ocfleet-agent/agent.toml
```

### Fix Steps

Synchronize time and restart the agent:

```bash
sudo timedatectl set-ntp true
sudo systemctl restart systemd-timesyncd || true
sudo systemctl restart ocfleet-agent
```

If the network is slow, raise bounded timeouts in `/etc/ocfleet-agent/agent.toml`:

```toml
[security]
allowed_clock_skew_seconds = 60
default_deadline_ms = 5000
max_deadline_ms = 10000
max_rpc_timeout_ms = 5000
max_handshake_duration_ms = 5000
max_connection_idle_ms = 5000
```

Then run:

```bash
sudo systemctl restart ocfleet-agent
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret ping hk-ocserv-01
```

### Logs And Metrics

- Agent audit: `error_code=REQUEST_EXPIRED`, `CLOCK_SKEW_EXCEEDED`, `INVALID_DEADLINE`, or `RPC_TIMEOUT`.
- Timeout rejection audit: `event=rpc_rejected`, `stage=handshake_timeout` or `connection_idle_timeout`.

## Unknown Peer Or `ENDPOINT_NOT_ALLOWED`

### Symptoms

Connection is rejected before a structured RPC response, or audit shows `ENDPOINT_NOT_ALLOWED`.

### Common Causes

- The controller EndpointID is missing from `[[security.controllers]]`.
- A source agent is missing from target `[[security.peers]]`.
- A peer entry exists but `enabled = false`.
- The wrong SecretKey is running on the controller or source agent.
- Controller trust is Active but unbound, points to a different node, or is one
  of multiple Active bindings for the node.

### Verification Commands

```bash
journalctl -u ocfleet-agent -n 100 --no-pager | grep ENDPOINT_NOT_ALLOWED || true
grep ENDPOINT_NOT_ALLOWED /var/log/ocfleet-agent/audit.jsonl || true
grep -n 'security.controllers\|security.peers\|endpoint_id' /etc/ocfleet-agent/agent.toml
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret doctor
```

### Fix Steps

Add the trusted controller:

```toml
[[security.controllers]]
endpoint_id = "<controller_endpoint_id>"
role = "viewer"
```

For one-hop path probes, add the source agent to the target:

```toml
[[security.peers]]
endpoint_id = "<source_agent_endpoint_id>"
enabled = true
```

Restart after config changes:

```bash
sudo systemctl restart ocfleet-agent
```

### Logs And Metrics

- Agent audit: `event=rpc_rejected`, `stage=connection_admission`, `error_code=ENDPOINT_NOT_ALLOWED`.
- Fields: `remote_endpoint_id`, `reason`, `resource=connection`.
- Controller/scheduler observations may use `ENDPOINT_TRUST_UNBOUND`,
  `ENDPOINT_TRUST_BINDING_MISMATCH`, `TARGET_ENDPOINT_TRUST_UNBOUND`, or
  `TARGET_ENDPOINT_TRUST_BINDING_MISMATCH`. These remain protocol-level
  `ENDPOINT_NOT_ALLOWED` failures.

## Endpoint Revoked, Quarantined, Or Rotated

### Symptoms

`trust diff` or controller RPC preflight reports `ENDPOINT_REVOKED`, `ENDPOINT_QUARANTINED`, `ENDPOINT_ROTATED`, or a generic inactive endpoint status.

### Common Causes

- The EndpointID was explicitly revoked or quarantined during incident response.
- A pre-hardening or restored database has a stale registry pointer from an old
  rotation.
- A restored controller database contains stale lifecycle state.
- An agent config still allows an old controller or peer EndpointID.

### Verification Commands

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret trust diff --format json
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret node list
grep -n 'endpoint_id' /etc/ocfleet-agent/agent.toml
```

### Fix Steps

Use explicit lifecycle commands; never rely on first contact to trust a new key:

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret endpoint rotate "$OLD_ENDPOINT_ID" --new-endpoint-id "$NEW_ENDPOINT_ID" --reason "planned key rotation"
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret trust diff --format json
```

A successful rotation moves the bound node pointer in the same transaction. An
exact retry of the recorded old/new pair is allowed; a different successor from
a rotated row is rejected. Revoked rows are terminal, while quarantined rows may
only rotate or revoke. A rotation from quarantine leaves the replacement node
disabled until an explicit, clean `node enable`. Exact no-ops do not increment
generation or write another audit row. An exact retry that repairs the one
deterministic legacy stale pointer writes `endpoint.rotate.reconcile` without a
generation increment.

For compromise or investigation:

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret endpoint revoke "$ENDPOINT_ID" --reason "retired or compromised"
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret endpoint quarantine "$ENDPOINT_ID" --reason "investigation"
```

### Logs And Metrics

- Controller audit: `event=endpoint.rotate`, `event=endpoint.revoke`, or `event=endpoint.quarantine`.
- Trust diff codes are low-sensitive and should not expose raw certificates, usernames, client IPs, or session IDs.

## Missing Path Authorization

### Symptoms

`ocfleet probe path <source> <target>` returns `ENDPOINT_NOT_ALLOWED` with a message containing `probe.path.echo authorization is missing`.

### Common Causes

- The source agent lacks a matching `[[security.path_probes]]` entry for the controller and target.
- The source agent does not list the target as an enabled `[[security.peers]]` entry.
- The target EndpointID in source config is stale.
- The target agent allows the source, but the source does not authorize the controller-target pair.

### Verification Commands

```bash
grep -n 'security.path_probes\|controller_endpoint_id\|target_endpoint_id' /etc/ocfleet-agent/agent.toml
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret probe summary source-ocserv-01 target-ocserv-01
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret doctor --json
```

### Fix Steps

On the source agent, add both entries:

```toml
[[security.peers]]
endpoint_id = "<target_agent_endpoint_id>"
enabled = true

[[security.path_probes]]
controller_endpoint_id = "<controller_endpoint_id>"
target_endpoint_id = "<target_agent_endpoint_id>"
enabled = true
```

On the target agent, add:

```toml
[[security.peers]]
endpoint_id = "<source_agent_endpoint_id>"
enabled = true
```

Restart both agents:

```bash
sudo systemctl restart ocfleet-agent
```

### Logs And Metrics

- Source agent audit: `event=rpc_request`, `stage=dispatch`, `method=probe.path.echo`, `error_code=ENDPOINT_NOT_ALLOWED`.
- Path fields: `root_request_id`, `path_target_endpoint_id`.
- Controller audit: `method=probe.path.echo`, `ok=false`, `error_code=ENDPOINT_NOT_ALLOWED`.

## Audit Durability Fallback Or Audit Write Failed

### Symptoms

Agent audit primary log stops growing, but RPCs continue and `audit.metrics.json` shows queued events.

### Common Causes

- Audit log path is unavailable, full, or has unsafe permissions.
- Filesystem temporarily rejected appends.
- The spool reached `spool_max_events`.

### Verification Commands

```bash
cat /var/lib/ocfleet-agent/audit.metrics.json
wc -l /var/lib/ocfleet-agent/audit.spool.jsonl
tail -n 20 /var/log/ocfleet-agent/audit.jsonl
journalctl -u ocfleet-agent -n 100 --no-pager | grep audit || true
```

### Fix Steps

Fix permissions and free space:

```bash
sudo install -d -o ocfleet -g ocfleet -m 0700 /var/log/ocfleet-agent /var/lib/ocfleet-agent
sudo touch /var/log/ocfleet-agent/audit.jsonl
sudo chown ocfleet:ocfleet /var/log/ocfleet-agent/audit.jsonl
sudo chmod 0600 /var/log/ocfleet-agent/audit.jsonl
df -h /var/log/ocfleet-agent /var/lib/ocfleet-agent
sudo systemctl restart ocfleet-agent
```

Replay is automatic. New RPCs and the periodic writer wakeup try to flush the spool to the primary audit log. Event IDs make replay idempotent if a crash occurs after a primary append but before spool compaction.

### Logs And Metrics

- `audit_queued`: events durably written to spool.
- `audit_dropped`: events rejected because both primary and spool capacity were unavailable.
- `audit_replayed`: spooled events flushed to primary.
- `audit_flush_failures`: failed replay attempts.
- `audit_oldest_age_seconds`: age of the oldest queued event, or `null`.

## Scheduler No Matching Node

### Symptoms

`schedule run --once` completes with no RPCs executed, or a scheduled job repeatedly produces no observations for the expected nodes.

### Common Causes

- The job selector does not match any current registry row.
- Matching nodes are disabled.
- A `path-probe` job is missing `--source-node-id` or `--target-node-id`, or one of those nodes no longer exists.
- The interval has not elapsed yet, so the job is not due.

### Verification Commands

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret schedule status
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret schedule job list
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret node list
```

### Fix Steps

Create selectors that match fixed registry fields only:

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret schedule job add --kind controller-ping --interval 5m --selector role=ocserv
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret schedule run --once
```

For a path probe, use explicit source and target node IDs:

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret schedule job add --kind path-probe --interval 5m --source-node-id source-ocserv-01 --target-node-id target-ocserv-01
```

### Logs And Metrics

- Controller audit: `event=scheduler.run.once`, `event=scheduler.job.add`.
- Observation history stays low-sensitive: method, node ID, endpoint status/error code, duration, and summarized result class.

## Alert Delivery Failed

### Symptoms

`alert deliver --hook <hook>` exits non-zero, or `alert test <hook>` reports a rejected hook.

### Common Causes

- The hook type is forbidden, such as `exec:`, `command:`, `shell:`, or `script:`.
- A `jsonl_file:` hook points to an unsafe path, symlink, hardlink, or group/world-writable parent.
- A `webhook:<hook-id>` hook is missing, disabled, uses a mismatched HMAC secret, resolves to forbidden address space, returns a redirect, or times out.
- There are no open alert events to deliver.

### Verification Commands

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret alert list --json
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret alert test jsonl_file:/var/lib/ocfleet-controller/alerts.jsonl
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret alert deliver --hook jsonl_file:/var/lib/ocfleet-controller/alerts.jsonl --dry-run
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret alert hook list --json
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret alert hook test <hook-id> --dry-run --hmac-secret-file /var/lib/ocfleet-controller/webhook.secret
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret alert deliver --hook webhook:<hook-id> --limit 100 --dry-run
```

### Fix Steps

Use only supported read-only alert delivery hooks:

```bash
sudo install -d -o "$USER" -g "$USER" -m 0700 /var/lib/ocfleet-controller
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret alert deliver --hook jsonl_file:/var/lib/ocfleet-controller/alerts.jsonl
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret alert hook add-webhook --name ops-alerts --url https://alerts.example.com/ocfleet --hmac-secret-file /var/lib/ocfleet-controller/webhook.secret --host-allow alerts.example.com
```

For webhook failures, confirm the URL is HTTPS, the host exactly matches
`--host-allow`, DNS resolves only to public addresses, the receiver returns 2xx
without redirecting, and the secret file matches the stored HMAC key id. Do not
replace a rejected hook with a shell/script wrapper.

### Logs And Metrics

- Controller audit: `event=alert.delivery`, `event=alert.hook.add_webhook`, `event=alert.test`, `event=alert.silence`, or `event=alert.resolve`.
- Webhook attempt state: `alert_delivery_attempts` records status, HTTP status class, low-sensitive error code, and bytes sent only.
- Alert payloads are redacted summaries and must not include usernames, client IPs, session IDs, certificate subjects, raw logs, or raw RPC bodies.
