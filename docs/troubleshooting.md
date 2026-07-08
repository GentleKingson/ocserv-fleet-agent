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

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret node remove hk-ocserv-01 --yes
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret node add hk-ocserv-01 --endpoint-id "$AGENT_ENDPOINT_ID" --region hk --role ocserv
```

### Logs And Metrics

- Controller audit: `event=rpc.completed`, `error_code=ENDPOINT_MISMATCH`.
- Error details: `expected_endpoint_id`, `actual_remote_endpoint_id`.
- Doctor checks: `registry.endpoint_id.parse`, `registry.peer_relationships`.

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

## Unknown Peer

### Symptoms

Connection is rejected before a structured RPC response, or audit shows `ENDPOINT_NOT_ALLOWED`.

### Common Causes

- The controller EndpointID is missing from `[[security.controllers]]`.
- A source agent is missing from target `[[security.peers]]`.
- A peer entry exists but `enabled = false`.
- The wrong SecretKey is running on the controller or source agent.

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

## Audit Durability Fallback

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
