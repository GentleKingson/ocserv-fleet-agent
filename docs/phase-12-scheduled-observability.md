# Phase 12 Scheduled Observability Design

## Summary

Phase 12 evolves `ocfleet` from manual read-only CLI probes into continuous
controller-owned observability. The controller schedules fixed read-only RPCs,
stores typed low-sensitive observations in SQLite, computes bounded health
summaries, evaluates alert rules, exports audit data, and serves a read-only
Web/API dashboard.

Phase 12 does not add new agent control powers. It reuses the current trust
model, controller registry, controller audit log, and Phase 11 ocserv read-only
RPC boundary.

## Goals

- Add a controller scheduler that runs explicitly configured observation jobs on
  a fixed interval or by an operator-triggered one-shot run.
- Add probe history retention so scheduled observations, run metadata, alert
  events, and health snapshots are pruned predictably without touching the
  node registry or trust state.
- Add a read-only health summary that derives node and fleet status from stored
  low-sensitive observations.
- Add alert hooks for fixed alert event delivery without arbitrary local script
  execution.
- Add audit export for bounded controller audit windows and scheduled
  observability events.
- Add a Web/API read-only dashboard for status, health, history, alerts, and
  audit export visibility.

## Non-goals

Phase 12 must not add or expose:

- `shell.exec`
- `command.run`
- `occtl.raw`
- `systemctl.raw`
- `journalctl.raw`
- `file.read`
- ocserv reload or restart
- ocserv config apply or rollback
- user disconnect or user management
- dashboard/API actions that trigger agent RPC
- scheduler behavior that automatically generates trust or automatically
  authorizes path probes
- arbitrary script or exec alert hooks

The dashboard and API are observation surfaces only. They must not become a
remote control plane for invoking RPCs, creating trust, modifying node state, or
running local commands.

## Architecture

The Phase 12 data flow is:

```text
controller scheduler
  -> fixed RPC
  -> typed observation
  -> SQLite history
  -> health summary
  -> alert evaluation
  -> read-only API/dashboard
```

The scheduler runs inside the controller boundary and uses the same local
controller `SecretKey`, SQLite database, node registry, EndpointID trust checks,
and RPC client path that manual CLI commands use today. It never changes agent
configuration and never infers new trust.

Each scheduled job resolves its target from static controller SQLite state:

- node-target jobs resolve exactly one enabled node and active EndpointID.
- path jobs resolve one explicitly configured source node and one explicitly
  configured target node.
- jobs fail closed if the node is missing, disabled, revoked, quarantined,
  rotated away, or otherwise not active.

Successful RPC responses are decoded into closed typed DTOs before storage.
Failed RPCs store only error code, fixed method name, node IDs, endpoint IDs,
duration, and sanitized low-sensitive error class. Raw response bodies are never
stored in history, audit, alert payloads, or dashboard views.

Low-sensitive identifiers are limited to controller-assigned `node_id`,
`region`, `role`, fixed RPC method names, request correlation IDs, and
EndpointIDs needed to prove endpoint binding or path-probe routing decisions.
These values may appear in controller-local history, health, alerts, exports,
and read-only dashboard/API responses, but they do not authorize any action and
must not be accepted as agent-supplied trust input. Certificate and config
fingerprints are not emitted as full hashes by default; CLI JSON, scheduled
history, alerts, and dashboards use aggregate status plus short fingerprint
prefixes only.

## Allowed Scheduled Methods

Only these methods are allowed in scheduled jobs:

- `probe.controller.ping`
- `ocserv.service.summary`
- `ocserv.version`
- `ocserv.sessions.summary`
- `ocserv.cert.expiry`
- `ocserv.config.fingerprint`
- `probe.path.echo`

`probe.path.echo` is allowed only for explicitly configured source/target pairs.
The scheduler must not enumerate the node registry to generate mesh pairs and
must not infer path-probe authorization from topology, region, role, naming
conventions, or past success. Source-side authorization requires both
`security.path_probes` and an enabled target entry in `security.peers`;
target-side authorization remains `security.peers`.

Unknown methods and known dangerous method names must be rejected at job
creation time and again at run time. A scheduler implementation must use an
allowlist, not a denylist.

## Data Model Draft

Phase 12 should use additive SQLite migrations. These table names are reserved
for the implementation design.

### `observability_jobs`

Stores scheduler configuration. This table is controller-local policy, not
agent-local config.

Draft columns:

- `job_id TEXT PRIMARY KEY`
- `name TEXT NOT NULL`
- `method TEXT NOT NULL`
- `target_node_id TEXT`
- `source_node_id TEXT`
- `target_peer_node_id TEXT`
- `interval_seconds INTEGER NOT NULL`
- `jitter_seconds INTEGER NOT NULL DEFAULT 0`
- `enabled INTEGER NOT NULL DEFAULT 1`
- `created_at TEXT NOT NULL`
- `updated_at TEXT NOT NULL`
- `last_run_at TEXT`
- `next_run_at TEXT`
- `labels_json TEXT NOT NULL DEFAULT '{}'`

Rules:

- `method` must be one of the allowed scheduled methods.
- node-target jobs must set `target_node_id` and leave path fields null.
- path jobs must set `source_node_id` and `target_peer_node_id`.
- `interval_seconds` must be positive and bounded.
- no column may store command text, local file paths, shell snippets, service
  units, journal queries, or agent-side selectors.

### `observability_runs`

Stores one scheduler attempt per job execution.

Draft columns:

- `run_id TEXT PRIMARY KEY`
- `job_id TEXT NOT NULL`
- `started_at TEXT NOT NULL`
- `finished_at TEXT`
- `status TEXT NOT NULL`
- `method TEXT NOT NULL`
- `node_id TEXT`
- `endpoint_id TEXT`
- `source_node_id TEXT`
- `source_endpoint_id TEXT`
- `target_node_id TEXT`
- `target_endpoint_id TEXT`
- `request_id TEXT`
- `ok INTEGER`
- `error_code TEXT`
- `duration_ms INTEGER`
- `observation_id TEXT`
- `detail_json TEXT NOT NULL DEFAULT '{}'`

Rules:

- `status` is one of `queued`, `running`, `succeeded`, `failed`, `skipped`, or
  `expired`.
- `detail_json` is metadata-only: method names, status, error codes, and fixed
  reason classes.
- no raw RPC response, raw error text, stdout/stderr, path, log, username,
  client IP, session ID, certificate subject/SAN/issuer/serial, or config
  content may be stored.

### `probe_observations`

Stores typed low-sensitive observations produced by scheduled methods.

Draft columns:

- `observation_id TEXT PRIMARY KEY`
- `run_id TEXT NOT NULL`
- `observed_at TEXT NOT NULL`
- `method TEXT NOT NULL`
- `node_id TEXT`
- `endpoint_id TEXT`
- `source_node_id TEXT`
- `source_endpoint_id TEXT`
- `target_node_id TEXT`
- `target_endpoint_id TEXT`
- `result_class TEXT NOT NULL DEFAULT 'low_sensitive_summary'`
- `status TEXT NOT NULL`
- `summary_json TEXT NOT NULL`

`summary_json` is a closed per-method shape, for example:

- controller ping: message class, agent version, agent time, endpoint match.
- service summary: service state and enabled state.
- version: bounded version string and availability status.
- sessions summary: aggregate session count only.
- cert expiry: aggregate cert count, minimum days remaining, health status, and
  optional short fingerprint prefix.
- config fingerprint: algorithm, short display hash prefix, and drift status.
- path echo: source/target endpoint IDs, root/peer request IDs, ok/error code,
  and target segment status.

Rules:

- `summary_json` stores typed low-sensitive summaries only.
- config and certificate fingerprints must not be stored or emitted as full
  hashes by default; use short prefixes and aggregate status. A future export
  that needs full hashes must add an explicit classification decision and a
  separate opt-in surface.
- session detail, usernames, client IPs, raw target results, raw response bodies,
  and raw provider errors are forbidden.

### `health_snapshots`

Stores derived read-only health state for nodes and fleet views.

Draft columns:

- `snapshot_id TEXT PRIMARY KEY`
- `computed_at TEXT NOT NULL`
- `scope TEXT NOT NULL`
- `node_id TEXT`
- `status TEXT NOT NULL`
- `severity TEXT NOT NULL`
- `source_window_seconds INTEGER NOT NULL`
- `summary_json TEXT NOT NULL`

Rules:

- `scope` is `fleet` or `node`.
- `status` is one of `ok`, `degraded`, `critical`, `unknown`, or `stale`.
- health is advisory and read-only. It must not modify nodes, trust, scheduler
  jobs, or agent state.
- `summary_json` contains counts, timestamps, method availability, stale
  windows, and alert references only.

### `alert_events`

Stores alert lifecycle events derived from health snapshots or observation
rules.

Draft columns:

- `alert_id TEXT PRIMARY KEY`
- `rule_id TEXT NOT NULL`
- `opened_at TEXT NOT NULL`
- `updated_at TEXT NOT NULL`
- `resolved_at TEXT`
- `silenced_until TEXT`
- `status TEXT NOT NULL`
- `severity TEXT NOT NULL`
- `node_id TEXT`
- `method TEXT`
- `observation_id TEXT`
- `health_snapshot_id TEXT`
- `message TEXT NOT NULL`
- `delivery_state TEXT NOT NULL`
- `detail_json TEXT NOT NULL DEFAULT '{}'`

Rules:

- `status` is `open`, `silenced`, or `resolved`.
- `delivery_state` is `pending`, `sent`, `failed`, or `disabled`.
- alert messages are bounded low-sensitive text.
- alert hooks receive alert metadata and summary fields only.
- local script execution, shell hooks, command hooks, and unbounded templates are
  forbidden.

### `retention_policies`

Stores retention limits for observability history.

Draft columns:

- `policy_id TEXT PRIMARY KEY`
- `target_table TEXT NOT NULL`
- `max_age_seconds INTEGER NOT NULL`
- `max_rows INTEGER`
- `enabled INTEGER NOT NULL DEFAULT 1`
- `updated_at TEXT NOT NULL`

Rules:

- allowed `target_table` values are `observability_runs`,
  `probe_observations`, `health_snapshots`, `alert_events`, and
  `controller_audit_log`.
- retention must not delete node registry rows, endpoint trust rows,
  enrollment rows, or current scheduler configuration.
- retention apply runs must write controller audit metadata about row counts,
  target table, and policy ID.

## CLI Proposal

Phase 12 should add these commands without changing the Phase 11 RPC boundary.

### Scheduler

```bash
ocfleet schedule job add --name ocserv-status \
  --method ocserv.service.summary \
  --node hk-ocserv-01 \
  --interval 60s

ocfleet schedule job add --name path-hk-to-sg \
  --method probe.path.echo \
  --source hk-ocserv-01 \
  --target sg-ocserv-01 \
  --interval 300s

ocfleet schedule job list
ocfleet schedule job enable <job-id>
ocfleet schedule job disable <job-id>
ocfleet schedule run --once <job-id>
ocfleet schedule daemon
```

`schedule daemon` runs scheduler loops only from local controller config and
SQLite job rows. It must not expose an unauthenticated socket and must not allow
dashboard/API callers to trigger RPCs.

After `schedule run --once` and after each daemon tick, the controller evaluates
local alert candidates from existing observations, health snapshots, and endpoint
trust state. This phase only upserts local `alert_events`; it does not run
jsonl, webhook, shell, exec, script, or other delivery hooks. `schedule run
--once` prints `alert_evaluation=ok|failed` and `alert_events=<count>`, and the
scheduler audit detail records the same bounded summary.

### Health

```bash
ocfleet health summary
ocfleet health node hk-ocserv-01
ocfleet health policy show
ocfleet health policy set --stale-window 24h --unreachable-failures 3 --cert-warning-days 30 --cert-critical-days 7
```

Health commands read SQLite snapshots and observations. They do not run probes.
Health policy commands update only controller-local SQLite thresholds for stale
health windows, consecutive unreachable failures, and certificate warning or
critical alert windows. Each policy update writes a controller audit record with
the old and new bounded threshold values.

### Retention

```bash
ocfleet retention show
ocfleet retention set --table probe_observations --max-age 30d --max-rows 100000
ocfleet retention apply
```

Retention commands modify retention policy and prune local SQLite history only.
They do not call agents.

### Alerts

```bash
ocfleet alert list
ocfleet alert test --rule cert-expiring
ocfleet alert silence <alert-id> --until 2026-08-01T00:00:00Z
ocfleet alert resolve <alert-id> --reason "certificate renewed"
```

`alert test` evaluates local rule configuration against existing SQLite data and
fixed sample payloads. It must not call agents and must not execute local
scripts.

### Audit Export

```bash
ocfleet audit export --since 2026-07-01T00:00:00Z --until 2026-07-08T00:00:00Z
ocfleet audit export --format jsonl --output ./audit-export.jsonl
```

Audit export reads bounded windows from controller SQLite and writes sanitized
controller audit records. It must not include raw response bodies.

### Read-only Web/API Dashboard

```bash
ocfleet-api --database controller.sqlite --read-only --listen 127.0.0.1:8080
```

Draft read-only routes:

- `GET /health/summary`
- `GET /health/nodes/{node_id}`
- `GET /observations`
- `GET /observations/{observation_id}`
- `GET /jobs`
- `GET /runs`
- `GET /alerts`
- `GET /audit/export`

The API must not define `POST /rpc`, `POST /jobs/{id}/run`, or any equivalent
endpoint that triggers agent RPCs. Mutating alert and retention commands remain
local CLI operations unless a later phase explicitly designs authenticated,
audited, non-RPC-triggering API mutations.

## Alert Hook Model

Alert hooks are outbound notification integrations only. The first supported
hook type should be a fixed-schema HTTPS webhook with a bounded JSON payload.

Allowed alert payload fields:

- alert ID
- rule ID
- status
- severity
- node ID
- fixed RPC method name
- observation ID
- health snapshot ID
- bounded low-sensitive message
- opened/updated/resolved timestamps

Forbidden hook behavior:

- shell execution
- local command execution
- arbitrary script execution
- template execution that can read files or environment variables
- raw observation payload delivery
- raw audit row delivery
- automatic remediation

Failed hook delivery must create or update `alert_events.delivery_state` and
write controller audit metadata. It must not retry without a configured bounded
backoff policy.

The current scheduler integration stops before this delivery phase: alert
evaluation only writes controller-local `alert_events`.

## Security Rules

Phase 12 keeps the project security posture:

- low-sensitive: scheduled outputs, history, health, alerts, exports, and
  dashboard views contain only low-sensitive summaries.
- read-only: scheduler and dashboard cannot control services, users, config,
  files, trust, or agent runtime state.
- fixed schema: scheduled observations are decoded into typed per-method shapes
  before storage.
- fixed RPC: scheduler jobs reference only the allowed method allowlist.
- no raw response bodies in audit, history, alert payloads, audit export, or
  dashboard/API responses.
- no controller-supplied agent-local paths, command names, service unit names,
  journal selectors, scripts, or file selectors.
- no automatic trust generation, no TOFU, no automatic path-probe
  authorization, and no mesh enumeration.
- all scheduler job creation, enable/disable, one-shot runs, retention apply,
  alert silence, alert resolve, and audit export operations write controller
  audit entries.
- dashboard/API reads must use a read-only SQLite connection where practical and
  must not mutate scheduler state.

## Health Summary Semantics

Health state is derived, not authoritative:

- `ok`: recent required observations succeeded and no active alert affects the
  scope.
- `degraded`: at least one scheduled method is unavailable, stale, or failed,
  but enough observations remain available for useful status.
- `critical`: a required observation class has crossed a critical rule, such as
  repeated node ping failures or expired certificate status.
- `unknown`: no relevant observations exist yet.
- `stale`: observations exist but are older than the configured health window.

Health summaries must include source timestamps and method coverage so operators
can distinguish real failures from missing schedules.

## Definition of Done

Phase 12 implementation is complete only when these gates pass:

```bash
cargo build --workspace
cargo test --workspace
```

Smoke commands for every new CLI/API surface:

```bash
ocfleet schedule job add --name smoke-ping --method probe.controller.ping --node hk-ocserv-01 --interval 60s
ocfleet schedule job list
ocfleet schedule job disable <job-id>
ocfleet schedule job enable <job-id>
ocfleet schedule run --once <job-id>
ocfleet schedule daemon --once

ocfleet health summary
ocfleet health node hk-ocserv-01

ocfleet retention show
ocfleet retention set --table probe_observations --max-age 30d --max-rows 100000
ocfleet retention apply

ocfleet alert list
ocfleet alert test --rule cert-expiring
ocfleet alert silence <alert-id> --until 2026-08-01T00:00:00Z
ocfleet alert resolve <alert-id> --reason "smoke resolved"

ocfleet audit export --since 2026-07-01T00:00:00Z --until 2026-07-08T00:00:00Z
ocfleet audit export --format jsonl --output ./audit-export.jsonl

ocfleet-api --database controller.sqlite --read-only --listen 127.0.0.1:8080
curl --fail http://127.0.0.1:8080/health/summary
curl --fail http://127.0.0.1:8080/jobs
curl --fail http://127.0.0.1:8080/alerts
```

Additional acceptance requirements:

- scheduler jobs reject forbidden methods and unknown methods.
- `probe.path.echo` jobs require explicit source and target node IDs.
- scheduler never enumerates mesh pairs.
- dashboard/API cannot trigger agent RPCs.
- alert hooks cannot execute local scripts or commands.
- history, health, alerts, dashboard, API, and audit export contain no raw
  response bodies.
- retention policies prune only approved history tables.
- controller audit records exist for job mutation, run completion, retention
  apply, alert lifecycle operations, audit export, and API startup.
