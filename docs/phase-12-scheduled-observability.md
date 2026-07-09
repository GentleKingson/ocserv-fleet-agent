# Phase 12 Scheduled Observability Design

## Summary

Phase 12 evolves `ocfleet` from manual read-only CLI probes into continuous
controller-owned observability. The controller schedules fixed read-only RPCs,
stores typed low-sensitive observations in SQLite, computes bounded health
summaries, evaluates alert rules, and exports audit data. A read-only Web/API
dashboard remains planned and is not implemented in the current source tree.

Phase 12 does not add new agent control powers. It reuses the current trust
model, controller registry, controller audit log, and Phase 11 ocserv read-only
RPC boundary.

## Current Implementation Status

| Surface | Current status | Current CLI or source state |
| --- | --- | --- |
| Scheduler | partially implemented / active implementation | `ocfleet schedule job add/list/enable/disable`, `ocfleet schedule run --once`, `ocfleet schedule daemon`, `ocfleet schedule status` |
| Health | partially implemented / active implementation | `ocfleet health summary`, `ocfleet health node`, `ocfleet health policy show/set` |
| Alerts | partially implemented / active implementation | `ocfleet alert list/test/deliver/silence/resolve`; only `jsonl_file:<path>` delivery is enabled |
| Retention | partially implemented / active implementation | `ocfleet retention show/set/apply` for observability history scopes |
| Audit export | partially implemented / active implementation | `ocfleet audit export --from ... --to ... --format jsonl --output ...` |
| `ocfleet-api` / Web dashboard | planned / not implemented | No API binary, routes, or Web UI are present |
| Webhook hooks | planned / not implemented | `webhook:` hooks are rejected until HTTPS/HMAC/SSRF protections are designed and implemented |

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
- Later, add a Web/API read-only dashboard for status, health, history, alerts,
  and audit export visibility.

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
  -> future read-only API/dashboard
```

The scheduler runs inside the controller boundary and uses the same local
controller `SecretKey`, SQLite database, node registry, EndpointID trust checks,
and RPC client path that manual CLI commands use today. It never changes agent
configuration and never infers new trust.

Each scheduled job resolves its target from static controller SQLite state:

- non-path jobs resolve enabled nodes with active EndpointIDs from
  controller-local selectors.
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

Only these methods are produced by current scheduled job kinds:

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

Unknown stored job kinds and known dangerous method names must be rejected before
RPC execution. Scheduler implementations must use allowlists, not denylists.

## Current SQLite Model

Phase 12 currently uses additive migrations plus safe rebuild migrations for
observability constraints. The current controller schema contains these
controller-local tables. They store fixed low-sensitive summaries only.

### `observability_jobs`

Stores scheduler configuration. This table is controller-local policy, not
agent-local config. Current columns:

- `job_id TEXT PRIMARY KEY`
- `kind TEXT NOT NULL`
- `selector_json TEXT NOT NULL`
- `pair_selector_json TEXT`
- `interval_seconds INTEGER NOT NULL`
- `jitter_seconds INTEGER NOT NULL DEFAULT 0`
- `timeout_ms INTEGER NOT NULL`
- `enabled INTEGER NOT NULL DEFAULT 1`
- `next_run_at TEXT`
- `last_run_at TEXT`
- `created_at TEXT NOT NULL`
- `updated_at TEXT NOT NULL`

Rules:

- `kind` is one of `controller-ping`, `ocserv-status`, `ocserv-cert`,
  `ocserv-sessions`, or `path-probe`.
- non-path jobs use a controller-local `role=<role>` or `node_id=<node-id>`
  selector.
- path jobs use `pair_selector_json` with explicit `source_node_id` and
  `target_node_id`.
- `interval_seconds` must be positive and bounded.
- no column may store command text, local file paths, shell snippets, service
  units, journal queries, or agent-side selectors.

### `observability_runs`

Stores one scheduler attempt per job execution. Current columns:

- `run_id TEXT PRIMARY KEY`
- `job_id TEXT`
- `started_at TEXT NOT NULL`
- `finished_at TEXT`
- `status TEXT NOT NULL`
- `triggered_by TEXT NOT NULL`
- `summary_json TEXT NOT NULL`

Rules:

- `status` is one of `running`, `succeeded`, `failed`, or `skipped`.
- `triggered_by` is currently `manual` or `scheduler.run.once`.
- `summary_json` is metadata-only: counts, status, error codes, and fixed
  reason classes.
- no raw RPC response, raw error text, stdout/stderr, path, log, username,
  client IP, session ID, certificate subject/SAN/issuer/serial, or config
  content may be stored.

### `probe_observations`

Stores typed low-sensitive observations produced by scheduled methods. Current
columns:

- `observation_id TEXT PRIMARY KEY`
- `run_id TEXT`
- `node_id TEXT`
- `endpoint_id TEXT`
- `method TEXT NOT NULL`
- `ok INTEGER`
- `error_code TEXT`
- `duration_ms INTEGER`
- `observed_at TEXT NOT NULL`
- `expires_at TEXT`
- `result_class TEXT NOT NULL`
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

Stores derived read-only health state for nodes. Current columns:

- `node_id TEXT PRIMARY KEY`
- `endpoint_id TEXT`
- `computed_at TEXT NOT NULL`
- `status TEXT NOT NULL`
- `freshness_seconds INTEGER`
- `last_success_at TEXT`
- `last_failure_at TEXT`
- `last_error_code TEXT`
- `degraded_methods_json TEXT NOT NULL`
- `summary_json TEXT NOT NULL`

Rules:

- `status` is one of `healthy`, `degraded`, `unreachable`, `stale`,
  `disabled`, or `unknown`.
- health is advisory and read-only. It must not modify nodes, trust, scheduler
  jobs, or agent state.
- `summary_json` contains counts, timestamps, method availability, stale
  windows, and alert references only.

### `alert_events`

Stores alert lifecycle events derived from health snapshots or observation
rules. Current columns:

- `alert_id TEXT PRIMARY KEY`
- `dedupe_key TEXT NOT NULL UNIQUE`
- `node_id TEXT`
- `severity TEXT NOT NULL`
- `state TEXT NOT NULL`
- `reason_code TEXT NOT NULL`
- `first_seen_at TEXT NOT NULL`
- `last_seen_at TEXT NOT NULL`
- `last_sent_at TEXT`
- `resolved_at TEXT`
- `detail_json TEXT NOT NULL`

Rules:

- `state` is `open`, `silenced`, or `resolved`.
- `reason_code` is a fixed low-sensitive enum such as `NODE_UNREACHABLE`,
  `NODE_STALE`, `OCSERV_DEGRADED`, `CERT_EXPIRING_CRITICAL`,
  `CERT_EXPIRING_WARNING`, or `ENDPOINT_INACTIVE`.
- alert messages are bounded low-sensitive text.
- alert hooks receive alert metadata and summary fields only.
- local script execution, shell hooks, command hooks, and unbounded templates are
  forbidden.
- current SQLite delivery tracking uses `last_sent_at`; first-phase JSONL
  delivery failures are recorded in `alert.delivery` audit rows rather than a
  delivery retry state machine.

### `retention_policies`

Stores retention limits for observability history.

Current columns:

- `scope TEXT PRIMARY KEY`
- `max_age_days INTEGER`
- `max_rows INTEGER`
- `updated_at TEXT NOT NULL`

Rules:

- allowed `scope` values are `observations`, `observability-runs`,
  `health-snapshots`, and `alert-events`.
- retention must not delete node registry rows, endpoint trust rows,
  enrollment rows, current scheduler configuration, or controller audit rows.
- retention apply runs must write controller audit metadata about row counts,
  scope, cutoff, and report checksum.

## Current CLI Surface And Planned API

The current Phase 12 CLI commands exist without changing the Phase 11 RPC
boundary. Examples below match the current `ocfleet` argument parser.

### Scheduler

```bash
ocfleet schedule job add \
  --kind ocserv-status \
  --selector node_id=hk-ocserv-01 \
  --interval 60s

ocfleet schedule job add \
  --kind controller-ping \
  --selector role=ocserv \
  --interval 300s

ocfleet schedule job add \
  --kind path-probe \
  --source-node-id hk-ocserv-01 \
  --target-node-id sg-ocserv-01 \
  --interval 300s

ocfleet schedule job list
ocfleet schedule job enable <job-id>
ocfleet schedule job disable <job-id>
ocfleet schedule run --once
ocfleet schedule run --once --max-concurrency 4
ocfleet schedule daemon --tick-seconds 60 --max-concurrency 4
ocfleet schedule status
```

`schedule daemon` runs scheduler loops only from local controller config and
SQLite job rows. It must not expose an unauthenticated socket and must not allow
dashboard/API callers to trigger RPCs.

After `schedule run --once` and after each daemon tick, the controller evaluates
local alert candidates from existing observations, health snapshots, and endpoint
trust state. This phase only upserts local `alert_events`; it does not deliver
JSONL files, call webhooks, execute shell, execute scripts, or perform
remediation. `schedule run --once` prints `alert_evaluation=ok|failed` and
`alert_events=<count>`, and the scheduler audit detail records the same bounded
summary.

### Health

```bash
ocfleet health summary
ocfleet health summary --json
ocfleet health node hk-ocserv-01
ocfleet health node hk-ocserv-01 --json
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
ocfleet retention set observations --max-age 30d --max-rows 100000
ocfleet retention apply --dry-run --scope observations --before 2026-07-01T00:00:00Z --json
ocfleet retention apply --scope observations --batch-size 1000 --limit 10000
```

Retention commands modify retention policy and prune local SQLite history only.
They do not call agents. `retention apply` reports `matched_count`, cutoff,
policy row cap, oldest/newest candidate timestamps, deleted rows, batch count,
and a SHA-256 report checksum. Actual deletes are split into bounded batches;
controller audit rows are never deleted by retention.

### Alerts

```bash
ocfleet alert list
ocfleet alert list --json
ocfleet alert test jsonl_file:./private-alerts/test.jsonl
ocfleet alert deliver --hook jsonl_file:./private-alerts/alerts.jsonl --limit 100
ocfleet alert deliver --hook jsonl_file:./private-alerts/alerts.jsonl --limit 100 --dry-run
ocfleet alert silence <dedupe-key> --for-duration 24h --reason "maintenance"
ocfleet alert resolve <dedupe-key> --reason "certificate renewed"
```

`alert test jsonl_file:<path>` writes a fixed synthetic JSONL test event after
validating that the destination is in a private directory and is not a symlink,
hardlink, world-readable file, or non-regular file. `alert deliver` evaluates
local alert state, selects bounded open alerts, writes compact JSONL payloads,
and updates `last_sent_at` after successful non-dry-run delivery. These commands
must not call agents, expand shell syntax, read secrets, or execute local
scripts.

### Audit Export

```bash
ocfleet audit export --from 2026-07-01T00:00:00Z --to 2026-07-08T00:00:00Z --format jsonl --output ./audit-export.jsonl
ocfleet audit export --from 2026-07-01T00:00:00Z --to 2026-07-08T00:00:00Z --output ./audit-export.jsonl --redact strict --include-checksum
```

Audit export reads bounded windows from controller SQLite and writes sanitized
controller audit records as JSONL. The window is mandatory and capped, row count
is bounded by `--max-rows`, output uses private `0600` create-new files under a
private `0700` parent, and `--include-checksum` writes a SHA-256 sidecar. Default
redaction hides secret-like fields; strict redaction hashes actor, node,
endpoint, and request identifiers. The `audit.export` audit row is written after
the file is produced, so it is not included in that export window snapshot.

### Planned Read-only Web/API Dashboard

```bash
ocfleet-api --database controller.sqlite --read-only --listen 127.0.0.1:8080
```

The command above is a planned interface, not a current binary. No Web/API
dashboard is implemented in the current source tree. Draft read-only routes:

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
hook type is `jsonl_file:<path>`, which appends compact fixed-schema JSONL to a
private local file. HTTPS webhook delivery is a later phase behind explicit
configuration and must remain disabled until SSRF, HMAC, timeout, redirect, and
retry boundaries are implemented.

Allowed alert payload fields:

- alert ID
- dedupe key
- severity
- node ID
- fixed RPC method names
- reason code
- state
- bounded low-sensitive summary
- opened/updated/sent/resolved timestamps

Forbidden hook behavior:

- shell execution
- local command execution
- arbitrary script execution
- template execution that can read files or environment variables
- raw observation payload delivery
- raw audit row delivery
- automatic remediation

The current JSONL delivery phase writes `alert.delivery` audit rows with bounded
metadata: hook type, alert count, bytes written, dry-run flag, and fixed
low-sensitive error code on failure. It does not store the output path in audit,
does not retry, and does not add a delivery retry state machine.

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
- future dashboard/API reads must use a read-only SQLite connection where
  practical and must not mutate scheduler state.

## Health Summary Semantics

Health state is derived, not authoritative. Current CLI status labels are:

- `healthy`: recent relevant observations succeeded and no active alert affects the
  scope.
- `degraded`: at least one scheduled method is unavailable, stale, or failed,
  but enough observations remain available for useful status.
- `unreachable`: endpoint trust is inactive or recent controller ping failures
  indicate the node cannot be reached.
- `stale`: observations exist but are older than the configured health window.
- `disabled`: the controller registry node is disabled.
- `unknown`: no relevant observations exist yet.

Health summaries must include source timestamps and method coverage so operators
can distinguish real failures from missing schedules.

## Definition of Done

Phase 12 CLI observability changes should pass the standard workspace gates:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -j1 -- --test-threads=1
```

Smoke commands for current CLI surfaces:

```bash
ocfleet schedule job add --kind controller-ping --selector node_id=hk-ocserv-01 --interval 60s
ocfleet schedule job add --kind path-probe --source-node-id hk-ocserv-01 --target-node-id sg-ocserv-01 --interval 300s
ocfleet schedule job list
ocfleet schedule job disable <job-id>
ocfleet schedule job enable <job-id>
ocfleet schedule run --once
ocfleet schedule status

ocfleet health summary
ocfleet health summary --json
ocfleet health node hk-ocserv-01
ocfleet health node hk-ocserv-01 --json
ocfleet health policy show

ocfleet retention show
ocfleet retention set observations --max-age 30d --max-rows 100000
ocfleet retention apply --dry-run --scope observations --json
ocfleet retention apply --scope observations --batch-size 1000 --limit 10000

ocfleet alert list
ocfleet alert list --json
ocfleet alert test jsonl_file:./private-alerts/test.jsonl
ocfleet alert deliver --hook jsonl_file:./private-alerts/alerts.jsonl --limit 100 --dry-run
ocfleet alert silence <dedupe-key> --for-duration 24h --reason "smoke silence"
ocfleet alert resolve <dedupe-key> --reason "smoke resolved"

ocfleet audit export --from 2026-07-01T00:00:00Z --to 2026-07-08T00:00:00Z --format jsonl --output ./audit-export.jsonl
ocfleet audit export --from 2026-07-01T00:00:00Z --to 2026-07-08T00:00:00Z --output ./audit-export.jsonl --redact default --include-checksum
```

Additional acceptance requirements:

- scheduler jobs are limited to current fixed job kinds.
- `probe.path.echo` jobs require explicit source and target node IDs.
- scheduler never enumerates mesh pairs.
- dashboard/API remains unimplemented until a separate read-only API design is
  approved.
- alert hooks cannot execute local scripts or commands.
- history, health, alerts, dashboard, API, and audit export contain no raw
  response bodies.
- retention policies prune only approved history tables.
- controller audit records exist for job mutation, run completion, retention
  apply, alert lifecycle operations, and audit export.
