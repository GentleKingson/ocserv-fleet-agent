# Metrics

## Exposure

The controller exports Prometheus text at `GET /metrics` on `ocfleet-api`.
`ocfleet-api` is loopback-only by default. The existing startup rule requires a
private bearer-token file for every non-loopback listener, and `/metrics` uses
the same authorization middleware as all other read-only routes.

```bash
ocfleet-api --database controller.sqlite --read-only --cursor-key-file ./cursor-keys.json --listen 127.0.0.1:8080
curl --fail http://127.0.0.1:8080/metrics
```

For a protected non-loopback listener, send the configured token as
`Authorization: Bearer <token>`. Metrics never bypass listener authentication.

## Cardinality And Sensitivity Contract

Metric names and label values are a closed compile-time catalog. The controller
uses only `result`, `status`, and `state` labels with at most five enumerated
values per family. It does not emit node IDs, EndpointIDs, users, client IPs,
addresses, sessions, request IDs, tokens, cookies, paths, certificate material,
error text, methods, hook IDs, job IDs, or other data-derived label values.

All current metrics are controller-local operational metadata. Counts, byte
sizes, and freshness are low sensitivity, but operators should still protect
non-loopback exposure because fleet health and activity rates are operational
information.

## Controller Catalog

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `ocfleet_controller_scheduler_jobs_due` | gauge | none | Enabled jobs whose next run is due. |
| `ocfleet_controller_scheduler_claims_active` | gauge | none | Unexpired scheduler claims. |
| `ocfleet_controller_scheduler_runs_total` | counter | `result=running,succeeded,failed,skipped` | Persisted scheduler run rows. |
| `ocfleet_controller_health_nodes` | gauge | `status=healthy,degraded,unreachable,unknown` | Persisted health snapshots. |
| `ocfleet_controller_alerts` | gauge | `state=open,silenced,resolved` | Persisted alerts. |
| `ocfleet_controller_delivery_attempts_total` | counter | `result=succeeded,failed` | Persisted delivery attempts. |
| `ocfleet_controller_delivery_queue` | gauge | `state=pending,claimed,retry,dead_letter,succeeded` | Delivery queue rows. |
| `ocfleet_controller_rpc_calls_total` | counter | `result=succeeded,failed` | Completed audited controller RPCs. |
| `ocfleet_controller_rpc_duration_milliseconds_sum` | counter | none | Cumulative audited RPC duration. |
| `ocfleet_controller_rpc_duration_milliseconds_count` | counter | none | Audited RPC duration sample count. |
| `ocfleet_controller_observations_total` | counter | none | Persisted observations. |
| `ocfleet_controller_observation_freshness_seconds` | gauge | none | Age of the newest observation. |
| `ocfleet_controller_sqlite_bytes` | gauge | none | Main SQLite database file size. |
| `ocfleet_controller_audit_exports_total` | counter | `result=succeeded,failed` | Audited export attempts. |
| `ocfleet_controller_retention_deleted_rows_total` | counter | none | Rows deleted by successful retention operations. |

Every scrape opens SQLite read-only with query-only and untrusted-schema modes.
The endpoint performs fixed aggregate queries and does not trigger RPC,
scheduler, evaluator, delivery, retention, export, or any controller mutation.

## Agent Exposure

`ocfleet-agent` serves Prometheus text on `127.0.0.1:9090` by default:

```bash
ocfleet-agent --config /etc/ocfleet-agent/config.toml \
  --metrics-listen 127.0.0.1:9090
curl --fail http://127.0.0.1:9090/metrics
```

A non-loopback `--metrics-listen` is rejected unless
`--metrics-auth-token-file <private-file>` is supplied. The token file uses the
same owner, regular-file, `0600`, no-symlink, no-hardlink, private-parent rules
as other secrets. The exporter is plain HTTP; non-loopback operation additionally
requires a TLS reverse proxy and network restriction. Only `/metrics` exists.

## Agent Catalog

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `ocfleet_agent_handshakes` | gauge | `state=active,rejected` | Active handshake tasks and bounded admission/authentication rejections. |
| `ocfleet_agent_connections` | gauge | `state=active,rejected` | Active admitted connections and limit rejections. |
| `ocfleet_agent_streams` | gauge | `state=active,rejected` | Active RPC streams and limit rejections. |
| `ocfleet_agent_rpc_calls_total` | counter | `state=succeeded,failed` | RPC responses by fixed result. |
| `ocfleet_agent_rpc_results_total` | counter | `state=success,validation,authorization,resource,timeout,dependency,internal` | RPC responses by closed result-code class. |
| `ocfleet_agent_rpc_duration_milliseconds_sum` | counter | none | Cumulative RPC duration. |
| `ocfleet_agent_rpc_duration_milliseconds_count` | counter | none | RPC duration sample count. |
| `ocfleet_agent_nonce_cache_size` | gauge | none | Current live nonce count. |
| `ocfleet_agent_nonce_rejections_total` | counter | `state=replay,resource_exhausted` | Replay and bounded-capacity nonce rejections. |
| `ocfleet_agent_audit_queue_events` | gauge | none | Events waiting in the durable audit spool. |
| `ocfleet_agent_audit_dropped_total` | counter | none | Events dropped after bounded spool exhaustion. |
| `ocfleet_agent_audit_replayed_total` | counter | none | Events replayed from the spool. |
| `ocfleet_agent_audit_write_failures_total` | counter | none | Primary/spool write failures. |
| `ocfleet_agent_audit_oldest_age_seconds` | gauge | none | Oldest queued event age, or zero when empty. |

Admission permits decrement active gauges on every drop. RPC result classes are
closed mappings from the protocol `ErrorCode` enum; raw error text or codes do
not become labels. The existing private audit JSON snapshot remains available
for local durability troubleshooting but is not served verbatim.
