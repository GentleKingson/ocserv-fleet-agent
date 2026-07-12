# A7 Low-Cardinality Metrics Inventory

This inventory closes the A7 acceptance audit. Both exporters are operational
metadata surfaces only: they are loopback by default, require authentication
for non-loopback listeners, and expose a closed metric and label catalog.

## Requirement Evidence

| Requirement | Metric or control | Implementation and verification |
| --- | --- | --- |
| Agent handshake active/rejected | `ocfleet_agent_handshakes{state}` | Live admission permits and rejection paths in `crates/ocfleet-agent/src/server.rs`; rendering and bounded-label tests in `crates/ocfleet-agent/src/metrics.rs`. |
| Agent connection active/rejected | `ocfleet_agent_connections{state}` | Connection permits increment/decrement on acquisition/drop and count limiter rejection in `server.rs`; metric tests cover active state. |
| Agent stream active/rejected | `ocfleet_agent_streams{state}` | Stream permits and limit rejection use the same drop-safe instrumentation in `server.rs`. |
| Agent RPC duration and result | `ocfleet_agent_rpc_duration_milliseconds_{sum,count}`, `ocfleet_agent_rpc_calls_total{state}`, `ocfleet_agent_rpc_results_total{state}` | Every response is timed and classified through the closed protocol `ErrorCode` mapping; no raw code or error text becomes a label. |
| Agent nonce cache and rejection | `ocfleet_agent_nonce_cache_size`, `ocfleet_agent_nonce_rejections_total{state}` | Live cache size plus closed `replay` and `resource_exhausted` counters are wired in nonce validation paths. |
| Agent audit queue/spool and failures | `ocfleet_agent_audit_queue_events`, `ocfleet_agent_audit_dropped_total`, `ocfleet_agent_audit_replayed_total`, `ocfleet_agent_audit_write_failures_total`, `ocfleet_agent_audit_oldest_age_seconds` | `AuditMetricsSnapshot` reports the durable spool event count, exhaustion, replay, primary/spool write failures, and oldest queued age. |
| Controller scheduler due/executed/skipped and lease state | `ocfleet_controller_scheduler_jobs_due`, `ocfleet_controller_scheduler_runs_total{result}`, `ocfleet_controller_scheduler_claims_active` | Fixed read-only aggregates cover due jobs, running/succeeded/failed/skipped runs, and unexpired claims. |
| Controller RPC duration/error | `ocfleet_controller_rpc_duration_milliseconds_{sum,count}`, `ocfleet_controller_rpc_calls_total{result}` | Fixed aggregates over closed `rpc.completed` audit rows; integration tests cover the series. |
| Controller observation freshness | `ocfleet_controller_observations_total`, `ocfleet_controller_observation_freshness_seconds` | Fixed observation count and newest-observation age queries. |
| Controller health counts | `ocfleet_controller_health_nodes{status}` | Closed `healthy`, `degraded`, `unreachable`, and `unknown` states. |
| Controller alert states | `ocfleet_controller_alerts{state}` | Closed `open`, `silenced`, and `resolved` states. |
| Controller delivery attempts/failures/dead-letter | `ocfleet_controller_delivery_attempts_total{result}`, `ocfleet_controller_delivery_queue{state}` | Attempt result counters and closed queue states including `dead_letter`. |
| Controller SQLite size | `ocfleet_controller_sqlite_bytes` | Main database file metadata only; no path label or value is exposed. |
| Controller retention deleted rows | `ocfleet_controller_retention_deleted_rows_total` | Sum of bounded `deleted_count` from successful, closed `retention.apply` audit details. |
| Controller audit export result | `ocfleet_controller_audit_exports_total{result}` | Successful/failed closed audit export result counts. |

## Exposure And Mutation Boundary

- Controller metrics use the existing read-only `GET /metrics` API route and
  `ApiReadStore`. Each scrape opens SQLite read-only with `query_only` and
  `trusted_schema=OFF`; it cannot schedule work or invoke a controller writer.
- The controller API is loopback-only by default. Existing startup validation
  requires a private bearer token and a TLS-terminating deployment boundary for
  non-loopback listeners, and the metrics route shares API authorization.
- Agent metrics listen on `127.0.0.1:9090` by default. Non-loopback startup is
  rejected without a private bearer-token file and additionally requires a TLS
  reverse proxy and network restriction.
- Exporter tests cover authorization, route bounds, content type, and the
  absence of usernames, EndpointIDs, IPs, addresses, sessions, request IDs,
  tokens, paths, raw errors, and other identity or data-derived fields.

## Cardinality And Sensitivity

The complete catalog and sensitivity guidance live in `docs/metrics.md`.
Controller labels are limited to `result`, `status`, and `state`, with no more
than five compile-time values per family. Agent labels use only `state`, with
closed admission states, RPC outcomes, protocol result classes, and nonce
rejection classes. Metric descriptor tests fail if forbidden label fragments or
unbounded values enter either catalog. Fleet activity and health rates remain
operationally sensitive, so authenticated non-loopback exposure is mandatory.

## Verification

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features`
- API integration tests prove `/metrics` remains read-only and does not change
  the database, while agent and controller unit tests verify the closed catalog,
  live counters, permit cleanup, authentication, and privacy constraints.

