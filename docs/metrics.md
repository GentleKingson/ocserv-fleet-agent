# Metrics

## Exposure

The controller exports Prometheus text at `GET /metrics` on `ocfleet-api`.
`ocfleet-api` is loopback-only by default. The existing startup rule requires a
private bearer-token file for every non-loopback listener, and `/metrics` uses
the same authorization middleware as all other read-only routes.

```bash
ocfleet-api --database controller.sqlite --read-only --listen 127.0.0.1:8080
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
| `ocfleet_controller_observations_total` | counter | none | Persisted observations. |
| `ocfleet_controller_observation_freshness_seconds` | gauge | none | Age of the newest observation. |
| `ocfleet_controller_sqlite_bytes` | gauge | none | Main SQLite database file size. |
| `ocfleet_controller_audit_exports_total` | counter | `result=succeeded,failed` | Audited export attempts. |

Every scrape opens SQLite read-only with query-only and untrusted-schema modes.
The endpoint performs fixed aggregate queries and does not trigger RPC,
scheduler, evaluator, delivery, retention, export, or any controller mutation.

## Agent Status

The existing agent audit durability JSON snapshot remains private local state;
it is not the A7 Prometheus exporter. Agent transport/RPC/nonce/audit catalog and
loopback-by-default protected exposition are the next A7 slice.

