# B1 Health History, Rollup, And SLO Completion Inventory

Issue `#41` is complete at SQLite schema version 25. This inventory maps the B1
requirements to current implementation and verification evidence. The API
remains read-only and no health path grants an agent, trust, scheduler, shell,
file, service-manager, or generic command capability.

| Requirement | Implementation evidence | Verification evidence | State |
| --- | --- | --- | --- |
| Append-only raw history | Schema 23 `health_history`; evaluator and interactive writers atomically commit history, latest projection, durable evaluation state where applicable, and audit | migration and observability-store history replay/rollback tests | proven |
| 5m, 1h, and 1d rollups | Schema 24 `health_rollups`; aligned bounded recompute uses raw history and typed observations with deterministic watermarks | rollup deterministic unit test; writer idempotency, bound, and audit-failure rollback test | proven |
| Unbiased status slots | Schema 25 requires `health_samples = covered_slots`; the last ordered evaluation in each five-minute slot wins | schema-24 upgrade constraint test and repeated-evaluation rollup unit test | proven |
| 24h, 7d, and 30d availability | CLI `health slo` and read-only `GET /health/slo` use 5m, hourly, and daily rows respectively | SLO projection unit test, fixed-window CLI parser test, API read-only integration test | proven |
| Status durations | Healthy, degraded, unreachable, stale, disabled, and unknown durations are distinct five-minute slot totals | SLO unit/API schemas and exact missing-duration assertions | proven |
| RPC P50/P95 | Each rollup computes nearest-rank P50/P95 from present duration samples; window projection exposes P50 bucket range and maximum bucket P95 without falsely merging quantiles | percentile unit tests and closed OpenAPI response schema | proven |
| Error rate and observation coverage | Only observations with a stored boolean outcome enter the error denominator; health coverage uses distinct five-minute slots | deterministic rollup and SLO missing-coverage tests | proven |
| Certificate risk trend | Warning/critical counters derive only from typed certificate-expiry observation summaries | deterministic rollup unit test and bounded projection schema | proven |
| Configuration drift timeline | Ordered typed fingerprint-prefix samples produce bounded change counters; no configuration content is stored or returned | deterministic rollup unit test and API low-sensitive contract | proven |
| Missing is not unknown | Absent buckets and slots remain absent and produce coverage/missing-duration fields; no backfill fabricates status | migration policy, rollup unit test, API missing-coverage integration test | proven |
| Unknown, stale, unreachable are distinct | Closed health status counters and durations remain separate throughout history, rollup, CLI, and API | schema checks, projection unit test, OpenAPI closed fields | proven |
| Alert independence | Rollup sources query only `health_history` and `probe_observations`; alert tables are not inputs | controller mutation/source guard plus source inspection | proven |
| Independent retention | Fixed `health-history` and `health-rollups` scopes have separate age/row defaults and bounded atomic apply | retention parser/store tests and status documentation | proven |
| Bounded queries | Half-open history/rollup windows, limits, 31-day recompute cap, 100,000-row cap, 1,000-node cap, and fixed SLO windows | CLI rejected-path tests and API malformed/unknown/alignment tests | proven |
| Continuous operation | `health rollup refresh` writes latest closed 5m/1h/1d buckets with input-bound deterministic operation IDs; hardened timer runs every five minutes | refresh closed-bucket, exact-replay, late-input replacement integration test and static systemd boundary test | proven |
| Read-only API boundary | API exposes one GET projection, opens SQLite read-only, never recomputes or invokes RPC, and rejects non-GET methods | router/OpenAPI drift, authenticated viewer, mutation-count, and method rejection tests | proven |

## Operational Notes

Schema 25 deliberately drops only reproducible schema 24 rollup rows. Bootstrap
historical SLO windows with bounded recompute after upgrade, optionally per
node where the fleet-wide 100,000-row cap would be exceeded. The persistent
timer catches up one invocation after downtime but does not invent missed data.

Window-wide quantiles cannot be reconstructed exactly from bucket quantiles.
The API names its latency fields as bucket ranges/maxima; an exact aggregate
would require a future bounded histogram schema rather than invalid percentile
arithmetic.
