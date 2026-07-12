# ADR: Health History, Rollups, And SLO Projections

## Status

Accepted for B1.

## Context

The latest health snapshot cannot prove historical availability, distinguish a
real `unknown` evaluation from missing collection, or support reproducible
time-window reports. Repeated interactive evaluations can also bias a naive
sample-count availability calculation.

## Decision

Schema 23 stores append-only, evaluation-bound health history. Schema 24 adds
derived 5-minute, hourly, and daily rollups with deterministic source
watermarks and independent retention. Schema 25 rebuilds the reproducible
rollup table and requires exactly one status per covered five-minute slot; the
last ordered evaluation in that slot wins.

Missing slots remain absent. They contribute to coverage and missing-duration
fields, never to `unknown`, `stale`, or `unreachable`. SLO windows use 5-minute
rollups for 24 hours, hourly rollups for 7 days, and daily rollups for 30 days.
Healthy, degraded, unreachable, and stale slots form the availability-eligible
denominator. Disabled and unknown time remains visible but excluded. Healthy
and degraded are service-available; strictly healthy is reported separately.

Stored per-bucket P50/P95 values cannot be merged into an exact window
percentile without retaining a bounded histogram. The projection therefore
reports explicitly named per-bucket P50 ranges and the maximum bucket P95,
rather than claiming a mathematically invalid aggregate percentile.

All queries use fixed windows, aligned half-open boundaries, bounded node and
row counts, and read-only storage access. Rollup recomputation is the only
mutation: it is actor-bound, audited atomically, replay-safe, and never invokes
an agent RPC. The HTTP API exposes projections only and has no recompute route.

## Consequences

- Schema 25 discards schema 24 rollup rows during upgrade. Source history,
  observations, retention policy, and audit evidence remain, so operators can
  recompute without inventing data.
- Coverage and availability have separate denominators and can be interpreted
  without treating collection failure as service failure.
- Certificate and fingerprint trends are counters from present typed
  observations; no certificate material or configuration content is exposed.
- Exact whole-window RPC percentiles require a future bounded histogram schema,
  not arithmetic over bucket percentiles.

