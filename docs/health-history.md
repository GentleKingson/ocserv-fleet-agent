# Health History And SLOs

## Append-Only History

Schema 23 adds `health_history`. Every successful evaluator finish atomically
inserts one sample per node while updating the latest-per-node
`health_snapshots` projection and committing the evaluator audit. Interactive
health summary/node writes use the same atomic path. Exact replay returns before
insertion, and `(evaluation_id, node_id)` prevents duplicates. Audit failure
rolls back the history and latest projection together.

Existing latest snapshots are not backfilled during migration because their
original evaluation identity cannot be proven. History begins with the first
successful post-upgrade evaluation and never invents missing samples.

The bounded read command uses a half-open time window:

```bash
ocfleet health history \
  --from 2026-07-11T00:00:00Z \
  --to 2026-07-12T00:00:00Z \
  --node hk-ocserv-01 \
  --limit 100 \
  --json
```

`--from` must precede `--to`; `--limit` is `1..=1000`; the optional node ID is
validated. Results contain only the low-sensitive health projection, not raw
observations, RPC bodies, addresses, users, sessions, paths, secrets,
certificate material, or storage envelopes.

## Independent Retention

`health-history` is separate from `health-snapshots`. Its default is 90 days
and 1,000,000 rows. Existing retention dry-run, stable-operation-ID,
bounded-batch, and atomic-audit behavior applies. Expired history deletion does
not delete the latest projection or controller audit evidence.

## Reproducible Rollups

Schema 24 adds bounded, deterministic 5-minute, 1-hour, and 1-day rollups.
Recomputation reads append-only health history and stored probe observations;
it never converts a missing five-minute slot into an `unknown` sample. Each row
therefore reports both `covered_slots` and `expected_slots`, alongside distinct
healthy, degraded, unreachable, stale, disabled, and unknown sample counts.

```console
ocfleet health rollup recompute \
  --from 2026-07-01T00:00:00Z \
  --to 2026-07-02T00:00:00Z \
  --bucket 1h \
  --json

ocfleet health rollup list \
  --from 2026-07-01T00:00:00Z \
  --to 2026-07-02T00:00:00Z \
  --bucket 1h \
  --limit 1000 \
  --json
```

Recompute windows must be aligned to the requested bucket, cannot exceed 31
days, and cannot produce more than 100,000 rows. Supplying an operation ID in
`health-rollup-<uuid>` form makes an exact retry audit-idempotent. Rows include
a deterministic input watermark and use the bucket end as `computed_at`, so
the same stored inputs produce the same row. Rollups have independent
`health-rollups` retention, defaulting to 1,095 days and 5,000,000 rows.

Schema 25 tightens availability semantics to exactly one status per
five-minute slot: the last evaluation in a slot wins. Because schema 24 rows
cannot be converted without bias, the migration drops only the derived rollup
table contents; append-only source history, observations, audit evidence, and
retention policy remain intact. Operators must recompute the desired windows
after upgrade.

## Bounded SLO Projections

The CLI and read-only API project fixed 24-hour, 7-day, and 30-day windows from
stored 5-minute, hourly, and daily rollups respectively. The window end is
required and bucket-aligned, which makes the same request reproducible.

```console
ocfleet health slo --window 24h --to 2026-07-12T00:00:00Z --node node-a --json
curl 'http://127.0.0.1:8080/health/slo?window=7d&to=2026-07-12T00:00:00Z&node_id=node-a'
```

Coverage uses five-minute slots. Missing slots and missing duration are
reported separately and are never changed into unknown, stale, or unreachable
samples. `service_available_basis_points` treats healthy and degraded samples
as service-available; `strictly_healthy_basis_points` counts only healthy
samples. Both use healthy, degraded, unreachable, and stale slots as the
availability-eligible denominator; disabled and unknown durations remain
visible but are not silently classified as downtime. Coverage has its own
full-window denominator. Observation error ratios likewise use
only observations with a stored boolean outcome.

Latency fields are deliberately named as ranges or maxima of the stored
per-bucket quantiles; they are not presented as mathematically merged window
percentiles. Certificate warning/critical and fingerprint change counters are
derived only from present typed observations. Fleet queries are capped at the
smaller of the configured API maximum and 1,000 nodes. Each node reads at most
288, 168, or 30 rollup rows for the 24-hour, 7-day, or 30-day window.

## Remaining B1 Work

Completion evidence and operational scheduling for continuous rollup refresh
remain before B1 can be marked operationally mature.
