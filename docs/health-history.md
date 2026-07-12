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

## Remaining B1 Work

Reproducible 5-minute, 1-hour, and 1-day rollups and bounded 24-hour, 7-day,
and 30-day SLO CLI/API projections remain. They must distinguish unknown,
stale, unreachable, and missing duration and derive latency, error, certificate
risk, and drift only from present typed observations.
