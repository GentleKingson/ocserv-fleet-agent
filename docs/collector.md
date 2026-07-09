# Local ocserv Metadata Collector

`ocfleet-ocserv-collector` is an agent-local, operator-controlled normalizer for the
`ocfleet.ocserv.snapshot.v2` JSON document consumed by the agent
`collector_snapshot` provider.

It is intentionally snapshot-only. It does not run local administration tools,
read service journals, execute shell commands or scripts, inspect sessions, read
raw config, read certificates, or accept controller-provided paths/selectors.
It does not discover metadata itself: a local producer or operator supplies only
the already-reduced aggregate fields and their original `collected_at` timestamp
in its private config. The normalizer preserves that timestamp exactly; reruns
cannot make old values appear fresh. No agent RPC, scheduler, API, or dashboard
path invokes this binary.

## CLI

```bash
ocfleet-ocserv-collector --print-example-config

ocfleet-ocserv-collector \
  --check \
  --config /etc/ocfleet-collector/collector.toml \
  --output /var/lib/ocfleet-agent/ocserv-live-snapshot.json

ocfleet-ocserv-collector \
  --config /etc/ocfleet-collector/collector.toml \
  --output /var/lib/ocfleet-agent/ocserv-live-snapshot.json
```

The config file must be a private local file. If `output_path` is present in the
config, `--output` must match it. Output is written with an atomic private-file
replace and remains owner-only readable/writable on Unix.

`--check` parses and validates the config and output target without creating or
replacing the snapshot. The output target must name a regular file below an
owner-only directory. Parent traversal, symlinks, hard links, and an existing
non-private file are rejected. A missing output directory is created as `0700`
only during a real write; the snapshot is `0600`.

## Config

```toml
service_identity = "ocserv"
output_path = "/var/lib/ocfleet-agent/ocserv-live-snapshot.json"
collected_at = "2026-07-09T12:00:00Z"
collector_status = "unknown"
service_state = "unknown"
enabled_state = "unknown"

# Optional low-sensitive aggregate fields.
version = "ocserv 1.3.0"
session_total = 0
auth_failure_count_rolling = 0
connection_failure_count_rolling = 0
cert_min_days_remaining = 90
config_fingerprint_short = "abcdef12"
```

Allowed enum values:

- `collector_status`: `ok`, `partial`, `stale`, `unavailable`, `unknown`
- `service_state`: `running`, `stopped`, `failed`, `starting`, `stopping`,
  `unknown`, `unavailable`
- `enabled_state`: `enabled`, `disabled`, `static`, `unknown`, `unavailable`

The collector rejects unknown config fields, out-of-range aggregate counts,
unsafe version strings, invalid short config fingerprints, invalid producer
timestamps, and timestamps more than five minutes in the future. It does not
replace an old producer timestamp with its own clock.

## Output

```json
{
  "schema_version": "ocfleet.ocserv.snapshot.v2",
  "collected_at": "2026-07-09T12:00:00Z",
  "collector_status": "ok",
  "service_state": "running",
  "enabled_state": "enabled",
  "version": "ocserv 1.3.0",
  "session_total": 7,
  "auth_failure_count_rolling": 2,
  "connection_failure_count_rolling": 3,
  "cert_min_days_remaining": 42,
  "config_fingerprint_short": "abcdef12"
}
```

The output must not contain usernames, accounts, client or VPN IPs, ports,
session IDs, cookies, tokens, certificate subject/SAN/issuer/serial/PEM/key
material, raw config, raw logs, stdout/stderr, local command text, journal
selectors, scripts, or file selectors.

## systemd

Example units are provided:

- `deploy/systemd/ocserv-metadata-collector.service`
- `deploy/systemd/ocserv-metadata-collector.timer`

They use `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=strict`,
`ProtectHome=true`, `UMask=0077`, and a narrow `ReadWritePaths` entry for the
snapshot directory. The service also has no network namespace, drops all
capabilities, and uses `StateDirectoryMode=0700`. Install the collector config
as an `ocfleet`-owned `0600` file at
`/etc/ocfleet-collector/collector.toml` below an `ocfleet`-owned `0700`
directory. `ProtectSystem=strict` and `ReadOnlyPaths` keep it read-only inside
the service. The controller must never manage or replace it.

The timer is an opt-in deployment example, not an enabled default. It runs at
most hourly and merely revalidates the local producer document. Since
`collected_at` is preserved, repeated timer runs do not extend freshness; the
agent provider continues to reject snapshots older than its bounded freshness
window.
