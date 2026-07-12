# ocserv Live Read-Only Provider

This document describes the `collector_snapshot` ocserv read-only provider. It is
an agent-local metadata ingestion path for low-sensitive ocserv observability. It
does not add controller-supplied commands, paths, selectors, service control, or
session inspection.

## Threat Model

The controller is allowed to request only fixed ocserv RPC methods that already
exist in the protocol:

- `ocserv.service.summary`
- `ocserv.version`
- `ocserv.sessions.summary`
- `ocserv.cert.expiry`
- `ocserv.config.fingerprint`

The controller is not trusted to choose local collection sources. In particular,
it must never send a path, command name, service unit, journal selector, config
selector, script, provider selector, or arbitrary payload that changes what the
agent reads locally.

The provider treats the local snapshot file as an agent configuration boundary:
the path is fixed in `agent.toml`, opened through private-file validation, parsed
into a closed schema, and converted into typed DTO fields. Parse failures,
unsafe file permissions, stale timestamps, and unsupported schema versions return
low-sensitive error codes only.

## Allowed Fields

The v2 live snapshot may contain only these fields:

| Field | Meaning | Limit |
| --- | --- | --- |
| `schema_version` | Must be `ocfleet.ocserv.snapshot.v2`. | Exact string. |
| `collected_at` | RFC3339 collection time. | Fresh within 1 hour, max 5 minutes future skew. |
| `collector_status` | `ok`, `partial`, `stale`, `unavailable`, or `unknown`. | Closed enum. |
| `service_state` | Low-sensitive service state. | Closed enum. |
| `enabled_state` | Low-sensitive enabled state. | Closed enum. |
| `version` | Optional ocserv version string. | 64 bytes, printable safe chars. |
| `session_total` | Optional aggregate session count. | No session details. |
| `auth_failure_count_rolling` | Optional rolling aggregate failure count. | `0..=1000000`. |
| `connection_failure_count_rolling` | Optional rolling aggregate failure count. | `0..=1000000`. |
| `cert_min_days_remaining` | Optional aggregate minimum certificate days remaining. | `-3650..=36500`. |
| `config_fingerprint_short` | Optional short hex config fingerprint prefix. | 6-16 hex chars only. |

The agent maps those fields into existing fixed DTOs. `ocfleet ocserv status
--json` includes the aggregate live metadata under `live`; the human output stays
as the existing low-sensitive status summary.

## Forbidden Fields

The snapshot schema rejects unknown fields. It must not include:

- username, account name, user groups, or authentication identity
- client IP, assigned VPN IP, source address, destination address, or port
- session ID, cookie, token, request body, or connection detail
- certificate subject, SAN, issuer, serial, PEM, key material, or full cert text
- config content, config path chosen by the controller, raw logs, raw stdout, or raw stderr
- local command, service unit, journal selector, script, provider selector, or file selector

The provider returns typed DTOs only. It never returns raw collector output.

## Provider Architecture

`collector_snapshot` is a fixed provider mode configured on the agent:

```toml
[ocserv_readonly]
enabled = true
provider = "collector_snapshot"
snapshot_path = "/var/lib/ocfleet-agent/ocserv-live-snapshot.json"

[ocserv_readonly.config_fingerprint]
name = "main"
config_path = "/etc/ocserv/ocserv.conf"
mode = "hmac_sha256"
key_id = "fleet-key-2026-07"
key_path = "/etc/ocfleet-agent/fingerprint.key"

[[ocserv_readonly.certificates]]
name = "server"
cert_path = "/etc/ocserv/server-cert.pem"
```

The controller cannot override `snapshot_path`, `config_path`, fingerprint key
paths, certificate paths,
or provider kind. `snapshot_path` must be absolute, and on Unix the snapshot file
must be a regular single-link private file owned by root or the agent user.

Provider composition remains fixed:

- `ocserv.service.summary`: v2 snapshot-backed service state plus optional live metadata
- `ocserv.version`: v2 snapshot-backed optional version
- `ocserv.sessions.summary`: v2 snapshot-backed optional aggregate count
- `ocserv.cert.expiry`: configured certificate parser
- `ocserv.config.fingerprint`: configured config file hasher

## Local Collector vs Direct Fixed Provider

The repository ships `ocfleet-ocserv-collector` as a local, operator-run,
snapshot-only normalizer for the v2 JSON document. It does not call local service
managers, ocserv administration tools, log readers, shells, or scripts. It reads
a private local TOML input, validates bounded aggregate fields, preserves the
producer-provided `collected_at` timestamp, and writes only the low-sensitive
snapshot schema listed above. Re-running it never refreshes that timestamp.

The collector remains outside controller control:

- local-only configuration
- no controller-selected source or output path
- no raw output persistence
- private atomic snapshot output
- bounded field lengths and counts

See `docs/collector.md` for the CLI, config format, and systemd timer.

## Snapshot Example

```json
{
  "schema_version": "ocfleet.ocserv.snapshot.v2",
  "collected_at": "2026-07-09T12:00:00Z",
  "collector_status": "ok",
  "service_state": "running",
  "enabled_state": "enabled",
  "version": "1.3.0",
  "session_total": 12,
  "auth_failure_count_rolling": 2,
  "connection_failure_count_rolling": 1,
  "cert_min_days_remaining": 42,
  "config_fingerprint_short": "abcdef123456"
}
```

## systemd Timer Example

The repository includes hardened opt-in example units in `deploy/systemd/`.
They run the local normalizer and write the fixed snapshot file. The service is
not controlled by ocfleet and is not invoked by the controller. A timer run
preserves producer time, so it cannot make static values look current.

`/etc/systemd/system/ocserv-metadata-collector.service`:

```ini
[Unit]
Description=ocfleet local ocserv metadata collector

[Service]
Type=oneshot
User=ocfleet
Group=ocfleet
UMask=0077
StateDirectory=ocfleet-agent
StateDirectoryMode=0700
ExecStart=/usr/local/bin/ocfleet-ocserv-collector --config /etc/ocfleet-collector/collector.toml --output /var/lib/ocfleet-agent/ocserv-live-snapshot.json
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ocfleet-agent
ReadOnlyPaths=/etc/ocfleet-collector/collector.toml
```

`/etc/systemd/system/ocserv-metadata-collector.timer`:

```ini
[Unit]
Description=Run ocfleet local ocserv metadata collector periodically

[Timer]
OnCalendar=hourly
AccuracySec=5min
Persistent=false
Unit=ocserv-metadata-collector.service

[Install]
WantedBy=timers.target
```

## Failure Behavior

Provider failures are intentionally low-detail:

- missing or unreadable file: `OCSERV_PROVIDER_UNAVAILABLE`
- stale timestamp: `OCSERV_PROVIDER_UNAVAILABLE`
- unsafe source permissions, symlink, or hardlink: `OCSERV_PROVIDER_UNSAFE_SOURCE`
- unsupported schema, unknown field, invalid enum, invalid timestamp, invalid
  version, invalid ranges, or invalid short fingerprint:
  `OCSERV_PROVIDER_INVALID_DATA`
- file larger than 16 KiB: `OCSERV_OUTPUT_BOUND_EXCEEDED`

Error messages do not include local paths, command strings, log lines, raw output,
or config contents.

## Migration From `snapshot`

Use `provider = "snapshot"` for the original simple typed snapshot:

```json
{
  "service": { "state": "running", "enabled": "enabled" },
  "version": "1.3.0",
  "sessions": { "total": 12 },
  "collected_at": "2026-07-09T12:00:00Z"
}
```

Use `provider = "collector_snapshot"` when a local collector can maintain the v2
flat document with freshness and aggregate failure/certificate metadata. Both
providers preserve the same controller boundary: fixed RPC methods, no
controller-supplied local source, and low-sensitive typed DTO output only.
