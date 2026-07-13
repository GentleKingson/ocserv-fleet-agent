# ocserv read-only RPC spec

## Goal

Phase 11 adds the first ocserv-aware observation surface for `ocserv-fleet-agent`.
It is intentionally low-sensitive, read-only, bounded, and fixed-schema:

```text
controller -> fixed RPC -> agent -> fixed ocserv readonly provider -> typed response
```

The goal is observability, not ocserv management.

## Non-goals

Phase 11 does not provide service control, reload, restart, config apply,
rollback, user management, user disconnect, session detail listing, generic file
reads, generic command execution, or arbitrary data-source selection.

## Threat Model

The controller is trusted only as an RPC caller. It is not trusted to choose
agent-local paths, service names, command lines, journal queries, regexes,
scripts, hosts, or ports. The agent must derive all ocserv data sources from its
local static config and must return only typed low-sensitive summaries.

## Data Sensitivity Classification

Allowed low-sensitive fields:

- service state enum
- service enabled enum
- version string capped at 64 bytes
- aggregate session count
- certificate validity timestamps, days remaining, status enum, and SHA-256 fingerprint
- opaque config SHA-256 fingerprint
- bounded source/freshness metadata without paths or command names

Forbidden fields:

- ocserv config content
- certificate PEM or DER content
- private key content or paths
- usernames
- client IP addresses
- session IDs
- device details
- logs
- unit files
- full command lines
- environment variables
- complete local filesystem paths

## Allowed RPC Methods

Only these fixed methods are allowed:

```text
ocserv.service.summary
ocserv.version
ocserv.sessions.summary
ocserv.cert.expiry
ocserv.config.fingerprint
```

Each request must use `null` params or `{}`. Request structs are empty and do not
contain selectors.

## Forbidden Interfaces

Phase 11 must not add or expose:

```text
shell.exec
command.run
ocserv.exec
ocserv.raw
file.read
systemctl.raw
occtl.raw
journalctl.raw
```

It must not return passthrough output from service managers, ocserv control
tools, journal/log readers, or files.

## Provider Contract

Providers must implement a fixed `OcservReadonlyProvider` trait and return typed
protocol structs. Unsupported data must be reported as `unknown` or
`unavailable`, or as a low-sensitive typed error. A provider must not call a
dangerous data source to fill a missing field.

Production provider code for Phase 11 is limited to:

- a disabled provider
- a typed snapshot provider for service summary, version, and session summary
- a typed `collector_snapshot` provider for fixed v2 low-sensitive live metadata
- certificate expiry parsing from configured certificate files
- config fingerprint hashing from a configured config file

Provider composition is fixed. `provider = "snapshot"` currently means:

- `ocserv.service.summary`: snapshot-backed
- `ocserv.version`: snapshot-backed
- `ocserv.sessions.summary`: snapshot-backed
- `ocserv.cert.expiry`: configured certificate parser
- `ocserv.config.fingerprint`: configured config file hasher

`provider = "collector_snapshot"` currently means:

- `ocserv.service.summary`: v2 snapshot-backed service state plus optional
  aggregate live metadata
- `ocserv.version`: v2 snapshot-backed optional version
- `ocserv.sessions.summary`: v2 snapshot-backed optional aggregate session count
- `ocserv.cert.expiry`: configured certificate parser
- `ocserv.config.fingerprint`: configured config file hasher

The snapshot file is not an RPC selector. It is local static agent config.
Controller RPC params cannot override `snapshot_path`, certificate paths,
config paths, service names, command names, unit names, or journal sources.

On Unix, provider files are opened with no-symlink fd semantics and validated
after open. Snapshot files must be regular, single-link, owned by root or the
agent user, and private to owner (`0600` or stricter). Certificate and config
fingerprint files may be group/world readable, but must be regular, single-link,
owned by root or the agent user, and not group/world writable.

## Agent Config

Default:

```toml
[ocserv_readonly]
enabled = false
provider = "disabled"
```

Snapshot example:

```toml
[ocserv_readonly]
enabled = true
provider = "snapshot"
snapshot_path = "/var/lib/ocfleet-agent/ocserv-readonly.json"

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

Validation rules:

- `enabled=true` requires an explicit provider.
- provider is `disabled`, `snapshot`, or `collector_snapshot`.
- configured paths must be absolute.
- certificate and fingerprint names are `[A-Za-z0-9_.-]`, max 64 bytes.
- at most 8 certificates are configured.
- unknown config fields are rejected.
- controller RPC params cannot override configured paths.

Collector snapshot example:

```toml
[ocserv_readonly]
enabled = true
provider = "collector_snapshot"
snapshot_path = "/var/lib/ocfleet-agent/ocserv-live-snapshot.json"
```

See [`ocserv-live-readonly-provider.md`](ocserv-live-readonly-provider.md) for
the v2 schema, freshness rules, local collector model, and migration notes.

## RPC Schemas

All responses include:

```rust
OcservReadonlyMeta {
    source,
    collected_at,
    freshness,
}
```

`source` is one of `provider`, `snapshot`, or `unavailable`. It never contains a
path, command, unit name, or log name.

`collected_at` must be bounded to 64 bytes, contain no control characters, and
parse as RFC3339. Response metadata must not contain paths, command markers, log
markers, or source selector text.

`ocserv.service.summary` returns `state`, `enabled`, and optional `since`.

`ocserv.version` returns optional `version` and a field status.

`ocserv.sessions.summary` returns optional aggregate `total` and a field status.

`ocserv.cert.expiry` returns up to 8 logical certificate entries with validity,
days remaining, status, and SHA-256 fingerprint.

`ocserv.config.fingerprint` returns algorithm `sha256`, optional 64-byte hex
hash, and a field status.

## CLI Behavior

`ocfleet ocserv status <node>` calls service summary, version, sessions summary,
and config fingerprint. Human output is key-value low-sensitive summary. It
returns `status=ok` when all four sub-RPCs succeed. It returns `status=degraded`
when at least one but not all sub-RPCs fail, with unavailable fields rendered as
`<unavailable>` and `degraded_methods` listing only fixed method names. It fails
only when all status sub-RPCs fail or when preflight checks fail.

`ocfleet ocserv cert <node>` calls certificate expiry and prints logical cert
name, status, expiry, days remaining, and fingerprint.

`ocfleet ocserv sessions summary <node>` calls sessions summary and prints only
the aggregate count.

The CLI does not accept ocserv-specific `--host`, `--port`, `--path`,
`--command`, `--unit`, or similar selector flags.

Human CLI output shortens certificate and config fingerprints for readability.
Use `--json` for the complete typed response with full 64-hex SHA-256 values.

## Audit Rules

Controller command-level audit events:

```text
ocserv.status
ocserv.cert
ocserv.sessions.summary
```

Controller RPC-level audit records include node ID, endpoint ID, method, request
ID, ok/error code, duration, params hash, and `result_class =
low_sensitive_summary`. They do not store full response bodies.

Ocserv CLI command audit details are metadata-only. Decode failures use the
fixed message `ocserv readonly response schema is invalid`; raw serde field
paths, response bodies, provider text, local paths, command output, and log text
must not be written to audit detail. Degraded status audit records list fixed
method names, not raw error messages.

Agent audit records include method, params hash, ok/error code, duration,
response size, and `result_class = low_sensitive_summary`. They do not store
full response bodies.

## Error Model

Low-sensitive ocserv error codes:

```text
OCSERV_READONLY_DISABLED
OCSERV_PROVIDER_UNAVAILABLE
OCSERV_PROVIDER_INVALID_DATA
OCSERV_PROVIDER_UNSAFE_SOURCE
OCSERV_OUTPUT_BOUND_EXCEEDED
OCSERV_UNSUPPORTED_FIELD
```

Error messages are sanitized and capped at 128 bytes. They must not include
local paths, file snippets, parser dumps, certificate material, config content,
logs, raw stdout/stderr, session/user identifiers, client addresses, certificate
subject/SAN/issuer/serial data, or command output.

## Bounds And Redaction

Limits:

- version string: 64 bytes
- logical cert name: 64 bytes
- cert entries: 8
- snapshot file: 16 KiB
- config file hashed: 1 MiB
- certificate file parsed: 1 MiB
- response JSON: 8 KiB
- error message: 128 bytes

All scalar fields reject control characters. Config fingerprints are opaque
byte-level SHA-256 drift fingerprints, not semantic normalized config summaries
and not secrecy-preserving digests. Human output shows only a short prefix; JSON
typed DTO output may include the full hash.

Phase 11.1 may replace or supplement SHA-256 with HMAC-SHA-256 once a fleet-level
fingerprint key model is designed.

## Test Requirements

Tests must prove:

- fixed method names are the only allowed ocserv RPCs
- request params reject controller-supplied source selectors
- response schemas are closed typed structs
- version, fingerprint, cert count, and file-size bounds are enforced
- session summary returns only aggregate count
- cert output excludes PEM, DER, subject, SAN, and paths
- config fingerprint output excludes config content and paths
- provider source does not introduce dangerous adapters
- CLI output and audit details are low-sensitive

## Future Extension Rules

Future ocserv RPCs must update this spec before implementation. New fields must
be classified, bounded, tested, and represented as typed protocol structs. New
providers must keep the controller unable to choose local data sources.
