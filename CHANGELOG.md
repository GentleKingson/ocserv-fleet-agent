# Changelog

## Unreleased

### Added

- OpenAPI 3.1.1 contract and drift tests for the 14-route `GET`-only API.
- Read-only dashboard views for fleet health, nodes, jobs, runs, observations,
  alerts, and bounded audit previews.
- Local `ocfleet-ocserv-collector` reduced-snapshot normalizer, compatibility
  tests, hardened opt-in systemd units, and operator documentation.
- TOML/YAML trust-policy validation with deterministic JSON and bounded private
  Markdown review output.
- Viewer/operator/security-admin policy vocabulary and fail-closed actor tests.
- Backend reader/writer/migration/audit traits with bounded SQLite reads.
- Default-off, non-connecting Postgres backend scaffold.
- Default-off controlled-write DTO/config preflight scaffold with no dispatch.
- `v0.2.0` release notes, pinned toolchain, four-binary/two-architecture draft
  release assembly, and malicious-version regression tests.

### Changed

- Workspace packages now report version `0.2.0`.
- Health `unreachable` now honors the configured consecutive ping-failure
  threshold; a single recent failure is degraded.
- Retention dry-run performs no deletion and writes no audit row.
- Scheduler alert evaluation remains local-only and delivery remains an
  explicit CLI action.
- API SQLite startup now validates private database/sidecar files, schema,
  integrity, query-only mode, limits, and viewer authentication.
- CI now checks default and all-feature builds independently and pins Rust
  1.96.1, cargo-deny 0.19.4, and cargo-audit 0.22.2.

### Security

- Added bounded low-sensitive storage validation and fail-closed reader checks
  for observability/audit JSON, including secret aliases, addresses, raw
  fields, excessive nesting, entry counts, and string sizes.
- Added bounded recursive audit-export redaction and contaminated legacy-row
  regression tests.
- Hardened webhook URLs to HTTPS, explicit allowlisted public hosts, no query or
  redirects, and a fixed non-secret path catalog.
- Enrollment, webhook, audit-export, collector, trust Markdown, and release
  files use private-file/symlink/hardlink protections appropriate to each flow.
- Controlled-write request debug output redacts actor, reason, signed material,
  and params; feature-enabled agents still return method-not-allowed.
- API/dashboard remain read-only and trust remains explicit with no TOFU,
  automatic authorization, mesh enumeration, or live ocserv mutation.

### Documentation

- Updated status, Phase 12, API, dashboard, collector, trust policy,
  governance, backend, controlled-write, install, security, release, and README
  documentation to match code and tests.
- Added this phase-by-phase implementation summary with verification gaps and
  remaining risks.

### Known limitations

- The collector normalizes operator-supplied aggregate metadata; it does not
  discover live ocserv state or call administration/log/service tools.
- SQLite is the only runtime backend; Postgres always returns unavailable.
- Some legacy controller mutations have not yet moved to atomic StoreWriter
  actor/audit transactions.
- Controlled writes are validation-only scaffolding and have no live code path.
- API TLS termination remains an external deployment responsibility.
- Browser screenshot QA, cargo-deny, cargo-audit, Linux multi-architecture
  release builds, and Docker distro smoke require their documented CI environments.

## v0.1.0 - 2026-07-07

- Ships the read-only MVP controller CLI and node agent.
- Adds fixed RPCs for `node.ping`, `node.info`, `probe.controller.ping`,
  `probe.peer.echo`, and `probe.path.echo`.
- Stores controller registry and controller audit records in SQLite.
- Uses persistent iroh SecretKeys and EndpointID allowlists.
- Adds `ocfleet doctor` with human and JSON output for read-only controller
  diagnostics.
- Adds durable agent audit fallback with append-only spool replay and metrics
  snapshots.
- Adds local E2E coverage for controller-to-agent, one-hop source-to-target path
  probes, EndpointID mismatch, nonce replay, expired requests, unknown peers,
  and missing path authorization.
