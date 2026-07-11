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
- SQLite schema version 9 stores scheduler selectors and explicit path pairs as
  closed schema-tagged v1 payloads. Migration canonicalizes exact legacy rows,
  disables ambiguous empty selectors, and rejects unknown or contaminated data
  after creating the normal private backup. CLI/API readers fail closed and do
  not expose the raw stored objects.
- SQLite schema version 10 stores health degraded methods and derived summaries
  as closed schema-tagged v1 payloads. Migration preserves exact legacy meaning,
  while unsupported methods, unknown fields, invalid bounds, future versions,
  and relational-status mismatches fail closed after private backup.
- SQLite schema version 11 stores probe observation summaries in a closed
  method/result-class-bound payload. Writers and CLI/API readers reject unknown,
  nested, sensitive, address, future-version, and relationally mismatched data.
- SQLite schema version 12 stores observability run summaries in a closed
  job/kind/status/trigger-bound payload with bounded terminal counts. Migration,
  writers, and CLI/API readers reject unknown, contaminated, inconsistent, or
  future-version data.
- SQLite schema version 13 stores endpoint trust bundles in a closed payload
  bound to relational endpoint identity, generation, and lifecycle status.
  Allowlists and explicit path pairs are bounded and unique; contaminated or
  mismatched rows fail closed without creating trust.
- SQLite schema version 14 stores alert details in a closed payload with fixed
  methods, bounded low-sensitive summary fields, and typed transition metadata.
  Migration canonicalizes exact legacy rows; writers and CLI/API readers reject
  unknown, contaminated, malformed, or future-version data.
- SQLite schema version 15 stores alert webhook host allowlists in a closed
  canonical payload bound to the relational endpoint host. Migration preserves
  exact legacy meaning; writers and readers reject unknown, forbidden,
  noncanonical, future-version, or mismatched data.
- SQLite schema version 16 stores enrollment token labels/scope and join-request
  requested/approved labels in closed kind-bound scalar-map payloads. Migration,
  writers, and readers reject unknown, nested, sensitive, malformed,
  future-version, or decision-inconsistent data.
- Node add, enable, disable, and remove now take an explicit resolved actor and
  commit their registry/trust change and success audit in one SQLite
  transaction through `StoreWriter`.
- Endpoint rotation, revocation, and quarantine now execute through
  `StoreWriter` and a closed lifecycle table. Rotation atomically moves the node
  registry pointer; revocation and quarantine disable the current bound node;
  node removal revokes its unique Active trust. Exact no-ops do not increment
  generation or write another audit row.
- Enrollment approval now requires explicit operator-owned node metadata and
  atomically commits the registry node, bound generation-1 trust, request
  decision, and audit through `StoreWriter`. `enroll claim` repairs only the
  strict legacy approved-unbound shape; exact retries are no-ops.
- Enrollment token creation/use, lazy expiry, revocation, and join-request
  rejection now use actor-bearing atomic `StoreWriter` transactions. Stable
  optional `join-<uuid>` request IDs make exact submission retries no-ops,
  compare-and-set usage prevents final-use races, and closed terminal
  transitions reject divergent actors, reasons, or inputs.
- Scheduler job add, enable, and disable now take the resolved actor and commit
  the job configuration change and success audit in one SQLite transaction
  through `StoreWriter`.
- Scheduler run start, bounded outcome, and finish transitions now use explicit
  actor-bound `StoreWriter` transactions. Each observation is paired with an
  RPC or scheduler audit, while finish commits terminal run state and the owning
  job clock together. No SQLite transaction spans RPC or semaphore waits.
- Health `unreachable` now honors the configured consecutive ping-failure
  threshold; a single recent failure is degraded.
- Retention dry-run performs no deletion and writes no audit row.
- Retention policy changes and each non-dry-run scope apply now use
  actor-bearing `StoreWriter` transactions. Stable `retention-<uuid>` operation
  IDs make exact applies replayable without another deletion; all bounded
  batches and their audit commit together or roll back together.
- Health summary/node evaluation now commits its bounded snapshot batch and
  matching low-sensitive audit atomically with replay-safe evaluation IDs.
- Alert candidate evaluation now commits its bounded candidate batch and audit
  atomically. Per-alert before-state checks reject stale evaluations rather
  than overwriting a concurrent silence or resolve decision.
- Alert silence/resolve now compare the persisted before-state and commit the
  transition with actor, reason, and audit atomically. Webhook-hook creation
  commits configuration and its redacted audit in the same transaction.
- Webhook delivery attempts now commit attempt history and a matching audit in
  one transaction. Delivery finalization compare-checks every alert and commits
  all `last_sent_at` updates with the delivery summary audit atomically.
- Scheduler alert evaluation remains local-only and delivery remains an
  explicit CLI action.
- API SQLite startup now validates private database/sidecar files, schema,
  integrity, query-only mode, limits, and viewer authentication.
- CI now checks default and all-feature builds independently and pins Rust
  1.96.1, cargo-deny 0.19.4, and cargo-audit 0.22.2.

### Security

- Controller and scheduler RPC preflight now reject a node whose EndpointID has
  no `endpoint_trust` row before loading controller key material or attempting
  network I/O. Scheduler tasks recheck source and path-target trust after
  concurrency waits at the dispatch boundary. Missing trust is distinct from
  active trust, produces fixed low-sensitive failure codes and rejection
  audits, and is reported by `ocfleet doctor`.
- Active status alone no longer authorizes dispatch. The controller requires an
  enabled registry node, matching node-to-endpoint and trust-to-node pointers,
  and exactly one Active binding. Scheduler workers repeat that full snapshot
  after concurrency waits. Unbound and mismatched source/path-target failures
  use fixed low-sensitive observation codes while retaining protocol-level
  `ENDPOINT_NOT_ALLOWED`.
- `ocfleet doctor` now reports aggregate-only counts for Active unbound rows,
  Active orphans, current binding mismatches, enabled nodes with inactive
  current endpoints, and extra Active bindings. Disabled lifecycle states and
  historical inactive tombstones are not binding-integrity errors.
- Endpoint binding and lifecycle hardening changes no SQLite schema version, RPC
  protocol, agent capability, read-only API route, or default read-only behavior.
- Added audit-insert failure and pre-commit transaction-drop coverage proving
  node registry and endpoint-trust mutations roll back instead of committing
  without audit, plus a CI guard for controller mutation SQL placement.
- Extended the production mutation guard to reject direct node and endpoint
  lifecycle mutator calls outside the reviewed SQLite store/backend boundary.
- Extended the production mutation guard to reject direct enrollment approval
  and legacy-claim mutators, plus token create/revoke and request submit/reject
  mutators. Audit-insert failure, concurrent retry, final-use race, and
  contaminated-state tests cover their all-or-nothing boundaries without
  recording fingerprints, agent keys, hostnames, label values, token hashes,
  or plaintext token material.
- Extended the production mutation guard to reject direct retention policy and
  apply mutators. Audit-trigger, concurrent replay, divergent replay, and
  multi-scope partial-progress tests prove every committed deletion scope has
  exactly one matching audit and no audit failure can leave unaudited deletes.
- Extended the production mutation guard to cover health policy/snapshot and
  alert-evaluation writers. Audit-trigger and stale-before tests prove batch
  rollback, exact retry, actor binding, and concurrent decision preservation.
- Added audit-insert failure coverage proving scheduler job add, enable, and
  disable roll back their `observability_jobs` changes instead of committing
  without audit. Scheduler audit before/after projections use only fixed job
  fields and a closed selector class, not free-form names or selector values.
- Added audit, observation, and job-clock failure injection for scheduler run
  execution. Partial outcome bundles roll back, terminal run rewrites are
  rejected, explicit actors are preserved, and persistence errors leave an
  incomplete `running` marker without advancing the job clock.
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

- Added the authoritative post-audit implementation DAG, machine-readable
  automation progress, all 24 milestone issues, and the atomic-audit ADR.
- Updated status, Phase 12, API, dashboard, collector, trust policy,
  governance, backend, controlled-write, install, security, release, and README
  documentation to match code and tests.
- Added this phase-by-phase implementation summary with verification gaps and
  remaining risks.

### Known limitations

- The collector normalizes operator-supplied aggregate metadata; it does not
  discover live ocserv state or call administration/log/service tools.
- SQLite is the only runtime backend; Postgres always returns unavailable.
- The production controller mutation families in the A1 inventory use atomic
  `StoreWriter` actor/audit transactions. Fixture-only raw helpers are guarded
  from production call sites. Recovery of incomplete scheduler `running` rows
  remains A3 scheduler-reliability work.
- Legacy approved-unbound enrollment rows require an explicit exact `enroll
  claim`; there is intentionally no automatic discovery or repair.
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
