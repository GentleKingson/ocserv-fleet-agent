# Implementation Summary

This roadmap automation pass advances the repository toward a conservative
`v0.2.0` read-only release candidate. Source code and tests remain the authority
for every status below.

## Safety Boundary Confirmation

- No shell, raw command, script, generic execution, raw file, raw log, raw
  config, raw certificate, stdout/stderr, user/session, or client-IP interface
  was added.
- No service-manager, ocserv administration tool, or journal passthrough was
  added. There is no live reload, restart, config apply/rollback, or session
  disconnect path in either the default or feature-enabled build.
- API and dashboard routes remain `GET`-only and cannot run jobs, contact
  agents, mutate alerts/retention/trust/registry state, or approve enrollment.
- Trust policy remains validate/diff/review only. There is no TOFU, automatic
  registration, inferred trust, mesh enumeration, or multi-hop relay probe.
- The collector is a local operator-run reduced-snapshot normalizer. Controller
  RPC, scheduler, API, and dashboard code cannot invoke it or choose its paths.

## Phase Status

| Phase | Status | Implemented result |
| --- | --- | --- |
| 1. Repository audit and baseline | Complete at `b3c906a` | `docs/next-roadmap.md` records schema v8, protocol v1, workspace v0.2.0, crates, binaries, features, workflows, baseline tests, drift, milestone issues, and the dependency DAG. |
| 2. CLI observability stabilization | Complete safe slice | Added bounded/fail-closed stored JSON and alert projections, audit-export redaction bounds, private enrollment token reads, retention dry-run no-audit behavior, threshold-correct unreachable health, fixed webhook paths, and rejected-path regression tests. Existing structured CLI assertions cover scheduler, observations, health, alerts, retention, and export surfaces. |
| 3. Read-only API/OpenAPI | Complete | Added OpenAPI 3.1.1 for all 14 `GET` routes, typed envelopes/errors, viewer bearer authentication, strict identifiers/limits/windows, read-only SQLite validation, method rejection, and router/spec drift tests. |
| 4. Read-only dashboard | Complete | Added health, nodes, jobs, runs, observations, alerts, and bounded audit-preview views; explicit `GET` fetches only; CSP and response hardening; forbidden-control tests. |
| 5. Local ocserv collector | Complete constrained implementation | Added `ocfleet-ocserv-collector`, fixed snapshot-v2 validation, private atomic output, snapshot-provider compatibility tests, hardened opt-in systemd units, and operator docs. It deliberately performs no live discovery or local tool invocation. |
| 6. Trust policy as code | Complete review-only implementation | Added TOML/YAML parity, strict explicit-topology validation, deterministic bounded diffs, JSON/Markdown output, private create-new Markdown files, example policy, and CI helper. No apply or agent contact exists. |
| 7. Governance/RBAC foundation | Complete foundation | Actor resolution now fails closed for invalid explicit values, including non-UTF-8 environment data. Fixed viewer/operator/security-admin policy tests exist; API principals remain viewer-only and local CLI RBAC remains intentionally unenforced. |
| 8. Store abstraction | Operationally mature A1 writer slice; implemented A2 storage slices | Added `StoreReader`, `StoreWriter`, `MigrationManager`, and `AuditWriter`; bounded SQLite reads fail closed on contaminated dynamic JSON. Every production mutation family in the A1 inventory uses actor-bearing atomic writers. Schemas 9 through 18 close scheduler selector/pair, health snapshot, observation-summary, run-summary, trust-bundle, alert-detail, webhook-host-allow, enrollment-metadata, delivery-attempt, and audit-detail storage, migrate exact legacy rows, and make readers reject contamination without exposing storage envelopes. API retains a narrower independent read adapter. |
| 8a. Scheduler reliability | Implemented A3 reliability slices | Schemas 19-20 add deterministic fenced claims, lease heartbeat, abandoned-run recovery, bounded misfire coalescing, transient-only retry/backoff under a hard RPC budget, atomically audited global maintenance suppression, audited SIGINT/SIGTERM admission-stop/drain/restart behavior, per-attempt timeouts, and deterministic bounded jitter. The final completion-matrix audit remains active A3 work. |
| 9. Optional Postgres backend | Complete non-connecting scaffold | Added default-off `postgres-backend`, redacted/validated connection-source types, and an always-unavailable connection stub. No client, DSN logging, schema, migration, import, or runtime selection exists. |
| 10. Controlled writes | Complete dry-run design slice | Added default-off typed DTO/config validation, redacted request `Debug`, signed-intent and rollback consistency checks, outage acknowledgement, and tests proving default and feature-enabled agents still reject every write RPC. No dispatch exists. |
| 11. CI and release readiness | Complete workflow slice | Pinned Rust 1.96.1 and actions, preserved least privilege, added default/all-feature gates, cargo-deny/audit jobs, tag-bound draft release assembly for four binaries on two architectures, release-version attack tests, install smoke coverage, and v0.2.0 install/release docs. |

## Verification

The completed local verification set is recorded here so future release review
can distinguish source checks from CI-only runtime checks:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace -j1 -- --test-threads=1`
- `cargo test --workspace --all-features -j1 -- --test-threads=1`
- crate-specific API, CLI, agent, config, and protocol tests, including
  all-feature controlled-write rejection
- `bash scripts/check-doc-claims.sh`
- `bash scripts/check-controller-mutations.sh`
- `bash scripts/tests/test-controller-mutation-guard.sh`
- `./scripts/check-github-actions-pinning.sh`
- `./scripts/test-release-version-validation.sh`
- `CARGO="$HOME/.cargo/bin/cargo" ./scripts/build-release.sh v0.2.0`
- `./scripts/verify-checksums.sh dist/v0.2.0/SHA256SUMS`
- `CARGO="$HOME/.cargo/bin/cargo" ./scripts/check-trust-policy.sh examples/trust-policy.toml`
- `actionlint .github/workflows/*.yml`
- `shellcheck` for the changed release, smoke, trust, and workflow-check scripts

`cargo-deny` and `cargo-audit` were not installed in the local environment, so
their pinned GitHub Actions jobs are the verification path for this candidate.

## Remaining Risks And Follow-up

- Convert every dynamic controller JSON column to a closed typed storage schema;
  current writes are bounded and reject forbidden content, and outputs apply
  typed projections, but some internal records still use `serde_json::Value`.
- Keep the completed A1 production mutation inventory and source guard current
  as new features are added. Health snapshot batches and alert candidate
  evaluation commit atomically with audit; candidate writes reject stale
  before-state. Scheduler job and run/outcome/finish writers
  now use short atomic boundaries without holding a transaction across RPC;
  incomplete outcome or finish persistence remains a durable `running` row for
  later scheduler recovery work. This changes no schema, protocol, or API route.
- Keep every controller and scheduler RPC gate fail closed on missing, inactive,
  unbound, mismatched, stale, disabled, or ambiguous endpoint trust. Dispatch now
  requires an enabled registry node with matching bidirectional pointers and one
  Active binding, and scheduler workers repeat the full source/target snapshot
  after concurrency waits. Lifecycle transitions keep the node pointer and trust
  state together, while doctor reports aggregate binding counts. This changes no
  schema, protocol, or API route.
- Enrollment approval now atomically creates the explicit operator-owned node,
  bound generation-1 trust, request decision, and low-sensitive audit. `enroll
  claim` reconciles only the strict legacy approved-unbound shape. Hostname and
  labels never select node identity, and there is no startup or dispatch repair.
  Exact retries are no-ops and divergent or contaminated state fails closed.
- Enrollment token creation/use, lazy expiry, revocation, and request rejection
  now commit state and low-sensitive audit together. Stable optional request IDs
  make exact submissions idempotent, final-use races serialize, and divergent
  actor/reason/input retries fail closed without token or submitted-identity
  material in audit or `Debug` output.
- Retention policy changes and each non-dry-run scope apply now commit state and
  low-sensitive audit together. Apply operation IDs prevent duplicate limited
  deletion, all bounded batches roll back on audit failure, and multi-scope
  retries resume from independently audited scopes. Dry-run/explain remain
  query-only and controller audit is never a retention target.
- Consolidate the API-specific read adapter with the backend-neutral reader only
  after their projection contracts can remain equally strict.
- Add a real Postgres client/schema/import path only as a separately reviewed,
  default-off implementation. SQLite remains the sole runtime backend.
- A browser runtime was unavailable for screenshot-based dashboard QA; HTTP,
  CSP, forbidden-action, and read-only interaction behavior is covered by API
  integration tests.
- The local Darwin/aarch64 four-binary release build and checksums passed. Linux
  x86_64/aarch64 builds and the Docker distro matrix remain CI responsibilities;
  do not mark a release publishable until those tag-bound jobs, cargo-deny,
  cargo-audit, and CodeQL pass.
- Structured integration assertions cover the current CLI contract. Dedicated
  serialized golden files for every listed command remain optional future drift
  hardening rather than a release claim.
