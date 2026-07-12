# Execution Roadmap

This document is the authoritative execution DAG for work after the repository
baseline at commit `b3c906a94823b4620dc1a2077a44e7160c0848b2`. When status or
ordering here conflicts with `docs/roadmap.md` or a historical implementation
summary, this document controls. Source, tests, migrations, and released
artifacts remain the final evidence for implementation claims.

The default build remains read-only. No milestone may add a shell, generic
command executor, arbitrary file RPC, raw administration-tool passthrough,
automatic trust, automatic peer mesh, or automatic path-probe authorization.

## Baseline

| Item | Audited state |
| --- | --- |
| Baseline commit | `b3c906a94823b4620dc1a2077a44e7160c0848b2` |
| Workspace | Version `0.2.0`, Rust edition `2024`, Rust toolchain `1.96.1` |
| Workspace crates | Five: `ocfleet-protocol`, `ocfleet-config`, `ocfleet-agent`, `ocfleet-cli`, and `ocfleet-api` |
| Release binaries | Four: `ocfleet`, `ocfleet-agent`, `ocfleet-api`, and `ocfleet-ocserv-collector` |
| Controller schema | SQLite schema version `8`; migrations `0001` through `0008` |
| RPC protocol | Protocol version `1`; ALPN `/com.github.gentlekingson.ocfleet.mgmt/1` |
| Other schemas | Config version `1`; trust-policy version `1`; collector snapshot `ocfleet.ocserv.snapshot.v2`; OpenAPI `3.1.1` |
| Features | Every crate has an empty default feature set. `controlled-writes` exists in protocol/config/agent and is propagated by the agent. `postgres-backend` exists in the CLI. Both tracks are default-off. |
| Runtime backends | SQLite only. The Postgres feature is a non-connecting scaffold. |
| HTTP API | Experimental version `0.2.0`; fourteen declared `GET` paths including the dashboard root; API data access is SQLite read-only. |

The baseline audit found no failing required check. These commands passed at the
baseline commit:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace -j1 -- --test-threads=1
cargo test --workspace --all-features -j1 -- --test-threads=1
bash scripts/check-doc-claims.sh
./scripts/check-github-actions-pinning.sh
./scripts/test-release-version-validation.sh
```

CI-only or platform-specific release, supply-chain, browser, Docker, and
multi-architecture evidence must still be attached to the milestone that claims
it. A green local baseline is not release verification.

## Status Vocabulary

Every issue, PR, status document, and release note must use these terms
consistently:

| Status | Meaning |
| --- | --- |
| `planned` | Requirements exist, but no implementation intended to satisfy this milestone has landed. |
| `scaffold` | Types, feature gates, design, or non-connecting/test-only structure exists, but no usable end-to-end capability exists. |
| `implemented slice` | A bounded, tested capability exists, but the milestone still lacks one or more reliability, migration, security, operating, or release requirements. |
| `operationally mature` | The complete milestone behavior, failure recovery, operator workflow, security boundary, and required tests are implemented. |
| `release verified` | Operational maturity is proven in all required CI/platform matrices, release artifacts and upgrade/rollback paths are verified, and release documentation is current. |
| `in progress` | An active branch is changing the milestone. This is execution state, not a maturity claim. |
| `blocked` | A documented external dependency prevents useful progress; the blocker and an unblocking action are recorded. |

`Complete` by itself is forbidden because it does not distinguish a design,
scaffold, implemented slice, operational maturity, and release verification.

## Dependency Rules

- An arrow `X -> Y` means `Y` may not claim operational maturity before `X`
  satisfies its acceptance criteria.
- Design and test-fixture work may overlap when it does not depend on an
  unfinished schema or behavior, but dependent implementation must not merge
  first.
- Every schema change is sequential, backed up, transactional, integrity
  checked, forward-schema refusing, fixture tested, and documented for restore.
- Every protocol or API change uses closed bounded DTOs, updates its machine
  contract in the same PR, and adds compatibility or drift tests.
- Every controller mutation takes a resolved actor and commits the business
  change and audit row in one transaction. Audit failure rolls back the change.
- Stage D starts only after the Stage A readiness node. It is default-off and
  does not block the read-only release train.

## Execution DAG

The current execution node is **A6** on issue `#38`. A1 through A5 are
operationally mature for the current production controller mutation, storage,
and scheduler reliability inventories. The node-lifecycle slice
merged through pull request `#57`, the scheduler-job configuration slice merged
through pull request `#58`, and the endpoint-trust fail-closed slice merged
through pull request `#59`. Atomic scheduler run, outcome, observation, audit,
and job-clock transitions merged through pull request `#60`. Endpoint binding
and lifecycle state-machine hardening merged through pull request `#61`
(`982d948b7a4fa6d152843dd58a7a9e1b3c47eb03`). This slice requires
bidirectional unique Active bindings at every
dispatch boundary, closes and audits effective lifecycle transitions, moves the
node registry pointer during rotation, terminalizes trust during removal, and
adds aggregate-only doctor diagnostics plus a production bypass guard. It does
not change schema, protocol, API routes, agent capabilities, or the default
read-only boundary. Statuses describe the milestone, not just the amount of
supporting code already in the repository. Explicit enrollment binding and its
actor-bearing writer migration merged through pull request `#62`
(`27b1fe56a957b0b3c79b2e5e9348090964943caf`). That slice makes new
approval one atomic operator-owned node/request/trust/audit transition and adds
a strict manual claim for legacy approved-unbound rows. It introduces no schema,
protocol, API, agent-capability, or default read-only boundary change.
Enrollment token lifecycle and request-decision transitions merged through pull
request `#63` (`f9f4f83378b8790ffea405b8d8a93f0ee0c4be64`). That slice routes token
create/revoke and request submit/reject through actor-bearing immediate
transactions, adds stable
optional request IDs, serializes the final token use, closes terminal
transitions, and keeps token/submitted-identity material out of audit and
`Debug`. It changes no schema, protocol, API route, agent capability, or default
read-only boundary.
Retention policy/apply atomicity merged through pull request `#64`
(`876f60de5a1cecf0dbb4304f2643641f2a5e088d`). That slice keeps
dry-run/explain read-only, moves
each non-dry-run scope deletion and its audit into one immediate transaction,
and uses stable operation IDs for exact replay across multi-scope partial
progress. It introduces no schema, protocol, API, agent-capability, or default
read-only boundary change. Health snapshot and alert candidate evaluation
atomicity merged through pull request `#65`
(`9aae8fff7e27f5de50206af641e8e9ac84749872`). That slice
commits each bounded evaluation and low-sensitive audit together, uses stable
evaluation identities for exact replay, and rejects stale alert before-state so
a concurrent operator silence or resolve is not overwritten. It changes no
schema, protocol, API route, agent capability, or default read-only boundary.
Alert operator transitions and webhook-hook creation merged through pull
request `#66` (`b4a0d6653d9862391ef535fd480abfb6c7e9b86a`). Silence/resolve compare persisted before-state
and commit with actor/reason/audit; hook creation commits configuration and a
redacted audit together. Alert delivery persistence is active on branch
`codex/a1-alert-delivery-writers` in pull request `#67`. Each webhook attempt commits with audit, and
finalization compare-checks the complete bounded alert set before committing
`last_sent_at` changes with the summary audit. External file/HTTPS I/O remains
outside database transactions. The final inventory and guard audit are recorded
in `docs/a1-mutation-inventory.md`; fixture-only raw helpers are rejected from
production call sites. A1 changes no schema, protocol, API route, agent
capability, feature default, or network read-only boundary. The completion audit
is published in pull request `#68`.

The first A2 slice moves scheduler selector and explicit-pair storage to closed
schema-tagged v1 payloads and advances SQLite to migration `0009`. New writes,
CLI reads, and the independent API read adapter reject unknown fields,
unsupported versions, malformed values, and contaminated data. Migration
canonicalizes exact legacy payloads, disables the ambiguous historical empty
selector for operator review, preserves exact valid legacy pairs, and aborts on
all other contamination after the standard private backup. Other dynamic JSON
families remain A2 work; the milestone is therefore an implemented slice, not
operationally mature.

The second A2 slice advances SQLite to migration `0010` and makes health
degraded-method and derived-summary storage closed and schema-tagged. Exact
legacy arrays/objects canonicalize transactionally, including empty summaries
whose missing optional fields remain null. Unsupported methods, unknown fields,
future schemas, invalid bounds, and disagreement with the relational snapshot
status fail the migration after backup. CLI alert evaluation and both CLI/API
read projections validate the payloads and expose only the established fixed
public fields.

The third A2 slice advances SQLite to migration `0011` and stores probe
observation summaries in a closed envelope bound to relational method and result
class. A fixed typed field catalog covers controller RPC, ocserv, and scheduler
summaries. Writers canonicalize before persistence; migration and CLI/API readers
reject unknown, nested, secret-like, address, raw, future-version, or mismatched
data while public projections omit the storage wrapper.

The fourth A2 slice advances SQLite to migration `0012` and stores
observability run summaries in a closed payload bound to relational job, job
kind, status, and trigger. Migration derives missing legacy relational fields,
preserves bounded terminal counts, and rejects unknown, sensitive, impossible,
future-version, or mismatched data. CLI and independent API readers validate
the envelope and omit its storage wrapper. The slice is published in pull
request `#72`.

The fifth A2 slice advances SQLite to migration `0013` and stores endpoint
trust bundles in a closed payload bound to relational endpoint ID, generation,
and lifecycle status. Exact legacy empty bundles become empty allowlists;
explicit controller/peer lists and path-probe pairs are bounded and unique.
Migration, writers, and store readers reject unknown, future, malformed,
duplicate, self-pair, or mismatched data without creating trust. The slice is
published in pull request `#73`.

The sixth A2 slice advances SQLite to migration `0014` and stores alert details
in a closed payload containing fixed methods, bounded low-sensitive summary
fields, and typed silence or resolution metadata. Exact legacy rows migrate;
writers and CLI/API readers reject unknown, nested, sensitive, malformed,
future-version, or relationally unsafe data. Current-schema contamination fails
closed without delivery or output. The slice is published in pull request `#74`.

The seventh A2 slice advances SQLite to migration `0015` and stores alert
webhook host allowlists in a closed payload with canonical, bounded, unique
hosts bound to the relational endpoint host. Exact legacy arrays migrate;
writers and readers reject unknown, forbidden, malformed, noncanonical,
future-version, or mismatched data before output or delivery. Publication is in
pull request `#75`.

The eighth A2 slice advances SQLite to migration `0016` and stores enrollment
token labels/scope and join-request requested/approved labels in closed,
kind-bound typed scalar maps. Exact legacy objects migrate; writers and readers
reject unknown, nested, sensitive, malformed, future-version, wrong-kind, or
decision-inconsistent data without changing enrollment identity or trust.
The slice is published in pull request `#76`.

The ninth A2 slice advances SQLite to migration `0017` and adds closed delivery
attempt detail payloads bound to every relational attempt field. Migration
rebuilds the table and recreates its index and foreign keys; writers and readers
reject unknown, malformed, future-version, out-of-range, or mismatched data.
Published for review in pull request `#77`.

The tenth A2 slice advances SQLite to migration `0018` and stores controller
audit detail in a closed, recursively typed, bounded payload. Its `_audit`
record is bound to every relational audit column, while a finite top-level
detail vocabulary rejects unknown legacy data. Migration rebuilds the table;
writers and controller/API readers fail closed on unsafe, malformed,
future-version, or mismatched data and never expose the storage envelope.
Published for review in pull request `#78`.

The final A2 inventory is recorded in `docs/a2-storage-inventory.md`. All nine
payload families named by issue `#34`, plus the adjacent webhook-host and
enrollment-metadata families discovered during the audit, now use typed
versioned writes, fail-closed migration, strict readers, and public projections
that omit storage envelopes. The completion audit makes A2 operationally mature
without changing the read-only or trust boundary.
The completion audit is published in pull request `#79`.

The first A3 slice advances SQLite to migration `0019` and adds deterministic
job claims with bounded expiry, monotonic fence tokens, active-run binding, and
atomic abandoned-run recovery. Production run-once and daemon paths claim work
through `StoreWriter`; two SQLite connections cannot acquire one due job, and
an expired owner cannot persist after takeover. Active execution renews a
two-minute lease every 30 seconds and fails closed if renewal loses its fence.
Misfires coalesce arbitrarily old backlogs into one audited execution. Transient
read-only RPC failures use a three-attempt exponential backoff while permanent
and partial failures do not retry; worst-case attempts are reserved from the
per-tick budget. Schema `0020` adds an atomically audited global maintenance
window that suppresses claims and RPC without advancing clocks. SIGINT/SIGTERM
closes admission, drains the admitted job and claim, then supports restart with
a fresh owner. Per-attempt timeouts produce typed audits and observations;
deterministic bounded jitter spreads post-run clocks. The completed acceptance
matrix is recorded in `docs/a3-scheduler-reliability-inventory.md`.
The A3 completion audit is published in pull request `#87`.
Timeout and jitter enforcement are published in pull request `#86`.
Graceful daemon drain and restart are published in pull request `#85`.
The schema-v20 maintenance policy is published in pull request `#84`.
The bounded retry policy is published in pull request `#83`.
The bounded misfire policy is published in pull request `#82`.
The lease-heartbeat follow-up is published in pull request `#81`.
Published for review in pull request `#80`.

The first A4 slice advances SQLite to migration `0021` and adds bounded durable
health evaluation run metadata. A unique input-watermark, policy-version, and
computation-version tuple establishes the replay boundary without storing raw
observations or expanding evaluator authority. Actor-bound atomic start,
snapshot completion, typed failure, audit rollback, and bounded abandoned-run
recovery are implemented. One-shot and daemon evaluator commands now refresh
snapshots independently of dashboard reads, coalesce deterministic minute
buckets, persist bounded invalid-input failures, and drain/restart on signals.
The final A4 acceptance inventory remains active work.
Schema 21 evaluator-run persistence is published in pull request `#88`.
Atomic evaluator lifecycle and recovery are published in pull request `#89`.
The independent graceful evaluator daemon is published in pull request `#90`.
The A4 completion audit is published in pull request `#91`.

The first A5 slice advances SQLite to migration `0022` and adds a bounded fenced
automatic webhook delivery queue. Durable idempotency and group keys, monotonic
claim fences, five-attempt retry bounds, explicit dead-letter and success state,
and due/lease indexes establish the persistence contract. Actor-bound atomic
enqueue, deterministic claim, renewal, bounded expiry recovery, retry/DLQ,
success, attempt-history, and audit writers are implemented with stale-fence
rejection. The worker reuses hardened HTTPS/HMAC dispatch with per-hook derived
private secret files, a global tick cap, per-group deferral, five-minute repeat
suppression, bounded retry, typed preflight failure, and graceful drain/restart.
The final A5 acceptance audit adds per-hook enable/disable, delivery health,
the required `alert delivery-daemon` compatibility spelling, and the evidence
inventory. JSONL paths remain operator supplied and are not
persisted for daemon selection.
Schema 22 delivery queue persistence is published in pull request `#92`.
Atomic delivery queue writers are published in pull request `#93`.
The automatic delivery worker is published in pull request `#94`.
The A5 acceptance completion audit is published in pull request `#95`.

The first A6 slice adds managed SQLite online backup create/list/verify/inspect,
closed identity-bound manifests, private artifacts, SHA-256 integrity, and
optional Ed25519 signatures in pull request `#96`. Restore plan/apply and the
automated restore drill remain active work.

The second A6 slice implements read-only restore planning, explicit confirmed
apply, controller identity/schema/integrity verification, managed pre-backup,
WAL/SHM handling, staged atomic replacement, restore audit, and injected-failure
rollback. Its pull request is the current A6 publication task.
The restore workflow is published in pull request `#97`.
The A6 acceptance completion inventory is published in pull request `#98`.

### Baseline And Production Foundation

| ID | Issue | Status | Depends on | Release target | Acceptance and required evidence |
| --- | --- | --- | --- | --- | --- |
| N0 Baseline and authoritative roadmap | n/a | operationally mature | none | `v0.2.x` | Baseline commit, versions, schemas, crates, binaries, features, workflows, test results, incomplete code, and documentation drift are recorded. This DAG and progress file exist and contain no secret or host-specific path. |
| A1 Atomic controller mutation audit | `#33` | operationally mature | N0 | `v0.2.x` | Every production mutation uses an actor-bound transactional writer; injected audit failure and crash-boundary tests prove rollback; direct mutation SQL and mutator bypasses outside approved store/backend boundaries are prevented; API remains read-only. `docs/a1-mutation-inventory.md` enumerates every family and its evidence. |
| A2 Typed versioned storage | `#34` | operationally mature | A1 | `v0.2.x` | New writes use closed, versioned payload types; legacy rows migrate or fail closed after private backup; contaminated fixtures cover oversize, unknown, secret-like, address, nesting, version, relationship, and method failures; CLI/API never expose raw persisted JSON. `docs/a2-storage-inventory.md` enumerates every requested family and its evidence. |
| A3 Scheduler reliability | `#35` | operationally mature | A1, A2 | `v0.3.0` | SQLite lease, fencing, deterministic claim, bounded retry/backoff, misfire, jitter, timeout, recovery, maintenance, concurrency, budget, and shutdown semantics pass competing-instance, crash, skew, and duplicate-suppression tests. `docs/a3-scheduler-reliability-inventory.md` records the completion evidence. |
| A4 Independent health evaluator | `#36` | operationally mature | A1, A2, A3 | `v0.3.0` | Idempotent evaluation runs record watermark, policy/computation versions, snapshots, and failures without agent RPC or trust/node/scheduler mutation; recovery and shutdown tests pass; dashboard freshness no longer depends on an interactive health command. `docs/a4-health-evaluator-inventory.md` records the completion evidence. |
| A5 Safe alert delivery worker | `#37` | operationally mature | A1, A2, A3, A4 | `v0.3.0` | Fixed JSONL/HTTPS delivery supports per-hook control, claim, bounded retry, dead-letter, recovery, grouping, rate limit, delivery health, idempotency, history, and shutdown. SSRF, HMAC, no-redirect, secret-redaction, and forbidden command/script/template tests pass. `docs/a5-alert-delivery-inventory.md` records the completion evidence. |
| A6 Backup, restore, and disaster recovery | `#38` | completion audit active | A1, A2 | `v0.3.0` | Create/list/verify/inspect and plan/apply workflows use private artifacts, checksums and optional signatures; restore checks schema, integrity, controller identity and WAL/SHM, backs up before overwrite, replaces atomically, rolls back on failure, and passes a restore drill. `docs/a6-backup-restore-inventory.md` records the completion evidence. |
| A7 Low-cardinality metrics | `#39` | scaffold | A3, A4, A5 | `v0.3.0` | Agent/controller Prometheus or OpenTelemetry metrics have documented sensitivity and cardinality; labels are fixed and bounded; non-loopback exposure is authenticated or explicitly protected; metric tests reject identity/request/session/address labels. |
| A8 Supply-chain and release hardening | `#40` | implemented slice | N0; final verification after A1-A7 | `v0.2.x` and every later release | Fuzzing, migration corpus, failure injection, browser E2E, SBOM, provenance, artifact signing, verification tooling, upgrade/rollback matrix, support policy, distro smoke, Linux architectures, CodeQL, dependency policy, and rollback runbook pass without weakening pinned actions or least privilege. |
| A-READY Production-foundation gate | n/a | planned | A1, A2, A3, A4, A5, A6, A7, A8 | `v0.3.0` | All Stage A issues meet at least operational maturity, A8 supplies release evidence, the default/all-feature matrices pass, and the read-only boundary is re-audited. This gate unlocks Stage D. |

### Read-only Product Capability

| ID | Issue | Status | Depends on | Release target | Acceptance and required evidence |
| --- | --- | --- | --- | --- | --- |
| B1 Health history, rollups, and SLOs | `#41` | scaffold | A2, A4 | `v0.3.0` | Append-only history and reproducible 5m/1h/1d rollups provide bounded 24h/7d/30d availability, duration, latency, error, coverage, certificate, and drift views without inventing missing data; retention is independently configurable. |
| B2 Labels, environment, and maintenance | `#42` | implemented slice | A1, A2, A3 | `v0.4.0` | Bounded audited metadata and selectors have a maximum match count; maintenance affects scheduling/presentation only; tests prove labels cannot create trust, peers, or path authorization. |
| B3 Versioned API and query contract | `#43` | implemented slice | A2, B1, B2 | `v0.4.0` | `/api/v1` has a compatibility plan, bounded tamper-resistant cursor pagination, time/metadata filters, ETag/conditional GET, stable errors/request IDs, exact OpenAPI/runtime validation, and no RPC-trigger route. Existing API drift listed below is resolved. |
| B4 Local producer SDK | `#44` | scaffold | A2 | `v0.4.0` | A snapshot-schema crate, validator, Rust SDK, machine schema, version negotiation, compatibility suite, and least-privilege sample producer emit fixed aggregates only and remain unreachable from controller RPC/API/scheduler paths. |
| B5 HMAC configuration fingerprint | `#45` | implemented slice | A2, B4 | `v0.4.0` | Optional fleet-local HMAC-SHA-256 supports private local key files, key IDs, rotation and dual-read migration, leaks no key material, preserves SHA-256 compatibility, and keeps human output shortened. |
| B6 Trust policy GitOps | `#46` | implemented slice | A1, A2 | `v0.4.0` | Signed revisions, bounded review plans, CI artifacts, drift alerts, policy history, and approval records remain review-only initially. Any later apply subphase additionally depends on C2 and D0 and executes individually audited operations without automatic enrollment or path authorization. |
| B7 Protocol capability negotiation | `#47` | planned | A2, B4, B5 | `v0.4.0` | Fixed `node.capabilities` returns bounded closed version/method/provider/feature data without paths or local policy detail; mixed-version and unsupported-capability matrices fail closed. |
| B8 Agent version drift | `#48` | scaffold | A4, B2, B7 | `v0.4.0` | Expected-version policy, fleet distribution, compatibility alerts, provider/protocol readiness, and read-only upgrade plans are bounded and tested; no remote package installation exists. |
| B-READY Read-only product gate | n/a | planned | B1, B2, B3, B4, B5, B6, B7, B8 | `v0.4.0` | All Stage B issues are operationally mature, query and history bounds are verified, mixed-version behavior is tested, and no product feature expands trust or agent control. |

### Multi-operator And Scale

| ID | Issue | Status | Depends on | Release target | Acceptance and required evidence |
| --- | --- | --- | --- | --- | --- |
| C1 Runtime Postgres backend | `#49` | scaffold | A1, A2, A3, A6 | `v0.5.0` | Default-off Postgres implements private DSN loading, pool, schema/migrations, atomic audit, retention/indexes, optional partitioning, verified SQLite import, backend selection, doctor/backup guidance, advisory migration lock, and shared SQLite/Postgres contract tests. SQLite remains default. |
| C2 OIDC, mTLS, and enforced RBAC | `#50` | scaffold | A1, B3 | `v0.5.0` | Auth abstraction supports local/bearer compatibility, OIDC, mTLS, service accounts, expiry, issuer/audience, claims, rotation, JWKS cache, failure audit, and break glass. Route/CLI policy is default-deny and actor identity cannot come from ordinary request fields. |
| C3 Controller high availability | `#51` | planned | A3, A4, A5, C1, C2 | `v0.5.0` | Replicas, leader scheduler/evaluator, lease/fencing, idempotent claims, delivery claims, failover, duplicate suppression, rolling upgrade, readiness, and partition recovery pass split-brain tests without duplicate RPC or non-atomic audit. |
| C-READY Scale and governance gate | n/a | planned | C1, C2, C3 | `v0.5.0` | Postgres parity, authenticated multi-operator behavior, HA failure tests, migration leadership, and atomic audit pass in isolated CI while SQLite standalone operation remains supported. |

### Default-off Controlled Writes Preview

| ID | Issue | Status | Depends on | Release target | Acceptance and required evidence |
| --- | --- | --- | --- | --- | --- |
| D0 Dry-run and approval state machine | `#52` | scaffold | A-READY; live dispatch also requires C2 | `controlled-writes-preview` | Additive tables and a closed state machine enforce different actor/approver, expiring approval, exact EndpointID, digest, UUID, idempotency, replay protection, signed intent, local policy, successful prior dry-run, and atomic audit. Feature-enabled agents still perform no mutation in D0. |
| D1 Single-node `ocserv.reload` | `#53` | planned | D0, C2, A4 | `controlled-writes-preview` | One exact node and locally bound service identity require feature/local/operation enablement, dry-run, two-person approval, ticket, signature, expected state, rate limit, idempotency, post-observation, typed output, and fail-closed fixed adapter behavior with no command/path/stdout/stderr RPC field. |
| D2 Canary and batch rollout | `#54` | planned | D1, B2, A3, A4 | `controlled-writes-preview` | Explicit targets, conservative canary/batches, max unavailable, maintenance/region sequencing, pause/resume/abort, health gate, per-node IDs, and stop-on-failure are tested; no implicit fleet selector exists. |
| D3 Signed config bundle apply/rollback | `#55` | planned | D0, D1, C2, A6 | `controlled-writes-preview` | Agent-known signed bundles use manifests, IDs, digests, signer IDs, expected previous state, private store, schema validation, atomic replace, dry-run, post-health, and rollback without RPC paths, raw config, arbitrary file writes, scripts, or config disclosure. |
| D4 Emergency restart | `#56` | planned | D1, D2, C2, A4 | `controlled-writes-preview` | Default-disabled emergency-only restart requires higher role, two-person approval, outage acknowledgement, ticket, strict target/canary, strong rate limit, maintenance window, post-observation, irreversibility audit, and stop-on-failure. Fleet-wide one-click restart and session disconnect remain unavailable. |
| D-READY Controlled-writes preview gate | n/a | planned | D0, D1, D2, D3, D4 | independent preview | Default and feature-disabled builds reject writes; local-policy, approval, signature, replay, dry-run, rollback, outage, and redaction matrices pass. No generic execution capability exists. This gate does not block read-only GA. |

## Terminal Nodes

| Terminal | Status | Depends on | Completion rule |
| --- | --- | --- | --- |
| Read-only GA | planned | A-READY, B-READY, C-READY | Target `v1.0.0`: the default build is read-only; SQLite and optional Postgres are supported and recoverable; API/auth/RBAC/HA contracts are stable; upgrade/restore and release evidence pass; remaining controlled-write work is explicitly excluded from the GA gate. |
| Whole program | planned | Read-only GA, D-READY | Every mapped issue is closed or explicitly dispositioned, the controlled-writes preview remains default-off and passes its security matrix, documentation matches source and release state, and the final implementation report records schema/protocol/API changes, tests, recovery, remaining risk, and unsupported capabilities. |

## Evidence Contract

No milestone may advance to `operationally mature` or `release verified` using a
status sentence alone. Its issue and PR must link or include:

- exact baseline and head commit SHAs, branch, issue, and PR;
- problem statement, design decision or ADR, threat model, and security boundary;
- schema, protocol, API, feature, binary, config, and compatibility changes;
- migration, upgrade, backup, rollback, and disaster-recovery impact;
- unit, integration, rejected-path, security-boundary, failure-injection, and
  platform test results appropriate to the change;
- default-feature and all-feature formatting, Clippy, and test results;
- applicable doc-claim, workflow-pinning, release-version, supply-chain,
  browser, Docker, Postgres, HA, and release-artifact results;
- updated README, SECURITY, CHANGELOG, status, roadmap, implementation summary,
  API/OpenAPI, operations, and release documents affected by the milestone;
- known limitations and any deferred work with an issue number.

CI evidence must identify the workflow/job and commit. Local-only evidence must
say so. A scaffold cannot satisfy an end-to-end acceptance criterion.

## Audited Documentation Drift

The baseline audit found the following documentation or contract drift. These
items remain open until the owning milestone supplies code/doc tests and updates
all affected documents:

| Drift | Owner | Required resolution |
| --- | --- | --- |
| `docs/roadmap.md`, `docs/status.md`, and `docs/implementation-summary.md` use incompatible future/partial/complete language for the same API, dashboard, and release slices. | A8 `#40` | Adopt this status vocabulary and make older roadmap material clearly historical or consistent. |
| `SECURITY.md` describes reload/restart/config apply as forbidden without distinguishing current/default-build prohibition from the separately designed future controlled-write track. | D0 `#52`, A8 `#40` | Separate current-release forbidden behavior from forbidden-forever generic execution and link the default-off preview boundary. |
| The audited status set omitted protocol `1`, ALPN, the complete feature inventory, and several schema versions. | N0 | Recorded in this baseline; add automated drift checks before any value changes. |
| `/health/summary` is documented as fleet-wide but silently counts only `--max-limit` rows. | B3 `#43` | Compute an exact bounded aggregate or return explicit overflow/truncation metadata and update OpenAPI. |
| Unknown-query rejection is documented globally, but routes without a query extractor ignore unknown keys. | B3 `#43` | Reject unknown/duplicate query keys consistently or narrow the contract route by route. |
| OpenAPI fixes query maxima/defaults and redaction defaults that are configurable at process startup. | B3 `#43` | Represent server-configured bounds/defaults accurately and validate runtime responses against the contract. |
| Audit API accepts offset RFC3339 values but compares their original text lexically in SQLite; interval closure is undocumented. | B3 `#43` | Normalize to canonical UTC before persistence/query and document the exact half-open interval. |
| OpenAPI low-sensitive prose excludes selectors while the job schema requires and returns a controller-local selector; runtime also supports `HEAD` and structured 405/500 responses not fully described by the contract. | B3 `#43` | Distinguish safe controller selectors from forbidden agent-local selectors and make method/error/header behavior explicit. |
| `scripts/check-doc-claims.sh` checks a small README phrase set rather than schema/protocol/feature/CLI/API drift. | A8 `#40` | Add source-derived checks for versions, features, routes, CLI examples, migrations, and safety claims. |
| README and Phase 12 development commands omit all-feature and repository-script gates; examples also contain version/toolchain drift. | A8 `#40` | Publish one canonical local/CI verification matrix and keep examples tied to workspace/toolchain versions. |
| Workspace/OpenAPI report `0.2.0`, while its changelog entries remain under `Unreleased`. | A8 `#40` | Explicitly mark `0.2.0` as an unreleased candidate or cut a dated release section and matching tag. |

## Progress Updates

`docs/automation-progress.json` is the machine-readable current pointer. Update
it before every commit without including secrets, tokens, DSNs, or absolute
local paths. Update this roadmap whenever an issue changes maturity, dependency,
release target, blocker, or acceptance scope. A PR number is recorded only after
the PR exists.
