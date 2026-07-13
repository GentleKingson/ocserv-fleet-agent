# B-READY Read-only Product Gate

## Gate Result

Stage B is operationally mature and ready for `v0.4.0` release preparation.
This is a source-tree readiness result, not a claim that `v0.4.0` has been
tagged or published.

| Gate | Result and evidence |
| --- | --- |
| B1-B8 completion | Every Stage B roadmap item is operationally mature and has a requirement-to-test inventory. |
| Query and history bounds | Health windows and rollups, API v1 pagination and filters, metadata selectors, trust plans/history, capability observations, and version distribution/readiness all enforce fixed row, time, or node caps. |
| Mixed-version behavior | Capability decoding rejects incompatible/future shapes, legacy `METHOD_NOT_FOUND` maps to an explicit unsupported state, SemVer pre-releases compare correctly, and missing/invalid observations stay unknown. |
| Default build | `cargo test --workspace --all-targets -- --test-threads=1` passes. |
| Feature build | `cargo test --workspace --all-targets --all-features -- --test-threads=1` passes, including the dormant controlled-write scaffold checks. |
| Static quality gates | Default and all-feature workspace Clippy pass with `-D warnings`; formatting, documentation claims, mutation-boundary, trust-policy, release-policy/version-consistency, and pinned-action checks pass. |
| Linux isolation | B4, B5, B7, and B8 focused suites pass as a non-root user in network-isolated Docker, covering producer file safety, HMAC key safety, capability negotiation, migrations, controller decoding, and version-readiness API behavior. |
| Read-only boundary | No Stage B API/dashboard route performs RPC or mutation. No install, package-manager, restart, trust apply, enrollment approval, automatic upgrade, generic command, shell, log, or raw-file path was added. |

## Product Boundary

The default build remains read-only at the agent-control boundary. The
all-feature build exposes only validated controlled-write configuration and
DTO scaffolding; it has no live dispatch. Stage B adds observations,
projections, local producer tooling, and review workflows, but it does not
expand who is trusted or what a controller can execute on an agent.

Schema 27 and the 23-route GET-only API are the Stage B storage and HTTP
baselines. Capability and version observations are advisory: unknown or stale
data never becomes compatible or ready by inference, and every version
readiness output keeps `actions_enabled=false`.

## Regression Hardening

The milestone regression also hardened the independent health evaluator.
Deterministic replay now accepts the same evaluation input on a later daemon
tick without requiring an identical start timestamp. Daemon tests terminate
and reap children on timeout, preventing a failed test from contaminating
later workspace runs. The evaluator and alert-worker drain/restart tests pass
in both milestone configurations.

## Remaining Limits

- `v0.4.0` release metadata and artifacts have not been created or published.
- Capability refresh remains explicit; readiness does not contact agents.
- The API remains SQLite-backed, viewer-only, and GET-only. Postgres, enforced
  multi-operator identity, and HA belong to Stage C.
- Controlled writes remain default-off and unimplemented pending their own
  Stage D safety gates.
