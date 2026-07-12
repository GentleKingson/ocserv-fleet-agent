# A8 Release Hardening Inventory

This is the live A8 acceptance inventory. A row is complete only when the
repository contains automated evidence and the release path verifies it.

| Requirement | Current evidence | Status |
| --- | --- | --- |
| Default/all-feature Rust gates | `.github/workflows/rust.yml` runs format, default/all-feature Clippy, and serialized default/all-feature tests. | complete |
| Protocol/frame/config fuzzing | `fuzz/` contains bounded libFuzzer targets and seed corpora; `.github/workflows/fuzz.yml` runs both with pinned `cargo-fuzz`. | complete |
| Migration corpus | `migration_tests.rs` deterministically constructs every historical schema and targeted contaminated/large fixtures; `docs/a8-migration-failure-inventory.md` records coverage and invariants. | complete |
| Failure injection | Scheduler, evaluator, alert delivery, audit spool, migration, restore, and read-only web boundaries are mapped to deterministic tests in the A8 inventory. | complete |
| Browser dashboard E2E | `tests/e2e/dashboard.spec.js` verifies desktop/narrow rendering, CSP, refresh, audit preview, empty states, console cleanliness, and GET-only traffic in Chromium; `.github/workflows/browser-e2e.yml` runs it. | complete |
| SBOM | Pinned `cargo-cyclonedx` emits validated CycloneDX 1.5 component SBOMs per architecture; the final release job revalidates them. | complete |
| Provenance | SHA-pinned `actions/attest-build-provenance` records every candidate file; the assembly job verifies each artifact against this repository before draft creation. | complete |
| Artifact signing and verification | Pinned cosign keyless-signs every binary and SBOM, then the final job verifies workflow identity and GitHub OIDC issuer before signing the combined checksum manifest. | complete |
| Version/upgrade/rollback policy | `docs/release-policy.md` defines SemVer, support windows, platforms, release gates, and the explicit `v0.1.x`/`v0.2.x` to `v0.3.x` matrix. | complete |
| Distro/architecture smoke | Debian trixie and Ubuntu 24.04 on x86_64/aarch64 run install smoke in `.github/workflows/install-smoke.yml`. | complete |
| Action pinning and least privilege | Remote actions are commit-SHA pinned; workflows default to `contents: read`; `scripts/check-github-actions-pinning.sh` enforces pinning. | complete |
| Rollback runbook | `docs/release-rollback-runbook.md` covers preflight, staged upgrade, rollback triggers, atomic restore, trust review, restart order, observation, and failed rollback. | complete |

## Current Slice

The first completion slice adds parser fuzz smoke without expanding the runtime
dependency graph or production surface. Targets accept only in-memory bytes,
apply explicit frame and CI time/memory bounds, and persist crash artifacts only
inside ephemeral CI storage. No configuration, identity, address, request, or
secret value is uploaded as an artifact.

The release supply-chain slice is documented in `docs/release-security.md`.
Its trust boundary uses ephemeral GitHub OIDC credentials, never repository
signing secrets, and the draft release job independently rechecks every output.
