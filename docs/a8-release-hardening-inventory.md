# A8 Release Hardening Inventory

This is the live A8 acceptance inventory. A row is complete only when the
repository contains automated evidence and the release path verifies it.

| Requirement | Current evidence | Status |
| --- | --- | --- |
| Default/all-feature Rust gates | `.github/workflows/rust.yml` runs format, default/all-feature Clippy, and serialized default/all-feature tests. | complete |
| Protocol/frame/config fuzzing | `fuzz/` contains bounded libFuzzer targets and seed corpora; `.github/workflows/fuzz.yml` runs both with pinned `cargo-fuzz`. | complete |
| Migration corpus | `crates/ocfleet-cli/tests/migration_tests.rs` constructs legacy schemas and contamination cases, but versioned binary corpus artifacts and a corpus manifest remain to be audited. | active |
| Failure injection | Scheduler, evaluator, alert delivery, audit spool, migration, and restore suites contain targeted injected failures; a requirement-to-test inventory remains. | active |
| Browser dashboard E2E | No Playwright workflow currently exercises the dashboard. | missing |
| SBOM | Release workflow does not yet generate or verify an SBOM. | missing |
| Provenance | Release workflow is tag-bound and checksum-verified but does not emit attestations. | missing |
| Artifact signing and verification | Backup/audit signatures exist, but release artifacts are not signed and independently verified. | missing |
| Version/upgrade/rollback policy | Semver input and binary version checks exist; support window and upgrade/rollback matrix documentation remain. | active |
| Distro/architecture smoke | Debian trixie and Ubuntu 24.04 on x86_64/aarch64 run install smoke in `.github/workflows/install-smoke.yml`. | complete |
| Action pinning and least privilege | Remote actions are commit-SHA pinned; workflows default to `contents: read`; `scripts/check-github-actions-pinning.sh` enforces pinning. | complete |
| Rollback runbook | Backup/restore documentation covers database recovery, but a release rollback runbook remains. | missing |

## Current Slice

The first completion slice adds parser fuzz smoke without expanding the runtime
dependency graph or production surface. Targets accept only in-memory bytes,
apply explicit frame and CI time/memory bounds, and persist crash artifacts only
inside ephemeral CI storage. No configuration, identity, address, request, or
secret value is uploaded as an artifact.
