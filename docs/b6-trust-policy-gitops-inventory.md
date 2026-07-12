# B6 Trust Policy GitOps Evidence Inventory

| Requirement | Implementation and evidence |
| --- | --- |
| Policy revision | Explicit bounded `metadata.revision` is required for signing and planning; the canonical SHA-256 digest and revision are projected by validation and every artifact. |
| Policy signature | Detached Ed25519 signature and separately pinned public-key documents bind revision and canonical policy digest. Tampering and metadata mismatch fail closed. |
| Deterministic plan | `trust policy plan` removes timestamps and absolute paths, canonicalizes TOML/YAML input ordering, sorts changes, and emits byte-identical JSON for identical policy/controller state. |
| Bounded change set | At most 512 changes are emitted with exact total count and truncation. Policy collections, files, plans, signatures, history, identifiers, and output fields are independently bounded. |
| Policy history | Private append-only JSONL history is capped at 256 unique revisions and 1 MiB; duplicate, malformed, unknown-field, timestamp, digest, and approval-link contamination fail closed. |
| CI review artifact | `scripts/trust-policy-ci-review.sh` produces private JSON and Markdown artifacts and rejects controller database digest changes. |
| Markdown report | The deterministic review report contains source basename, revision, digest, signature key ID, drift state, bounds, and the closed change table; strict creation requires mode `0600`. |
| Drift alert | Every plan projects closed reason `TRUST_POLICY_DRIFT`, active state, severity, and total count without inserting or mutating operational alert state. |
| Approval record | `trust policy approve` emits a private Ed25519-signed record bound to exact plan hash, revision, global actor, timestamp, and key ID. History verifies the signature and link before append. |
| TOML/YAML parity | Canonical structs and sorted collections make equivalent TOML/YAML policy digests and validation reports match. |
| Zero database mutation | `Store::open_read_only_policy_snapshot` uses SQLite immutable/read-only/query-only flags, refuses migration and active WAL recovery, and uses an in-memory empty schema when the selected file is absent. Tests compare database/WAL/SHM bytes, prove active WAL fails without checkpointing, and prove missing state is not created. |
| No agent contact or trust apply | The review module has no RPC or `StoreWriter` adapter. Source-boundary tests reject agent RPC, node mutation, enrollment approval, and trust mutation symbols. No policy apply command exists. |
| Forbidden fields | Closed TOML/YAML and artifact DTOs use `deny_unknown_fields`; parser errors do not echo rejected policy values. |

Primary tests live in `crates/ocfleet-cli/tests/trust_policy_tests.rs` and
`crates/ocfleet-cli/tests/cli_args_tests.rs`. The Linux Docker CI simulation
runs the signing, planning, approval, history, permission, and zero-mutation
workflow as a non-root user.
