# A6 Backup, Restore, And Disaster Recovery Inventory

## Scope

A6 protects controller SQLite state with managed, private, identity-bound backup
artifacts and a plan-first restore workflow. It does not back up SecretKey bytes,
change controller identity, call an agent, or add any remote file or command
surface.

## Requirement Evidence

| Requirement | Implementation | Verification |
| --- | --- | --- |
| `backup create` | Uses SQLite online backup against a private current-schema source and publishes a database, checksum, closed manifest, and optional signature under an existing owned `0700` directory. | `backup_create_list_verify_and_detect_corruption` proves a usable snapshot and private artifact workflow. Migration backup tests independently cover online backup under live schema transitions. |
| `backup list` | Scans only `backup-*.manifest.json`, caps the directory at 1,000 manifests, requires strict private directory ownership/mode, denies unknown manifest fields, and sorts deterministically. | Backup integration tests list the exact created manifest. |
| `backup verify` | Recomputes SHA-256 and size, runs SQLite `integrity_check`, checks relational schema version, validates closed manifest fields, and verifies any present Ed25519 signature. | Corruption, signature, and tampered-manifest tests fail closed. |
| `backup inspect` | Reads only one bounded private manifest and prints its closed low-sensitive fields without opening or changing controller state. | CLI parser and manifest validation tests cover the path; unknown or oversized content is rejected. |
| Manifest fields | Versioned manifest contains schema, application and protocol versions, RFC3339 creation time, database checksum/size, backup ID/file, and expected controller EndpointID. | `BackupManifest` uses `deny_unknown_fields`; create and verify validate every field and relationship. |
| No SecretKey material | Backup creation loads the private controller key only to derive its public EndpointID. The manifest schema has no secret field and the database snapshot never includes the identity file. | Closed manifest serialization and artifact inventory prove only database/checksum/manifest/signature outputs. |
| Private files | Source database, controller identity, signing key, manifests, databases, checksums, signatures, stage, rollback, lock, and pre-backup artifacts use owner/regular-file/mode/no-follow/no-hardlink checks as applicable. Directories are owned, non-symlink, exact `0700`; created files are `0600`. | Unsafe-directory, secret-file, migration-backup, and private-file suites cover modes, owner, symlink and hardlink rejection. |
| Checksum and optional signature | SHA-256 is embedded in the manifest and written as a sidecar. Optional Ed25519 signs the exact manifest bytes and records bounded public verification material. | Signed backup verifies; database, manifest, signature metadata, and signature tampering fail closed. |
| Read-only restore plan | `restore plan` fully verifies the artifact and reports source/target, schema, checksum, integrity, signature presence, identity match, overwrite/pre-backup decision, and WAL/SHM presence. | The restore drill byte-compares the target before/after plan and proves identity mismatch is reported without mutation. |
| Explicit confirmed apply | `restore apply` refuses without `--yes`, rejects current-schema or EndpointID mismatch, and uses a private per-database create-new lock. | Restore drill covers missing confirmation and wrong identity rejection. |
| Pre-backup existing state | Before replacement, apply creates a complete managed online backup under `.ocfleet-pre-restore-backups`. | Restore drill verifies the pre-backup artifact and proves it contains the pre-restore live value. |
| Atomic replacement and audit | Apply copies into a private same-directory stage, inserts the actor-bound `controller.restore.apply` audit while staged, verifies it, moves target state aside, renames the stage atomically, syncs the directory, and verifies again. Audit failure occurs before replacement. | Restore drill proves the restored value and audit row. Controller mutation guard remains green. |
| Failure rollback | Any move or post-replacement verification failure removes the replacement and restores the prior database plus moved sidecars before returning failure. | `post_replace_failure_restores_original_database` injects failure after rename and proves the original disabled-node state returns. |
| WAL/SHM handling | Plan reports target sidecars. Apply moves them with the original state, removes stale moved sidecars after success, and restores them on failure. | Restore drill supplies stale WAL/SHM files and proves both are handled. |
| Disaster recovery runbook | `docs/backup-restore.md` gives executable create/list/inspect/verify/plan/apply commands, stop/restart ordering, confirmation and identity rules, pre-backup behavior, and post-restore checks. | README documentation claim check passes. |
| Automated restore drill | `backup_tests` creates live state, snapshots it, diverges live state, plans, restores, verifies audit and recovered state, then verifies the automatic pre-backup. | The integration suite runs in every default/all-feature workspace CI test job. |

## Release Evidence

- Managed backup artifacts: pull request `#96`.
- Atomic restore workflow and disaster-recovery drill: pull request `#97`.
- Completion inventory and phase transition: the A6 completion pull request
  recorded in `docs/next-roadmap.md`.
- PR #96 and #97 passed rustfmt, clippy, full workspace tests, CodeQL,
  supply-chain checks, and Debian/Ubuntu x86_64/aarch64 install smoke.

## Operator Boundary

The restore lock serializes restore invocations only. Operators must stop every
other controller process before apply. A restore never replaces the controller
SecretKey; the manifest EndpointID must match the explicitly supplied current
SecretKey or apply fails before staging or target mutation.

