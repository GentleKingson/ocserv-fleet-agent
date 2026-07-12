# Release Upgrade And Rollback Runbook

This runbook rolls back ocfleet binaries and controller SQLite state. It does
not roll back ocserv, execute remote commands, or infer trust.

## Before Upgrade

1. Stop scheduler, evaluator, alert worker, API, and other controller processes.
2. Record all four binary versions and the controller EndpointID.
3. Run `doctor --json`, `trust diff --format json`, and worker/scheduler status.
4. Create and verify a signed managed backup as documented in
   `docs/backup-restore.md`. Preserve the controller SecretKey separately.
5. Download the candidate and pass checksum, Sigstore, provenance, and SBOM
   verification from `docs/release-security.md`.
6. Retain the old binaries and database backup until the observation window
   below completes.

## Upgrade

Replace all four binaries from one verified release. Open the database first
with a local `ocfleet doctor --json`; this performs any forward migration and
must create its private migration backup before schema changes. Do not start
daemons if migration, integrity, schema, identity, or trust coverage fails.

Start the read-only API, then evaluator, scheduler, and alert worker one at a
time. Verify status between each step. Finally start agents in a bounded batch
and run fixed low-sensitive ping, health, metrics, API, dashboard, and audit
checks. Observe at least one complete scheduler/evaluator interval and alert
delivery retry window before declaring success.

## Rollback Decision

Rollback is mandatory for database integrity failure, controller identity
mismatch, incomplete trust coverage, repeated startup crash, audit durability
failure, unbounded resource growth, or a regression that crosses the read-only
or controlled-write boundary. Pause and investigate bounded feature failures
only when state integrity, audit, trust, and security boundaries remain intact.

## Rollback Procedure

1. Stop every new-version controller process and all agents being rolled back.
2. Preserve logs, metrics, the failed database, WAL/SHM sidecars, and generated
   diagnostic reports as private incident evidence.
3. Run `restore plan` against the verified pre-upgrade managed backup. Confirm
   controller identity, schema, checksum, signature, integrity, target, and
   sidecar findings.
4. Run `restore apply --yes`. The command creates a pre-restore backup and
   atomically replaces the database; do not manually copy over a live SQLite
   file.
5. Reinstall all four old binaries from their previously verified artifacts.
   Restore the matching controller SecretKey only if it was changed separately.
6. Run `doctor --json` and `trust diff --format json` before any RPC. Review
   rotated, revoked, and quarantined endpoints because restored state is older.
7. Start API, evaluator, scheduler, worker, and agents one at a time. Repeat the
   read-only smoke and observation window.

An older binary must never open a database migrated by a newer binary. Binary
rollback without database restore is allowed only for a patch release whose
release notes explicitly prove an unchanged schema and backward-compatible
storage contract.

## Failed Rollback

Keep all controller processes stopped. Restore the original failed database
from `.ocfleet-pre-restore-backups/`, or use the offline recovery procedure in
`docs/backup-restore.md`. Do not generate a new SecretKey, recreate trust from
node metadata, delete audit evidence, or bypass integrity/signature checks to
force startup.
