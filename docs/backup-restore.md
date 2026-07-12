# Backup And Restore

This runbook covers controller-local state for the read-only MVP baseline. It does not add any ocserv write operation, config push, user management, shell RPC, or file-read RPC.

## Files To Protect

- Controller database: `/var/lib/ocfleet-controller/controller.sqlite`
- Controller SecretKey: `/var/lib/ocfleet-controller/controller.secret`
- Agent SecretKey: `/var/lib/ocfleet-agent/iroh.secret`
- Agent config: `/etc/ocfleet-agent/agent.toml`

Store backups in a private directory:

```bash
sudo install -d -m 0700 /var/backups/ocfleet
```

## Controller SQLite Backup

The managed backup workflow uses SQLite online backup and never copies the
controller SecretKey into its artifacts:

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite \
  --secret-key /var/lib/ocfleet-controller/controller.secret \
  backup create --output-dir /var/backups/ocfleet --json
ocfleet backup list --backup-dir /var/backups/ocfleet --json
ocfleet backup inspect --manifest /var/backups/ocfleet/backup-ID.manifest.json --json
ocfleet backup verify --manifest /var/backups/ocfleet/backup-ID.manifest.json --json
```

The output directory must already be owned by the operator, must not be a
symlink, and must have mode `0700`. Database, checksum, manifest, and optional
signature sidecars use mode `0600`. The manifest records schema, application and
protocol versions, creation time, database checksum/size, and the expected
controller EndpointID. It contains no SecretKey bytes. Add
`--sign-with-key-file <private-ed25519-pkcs8>` to `backup create` when an
independent authenticity signature is required. `backup verify` checks the
checksum, SQLite integrity, schema binding, and any present signature.

Run `doctor` before taking a backup:

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret doctor
```

For a quiet controller host, an offline copy is acceptable:

```bash
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
sqlite3 /var/lib/ocfleet-controller/controller.sqlite 'PRAGMA integrity_check;'
sudo cp -a /var/lib/ocfleet-controller/controller.sqlite "/var/backups/ocfleet/controller.sqlite.$timestamp"
sudo sha256sum "/var/backups/ocfleet/controller.sqlite.$timestamp" | sudo tee "/var/backups/ocfleet/controller.sqlite.$timestamp.sha256" >/dev/null
```

If another local process may have the database open, prefer SQLite's backup command:

```bash
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
sqlite3 /var/lib/ocfleet-controller/controller.sqlite ".backup '/var/backups/ocfleet/controller.sqlite.$timestamp'"
sudo chmod 0600 "/var/backups/ocfleet/controller.sqlite.$timestamp"
sudo sha256sum "/var/backups/ocfleet/controller.sqlite.$timestamp" | sudo tee "/var/backups/ocfleet/controller.sqlite.$timestamp.sha256" >/dev/null
```

Keep the SecretKey with matching permissions:

```bash
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
sudo cp -a /var/lib/ocfleet-controller/controller.secret "/var/backups/ocfleet/controller.secret.$timestamp"
sudo chmod 0600 "/var/backups/ocfleet/controller.secret.$timestamp"
```

## Migration Auto-Backups

When an older non-empty controller database is opened by a newer binary, migrations first create a private backup under `.ocfleet-migration-backups/` next to the database. The backup directory is `0700`, backup files are `0600`, and each backup has a `.sha256` sidecar.

Migration is refused if the automatic backup or checksum cannot be completed. Do not delete these automatic backups until the upgraded binary has passed `doctor` and your smoke checks.

## Restore

Stop processes that could touch controller state:

```bash
sudo systemctl stop ocfleet-agent || true
```

Create a read-only restore plan first. It verifies the managed backup and reports
identity match, target existence, and WAL/SHM state without changing any file:

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite \
  --secret-key /var/lib/ocfleet-controller/controller.secret \
  restore plan --manifest /var/backups/ocfleet/backup-ID.manifest.json --json
```

After reviewing the plan and stopping every controller process that can open the
database, apply with explicit confirmation:

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite \
  --secret-key /var/lib/ocfleet-controller/controller.secret \
  restore apply --manifest /var/backups/ocfleet/backup-ID.manifest.json --yes --json
```

Apply refuses to run without `--yes`. It rejects checksum, signature, integrity,
schema, or controller EndpointID mismatches. If the target exists, apply first
creates a managed online backup under `.ocfleet-pre-restore-backups/`. It stages
and verifies the replacement in the target directory, moves the database and
any WAL/SHM files aside, atomically renames the stage, verifies it again, and
restores the original database plus sidecars if any post-replacement step fails.
The per-database private restore lock prevents concurrent restore invocations;
operators must still stop other controller processes before apply. The staged
database receives the actor-bound `controller.restore.apply` audit row before
the atomic rename, so audit failure prevents replacement.

Verify the backup checksum before restore:

```bash
cd /var/backups/ocfleet
sha256sum -c controller.sqlite.TIMESTAMP.sha256
```

Restore the database and SecretKey:

```bash
sudo install -d -o "$USER" -g "$USER" -m 0700 /var/lib/ocfleet-controller
sudo install -m 0600 /var/backups/ocfleet/controller.sqlite.TIMESTAMP /var/lib/ocfleet-controller/controller.sqlite
sudo install -m 0600 /var/backups/ocfleet/controller.secret.TIMESTAMP /var/lib/ocfleet-controller/controller.secret
```

Validate before resuming operations:

```bash
sqlite3 /var/lib/ocfleet-controller/controller.sqlite 'PRAGMA integrity_check;'
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret doctor --json
```

Then restart the agent if this host also runs one:

```bash
sudo systemctl start ocfleet-agent || true
```

## Recovery Notes

- Restoring an older controller database can reintroduce old EndpointID trust state. Run `trust diff --format json` and review revoked, quarantined, or rotated endpoints before relying on RPCs.
- Restoring a SecretKey restores the same EndpointID. Replacing a SecretKey rotates identity and requires explicit registry/config updates.
- Do not restore agent audit logs over live files. Keep old audit JSONL/spool files as evidence and let the agent create fresh files with private permissions.
