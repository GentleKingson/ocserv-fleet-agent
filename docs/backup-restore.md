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
