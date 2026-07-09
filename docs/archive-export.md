# Archive And Export

Long-term history is handled by export and external archival, not by widening
the controller runtime boundary.

## Controller Audit

`controller_audit_log` is the durable record of local controller mutations,
agent RPC attempts, rejected paths, alert delivery attempts, and audit exports.
Retention policies do not delete this table.

Use bounded audit exports for archival:

```bash
ocfleet audit export \
  --from 2026-07-01T00:00:00Z \
  --to 2026-07-08T00:00:00Z \
  --output /var/lib/ocfleet-controller/exports/audit-20260701.jsonl \
  --redact strict \
  --include-checksum \
  --sign-with-key-file /var/lib/ocfleet-controller/audit-signing-key.pk8
```

Exports are private JSONL files. Checksum and Ed25519 signature sidecars are
optional but recommended for long-term custody.

## Observability History

Retention can prune only the explicitly supported observability scopes:

- `observations`
- `observability-runs`
- `health-snapshots`
- `alert-events`

Use `retention explain` before `retention apply` to preview candidate counts.
For longer history, export or copy the SQLite database under local operational
controls before pruning. Do not use retention as an audit deletion mechanism.

## Archive Handling

Recommended archive process:

1. Stop writer processes or take a consistent SQLite backup.
2. Run integrity checks on the backup.
3. Export audit windows with `--redact default` or `--redact strict`.
4. Write checksum/signature sidecars.
5. Move artifacts to your archive system over an authenticated channel.
6. Verify checksums/signatures after transfer.

Archive systems must not rehydrate redacted fields into dashboards or incident
tools as raw secrets. EndpointIDs and node IDs are low-sensitive identifiers, but
strict redaction is preferred when exports leave the operations team.
