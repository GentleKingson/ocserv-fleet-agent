# Local Snapshot Producer Author Guide

`ocfleet-snapshot-schema` is the only supported contract for third-party local
snapshot producers. Producers run independently under an operator-managed
account. The controller, API, scheduler, and agent RPC dispatcher cannot start
or configure them.

## Contract

Use `SnapshotDocument` and `SnapshotProducer`. The current compatible version
is `ocfleet.ocserv.snapshot.v2`; `supports_version` fails closed for every
other version. The machine-readable JSON Schema is located at
`crates/ocfleet-snapshot-schema/schema/ocfleet.ocserv.snapshot.v2.schema.json`.

Only fixed aggregate fields are accepted: service/enabled state, bounded
version, total session count, bounded rolling failure counts, minimum
certificate days, and a short configuration fingerprint. Unknown fields are
rejected. Raw logs, usernames, IP addresses, individual sessions, cookies,
certificate identities, raw configuration, and command output have no schema
representation and must never be collected.

The SDK intentionally provides no shell execution, `occtl`, `journalctl`,
service-manager, command, or raw-output API.

## Produce And Validate

The output path must be absolute and its existing parent must be owned by the
producer with mode `0700`. The SDK rejects relative paths, unsafe parents,
symlinks, and hard-linked destinations. Publication uses a private `0600`
temporary file, sync, same-directory atomic rename, and directory sync.

```bash
cargo run -p ocfleet-snapshot-schema --example minimal-producer -- \
  /run/ocfleet-producer/ocserv-snapshot.json

cargo run -p ocfleet-snapshot-schema --bin ocfleet-snapshot-validator -- \
  /run/ocfleet-producer/ocserv-snapshot.json
```

`--print-schema` emits the embedded machine schema. The validator is local and
does not contact an agent or controller.
