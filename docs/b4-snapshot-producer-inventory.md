# B4 Local Snapshot Producer SDK Completion Inventory

Issue `#44` is operationally mature. The `ocfleet-snapshot-schema` crate is an
independent local producer contract and has no dependency on the agent,
controller, scheduler, or API.

| Requirement | Evidence |
| --- | --- |
| Closed schema crate | `SnapshotDocument` denies unknown fields and validates the exact `ocfleet.ocserv.snapshot.v2` aggregate contract and bounds. |
| Validator | `ocfleet-snapshot-validator` validates bounded regular files, emits stable machine output, and prints the embedded schema. |
| Rust SDK | `SnapshotProducer` validates before output and performs private same-directory atomic publication without shell or command APIs. |
| Machine schema | Draft 2020-12 JSON Schema is embedded and checked for version and closed-field alignment. |
| Compatibility | `supports_version` fails closed; the agent collector snapshot provider consumes the shared type and validation library. |
| Forbidden data | Tests inject raw logs, username, IP, session, cookie, certificate identity, raw config, and command output fields and prove rejection. |
| Sample and guide | `minimal-producer` and `docs/snapshot-producer-author-guide.md` cover least-privilege local publication. |
| Linux permissions | A non-root Docker user builds and runs the producer and validator; output is owned by that user with mode `0600`, while symlink and hardlink destinations fail. |

Nothing in the crate can start a producer remotely. It contains no RPC method,
controller route, scheduler hook, shell wrapper, `occtl`, or `journalctl` API.
