# B5 HMAC Configuration Fingerprint Completion Inventory

Issue `#45` is operationally mature. Configuration fingerprints default to
agent-local HMAC-SHA-256 when configured, while explicit `legacy_sha256` mode
preserves the v0.3 response shape.

| Requirement | Evidence |
| --- | --- |
| Local key and key ID | Agent config requires a bounded key ID and absolute private key file. The fixed RPC request remains empty and cannot supply either value. |
| HMAC-SHA-256 | The provider reads bounded config bytes and signs them with `ring` HMAC-SHA-256. Stability, different-key, and changed-config tests pass. |
| Rotation | Optional previous key ID/path emits one bounded previous digest. IDs must differ and current/previous fields are configured in pairs. |
| Dual read/report | Controller observation projection stores only current/previous 12-character prefixes and IDs. Health rollups treat intersecting aliases as continuous across rotation. |
| Legacy compatibility | `legacy_sha256` emits the old algorithm/hash/status JSON because all new fields are omitted when absent. New DTO fields default during old response decoding. |
| Private key safety | Key files must be owner-only regular files with one link. Mode, owner, symlink, hardlink, minimum and maximum size checks fail closed. |
| Redaction | Custom config `Debug` exposes key IDs and configured booleans but never config/key paths. RPC, CLI, summaries, and errors never contain key material or paths. |
| Human output | Full digests never print; current and previous values use 12-character prefixes. |

The key is never stored in controller SQLite, sent through RPC, placed in an
audit row, or accepted from a controller/API/scheduler parameter.
