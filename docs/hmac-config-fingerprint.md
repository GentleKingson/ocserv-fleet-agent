# HMAC Configuration Fingerprint

HMAC mode is the recommended local configuration:

```toml
[ocserv_readonly.config_fingerprint]
name = "main"
config_path = "/etc/ocserv/ocserv.conf"
mode = "hmac_sha256"
key_id = "fleet-key-2026-07"
key_path = "/etc/ocfleet-agent/fingerprint.key"
```

Create the key locally as random bytes in an owner-only file beneath a private
agent directory. The agent requires at least 32 bytes and reads at most 1024.
Do not put the key in TOML, controller storage, CLI arguments, or enrollment
metadata.

During rotation, retain exactly one previous key temporarily:

```toml
previous_key_id = "fleet-key-2026-06"
previous_key_path = "/etc/ocfleet-agent/fingerprint.previous.key"
```

The agent reports both keyed digests, allowing the controller to recognize
continuity. Remove both previous fields after the migration window.

Explicit compatibility mode requires no key fields:

```toml
mode = "legacy_sha256"
```

Legacy SHA-256 is unkeyed and permits cross-fleet dictionary comparison; use it
only for a planned compatibility interval.
