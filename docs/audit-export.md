# Audit Export

`ocfleet audit export` writes bounded controller audit windows as private JSONL
files. It is a controller-local observability/export command, not an agent RPC,
and it does not expose raw RPC bodies or ocserv write operations.

## Command

```bash
ocfleet audit export \
  --from 2026-07-01T00:00:00Z \
  --to 2026-07-08T00:00:00Z \
  --format jsonl \
  --output /var/lib/ocfleet-controller/exports/audit-20260701.jsonl \
  --redact default \
  --include-checksum \
  --sign-with-key-file /var/lib/ocfleet-controller/audit-signing-key.pk8 \
  --max-rows 10000
```

The export window is mandatory, uses RFC3339 timestamps, and is capped at 31
days. `--max-rows` is also bounded; the command fails before writing the file if
the selected window contains more rows than the limit.

## Redaction Modes

- `--redact none` leaves top-level identifiers such as actor, node ID,
  EndpointID, and request ID un-hashed, but secret-like detail keys are still
  redacted.
- `--redact default` keeps normal low-sensitive top-level identifiers and
  redacts secret-like detail keys such as token, secret, password, private key,
  HMAC, authorization, and cookie fields.
- `--redact strict` also hashes actor, node ID, EndpointID, and request ID with
  stable `sha256:<prefix>` values.

All modes keep the export within the low-sensitive audit boundary. Do not use
audit export as a raw log, raw stdout/stderr, raw request body, config content,
or secret extraction surface.

## Output Files

The output path is written through the private file helper as a create-new
`0600` JSONL file under a private `0700` parent directory. Symlink, hardlink,
world-readable, world-writable, existing output, and directory-target risks are
rejected.

When `--include-checksum` is set, a SHA-256 sidecar is written next to the JSONL
file. The `audit.export` audit row is written after the export snapshot is
produced, so that audit row is not included in the same output file.

When `--sign-with-key-file` is set, `ocfleet` reads an Ed25519 PKCS#8 private
key from a private file and writes an `.sig` JSON sidecar next to the export.
The sidecar contains the algorithm, signed file name, content SHA-256, public
key, signature, and signing timestamp. It does not contain the private key or key
file path. Signing is optional and does not change the exported JSONL payload.

## Verification

```bash
sha256sum -c audit-20260701.jsonl.sha256
```

On platforms without `sha256sum`, use an equivalent SHA-256 tool and compare the
digest in the sidecar. Keep exported files private and delete them according to
your local audit retention policy.

For signed exports, verify the `.sig` sidecar with the included Ed25519 public
key and the exact JSONL bytes. Rotate signing keys by creating a new private key
file, storing it under a private `0700` parent directory with `0600` file mode,
and recording the public key fingerprint in your archive inventory.
