# ADR: Versioned Audit Detail Storage

## Status

Accepted.

## Decision

Every controller audit row stores `ocfleet.audit.detail.v1`. The payload keeps a
closed `_audit` record containing the timestamp, actor, event, optional object
identifiers, method, request metadata, outcome, error code, and duration. Audit
detail fields use a recursively typed JSON value model, a finite top-level key
catalog, and the existing low-sensitive depth, entry, string, and byte bounds.

Writers construct the payload from the complete relational record. Controller
and API readers parse the versioned payload, require every `_audit` value to
match its relational column, and return only the validated public detail fields.
The storage envelope never reaches CLI or API output.

Migration `0018` transactionally rebuilds `controller_audit_log`, preserves row
IDs and `AUTOINCREMENT`, makes `detail_json` required, and adds checks for audit
outcomes and nonnegative durations. Null legacy detail becomes an empty typed
detail. Invalid JSON, unknown top-level detail fields, unsafe values, malformed
metadata, or unsupported typed payloads abort migration after the standard
private schema-17 backup.

## Security Consequences

- Unknown or unsafe legacy detail cannot be silently carried into the current
  schema.
- Relational and payload contamination fails closed before audit export or API
  projection.
- The finite top-level vocabulary prevents new persisted audit data from being
  introduced without an explicit schema review.
- Recursive values remain bounded and low-sensitive; raw RPC bodies, secrets,
  addresses, command material, and filesystem paths remain forbidden.

## Compatibility And Rollback

Public `AuditRecord` and audit export detail shapes are unchanged because
readers unwrap the payload. Existing valid schema-17 rows are converted from
their legacy detail objects. Rollback restores the private schema-17 backup;
older binaries must not open a schema-18 database.
