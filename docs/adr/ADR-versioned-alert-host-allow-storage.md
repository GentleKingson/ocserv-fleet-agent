# ADR: Versioned Alert Host-Allow Storage

## Status

Accepted as the seventh A2 typed-versioned-storage slice.

## Decision

Alert webhook rows persist `ocfleet.alert.host-allow.v1`, a closed payload with
one to sixteen canonical, unique hosts. The stored list must include the
relational webhook endpoint host. Writers require already-canonical record data
and serialize the typed envelope; readers validate both the envelope and its
relationship before returning the established host list.

Migration `0015` canonicalizes exact legacy string arrays transactionally after
the standard private backup. It preserves the existing lowercase, trailing-dot
removal, sorting, and deduplication rules. Unknown fields, malformed or empty
lists, forbidden hosts, unsupported schemas, and endpoint-host mismatches abort
migration. Current-schema readers fail closed on externally contaminated rows.

## Consequences

SQLite schema version increases from `14` to `15` without changing the table
shape. Rollback requires restoring the pre-migration backup before running an
older binary. CLI hook output continues to expose only the public host list.
This change adds no webhook destination, automatic delivery, DNS authority,
agent RPC, or API/dashboard mutation route.
