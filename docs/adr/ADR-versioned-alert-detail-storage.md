# ADR: Versioned Alert Detail Storage

## Status

Accepted as the sixth A2 typed-versioned-storage slice.

## Decision

Alert rows persist `ocfleet.alert.detail.v1`, a closed payload containing a
bounded fixed-method list, a fixed low-sensitive summary, and optional bounded
silence or resolution metadata. Writers canonicalize exact public and legacy
inputs before persistence. Controller and independent API readers require the
storage envelope and expose only the established public detail fields.

Migration `0014` canonicalizes exact legacy alert details transactionally after
the standard private backup. Unknown or nested fields, unsupported methods or
schemas, invalid status values or bounds, secret-like/address content, and
malformed deadlines or reasons abort migration. Current-schema readers fail
closed on externally contaminated rows instead of attempting legacy projection.

## Consequences

SQLite schema version increases from `13` to `14` without changing the table
shape. Rollback requires restoring the pre-migration backup before running an
older binary. The storage envelope is not a CLI/API contract. Alert evaluation,
operator transitions, and explicit delivery retain their existing behavior;
this change adds no automatic delivery, agent RPC, or mutation route.
