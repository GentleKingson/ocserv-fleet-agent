# ADR: Versioned Trust Bundle Storage

## Status

Accepted.

## Decision

Endpoint trust rows persist `ocfleet.trust.bundle.v1`, a closed payload bound to
the relational endpoint ID, generation, and lifecycle status. Controller and
peer allowlists and explicit path-probe pairs have fixed entry shapes, bounded
counts, bounded identifiers, uniqueness requirements, and no wildcard or
implicit-mesh representation. Writers canonicalize before persistence. Store
readers validate the envelope and return only the established public bundle
fields to trust, enrollment, lifecycle, doctor, and policy-diff code.

Migration `0013` canonicalizes exact legacy bundles transactionally after the
standard private backup. Historical empty objects are interpreted only as empty
allowlists with identity, generation, and status derived from the same row.
Unknown fields, future schemas, malformed lists, duplicates, self-pairs,
invalid bounds, and relational mismatches abort the migration.

## Consequences

SQLite schema version increases from `12` to `13` without changing the table
shape. Rollback requires restoring the pre-migration backup before running an
older binary. The storage wrapper is not an output contract. This change adds
no trust, peer, or path-probe authorization and creates no automatic
reconciliation or API mutation path.
