# ADR: Versioned Delivery Attempt Storage

## Status

Accepted as the ninth A2 typed-versioned-storage slice.

## Decision

Each alert delivery-attempt row persists `ocfleet.delivery-attempt.detail.v1` in
a required `detail_json` column. The closed payload repeats the attempt, alert,
and hook IDs, attempt number, status, HTTP status class, error code, and bounded
byte count. Writers build it from the relational record. Readers require an
exact match with every relational column before returning an attempt.

Migration `0017` rebuilds the delivery-attempt table transactionally after the
standard private backup and derives each payload from existing constrained
columns. Invalid bounds, identifiers, statuses, HTTP classes, error codes, or
byte counts abort migration. Unknown fields, unsupported schemas, and later
relational mismatches fail closed on current-schema reads.

## Consequences

SQLite schema version increases from `16` to `17`; the existing delivery index
and foreign keys are recreated. Rollback requires restoring the pre-migration
backup before running an older binary. The payload is an integrity-bound
storage representation, not a new output contract, and adds no delivery worker,
destination, retry behavior, agent RPC, or API/dashboard mutation.
