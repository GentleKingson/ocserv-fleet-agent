# ADR: Versioned Run Summary Storage

## Status

Accepted.

## Decision

Observability runs persist `ocfleet.run.summary.v1`, a closed payload containing
only the fixed result class, relational job identity and kind, run status,
trigger, and bounded terminal observation counts. Writers canonicalize exact
legacy summaries before insertion or completion. CLI and independent API
readers validate the payload against the relational job, kind, status, and
trigger, then expose only the established public summary fields.

Migration `0012` canonicalizes exact legacy objects transactionally after the
standard private backup. It derives missing relational fields rather than
guessing dynamic data. Unknown fields, future schemas, invalid job kinds,
inconsistent relational fields, unsafe identifiers, and impossible counts abort
the migration. Existing typed rows are accepted only when they pass the same
relationship checks.

## Consequences

SQLite schema version increases from `11` to `12` without changing the table
shape. Rollback requires restoring the pre-migration backup before running an
older binary. Public run list/show response shapes do not expose the storage
schema wrapper and do not gain a mutating route or an agent RPC capability.
