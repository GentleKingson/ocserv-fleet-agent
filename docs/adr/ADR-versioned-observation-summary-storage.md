# ADR: Versioned Observation Summary Storage

## Status

Accepted as the third A2 typed-versioned-storage slice.

## Decision

Probe observations persist `ocfleet.observation.summary.v1`: a closed envelope
binding the relational method and result class to a fixed scalar field DTO.
The field catalog covers controller RPC, ocserv, and scheduler success/failure
summaries; unknown, nested, secret-like, address, raw, and unsupported values
are rejected. The one bounded method list is restricted to the fixed ocserv
observation catalog.

Writers canonicalize reviewed internal summaries before insertion. SQLite
migration `0011` canonicalizes exact legacy objects transactionally after the
normal private backup. Store and independent API readers validate the envelope
and relational binding, then return only the established public summary fields;
the persisted schema wrapper is never an output contract.

## Consequences

SQLite schema version increases from `10` to `11` without changing table
shape. Malformed, contaminated, future-version, unknown-field, and mismatched
rows stop upgrade and leave the source database unchanged beside its backup.
RPC, API routes, agent capabilities, trust, feature defaults, and the read-only
boundary do not change. Other dynamic JSON families remain A2 work.
