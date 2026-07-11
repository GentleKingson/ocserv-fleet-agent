# ADR: Enrollment Transition Atomicity

## Status

Accepted.

## Context

Enrollment token issuance/use and join-request rejection previously used direct
store mutations with incomplete actor normalization. A process failure or audit
failure must not leave an unaudited token, usage counter, expiry, revocation, or
request decision. Automatic retry must also not spend a token twice or rewrite
a terminal decision.

The existing schema already has stable token IDs, unique token hashes, stable
join-request IDs, closed status values, usage counters, and controller audit
rows. Adding a second idempotency table would duplicate that state and require
a migration without strengthening the contract.

## Decision

- Every token creation, use, lazy expiry, revocation, and request rejection is
  an actor-bearing `StoreWriter` operation using an immediate SQLite
  transaction.
- The business change and its low-sensitive audit row commit together. Audit
  failure rolls back the entire transaction.
- Token credentials remain hash-only at rest. Secret-bearing inputs and records
  use redacted `Debug` implementations.
- A submission carries a caller-visible `join-<uuid>` request ID. An exact
  same-actor replay returns the existing request without another usage or audit
  row; different inputs or actor fail closed.
- Token usage uses a compare-and-set counter and status predicate. Immediate
  transactions serialize competing final-use submissions.
- Lazy expiry changes `active` to `expired` and writes both expiry and rejection
  audits in the same transaction.
- Revocation accepts only `active -> revoked`. Request rejection accepts only
  `pending -> rejected`. Exact same-actor, same-reason terminal retries are
  no-ops; divergent retries and other terminal transitions are rejected.
- Creation idempotency is based on immutable issuance metadata and its unique
  audit provenance. A later use, expiry, or revocation does not make an exact
  creation retry a conflict.
- The production mutation guard covers all enrollment mutators outside the
  reviewed store/backend boundary.

## Consequences

Retries are deterministic and cannot double-spend a token or overwrite an
operator decision. Corrupt or ambiguous audit provenance fails closed. The CLI
gains optional `--request-id`, token revocation, and request rejection controls,
but the SQLite schema, RPC protocol, read-only HTTP API, agent capabilities, and
default read-only boundary do not change.

This design deliberately does not add automatic enrollment, trust-on-first-use,
hostname/label identity inference, automatic repair, or any agent mutation.
