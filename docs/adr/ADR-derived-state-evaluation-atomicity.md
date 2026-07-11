# ADR: Derived-State Evaluation Atomicity

## Status

Accepted for the A1 atomic mutation-audit milestone.

## Context

Health commands previously upserted snapshots one row at a time and wrote their
summary audit afterward. Alert evaluation similarly upserted candidates before
writing its evaluation audit. A database or process failure could therefore
leave a partial derived-state batch or committed state without matching audit.
Alert evaluation also reads candidates before writing, so a later upsert could
overwrite a concurrent operator silence or resolve.

## Decision

- A health evaluation has a bounded batch of at most 1,000 snapshots, a closed
  `health.summary` or `health.node` event, and a `health-eval-<uuid>` identity.
  All snapshots and one low-sensitive audit commit in one immediate SQLite
  transaction.
- An alert evaluation has at most 1,000 before/after entries and an
  `alert-eval-<uuid>` identity. The writer compares every current row with its
  evaluated before-state inside the immediate transaction, then commits all
  candidate rows and one low-sensitive audit together.
- Exact retries require the same actor and canonical input hash and return as a
  no-op. Reused identities with different provenance or input fail closed.
- Evaluation audits contain only the evaluation identity and aggregate counts.
  Candidate detail remains subject to the bounded low-sensitive JSON validator.
- Direct production calls to these derived-state writers are restricted to the
  reviewed store/backend boundary by the mutation source guard.

## Consequences

Audit insertion failure rolls back every row in the evaluation. A stale alert
evaluation fails rather than overwriting a newer operator decision. Health and
alert evaluation remain controller-local and make no agent RPC. Alert
silence/resolve, hook configuration, and delivery are separate mutation
families and remain follow-up A1 work.

This decision changes no schema, protocol, API route, feature default, agent
capability, or network authorization boundary. The API and dashboard remain
read-only.

## Rollback

No migration is involved. Reverting the writer integration restores the known
partial-write and unaudited-state risks and is not suitable for production.
Existing snapshot, alert, and audit rows remain schema-compatible.
