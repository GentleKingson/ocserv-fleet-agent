# ADR: Alert Operator Transition Atomicity

## Status

Accepted for the A1 atomic mutation-audit milestone.

## Context

Alert silence and resolve previously upserted the alert before inserting their
audit. Webhook-hook creation likewise inserted configuration and audited it in
a second transaction. Audit failure could leave unaudited state, and an
operator transition computed from a stale row could overwrite a newer alert
decision.

## Decision

- Silence and resolve use an `alert-action-<uuid>` operation identity and carry
  an exact before/after record plus the validated reason.
- The writer starts an immediate transaction, verifies persisted state equals
  the supplied before-state, applies the closed transition, inserts its
  low-sensitive actor/reason audit, and commits once.
- Webhook-hook creation validates the closed hook record and commits the hook
  with a redacted audit in one immediate transaction. The hook ID is its replay
  identity; exact same-actor/input retries are no-ops.
- Divergent actor/input replay, invalid transition shape, and stale before-state
  fail closed. The mutation source guard restricts production calls to the
  reviewed store/backend boundary.

## Consequences

Audit failure rolls back the alert or hook change. Operator decisions cannot
silently overwrite a concurrent alert update. Hook audit contains the host and
HMAC key identifier but not the endpoint path or HMAC secret.

Delivery attempts and final `last_sent_at` updates are deliberately separate.
External file or HTTPS I/O cannot be enclosed in a database transaction, so the
next slice must model durable attempt and finalization boundaries rather than
holding SQLite open during network or filesystem work.

No schema, protocol, API route, agent capability, feature default, or network
authorization changes. The API/dashboard remain read-only.
