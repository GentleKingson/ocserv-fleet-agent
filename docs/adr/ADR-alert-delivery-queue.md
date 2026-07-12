# ADR: Fenced Automatic Alert Delivery Queue

## Status

Accepted for A5.

## Context

Manual alert delivery already validates fixed JSONL and HTTPS webhook outputs,
persists bounded attempts, enforces HTTPS host allowlists and public resolution,
rejects redirects, signs webhook bodies, and never exposes a command or template
surface. Automatic delivery additionally needs durable work ownership, retry and
dead-letter lifecycle, recovery, grouping, rate limits, and restart semantics.

## Decision

Schema 22 adds `alert_delivery_queue`. Each row binds one alert, one persisted
webhook hook, a 64-character idempotency key, and a bounded group key. Lifecycle
states are `pending`, `claimed`, `retry`, `dead_letter`, and `succeeded`.

Claimed rows require an owner, claim timestamp, live lease timestamp, and a
positive monotonic fence token. Non-claimed rows cannot retain claim metadata.
Attempts are capped at five. Successful rows require a delivery timestamp and
dead-letter rows require a fixed bounded error code. Due and lease indexes allow
deterministic bounded acquisition and recovery without scanning payload bodies.

Queue rows contain no webhook body, HMAC secret, endpoint URL, address, command,
script, template, or raw error. The worker must re-read and revalidate the
persisted hook at dispatch time and continue using the existing hardened HTTPS
transport. JSONL remains an explicit operator-supplied local action because its
path is not persisted and must not become daemon-selected filesystem authority.

Actor-bound `StoreWriter` methods enqueue exact idempotent work, acquire the
earliest due item, renew its lease, recover at most 100 expired claims, and
commit each attempt with its retry, dead-letter, or success transition and audit
in one immediate transaction. Recovery does not consume an attempt. Claims use
monotonic fences, and stale owners cannot renew or persist outcomes after
takeover. Retry timestamps are explicit, bounded to one hour, and permitted only
for retryable failures below the hook attempt cap.

The worker reuses the hardened request builder and sender. It revalidates the
hook and reads only `<hook-id>.key` below one explicit operator directory. A
tick attempts at most 100 items and at most three items per group; excess group
work is atomically deferred without consuming an attempt. Successful alert
versions are suppressed for five minutes. Signal handlers are installed before
the first evaluation, and shutdown completes the admitted blocking attempt and
its fenced outcome before returning.

## Compatibility And Rollback

The migration creates an empty queue and three indexes. It does not enqueue old
alerts, enable hooks, read HMAC files, or begin delivery. Older binaries must not
open schema 22. Rollback requires restoring the private pre-migration backup.
