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

## Compatibility And Rollback

The migration creates an empty queue and three indexes. It does not enqueue old
alerts, enable hooks, read HMAC files, or begin delivery. Older binaries must not
open schema 22. Rollback requires restoring the private pre-migration backup.
