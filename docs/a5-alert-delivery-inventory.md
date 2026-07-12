# A5 Safe Alert Delivery Worker Inventory

## Scope And Decision

A5 provides fixed low-sensitivity JSONL and HTTPS webhook delivery without any
command, shell, script, template, remediation, or agent-RPC surface. JSONL is an
explicit operator-path action; the daemon never persists or selects a local
filesystem path. Automatic delivery is therefore limited to persisted HTTPS
webhook hooks whose endpoint authority is allowlisted and revalidated on every
attempt. This least-authority split is recorded in
`docs/adr/ADR-alert-delivery-queue.md`.

## Requirement Evidence

| Requirement | Implementation | Verification |
| --- | --- | --- |
| Fixed JSONL and HTTPS DTOs | `alert_delivery.rs` and `alert_webhook.rs` serialize closed bounded payloads. JSONL remains operator-invoked; the worker uses HTTPS only. | `alert_hooks_tests` covers fixed JSONL, webhook bodies, oversized payload rejection, and redaction. |
| Per-hook enable/disable | `alert hook enable\|disable` uses an actor-bound transactional writer. Repeating the desired state is a no-op. Disabled hooks cannot enqueue or dispatch. | `alert_hook_enable_state_is_idempotent_atomic_and_visible_in_delivery_health` proves idempotency and audit-failure rollback. |
| Queue, claims, and recovery | Schema 22 stores bounded queue state. Claim transactions recover at most 100 expired leases, increment monotonic fences, and reject stale owners. | `alert_delivery_queue_is_fenced_retryable_and_idempotent` covers competing claims, takeover, stale-fence rejection, and recovery audit. |
| Retry and dead letter | Attempts and queue outcomes commit atomically. Retry uses bounded exponential delay and the hook attempt cap; permanent and exhausted failures enter `dead_letter`. | Worker retry/DLQ tests and queue writer tests cover retry timing, permanent failure, history, and rollback. |
| Grouping and rate limits | Queue rows carry bounded severity/reason group keys. A tick has a global cap and permits three attempts per group; excess work is durably deferred without consuming an attempt. Successful alert versions are suppressed for five minutes. | `alert_worker_caps_each_group_without_starving_another_group` and replay tests cover group deferral and repeat suppression. |
| Delivery health and history | `alert worker status [--json]` reports aggregate queue states, due work, expired claims, oldest due time, and latest attempt time. Attempt rows retain fixed status classes/error codes and byte counts, never bodies. | Store/CLI tests cover populated health, attempts, and dead-letter state. |
| Idempotency | Alert/hook/version input produces deterministic idempotency and queue keys. Exact enqueue replay is accepted without another row. | Queue and worker replay tests cover duplicate suppression. |
| Graceful shutdown | `alert worker daemon` and compatibility command `alert delivery-daemon` install signal handling before work, finish the admitted synchronous attempt/outcome, then stop. | `alert_worker_daemon_drains_on_sigterm_and_restarts` covers repeated SIGTERM/restart with no stranded claim. |
| Webhook security | Dispatch requires HTTPS, explicit host allowlist, public-IP resolution, no redirects, HMAC, bounded body/response/timeout, and private owned secret files. Hook configuration is reloaded before each attempt. | SSRF, DNS, metadata, redirect, signature, size, secret mode/symlink/hardlink, and audit-redaction tests pass. |
| No execution/remediation | No hook schema or CLI field accepts commands, scripts, templates, service units, selectors, or remediation actions. Queue/audit rows exclude URL, body, secret, path, raw response, and raw error data. | Controller mutation guard, typed schema checks, rejected-hook tests, and source inventory enforce the boundary. |

## Operational Commands

```text
ocfleet alert hook enable <hook-id>
ocfleet alert hook disable <hook-id>
ocfleet alert worker run --hmac-secret-dir <private-0700-dir> --json
ocfleet alert worker daemon --hmac-secret-dir <private-0700-dir>
ocfleet alert delivery-daemon --hmac-secret-dir <private-0700-dir>
ocfleet alert worker status --json
```

The worker secret directory must be owned by the effective user, must not be a
symlink, and must have mode `0700`. Each `<hook-id>.key` is opened with the
existing owner, regular-file, `0600`, no-symlink, and no-hardlink checks.

## Release Evidence

- Schema and queue invariants: pull request `#92`.
- Transactional queue writers and recovery: pull request `#93`.
- Automatic webhook worker and shutdown path: pull request `#94`.
- Enable/disable, delivery health, compatibility command, and this completion
  audit: the A5 completion pull request recorded in `docs/next-roadmap.md`.
- Required local gates: rustfmt, default/all-feature clippy, default/all-feature
  workspace tests, documentation claims, action pinning, release validation,
  controller mutation guards, and install smoke coverage.
