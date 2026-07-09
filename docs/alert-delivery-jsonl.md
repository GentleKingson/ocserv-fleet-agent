# Alert Delivery JSONL

Phase 12 alert delivery currently supports only the local `jsonl_file:<path>`
hook. Webhook hooks are planned / not implemented and are rejected; `exec:`,
`command:`, `shell:`, and `script:` hooks are forbidden.

## Commands

```bash
ocfleet alert test jsonl_file:/var/lib/ocfleet-controller/alerts/test.jsonl
ocfleet alert deliver --hook jsonl_file:/var/lib/ocfleet-controller/alerts/alerts.jsonl --limit 100
ocfleet alert deliver --hook jsonl_file:/var/lib/ocfleet-controller/alerts/alerts.jsonl --limit 100 --dry-run
```

`alert deliver` evaluates controller-local alert state, selects bounded open
alerts, writes one compact JSON object per line, and updates `last_sent_at` only
after a successful non-dry-run write. It does not call agents or execute local
commands.

## Payload Schema

Each delivered line is a low-sensitive JSON object:

```json
{
  "event": "alert.event",
  "hook_type": "jsonl_file",
  "dedupe_key": "node:hk-ocserv-01:node_stale",
  "node_id": "hk-ocserv-01",
  "severity": "warning",
  "state": "open",
  "reason_code": "NODE_STALE",
  "first_seen_at": "2026-07-08T00:00:00Z",
  "last_seen_at": "2026-07-08T00:00:00Z",
  "methods": ["probe.controller.ping"],
  "summary": {
    "status": "stale",
    "freshness_seconds": 90000
  }
}
```

Allowed top-level fields are alert IDs/keys, node ID, severity, lifecycle state,
fixed reason code, timestamps, fixed method names, and a sanitized summary.
Allowed summary keys are bounded status/counter fields such as `status`,
`last_error_code`, `freshness_seconds`, `consecutive_failures`,
`days_remaining`, `endpoint_id`, `endpoint_status`, and `result_class`.

Payloads must not contain username, client IP, session ID, certificate subject,
issuer, serial, SAN, raw stdout/stderr, raw RPC body, raw log lines, config
content, local paths, command names, or remediation instructions.

## File Safety

The output file is created or appended through the private file helper. The
destination must be a regular private file under a private directory. Symlinks,
hardlinks, world-readable files, world-writable parents, and directory targets
are rejected. Delivery failures write an `alert.delivery` audit record with a
bounded error code.
