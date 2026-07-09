# Alert Webhook Delivery

Phase 12 supports controller-local HTTPS webhook alert delivery in addition to
the existing `jsonl_file:<path>` hook. Webhooks are explicit controller-local
notification hooks only. They do not trigger agent RPC, scheduler runs, ocserv
changes, user actions, shell commands, scripts, or automatic remediation.

## Threat Model

Webhook delivery treats the receiver URL, DNS, network path, payload, and secret
material as sensitive operational boundaries.

Primary risks:

- SSRF to localhost, private networks, link-local addresses, metadata endpoints,
  or non-HTTP resources.
- Secret leakage through SQLite, audit rows, command output, URL path/query, or
  response logging.
- Payload overexposure through raw RPC bodies, usernames, client IPs, session
  IDs, certificate material, raw logs, raw config, or raw stdout/stderr.
- Retry storms caused by long timeouts, unbounded retries, or unbounded pending
  work.
- Redirects escaping the configured receiver host.

The implementation reduces those risks by requiring HTTPS, an explicit host
allowlist, private HMAC secret files, bounded payloads, bounded attempts, short
timeouts, disabled redirects, and low-sensitive audit rows.

## Config Model

Webhook hook configuration is stored in controller SQLite table `alert_hooks`.
The HMAC secret itself is not stored in SQLite. Operators provide it each time
they add, test, or deliver a webhook through `--hmac-secret-file`.

```bash
ocfleet alert hook add-webhook \
  --name ops-alerts \
  --url https://alerts.example.com/ocfleet \
  --hmac-secret-file /var/lib/ocfleet-controller/webhook.secret \
  --host-allow alerts.example.com \
  --max-attempts 3 \
  --timeout-ms 3000

ocfleet alert hook list --json
ocfleet alert hook test <hook-id> --dry-run --hmac-secret-file /var/lib/ocfleet-controller/webhook.secret
ocfleet alert deliver --hook webhook:<hook-id> --limit 100 --dry-run
ocfleet alert deliver --hook webhook:<hook-id> --limit 100 --hmac-secret-file /var/lib/ocfleet-controller/webhook.secret
```

Limits:

- URL scheme must be `https`.
- URL must not include userinfo or fragments.
- Host must match one configured `--host-allow` entry.
- Resolved IPs must not be loopback, private, link-local, multicast,
  unspecified, shared carrier-grade NAT, or metadata addresses.
- Redirect following is disabled.
- Timeout must be between 1000 and 5000 ms.
- Attempts must be between 1 and 5.
- Response bodies are read only up to a small cap and are never logged.

The `alert_delivery_attempts` table records low-sensitive attempt metadata:
`alert_id`, `hook_id`, `attempt_no`, `attempted_at`, `status`,
`http_status_class`, `error_code`, and `bytes_sent`. It does not store full
URLs, secrets, request bodies, response bodies, usernames, client IPs, or raw
logs.

## Payload Schema

Webhook delivery reuses the alert delivery payload projection with
`hook_type="webhook"` and `schema="ocfleet.alert.v1"`.

Example:

```json
{
  "schema": "ocfleet.alert.v1",
  "hook_type": "webhook",
  "alert_id": "alert-...",
  "dedupe_key": "node:hk-ocserv-01:node_stale",
  "node_id": "hk-ocserv-01",
  "severity": "warning",
  "state": "open",
  "reason_code": "NODE_STALE",
  "first_seen_at": "2026-07-08T00:00:00Z",
  "last_seen_at": "2026-07-08T00:00:00Z",
  "last_sent_at": null,
  "resolved_at": null,
  "methods": ["probe.controller.ping"],
  "summary": {
    "status": "stale"
  }
}
```

Forbidden payload content remains forbidden for webhook and JSONL delivery:
raw RPC bodies, raw stdout/stderr, raw logs, raw config, certificate
subject/SAN/issuer/serial values, usernames, client IPs, and session IDs.

## HMAC Signing

Every non-dry-run webhook request includes:

- `X-Ocfleet-Signature: sha256=<hex-hmac>`
- `X-Ocfleet-Timestamp: <rfc3339>`
- `X-Ocfleet-Delivery-Id: <delivery-id>`
- `X-Ocfleet-Hook-Id: <hook-id>`
- `X-Ocfleet-Hmac-Key-Id: <short-secret-hash>`

The signature message is:

```text
<timestamp>.<delivery-id>.<raw-json-request-body>
```

The algorithm is HMAC-SHA256 with the bytes from `--hmac-secret-file`.
Receivers should reject stale timestamps, duplicate delivery IDs, and signature
mismatches. Rotate the secret by creating a new private secret file, adding a
new hook or updating operational delivery to the matching hook key id, testing
with `--dry-run`, and disabling the old receiver path outside ocfleet.

## Receiver Example

Pseudo-code for a receiver:

```text
read raw body bytes
read X-Ocfleet-Timestamp, X-Ocfleet-Delivery-Id, X-Ocfleet-Signature
reject if timestamp is stale
reject if delivery id was already seen
expected = "sha256=" + hmac_sha256_hex(secret, timestamp + "." + delivery_id + "." + body)
constant_time_compare(expected, signature)
parse JSON
accept only schema == "ocfleet.alert.v1"
store or notify using low-sensitive fields only
```

## Audit Behavior

Adding a webhook writes `alert.hook.add_webhook` with the hook id, hook type,
name, endpoint host, redacted endpoint URL, HMAC key id, enabled state, attempts,
and timeout. It does not store the secret or the URL path/query.

Delivery writes `alert.delivery` success or failure rows with hook type,
alert count, byte count, dry-run state, and a low-sensitive error code when
applicable. Per-attempt HTTP outcome is stored in `alert_delivery_attempts`.
No audit row stores webhook secrets, full URL path/query, request body, response
body, or raw network errors.

## Troubleshooting

- `webhook URL must use https`: replace the endpoint with an HTTPS URL.
- `webhook URL host is not in the host allowlist`: add the exact host with
  `--host-allow`.
- `webhook resolved IP is forbidden`: the host resolves to localhost, private,
  link-local, metadata, multicast, or otherwise forbidden address space.
- `webhook HMAC secret does not match hook key id`: use the secret file that
  was used when the hook was added, or add a new hook for a rotated secret.
- `WEBHOOK_REDIRECT_FORBIDDEN`: configure the receiver to return 2xx directly.
- `WEBHOOK_TIMEOUT` or `WEBHOOK_HTTP_5XX`: retry is bounded by hook
  `max_attempts`; inspect receiver availability without logging secret values.

Do not work around a rejected webhook by adding `exec:`, `command:`, `shell:`,
or `script:` hooks. Those hook types remain forbidden.
