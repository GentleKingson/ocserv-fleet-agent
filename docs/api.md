# Read-only API

`ocfleet-api` is an experimental Phase 12 observation surface. It reads an
existing controller SQLite database and returns low-sensitive JSON summaries. It
does not call agents, run scheduler jobs, create trust, or write controller
state.

## Start

```bash
ocfleet-api \
  --database controller.sqlite \
  --read-only \
  --listen 127.0.0.1:8080
```

Defaults:

- `--listen 127.0.0.1:8080`
- `--max-limit 1000`
- `--redact default`

`--read-only` is required. The API opens SQLite with `SQLITE_OPEN_READ_ONLY` and
also enables connection-local query-only mode. Startup does not write a
controller audit row because the database connection is read-only.

## Auth

Loopback listeners may run without auth for local operator workflows.
Non-loopback listeners fail closed unless `--auth-token-file` is provided.

```bash
install -m 0600 /dev/null ./api.token
# Put a 32+ byte bearer token into ./api.token.
ocfleet-api --database controller.sqlite --read-only \
  --listen 0.0.0.0:8080 \
  --auth-token-file ./api.token
```

The token file must be private: regular file, owned by the current user, no
symlink or hardlink, not group/world readable, and under a private parent
directory. Clients send `Authorization: Bearer <token>`.

## Response Shape

Every JSON response includes `generated_at`.

List responses:

```json
{
  "generated_at": "2026-07-09T00:00:00Z",
  "limit": 50,
  "count": 1,
  "items": []
}
```

Single-record responses:

```json
{
  "generated_at": "2026-07-09T00:00:00Z",
  "item": {}
}
```

Errors:

```json
{
  "generated_at": "2026-07-09T00:00:00Z",
  "error_code": "BAD_REQUEST",
  "message": "limit must be between 1 and 1000",
  "request_id": "<request-id>"
}
```

## Routes

- `GET /healthz`
- `GET /health/summary`
- `GET /health/nodes`
- `GET /health/nodes/{node_id}`
- `GET /jobs`
- `GET /jobs/{job_id}`
- `GET /runs?limit=&job_id=&status=`
- `GET /runs/{run_id}`
- `GET /observations?limit=&node_id=&method=`
- `GET /observations/{observation_id}`
- `GET /alerts?state=&severity=&node_id=&limit=`
- `GET /alerts/{dedupe_key_or_alert_id}`
- `GET /audit/export?from=&to=&redact=&max_rows=`

`limit` defaults to `50` for query-heavy list routes and may not exceed
`--max-limit`. `--max-limit` itself may not exceed `10000`.

`/audit/export` returns JSON rather than writing a file. It enforces the same
31-day window rule as the CLI audit export. `redact` may be `none`, `default`,
or `strict`; omitted values use the process default.

## Explicit Non-goals

The API intentionally does not implement:

- `POST /rpc`
- `POST /jobs/{id}/run`
- `POST /alerts/{id}/resolve`
- `POST /alerts/{id}/silence`
- any `PUT`, `PATCH`, or `DELETE` mutation surface
- shell, command, script, raw file read, raw logs, raw config, or raw cert routes

Health routes read existing node registry and latest health snapshots. They do
not recompute health or upsert snapshots. Alert routes read existing alert
events. They do not evaluate, silence, resolve, or deliver alerts.

## Redaction

API output is limited to low-sensitive observation fields: IDs, timestamps,
fixed method names, status, counts, error codes, and sanitized summaries.

The API must not return raw RPC response bodies, raw stdout/stderr, raw audit
secret-like fields, username, client IP, session ID, certificate subject/SAN,
issuer, serial, private keys, raw config content, or raw logs.
