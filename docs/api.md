# Read-only API

`ocfleet-api` is an experimental Phase 12 observation surface. It reads an
existing controller SQLite database and returns low-sensitive JSON summaries. It
does not call agents, run scheduler jobs, create trust, or mutate controller
records.

The machine-readable contract lives at `docs/api/openapi.yaml`. It uses OpenAPI
3.1.1, declares only `GET` operations, and defines the bounded projection for
each stored record type.

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
also enables connection-local query-only mode and disables trusted schema
features. Before every open it validates the database and fixed
`<database>-wal`/`<database>-shm` sidecars as private, owner-controlled regular
files with no symlink or hardlink, and validates them again after SQLite opens.
When these WAL runtime files are absent, the API creates only those two fixed
paths with private permissions before opening SQLite; the database directory
therefore must remain writable by the API account. SQLite may manage their
contents even on a read-only WAL connection. They are runtime coordination
files, not controller records: the API never mutates a table or writes a
controller audit row. Startup requires the exact current schema version, all
API tables, and a successful SQLite `quick_check`; it never migrates an old or
future schema.

## Auth

Loopback listeners may run without auth for local operator workflows.
Non-loopback listeners fail closed unless `--auth-token-file` is provided.

`ocfleet-api` serves plain HTTP and does not terminate TLS. Never expose port
8080 directly to the public Internet and never send its bearer token over a
cleartext network connection. A non-loopback deployment must place the API
behind a TLS-terminating reverse proxy, restrict the listener with a host
firewall or private network, and forward only the documented read-only routes.
Loopback binding remains the recommended local-operator mode.

```bash
install -m 0600 /dev/null ./api.token
# Put a 32+ byte bearer token into ./api.token.
# Internal upstream only; firewall access to the TLS proxy.
ocfleet-api --database controller.sqlite --read-only \
  --listen 0.0.0.0:8080 \
  --auth-token-file ./api.token
```

The token file must be private: regular file, owned by the current user, no
symlink or hardlink, not group/world readable, and under a private parent
directory. Clients send `Authorization: Bearer <token>`.

The current API role is `viewer`: all implemented data routes are read-only
`GET` observation routes. A configured bearer token resolves to an
authenticated `viewer` principal; it does not unlock another route or
operation. The RBAC foundation reserves `operator` and `security-admin` for
future authenticated mutation surfaces, but no such routes exist today. Any
future non-GET API route must require authentication and an explicit role
check.

`GET /` serves only the static dashboard shell and remains loadable when bearer
auth is configured. Every JSON data request made by that page still requires
the configured token. Tokens stay in page memory and are not persisted by the
dashboard.

`GET /metrics` serves Prometheus text and follows the same authorization rule
as JSON data routes. Its fixed low-cardinality catalog is documented in
`docs/metrics.md`; it never includes identifiers, addresses, requests, sessions,
tokens, paths, or other data-derived label values.

## Response Shape

Every JSON API success or error response includes `generated_at`. Rejected
methods, unknown routes, malformed query strings, unsupported query keys, and
invalid identifiers use the same structured error envelope. All responses send
`Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

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

| Route | Stored projection |
| --- | --- |
| `GET /` | static read-only dashboard shell |
| `GET /healthz` | API and SQLite readability |
| `GET /health/summary` | fleet status counts |
| `GET /health/nodes` | bounded node health rows |
| `GET /health/nodes/{node_id}` | one node health row |
| `GET /jobs` | bounded scheduler job rows |
| `GET /jobs/{job_id}` | one scheduler job row |
| `GET /runs?limit=&job_id=&status=` | bounded stored run rows |
| `GET /runs/{run_id}` | one stored run row |
| `GET /observations?limit=&node_id=&method=` | bounded low-sensitive observations |
| `GET /observations/{observation_id}` | one low-sensitive observation |
| `GET /alerts?state=&severity=&node_id=&limit=` | bounded alert rows |
| `GET /alerts/{dedupe_key_or_alert_id}` | one alert row |
| `GET /audit/export?from=&to=&redact=&max_rows=` | bounded audit window |

`limit` and `max_rows` default to `50` and may not exceed `--max-limit`.
`--max-limit` itself must be from `1` through `10000`. Unknown query keys,
duplicate scalar keys, and non-numeric limits are rejected rather than ignored.

`/audit/export` returns JSON rather than writing a file. It enforces the same
31-day window rule as the CLI audit export. The API requests one sentinel row
past `max_rows` and rejects an overflowing result rather than returning a
silently truncated export. `redact` may be `none`, `default`, or `strict`;
omitted values use the process default. Secret-like audit keys remain redacted
in every mode.

Example local queries:

```bash
curl --fail http://127.0.0.1:8080/health/summary
curl --fail 'http://127.0.0.1:8080/runs?limit=25&status=failed'
curl --fail 'http://127.0.0.1:8080/audit/export?from=2026-07-09T00%3A00%3A00Z&to=2026-07-10T00%3A00%3A00Z&max_rows=50&redact=strict'
```

When bearer auth is configured, add `Authorization: Bearer <token>` without
placing the token in the URL.

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
Dynamic summary objects are capped at 32 entries per object/array, four nesting
levels, and 256 bytes per string. Oversized or forbidden values are replaced or
dropped rather than truncated into a potentially misleading value.

Alert and health method arrays accept only the fixed observation method
catalog and at most 16 entries. If stored JSON contains an unknown method, a
non-string item, or too many entries, the projection drops the entire method
array. It never reflects the polluted value into the API or dashboard.

The API must not return raw RPC response bodies, raw stdout/stderr, raw audit
secret-like fields, username, client IP, session ID, certificate subject/SAN,
issuer, serial, private keys, raw config content, or raw logs.
`GET /health/slo` accepts a required fixed `window` (`24h`, `7d`, or `30d`),
an aligned RFC3339 `to`, and an optional `node_id`. It returns bounded,
low-sensitive projections from stored rollups only and never triggers probes or
agent RPC. Missing coverage is explicit and excluded from health-sample ratios.
