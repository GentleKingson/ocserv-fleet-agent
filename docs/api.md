# Read-only API

`ocfleet-api` is an experimental Phase 12 observation surface. It reads an
existing controller SQLite database and returns low-sensitive JSON summaries. It
does not call agents, run scheduler jobs, create trust, or mutate controller
records.

The machine-readable contract lives at `docs/api/openapi.yaml`. It uses OpenAPI
3.1.1, declares only `GET` operations, and defines the bounded projection for
each stored record type.

`/api/v1` is the stable read-only compatibility namespace introduced in B3.
The unversioned Phase 12 routes remain available through the v0.4 compatibility
window and are not aliases for write or RPC-trigger behavior.

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

Loopback listeners may run without auth for local development. Non-loopback
listeners fail closed unless `--auth-token-file` or a remote method in a private
`--auth-config-file` is provided.

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
  --cursor-key-file ./cursor-keys.json \
  --auth-token-file ./api.token
```

All listeners require `--cursor-key-file`. It must be an owner-only regular
file under a private directory and use this closed format:

```json
{
  "schema": "ocfleet.cursor-keys.v1",
  "current": {
    "key_id": "cursor-2026-07",
    "key_base64": "<base64-encoded 32 random bytes>"
  }
}
```

During rotation, move the old entry to optional `previous` and install a new
`current` entry. Both key IDs must differ. Cursors expire at a deterministic
UTC-day boundary 24-48 hours after issuance; keep `previous` for 48 hours
before removing it. Instances behind one load balancer must read the same key
file. Key material is never returned or logged.

The legacy token file must be private: regular file, owned by the current user, no
symlink or hardlink, not group/world readable, and under a private parent
directory. Clients send `Authorization: Bearer <token>`.

The private auth config supports expiring service accounts, OIDC, forwarded
mTLS identity, and an explicitly enabled one-hour break-glass principal. The
fixed roles are `viewer`, `operator`, `security-admin`, `change-approver`, and
`auditor`. Every route calls an explicit permission check; unmatched roles and
OIDC groups are denied. Legacy bearer tokens retain viewer compatibility.

OIDC accepts only EdDSA JWTs and validates signature, pinned `kid`, issuer,
audience, `exp`, `nbf`, subject, and an explicit group-to-role mapping. Keys may
be listed in the auth config or loaded from an absolute private standard JWKS
cache containing `OKP`/`Ed25519` signing keys. Multiple key IDs support a
rotation window. Updating the pinned cache requires a controlled API restart;
the API never follows token-provided key URLs.

Forwarded mTLS identity is accepted only on a loopback listener and only with an
independent proxy-auth secret. A trusted TLS proxy must remove all
client-supplied `X-Ocfleet-Mtls-*` headers, verify the client certificate, set
`X-Ocfleet-Mtls-Verified: SUCCESS`, forward the exact certificate subject in
`X-Ocfleet-Mtls-Subject`, and set `X-Ocfleet-Mtls-Proxy-Secret` to a private
random token of at least 32 bytes. The API validates its configured SHA-256
digest with a constant-time comparison before trusting the subject. This makes
direct loopback requests from other local processes fail closed. Direct
non-loopback startup with mTLS subject mappings is also rejected. The proxy must
not log the secret header and should rotate it through the same private secret
distribution used for service credentials.

Example owner-only auth config:

```toml
local_development = false
mtls_proxy_secret_sha256 = "<lowercase-sha256-of-32+-byte-proxy-secret>"

[[service_accounts]]
principal_id = "service:inventory-reader"
token_sha256 = "<lowercase-sha256-of-32+-byte-token>"
expires_at = "2026-07-15T00:00:00Z"
roles = ["viewer"]

[oidc]
issuer = "https://identity.example"
audience = "ocfleet-api"
groups_claim = "groups"
jwks_file = "/run/secrets/ocfleet-oidc-jwks.json"

[[oidc.role_mappings]]
group = "ocfleet-operators"
role = "operator"

[[mtls_subjects]]
subject = "CN=ocfleet-auditor,O=Example"
principal_id = "mtls:ocfleet-auditor"
roles = ["auditor"]
```

Authentication failures and permission denials increment only the fixed
`missing`, `invalid`, `expired`, and `forbidden` metric labels. Logs never
include tokens, JWT claims, subjects, configured hashes, keys, or private file
paths. All implemented data routes remain read-only `GET` observation routes;
there is still no authenticated mutation or agent-RPC trigger route.

`GET /` serves only the static dashboard shell and remains loadable when bearer
auth is configured. Every JSON data request made by that page still requires
the configured token. Tokens stay in page memory and are not persisted by the
dashboard.

`GET /metrics` serves Prometheus text and follows the same authorization rule
as JSON data routes. Its fixed low-cardinality catalog is documented in
`docs/metrics.md`; it never includes identifiers, addresses, requests, sessions,
tokens, paths, or other data-derived label values.

## Response Shape

Legacy JSON successes and every error response include `generated_at`. Stable
`/api/v1` success envelopes contain only deterministic `data`; this lets their
strong ETag identify the complete response bytes. Rejected
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
| `GET /api/v1/fleet/summary` | exact fleet status distribution with ETag |
| `GET /api/v1/version/readiness` | bounded version distribution, compatibility, readiness, and derived read-only alerts with ETag |
| `GET /api/v1/nodes?limit=&cursor=&region=&role=&environment=&label=&status=` | signed keyset-paginated node health and metadata |
| `GET /api/v1/nodes/{node_id}` | conditional single-node health and metadata |
| `GET /api/v1/health/history?from=&to=&limit=&cursor=&node_id=&status=` | signed keyset-paginated health history |
| `GET /api/v1/alerts?from=&to=&limit=&cursor=&state=&severity=&node_id=&reason=` | signed keyset-paginated alert history |
| `GET /api/v1/alerts/{dedupe_key_or_alert_id}` | conditional single-alert projection |

Every `/api/v1` `200` response uses a strong ETag computed over the complete
deterministic envelope. Two responses with the same ETag are byte-identical;
`If-None-Match` returns an empty `304` when that representation is unchanged.

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
All RFC3339 window boundaries for `/health/slo`, `/api/v1/health/history`, and
`/api/v1/alerts` are normalized to UTC before SQLite comparison. The v1 cursor
filter hash uses the same canonical UTC values, so equivalent `Z`, positive
offset, and negative offset windows share pagination semantics.
