# Web Dashboard

The Web dashboard is an experimental static page served by `ocfleet-api` at
`GET /`. It is an observation view over the read-only API, not a control
surface.

## Start

```bash
ocfleet-api --database controller.sqlite --read-only --listen 127.0.0.1:8080
```

Open `http://127.0.0.1:8080/` from the same host. For non-loopback listeners,
configure `--auth-token-file`; the page accepts a bearer token in memory for the
current browser page and sends it on API requests. It does not store the token in
local storage.

## Current Views

- fleet health summary
- node health table from latest stored health snapshots
- scheduler jobs
- open alerts
- recent observability runs
- recent low-sensitive observations
- bounded audit export preview

The dashboard calls only read-only `GET` endpoints. It has no controls for
running jobs, calling agent RPCs, resolving or silencing alerts, changing
retention policy, editing trust, or modifying the node registry.

The audit preview submits a same-origin `GET /audit/export` request with a
bounded time window and row count. It presents only the API projection and
offers `default` or `strict` redaction; it does not create a server-side file or
write an audit row.

`GET /` is served with a Content-Security-Policy header that denies default
loads, allows same-origin API fetches, and permits the static inline dashboard
style/script only by SHA-256 hash. The route also sends `X-Content-Type-Options:
nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, and
`Cache-Control: no-store`.

The dashboard builds table cells with DOM text nodes rather than HTML string
insertion. Stored values cannot create markup. Its single fetch helper sets
`method: GET` explicitly, and the page contains no non-GET fetch or form and no
beacon or XHR path.

## Limits

- The dashboard is not production-complete.
- It does not include a login/session provider.
- Health views do not recompute or upsert snapshots; they show stored state.
- Alert views do not evaluate rules or deliver hooks.
- Audit export remains available through the read-only JSON API route and the
  local CLI file export.

## Browser Verification

`npm run test:e2e` starts an isolated, initialized controller database and the
read-only API on loopback, then runs Chromium checks at desktop and narrow
viewports. The suite verifies CSP, all dashboard views, refresh, audit preview,
empty-state rendering, console cleanliness, and that every browser request uses
`GET`. CI installs dependencies from `package-lock.json` and does not upload
traces or controller state.
