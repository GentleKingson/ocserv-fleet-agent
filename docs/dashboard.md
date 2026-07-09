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
- open alerts
- recent observability runs
- recent low-sensitive observations

The dashboard calls only read-only `GET` endpoints. It has no controls for
running jobs, calling agent RPCs, resolving or silencing alerts, changing
retention policy, editing trust, or modifying the node registry.

## Limits

- The dashboard is not production-complete.
- It does not include a login/session provider.
- Health views do not recompute or upsert snapshots; they show stored state.
- Alert views do not evaluate rules or deliver hooks.
- Audit export remains available through the read-only JSON API route and the
  local CLI file export.
