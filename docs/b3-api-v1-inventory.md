# B3 Versioned Read-only API Inventory

Issue `#43` is operationally mature. B3 adds a stable `/api/v1`
namespace without removing or changing the experimental legacy routes.

## Implemented

- `GET /api/v1/fleet/summary` computes exact fleet status counts in SQLite.
- `GET /api/v1/nodes` provides keyset cursor pagination ordered by `node_id`.
- `GET /api/v1/health/history` provides bounded half-open time windows, node
  and status filters, and signed composite keyset pagination.
- `GET /api/v1/alerts` provides bounded half-open time windows, node, state,
  severity, and alert-reason filters with signed composite pagination.
- Cursors are HMAC-SHA-256 signed with a process-local random key, are bound to
  the resource and canonical filter set, have a fixed size limit, and fail with
  `INVALID_CURSOR` after tampering or cross-filter reuse.
- Node filters cover region, role, environment, exact string labels, and all
  supported health statuses. Unknown and duplicate scalar query keys fail.
- Responses provide representation ETags, conditional `304`, bounded request
  correlation IDs, and explicit private revalidation caching.
- OpenAPI 3.1 remains GET-only and declares the v1 routes and envelopes.
- Legacy routes remain available during the v0.4 compatibility window.
- Docker reverse-proxy E2E runs nginx in front of the authenticated non-loopback
  API and verifies a v1 response, forwarded correlation ID, ETag, and `304`.

## Compatibility Boundary

The stable v1 contract covers fleet summary, node collection and single-node
projection, health history, alert collection, and single-alert projection.
Experimental unversioned jobs, runs, observations, metrics, and dashboard
routes remain available but are not claimed as stable v1 resources. No v1
route starts RPC, agents, scheduler work, or mutations.
