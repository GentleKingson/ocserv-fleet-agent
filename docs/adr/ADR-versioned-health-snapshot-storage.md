# ADR: Versioned Health Snapshot Storage

## Status

Accepted as the second A2 typed-versioned-storage slice.

## Context

Health snapshots persisted degraded methods and derived summary fields as open
JSON. The values are controller-derived and advisory, but they feed alert
evaluation and the read-only API. Open objects allowed compatibility ambiguity
and made polluted address, secret, method, or nested fields indistinguishable
from supported state.

## Decision

- Degraded methods use the closed
  `ocfleet.health.degraded-methods.v1` payload with a sorted unique list drawn
  from the five fixed ocserv observation methods.
- Derived summary data uses the closed `ocfleet.health.summary.v1` payload with
  schema, optional region/role, snapshot status, optional endpoint lifecycle
  status, and an optional bounded consecutive-failure count.
- The summary status must equal the relational `health_snapshots.status` value.
- New health evaluation writes construct these payloads before entering the
  atomic snapshot/audit writer. Store and API readers deserialize both payloads
  and fail closed before alert evaluation or projection.
- SQLite migration `0010` canonicalizes exact legacy arrays and summary objects.
  Empty historical summaries retain the relational status and receive null
  optional fields. Unknown fields, unsupported methods or versions, malformed
  values, and status mismatches abort migration after the normal private backup.
- CLI and API output preserve the existing fixed public shape and never expose
  the persisted schema wrapper.

## Consequences

SQLite schema version increases from `9` to `10` without adding a table or
column. Older binaries refuse the forward schema. Exact legacy snapshot meaning
is preserved without inventing missing region, role, endpoint state, or failure
counts.

This changes no health policy, alert threshold, RPC protocol, API route, agent
capability, feature default, trust decision, or network behavior. API and
dashboard remain read-only. Other dynamic controller JSON families remain A2
work.
