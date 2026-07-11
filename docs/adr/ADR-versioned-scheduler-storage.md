# ADR: Versioned Scheduler Storage Payloads

## Status

Accepted as the first A2 typed-versioned-storage slice.

## Context

Scheduler selectors and path pairs were persisted as open JSON objects. Runtime
validators bounded their contents, but the database did not identify a payload
schema and legacy readers could accept fields that no scheduler operation
needed. This made compatibility ambiguous and increased the risk that secret,
address, nested, or method-shaped data could survive in controller storage.

## Decision

- New selector writes use the closed `ocfleet.scheduler.selector.v1` payload
  with exactly `schema`, `selector`, and nullable `name` fields.
- New path-pair writes use the closed `ocfleet.scheduler.pair.v1` payload with
  exactly `schema`, `source_node_id`, and `target_node_id` fields.
- Selectors are limited to `role=<role>`, `node_id=<node-id>`, or the internal
  `explicit-pair` marker. Roles, node IDs, names, distinct pair endpoints, and
  path/non-path relationships retain their existing bounds.
- SQLite migration `0009` rewrites exact legacy objects into canonical v1
  payloads in one transaction. The historical empty selector is converted to
  `role=ocserv` and disabled for operator review. Exact valid legacy path pairs
  remain enabled.
- Malformed JSON, unknown fields, unsupported schemas, invalid values, and
  contaminated legacy payloads abort migration after the normal private
  pre-migration backup has been created.
- CLI store readers and the independent read-only API adapter deserialize the
  typed payloads and fail closed. Projections expose only fixed typed fields,
  never the persisted JSON object.

## Consequences

Schema version increases from `8` to `9` without adding a table or column. A
v9 database cannot be opened by an older binary. Operators must inspect and
explicitly re-enable quarantined jobs after confirming their selector.

This slice changes no RPC protocol, API route, agent capability, feature
default, trust decision, or network behavior. API and dashboard remain
read-only. Other dynamic controller JSON columns remain A2 work.
