# B7 Protocol Capability Negotiation Inventory

## Scope And Decision

B7 implements only the fixed read-only `node.capabilities` RPC. The response is
a versioned compatibility observation, never an authorization source or an
automatic feature switch. No SQLite migration or API route is added.

| Requirement | Implementation and evidence |
| --- | --- |
| Protocol min/max and agent version | Closed `NodeCapabilitiesResponse`; protocol ranges and a 64-byte closed-ASCII version are validated. |
| Supported fixed methods | `FixedRpcMethod` and `READONLY_FIXED_METHOD_CATALOG` are closed enums/catalogs; sorted, unique, non-empty, maximum 32. |
| Provider schema versions | Closed `ProviderSchemaId`, sorted unique ranges, maximum 8; the agent reports ocserv snapshot schema v2. |
| Fixed feature flags | Closed `AgentFeatureFlag`, sorted unique list, maximum 16. |
| Controlled-write state | Separate compile-time and local-enable booleans; local enablement without compilation is invalid. No write method exists in the advertised enum. |
| No local detail or secrets | Empty closed request and closed response have no path, command, unit, selector, local-policy, secret, raw-config, or output field. Serialized response is capped at 16 KiB. |
| Agent dispatch and authorization | Controller callers may request the method; peer callers are rejected. Dispatch ignores no caller-selected local input because the request must be empty. |
| Controller fail closed | Decode rejects unknown fields and invalid bounds. Protocol mismatch or omission of `node.capabilities` maps to `SCHEMA_VERSION_UNSUPPORTED`. |
| Old-agent behavior | Only `METHOD_NOT_FOUND` maps to deterministic `legacy_unsupported`; compatibility is unknown and actions stay disabled. Other failures are preserved. |
| No automatic enablement | Human/JSON output and audit compatibility projections explicitly keep `actions_enabled=false`; the result does not mutate config, trust, or dispatch catalogs. |
| Low-sensitive audit | Audit summary records version/range, counts, compatibility, and booleans, dropping raw capability lists. |

## Compatibility Matrix

| Agent response | Controller result | Feature effect |
| --- | --- | --- |
| Valid range containing protocol 1 | `compatible` | None; actions disabled. |
| Future/older non-overlapping range | Fail closed with `SCHEMA_VERSION_UNSUPPORTED` | None. |
| Valid DTO missing `node.capabilities` | Fail closed with `SCHEMA_VERSION_UNSUPPORTED` | None. |
| Unknown field, enum, duplicate, order, or bound violation | Fail closed with `INVALID_RESPONSE` | None. |
| Legacy `METHOD_NOT_FOUND` | `legacy_unsupported`, compatibility unknown | None; no inferred capability. |
| Any other RPC error | Preserve the error | None. |

## Verification

Direct consumers are covered by:

- `ocfleet-protocol/tests/capabilities_tests.rs` for serialization, unknown
  fields, list/string bounds, ordering, compatibility, and the closed catalog;
- `ocfleet-agent/tests/agent_unit_tests.rs` for dispatch, controller/peer
  authorization, default/all-feature controlled-write reporting, and absence
  of sensitive local configuration;
- `ocfleet-cli/tests/controller_rpc_tests.rs` for decode, future/missing
  capability failure, audit reduction, and the legacy fixture; and
- `ocfleet-cli/tests/cli_args_tests.rs` for the fixed CLI surface.

The acceptance run uses default and all-feature workspace checks plus a
non-root Linux Docker run of the cross-crate B7 tests. The Docker fixture is
network-isolated at execution time and exercises both the current response and
the deterministic old-agent `METHOD_NOT_FOUND` projection.

## Explicit Non-Goals

B7 does not add a generic introspection RPC, method parameters, capability
registration, negotiation persistence, controller-side enablement, trust
inference, agent discovery, controlled-write dispatch, package management, or
upgrade behavior. Version fleet governance belongs to B8.
