# B8 Agent Version Governance Inventory

## Scope

B8 adds bounded read-only version policy, distribution, compatibility alerts,
and upgrade-readiness projections. Schema 27 stores the latest closed B7
capability observation; it adds no remote write or upgrade RPC.

| Requirement | Implementation and evidence |
| --- | --- |
| Expected version policy | Existing audited B2 `expected_agent_version` metadata is interpreted as a minimum SemVer target. Missing and invalid policy remain explicit. |
| Semantic versions and pre-releases | Direct `semver` parsing/order; final `0.4.0` correctly treats `0.4.0-rc.1` as outdated. Invalid observed versions never become ready. |
| Fleet distribution | Deterministic version-sorted counts with a 1,000-node hard cap and explicit unobserved count in CLI output. |
| Outdated alert | Readiness projection emits bounded `AGENT_VERSION_OUTDATED` only for enabled nodes below policy. |
| Protocol incompatibility | Structurally valid non-overlapping ranges and missing required capability are stored distinctly and project `PROTOCOL_INCOMPATIBLE`; unknown/legacy data is not treated as compatible. |
| Provider incompatibility | Fixed ocserv snapshot schema range is checked against required schema v2 and projects `PROVIDER_SCHEMA_INCOMPATIBLE`. |
| Upgrade readiness | A node is ready only with an enabled node, current/ahead SemVer, compatible protocol, and compatible provider. All other states are blocked, unknown, or disabled. |
| Read-only CLI | `ocfleet version distribution|readiness`; all outputs set `actions_enabled=false`. |
| API/dashboard | `GET /api/v1/version/readiness` is query-closed, bounded, ETag-enabled, authenticated like other v1 reads, and rendered on the existing read-only dashboard. |
| Observation durability | Capability snapshot and RPC audit share one transaction; current EndpointID is rechecked and injected audit failure rolls back the snapshot. |
| Redaction | Stored/report fields are closed scalars. Tests reject path, command, local-policy, package-manager, and secret markers. |
| No upgrade control | No install/restart/package-manager/configuration command, RPC method, API mutation, scheduler job, or automatic refresh is added. |

## Compatibility States

| Input | Version state | Compatibility/readiness behavior |
| --- | --- | --- |
| Observed equals expected | `current` | Ready only if protocol and provider also match. |
| Observed greater than expected | `ahead` | Ready only if compatibility also matches. |
| Observed or pre-release lower than expected | `outdated` | Blocked and emits outdated alert. |
| Invalid observed/expected SemVer | explicit invalid state | Unknown readiness; no optimistic inference. |
| No observation or legacy unsupported negotiation | unknown version/protocol | Unknown readiness. |
| Non-overlapping protocol or required method omitted | incompatible | Blocked and emits protocol alert. |
| Provider range excludes schema v2 | incompatible | Blocked and emits provider alert. |
| Disabled node | evaluated and visible | `disabled`; no version alert. |

## Direct Tests

- `version_governance_tests.rs`: SemVer, pre-release, distribution, expected
  policy, outdated/protocol/provider alerts, unknown states, node cap,
  redaction, readiness, and snapshot/audit rollback.
- `controller_rpc_tests.rs`: compatible/incompatible/unsupported decode,
  bounded audit summary, snapshot projection, and deterministic legacy state.
- `migration_tests.rs`: every historical schema upgrades through current schema 28 and
  new/reopened databases remain complete and idempotent.
- `cli_args_tests.rs`: closed distribution/readiness command surface.
- `api_tests.rs`: exact OpenAPI/router path, bounded readiness projection,
  derived alert, ETag/304, unknown-query rejection, redaction, and zero
  mutation.

The milestone gate also runs default/all-feature workspace checks and tests,
plus a non-root, network-isolated Linux Docker run of the version-governance,
controller-decode, migration, and API consumers.

## Residual Limits

Capability refresh is explicit per node; the readiness endpoint never contacts
agents. B8 does not define a freshness expiry policy, automatically discover
versions, persist its derived alerts in the general alert-delivery queue, or
perform an upgrade. The observation timestamp is exposed so operators can
judge age without silently converting old data to success.
