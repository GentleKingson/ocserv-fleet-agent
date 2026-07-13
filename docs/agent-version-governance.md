# Agent Version Governance

B8 provides read-only fleet version governance. It reports what is observed,
compares it with operator-owned expected-version policy, and identifies upgrade
blockers. It cannot install a package, invoke a package manager, restart an
agent, or enable any remote action.

## Data Flow

Run the fixed B7 negotiation RPC to refresh one node's latest bounded
observation:

```bash
ocfleet node capabilities <node-id> --json
```

Schema 27 stores only the latest closed compatibility projection for that
node: endpoint binding, observation time, negotiation state, agent version,
protocol/provider ranges, and the two controlled-write booleans. The snapshot
and its RPC audit commit atomically. A stale endpoint cannot update the row,
and an audit failure rolls the snapshot back.

Successful, structurally valid incompatible, legacy `METHOD_NOT_FOUND`, and
invalid-response outcomes have distinct states. Other transport failures do
not erase the last compatibility observation. No raw capability list, path,
command, service unit, local policy, secret, configuration, or command output
is persisted.

Expected versions come from the advisory B2
`node metadata set --expected-agent-version` field. B8 interprets this as the
minimum acceptable semantic version for the node. Equal versions are current,
higher versions are ahead, and lower versions, including a pre-release below a
final expected release, are outdated. Missing and invalid expected or observed
versions remain explicit unknown/policy states.

## Reports

```bash
ocfleet version distribution --json
ocfleet version readiness --json
```

The distribution has a 1,000-node hard limit. The readiness report includes
per-node semantic-version state, protocol compatibility, ocserv snapshot schema
v2 compatibility, aggregate counts, and derived read-only alerts:

- `AGENT_VERSION_OUTDATED`;
- `PROTOCOL_INCOMPATIBLE`; and
- `PROVIDER_SCHEMA_INCOMPATIBLE`.

Disabled nodes remain visible but do not emit version alerts. Unknown data does
not become compatible or ready. A node is ready only when it is enabled, its
version meets policy, protocol 1 is supported, and provider schema v2 is
supported. Every report and node projection has `actions_enabled=false`.

The same bounded report is available at `GET /api/v1/version/readiness` with
ETag/conditional GET behavior. The read-only dashboard displays its aggregate
counts and per-node states. Neither surface starts capability collection or
mutates controller/agent state.

## Upgrade Workflow

The report is preparation evidence, not an upgrade executor. Operators perform
package installation and service lifecycle work through their existing local
configuration-management process. Refresh `node.capabilities` afterward and
confirm that readiness changes based on a new explicit observation.
