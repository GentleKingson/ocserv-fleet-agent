# Trust Policy As Code

Trust policy files describe the intended controller registry/trust shape. The
current implementation supports local validation and diff only:

```bash
ocfleet trust policy validate ./trust-policy.toml
ocfleet trust policy validate ./trust-policy.toml --json
ocfleet trust policy diff ./trust-policy.toml
ocfleet trust policy diff ./trust-policy.toml --json
```

There is no `apply` command in this slice. These commands do not contact agents,
do not modify SQLite trust state, do not approve enrollment, and do not generate
path-probe authorization.

## TOML Schema

TOML parsing is implemented today. YAML uses the same field model but remains a
documented future parser choice until dependency and compatibility review.

```toml
version = 1

[[nodes]]
node_id = "hk-ocserv-01"
endpoint_id = "<agent-endpoint-id>"
region = "hk"
role = "ocserv"
lifecycle = "active"
enabled = true

[[nodes]]
node_id = "sg-ocserv-01"
endpoint_id = "<agent-endpoint-id>"
region = "sg"
role = "ocserv"
lifecycle = "quarantined"
enabled = false

[[controllers]]
endpoint_id = "<controller-endpoint-id>"
role = "viewer"

[[peers]]
source_node_id = "hk-ocserv-01"
peer_node_id = "sg-ocserv-01"

[[path_probes]]
source_node_id = "hk-ocserv-01"
target_node_id = "sg-ocserv-01"
enabled = true
```

Allowed lifecycle values are `active`, `rotated`, `revoked`, and
`quarantined`. Path probes must always name one explicit source node and one
explicit target node.

## Forbidden Fields

Policy files must not contain local paths, command names, service units, journal
selectors, shell snippets, scripts, raw RPC payloads, or provider selectors.
Unknown fields are rejected, so entries such as `command = "systemctl ..."` or
`path = "/etc/ocserv/ocserv.conf"` fail validation.

## Diff Semantics

`ocfleet trust policy diff` compares policy nodes and endpoint lifecycle states
against the controller SQLite registry:

- missing or extra nodes
- node endpoint, region, role, or enabled mismatches
- missing, extra, or lifecycle-mismatched EndpointIDs

The diff is advisory. Operators must use existing explicit audited CLI commands
to make any change. This preserves the no-TOFU and no-automatic-trust boundary.

## YAML Shape

The equivalent YAML shape is:

```yaml
version: 1
nodes:
  - node_id: hk-ocserv-01
    endpoint_id: <agent-endpoint-id>
    region: hk
    role: ocserv
    lifecycle: active
    enabled: true
controllers:
  - endpoint_id: <controller-endpoint-id>
    role: viewer
peers:
  - source_node_id: hk-ocserv-01
    peer_node_id: sg-ocserv-01
path_probes:
  - source_node_id: hk-ocserv-01
    target_node_id: sg-ocserv-01
    enabled: true
```

The CLI currently rejects `.yaml` and `.yml` with a clear message rather than
silently accepting an unreviewed parser.
