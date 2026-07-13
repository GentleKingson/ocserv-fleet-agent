# Trust Policy As Code

Trust policy files describe the intended controller registry/trust shape. The
base workflow supports validation and advisory diff:

```bash
ocfleet trust policy validate ./trust-policy.toml
ocfleet trust policy validate ./trust-policy.toml --json
ocfleet trust policy validate ./trust-policy.yaml --json
ocfleet trust policy diff ./trust-policy.toml
ocfleet trust policy diff ./trust-policy.toml --json
install -d -m 0700 ./trust-policy-review
ocfleet trust policy diff ./trust-policy.toml --format markdown \
  --output ./trust-policy-review/trust-policy-diff.md
```

There is no `apply` command in this slice. These commands do not contact agents,
do not modify SQLite trust state, do not approve enrollment, and do not generate
path-probe authorization.

`validate` is a pure file operation and does not open, create, or migrate the
controller database. `diff` and the signed `plan` workflow open existing state
immutable, read-only, and query-only; an absent database is represented in
memory and is not created. Older schemas and non-empty WAL snapshots are
rejected rather than migrated, checkpointed, or recovered.

Stage B6 adds detached signing, deterministic CI plans, Markdown review,
signed approval records, bounded history, and drift-alert projection. See
[`trust-policy-gitops.md`](trust-policy-gitops.md). It deliberately adds no
policy apply path.

## TOML And YAML Schema

`.toml`, `.yaml`, and `.yml` use the same deny-unknown-fields data model. Input
is a bounded regular file. Parsing never contacts an agent or changes trust.

```toml
version = 1

[metadata]
name = "production-fleet"
revision = "rev-2026-07"

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
explicit target node. Every path-probe pair also requires a matching explicit
peer pair and at least one explicit controller; validation never infers either
relationship. A rotated, revoked, or quarantined node must set `enabled=false`
and cannot appear in a peer relationship.

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
- missing or unexpected controller allowlist entries
- missing or unexpected peer allowlist entries
- missing or unexpected explicit controller/target path-probe pairs

The diff is advisory. Operators must use existing explicit audited CLI commands
to make any change. This preserves the no-TOFU and no-automatic-trust boundary.

`--format markdown --output <path>` writes a bounded PR-review summary using
strict private create-new file semantics. The parent must be `0700`; the output
is `0600`. The summary contains only the policy basename, bounded identifiers,
enum/status values, and counts. Diff items have deterministic ordering and are
capped at 512; `total_diff_count` and `truncated` make truncation explicit. It is
still advisory and does not mutate controller state.

## YAML Shape

The equivalent YAML shape is:

```yaml
version: 1
metadata:
  name: production-fleet
  revision: rev-2026-07
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

TOML and YAML validation reports and diff semantics are equivalent. Duplicate
nodes, EndpointIDs, controllers, peers, path-probe pairs, wildcard EndpointIDs,
automatic-trust fields, and unknown fields are rejected.

## CI Review Helper

`scripts/check-trust-policy.sh examples/trust-policy.toml` validates a policy
with an isolated nonexistent database path and fails if validation creates that
file. It is validation-only: it does not apply policy, approve enrollment,
authorize probes, or contact agents.
