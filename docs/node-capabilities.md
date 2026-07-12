# Node Capability Negotiation

B7 adds one fixed read-only RPC, `node.capabilities`. It lets a controller
decide whether it can safely interpret an agent without turning discovery into
authorization or a generic introspection interface.

## Wire Contract

The request is an empty, closed object. The response is also closed and
contains only:

- the agent's supported protocol minimum and maximum;
- the bounded agent package version;
- supported methods selected from the compiled fixed read-only catalog;
- bounded provider schema version ranges from a closed provider enum;
- bounded feature flags from a closed enum; and
- separate `controlled_writes.compiled` and
  `controlled_writes.locally_enabled` booleans.

The current method catalog is `node.ping`, `node.info`,
`node.capabilities`, `probe.controller.ping`, `probe.peer.echo`,
`probe.path.echo`, and the five fixed `ocserv.*` read-only methods. It cannot
represent a generic command, file operation, service action, or controlled
write.

Provider and feature identifiers are enums rather than caller-controlled
strings. Lists must be non-empty, sorted, unique, and within their fixed count
limits. Agent versions use a closed ASCII character set and a 64-byte limit;
the serialized response is capped at 16 KiB. Unknown fields fail decoding.

## Controller Behavior

Run negotiation explicitly:

```bash
ocfleet node capabilities <node-id>
ocfleet node capabilities <node-id> --json
```

The controller accepts a response only when its protocol version lies inside
the reported range and `node.capabilities` is present in the reported method
catalog. Malformed and unsupported responses fail closed. Audit output stores
only protocol/provider bounds, agent version, list counts, and the two
controlled-write booleans, not the raw lists. B8 schema 27 also retains this
closed latest projection atomically with that audit for version governance.

An older agent that returns `METHOD_NOT_FOUND` receives the deterministic
`legacy_unsupported` projection. Compatibility remains `unknown` and
`actions_enabled` remains `false`; the controller does not infer support from
the agent version. Other errors remain errors.

Capability results are observations only. They never add trust, peer or path
authorization, change local policy, or enable an operation. In particular,
reporting controlled-write compilation and local enablement does not create a
controller dispatch path.

## Privacy Boundary

The DTO has no path, command, service unit, selector, local policy, secret,
token, raw configuration, or command-output field. The agent derives the
response from compile-time catalogs and bounded local booleans; controller
parameters cannot select local resources or request additional detail.
