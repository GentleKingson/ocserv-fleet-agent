# Direction-Two Phase 7: ocserv-aware read-only checks remain reserved

Phase 7 evaluated whether `ocfleet` can safely add fixed ocserv-aware read-only checks without weakening the Direction-Two trust and execution boundaries.

The current decision is docs-only: no ocserv-aware runtime adapter is approved in this phase.

## Baseline

`ocfleet` remains a read-only control plane with fixed RPC methods, iroh EndpointID identity, explicit trust configuration, and controller/agent audit trails.

The current codebase does not expose a safe fixed source of low-sensitive ocserv metadata that can be queried without crossing a reserved boundary.

## Reserved Boundary

Phase 7 does not add:

- an RPC method
- a CLI command
- an agent runtime adapter
- shell or script execution
- generic command running
- raw file reads
- raw ocserv/system interfaces
- `systemctl`, `occtl`, or `journalctl` adapters
- process control
- session or user mutation
- config parsing from raw ocserv files
- unbounded command or log output

These exclusions are deliberate. A future ocserv-aware phase must not treat `systemctl`, `occtl`, `journalctl`, shell, scripts, or raw files as implementation shortcuts.

## Requirements For Any Future Runtime Design

Any future ocserv-aware runtime capability must first freeze a new spec and implementation plan. That future design must prove all of the following before code is written:

- the data source is fixed, bounded, and read-only
- request and response schemas are closed
- authorization is caller-aware
- outputs are low-sensitive and do not include raw config, logs, certificates, secrets, or command output
- resource limits are explicit
- audit records are low-sensitive and sufficient to explain success, failure, rejection, and timeout paths
- tests prove no shell, command runner, raw file read, raw ocserv/system interface, process control, relay, mesh, or forwarding behavior exists

If those conditions cannot be proven, ocserv-aware checks must remain reserved.

## Current Operator Guidance

Operators should continue to use the existing fixed, audited surfaces:

- `ocfleet probe ping <node_id>`
- `ocfleet probe path <source_node_id> <target_node_id>`
- `ocfleet probe summary <source_node_id> <target_node_id>`
- `ocfleet probe topology`
- `ocfleet probe history [node_id]`

These commands validate management connectivity, explicit path probe behavior, registry observation, topology observation, and existing probe audit history without adding raw ocserv control or host-level diagnostics.
