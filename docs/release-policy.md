# Release And Support Policy

## Versioning

ocfleet uses Semantic Versioning for its four binaries as one release unit.
Before `1.0.0`, a minor release may change CLI, protocol, stored schema, and
deployment contracts when release notes and an upgrade path are provided. Patch
releases within a minor line are reserved for compatible fixes and security
updates. A release tag, workspace version, binary `--version`, release-note
filename, workflow input, and artifact filename must match exactly.

The wire protocol and SQLite schema are versioned independently. A package
version match does not authorize a peer and does not make an older database
safe to open with an arbitrary binary.

## Supported Releases

Until `1.0.0`, only the latest published minor line receives routine fixes. The
immediately preceding minor line receives critical security fixes for 90 days
after its successor is published. Older lines are unsupported. There is no
automatic update mechanism and no remote package-install RPC.

Supported release artifacts are Linux `x86_64` and `aarch64` binaries verified
on Debian Trixie and Ubuntu 24.04. Source builds on other systems are not part of
the release support matrix. SQLite is the only production runtime backend.

Security reports follow `SECURITY.md`. Support status never weakens the default
read-only boundary, explicit trust, or the default-off controlled-write gate.

## Upgrade Matrix

| From | To | Database action | Required evidence |
| --- | --- | --- | --- |
| `v0.1.x` | `v0.2.x` | Automatic forward migration with private pre-migration backup. | Release checksum; backup; `doctor --json`; trust coverage; read-only smoke. |
| `v0.1.x` | `v0.3.x` | Supported direct migration through every recorded schema version. | Managed backup and verify; migration corpus; `doctor --json`; trust diff; scheduler/evaluator/worker status. |
| `v0.2.x` | `v0.3.x` | Supported forward migration with private backup before the first schema write. | Managed backup and verify; `doctor --json`; trust diff; read-only RPC/API/dashboard smoke. |
| `v0.3.x` | later minor | Not supported until that release documents and tests the path. | Release-specific matrix and rollback drill. |
| any newer schema | older binary | Never open in place. | Restore the pre-upgrade database before starting the older binary. |

Skipping a row not explicitly listed as supported is prohibited. Upgrade one
controller at a time; agents may be replaced independently only when the target
release notes declare the protocol combination compatible.

## Release Gate

A candidate remains a draft until all of the following are green on the tagged
commit: default/all-feature Rust gates, fuzz smoke, migration corpus, failure
injection, Chromium E2E, dependency policy, CodeQL, distro/architecture install
smoke, SBOM generation, Sigstore verification, provenance verification, and the
documented upgrade/rollback drill. The release owner also confirms that the API
and dashboard remain GET-only and controlled writes remain default-off.

Promotion is manual. Failed or missing evidence cannot be waived by editing
release notes; a corrected commit receives a new version tag.
