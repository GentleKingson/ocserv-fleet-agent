# Install Guide

This guide installs the `v0.2.x` read-only MVP baseline on Linux with systemd. Commands assume two hosts:

- controller host: runs the `ocfleet` CLI and stores controller SQLite state.
- agent host: runs `ocfleet-agent` on an ocserv node.

The release also includes the optional read-only `ocfleet-api` process and the
operator-run `ocfleet-ocserv-collector` snapshot normalizer. Neither binary
adds a remote write capability.

Replace placeholder EndpointIDs before running RPC smoke tests.

For backup and hardening details, keep these guides next to this install runbook:

- [Backup And Restore](backup-restore.md)
- [Security Hardening](security-hardening.md)
- [Troubleshooting](troubleshooting.md)

## Local CLI/State Smoke

Before packaging or upgrading a host, run the local smoke test from a clean checkout:

```bash
./scripts/smoke-local.sh
```

The script builds the workspace, creates a private temp controller state, generates a minimal agent config, and exercises controller-local CLI/state commands. It does not start a long-running agent, contact a real ocserv instance, or require a public iroh relay. Set `OCFLEET_SMOKE_KEEP_TEMP=1` only when you need to inspect the temporary files after a failure.

## Build And Verify Release Artifacts

```bash
git clone https://github.com/GentleKingson/ocserv-fleet-agent.git
cd ocserv-fleet-agent
./scripts/build-release.sh v0.2.0
./scripts/verify-checksums.sh dist/v0.2.0/SHA256SUMS
cat dist/v0.2.0/SHA256SUMS
```

Each supported architecture produces four binaries: `ocfleet`,
`ocfleet-agent`, `ocfleet-api`, and `ocfleet-ocserv-collector`. The manual
`Release Draft` GitHub Actions workflow builds them for Linux `x86_64` and
`aarch64`, verifies the combined checksums, and creates a draft GitHub Release.
Run that workflow from the exact existing version tag and provide the same tag
as its version input; branch dispatches and mismatched tags fail closed. The
workflow does not publish crates.io packages.

Install binaries:

```bash
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in arm64) ARCH="aarch64";; amd64) ARCH="x86_64";; esac
sudo install -m 0755 "dist/v0.2.0/ocfleet-v0.2.0-$OS-$ARCH" /usr/local/bin/ocfleet
sudo install -m 0755 "dist/v0.2.0/ocfleet-agent-v0.2.0-$OS-$ARCH" /usr/local/bin/ocfleet-agent
sudo install -m 0755 "dist/v0.2.0/ocfleet-api-v0.2.0-$OS-$ARCH" /usr/local/bin/ocfleet-api
sudo install -m 0755 "dist/v0.2.0/ocfleet-ocserv-collector-v0.2.0-$OS-$ARCH" /usr/local/bin/ocfleet-ocserv-collector
for binary in ocfleet ocfleet-agent ocfleet-api ocfleet-ocserv-collector; do
  "$binary" --version
done
```

Installing a binary does not enable a service. Keep the API loopback-only
unless a private bearer-token file is configured, and follow
[`docs/collector.md`](collector.md) before enabling the local collector timer.

## CI Install Smoke Coverage

The four release binaries are smoke-tested in GitHub Actions on Debian Trixie
and Ubuntu 24.04 for both `linux-x86_64` and `linux-aarch64` artifacts. The CI
gate builds the binaries, verifies `SHA256SUMS`, installs them into minimal
distro containers, and checks the install layout, directory permissions,
SecretKey file mode, `ocfleet doctor`, JSON doctor output parsing, checked-in
agent and collector systemd unit syntax, exact binary versions, and basic
binary executability.

This is not `.deb` package support. The smoke containers do not run
`systemctl start`; they only use `systemd-analyze verify` for the checked-in
unit files because systemd is not PID 1 in the containers.

## Controller Setup

Create a locked-down runtime area:

```bash
sudo useradd --system --home-dir /var/lib/ocfleet-controller --shell /usr/sbin/nologin ocfleet || true
sudo install -d -o "$USER" -g "$USER" -m 0700 /var/lib/ocfleet-controller
```

Initialize the controller database and SecretKey:

```bash
ocfleet \
  --database /var/lib/ocfleet-controller/controller.sqlite \
  --secret-key /var/lib/ocfleet-controller/controller.secret \
  init
```

Save the printed value:

```bash
CONTROLLER_ENDPOINT_ID="<controller_endpoint_id_from_init>"
```

Verify the controller state:

```bash
ocfleet \
  --database /var/lib/ocfleet-controller/controller.sqlite \
  --secret-key /var/lib/ocfleet-controller/controller.secret \
  doctor

ocfleet \
  --database /var/lib/ocfleet-controller/controller.sqlite \
  --secret-key /var/lib/ocfleet-controller/controller.secret \
  doctor --json
```

## Agent Setup

Create the agent user and directories:

```bash
sudo useradd --system --home-dir /var/lib/ocfleet-agent --shell /usr/sbin/nologin ocfleet || true
sudo install -d -o root -g ocfleet -m 0750 /etc/ocfleet-agent
sudo install -d -o ocfleet -g ocfleet -m 0700 /var/lib/ocfleet-agent /var/log/ocfleet-agent
```

Generate an agent SecretKey:

```bash
sudo sh -c 'umask 077; openssl rand -base64 32 > /var/lib/ocfleet-agent/iroh.secret'
sudo chown ocfleet:ocfleet /var/lib/ocfleet-agent/iroh.secret
sudo chmod 0600 /var/lib/ocfleet-agent/iroh.secret
```

Create `/etc/ocfleet-agent/agent.toml`:

```bash
sudo tee /etc/ocfleet-agent/agent.toml >/dev/null <<EOF
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/var/lib/ocfleet-agent/iroh.secret"

[audit]
path = "/var/log/ocfleet-agent/audit.jsonl"
spool_path = "/var/lib/ocfleet-agent/audit.spool.jsonl"
metrics_path = "/var/lib/ocfleet-agent/audit.metrics.json"
spool_max_events = 10000
audit_queue_capacity = 1024

[security]
allowed_clock_skew_seconds = 60
default_deadline_ms = 5000
max_deadline_ms = 10000
max_rpc_timeout_ms = 5000

[[security.controllers]]
endpoint_id = "$CONTROLLER_ENDPOINT_ID"
role = "viewer"
EOF
sudo chown root:ocfleet /etc/ocfleet-agent/agent.toml
sudo chmod 0640 /etc/ocfleet-agent/agent.toml
```

The agent fails closed if the config file is a symlink, hardlink, non-regular
file, group/world-writable file, or if `/etc/ocfleet-agent` is group/world
writable. Keep the owner as `root` or `ocfleet`.

Audit writes are also fail-closed: if both the primary audit log and bounded
spool cannot accept an event, the affected RPC fails instead of returning an
unaudited success. Put `/var/log/ocfleet-agent` and `/var/lib/ocfleet-agent` on
monitored storage with enough quota for the configured spool.

Install the systemd unit:

```bash
sudo install -m 0644 deploy/systemd/ocfleet-agent.service /etc/systemd/system/ocfleet-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now ocfleet-agent
sudo systemctl status ocfleet-agent --no-pager
```

Capture the agent EndpointID:

```bash
journalctl -u ocfleet-agent -n 50 --no-pager | grep 'agent_endpoint_id='
AGENT_ENDPOINT_ID="<agent_endpoint_id_from_journal>"
```

Register the node on the controller:

```bash
ocfleet \
  --database /var/lib/ocfleet-controller/controller.sqlite \
  --secret-key /var/lib/ocfleet-controller/controller.secret \
  node add hk-ocserv-01 \
  --endpoint-id "$AGENT_ENDPOINT_ID" \
  --region hk \
  --role ocserv

ocfleet \
  --database /var/lib/ocfleet-controller/controller.sqlite \
  --secret-key /var/lib/ocfleet-controller/controller.secret \
  node list
```

## Systemd Drop-In Examples

Increase audit spool capacity:

```bash
sudo install -d -m 0755 /etc/systemd/system/ocfleet-agent.service.d
sudo tee /etc/systemd/system/ocfleet-agent.service.d/10-audit.conf >/dev/null <<'EOF'
[Service]
Environment=RUST_LOG=info
ReadWritePaths=/var/lib/ocfleet-agent /var/log/ocfleet-agent
EOF
sudo systemctl daemon-reload
sudo systemctl restart ocfleet-agent
```

Optional controller doctor one-shot:

```bash
CONTROLLER_STATE_USER="$(id -un)"
sudo tee /etc/systemd/system/ocfleet-controller-doctor.service >/dev/null <<EOF
[Unit]
Description=ocfleet controller doctor

[Service]
Type=oneshot
User=$CONTROLLER_STATE_USER
ExecStart=/usr/local/bin/ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret doctor
EOF
sudo systemctl daemon-reload
sudo systemctl start ocfleet-controller-doctor.service
```

## SecretKey Backup, Restore, And Rotation

Back up SecretKeys and the controller DB:

```bash
sudo install -d -m 0700 /var/backups/ocfleet
sudo cp -a /var/lib/ocfleet-controller/controller.secret /var/backups/ocfleet/controller.secret.$(date -u +%Y%m%dT%H%M%SZ)
sudo cp -a /var/lib/ocfleet-controller/controller.sqlite /var/backups/ocfleet/controller.sqlite.$(date -u +%Y%m%dT%H%M%SZ)
sudo cp -a /var/lib/ocfleet-agent/iroh.secret /var/backups/ocfleet/agent.$(hostname).iroh.secret.$(date -u +%Y%m%dT%H%M%SZ)
```

Restore a SecretKey:

```bash
sudo install -o ocfleet -g ocfleet -m 0600 /var/backups/ocfleet/agent.HOST.iroh.secret.TIMESTAMP /var/lib/ocfleet-agent/iroh.secret
sudo systemctl restart ocfleet-agent
```

Rotating a SecretKey changes that node or controller EndpointID. Update every allowlist and controller registry entry before relying on RPCs again:

```bash
sudo systemctl stop ocfleet-agent
sudo mv /var/lib/ocfleet-agent/iroh.secret /var/lib/ocfleet-agent/iroh.secret.old
sudo sh -c 'umask 077; openssl rand -base64 32 > /var/lib/ocfleet-agent/iroh.secret'
sudo chown ocfleet:ocfleet /var/lib/ocfleet-agent/iroh.secret
sudo systemctl start ocfleet-agent
journalctl -u ocfleet-agent -n 20 --no-pager | grep 'agent_endpoint_id='
```

## Database Upgrade And Backup

The controller database uses versioned SQLite migrations. On startup, `ocfleet`
refuses to open a database that records a schema version newer than the binary
supports. When an older non-empty schema is upgraded, the controller first
creates a private SQLite backup under `.ocfleet-migration-backups/` next to the
database. Backup names include the database filename, source schema version,
target schema version, and UTC timestamp; the backup directory is kept at
`0700`, backup files are created with mode `0600`, and a private `.sha256`
checksum sidecar is written next to each backup. Migration continues only after
the backup and checksum are complete.

Schema version 9 canonicalizes scheduler selector and path-pair JSON into
closed versioned payloads. Exact valid legacy selectors are preserved. A legacy
empty selector is converted to `role=ocserv` and its job is disabled for manual
review; it is never silently re-enabled. Unknown fields, unsupported schemas,
malformed JSON, or invalid selector/pair values stop the upgrade and leave the
version-8 database unchanged beside its private pre-migration backup.

Schema version 10 canonicalizes health degraded-method arrays and derived
summary objects into closed versioned payloads. Exact empty legacy summaries
keep their relational status and null optional metadata. Unknown fields,
unsupported methods or versions, invalid bounds, malformed JSON, and status
mismatches stop the upgrade and leave the version-9 database unchanged beside
its private pre-migration backup.

Schema version 11 canonicalizes probe observation summaries into closed
method/result-class-bound payloads. Unknown or nested fields, sensitive/address
content, unsupported versions, malformed JSON, and relational mismatches stop
the upgrade and leave the version-10 database unchanged beside its private
pre-migration backup.

Schema version 12 canonicalizes observability run summaries into closed
job/kind/status/trigger-bound payloads with bounded terminal counts. Unknown or
sensitive fields, unsupported versions or job kinds, impossible counts,
malformed JSON, and relational mismatches stop the upgrade and leave the
version-11 database unchanged beside its private pre-migration backup.

Schema version 13 canonicalizes endpoint trust bundles into closed payloads
bound to relational endpoint identity, generation, and lifecycle status. Exact
legacy empty bundles become empty allowlists; explicit allowlists and path pairs
remain bounded and unique. Unknown fields, unsupported versions, malformed or
duplicate entries, self-pairs, and relational mismatches stop the upgrade and
leave the version-12 database unchanged beside its private backup.

Schema version 14 canonicalizes alert details into closed payloads with fixed
methods, bounded low-sensitive summary fields, and typed silence or resolution
metadata. Unknown or nested fields, unsupported methods or versions, invalid
bounds, malformed deadlines, and sensitive or address content stop the upgrade
and leave the version-13 database unchanged beside its private backup.

Schema version 15 canonicalizes alert webhook host allowlists into closed
payloads bound to each relational endpoint host. Unknown fields, unsupported
versions, forbidden or malformed hosts, empty or oversized lists, and endpoint
mismatches stop the upgrade and leave the version-14 database unchanged beside
its private backup.

Schema version 16 canonicalizes enrollment token labels/scope and join-request
requested/approved labels into closed kind-bound scalar maps. Unknown fields,
unsupported versions or kinds, nested values, invalid keys or bounds,
sensitive/address-like data, and approved labels on non-approved requests stop
the upgrade and leave the version-15 database unchanged beside its backup.

Schema version 17 rebuilds alert delivery-attempt storage with a required closed
detail payload derived from each constrained relational row. Invalid IDs,
attempt numbers, statuses, HTTP classes, error codes, or byte counts stop the
upgrade and leave the version-16 database unchanged beside its private backup.

Before upgrades, keep an operator-managed backup as well:

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret doctor
sqlite3 /var/lib/ocfleet-controller/controller.sqlite 'PRAGMA integrity_check;'
sudo cp -a /var/lib/ocfleet-controller/controller.sqlite /var/backups/ocfleet/controller.sqlite.pre-upgrade.$(date -u +%Y%m%dT%H%M%SZ)
```

After installing a new binary:

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret doctor --json
```

## Upgrade Flow

Use this order for routine binary upgrades, with `OS` and `ARCH` set as in the install step above:

```bash
sudo systemctl stop ocfleet-agent
sudo install -d -m 0700 /var/backups/ocfleet
sqlite3 /var/lib/ocfleet-controller/controller.sqlite 'PRAGMA integrity_check;'
sudo cp -a /var/lib/ocfleet-controller/controller.sqlite /var/backups/ocfleet/controller.sqlite.pre-upgrade.$(date -u +%Y%m%dT%H%M%SZ)
sudo install -m 0755 "dist/v0.2.0/ocfleet-v0.2.0-$OS-$ARCH" /usr/local/bin/ocfleet
sudo install -m 0755 "dist/v0.2.0/ocfleet-agent-v0.2.0-$OS-$ARCH" /usr/local/bin/ocfleet-agent
sudo install -m 0755 "dist/v0.2.0/ocfleet-api-v0.2.0-$OS-$ARCH" /usr/local/bin/ocfleet-api
sudo install -m 0755 "dist/v0.2.0/ocfleet-ocserv-collector-v0.2.0-$OS-$ARCH" /usr/local/bin/ocfleet-ocserv-collector
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret doctor
sudo systemctl start ocfleet-agent
```

Do not start controller scheduler execution until
`registry.endpoint_trust.coverage` is `ok`. Missing trust is unauthorized and
fails before key loading or network dispatch. If the check fails, retain the
backup and either restore a known-good database or explicitly re-register each
affected node with its operator-verified EndpointID; there is no automatic
trust reconstruction from registry rows.

Keep the controller SQLite backup until the new binary has passed `doctor`,
expected controller-local smoke commands, and at least one low-sensitive
read-only RPC smoke in your deployment.

## Smoke Tests

Controller-only smoke:

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret doctor
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret node list
```

Agent smoke:

```bash
systemctl is-active ocfleet-agent
test -s /var/lib/ocfleet-agent/iroh.secret
test -s /var/log/ocfleet-agent/audit.metrics.json || true
journalctl -u ocfleet-agent -n 50 --no-pager
```

RPC smoke where endpoint addressing is available in your deployment:

```bash
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret ping hk-ocserv-01
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret node info hk-ocserv-01
ocfleet --database /var/lib/ocfleet-controller/controller.sqlite --secret-key /var/lib/ocfleet-controller/controller.secret probe ping hk-ocserv-01
```

The production CLI intentionally does not accept host, port, relay, or arbitrary address flags in `v0.2.x`.

## Uninstall And Cleanup

```bash
sudo systemctl disable --now ocfleet-agent || true
sudo rm -f /etc/systemd/system/ocfleet-agent.service
sudo rm -rf /etc/systemd/system/ocfleet-agent.service.d
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/ocfleet /usr/local/bin/ocfleet-agent
sudo rm -f /usr/local/bin/ocfleet-api /usr/local/bin/ocfleet-ocserv-collector
```

Remove state only after backups are confirmed:

```bash
sudo rm -rf /etc/ocfleet-agent /var/lib/ocfleet-agent /var/log/ocfleet-agent
sudo rm -rf /var/lib/ocfleet-controller
```
