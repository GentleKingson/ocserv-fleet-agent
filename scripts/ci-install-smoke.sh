#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s <version> <arch> <distro-image>\n' "$0" >&2
}

if [[ $# -ne 3 ]]; then
  usage
  exit 2
fi

version="$1"
arch="$2"
distro_image="$3"

case "$version" in
  v*) ;;
  *) version="v$version" ;;
esac

case "$arch" in
  linux-x86_64|x86_64|amd64) artifact_arch="linux-x86_64" ;;
  linux-aarch64|aarch64|arm64) artifact_arch="linux-aarch64" ;;
  *)
    printf 'unsupported release arch: %s\n' "$arch" >&2
    exit 2
    ;;
esac

repo_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
dist_dir="$repo_root/dist/$version"
ocfleet_artifact="$dist_dir/ocfleet-$version-$artifact_arch"
agent_artifact="$dist_dir/ocfleet-agent-$version-$artifact_arch"

if [[ ! -x "$ocfleet_artifact" ]]; then
  printf 'missing executable release artifact: %s\n' "$ocfleet_artifact" >&2
  exit 1
fi
if [[ ! -x "$agent_artifact" ]]; then
  printf 'missing executable release artifact: %s\n' "$agent_artifact" >&2
  exit 1
fi

printf 'install_smoke version=%s arch=%s image=%s\n' "$version" "$artifact_arch" "$distro_image"

docker run --rm --interactive \
  --volume "$repo_root:/workspace/repo:ro" \
  --volume "$dist_dir:/workspace/dist:ro" \
  "$distro_image" \
  bash -s -- "$version" "$artifact_arch" <<'SMOKE'
set -euo pipefail

version="$1"
artifact_arch="$2"
dist_dir="/workspace/dist"
repo_root="/workspace/repo"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates \
  coreutils \
  file \
  passwd \
  python3-minimal \
  sqlite3 \
  systemd
rm -rf /var/lib/apt/lists/*

install -m 0755 "$dist_dir/ocfleet-$version-$artifact_arch" /usr/local/bin/ocfleet
install -m 0755 "$dist_dir/ocfleet-agent-$version-$artifact_arch" /usr/local/bin/ocfleet-agent

ocfleet --version
ocfleet-agent --version
file /usr/local/bin/ocfleet
file /usr/local/bin/ocfleet-agent

if ! id -u ocfleet >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/ocfleet --shell /usr/sbin/nologin ocfleet
fi

install -d -m 0755 /etc/ocfleet
install -d -o ocfleet -g ocfleet -m 0700 /var/lib/ocfleet /var/log/ocfleet
install -d -o ocfleet -g ocfleet -m 0700 /etc/ocfleet-agent /var/lib/ocfleet-agent /var/log/ocfleet-agent

test -d /etc/ocfleet
test -d /var/lib/ocfleet
test -d /var/log/ocfleet
test "$(stat -c '%a' /etc/ocfleet)" = "755"
test "$(stat -c '%U:%G %a' /var/lib/ocfleet)" = "ocfleet:ocfleet 700"
test "$(stat -c '%U:%G %a' /var/log/ocfleet)" = "ocfleet:ocfleet 700"

if [[ -f "$repo_root/deploy/systemd/ocfleet-agent.service" ]]; then
  systemd-analyze verify "$repo_root/deploy/systemd/ocfleet-agent.service"
else
  printf 'No reusable systemd unit fixture found; skipping unit syntax verification.\n'
fi

ocfleet doctor --help >/dev/null

smoke_dir="$(mktemp -d /tmp/ocfleet-install-smoke.XXXXXX)"
cleanup() {
  rm -rf "$smoke_dir"
}
trap cleanup EXIT

database="$smoke_dir/controller.sqlite"
secret_key="$smoke_dir/controller.secret"
json_report="$smoke_dir/doctor.json"

ocfleet --database "$database" --secret-key "$secret_key" init >/dev/null

test -s "$secret_key"
case "$(stat -c '%a' "$secret_key")" in
  600|640) ;;
  *)
    printf 'unexpected SecretKey mode: %s\n' "$(stat -c '%a' "$secret_key")" >&2
    exit 1
    ;;
esac
test "$(stat -c '%U:%G' "$secret_key")" = "root:root"
decoded_secret_bytes="$(base64 -d "$secret_key" | wc -c | tr -d '[:space:]')"
test "$decoded_secret_bytes" = "32"

ocfleet --database "$database" --secret-key "$secret_key" doctor >/dev/null
ocfleet --database "$database" --secret-key "$secret_key" doctor --json > "$json_report"
python3 - "$json_report" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    report = json.load(handle)

assert report["status"] in {"ok", "warning"}
assert report["exit_code"] == 0
assert report["schema_version_expected"] == 1
assert report["schema_version_actual"] == 1
assert isinstance(report["checks"], list)
PY

printf 'install smoke passed for %s %s\n' "$version" "$artifact_arch"
SMOKE
