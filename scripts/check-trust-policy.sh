#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
policy="${1:-$repo_root/examples/trust-policy.toml}"
cargo_bin="${CARGO:-cargo}"

case "$policy" in
  *.toml|*.yaml|*.yml) ;;
  *)
    echo "trust policy must use .toml, .yaml, or .yml" >&2
    exit 2
    ;;
esac

umask 077
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/ocfleet-trust-policy.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

"$cargo_bin" run --quiet --manifest-path "$repo_root/Cargo.toml" \
  -p ocfleet-cli --bin ocfleet -- \
  --database "$tmp_dir/controller.sqlite" \
  trust policy validate "$policy" --json

if [[ -e "$tmp_dir/controller.sqlite" ]]; then
  echo "trust policy validate unexpectedly created a controller database" >&2
  exit 1
fi
