#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/ocfleet-dashboard-e2e.XXXXXX")"
api_pid=""

cleanup() {
  if [[ -n "$api_pid" ]]; then
    kill "$api_pid" 2>/dev/null || true
    wait "$api_pid" 2>/dev/null || true
  fi
  rm -rf "$fixture_dir"
}
trap cleanup EXIT INT TERM

cd "$repo_root"
cargo build --locked -p ocfleet-cli -p ocfleet-api --bins
target/debug/ocfleet \
  --database "$fixture_dir/controller.sqlite" \
  --secret-key "$fixture_dir/controller.secret" \
  init >/dev/null
target/debug/ocfleet-api \
  --database "$fixture_dir/controller.sqlite" \
  --read-only \
  --listen 127.0.0.1:4173 &
api_pid="$!"
wait "$api_pid"
