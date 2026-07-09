#!/usr/bin/env bash
set -Eeuo pipefail

log() {
  printf '[smoke] %s\n' "$*"
}

fail() {
  printf '[smoke] ERROR: %s\n' "$*" >&2
  exit 1
}

find_cargo() {
  if [[ -n "${CARGO:-}" ]]; then
    printf '%s\n' "$CARGO"
    return 0
  fi
  if command -v cargo >/dev/null 2>&1; then
    command -v cargo
    return 0
  fi
  if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
    printf '%s\n' "$HOME/.cargo/bin/cargo"
    return 0
  fi
  fail "cargo not found; set CARGO=/path/to/cargo"
}

require_private_file() {
  local path="$1"
  [[ -f "$path" ]] || fail "expected file was not created: $path"
  [[ ! -L "$path" ]] || fail "unsafe symlink created: $path"
}

extract_controller_endpoint_id() {
  local line
  while IFS= read -r line; do
    case "$line" in
      controller_endpoint_id=*)
        printf '%s\n' "${line#controller_endpoint_id=}"
        return 0
        ;;
    esac
  done
  return 1
}

repo_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cargo_bin="$(find_cargo)"

umask 077
tmp_parent="${TMPDIR:-/tmp}"
tmp_parent="${tmp_parent%/}"
tmp_dir="$(mktemp -d "$tmp_parent/ocfleet-smoke.XXXXXX")"
chmod 700 "$tmp_dir"

cleanup() {
  local status=$?
  if [[ "${OCFLEET_SMOKE_KEEP_TEMP:-0}" == "1" ]]; then
    log "kept tempdir: $tmp_dir"
  else
    rm -rf "$tmp_dir"
  fi
  exit "$status"
}
trap cleanup EXIT

controller_dir="$tmp_dir/controller"
agent_dir="$tmp_dir/agent"
mkdir -m 700 "$controller_dir" "$agent_dir"

database="$controller_dir/controller.sqlite"
secret_key="$controller_dir/controller.secret"
agent_config="$agent_dir/agent.toml"

log "repo: $repo_root"
log "tempdir: $tmp_dir"
log "building workspace"
(
  cd "$repo_root"
  "$cargo_bin" build --workspace
)

ocfleet="$repo_root/target/debug/ocfleet"
ocfleet_agent="$repo_root/target/debug/ocfleet-agent"
[[ -x "$ocfleet" ]] || fail "ocfleet binary missing after build"
[[ -x "$ocfleet_agent" ]] || fail "ocfleet-agent binary missing after build"

ocfleet_args=("$ocfleet" "--database" "$database" "--secret-key" "$secret_key")

log "initializing controller state"
init_output="$("${ocfleet_args[@]}" init)"
controller_endpoint_id="$(extract_controller_endpoint_id <<< "$init_output")" \
  || fail "controller init did not print controller_endpoint_id"
require_private_file "$database"
require_private_file "$secret_key"
log "captured controller EndpointID"

log "running controller doctor"
"${ocfleet_args[@]}" doctor > "$tmp_dir/doctor.txt"
"${ocfleet_args[@]}" doctor --json > "$tmp_dir/doctor.json"
if command -v python3 >/dev/null 2>&1; then
  python3 "$repo_root/scripts/validate-doctor-report.py" "$tmp_dir/doctor.json"
fi

log "generating minimal agent config"
cat > "$agent_config" <<EOF
[node]
id = "smoke-agent-01"
region = "local"
role = "ocserv"

[iroh]
secret_key_path = "$agent_dir/iroh.secret"

[audit]
path = "$agent_dir/audit.jsonl"
spool_path = "$agent_dir/audit.spool.jsonl"
metrics_path = "$agent_dir/audit.metrics.json"
spool_max_events = 1000
audit_queue_capacity = 128

[security]
allowed_clock_skew_seconds = 60
default_deadline_ms = 5000
max_deadline_ms = 10000
max_rpc_timeout_ms = 5000

[[security.controllers]]
endpoint_id = "$controller_endpoint_id"
role = "viewer"
EOF
chmod 600 "$agent_config"
require_private_file "$agent_config"
"$ocfleet_agent" --help > "$tmp_dir/ocfleet-agent-help.txt"

log "registering smoke node"
"${ocfleet_args[@]}" node add smoke-agent-01 \
  --endpoint-id "$controller_endpoint_id" \
  --region local \
  --role ocserv > "$tmp_dir/node-add.txt"
"${ocfleet_args[@]}" node list > "$tmp_dir/node-list.txt"

log "creating enrollment token (token output redacted)"
token_output="$tmp_dir/enroll-token.txt"
"${ocfleet_args[@]}" enroll token create \
  --ttl 1h \
  --max-uses 1 \
  --description local-smoke > "$token_output"
grep -q '^token_id=' "$token_output" || fail "enroll token output missing token_id"
grep -q '^token=' "$token_output" || fail "enroll token output missing token"

log "checking retention, health, and scheduler state"
"${ocfleet_args[@]}" retention show > "$tmp_dir/retention-show.txt"
"${ocfleet_args[@]}" health policy show > "$tmp_dir/health-policy-show.txt"
"${ocfleet_args[@]}" schedule status > "$tmp_dir/schedule-status.txt"

log "local CLI/state smoke passed"
