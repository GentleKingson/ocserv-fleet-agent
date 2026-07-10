#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly REPO_ROOT
readonly GUARD="$REPO_ROOT/scripts/check-controller-mutations.sh"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/ocfleet-mutation-guard.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

fixture_root="$tmp_dir/repository"
cli_src="$fixture_root/crates/ocfleet-cli/src"
mkdir -p \
  "$cli_src" \
  "$fixture_root/crates/ocfleet-cli/tests" \
  "$fixture_root/crates/ocfleet-cli/fixtures" \
  "$fixture_root/crates/ocfleet-api/src"

printf '%s\n' \
  'pub const SQL: &str = "INSERT INTO nodes (node_id) VALUES (?1)";' \
  > "$cli_src/store.rs"
printf '%s\n' \
  'pub const SQL: &str = "CREATE TABLE nodes (node_id TEXT PRIMARY KEY)";' \
  > "$cli_src/migrations.rs"
printf '%s\n' \
  'pub const QUERY: &str = "SELECT node_id FROM nodes";' \
  '#[cfg(test)]' \
  'mod tests {' \
  '    const FIXTURE_SQL: &str = "UPDATE nodes SET enabled = 0";' \
  '}' \
  'pub const OTHER_QUERY: &str = "SELECT enabled FROM nodes";' \
  > "$cli_src/backend.rs"
printf '%s\n' \
  'pub const FIXTURE_SQL: &str = "DELETE FROM nodes";' \
  > "$fixture_root/crates/ocfleet-cli/tests/controller.rs"
printf '%s\n' \
  'INSERT INTO nodes (node_id) VALUES ("fixture")' \
  > "$fixture_root/crates/ocfleet-cli/fixtures/controller.sql"
printf '%s\n' \
  '// UPDATE nodes SET enabled = 0' \
  'pub const QUERY: &str = "SELECT node_id FROM nodes";' \
  > "$fixture_root/crates/ocfleet-api/src/readonly_store.rs"

pass_output="$tmp_dir/pass-output"
if ! "$GUARD" --repo-root "$fixture_root" "$fixture_root" >"$pass_output" 2>&1; then
  printf 'controller mutation guard rejected allowed store/test fixtures:\n' >&2
  sed -n '1,120p' "$pass_output" >&2
  exit 1
fi

printf '%s\n' \
  'pub const BYPASS: &str = r#"' \
  '  insert' \
  '  into nodes (node_id) values (?1)' \
  '"#;' \
  > "$cli_src/unsafe_writer.rs"

fail_output="$tmp_dir/fail-output"
if "$GUARD" --repo-root "$fixture_root" "$fixture_root" >"$fail_output" 2>&1; then
  printf 'controller mutation guard accepted production mutation SQL\n' >&2
  exit 1
fi
if ! grep -Fq 'unsafe_writer.rs:2: controller mutation SQL outside' "$fail_output"; then
  printf 'controller mutation guard did not report the expected file and line:\n' >&2
  sed -n '1,120p' "$fail_output" >&2
  exit 1
fi

rm -f "$cli_src/unsafe_writer.rs"
printf '%s\n' \
  'pub fn bypass(store: &Store, observation: &ProbeObservationInsert) {' \
  '    store.insert_probe_observation(observation);' \
  '}' \
  > "$cli_src/unsafe_scheduler_writer.rs"

legacy_fail_output="$tmp_dir/legacy-fail-output"
if "$GUARD" --repo-root "$fixture_root" "$fixture_root" >"$legacy_fail_output" 2>&1; then
  printf 'controller mutation guard accepted a legacy scheduler writer call\n' >&2
  exit 1
fi
if ! grep -Fq 'unsafe_scheduler_writer.rs:2: legacy scheduler persistence call outside transactional writer boundary: insert_probe_observation' "$legacy_fail_output"; then
  printf 'controller mutation guard did not report the legacy scheduler writer call:\n' >&2
  sed -n '1,120p' "$legacy_fail_output" >&2
  exit 1
fi

rm -f "$cli_src/unsafe_scheduler_writer.rs"
printf '%s\n' \
  'pub fn bypass(store: &Store, audit: RpcAuditRecord) {' \
  '    write_rpc_audit(store, audit);' \
  '}' \
  > "$cli_src/unsafe_rpc_audit.rs"

rpc_fail_output="$tmp_dir/rpc-fail-output"
if "$GUARD" --repo-root "$fixture_root" "$fixture_root" >"$rpc_fail_output" 2>&1; then
  printf 'controller mutation guard accepted a direct RPC audit write\n' >&2
  exit 1
fi
if ! grep -Fq 'unsafe_rpc_audit.rs:2: direct RPC audit write outside reviewed caller boundary: write_rpc_audit' "$rpc_fail_output"; then
  printf 'controller mutation guard did not report the direct RPC audit write:\n' >&2
  sed -n '1,120p' "$rpc_fail_output" >&2
  exit 1
fi

printf 'Controller mutation SQL guard self-test passed.\n'
