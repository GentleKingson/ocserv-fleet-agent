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
  'pub fn reviewed(store: &Store, node: &NodeInsert, token: &EnrollmentTokenInsert, request: &JoinRequestInsert, approval: &ApprovalInput, claim: &LegacyEnrollmentClaimInput, policy: &RetentionPolicyRecord, apply: &RetentionApplyInput, health_policy: &HealthPolicyRecord, health: &HealthSnapshotWrite, alerts: &AlertEvaluationWrite, alert: &AlertEventRecord, action: &AlertStateTransition, hook: &AlertWebhookHookRecord, attempt: &AlertDeliveryAttemptWrite, finalize: &AlertDeliveryFinalizeWrite) {' \
  '    Store::add_node(store, node, "actor");' \
  '    store.enable_node("node", "actor");' \
  '    store.disable_node("node", "actor");' \
  '    store.remove_node("node", "actor");' \
  '    store.rotate_endpoint("old", "new", "actor", "reason");' \
  '    store.revoke_endpoint("endpoint", "actor", "reason");' \
  '    store.quarantine_endpoint("endpoint", "actor", "reason");' \
  '    store.create_enrollment_token(token, "actor");' \
  '    store.revoke_enrollment_token("token", "actor", "reason");' \
  '    store.submit_join_request(request, "actor");' \
  '    store.reject_join_request("request", "actor", "reason");' \
  '    store.approve_join_request(approval, "actor");' \
  '    Store::claim_legacy_enrollment(store, claim, "actor");' \
  '    store.set_retention_policy(policy, "actor");' \
  '    Store::apply_retention(store, apply, "actor");' \
  '    store.set_health_policy(health_policy, "actor");' \
  '    Store::write_health_snapshots(store, health, "actor");' \
  '    store.write_alert_evaluation(alerts, "actor");' \
  '    store.write_alert_state_transition(action, "actor");' \
  '    Store::write_alert_webhook_hook_create(store, hook, "actor");' \
  '    store.upsert_alert_event(alert);' \
  '    store.write_alert_delivery_attempt(attempt, "actor");' \
  '    Store::write_alert_delivery_finalize(store, finalize, "actor");' \
  '}' \
  'pub const OTHER_QUERY: &str = "SELECT enabled FROM nodes";' \
  > "$cli_src/backend.rs"
printf '%s\n' \
  'pub const FIXTURE_SQL: &str = "DELETE FROM nodes";' \
  'pub fn integration_fixture(store: &Store, node: &NodeInsert) {' \
  '    store.add_node(node, "actor");' \
  '    store.remove_node("node", "actor");' \
  '}' \
  > "$fixture_root/crates/ocfleet-cli/tests/controller.rs"
printf '%s\n' \
  'INSERT INTO nodes (node_id) VALUES ("fixture")' \
  > "$fixture_root/crates/ocfleet-cli/fixtures/controller.sql"
printf '%s\n' \
  '// UPDATE nodes SET enabled = 0' \
  'pub const QUERY: &str = "SELECT node_id FROM nodes";' \
  '#[cfg(test)]' \
  'fn test_fixture(store: &Store) {' \
  '    store.remove_node("node", "actor");' \
  '    Store::revoke_endpoint(store, "endpoint", "actor", "reason");' \
  '}' \
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
  'pub fn bypass(store: &Store, observation: &ProbeObservationInsert, job: &ObservabilityJobRecord) {' \
  '    store.insert_probe_observation(observation);' \
  '    store.insert_observability_job(job, "actor");' \
  '    Store::set_observability_job_enabled(store, "job", true, "actor");' \
  '}' \
  > "$cli_src/unsafe_scheduler_writer.rs"

legacy_fail_output="$tmp_dir/legacy-fail-output"
if "$GUARD" --repo-root "$fixture_root" "$fixture_root" >"$legacy_fail_output" 2>&1; then
  printf 'controller mutation guard accepted a legacy scheduler writer call\n' >&2
  exit 1
fi
for expected in \
  'unsafe_scheduler_writer.rs:2: legacy scheduler persistence call outside transactional writer boundary: insert_probe_observation' \
  'unsafe_scheduler_writer.rs:3: direct scheduler config mutator call outside reviewed store/backend boundary: insert_observability_job' \
  'unsafe_scheduler_writer.rs:4: direct scheduler config mutator call outside reviewed store/backend boundary: set_observability_job_enabled'
do
  if ! grep -Fq "$expected" "$legacy_fail_output"; then
    printf 'controller mutation guard did not report expected scheduler violation: %s\n' "$expected" >&2
    sed -n '1,120p' "$legacy_fail_output" >&2
    exit 1
  fi
done

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

rm -f "$cli_src/unsafe_rpc_audit.rs"
printf '%s\n' \
  'pub fn bypass(store: &Store, node: &NodeInsert) {' \
  '    store.add_node(node, "actor");' \
  '    Store::enable_node(store, "node", "actor");' \
  '    store.disable_node("node", "actor");' \
  '    Store::remove_node(store, "node", "actor");' \
  '    store.rotate_endpoint("old", "new", "actor", "reason");' \
  '    Store::revoke_endpoint(store, "endpoint", "actor", "reason");' \
  '    store.quarantine_endpoint("endpoint", "actor", "reason");' \
  '}' \
  > "$cli_src/unsafe_node_endpoint_mutator.rs"

node_endpoint_fail_output="$tmp_dir/node-endpoint-fail-output"
if "$GUARD" --repo-root "$fixture_root" "$fixture_root" >"$node_endpoint_fail_output" 2>&1; then
  printf 'controller mutation guard accepted direct node/endpoint mutator calls\n' >&2
  exit 1
fi
for expected in \
  'unsafe_node_endpoint_mutator.rs:2: direct node/endpoint mutator call outside reviewed store/backend boundary: add_node' \
  'unsafe_node_endpoint_mutator.rs:3: direct node/endpoint mutator call outside reviewed store/backend boundary: enable_node' \
  'unsafe_node_endpoint_mutator.rs:4: direct node/endpoint mutator call outside reviewed store/backend boundary: disable_node' \
  'unsafe_node_endpoint_mutator.rs:5: direct node/endpoint mutator call outside reviewed store/backend boundary: remove_node' \
  'unsafe_node_endpoint_mutator.rs:6: direct node/endpoint mutator call outside reviewed store/backend boundary: rotate_endpoint' \
  'unsafe_node_endpoint_mutator.rs:7: direct node/endpoint mutator call outside reviewed store/backend boundary: revoke_endpoint' \
  'unsafe_node_endpoint_mutator.rs:8: direct node/endpoint mutator call outside reviewed store/backend boundary: quarantine_endpoint'
do
  if ! grep -Fq "$expected" "$node_endpoint_fail_output"; then
    printf 'controller mutation guard did not report expected mutator violation: %s\n' "$expected" >&2
    sed -n '1,160p' "$node_endpoint_fail_output" >&2
    exit 1
  fi
done

rm -f "$cli_src/unsafe_node_endpoint_mutator.rs"
printf '%s\n' \
  'pub fn bypass(store: &Store, token: &EnrollmentTokenInsert, request: &JoinRequestInsert, approval: &ApprovalInput, claim: &LegacyEnrollmentClaimInput) {' \
  '    store.create_enrollment_token(token, "actor");' \
  '    Store::revoke_enrollment_token(store, "token", "actor", "reason");' \
  '    store.submit_join_request(request, "actor");' \
  '    Store::reject_join_request(store, "request", "actor", "reason");' \
  '    store.approve_join_request(approval, "actor");' \
  '    Store::claim_legacy_enrollment(store, claim, "actor");' \
  '}' \
  > "$cli_src/unsafe_enrollment_mutator.rs"

enrollment_fail_output="$tmp_dir/enrollment-fail-output"
if "$GUARD" --repo-root "$fixture_root" "$fixture_root" >"$enrollment_fail_output" 2>&1; then
  printf 'controller mutation guard accepted direct enrollment mutator calls\n' >&2
  exit 1
fi
for expected in \
  'unsafe_enrollment_mutator.rs:2: direct enrollment mutator call outside reviewed store/backend boundary: create_enrollment_token' \
  'unsafe_enrollment_mutator.rs:3: direct enrollment mutator call outside reviewed store/backend boundary: revoke_enrollment_token' \
  'unsafe_enrollment_mutator.rs:4: direct enrollment mutator call outside reviewed store/backend boundary: submit_join_request' \
  'unsafe_enrollment_mutator.rs:5: direct enrollment mutator call outside reviewed store/backend boundary: reject_join_request' \
  'unsafe_enrollment_mutator.rs:6: direct enrollment mutator call outside reviewed store/backend boundary: approve_join_request' \
  'unsafe_enrollment_mutator.rs:7: direct enrollment mutator call outside reviewed store/backend boundary: claim_legacy_enrollment'
do
  if ! grep -Fq "$expected" "$enrollment_fail_output"; then
    printf 'controller mutation guard did not report expected enrollment mutator violation: %s\n' "$expected" >&2
    sed -n '1,120p' "$enrollment_fail_output" >&2
    exit 1
  fi
done

rm -f "$cli_src/unsafe_enrollment_mutator.rs"
printf '%s\n' \
  'pub fn bypass(store: &Store, policy: &RetentionPolicyRecord, apply: &RetentionApplyInput) {' \
  '    store.set_retention_policy(policy, "actor");' \
  '    Store::apply_retention(store, apply, "actor");' \
  '}' \
  > "$cli_src/unsafe_retention_mutator.rs"

retention_fail_output="$tmp_dir/retention-fail-output"
if "$GUARD" --repo-root "$fixture_root" "$fixture_root" >"$retention_fail_output" 2>&1; then
  printf 'controller mutation guard accepted direct retention mutator calls\n' >&2
  exit 1
fi
for expected in \
  'unsafe_retention_mutator.rs:2: direct retention mutator call outside reviewed store/backend boundary: set_retention_policy' \
  'unsafe_retention_mutator.rs:3: direct retention mutator call outside reviewed store/backend boundary: apply_retention'
do
  if ! grep -Fq "$expected" "$retention_fail_output"; then
    printf 'controller mutation guard did not report expected retention mutator violation: %s\n' "$expected" >&2
    sed -n '1,120p' "$retention_fail_output" >&2
    exit 1
  fi
done

rm -f "$cli_src/unsafe_retention_mutator.rs"
printf '%s\n' \
  'pub fn bypass(store: &Store, policy: &HealthPolicyRecord, health: &HealthSnapshotWrite, alerts: &AlertEvaluationWrite) {' \
  '    store.set_health_policy(policy, "actor");' \
  '    Store::write_health_snapshots(store, health, "actor");' \
  '    store.write_alert_evaluation(alerts, "actor");' \
  '}' \
  > "$cli_src/unsafe_derived_state_mutator.rs"

derived_state_fail_output="$tmp_dir/derived-state-fail-output"
if "$GUARD" --repo-root "$fixture_root" "$fixture_root" >"$derived_state_fail_output" 2>&1; then
  printf 'controller mutation guard accepted direct derived-state mutator calls\n' >&2
  exit 1
fi
for expected in \
  'unsafe_derived_state_mutator.rs:2: direct derived-state mutator call outside reviewed store/backend boundary: set_health_policy' \
  'unsafe_derived_state_mutator.rs:3: direct derived-state mutator call outside reviewed store/backend boundary: write_health_snapshots' \
  'unsafe_derived_state_mutator.rs:4: direct derived-state mutator call outside reviewed store/backend boundary: write_alert_evaluation'
do
  if ! grep -Fq "$expected" "$derived_state_fail_output"; then
    printf 'controller mutation guard did not report expected derived-state mutator violation: %s\n' "$expected" >&2
    sed -n '1,120p' "$derived_state_fail_output" >&2
    exit 1
  fi
done

rm -f "$cli_src/unsafe_derived_state_mutator.rs"
printf '%s\n' \
  'pub fn bypass(store: &Store, alert: &AlertEventRecord, action: &AlertStateTransition, hook: &AlertWebhookHookRecord, attempt: &AlertDeliveryAttemptWrite, finalize: &AlertDeliveryFinalizeWrite) {' \
  '    store.upsert_alert_event(alert);' \
  '    store.write_alert_state_transition(action, "actor");' \
  '    Store::write_alert_webhook_hook_create(store, hook, "actor");' \
  '    store.write_alert_delivery_attempt(attempt, "actor");' \
  '    Store::write_alert_delivery_finalize(store, finalize, "actor");' \
  '}' \
  > "$cli_src/unsafe_alert_action_mutator.rs"

alert_action_fail_output="$tmp_dir/alert-action-fail-output"
if "$GUARD" --repo-root "$fixture_root" "$fixture_root" >"$alert_action_fail_output" 2>&1; then
  printf 'controller mutation guard accepted direct alert action mutator calls\n' >&2
  exit 1
fi
for expected in \
  'unsafe_alert_action_mutator.rs:2: direct alert action mutator call outside reviewed store/backend boundary: upsert_alert_event' \
  'unsafe_alert_action_mutator.rs:3: direct alert action mutator call outside reviewed store/backend boundary: write_alert_state_transition' \
  'unsafe_alert_action_mutator.rs:4: direct alert action mutator call outside reviewed store/backend boundary: write_alert_webhook_hook_create' \
  'unsafe_alert_action_mutator.rs:5: direct alert action mutator call outside reviewed store/backend boundary: write_alert_delivery_attempt' \
  'unsafe_alert_action_mutator.rs:6: direct alert action mutator call outside reviewed store/backend boundary: write_alert_delivery_finalize'
do
  if ! grep -Fq "$expected" "$alert_action_fail_output"; then
    printf 'controller mutation guard did not report expected alert action violation: %s\n' "$expected" >&2
    sed -n '1,120p' "$alert_action_fail_output" >&2
    exit 1
  fi
done

printf 'Controller mutation SQL guard self-test passed.\n'
