use ocfleet_cli::alert_delivery::MAX_DELIVERY_LIMIT;
use ocfleet_cli::store::{
    AlertEventRecord, HealthSnapshotRecord, NodeInsert, ProbeObservationInsert, Store,
};
use ocfleet_protocol::method::OCSERV_CERT_EXPIRY;
use rusqlite::Connection;
use serde_json::{Value, json};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

fn run_ocfleet(args: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_ocfleet"))
        .args(args)
        .env("USER", "alert-user")
        .output()
        .expect("run ocfleet");
    assert!(
        output.status.success(),
        "ocfleet failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn run_ocfleet_failure(args: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_ocfleet"))
        .args(args)
        .env("USER", "alert-user")
        .output()
        .expect("run ocfleet");
    assert!(
        !output.status.success(),
        "ocfleet unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn seed_alert(store: &Store, dedupe_key: &str) {
    store
        .upsert_alert_event(&AlertEventRecord {
            alert_id: "alert-seeded".to_string(),
            dedupe_key: dedupe_key.to_string(),
            node_id: Some("hk-ocserv-01".to_string()),
            severity: "warning".to_string(),
            state: "open".to_string(),
            reason_code: "NODE_STALE".to_string(),
            first_seen_at: "2026-07-08T00:00:00Z".to_string(),
            last_seen_at: "2026-07-08T00:00:00Z".to_string(),
            last_sent_at: None,
            resolved_at: None,
            detail_json: json!({
                "methods": ["probe.controller.ping"],
                "summary": {"status": "stale"}
            }),
        })
        .expect("seed alert");
}

fn upsert_alert(
    store: &Store,
    alert_id: &str,
    dedupe_key: &str,
    node_id: Option<&str>,
    severity: &str,
    state: &str,
) {
    store
        .upsert_alert_event(&AlertEventRecord {
            alert_id: alert_id.to_string(),
            dedupe_key: dedupe_key.to_string(),
            node_id: node_id.map(ToOwned::to_owned),
            severity: severity.to_string(),
            state: state.to_string(),
            reason_code: "NODE_STALE".to_string(),
            first_seen_at: "2026-07-08T00:00:00Z".to_string(),
            last_seen_at: "2026-07-08T00:00:00Z".to_string(),
            last_sent_at: None,
            resolved_at: (state == "resolved").then(|| "2026-07-08T01:00:00Z".to_string()),
            detail_json: json!({
                "methods": ["probe.controller.ping"],
                "summary": {"status": "stale"}
            }),
        })
        .expect("seed alert");
}

fn seed_stale_health_snapshot(store: &Store) {
    store
        .upsert_health_snapshot(&HealthSnapshotRecord {
            node_id: "hk-ocserv-01".to_string(),
            endpoint_id: Some("endpoint-1".to_string()),
            computed_at: "2026-07-08T00:00:00Z".to_string(),
            status: "stale".to_string(),
            freshness_seconds: Some(90_000),
            last_success_at: Some("2026-07-07T00:00:00Z".to_string()),
            last_failure_at: None,
            last_error_code: None,
            degraded_methods_json: json!(["probe.controller.ping"]),
            summary_json: json!({"status": "stale"}),
        })
        .expect("seed health snapshot");
}

fn latest_audit(database: &Path) -> (String, Value) {
    let (event, _ok, detail) = latest_audit_with_ok(database);
    (event, detail)
}

fn latest_audit_with_ok(database: &Path) -> (String, i64, Value) {
    let (event, ok, detail): (String, i64, String) = Connection::open(database)
        .expect("open db")
        .query_row(
            "SELECT event, ok, detail_json FROM controller_audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("latest audit");
    (
        event,
        ok,
        serde_json::from_str(&detail).expect("parse detail json"),
    )
}

fn assert_no_forbidden_payload_keys(value: &Value) {
    if let Value::Object(map) = value {
        for key in map.keys() {
            assert!(
                !matches!(
                    key.as_str(),
                    "path" | "command" | "log" | "username" | "client_ip" | "session_id"
                ),
                "forbidden payload key present: {key}"
            );
        }
        for value in map.values() {
            assert_no_forbidden_payload_keys(value);
        }
    }
    if let Value::Array(values) = value {
        for value in values {
            assert_no_forbidden_payload_keys(value);
        }
    }
}

#[cfg(unix)]
fn assert_mode(path: &Path, expected: u32) {
    let mode = fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, expected, "unexpected mode for {}", path.display());
}

#[test]
fn alert_hooks_tests_alert_list_json_is_valid() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    seed_alert(&store, "node:hk-ocserv-01:node_stale");
    drop(store);

    let output = run_ocfleet(&["--database", &database_arg, "alert", "list", "--json"]);
    let value: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");

    assert_eq!(
        value["alerts"][0]["dedupe_key"],
        "node:hk-ocserv-01:node_stale"
    );
    assert_eq!(value["alerts"][0]["state"], "open");
}

#[test]
fn alert_hooks_tests_alert_list_filters_state_severity_and_node() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    upsert_alert(
        &store,
        "alert-critical-open",
        "node:hk-ocserv-01:critical",
        Some("hk-ocserv-01"),
        "critical",
        "open",
    );
    upsert_alert(
        &store,
        "alert-warning-open",
        "node:hk-ocserv-01:warning",
        Some("hk-ocserv-01"),
        "warning",
        "open",
    );
    upsert_alert(
        &store,
        "alert-critical-resolved",
        "node:sg-ocserv-01:critical",
        Some("sg-ocserv-01"),
        "critical",
        "resolved",
    );
    drop(store);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "alert",
        "list",
        "--state",
        "open",
        "--severity",
        "critical",
        "--node",
        "hk-ocserv-01",
        "--json",
    ]);
    let value: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(value["state_filter"], "open");
    assert_eq!(value["severity_filter"], "critical");
    assert_eq!(value["node_filter"], "hk-ocserv-01");
    let alerts = value["alerts"].as_array().expect("alerts");
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0]["dedupe_key"], "node:hk-ocserv-01:critical");
    assert_eq!(alerts[0]["severity"], "critical");
    assert_eq!(alerts[0]["state"], "open");
}

#[test]
fn alert_hooks_tests_upsert_same_dedupe_key_does_not_create_duplicate() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    seed_stale_health_snapshot(&store);
    drop(store);

    run_ocfleet(&["--database", &database_arg, "alert", "list"]);
    run_ocfleet(&["--database", &database_arg, "alert", "list"]);

    let store = Store::open(&database).expect("reopen store");
    let alerts = store.list_alert_events().expect("list alerts");
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].dedupe_key, "node:hk-ocserv-01:node_stale");
}

#[test]
fn alert_hooks_tests_alert_list_writes_evaluation_audit_when_rows_are_upserted() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    seed_stale_health_snapshot(&store);
    drop(store);

    run_ocfleet(&["--database", &database_arg, "alert", "list"]);

    let (event, ok, detail) = latest_audit_with_ok(&database);
    assert_eq!(event, "alert.evaluate");
    assert_eq!(ok, 1);
    assert_eq!(detail["evaluated_candidates"], 1);
    assert_eq!(detail["created_or_updated_count"], 1);
}

#[test]
fn alert_hooks_tests_resolve_changes_state() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    seed_alert(&store, "node:hk-ocserv-01:node_stale");
    drop(store);

    run_ocfleet(&[
        "--database",
        &database_arg,
        "alert",
        "resolve",
        "node:hk-ocserv-01:node_stale",
        "--reason",
        "observation recovered",
    ]);

    let store = Store::open(&database).expect("reopen store");
    let alerts = store.list_alert_events().expect("list alerts");
    assert_eq!(alerts[0].state, "resolved");
    assert!(alerts[0].resolved_at.is_some());
}

#[test]
fn alert_hooks_tests_resolve_writes_audit() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    seed_alert(&store, "node:hk-ocserv-01:node_stale");
    drop(store);

    run_ocfleet(&[
        "--database",
        &database_arg,
        "alert",
        "resolve",
        "node:hk-ocserv-01:node_stale",
        "--reason",
        "operator verified recovery",
    ]);

    let (event, detail) = latest_audit(&database);
    assert_eq!(event, "alert.resolve");
    assert_eq!(detail["dedupe_key"], "node:hk-ocserv-01:node_stale");
    assert_eq!(detail["reason"], "operator verified recovery");
}

#[test]
fn alert_hooks_tests_silence_writes_audit() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    seed_alert(&store, "node:hk-ocserv-01:node_stale");
    drop(store);

    run_ocfleet(&[
        "--database",
        &database_arg,
        "alert",
        "silence",
        "node:hk-ocserv-01:node_stale",
        "--for-duration",
        "1h",
        "--reason",
        "maintenance",
    ]);

    let (event, detail) = latest_audit(&database);
    assert_eq!(event, "alert.silence");
    assert_eq!(detail["dedupe_key"], "node:hk-ocserv-01:node_stale");
    assert_eq!(detail["reason"], "maintenance");
}

#[test]
fn alert_hooks_tests_reject_reason_control_characters_and_overlong_text() {
    for (command, reason) in [
        ("silence".to_string(), "maintenance\nopen".to_string()),
        ("resolve".to_string(), "\x1b[31mresolved".to_string()),
        ("silence".to_string(), "a".repeat(257)),
    ] {
        let dir = tempfile::tempdir().expect("temp dir");
        let database = dir.path().join("controller.sqlite");
        let database_arg = database.to_string_lossy().into_owned();
        let store = Store::open(&database).expect("open store");
        seed_alert(&store, "node:hk-ocserv-01:node_stale");
        drop(store);

        let mut args = vec![
            "--database",
            &database_arg,
            "alert",
            command.as_str(),
            "node:hk-ocserv-01:node_stale",
        ];
        if command == "silence" {
            args.extend(["--for-duration", "1h"]);
        }
        args.extend(["--reason", reason.as_str()]);

        let output = run_ocfleet_failure(&args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("reason"),
            "stderr did not name reason: {stderr}"
        );
    }
}

#[test]
fn alert_hooks_tests_silenced_alert_stays_silenced_while_active_candidate_exists() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    seed_stale_health_snapshot(&store);
    drop(store);

    run_ocfleet(&["--database", &database_arg, "alert", "list"]);
    run_ocfleet(&[
        "--database",
        &database_arg,
        "alert",
        "silence",
        "node:hk-ocserv-01:node_stale",
        "--for-duration",
        "1h",
        "--reason",
        "maintenance",
    ]);
    run_ocfleet(&["--database", &database_arg, "alert", "list"]);

    let store = Store::open(&database).expect("reopen store");
    let alerts = store.list_alert_events().expect("list alerts");
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].state, "silenced");
}

#[test]
fn alert_hooks_tests_rotated_endpoint_generates_inactive_alert() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    let new_endpoint_id = iroh::SecretKey::generate().public().to_string();
    store
        .add_node(&NodeInsert {
            node_id: "hk-ocserv-01".to_string(),
            endpoint_id: endpoint_id.clone(),
            name: "hk-ocserv-01".to_string(),
            region: "hk".to_string(),
            role: "ocserv".to_string(),
        })
        .expect("add node");
    store
        .rotate_endpoint(&endpoint_id, &new_endpoint_id, "operator", "test rotate")
        .expect("rotate endpoint");
    drop(store);

    let output = run_ocfleet(&["--database", &database_arg, "alert", "list", "--json"]);
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid payload");
    let inactive = payload["alerts"]
        .as_array()
        .expect("alerts array")
        .iter()
        .find(|alert| alert["reason_code"] == "ENDPOINT_INACTIVE")
        .expect("inactive endpoint alert");
    assert_eq!(inactive["severity"], "critical");
    assert_eq!(inactive["summary"]["endpoint_status"], "rotated");
}

#[test]
fn alert_hooks_tests_cert_expiry_summary_fields_generate_cert_alerts() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    store
        .add_node(&NodeInsert {
            node_id: "hk-ocserv-01".to_string(),
            endpoint_id: endpoint_id.clone(),
            name: "hk-ocserv-01".to_string(),
            region: "hk".to_string(),
            role: "ocserv".to_string(),
        })
        .expect("add node");
    store
        .insert_probe_observation(&ProbeObservationInsert {
            observation_id: "obs-cert-critical".to_string(),
            run_id: None,
            node_id: Some("hk-ocserv-01".to_string()),
            endpoint_id: Some(endpoint_id),
            method: OCSERV_CERT_EXPIRY.to_string(),
            ok: Some(true),
            error_code: None,
            duration_ms: Some(12),
            observed_at: "2026-07-08T00:00:00Z".to_string(),
            expires_at: None,
            result_class: "low_sensitive_summary".to_string(),
            summary_json: json!({
                "result_class": "low_sensitive_summary",
                "cert_count": 1,
                "days_remaining": 3,
                "status": "expiring_soon"
            }),
        })
        .expect("insert cert observation");
    drop(store);

    let output = run_ocfleet(&["--database", &database_arg, "alert", "list", "--json"]);
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid payload");
    let cert_alert = payload["alerts"]
        .as_array()
        .expect("alerts array")
        .iter()
        .find(|alert| alert["reason_code"] == "CERT_EXPIRING_CRITICAL")
        .expect("cert expiry alert");

    assert_eq!(cert_alert["severity"], "critical");
    assert_eq!(cert_alert["summary"]["days_remaining"], 3);
    assert_eq!(cert_alert["summary"]["status"], "expiring_soon");
}

#[test]
#[cfg(unix)]
fn alert_hooks_tests_jsonl_file_delivery_writes_private_jsonl_and_updates_last_sent() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_dir = dir.path().join("alerts-private");
    let output_path = output_dir.join("alerts.jsonl");
    let hook = format!("jsonl_file:{}", output_path.display());
    let store = Store::open(&database).expect("open store");
    seed_alert(&store, "node:hk-ocserv-01:node_stale");
    drop(store);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "alert",
        "deliver",
        "--hook",
        &hook,
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("status=ok"));
    assert!(stdout.contains("hook_type=jsonl_file"));
    assert!(stdout.contains("alert_count=1"));
    assert!(stdout.contains("dry_run=false"));

    assert_mode(&output_dir, 0o700);
    assert_mode(&output_path, 0o600);
    let contents = fs::read_to_string(&output_path).expect("read jsonl");
    let lines = contents.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 1);
    let payload: Value = serde_json::from_str(lines[0]).expect("jsonl payload");
    assert_eq!(payload["dedupe_key"], "node:hk-ocserv-01:node_stale");
    assert_eq!(payload["hook_type"], "jsonl_file");
    assert_no_forbidden_payload_keys(&payload);

    let store = Store::open(&database).expect("reopen store");
    let alerts = store.list_alert_events().expect("list alerts");
    assert!(alerts[0].last_sent_at.is_some());

    let (event, ok, detail) = latest_audit_with_ok(&database);
    assert_eq!(event, "alert.delivery");
    assert_eq!(ok, 1);
    assert_eq!(detail["hook_type"], "jsonl_file");
    assert_eq!(detail["alert_count"], 1);
    assert_eq!(detail["ok"], true);
}

#[test]
#[cfg(unix)]
fn alert_hooks_tests_jsonl_file_test_writes_fixed_test_event() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_path = dir.path().join("alerts-test").join("test.jsonl");
    let hook = format!("jsonl_file:{}", output_path.display());

    let output = run_ocfleet(&["--database", &database_arg, "alert", "test", &hook]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("status=ok"));
    assert!(stdout.contains("hook_type=jsonl_file"));
    assert!(stdout.contains("test_event=true"));

    let contents = fs::read_to_string(&output_path).expect("read jsonl");
    let payload: Value = serde_json::from_str(contents.trim()).expect("jsonl payload");
    assert_eq!(payload["event"], "alert.delivery.test");
    assert_eq!(payload["hook_type"], "jsonl_file");
    assert_no_forbidden_payload_keys(&payload);
}

#[test]
#[cfg(unix)]
fn alert_hooks_tests_existing_private_jsonl_file_appends() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_dir = dir.path().join("alerts-private");
    fs::create_dir(&output_dir).expect("create output dir");
    fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o700)).expect("chmod dir");
    let output_path = output_dir.join("alerts.jsonl");
    fs::write(&output_path, "{\"existing\":true}\n").expect("seed jsonl");
    fs::set_permissions(&output_path, fs::Permissions::from_mode(0o600)).expect("chmod file");
    let hook = format!("jsonl_file:{}", output_path.display());
    let store = Store::open(&database).expect("open store");
    seed_alert(&store, "node:hk-ocserv-01:node_stale");
    drop(store);

    run_ocfleet(&[
        "--database",
        &database_arg,
        "alert",
        "deliver",
        "--hook",
        &hook,
    ]);

    let contents = fs::read_to_string(&output_path).expect("read jsonl");
    assert_eq!(contents.lines().count(), 2);
    assert_mode(&output_path, 0o600);
}

#[test]
#[cfg(unix)]
fn alert_hooks_tests_existing_world_readable_jsonl_file_is_rejected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_dir = dir.path().join("alerts-private");
    fs::create_dir(&output_dir).expect("create output dir");
    fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o700)).expect("chmod dir");
    let output_path = output_dir.join("alerts.jsonl");
    fs::write(&output_path, "").expect("seed jsonl");
    fs::set_permissions(&output_path, fs::Permissions::from_mode(0o644)).expect("chmod file");
    let hook = format!("jsonl_file:{}", output_path.display());
    let store = Store::open(&database).expect("open store");
    seed_alert(&store, "node:hk-ocserv-01:node_stale");
    drop(store);

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "alert",
        "deliver",
        "--hook",
        &hook,
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("alert delivery failed"));
    let (_event, ok, detail) = latest_audit_with_ok(&database);
    assert_eq!(ok, 0);
    assert_eq!(detail["error_code"], "ALERT_DELIVERY_FAILED");
}

#[test]
#[cfg(unix)]
fn alert_hooks_tests_jsonl_file_dry_run_does_not_write_or_update_last_sent() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_path = dir.path().join("alerts-private").join("alerts.jsonl");
    let hook = format!("jsonl_file:{}", output_path.display());
    let store = Store::open(&database).expect("open store");
    seed_alert(&store, "node:hk-ocserv-01:node_stale");
    drop(store);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "alert",
        "deliver",
        "--hook",
        &hook,
        "--dry-run",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("status=ok"));
    assert!(stdout.contains("alert_count=1"));
    assert!(stdout.contains("dry_run=true"));
    assert!(!output_path.exists());

    let store = Store::open(&database).expect("reopen store");
    let alerts = store.list_alert_events().expect("list alerts");
    assert!(alerts[0].last_sent_at.is_none());
    let (event, ok, detail) = latest_audit_with_ok(&database);
    assert_eq!(event, "alert.delivery");
    assert_eq!(ok, 1);
    assert_eq!(detail["dry_run"], true);
}

#[test]
#[cfg(unix)]
fn alert_hooks_tests_jsonl_file_symlink_target_is_rejected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_dir = dir.path().join("alerts-private");
    fs::create_dir(&output_dir).expect("create output dir");
    fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o700)).expect("chmod dir");
    let target = output_dir.join("target.jsonl");
    fs::write(&target, "").expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("chmod target");
    let output_path = output_dir.join("alerts.jsonl");
    std::os::unix::fs::symlink(&target, &output_path).expect("symlink");
    let hook = format!("jsonl_file:{}", output_path.display());
    let store = Store::open(&database).expect("open store");
    seed_alert(&store, "node:hk-ocserv-01:node_stale");
    drop(store);

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "alert",
        "deliver",
        "--hook",
        &hook,
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("alert delivery failed"));
    let (event, ok, detail) = latest_audit_with_ok(&database);
    assert_eq!(event, "alert.delivery");
    assert_eq!(ok, 0);
    assert_eq!(detail["error_code"], "ALERT_DELIVERY_FAILED");
}

#[test]
#[cfg(unix)]
fn alert_hooks_tests_jsonl_file_hardlink_is_rejected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_dir = dir.path().join("alerts-private");
    fs::create_dir(&output_dir).expect("create output dir");
    fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o700)).expect("chmod dir");
    let output_path = output_dir.join("alerts.jsonl");
    fs::write(&output_path, "").expect("seed jsonl");
    fs::set_permissions(&output_path, fs::Permissions::from_mode(0o600)).expect("chmod file");
    let hardlink = output_dir.join("alerts-hardlink.jsonl");
    fs::hard_link(&output_path, &hardlink).expect("hardlink");
    let hook = format!("jsonl_file:{}", output_path.display());
    let store = Store::open(&database).expect("open store");
    seed_alert(&store, "node:hk-ocserv-01:node_stale");
    drop(store);

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "alert",
        "deliver",
        "--hook",
        &hook,
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("alert delivery failed"));
    let (_event, ok, detail) = latest_audit_with_ok(&database);
    assert_eq!(ok, 0);
    assert_eq!(detail["error_code"], "ALERT_DELIVERY_FAILED");
}

#[test]
#[cfg(unix)]
fn alert_hooks_tests_jsonl_file_world_writable_parent_is_rejected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_dir = dir.path().join("alerts-open");
    fs::create_dir(&output_dir).expect("create output dir");
    fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o777)).expect("chmod dir");
    let output_path = output_dir.join("alerts.jsonl");
    let hook = format!("jsonl_file:{}", output_path.display());
    let store = Store::open(&database).expect("open store");
    seed_alert(&store, "node:hk-ocserv-01:node_stale");
    drop(store);

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "alert",
        "deliver",
        "--hook",
        &hook,
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("alert delivery failed"));
    let (_event, ok, detail) = latest_audit_with_ok(&database);
    assert_eq!(ok, 0);
    assert_eq!(detail["error_code"], "ALERT_DELIVERY_FAILED");
}

#[test]
#[cfg(unix)]
fn alert_hooks_tests_jsonl_file_world_readable_parent_is_rejected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_dir = dir.path().join("alerts-readable");
    fs::create_dir(&output_dir).expect("create output dir");
    fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o755)).expect("chmod dir");
    let output_path = output_dir.join("alerts.jsonl");
    let hook = format!("jsonl_file:{}", output_path.display());
    let store = Store::open(&database).expect("open store");
    seed_alert(&store, "node:hk-ocserv-01:node_stale");
    drop(store);

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "alert",
        "deliver",
        "--hook",
        &hook,
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("alert delivery failed"));
    let (_event, ok, detail) = latest_audit_with_ok(&database);
    assert_eq!(ok, 0);
    assert_eq!(detail["error_code"], "ALERT_DELIVERY_FAILED");
}

#[test]
#[cfg(unix)]
fn alert_hooks_tests_jsonl_file_directory_target_is_rejected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_dir = dir.path().join("alerts-private");
    fs::create_dir(&output_dir).expect("create output dir");
    fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o700)).expect("chmod dir");
    let output_path = output_dir.join("alerts.jsonl");
    fs::create_dir(&output_path).expect("create directory target");
    let hook = format!("jsonl_file:{}", output_path.display());
    let store = Store::open(&database).expect("open store");
    seed_alert(&store, "node:hk-ocserv-01:node_stale");
    drop(store);

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "alert",
        "deliver",
        "--hook",
        &hook,
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("alert delivery failed"));
    let (_event, ok, detail) = latest_audit_with_ok(&database);
    assert_eq!(ok, 0);
    assert_eq!(detail["error_code"], "ALERT_DELIVERY_FAILED");
}

#[test]
#[cfg(unix)]
fn alert_hooks_tests_jsonl_file_payload_over_limit_is_rejected_without_writing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_path = dir.path().join("alerts-private").join("alerts.jsonl");
    let hook = format!("jsonl_file:{}", output_path.display());
    let store = Store::open(&database).expect("open store");
    store
        .upsert_alert_event(&AlertEventRecord {
            alert_id: "alert-large".to_string(),
            dedupe_key: "node:hk-ocserv-01:node_stale".to_string(),
            node_id: Some("hk-ocserv-01".to_string()),
            severity: "warning".to_string(),
            state: "open".to_string(),
            reason_code: "NODE_STALE".to_string(),
            first_seen_at: "2026-07-08T00:00:00Z".to_string(),
            last_seen_at: "2026-07-08T00:00:00Z".to_string(),
            last_sent_at: None,
            resolved_at: None,
            detail_json: json!({
                "methods": ["probe.controller.ping"],
                "summary": {"status": "x".repeat(20 * 1024)}
            }),
        })
        .expect("seed large alert");
    drop(store);

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "alert",
        "deliver",
        "--hook",
        &hook,
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("alert delivery payload exceeds limit"));
    assert!(!output_path.exists());
    let (_event, ok, detail) = latest_audit_with_ok(&database);
    assert_eq!(ok, 0);
    assert_eq!(detail["error_code"], "ALERT_DELIVERY_FAILED");
}

#[test]
#[cfg(unix)]
fn alert_hooks_tests_jsonl_file_limit_above_max_is_rejected_and_audited() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_path = dir.path().join("alerts-private").join("alerts.jsonl");
    let hook = format!("jsonl_file:{}", output_path.display());
    let limit = (MAX_DELIVERY_LIMIT + 1).to_string();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "alert",
        "deliver",
        "--hook",
        &hook,
        "--limit",
        &limit,
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--limit must be between 1"));
    assert!(!output_path.exists());
    let (event, ok, detail) = latest_audit_with_ok(&database);
    assert_eq!(event, "alert.delivery");
    assert_eq!(ok, 0);
    assert_eq!(detail["error_code"], "ALERT_DELIVERY_FAILED");
}

#[test]
fn alert_hooks_tests_webhook_hook_is_rejected_in_phase12_mvp() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    seed_stale_health_snapshot(&store);
    drop(store);

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "alert",
        "test",
        "webhook:https://example.com/alerts,hmac_secret=secret",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("webhook hooks are disabled"));

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "alert",
        "deliver",
        "--hook",
        "webhook:https://example.com/alerts,hmac_secret=secret",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("webhook hooks are disabled"));
}

#[test]
fn alert_hooks_tests_http_webhook_is_rejected_without_network_delivery() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    seed_stale_health_snapshot(&store);
    drop(store);

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "alert",
        "test",
        "webhook:http://127.0.0.1:9/alerts",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("webhook hooks are disabled"));

    for hook in [
        "webhook:http://127.0.0.1:9/alerts",
        "webhook:https://127.0.0.1/alerts",
        "webhook:https://10.0.0.1/alerts",
    ] {
        let output = run_ocfleet_failure(&[
            "--database",
            &database_arg,
            "alert",
            "deliver",
            "--hook",
            hook,
        ]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("webhook hooks are disabled"));
    }
}

#[test]
fn alert_hooks_tests_forbidden_hook_types_are_rejected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    for hook in [
        "exec:/bin/true",
        "command:/bin/true",
        "shell:echo hi",
        "script:/tmp/hook",
    ] {
        let output = run_ocfleet_failure(&["--database", &database_arg, "alert", "test", hook]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("forbidden alert hook type"));

        let output = run_ocfleet_failure(&[
            "--database",
            &database_arg,
            "alert",
            "deliver",
            "--hook",
            hook,
        ]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("forbidden alert hook type"));
    }
}

#[test]
fn alert_hooks_tests_payload_does_not_contain_forbidden_keys() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    seed_stale_health_snapshot(&store);
    drop(store);

    let output = run_ocfleet(&["--database", &database_arg, "alert", "list", "--json"]);
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid payload");

    assert_no_forbidden_payload_keys(&payload);
}

#[test]
fn alert_hooks_tests_payload_uses_summary_allowlist() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    store
        .upsert_alert_event(&AlertEventRecord {
            alert_id: "alert-seeded".to_string(),
            dedupe_key: "node:hk-ocserv-01:node_stale".to_string(),
            node_id: Some("hk-ocserv-01".to_string()),
            severity: "warning".to_string(),
            state: "open".to_string(),
            reason_code: "NODE_STALE".to_string(),
            first_seen_at: "2026-07-08T00:00:00Z".to_string(),
            last_seen_at: "2026-07-08T00:00:00Z".to_string(),
            last_sent_at: None,
            resolved_at: None,
            detail_json: json!({
                "methods": ["probe.controller.ping"],
                "summary": {
                    "status": "stale",
                    "message": "client_ip=10.0.0.2 session_id=abc"
                }
            }),
        })
        .expect("seed alert");
    drop(store);

    let output = run_ocfleet(&["--database", &database_arg, "alert", "list", "--json"]);
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid payload");
    assert_eq!(payload["alerts"][0]["summary"]["status"], "stale");
    assert!(payload["alerts"][0]["summary"].get("message").is_none());
}
