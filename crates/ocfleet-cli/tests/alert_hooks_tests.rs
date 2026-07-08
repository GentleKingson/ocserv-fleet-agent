use ocfleet_cli::store::{AlertEventRecord, HealthSnapshotRecord, NodeInsert, Store};
use rusqlite::Connection;
use serde_json::{Value, json};
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
    let (event, detail): (String, String) = Connection::open(database)
        .expect("open db")
        .query_row(
            "SELECT event, detail_json FROM controller_audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("latest audit");
    (
        event,
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
fn alert_hooks_tests_jsonl_file_hook_is_rejected_in_phase12_mvp() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_path = dir.path().join("alerts.jsonl");
    let hook = format!("jsonl_file:{}", output_path.display());
    let store = Store::open(&database).expect("open store");
    seed_stale_health_snapshot(&store);
    drop(store);

    let output = run_ocfleet_failure(&["--database", &database_arg, "alert", "test", &hook]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("jsonl_file hooks are disabled"));
    assert!(!output_path.exists());
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
}

#[test]
fn alert_hooks_tests_forbidden_hook_types_are_rejected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    for hook in ["exec:/bin/true", "shell:echo hi", "script:/tmp/hook"] {
        let output = run_ocfleet_failure(&["--database", &database_arg, "alert", "test", hook]);
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
