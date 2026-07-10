use ocfleet_cli::alert_delivery::MAX_DELIVERY_LIMIT;
use ocfleet_cli::alert_webhook::{
    WebhookHttpRequest, WebhookHttpResponse, WebhookHttpResult, WebhookSender, hmac_key_id,
    validate_webhook_endpoint, webhook_signature,
};
use ocfleet_cli::alerts::deliver_webhook_alerts_with_sender;
use ocfleet_cli::store::{
    AlertEventRecord, AlertWebhookHookRecord, HealthSnapshotRecord, NodeInsert,
    ProbeObservationInsert, Store,
};
use ocfleet_protocol::method::OCSERV_CERT_EXPIRY;
use rusqlite::Connection;
use serde_json::{Value, json};
use std::cell::RefCell;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

#[derive(Debug)]
struct FakeWebhookSender {
    requests: RefCell<Vec<WebhookHttpRequest>>,
    result: WebhookHttpResult,
}

impl FakeWebhookSender {
    fn new(result: WebhookHttpResult) -> Self {
        Self {
            requests: RefCell::new(Vec::new()),
            result,
        }
    }

    fn request_count(&self) -> usize {
        self.requests.borrow().len()
    }

    fn requests(&self) -> Vec<WebhookHttpRequest> {
        self.requests.borrow().clone()
    }
}

impl WebhookSender for FakeWebhookSender {
    fn send(&self, request: &WebhookHttpRequest) -> WebhookHttpResult {
        self.requests.borrow_mut().push(request.clone());
        self.result.clone()
    }
}

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

fn seed_webhook_hook(
    store: &Store,
    hook_id: &str,
    endpoint_url: &str,
    secret: &[u8],
) -> AlertWebhookHookRecord {
    let host = validate_webhook_endpoint(endpoint_url, &["93.184.216.34".to_string()])
        .expect("valid endpoint");
    let hook = AlertWebhookHookRecord {
        hook_id: hook_id.to_string(),
        name: "ops".to_string(),
        hook_type: "webhook".to_string(),
        endpoint_url: host.url,
        endpoint_url_redacted: host.redacted_url,
        endpoint_host: host.host,
        host_allow: host.host_allow,
        hmac_key_id: hmac_key_id(secret),
        enabled: true,
        max_attempts: 2,
        timeout_ms: 1_500,
        created_at: "2026-07-08T00:00:00Z".to_string(),
        updated_at: "2026-07-08T00:00:00Z".to_string(),
    };
    store
        .insert_alert_webhook_hook(&hook)
        .expect("insert webhook hook");
    hook
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

#[cfg(unix)]
fn write_private_secret(path: &Path, secret: &[u8]) {
    fs::write(path, secret).expect("write secret");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod secret");
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
        .add_node(
            &NodeInsert {
                node_id: "hk-ocserv-01".to_string(),
                endpoint_id: endpoint_id.clone(),
                name: "hk-ocserv-01".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            "alert-test",
        )
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
        .add_node(
            &NodeInsert {
                node_id: "hk-ocserv-01".to_string(),
                endpoint_id: endpoint_id.clone(),
                name: "hk-ocserv-01".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            "alert-test",
        )
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
fn alert_hooks_tests_jsonl_file_projects_oversized_legacy_payload_before_delivery() {
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
                "summary": {"status": "stale"}
            }),
        })
        .expect("seed alert");
    drop(store);
    Connection::open(&database)
        .expect("open contaminated fixture")
        .execute(
            "UPDATE alert_events SET detail_json = ?1 WHERE alert_id = 'alert-large'",
            [json!({
                "methods": ["probe.controller.ping"],
                "summary": {"status": "x".repeat(20 * 1024)}
            })
            .to_string()],
        )
        .expect("seed oversized legacy alert detail");

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
    assert!(!output_path.exists());
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
#[cfg(unix)]
fn alert_hooks_tests_webhook_add_rejects_http_url() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let secret = dir.path().join("webhook.secret");
    write_private_secret(&secret, b"0123456789abcdef0123456789abcdef");
    let secret_arg = secret.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "alert",
        "hook",
        "add-webhook",
        "--name",
        "ops",
        "--url",
        "http://93.184.216.34/alerts",
        "--hmac-secret-file",
        &secret_arg,
        "--host-allow",
        "93.184.216.34",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("webhook URL must use https"));
}

#[test]
#[cfg(unix)]
fn alert_hooks_tests_webhook_add_rejects_private_and_metadata_hosts() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let secret = dir.path().join("webhook.secret");
    write_private_secret(&secret, b"0123456789abcdef0123456789abcdef");
    let secret_arg = secret.to_string_lossy().into_owned();

    for host in [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "metadata.google.internal",
    ] {
        let url = format!("https://{host}/alerts");
        let output = run_ocfleet_failure(&[
            "--database",
            &database_arg,
            "alert",
            "hook",
            "add-webhook",
            "--name",
            "ops",
            "--url",
            &url,
            "--hmac-secret-file",
            &secret_arg,
            "--host-allow",
            host,
        ]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("forbidden"),
            "expected forbidden host/IP error for {host}: {stderr}"
        );
    }
}

#[test]
#[cfg(unix)]
fn alert_hooks_tests_webhook_add_list_and_audit_redact_url_path() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let secret = dir.path().join("webhook.secret");
    write_private_secret(&secret, b"0123456789abcdef0123456789abcdef");
    let secret_arg = secret.to_string_lossy().into_owned();

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "alert",
        "hook",
        "add-webhook",
        "--name",
        "ops",
        "--url",
        "https://93.184.216.34/alerts",
        "--hmac-secret-file",
        &secret_arg,
        "--host-allow",
        "93.184.216.34",
        "--max-attempts",
        "2",
        "--timeout-ms",
        "1500",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hook_type=webhook"));
    assert!(stdout.contains("endpoint_url=https://93.184.216.34/<redacted>"));
    let hook_id = stdout
        .lines()
        .find_map(|line| line.strip_prefix("hook_id="))
        .expect("hook id")
        .to_string();

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "alert",
        "hook",
        "list",
        "--json",
    ]);
    let list = String::from_utf8_lossy(&output.stdout);
    assert!(list.contains("https://93.184.216.34/<redacted>"));
    assert!(!list.contains("/alerts/path"));
    assert!(!list.contains("0123456789abcdef"));

    let (event, detail) = latest_audit(&database);
    assert_eq!(event, "alert.hook.add_webhook");
    assert_eq!(detail["endpoint_host"], "93.184.216.34");
    assert!(detail.get("endpoint_url").is_none());
    assert!(!detail.to_string().contains("0123456789abcdef"));

    let store = Store::open(&database).expect("open store");
    seed_alert(&store, "node:hk-ocserv-01:node_stale");
    drop(store);
    let hook_arg = format!("webhook:{hook_id}");
    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "alert",
        "deliver",
        "--hook",
        &hook_arg,
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--hmac-secret-file"));
    let (event, ok, detail) = latest_audit_with_ok(&database);
    assert_eq!(event, "alert.delivery");
    assert_eq!(ok, 0);
    assert_eq!(detail["hook_type"], "webhook");
    assert!(!detail.to_string().contains("0123456789abcdef"));
    assert!(!detail.to_string().contains("/alerts/path"));
}

#[test]
#[cfg(unix)]
fn alert_hooks_tests_webhook_rejects_query_secrets_before_storage() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let secret = dir.path().join("webhook.secret");
    write_private_secret(&secret, b"0123456789abcdef0123456789abcdef");
    let secret_arg = secret.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "alert",
        "hook",
        "add-webhook",
        "--name",
        "ops",
        "--url",
        "https://93.184.216.34/alerts?token=supersecret",
        "--hmac-secret-file",
        &secret_arg,
        "--host-allow",
        "93.184.216.34",
    ]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("must not contain a query"));

    let store = Store::open(&database).expect("open store");
    assert!(
        store
            .list_alert_webhook_hooks()
            .expect("list hooks")
            .is_empty()
    );
}

#[test]
#[cfg(unix)]
fn alert_hooks_tests_webhook_rejects_opaque_path_credentials() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let secret = dir.path().join("webhook.secret");
    write_private_secret(&secret, b"0123456789abcdef0123456789abcdef");
    let secret_arg = secret.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "alert",
        "hook",
        "add-webhook",
        "--name",
        "ops",
        "--url",
        "https://93.184.216.34/services/opaque-capability-token",
        "--hmac-secret-file",
        &secret_arg,
        "--host-allow",
        "93.184.216.34",
    ]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("fixed low-sensitive path catalog"));
}

#[test]
fn alert_hooks_tests_webhook_signature_is_deterministic() {
    let signature = webhook_signature(
        b"0123456789abcdef",
        "2026-07-09T00:00:00Z",
        "delivery-fixed",
        br#"{"schema":"ocfleet.alert.v1"}"#,
    );
    assert_eq!(
        signature,
        "2680331a9d05793856ee7c9700574921c103b94ce286f0539dc0b979d3c9bac9"
    );
    assert_eq!(
        signature,
        webhook_signature(
            b"0123456789abcdef",
            "2026-07-09T00:00:00Z",
            "delivery-fixed",
            br#"{"schema":"ocfleet.alert.v1"}"#,
        )
    );
}

#[test]
fn alert_hooks_tests_webhook_dry_run_writes_attempt_without_network_request() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let store = Store::open(&database).expect("open store");
    seed_alert(&store, "node:hk-ocserv-01:node_stale");
    let hook = seed_webhook_hook(
        &store,
        "webhook-dry-run",
        "https://93.184.216.34/alerts",
        b"0123456789abcdef",
    );
    let alerts = store.list_alert_events().expect("list alerts");
    let sender = FakeWebhookSender::new(WebhookHttpResult::Completed(WebhookHttpResponse {
        status_code: 200,
        status_class: "2xx".to_string(),
        response_bytes: 0,
    }));

    let summary =
        deliver_webhook_alerts_with_sender(&store, &hook.hook_id, &alerts, true, None, &sender)
            .expect("dry-run delivery");

    assert_eq!(summary.record_count, 1);
    assert!(summary.bytes_written < 4 * 1024);
    assert!(summary.bytes_written > 0);
    assert_eq!(sender.request_count(), 0);
    let attempts = store
        .list_alert_delivery_attempts()
        .expect("list delivery attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].status, "dry_run");
    assert!(attempts[0].http_status_class.is_none());
}

#[test]
fn alert_hooks_tests_webhook_projects_oversized_legacy_payload_before_request() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
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
                "summary": {"status": "stale"}
            }),
        })
        .expect("seed alert");
    Connection::open(&database)
        .expect("open contaminated fixture")
        .execute(
            "UPDATE alert_events SET detail_json = ?1 WHERE alert_id = 'alert-large'",
            [json!({
                "methods": ["probe.controller.ping"],
                "summary": {"status": "x".repeat(20 * 1024)}
            })
            .to_string()],
        )
        .expect("seed oversized legacy alert detail");
    let hook = seed_webhook_hook(
        &store,
        "webhook-large",
        "https://93.184.216.34/alerts",
        b"0123456789abcdef",
    );
    let alerts = store.list_alert_events().expect("list alerts");
    let sender = FakeWebhookSender::new(WebhookHttpResult::Completed(WebhookHttpResponse {
        status_code: 200,
        status_class: "2xx".to_string(),
        response_bytes: 0,
    }));

    let summary =
        deliver_webhook_alerts_with_sender(&store, &hook.hook_id, &alerts, true, None, &sender)
            .expect("legacy payload must be projected before request");

    assert_eq!(summary.record_count, 1);
    assert!(summary.bytes_written < 4 * 1024);
    assert_eq!(sender.request_count(), 0);
    assert_eq!(
        store
            .list_alert_delivery_attempts()
            .expect("list delivery attempts")
            .len(),
        1
    );
}

#[test]
#[cfg(unix)]
fn alert_hooks_tests_webhook_delivery_writes_attempt_and_hmac_headers() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_path = dir.path().join("webhook.secret");
    let secret = b"0123456789abcdef0123456789abcdef";
    write_private_secret(&secret_path, secret);
    let store = Store::open(&database).expect("open store");
    seed_alert(&store, "node:hk-ocserv-01:node_stale");
    let hook = seed_webhook_hook(
        &store,
        "webhook-success",
        "https://93.184.216.34/alerts",
        secret,
    );
    let alerts = store.list_alert_events().expect("list alerts");
    let sender = FakeWebhookSender::new(WebhookHttpResult::Completed(WebhookHttpResponse {
        status_code: 200,
        status_class: "2xx".to_string(),
        response_bytes: 0,
    }));

    let summary = deliver_webhook_alerts_with_sender(
        &store,
        &hook.hook_id,
        &alerts,
        false,
        Some(&secret_path),
        &sender,
    )
    .expect("webhook delivery");

    assert_eq!(summary.record_count, 1);
    assert!(summary.bytes_written > 0);
    let requests = sender.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url, "https://93.184.216.34/alerts");
    assert!(
        requests[0]
            .headers
            .iter()
            .any(|(name, value)| name == "X-Ocfleet-Signature" && value.starts_with("sha256="))
    );
    assert!(
        requests[0]
            .headers
            .iter()
            .any(|(name, _)| name == "X-Ocfleet-Timestamp")
    );
    assert!(
        requests[0]
            .headers
            .iter()
            .any(|(name, _)| name == "X-Ocfleet-Delivery-Id")
    );
    let attempts = store
        .list_alert_delivery_attempts()
        .expect("list delivery attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].status, "succeeded");
    assert_eq!(attempts[0].http_status_class.as_deref(), Some("2xx"));
    assert!(attempts[0].error_code.is_none());
}

#[test]
#[cfg(unix)]
fn alert_hooks_tests_webhook_redirect_is_rejected_and_attempt_is_recorded() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_path = dir.path().join("webhook.secret");
    let secret = b"0123456789abcdef0123456789abcdef";
    write_private_secret(&secret_path, secret);
    let store = Store::open(&database).expect("open store");
    seed_alert(&store, "node:hk-ocserv-01:node_stale");
    let hook = seed_webhook_hook(
        &store,
        "webhook-redirect",
        "https://93.184.216.34/alerts",
        secret,
    );
    let alerts = store.list_alert_events().expect("list alerts");
    let sender = FakeWebhookSender::new(WebhookHttpResult::Completed(WebhookHttpResponse {
        status_code: 302,
        status_class: "3xx".to_string(),
        response_bytes: 0,
    }));

    let err = deliver_webhook_alerts_with_sender(
        &store,
        &hook.hook_id,
        &alerts,
        false,
        Some(&secret_path),
        &sender,
    )
    .expect_err("redirect is rejected");

    assert!(err.to_string().contains("WEBHOOK_REDIRECT_FORBIDDEN"));
    assert_eq!(sender.request_count(), 1);
    let attempts = store
        .list_alert_delivery_attempts()
        .expect("list delivery attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].status, "failed");
    assert_eq!(attempts[0].http_status_class.as_deref(), Some("3xx"));
    assert_eq!(
        attempts[0].error_code.as_deref(),
        Some("WEBHOOK_REDIRECT_FORBIDDEN")
    );
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
                "summary": {"status": "stale"}
            }),
        })
        .expect("seed alert");
    drop(store);
    Connection::open(&database)
        .expect("open contaminated fixture database")
        .execute(
            "UPDATE alert_events SET detail_json = ?1 WHERE alert_id = 'alert-seeded'",
            [json!({
                "methods": ["probe.controller.ping", "shell.exec", "/etc/secret"],
                "summary": {
                    "status": "stale",
                    "message": "client_ip=10.0.0.2 session_id=abc",
                    "result_class": "x".repeat(129)
                }
            })
            .to_string()],
        )
        .expect("seed contaminated alert detail");

    let output = run_ocfleet(&["--database", &database_arg, "alert", "list", "--json"]);
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid payload");
    assert_eq!(payload["alerts"][0]["summary"]["status"], "stale");
    assert!(payload["alerts"][0]["summary"].get("message").is_none());
    assert!(
        payload["alerts"][0]["summary"]
            .get("result_class")
            .is_none()
    );
    assert_eq!(
        payload["alerts"][0]["methods"],
        json!(["probe.controller.ping"])
    );
}
