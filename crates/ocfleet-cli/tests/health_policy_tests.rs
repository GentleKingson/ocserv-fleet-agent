use ocfleet_cli::store::{HealthPolicyRecord, NodeInsert, ProbeObservationInsert, Store};
use ocfleet_protocol::method::{OCSERV_CERT_EXPIRY, PROBE_CONTROLLER_PING};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::path::Path;
use std::process::{Command, Output};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

fn run_ocfleet(args: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_ocfleet"))
        .args(args)
        .env("USER", "policy-user")
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
        .env("USER", "policy-user")
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

fn add_node(store: &Store, node_id: &str) {
    store
        .add_node(
            &NodeInsert {
                node_id: node_id.to_string(),
                endpoint_id: iroh::SecretKey::generate().public().to_string(),
                name: node_id.to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            "health-policy-test",
        )
        .expect("add node");
}

fn timestamp_days_ago(days: i64) -> String {
    (OffsetDateTime::now_utc() - Duration::days(days))
        .format(&Rfc3339)
        .expect("format timestamp")
}

fn timestamp_minutes_ago(minutes: i64) -> String {
    (OffsetDateTime::now_utc() - Duration::minutes(minutes))
        .format(&Rfc3339)
        .expect("format timestamp")
}

struct ObservationFixture<'a> {
    observation_id: &'a str,
    node_id: &'a str,
    method: &'a str,
    ok: bool,
    error_code: Option<&'a str>,
    observed_at: &'a str,
    summary_json: Value,
}

fn insert_observation(store: &Store, fixture: ObservationFixture<'_>) {
    let endpoint_id = store
        .get_node(fixture.node_id)
        .expect("get node")
        .expect("node exists")
        .endpoint_id;
    store
        .insert_probe_observation(&ProbeObservationInsert {
            observation_id: fixture.observation_id.to_string(),
            run_id: None,
            node_id: Some(fixture.node_id.to_string()),
            endpoint_id: Some(endpoint_id),
            method: fixture.method.to_string(),
            ok: Some(fixture.ok),
            error_code: fixture.error_code.map(ToOwned::to_owned),
            duration_ms: Some(12),
            observed_at: fixture.observed_at.to_string(),
            expires_at: None,
            result_class: "low_sensitive_summary".to_string(),
            summary_json: fixture.summary_json,
        })
        .expect("insert observation");
}

fn latest_audit(database: &Path) -> (String, String, Value) {
    let (actor, event, detail): (String, String, String) = Connection::open(database)
        .expect("open db")
        .query_row(
            "SELECT actor, event, detail_json FROM controller_audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("latest audit");
    (
        actor,
        event,
        serde_json::from_str(&detail).expect("parse detail json"),
    )
}

#[test]
fn health_policy_tests_show_outputs_default_values() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let output = run_ocfleet(&["--database", &database_arg, "health", "policy", "show"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("stale_window_seconds=86400"));
    assert!(stdout.contains("unreachable_consecutive_failures=3"));
    assert!(stdout.contains("cert_warning_days=30"));
    assert!(stdout.contains("cert_critical_days=7"));
}

#[test]
fn health_policy_tests_set_persists_policy_and_writes_audit() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    assert_eq!(
        store.get_health_policy().expect("default policy"),
        Store::default_health_policy()
    );
    drop(store);

    run_ocfleet(&[
        "--database",
        &database_arg,
        "health",
        "policy",
        "set",
        "--stale-window",
        "15d",
        "--unreachable-failures",
        "2",
        "--cert-warning-days",
        "60",
        "--cert-critical-days",
        "14",
    ]);

    let store = Store::open(&database).expect("reopen store");
    let policy = store.get_health_policy().expect("health policy");
    assert_eq!(policy.stale_window_seconds, 15 * 24 * 60 * 60);
    assert_eq!(policy.unreachable_consecutive_failures, 2);
    assert_eq!(policy.cert_warning_days, 60);
    assert_eq!(policy.cert_critical_days, 14);
    drop(store);

    let (actor, event, detail) = latest_audit(&database);
    assert_eq!(actor, "policy-user");
    assert_eq!(event, "health.policy.set");
    assert_eq!(detail["policy_class"], "health_thresholds");
    assert_eq!(detail["old_value"]["stale_window_seconds"], 86_400);
    assert_eq!(detail["new_value"]["stale_window_seconds"], 1_296_000);
    assert_eq!(detail["new_value"]["unreachable_consecutive_failures"], 2);
}

#[test]
fn health_policy_tests_custom_stale_window_controls_health_status() {
    for (stale_window, expected_status) in [("15d", "healthy"), ("1h", "stale")] {
        let dir = tempfile::tempdir().expect("temp dir");
        let database = dir.path().join("controller.sqlite");
        let database_arg = database.to_string_lossy().into_owned();
        let store = Store::open(&database).expect("open store");
        add_node(&store, "hk-ocserv-01");
        let observed_at = timestamp_days_ago(10);
        insert_observation(
            &store,
            ObservationFixture {
                observation_id: "obs-old-ping",
                node_id: "hk-ocserv-01",
                method: PROBE_CONTROLLER_PING,
                ok: true,
                error_code: None,
                observed_at: &observed_at,
                summary_json: json!({"message": "pong"}),
            },
        );
        drop(store);

        run_ocfleet(&[
            "--database",
            &database_arg,
            "health",
            "policy",
            "set",
            "--stale-window",
            stale_window,
        ]);
        let output = run_ocfleet(&["--database", &database_arg, "health", "summary"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            stdout.contains(&format!("status={expected_status}")),
            "expected {expected_status} for stale window {stale_window}: {stdout}"
        );
    }
}

#[test]
fn health_policy_tests_unreachable_failure_threshold_controls_alerts() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    add_node(&store, "hk-ocserv-01");
    for idx in 0..2 {
        let observed_at = timestamp_minutes_ago(2 - idx);
        insert_observation(
            &store,
            ObservationFixture {
                observation_id: if idx == 0 {
                    "obs-timeout-1"
                } else {
                    "obs-timeout-2"
                },
                node_id: "hk-ocserv-01",
                method: PROBE_CONTROLLER_PING,
                ok: false,
                error_code: Some("RPC_TIMEOUT"),
                observed_at: &observed_at,
                summary_json: json!({"result_class": "low_sensitive_summary"}),
            },
        );
    }
    drop(store);

    run_ocfleet(&[
        "--database",
        &database_arg,
        "health",
        "policy",
        "set",
        "--unreachable-failures",
        "2",
    ]);
    let output = run_ocfleet(&["--database", &database_arg, "alert", "list", "--json"]);
    let value: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");

    assert_eq!(value["alerts"][0]["reason_code"], "NODE_UNREACHABLE");
    assert_eq!(value["alerts"][0]["summary"]["consecutive_failures"], 2);
    let health = run_ocfleet(&[
        "--database",
        &database_arg,
        "health",
        "node",
        "hk-ocserv-01",
    ]);
    assert!(String::from_utf8_lossy(&health.stdout).contains("status=unreachable"));
}

#[test]
fn health_policy_tests_cert_thresholds_control_alert_severity() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    for (node_id, days_remaining) in [("hk-ocserv-critical", 10), ("hk-ocserv-warning", 45)] {
        add_node(&store, node_id);
        let observed_at = timestamp_minutes_ago(days_remaining);
        insert_observation(
            &store,
            ObservationFixture {
                observation_id: node_id,
                node_id,
                method: OCSERV_CERT_EXPIRY,
                ok: true,
                error_code: None,
                observed_at: &observed_at,
                summary_json: json!({
                    "days_remaining": days_remaining,
                    "status": "valid"
                }),
            },
        );
    }
    drop(store);

    run_ocfleet(&[
        "--database",
        &database_arg,
        "health",
        "policy",
        "set",
        "--cert-warning-days",
        "60",
        "--cert-critical-days",
        "14",
    ]);
    let output = run_ocfleet(&["--database", &database_arg, "alert", "list", "--json"]);
    let value: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    let alerts = value["alerts"].as_array().expect("alerts array");

    let critical = alerts
        .iter()
        .find(|alert| alert["node_id"] == "hk-ocserv-critical")
        .expect("critical cert alert");
    assert_eq!(critical["severity"], "critical");
    assert_eq!(critical["reason_code"], "CERT_EXPIRING_CRITICAL");

    let warning = alerts
        .iter()
        .find(|alert| alert["node_id"] == "hk-ocserv-warning")
        .expect("warning cert alert");
    assert_eq!(warning["severity"], "warning");
    assert_eq!(warning["reason_code"], "CERT_EXPIRING_WARNING");
}

#[test]
fn health_policy_tests_invalid_thresholds_are_rejected_without_db_write_or_audit() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    let before = store.get_health_policy().expect("initial policy");
    let before_audit_count = store.audit_count().expect("initial audit count");
    drop(store);

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "health",
        "policy",
        "set",
        "--stale-window",
        "0s",
    ]);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("stale-window"),
        "stderr should name stale-window: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "health",
        "policy",
        "set",
        "--cert-warning-days",
        "7",
        "--cert-critical-days",
        "30",
    ]);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cert-critical-days"),
        "stderr should name cert-critical-days: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let store = Store::open(&database).expect("reopen store");
    let after = store.get_health_policy().expect("unchanged policy");
    assert_eq!(after, before);
    assert_eq!(
        store.audit_count().expect("audit count"),
        before_audit_count
    );

    let invalid_direct = HealthPolicyRecord {
        stale_window_seconds: 59,
        ..Store::default_health_policy()
    };
    assert!(
        store
            .set_health_policy(&invalid_direct, "policy-user")
            .is_err()
    );
}
