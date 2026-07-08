use ocfleet_cli::audit::AuditEvent;
use ocfleet_cli::store::{AlertEventRecord, HealthSnapshotRecord, ProbeObservationInsert, Store};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::path::Path;
use std::process::{Command, Output};

fn run_ocfleet(args: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_ocfleet"))
        .args(args)
        .env("USER", "retention-user")
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
        .env("USER", "retention-user")
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

fn insert_observation(store: &Store, observation_id: &str, observed_at: &str) {
    store
        .insert_probe_observation(&ProbeObservationInsert {
            observation_id: observation_id.to_string(),
            run_id: Some("run-1".to_string()),
            node_id: Some("hk-ocserv-01".to_string()),
            endpoint_id: Some("endpoint-1".to_string()),
            method: "probe.controller.ping".to_string(),
            ok: Some(true),
            error_code: None,
            duration_ms: Some(10),
            observed_at: observed_at.to_string(),
            expires_at: None,
            result_class: "controller_rpc_summary".to_string(),
            summary_json: json!({"message": "pong"}),
        })
        .expect("insert observation");
}

fn insert_old_health_and_alert(store: &Store) {
    store
        .upsert_health_snapshot(&HealthSnapshotRecord {
            node_id: "hk-ocserv-01".to_string(),
            endpoint_id: Some("endpoint-1".to_string()),
            computed_at: "2026-01-01T00:00:00Z".to_string(),
            status: "stale".to_string(),
            freshness_seconds: Some(86_400),
            last_success_at: None,
            last_failure_at: Some("2026-01-01T00:00:00Z".to_string()),
            last_error_code: Some("RPC_TIMEOUT".to_string()),
            degraded_methods_json: json!(["probe.controller.ping"]),
            summary_json: json!({"status": "stale"}),
        })
        .expect("insert health snapshot");
    store
        .upsert_alert_event(&AlertEventRecord {
            alert_id: "alert-1".to_string(),
            dedupe_key: "node:hk-ocserv-01".to_string(),
            node_id: Some("hk-ocserv-01".to_string()),
            severity: "warning".to_string(),
            state: "open".to_string(),
            reason_code: "STALE".to_string(),
            first_seen_at: "2026-01-01T00:00:00Z".to_string(),
            last_seen_at: "2026-01-01T00:00:00Z".to_string(),
            last_sent_at: None,
            resolved_at: None,
            detail_json: json!({"status": "stale"}),
        })
        .expect("insert alert");
}

fn audit_count(database: &Path) -> i64 {
    Connection::open(database)
        .expect("open db")
        .query_row("SELECT count(*) FROM controller_audit_log", [], |row| {
            row.get(0)
        })
        .expect("count audit")
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

#[test]
fn retention_tests_show_outputs_default_policies() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let output = run_ocfleet(&["--database", &database_arg, "retention", "show"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("scope=observations"));
    assert!(stdout.contains("max_age_days=30"));
    assert!(stdout.contains("max_rows=100000"));
    assert!(stdout.contains("scope=health-snapshots"));
    assert!(stdout.contains("scope=alert-events"));
    assert!(stdout.contains("max_age_days=180"));
    assert!(stdout.contains("scope=controller_audit_log"));
    assert!(stdout.contains("retention=never"));
}

#[test]
fn retention_tests_set_writes_policy() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    run_ocfleet(&[
        "--database",
        &database_arg,
        "retention",
        "set",
        "observations",
        "--max-age",
        "7d",
        "--max-rows",
        "10",
    ]);

    let store = Store::open(&database).expect("open store");
    let policy = store
        .get_retention_policy("observations")
        .expect("get policy")
        .expect("policy exists");
    assert_eq!(policy.scope, "observations");
    assert_eq!(policy.max_age_days, Some(7));
    assert_eq!(policy.max_rows, Some(10));

    let (event, detail) = latest_audit(&database);
    assert_eq!(event, "retention.set");
    assert_eq!(detail["scope"], "observations");
    assert_eq!(detail["max_age_days"], 7);
    assert_eq!(detail["max_rows"], 10);
}

#[test]
fn retention_tests_apply_dry_run_does_not_delete() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    insert_observation(&store, "obs-old", "2026-01-01T00:00:00Z");
    drop(store);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "retention",
        "apply",
        "--dry-run",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("scope=observations"));
    assert!(stdout.contains("deleted_count=1"));
    assert!(stdout.contains("dry_run=true"));

    let store = Store::open(&database).expect("reopen store");
    assert_eq!(
        store
            .list_probe_observations(None, 10)
            .expect("list observations")
            .len(),
        1
    );
}

#[test]
fn retention_tests_apply_deletes_expired_probe_observations() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    insert_observation(&store, "obs-old", "2026-01-01T00:00:00Z");
    insert_observation(&store, "obs-new", "2026-07-08T00:00:00Z");
    insert_old_health_and_alert(&store);
    drop(store);

    run_ocfleet(&["--database", &database_arg, "retention", "apply"]);

    let store = Store::open(&database).expect("reopen store");
    let observations = store
        .list_probe_observations(None, 10)
        .expect("list observations");
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].observation_id, "obs-new");
}

#[test]
fn retention_tests_apply_does_not_delete_controller_audit_log() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    let mut event = AuditEvent::new("retention-user", "probe.history");
    event.ts = "2026-01-01T00:00:00Z".to_string();
    event.method = Some("probe.controller.ping".to_string());
    event.node_id = Some("hk-ocserv-01".to_string());
    event.ok = Some(true);
    event.detail_json = json!({"message": "legacy audit history"});
    store.insert_audit(&event).expect("insert audit");
    drop(store);
    let before = audit_count(&database);

    run_ocfleet(&["--database", &database_arg, "retention", "apply"]);

    assert!(audit_count(&database) >= before);
    let (event, detail) = latest_audit(&database);
    assert_eq!(event, "retention.apply");
    assert!(detail.get("scope").is_some());
    assert!(detail.get("cutoff").is_some());
    assert!(detail.get("deleted_count").is_some());
    assert!(detail.get("dry_run").is_some());
}

#[test]
fn retention_tests_probe_history_json_outputs_valid_json() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    insert_observation(&store, "obs-json", "2026-07-08T00:00:00Z");
    drop(store);

    let output = run_ocfleet(&["--database", &database_arg, "probe", "history", "--json"]);
    let value: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");

    assert_eq!(value["source"], "probe_observations");
    assert_eq!(value["record_count"], 1);
    assert_eq!(value["records"][0]["observation_id"], "obs-json");
    assert_eq!(value["records"][0]["method"], "probe.controller.ping");
}

#[test]
fn retention_tests_probe_history_rejects_limit_above_1000() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "probe",
        "history",
        "--limit",
        "1001",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--limit must be at most 1000"));
}
