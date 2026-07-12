use ocfleet_cli::audit::AuditEvent;
use ocfleet_cli::backend::StoreWriter;
use ocfleet_cli::storage_payloads::{HealthDegradedMethodsPayloadV1, HealthSummaryPayloadV1};
use ocfleet_cli::store::{
    HealthSnapshotRecord, HealthSnapshotWrite, NodeInsert, ProbeObservationInsert, Store,
};
use ocfleet_protocol::enrollment::EndpointStatus;
use ocfleet_protocol::method::{
    OCSERV_CERT_EXPIRY, OCSERV_SERVICE_SUMMARY, OCSERV_VERSION, PROBE_CONTROLLER_PING,
};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::Duration as StdDuration;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

fn run_ocfleet(args: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_ocfleet"))
        .args(args)
        .env("USER", "health-user")
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

fn spawn_ocfleet(args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_ocfleet"))
        .args(args)
        .env("USER", "health-user")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ocfleet")
}

fn wait_for_health_evaluation(database: &std::path::Path, timeout: StdDuration) {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        let found = Connection::open(database)
            .and_then(|conn| {
                conn.query_row(
                    "SELECT EXISTS(
                       SELECT 1 FROM health_evaluation_runs WHERE status = 'completed'
                     )",
                    [],
                    |row| row.get::<_, i64>(0),
                )
            })
            .unwrap_or(0);
        if found == 1 {
            return;
        }
        thread::sleep(StdDuration::from_millis(25));
    }
    panic!("timed out waiting for completed health evaluation");
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
            "health-summary-test",
        )
        .expect("add node");
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("format timestamp")
}

fn old_rfc3339() -> String {
    (OffsetDateTime::now_utc() - Duration::days(10))
        .format(&Rfc3339)
        .expect("format timestamp")
}

#[test]
fn health_rollup_refresh_writes_only_closed_buckets_and_replays_idempotently() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let store = Store::open(&database).expect("open store");
    add_node(&store, "refresh-node");
    StoreWriter::write_health_snapshots(
        &store,
        &HealthSnapshotWrite {
            evaluation_id: "health-eval-00000000-0000-4000-8000-000000000777".into(),
            event: "health.summary".into(),
            snapshots: vec![HealthSnapshotRecord {
                node_id: "refresh-node".into(),
                endpoint_id: None,
                computed_at: "2026-07-11T00:02:00Z".into(),
                status: "healthy".into(),
                freshness_seconds: Some(0),
                last_success_at: Some("2026-07-11T00:02:00Z".into()),
                last_failure_at: None,
                last_error_code: None,
                degraded_methods_json: HealthDegradedMethodsPayloadV1::new(vec![])
                    .expect("methods")
                    .to_value(),
                summary_json: HealthSummaryPayloadV1::new(None, None, "healthy".into(), None, None)
                    .expect("summary")
                    .to_value(),
            }],
        },
        "health-refresh-test",
    )
    .expect("write history");
    let audit_before = store.audit_count().expect("audit count");
    drop(store);

    let database_arg = database.to_str().expect("database path");
    let args = [
        "--database",
        database_arg,
        "health",
        "rollup",
        "refresh",
        "--at",
        "2026-07-11T01:02:00Z",
        "--json",
    ];
    let first: Value = serde_json::from_slice(&run_ocfleet(&args).stdout).expect("refresh JSON");
    assert_eq!(first["schema"], "ocfleet.health_rollup_refresh.v1");
    assert_eq!(first["results"][0]["row_count"], 0);
    assert_eq!(first["results"][1]["row_count"], 1);
    assert_eq!(first["results"][2]["row_count"], 0);

    let store = Store::open(&database).expect("reopen store");
    let audit_after_first = store.audit_count().expect("audit count");
    assert_eq!(audit_after_first, audit_before + 1);
    assert_eq!(
        store
            .list_health_rollups(
                Some("refresh-node"),
                3_600,
                "2026-07-11T00:00:00Z",
                "2026-07-11T02:00:00Z",
                10,
            )
            .expect("hourly rollups")
            .len(),
        1
    );
    drop(store);

    let second: Value = serde_json::from_slice(&run_ocfleet(&args).stdout).expect("replay JSON");
    assert_eq!(
        second["results"][1]["operation_id"],
        first["results"][1]["operation_id"]
    );
    let store = Store::open(&database).expect("reopen replayed store");
    assert_eq!(store.audit_count().expect("audit count"), audit_after_first);
    StoreWriter::write_health_snapshots(
        &store,
        &HealthSnapshotWrite {
            evaluation_id: "health-eval-00000000-0000-4000-8000-000000000778".into(),
            event: "health.summary".into(),
            snapshots: vec![HealthSnapshotRecord {
                node_id: "refresh-node".into(),
                endpoint_id: None,
                computed_at: "2026-07-11T00:04:00Z".into(),
                status: "degraded".into(),
                freshness_seconds: Some(0),
                last_success_at: Some("2026-07-11T00:02:00Z".into()),
                last_failure_at: Some("2026-07-11T00:04:00Z".into()),
                last_error_code: Some("RPC_TIMEOUT".into()),
                degraded_methods_json: HealthDegradedMethodsPayloadV1::new(vec![
                    OCSERV_SERVICE_SUMMARY.into(),
                ])
                .expect("methods")
                .to_value(),
                summary_json: HealthSummaryPayloadV1::new(
                    None,
                    None,
                    "degraded".into(),
                    None,
                    None,
                )
                .expect("summary")
                .to_value(),
            }],
        },
        "health-refresh-test",
    )
    .expect("write late history");
    let audit_before_late_refresh = store.audit_count().expect("audit count");
    drop(store);

    let third: Value = serde_json::from_slice(&run_ocfleet(&args).stdout).expect("late refresh");
    assert_ne!(
        third["results"][1]["operation_id"],
        first["results"][1]["operation_id"]
    );
    let store = Store::open(&database).expect("reopen late-refreshed store");
    assert_eq!(
        store.audit_count().expect("audit count"),
        audit_before_late_refresh + 1
    );
    let rows = store
        .list_health_rollups(
            Some("refresh-node"),
            3_600,
            "2026-07-11T00:00:00Z",
            "2026-07-11T02:00:00Z",
            10,
        )
        .expect("late rollup");
    assert_eq!(rows[0].healthy_count, 0);
    assert_eq!(rows[0].degraded_count, 1);
}

#[test]
fn health_rollup_refresh_systemd_units_are_bounded_and_network_isolated() {
    let service = include_str!("../../../deploy/systemd/ocfleet-health-rollup-refresh.service");
    let timer = include_str!("../../../deploy/systemd/ocfleet-health-rollup-refresh.timer");
    assert!(service.contains("PrivateNetwork=true"));
    assert!(service.contains("NoNewPrivileges=true"));
    assert!(service.contains("ProtectSystem=strict"));
    assert!(service.contains("CapabilityBoundingSet="));
    assert!(service.contains("health rollup refresh"));
    assert!(!service.contains("/bin/sh"));
    assert!(!service.contains("curl"));
    assert!(!service.contains("systemctl"));
    assert!(timer.contains("OnCalendar=*:0/5"));
    assert!(timer.contains("Persistent=true"));
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

#[test]
fn health_summary_tests_no_observation_reports_unknown() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    add_node(&store, "hk-ocserv-01");
    drop(store);

    let output = run_ocfleet(&["--database", &database_arg, "health", "summary"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("node_id=hk-ocserv-01"));
    assert!(stdout.contains("status=unknown"));
    assert!(stdout.contains("unknown=1"));
}

#[test]
fn health_summary_tests_disabled_node_reports_disabled() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    add_node(&store, "hk-ocserv-01");
    store
        .disable_node("hk-ocserv-01", "health-summary-test")
        .expect("disable node");
    drop(store);

    let output = run_ocfleet(&["--database", &database_arg, "health", "summary"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("node_id=hk-ocserv-01"));
    assert!(stdout.contains("status=disabled"));
    assert!(stdout.contains("disabled=1"));
}

#[test]
fn health_summary_tests_recent_controller_ping_ok_reports_healthy_without_agent_or_secret() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let secret_arg = dir
        .path()
        .join("missing.secret")
        .to_string_lossy()
        .into_owned();
    let store = Store::open(&database).expect("open store");
    add_node(&store, "hk-ocserv-01");
    let observed_at = now_rfc3339();
    insert_observation(
        &store,
        ObservationFixture {
            observation_id: "obs-ping-ok",
            node_id: "hk-ocserv-01",
            method: PROBE_CONTROLLER_PING,
            ok: true,
            error_code: None,
            observed_at: &observed_at,
            summary_json: json!({"message": "pong"}),
        },
    );
    drop(store);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_arg,
        "health",
        "summary",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("node_id=hk-ocserv-01"));
    assert!(stdout.contains("status=healthy"));
    assert!(stdout.contains("healthy=1"));
}

#[test]
fn health_summary_tests_inactive_endpoint_overrides_recent_success() {
    for (status, expected_code) in [
        (EndpointStatus::Revoked, "ENDPOINT_REVOKED"),
        (EndpointStatus::Quarantined, "ENDPOINT_QUARANTINED"),
        (EndpointStatus::Rotated, "ENDPOINT_ROTATED"),
    ] {
        let dir = tempfile::tempdir().expect("temp dir");
        let database = dir.path().join("controller.sqlite");
        let database_arg = database.to_string_lossy().into_owned();
        let store = Store::open(&database).expect("open store");
        add_node(&store, "hk-ocserv-01");
        let endpoint_id = store
            .get_node("hk-ocserv-01")
            .expect("get node")
            .expect("node exists")
            .endpoint_id;
        // Preserve an enabled legacy registry pointer so this test isolates the
        // health evaluator's inactive-trust precedence rather than lifecycle disablement.
        Connection::open(&database)
            .expect("open database")
            .execute(
                "UPDATE endpoint_trust
                 SET status = ?1,
                     trust_bundle_json = json_set(trust_bundle_json, '$.status', ?1)
                 WHERE endpoint_id = ?2",
                rusqlite::params![status.as_str(), endpoint_id],
            )
            .expect("mark current endpoint inactive");
        let observed_at = now_rfc3339();
        insert_observation(
            &store,
            ObservationFixture {
                observation_id: "obs-ping-ok",
                node_id: "hk-ocserv-01",
                method: PROBE_CONTROLLER_PING,
                ok: true,
                error_code: None,
                observed_at: &observed_at,
                summary_json: json!({"message": "pong"}),
            },
        );
        drop(store);

        let output = run_ocfleet(&["--database", &database_arg, "health", "summary"]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("status=healthy"),
            "inactive {status:?} endpoint must not be healthy: {stdout}"
        );
        assert!(stdout.contains("status=unreachable"));
        assert!(stdout.contains(expected_code));
    }
}

#[test]
fn health_summary_tests_missing_endpoint_trust_fails_closed_without_network_attempt() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let missing_secret_arg = dir
        .path()
        .join("missing.secret")
        .to_string_lossy()
        .into_owned();
    let store = Store::open(&database).expect("open store");
    add_node(&store, "hk-ocserv-01");
    let observed_at = now_rfc3339();
    insert_observation(
        &store,
        ObservationFixture {
            observation_id: "obs-ping-ok",
            node_id: "hk-ocserv-01",
            method: PROBE_CONTROLLER_PING,
            ok: true,
            error_code: None,
            observed_at: &observed_at,
            summary_json: json!({"message": "pong"}),
        },
    );
    drop(store);

    let conn = rusqlite::Connection::open(&database).expect("open db");
    conn.execute(
        "DELETE FROM endpoint_trust WHERE endpoint_id = (SELECT endpoint_id FROM nodes WHERE node_id = ?1)",
        ["hk-ocserv-01"],
    )
    .expect("delete endpoint trust");
    drop(conn);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "--secret-key",
        &missing_secret_arg,
        "health",
        "summary",
        "--json",
    ]);
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid payload");
    let node = payload["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .find(|node| node["node_id"] == "hk-ocserv-01")
        .expect("node health");

    assert_eq!(node["endpoint_status"], Value::Null);
    assert_eq!(node["status"], "unreachable");
    assert_eq!(node["last_error_code"], "ENDPOINT_TRUST_MISSING");
    assert_eq!(payload["summary"]["unreachable"], 1);
}

#[test]
fn health_summary_tests_ocserv_degraded_methods_reports_degraded() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    add_node(&store, "hk-ocserv-01");
    let observed_at = now_rfc3339();
    insert_observation(
        &store,
        ObservationFixture {
            observation_id: "obs-ping-ok",
            node_id: "hk-ocserv-01",
            method: PROBE_CONTROLLER_PING,
            ok: true,
            error_code: None,
            observed_at: &observed_at,
            summary_json: json!({"message": "pong"}),
        },
    );
    insert_observation(
        &store,
        ObservationFixture {
            observation_id: "obs-ocserv-version",
            node_id: "hk-ocserv-01",
            method: OCSERV_VERSION,
            ok: false,
            error_code: Some("OCSERV_PROVIDER_UNAVAILABLE"),
            observed_at: &observed_at,
            summary_json: json!({"degraded_methods": [OCSERV_VERSION]}),
        },
    );
    drop(store);

    let output = run_ocfleet(&["--database", &database_arg, "health", "summary"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("status=degraded"));
    assert!(stdout.contains("degraded=1"));
    assert!(stdout.contains("degraded_methods=ocserv.version"));
}

#[test]
fn health_summary_tests_cert_expiring_status_reports_degraded() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    add_node(&store, "hk-ocserv-01");
    let observed_at = now_rfc3339();
    insert_observation(
        &store,
        ObservationFixture {
            observation_id: "obs-cert-expiring",
            node_id: "hk-ocserv-01",
            method: OCSERV_CERT_EXPIRY,
            ok: true,
            error_code: None,
            observed_at: &observed_at,
            summary_json: json!({
                "result_class": "low_sensitive_summary",
                "cert_count": 1,
                "days_remaining": 3,
                "status": "expiring_soon"
            }),
        },
    );
    drop(store);

    let output = run_ocfleet(&["--database", &database_arg, "health", "summary", "--json"]);
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid payload");
    let node = payload["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .find(|node| node["node_id"] == "hk-ocserv-01")
        .expect("node health");

    assert_eq!(node["status"], "degraded");
    assert!(
        node["degraded_methods"]
            .as_array()
            .expect("degraded methods")
            .iter()
            .any(|method| method == OCSERV_CERT_EXPIRY)
    );
}

#[test]
fn health_summary_tests_one_recent_controller_ping_failure_reports_degraded() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    add_node(&store, "hk-ocserv-01");
    let observed_at = now_rfc3339();
    insert_observation(
        &store,
        ObservationFixture {
            observation_id: "obs-ping-failed",
            node_id: "hk-ocserv-01",
            method: PROBE_CONTROLLER_PING,
            ok: false,
            error_code: Some("RPC_TIMEOUT"),
            observed_at: &observed_at,
            summary_json: json!({"message": "timeout"}),
        },
    );
    drop(store);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "health",
        "node",
        "hk-ocserv-01",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("node_id=hk-ocserv-01"));
    assert!(stdout.contains("status=degraded"));
    assert!(stdout.contains("last_error_code=RPC_TIMEOUT"));
}

#[test]
fn health_summary_tests_old_observation_reports_stale() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    add_node(&store, "hk-ocserv-01");
    let observed_at = old_rfc3339();
    insert_observation(
        &store,
        ObservationFixture {
            observation_id: "obs-old",
            node_id: "hk-ocserv-01",
            method: PROBE_CONTROLLER_PING,
            ok: true,
            error_code: None,
            observed_at: &observed_at,
            summary_json: json!({"message": "pong"}),
        },
    );
    drop(store);

    let output = run_ocfleet(&["--database", &database_arg, "health", "summary"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("node_id=hk-ocserv-01"));
    assert!(stdout.contains("status=stale"));
    assert!(stdout.contains("stale=1"));
}

#[test]
fn health_summary_tests_json_output_is_valid_fixed_schema() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    add_node(&store, "hk-ocserv-01");
    let observed_at = now_rfc3339();
    insert_observation(
        &store,
        ObservationFixture {
            observation_id: "obs-ping-ok",
            node_id: "hk-ocserv-01",
            method: PROBE_CONTROLLER_PING,
            ok: true,
            error_code: None,
            observed_at: &observed_at,
            summary_json: json!({"message": "pong"}),
        },
    );
    insert_observation(
        &store,
        ObservationFixture {
            observation_id: "obs-service",
            node_id: "hk-ocserv-01",
            method: OCSERV_SERVICE_SUMMARY,
            ok: true,
            error_code: None,
            observed_at: &observed_at,
            summary_json: json!({"service_state": "running", "service_enabled": "enabled"}),
        },
    );
    drop(store);

    let output = run_ocfleet(&["--database", &database_arg, "health", "summary", "--json"]);
    let value: Value = serde_json::from_slice(&output.stdout).expect("valid json");

    assert_eq!(value["schema"], "ocfleet.health.v1");
    assert!(value.get("generated_at").is_some());
    assert_eq!(value["summary"]["total"], 1);
    assert!(value["summary"].get("degraded").is_some());
    assert!(value["summary"].get("unreachable").is_some());
    assert!(value["summary"].get("stale").is_some());
    assert!(value["summary"].get("disabled").is_some());
    assert!(value["summary"].get("unknown").is_some());
    assert_eq!(value["summary"]["healthy"], 1);
    assert_eq!(value["nodes"][0]["node_id"], "hk-ocserv-01");
    assert_eq!(value["nodes"][0]["status"], "healthy");
}

#[test]
fn health_summary_tests_snapshot_list_json_reports_latest_per_node_limitation() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    add_node(&store, "hk-ocserv-01");
    let observed_at = now_rfc3339();
    insert_observation(
        &store,
        ObservationFixture {
            observation_id: "obs-ping-ok",
            node_id: "hk-ocserv-01",
            method: PROBE_CONTROLLER_PING,
            ok: true,
            error_code: None,
            observed_at: &observed_at,
            summary_json: json!({"message": "pong"}),
        },
    );
    drop(store);

    let summary = run_ocfleet(&[
        "--database",
        &database_arg,
        "health",
        "node",
        "hk-ocserv-01",
        "--json",
    ]);
    let summary: Value = serde_json::from_slice(&summary.stdout).expect("valid health JSON");
    assert_eq!(summary["schema"], "ocfleet.health.v1");
    assert_eq!(summary["nodes"][0]["status"], "healthy");

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "health",
        "snapshot",
        "list",
        "--limit",
        "10",
        "--json",
    ]);
    let value: Value = serde_json::from_slice(&output.stdout).expect("valid snapshot JSON");
    assert_eq!(value["schema"], "ocfleet.health_snapshots.v1");
    assert_eq!(value["limit"], 10);
    assert_eq!(value["limitation"], "latest_per_node");
    assert_eq!(value["snapshot_count"], 1);
    assert_eq!(value["snapshots"][0]["node_id"], "hk-ocserv-01");
    assert_eq!(value["snapshots"][0]["status"], "healthy");
}

#[test]
fn health_summary_tests_writes_health_audit_without_raw_response_body() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    add_node(&store, "hk-ocserv-01");
    let mut event = AuditEvent::new("health-user", "seed");
    event.detail_json = json!({"ignored": true});
    store.insert_audit(&event).expect("seed audit");
    drop(store);

    run_ocfleet(&["--database", &database_arg, "health", "summary"]);

    let conn = rusqlite::Connection::open(&database).expect("open db");
    let (event, detail): (String, String) = conn
        .query_row(
            "SELECT event, detail_json FROM controller_audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("latest audit");
    let detail: Value = serde_json::from_str(&detail).expect("parse audit detail");
    assert_eq!(event, "health.summary");
    assert_eq!(detail["node_count"], 1);
    assert!(detail.get("nodes").is_none());
    assert!(detail.get("response").is_none());
}

#[test]
fn health_evaluator_run_is_independent_idempotent_and_persists_snapshots() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    add_node(&store, "hk-ocserv-01");
    drop(store);

    let first = run_ocfleet(&[
        "--database",
        &database_arg,
        "health",
        "evaluator",
        "run",
        "--json",
    ]);
    let first: Value = serde_json::from_slice(&first.stdout).expect("valid evaluator JSON");
    assert_eq!(first["schema"], "ocfleet.health_evaluator.v1");
    assert_eq!(first["status"], "completed");

    let second = run_ocfleet(&[
        "--database",
        &database_arg,
        "health",
        "evaluator",
        "run",
        "--json",
    ]);
    let second: Value = serde_json::from_slice(&second.stdout).expect("valid evaluator JSON");
    assert_eq!(second["status"], "replayed");

    let conn = Connection::open(&database).expect("open database");
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM health_evaluation_runs WHERE status = 'completed'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .expect("completed evaluation count"),
        1
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM health_snapshots", [], |row| {
            row.get::<_, i64>(0)
        })
        .expect("snapshot count"),
        1
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM health_history", [], |row| {
            row.get::<_, i64>(0)
        })
        .expect("history count"),
        1,
        "idempotent evaluator replay must not duplicate history"
    );
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM controller_audit_log
             WHERE event IN ('health.evaluation.start', 'health.evaluation.finish')",
            [],
            |row| row.get::<_, i64>(0),
        )
        .expect("evaluator audit count"),
        2
    );
    drop(conn);

    let history = run_ocfleet(&[
        "--database",
        &database_arg,
        "health",
        "history",
        "--from",
        "2020-01-01T00:00:00Z",
        "--to",
        "2030-01-01T00:00:00Z",
        "--node",
        "hk-ocserv-01",
        "--limit",
        "10",
        "--json",
    ]);
    let history: Value = serde_json::from_slice(&history.stdout).expect("valid history JSON");
    assert_eq!(history["schema"], "ocfleet.health_history.v1");
    assert_eq!(history["sample_count"], 1);
    assert_eq!(history["samples"][0]["snapshot"]["node_id"], "hk-ocserv-01");
    let encoded = history.to_string().to_ascii_lowercase();
    for forbidden in ["password", "client_ip", "session_id", "/etc/"] {
        assert!(!encoded.contains(forbidden), "history leaked {forbidden}");
    }
}

#[test]
fn health_evaluator_persists_bounded_failure_without_raw_input() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    add_node(&store, "hk-ocserv-01");
    let observed_at = now_rfc3339();
    insert_observation(
        &store,
        ObservationFixture {
            observation_id: "obs-contaminated",
            node_id: "hk-ocserv-01",
            method: PROBE_CONTROLLER_PING,
            ok: true,
            error_code: None,
            observed_at: &observed_at,
            summary_json: json!({"message": "pong"}),
        },
    );
    drop(store);
    let conn = Connection::open(&database).expect("open database");
    conn.pragma_update(None, "ignore_check_constraints", true)
        .expect("ignore constraints");
    conn.execute(
        "UPDATE probe_observations SET summary_json = '{\"raw\":\"/etc/secret\"}'
         WHERE observation_id = 'obs-contaminated'",
        [],
    )
    .expect("contaminate observation");
    drop(conn);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "health",
        "evaluator",
        "run",
        "--json",
    ]);
    let value: Value = serde_json::from_slice(&output.stdout).expect("valid evaluator JSON");
    assert_eq!(value["status"], "failed");

    let conn = Connection::open(&database).expect("open database");
    let (status, failure_code): (String, Option<String>) = conn
        .query_row(
            "SELECT status, failure_code FROM health_evaluation_runs",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("failed evaluation");
    assert_eq!(status, "failed");
    assert_eq!(failure_code.as_deref(), Some("HEALTH_EVALUATION_FAILED"));
    assert_eq!(
        conn.query_row("SELECT count(*) FROM health_snapshots", [], |row| {
            row.get::<_, i64>(0)
        })
        .expect("snapshot count"),
        0
    );
    let audit_detail: String = conn
        .query_row(
            "SELECT detail_json FROM controller_audit_log
             WHERE event = 'health.evaluation.fail'",
            [],
            |row| row.get(0),
        )
        .expect("failure audit");
    assert!(!audit_detail.contains("/etc/secret"));
    assert!(!audit_detail.contains("raw"));
}

#[cfg(unix)]
#[test]
fn health_evaluator_daemon_drains_on_sigterm_and_restarts_cleanly() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    drop(Store::open(&database).expect("open store"));

    let child = spawn_ocfleet(&[
        "--database",
        &database_arg,
        "health",
        "evaluator",
        "daemon",
        "--interval-seconds",
        "10",
    ]);
    wait_for_health_evaluation(&database, StdDuration::from_secs(30));
    let signal = Command::new("kill")
        .args(["-TERM", child.id().to_string().as_str()])
        .output()
        .expect("signal evaluator daemon");
    assert!(signal.status.success());
    let output = child.wait_with_output().expect("wait for evaluator daemon");
    assert!(
        output.status.success(),
        "daemon failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("status=stopped"));

    let second = spawn_ocfleet(&[
        "--database",
        &database_arg,
        "health",
        "evaluator",
        "daemon",
        "--interval-seconds",
        "10",
    ]);
    thread::sleep(StdDuration::from_millis(500));
    let signal = Command::new("kill")
        .args(["-TERM", second.id().to_string().as_str()])
        .output()
        .expect("signal restarted evaluator daemon");
    assert!(signal.status.success());
    let output = second
        .wait_with_output()
        .expect("wait for restarted daemon");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("status=stopped"));

    let conn = Connection::open(&database).expect("open database");
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM health_evaluation_runs WHERE status = 'running'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .expect("running evaluation count"),
        0
    );
}
