use ocfleet_cli::audit::AuditEvent;
use ocfleet_cli::store::{NodeInsert, ProbeObservationInsert, Store};
use ocfleet_protocol::enrollment::EndpointStatus;
use ocfleet_protocol::method::{
    OCSERV_CERT_EXPIRY, OCSERV_SERVICE_SUMMARY, OCSERV_VERSION, PROBE_CONTROLLER_PING,
};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::process::{Command, Output};
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
                "UPDATE endpoint_trust SET status = ?1 WHERE endpoint_id = ?2",
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
            summary_json: json!({"service": {"state": "running", "enabled": "enabled"}}),
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
