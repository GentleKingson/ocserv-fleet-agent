use ocfleet_cli::store::{ProbeObservationInsert, Store};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::process::{Command, Output};

fn run_ocfleet(args: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_ocfleet"))
        .args(args)
        .env("USER", "observation-user")
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
        .env("USER", "observation-user")
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

fn seed_observation(store: &Store, observation_id: &str) {
    store
        .insert_probe_observation(&ProbeObservationInsert {
            observation_id: observation_id.to_string(),
            run_id: None,
            node_id: Some("hk-ocserv-01".to_string()),
            endpoint_id: Some("endpoint-1".to_string()),
            method: "probe.controller.ping".to_string(),
            ok: Some(false),
            error_code: Some("RPC_TIMEOUT".to_string()),
            duration_ms: Some(25),
            observed_at: "2026-07-08T00:00:00Z".to_string(),
            expires_at: None,
            result_class: "controller_rpc_summary".to_string(),
            summary_json: json!({
                "result_class": "controller_rpc_summary",
                "message": "pong"
            }),
        })
        .expect("seed observation");
}

fn assert_no_forbidden_observation_payload(value: &Value) {
    let text = value.to_string();
    for forbidden in [
        "raw_body",
        "username",
        "alice",
        "client_ip",
        "10.0.0.2",
        "session_id",
        "session-secret",
        "/etc/passwd",
    ] {
        assert!(
            !text.contains(forbidden),
            "forbidden observation payload value present: {forbidden}"
        );
    }
}

#[test]
fn observation_tests_list_and_show_safe_summary_and_filter() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    seed_observation(&store, "obs-safe-1");
    drop(store);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "observation",
        "list",
        "--node",
        "hk-ocserv-01",
        "--method",
        "probe.controller.ping",
        "--limit",
        "10",
        "--json",
    ]);
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(payload["limit"], 10);
    assert_eq!(payload["observation_count"], 1);
    assert_eq!(payload["observations"][0]["observation_id"], "obs-safe-1");
    assert_eq!(payload["observations"][0]["summary"]["message"], "pong");
    assert_no_forbidden_observation_payload(&payload);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "observation",
        "show",
        "obs-safe-1",
        "--json",
    ]);
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(payload["observation"]["observation_id"], "obs-safe-1");
    assert_eq!(payload["observation"]["summary"]["message"], "pong");
    assert_no_forbidden_observation_payload(&payload);
}

#[test]
fn observation_tests_fail_closed_on_contaminated_stored_summary() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    seed_observation(&store, "obs-contaminated-1");
    drop(store);
    Connection::open(&database)
        .expect("open fixture database")
        .execute(
            "UPDATE probe_observations SET summary_json = ?1 WHERE observation_id = ?2",
            rusqlite::params![
                json!({"client_address": "10.0.0.2"}).to_string(),
                "obs-contaminated-1"
            ],
        )
        .expect("seed contaminated summary");

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "observation",
        "list",
        "--limit",
        "10",
        "--json",
    ]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("observation summary"));
}

#[test]
fn observation_tests_limit_is_capped() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "observation",
        "list",
        "--limit",
        "1001",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--limit must be between 1 and 1000"));
}
