use ocfleet_cli::store::{EnrollmentTokenInsert, JoinRequestInsert, NodeInsert, Store};
use ocfleet_protocol::enrollment::{EndpointStatus, JoinRequestStatus};
use rusqlite::Connection;
use serde_json::Value;
use std::path::Path;
use std::process::Command;

fn run_ocfleet(args: &[&str]) -> std::process::Output {
    let output = Command::new(env!("CARGO_BIN_EXE_ocfleet"))
        .args(args)
        .env("USER", "phase10-user")
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

fn run_ocfleet_failure(args: &[&str]) -> std::process::Output {
    let output = Command::new(env!("CARGO_BIN_EXE_ocfleet"))
        .args(args)
        .env("USER", "phase10-user")
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

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn field<'a>(text: &'a str, name: &str) -> &'a str {
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("missing {name}= in stdout: {text}"))
}

fn latest_audit_event(database: &Path) -> (String, Value) {
    let conn = Connection::open(database).expect("open db");
    let (event, detail): (String, String) = conn
        .query_row(
            "SELECT event, detail_json FROM controller_audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("latest audit");
    (
        event,
        serde_json::from_str(&detail).expect("parse audit detail"),
    )
}

#[test]
fn enroll_token_create_prints_plaintext_once_and_stores_only_hash() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "enroll",
        "token",
        "create",
        "--ttl",
        "24h",
        "--max-uses",
        "1",
        "--description",
        "prod node onboarding",
    ]);
    let text = stdout(&output);
    let token_id = field(&text, "token_id");
    let token = field(&text, "token");

    let store = Store::open(&database).expect("store opens");
    let stored = store
        .get_enrollment_token(token_id)
        .expect("load token")
        .expect("token exists");
    assert_eq!(stored.token_hash, Store::hash_enrollment_token(token));
    assert_ne!(stored.token_hash, token);
    assert_eq!(stored.description.as_deref(), Some("prod node onboarding"));
}

#[test]
fn enroll_approve_activates_pending_join_request() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let token_plaintext = "approval-token";
    let store = Store::open(&database).expect("store opens");
    store
        .create_enrollment_token(
            &EnrollmentTokenInsert {
                token_id: "tok-approve".to_string(),
                token_hash: Store::hash_enrollment_token(token_plaintext),
                created_by: "operator".to_string(),
                expires_at: "2099-01-01T00:00:00Z".to_string(),
                max_uses: 1,
                description: None,
                labels_json: serde_json::json!({}),
                scope_json: serde_json::json!({}),
            },
            "operator",
        )
        .expect("token created");
    let join = store
        .submit_join_request(
            &JoinRequestInsert {
                token_plaintext: token_plaintext.to_string(),
                agent_public_key: "agent-public-key".to_string(),
                fingerprint: "agent-fingerprint".to_string(),
                requested_endpoint_id: None,
                hostname: "hk-ocserv-01".to_string(),
                agent_version: "0.1.0".to_string(),
                requested_labels_json: serde_json::json!({}),
            },
            "agent",
        )
        .expect("join request");
    drop(store);

    run_ocfleet(&[
        "--database",
        &database_arg,
        "enroll",
        "approve",
        &join.request_id,
        "--endpoint-id",
        "endpoint-approved",
        "--reason",
        "ticket-123",
    ]);

    let store = Store::open(&database).expect("store reopens");
    let approved = store
        .get_join_request(&join.request_id)
        .expect("load join")
        .expect("join exists");
    assert_eq!(approved.status, JoinRequestStatus::Approved);
    assert_eq!(
        approved.assigned_endpoint_id.as_deref(),
        Some("endpoint-approved")
    );
    let endpoint = store
        .get_endpoint_trust("endpoint-approved")
        .expect("load endpoint")
        .expect("endpoint exists");
    assert_eq!(endpoint.status, EndpointStatus::Active);
}

#[test]
fn endpoint_lifecycle_commands_write_audit_and_update_registry() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("store opens");
    store
        .add_node(&NodeInsert {
            node_id: "hk-ocserv-01".to_string(),
            endpoint_id: "endpoint-one".to_string(),
            name: "hk-ocserv-01".to_string(),
            region: "hk".to_string(),
            role: "ocserv".to_string(),
        })
        .expect("node added");
    drop(store);

    run_ocfleet(&[
        "--database",
        &database_arg,
        "endpoint",
        "rotate",
        "endpoint-one",
        "--new-endpoint-id",
        "endpoint-two",
        "--reason",
        "key rotation",
    ]);
    run_ocfleet(&[
        "--database",
        &database_arg,
        "endpoint",
        "revoke",
        "endpoint-two",
        "--reason",
        "lost host",
    ]);
    run_ocfleet(&[
        "--database",
        &database_arg,
        "endpoint",
        "quarantine",
        "endpoint-two",
        "--reason",
        "suspicious traffic",
    ]);

    let store = Store::open(&database).expect("store reopens");
    assert_eq!(
        store
            .get_endpoint_trust("endpoint-one")
            .expect("load old")
            .expect("old exists")
            .status,
        EndpointStatus::Rotated
    );
    assert_eq!(
        store
            .get_endpoint_trust("endpoint-two")
            .expect("load new")
            .expect("new exists")
            .status,
        EndpointStatus::Quarantined
    );
    let (event, detail) = latest_audit_event(&database);
    assert_eq!(event, "endpoint.quarantine");
    assert_eq!(detail["reason"], "suspicious traffic");
}

#[test]
fn trust_diff_reports_registry_status_and_strict_fails_on_high_severity_diff() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("store opens");
    store
        .add_node(&NodeInsert {
            node_id: "hk-ocserv-01".to_string(),
            endpoint_id: "endpoint-one".to_string(),
            name: "hk-ocserv-01".to_string(),
            region: "hk".to_string(),
            role: "ocserv".to_string(),
        })
        .expect("node added");
    store
        .revoke_endpoint("endpoint-one", "operator", "lost host")
        .expect("endpoint revoked");
    drop(store);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "trust",
        "diff",
        "--endpoint",
        "endpoint-one",
        "--format",
        "json",
    ]);
    let value: Value = serde_json::from_slice(&output.stdout).expect("trust diff json");
    assert_eq!(value["endpoint_filter"], "endpoint-one");
    assert_eq!(value["diffs"][0]["code"], "REVOKED_PEER_STILL_TRUSTED");

    let strict = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "trust",
        "diff",
        "--endpoint",
        "endpoint-one",
        "--strict",
    ]);
    assert!(stdout(&strict).contains("REVOKED_PEER_STILL_TRUSTED"));
}
