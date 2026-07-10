use ocfleet_cli::audit::AuditEvent;
use ocfleet_cli::store::{NodeInsert, Store};
use ocfleet_protocol::method::{
    NODE_PING, OCSERV_CERT_EXPIRY, OCSERV_SERVICE_SUMMARY, PROBE_CONTROLLER_PING, PROBE_PATH_ECHO,
};
use rusqlite::Connection;
use serde_json::Value;
use std::path::Path;
use std::process::Command;

const TEST_ACTOR: &str = "audit-test";

fn run_ocfleet(args: &[&str]) {
    let output = Command::new(env!("CARGO_BIN_EXE_ocfleet"))
        .args(args)
        .env("USER", "audit-user")
        .output()
        .expect("run ocfleet");
    assert!(
        output.status.success(),
        "ocfleet failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_ocfleet_output(args: &[&str]) -> std::process::Output {
    let output = Command::new(env!("CARGO_BIN_EXE_ocfleet"))
        .args(args)
        .env("USER", "audit-user")
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
        .env("USER", "audit-user")
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

fn latest_audit(database: &Path) -> (String, i64, Value) {
    let conn = Connection::open(database).expect("open db");
    let (event, ok, detail): (String, i64, String) = conn
        .query_row(
            "SELECT event, ok, detail_json FROM controller_audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("latest audit");
    let detail = serde_json::from_str(&detail).expect("parse detail json");
    (event, ok, detail)
}

#[derive(Debug)]
struct LatestRpcAudit {
    event: String,
    actor: String,
    node_id: Option<String>,
    endpoint_id: Option<String>,
    method: Option<String>,
    ok: i64,
    error_code: Option<String>,
    detail: Value,
}

type LatestRpcAuditRow = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
    Option<String>,
    String,
);

fn latest_rpc_audit(database: &Path) -> LatestRpcAudit {
    let conn = Connection::open(database).expect("open db");
    let row: LatestRpcAuditRow = conn
        .query_row(
            "SELECT event, actor, node_id, endpoint_id, method, ok, error_code, detail_json FROM controller_audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .expect("latest rpc audit");
    LatestRpcAudit {
        event: row.0,
        actor: row.1,
        node_id: row.2,
        endpoint_id: row.3,
        method: row.4,
        ok: row.5,
        error_code: row.6,
        detail: serde_json::from_str(&row.7).expect("parse detail json"),
    }
}

#[test]
fn node_list_writes_success_audit_with_node_count() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let endpoint_id = iroh::SecretKey::generate().public().to_string();

    run_ocfleet(&[
        "--database",
        &database_arg,
        "node",
        "add",
        "hk-ocserv-01",
        "--endpoint-id",
        &endpoint_id,
        "--region",
        "hk",
    ]);
    run_ocfleet(&["--database", &database_arg, "node", "list"]);

    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "node.list");
    assert_eq!(ok, 1);
    assert_eq!(detail, serde_json::json!({ "node_count": 1 }));
}

#[test]
fn node_add_rejects_malformed_endpoint_id_without_writing_node() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "node",
        "add",
        "bad-node",
        "--endpoint-id",
        "not-an-endpoint-id",
        "--region",
        "hk",
    ]);

    assert!(String::from_utf8_lossy(&output.stderr).contains("endpoint_id"));
    let store = Store::open(&database).expect("store opens after failed add");
    assert!(
        store
            .get_node("bad-node")
            .expect("query failed node")
            .is_none()
    );
}

#[test]
fn node_add_stores_valid_endpoint_id_as_canonical_string() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let endpoint_id = iroh::SecretKey::generate().public();
    let endpoint_arg = endpoint_id.to_string();

    run_ocfleet(&[
        "--database",
        &database_arg,
        "node",
        "add",
        "hk-ocserv-01",
        "--endpoint-id",
        &endpoint_arg,
        "--region",
        "hk",
    ]);

    let store = Store::open(&database).expect("store opens");
    let node = store
        .get_node("hk-ocserv-01")
        .expect("query node")
        .expect("node inserted");
    assert_eq!(node.endpoint_id, endpoint_id.to_string());
}

#[test]
fn ping_missing_node_writes_failure_audit() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("controller.secret");
    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "ping",
        "missing-node",
    ]);

    assert!(String::from_utf8_lossy(&output.stderr).contains("node not found"));
    let audit = latest_rpc_audit(&database);
    assert_eq!(audit.event, "rpc.completed");
    assert_eq!(audit.actor, "audit-user");
    assert_eq!(audit.node_id.as_deref(), Some("missing-node"));
    assert_eq!(audit.endpoint_id, None);
    assert_eq!(audit.method.as_deref(), Some(NODE_PING));
    assert_eq!(audit.ok, 0);
    assert_eq!(audit.error_code.as_deref(), Some("NODE_NOT_FOUND"));
    assert_eq!(audit.detail["message"], "node not found: missing-node");
}

#[test]
fn ping_disabled_node_writes_failure_audit() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("controller.secret");
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("store opens");
    store
        .add_node(
            &NodeInsert {
                node_id: "hk-ocserv-01".to_string(),
                endpoint_id: endpoint_id.clone(),
                name: "hk-ocserv-01".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            TEST_ACTOR,
        )
        .expect("insert node");
    store
        .disable_node("hk-ocserv-01", TEST_ACTOR)
        .expect("disable node");
    drop(store);

    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();
    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "ping",
        "hk-ocserv-01",
    ]);

    assert!(String::from_utf8_lossy(&output.stderr).contains("node disabled"));
    let audit = latest_rpc_audit(&database);
    assert_eq!(audit.event, "rpc.completed");
    assert_eq!(audit.actor, "audit-user");
    assert_eq!(audit.node_id.as_deref(), Some("hk-ocserv-01"));
    assert_eq!(audit.endpoint_id.as_deref(), Some(endpoint_id.as_str()));
    assert_eq!(audit.method.as_deref(), Some(NODE_PING));
    assert_eq!(audit.ok, 0);
    assert_eq!(audit.error_code.as_deref(), Some("NODE_DISABLED"));
    assert_eq!(audit.detail["message"], "node disabled: hk-ocserv-01");
}

#[test]
fn ping_missing_endpoint_trust_fails_closed_before_key_loading() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("missing-controller.secret");
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("store opens");
    store
        .add_node(
            &NodeInsert {
                node_id: "hk-ocserv-01".to_string(),
                endpoint_id: endpoint_id.clone(),
                name: "hk-ocserv-01".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            TEST_ACTOR,
        )
        .expect("insert node");
    drop(store);
    Connection::open(&database)
        .expect("open db")
        .execute(
            "DELETE FROM endpoint_trust WHERE endpoint_id = ?1",
            [&endpoint_id],
        )
        .expect("remove endpoint trust fixture");

    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();
    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "ping",
        "hk-ocserv-01",
    ]);

    assert!(String::from_utf8_lossy(&output.stderr).contains("endpoint trust missing"));
    assert!(!secret_key.exists());
    let audit = latest_rpc_audit(&database);
    assert_eq!(audit.event, "rpc.completed");
    assert_eq!(audit.node_id.as_deref(), Some("hk-ocserv-01"));
    assert_eq!(audit.endpoint_id.as_deref(), Some(endpoint_id.as_str()));
    assert_eq!(audit.method.as_deref(), Some(NODE_PING));
    assert_eq!(audit.ok, 0);
    assert_eq!(audit.error_code.as_deref(), Some("ENDPOINT_NOT_ALLOWED"));
    assert_eq!(audit.detail["endpoint_trust_state"], "missing");
    assert!(audit.detail.get("endpoint_status").is_none());
}

#[test]
fn ping_unbound_endpoint_trust_fails_closed_before_key_loading() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("missing-controller.secret");
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("store opens");
    store
        .add_node(
            &NodeInsert {
                node_id: "hk-ocserv-01".to_string(),
                endpoint_id: endpoint_id.clone(),
                name: "hk-ocserv-01".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            TEST_ACTOR,
        )
        .expect("insert node");
    drop(store);
    Connection::open(&database)
        .expect("open db")
        .execute(
            "UPDATE endpoint_trust SET node_id = NULL WHERE endpoint_id = ?1",
            [&endpoint_id],
        )
        .expect("unbind endpoint trust fixture");

    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();
    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "ping",
        "hk-ocserv-01",
    ]);

    assert!(String::from_utf8_lossy(&output.stderr).contains("trust is unbound"));
    assert!(!secret_key.exists());
    let audit = latest_rpc_audit(&database);
    assert_eq!(audit.error_code.as_deref(), Some("ENDPOINT_NOT_ALLOWED"));
    assert_eq!(audit.detail["endpoint_trust_state"], "unbound");
    assert_eq!(audit.detail["endpoint_status"], "active");
}

#[test]
fn probe_ping_missing_node_writes_failure_audit() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("controller.secret");
    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "probe",
        "ping",
        "missing-node",
    ]);

    assert!(String::from_utf8_lossy(&output.stderr).contains("node not found"));
    let audit = latest_rpc_audit(&database);
    assert_eq!(audit.event, "rpc.completed");
    assert_eq!(audit.actor, "audit-user");
    assert_eq!(audit.node_id.as_deref(), Some("missing-node"));
    assert_eq!(audit.endpoint_id, None);
    assert_eq!(audit.method.as_deref(), Some(PROBE_CONTROLLER_PING));
    assert_eq!(audit.ok, 0);
    assert_eq!(audit.error_code.as_deref(), Some("NODE_NOT_FOUND"));
    assert_eq!(audit.detail["message"], "node not found: missing-node");
}

#[test]
fn probe_ping_disabled_node_writes_failure_audit() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("controller.secret");
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("store opens");
    store
        .add_node(
            &NodeInsert {
                node_id: "hk-ocserv-01".to_string(),
                endpoint_id: endpoint_id.clone(),
                name: "hk-ocserv-01".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            TEST_ACTOR,
        )
        .expect("insert node");
    store
        .disable_node("hk-ocserv-01", TEST_ACTOR)
        .expect("disable node");
    drop(store);

    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();
    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "probe",
        "ping",
        "hk-ocserv-01",
    ]);

    assert!(String::from_utf8_lossy(&output.stderr).contains("node disabled"));
    let audit = latest_rpc_audit(&database);
    assert_eq!(audit.event, "rpc.completed");
    assert_eq!(audit.actor, "audit-user");
    assert_eq!(audit.node_id.as_deref(), Some("hk-ocserv-01"));
    assert_eq!(audit.endpoint_id.as_deref(), Some(endpoint_id.as_str()));
    assert_eq!(audit.method.as_deref(), Some(PROBE_CONTROLLER_PING));
    assert_eq!(audit.ok, 0);
    assert_eq!(audit.error_code.as_deref(), Some("NODE_DISABLED"));
    assert_eq!(audit.detail["message"], "node disabled: hk-ocserv-01");
}

#[test]
fn ocserv_status_missing_node_writes_command_audit_without_raw_response() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("controller.secret");
    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "ocserv",
        "status",
        "missing-node",
    ]);

    assert!(String::from_utf8_lossy(&output.stderr).contains("node not found"));
    let audit = latest_rpc_audit(&database);
    assert_eq!(audit.event, "ocserv.status");
    assert_eq!(audit.actor, "audit-user");
    assert_eq!(audit.node_id.as_deref(), Some("missing-node"));
    assert_eq!(audit.endpoint_id, None);
    assert_eq!(audit.method.as_deref(), Some(OCSERV_SERVICE_SUMMARY));
    assert_eq!(audit.ok, 0);
    assert_eq!(audit.error_code.as_deref(), Some("NODE_NOT_FOUND"));
    assert_eq!(audit.detail["result_class"], "low_sensitive_summary");
    assert!(audit.detail.get("result").is_none());
}

#[test]
fn ocserv_cert_disabled_node_writes_command_audit_without_certificate_material() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("controller.secret");
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("store opens");
    store
        .add_node(
            &NodeInsert {
                node_id: "hk-ocserv-01".to_string(),
                endpoint_id: endpoint_id.clone(),
                name: "hk-ocserv-01".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            TEST_ACTOR,
        )
        .expect("insert node");
    store
        .disable_node("hk-ocserv-01", TEST_ACTOR)
        .expect("disable node");
    drop(store);

    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();
    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "ocserv",
        "cert",
        "hk-ocserv-01",
    ]);

    assert!(String::from_utf8_lossy(&output.stderr).contains("node disabled"));
    let audit = latest_rpc_audit(&database);
    assert_eq!(audit.event, "ocserv.cert");
    assert_eq!(audit.node_id.as_deref(), Some("hk-ocserv-01"));
    assert_eq!(audit.endpoint_id.as_deref(), Some(endpoint_id.as_str()));
    assert_eq!(audit.method.as_deref(), Some(OCSERV_CERT_EXPIRY));
    assert_eq!(audit.ok, 0);
    assert_eq!(audit.error_code.as_deref(), Some("NODE_DISABLED"));
    let detail_text = audit.detail.to_string();
    assert!(!detail_text.contains("BEGIN CERTIFICATE"));
    assert!(!detail_text.contains("/etc/ocserv"));
}

#[test]
fn probe_path_missing_source_writes_failure_audit() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("controller.secret");
    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "probe",
        "path",
        "missing-source",
        "target-node",
    ]);

    assert!(String::from_utf8_lossy(&output.stderr).contains("node not found"));
    let audit = latest_rpc_audit(&database);
    assert_eq!(audit.event, "rpc.completed");
    assert_eq!(audit.actor, "audit-user");
    assert_eq!(audit.node_id.as_deref(), Some("missing-source"));
    assert_eq!(audit.endpoint_id, None);
    assert_eq!(audit.method.as_deref(), Some(PROBE_PATH_ECHO));
    assert_eq!(audit.ok, 0);
    assert_eq!(audit.error_code.as_deref(), Some("NODE_NOT_FOUND"));
    assert_eq!(audit.detail["source_node_id"], "missing-source");
    assert_eq!(audit.detail["target_node_id"], "target-node");
}

#[test]
fn probe_path_missing_target_writes_failure_audit_on_source_node() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("controller.secret");
    let source_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("store opens");
    store
        .add_node(
            &NodeInsert {
                node_id: "source-node".to_string(),
                endpoint_id: source_endpoint_id.clone(),
                name: "source-node".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            TEST_ACTOR,
        )
        .expect("insert source node");
    drop(store);

    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();
    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "probe",
        "path",
        "source-node",
        "missing-target",
    ]);

    assert!(String::from_utf8_lossy(&output.stderr).contains("node not found"));
    let audit = latest_rpc_audit(&database);
    assert_eq!(audit.event, "rpc.completed");
    assert_eq!(audit.actor, "audit-user");
    assert_eq!(audit.node_id.as_deref(), Some("source-node"));
    assert_eq!(
        audit.endpoint_id.as_deref(),
        Some(source_endpoint_id.as_str())
    );
    assert_eq!(audit.method.as_deref(), Some(PROBE_PATH_ECHO));
    assert_eq!(audit.ok, 0);
    assert_eq!(audit.error_code.as_deref(), Some("NODE_NOT_FOUND"));
    assert_eq!(audit.detail["source_node_id"], "source-node");
    assert_eq!(audit.detail["target_node_id"], "missing-target");
}

#[test]
fn probe_path_missing_target_trust_fails_closed_before_key_loading() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("missing-controller.secret");
    let source_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let target_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("store opens");
    for (node_id, endpoint_id, region) in [
        ("source-node", &source_endpoint_id, "hk"),
        ("target-node", &target_endpoint_id, "sg"),
    ] {
        store
            .add_node(
                &NodeInsert {
                    node_id: node_id.to_string(),
                    endpoint_id: endpoint_id.clone(),
                    name: node_id.to_string(),
                    region: region.to_string(),
                    role: "ocserv".to_string(),
                },
                TEST_ACTOR,
            )
            .expect("insert node");
    }
    drop(store);
    Connection::open(&database)
        .expect("open db")
        .execute(
            "DELETE FROM endpoint_trust WHERE endpoint_id = ?1",
            [&target_endpoint_id],
        )
        .expect("remove target endpoint trust fixture");

    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();
    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "probe",
        "path",
        "source-node",
        "target-node",
    ]);

    assert!(String::from_utf8_lossy(&output.stderr).contains("endpoint trust missing"));
    assert!(!secret_key.exists());
    let audit = latest_rpc_audit(&database);
    assert_eq!(audit.event, "rpc.completed");
    assert_eq!(audit.node_id.as_deref(), Some("source-node"));
    assert_eq!(
        audit.endpoint_id.as_deref(),
        Some(source_endpoint_id.as_str())
    );
    assert_eq!(audit.method.as_deref(), Some(PROBE_PATH_ECHO));
    assert_eq!(audit.ok, 0);
    assert_eq!(audit.error_code.as_deref(), Some("ENDPOINT_NOT_ALLOWED"));
    assert_eq!(audit.detail["target_endpoint_trust_state"], "missing");
    assert!(audit.detail.get("target_endpoint_status").is_none());
}

#[test]
fn probe_path_target_binding_mismatch_fails_closed_before_key_loading() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("missing-controller.secret");
    let source_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let target_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let wrong_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("store opens");
    for (node_id, endpoint_id, region) in [
        ("source-node", &source_endpoint_id, "hk"),
        ("target-node", &target_endpoint_id, "sg"),
        ("wrong-node", &wrong_endpoint_id, "us"),
    ] {
        store
            .add_node(
                &NodeInsert {
                    node_id: node_id.to_string(),
                    endpoint_id: endpoint_id.clone(),
                    name: node_id.to_string(),
                    region: region.to_string(),
                    role: "ocserv".to_string(),
                },
                TEST_ACTOR,
            )
            .expect("insert node");
    }
    drop(store);
    Connection::open(&database)
        .expect("open db")
        .execute(
            "UPDATE endpoint_trust SET node_id = 'wrong-node' WHERE endpoint_id = ?1",
            [&target_endpoint_id],
        )
        .expect("mismatch target endpoint trust fixture");

    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();
    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "probe",
        "path",
        "source-node",
        "target-node",
    ]);

    assert!(String::from_utf8_lossy(&output.stderr).contains("trust binding mismatch"));
    assert!(!secret_key.exists());
    let audit = latest_rpc_audit(&database);
    assert_eq!(audit.error_code.as_deref(), Some("ENDPOINT_NOT_ALLOWED"));
    assert_eq!(
        audit.detail["target_endpoint_trust_state"],
        "binding_mismatch"
    );
    assert_eq!(audit.detail["target_endpoint_status"], "active");
}

#[test]
fn probe_summary_reports_existing_and_disabled_nodes_without_secret_key_or_rpc() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("unused-controller.secret");
    let source_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let target_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("store opens");
    store
        .add_node(
            &NodeInsert {
                node_id: "source-node".to_string(),
                endpoint_id: source_endpoint_id.clone(),
                name: "source-node".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            TEST_ACTOR,
        )
        .expect("insert source node");
    store
        .add_node(
            &NodeInsert {
                node_id: "target-node".to_string(),
                endpoint_id: target_endpoint_id.clone(),
                name: "target-node".to_string(),
                region: "sg".to_string(),
                role: "ocserv".to_string(),
            },
            TEST_ACTOR,
        )
        .expect("insert target node");
    store
        .disable_node("target-node", TEST_ACTOR)
        .expect("disable target");
    drop(store);

    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();
    let output = run_ocfleet_output(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "probe",
        "summary",
        "source-node",
        "target-node",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("probe_summary=path_observation"));
    assert!(stdout.contains("source_node_id=source-node source_status=enabled"));
    assert!(stdout.contains(source_endpoint_id.as_str()));
    assert!(stdout.contains("target_node_id=target-node target_status=disabled"));
    assert!(stdout.contains(target_endpoint_id.as_str()));
    assert!(stdout.contains("registry_authorizes_probe=false"));
    assert!(stdout.contains("required_source_authorization=security.path_probes"));
    assert!(stdout.contains("required_target_authorization=security.peers"));
    assert!(stdout.contains("no_probe_executed=true"));
    assert!(!stdout.contains("SecretKey"));

    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "probe.summary");
    assert_eq!(ok, 1);
    assert_eq!(detail["source_node_id"], "source-node");
    assert_eq!(detail["target_node_id"], "target-node");
    assert_eq!(detail["source_status"], "enabled");
    assert_eq!(detail["target_status"], "disabled");
    assert_eq!(detail["registry_authorizes_probe"], false);
    assert_eq!(detail["no_probe_executed"], true);
}

#[test]
fn probe_summary_reports_missing_nodes_without_failure() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let output = run_ocfleet_output(&[
        "--database",
        &database_arg,
        "probe",
        "summary",
        "missing-source",
        "missing-target",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("source_node_id=missing-source source_status=missing"));
    assert!(stdout.contains("target_node_id=missing-target target_status=missing"));
    assert!(stdout.contains("registry_authorizes_probe=false"));
    assert!(stdout.contains("no_probe_executed=true"));

    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "probe.summary");
    assert_eq!(ok, 1);
    assert_eq!(detail["source_status"], "missing");
    assert_eq!(detail["target_status"], "missing");
}

#[test]
fn probe_summary_reports_disabled_source_without_running_rpc() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("unused-controller.secret");
    let source_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let target_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("store opens");
    store
        .add_node(
            &NodeInsert {
                node_id: "source-node".to_string(),
                endpoint_id: source_endpoint_id,
                name: "source-node".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            TEST_ACTOR,
        )
        .expect("insert source node");
    store
        .add_node(
            &NodeInsert {
                node_id: "target-node".to_string(),
                endpoint_id: target_endpoint_id,
                name: "target-node".to_string(),
                region: "sg".to_string(),
                role: "ocserv".to_string(),
            },
            TEST_ACTOR,
        )
        .expect("insert target node");
    store
        .disable_node("source-node", TEST_ACTOR)
        .expect("disable source");
    drop(store);

    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();
    let output = run_ocfleet_output(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "probe",
        "summary",
        "source-node",
        "target-node",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("source_node_id=source-node source_status=disabled"));
    assert!(stdout.contains("target_node_id=target-node target_status=enabled"));
    assert!(stdout.contains("no_probe_executed=true"));

    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "probe.summary");
    assert_eq!(ok, 1);
    assert_eq!(detail["source_status"], "disabled");
    assert_eq!(detail["target_status"], "enabled");
    assert_eq!(detail["no_probe_executed"], true);
}

#[test]
fn probe_topology_reports_empty_registry_without_secret_key_or_rpc() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("unused-controller.secret");
    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();

    let output = run_ocfleet_output(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "probe",
        "topology",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("topology_summary=registry_observation"));
    assert!(stdout.contains("registered_node_count=0 enabled_node_count=0 disabled_node_count=0"));
    assert!(stdout.contains("registry_authorizes_probe=false"));
    assert!(stdout.contains("topology_discovery=false"));
    assert!(stdout.contains("no_probe_executed=true"));
    assert!(stdout.contains("no_config_generated=true"));
    assert!(!stdout.contains("SecretKey"));

    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "probe.topology");
    assert_eq!(ok, 1);
    assert_eq!(detail["registered_node_count"], 0);
    assert_eq!(detail["enabled_node_count"], 0);
    assert_eq!(detail["disabled_node_count"], 0);
    assert_eq!(detail["registry_authorizes_probe"], false);
    assert_eq!(detail["topology_discovery"], false);
    assert_eq!(detail["no_probe_executed"], true);
}

#[test]
fn probe_topology_reports_region_role_groups_without_claiming_authorization() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("unused-controller.secret");
    let hk_source_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let hk_target_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let sg_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("store opens");
    store
        .add_node(
            &NodeInsert {
                node_id: "hk-source".to_string(),
                endpoint_id: hk_source_endpoint_id,
                name: "hk-source".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            TEST_ACTOR,
        )
        .expect("insert hk source");
    store
        .add_node(
            &NodeInsert {
                node_id: "hk-target".to_string(),
                endpoint_id: hk_target_endpoint_id,
                name: "hk-target".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            TEST_ACTOR,
        )
        .expect("insert hk target");
    store
        .add_node(
            &NodeInsert {
                node_id: "sg-relay-observer".to_string(),
                endpoint_id: sg_endpoint_id,
                name: "sg-relay-observer".to_string(),
                region: "sg".to_string(),
                role: "observer".to_string(),
            },
            TEST_ACTOR,
        )
        .expect("insert sg observer");
    store
        .disable_node("hk-target", TEST_ACTOR)
        .expect("disable target");
    drop(store);

    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();
    let output = run_ocfleet_output(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "probe",
        "topology",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("registered_node_count=3 enabled_node_count=2 disabled_node_count=1"));
    assert!(stdout.contains("group region=hk role=ocserv total=2 enabled=1 disabled=1"));
    assert!(stdout.contains("group region=sg role=observer total=1 enabled=1 disabled=0"));
    assert!(stdout.contains("node_id=hk-source region=hk role=ocserv enabled=true"));
    assert!(stdout.contains("node_id=hk-target region=hk role=ocserv enabled=false"));
    assert!(stdout.contains("registry_potential_pair_count=2"));
    assert!(stdout.contains("registry_authorizes_probe=false"));
    assert!(stdout.contains("authoritative_authorization=security.path_probes+security.peers"));
    assert!(stdout.contains("topology_discovery=false"));
    assert!(stdout.contains("no_probe_executed=true"));
    assert!(stdout.contains("no_config_generated=true"));
    assert!(!stdout.contains("SecretKey"));

    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "probe.topology");
    assert_eq!(ok, 1);
    assert_eq!(detail["registered_node_count"], 3);
    assert_eq!(detail["enabled_node_count"], 2);
    assert_eq!(detail["disabled_node_count"], 1);
    assert_eq!(detail["registry_potential_pair_count"], 2);
    assert_eq!(detail["registry_authorizes_probe"], false);
    assert_eq!(detail["topology_discovery"], false);
    assert_eq!(detail["no_config_generated"], true);
}

#[test]
fn probe_history_reports_empty_existing_audit_without_secret_key_or_rpc() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("unused-controller.secret");
    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();

    let output = run_ocfleet_output(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "probe",
        "history",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("probe_history=controller_audit"));
    assert!(stdout.contains("record_count=0"));
    assert!(stdout.contains("no_probe_executed=true"));
    assert!(stdout.contains("health_score=false"));
    assert!(!stdout.contains("SecretKey"));

    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "probe.history");
    assert_eq!(ok, 1);
    assert_eq!(detail["record_count"], 0);
    assert_eq!(detail["no_probe_executed"], true);
}

#[test]
fn probe_history_reports_probe_rpc_records_and_peer_request_id() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("unused-controller.secret");
    let store = Store::open(&database).expect("store opens");

    let mut ping = AuditEvent::new("seed", "rpc.completed");
    ping.node_id = Some("source-node".to_string());
    ping.endpoint_id = Some("source-endpoint".to_string());
    ping.method = Some(PROBE_CONTROLLER_PING.to_string());
    ping.request_id = Some("root-request-1".to_string());
    ping.ok = Some(true);
    ping.duration_ms = Some(12);
    ping.detail_json = serde_json::json!({"result": "pong"});
    store.insert_audit(&ping).expect("insert ping audit");

    let mut path = AuditEvent::new("seed", "rpc.completed");
    path.node_id = Some("source-node".to_string());
    path.endpoint_id = Some("source-endpoint".to_string());
    path.method = Some(PROBE_PATH_ECHO.to_string());
    path.request_id = Some("root-request-2".to_string());
    path.ok = Some(false);
    path.error_code = Some("ENDPOINT_NOT_ALLOWED".to_string());
    path.duration_ms = Some(34);
    path.detail_json = serde_json::json!({"peer_request_id": "peer-request-2"});
    store.insert_audit(&path).expect("insert path audit");

    let mut node_ping = AuditEvent::new("seed", "rpc.completed");
    node_ping.node_id = Some("source-node".to_string());
    node_ping.method = Some(NODE_PING.to_string());
    node_ping.ok = Some(true);
    store
        .insert_audit(&node_ping)
        .expect("insert non-probe audit");
    drop(store);

    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();
    let output = run_ocfleet_output(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "probe",
        "history",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("record_count=2"));
    assert!(stdout.contains("method=probe.controller.ping ok=true"));
    assert!(stdout.contains("request_id=root-request-1"));
    assert!(stdout.contains("method=probe.path.echo ok=false"));
    assert!(stdout.contains("error_code=ENDPOINT_NOT_ALLOWED"));
    assert!(stdout.contains("peer_request_id=peer-request-2"));
    assert!(!stdout.contains("method=node.ping"));
    assert!(stdout.contains("no_probe_executed=true"));

    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "probe.history");
    assert_eq!(ok, 1);
    assert_eq!(detail["record_count"], 2);
    assert_eq!(detail["node_filter"], serde_json::Value::Null);
    assert_eq!(detail["no_probe_executed"], true);
}

#[test]
fn probe_history_filters_by_node_id() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let store = Store::open(&database).expect("store opens");

    for (node_id, request_id) in [
        ("source-node", "source-request"),
        ("target-node", "target-request"),
    ] {
        let mut event = AuditEvent::new("seed", "rpc.completed");
        event.node_id = Some(node_id.to_string());
        event.method = Some(PROBE_PATH_ECHO.to_string());
        event.request_id = Some(request_id.to_string());
        event.ok = Some(true);
        event.duration_ms = Some(5);
        event.detail_json = serde_json::json!({});
        store.insert_audit(&event).expect("insert probe audit");
    }
    drop(store);

    let database_arg = database.to_string_lossy().into_owned();
    let output = run_ocfleet_output(&[
        "--database",
        &database_arg,
        "probe",
        "history",
        "source-node",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("node_filter=source-node"));
    assert!(stdout.contains("record_count=1"));
    assert!(stdout.contains("request_id=source-request"));
    assert!(!stdout.contains("request_id=target-request"));
}

#[test]
fn probe_observe_reports_registry_status_without_history_or_rpc() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("unused-controller.secret");
    let source_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let target_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("store opens");
    store
        .add_node(
            &NodeInsert {
                node_id: "source-node".to_string(),
                endpoint_id: source_endpoint_id,
                name: "source-node".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            TEST_ACTOR,
        )
        .expect("insert source");
    store
        .add_node(
            &NodeInsert {
                node_id: "target-node".to_string(),
                endpoint_id: target_endpoint_id,
                name: "target-node".to_string(),
                region: "sg".to_string(),
                role: "ocserv".to_string(),
            },
            TEST_ACTOR,
        )
        .expect("insert target");
    drop(store);

    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();
    let output = run_ocfleet_output(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "probe",
        "observe",
        "source-node",
        "target-node",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("path_observation=audit_history"));
    assert!(stdout.contains("source_node_id=source-node source_status=enabled"));
    assert!(stdout.contains("target_node_id=target-node target_status=enabled"));
    assert!(stdout.contains("last_observation=missing"));
    assert!(stdout.contains("no_probe_executed=true"));
    assert!(stdout.contains("no_route_discovery=true"));
    assert!(!stdout.contains("SecretKey"));

    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "probe.observe");
    assert_eq!(ok, 1);
    assert_eq!(detail["source_node_id"], "source-node");
    assert_eq!(detail["target_node_id"], "target-node");
    assert_eq!(detail["last_observation"], "missing");
    assert_eq!(detail["no_probe_executed"], true);
}

#[test]
fn probe_observe_reports_latest_matching_path_result_only() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("unused-controller.secret");
    let source_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let target_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let other_target_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("store opens");
    store
        .add_node(
            &NodeInsert {
                node_id: "source-node".to_string(),
                endpoint_id: source_endpoint_id,
                name: "source-node".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            TEST_ACTOR,
        )
        .expect("insert source");
    store
        .add_node(
            &NodeInsert {
                node_id: "target-node".to_string(),
                endpoint_id: target_endpoint_id.clone(),
                name: "target-node".to_string(),
                region: "sg".to_string(),
                role: "ocserv".to_string(),
            },
            TEST_ACTOR,
        )
        .expect("insert target");

    let mut other_target = AuditEvent::new("seed", "rpc.completed");
    other_target.node_id = Some("source-node".to_string());
    other_target.method = Some(PROBE_PATH_ECHO.to_string());
    other_target.request_id = Some("other-root".to_string());
    other_target.ok = Some(true);
    other_target.duration_ms = Some(10);
    other_target.detail_json = serde_json::json!({
        "target_node_id": "other-target",
        "target_endpoint_id": other_target_endpoint_id,
        "peer_request_id": "other-peer"
    });
    store
        .insert_audit(&other_target)
        .expect("insert other path audit");

    let mut matching = AuditEvent::new("seed", "rpc.completed");
    matching.node_id = Some("source-node".to_string());
    matching.method = Some(PROBE_PATH_ECHO.to_string());
    matching.request_id = Some("matching-root".to_string());
    matching.ok = Some(false);
    matching.error_code = Some("ENDPOINT_NOT_ALLOWED".to_string());
    matching.duration_ms = Some(42);
    matching.detail_json = serde_json::json!({
        "target_node_id": "target-node",
        "target_endpoint_id": target_endpoint_id,
        "peer_request_id": "matching-peer"
    });
    store
        .insert_audit(&matching)
        .expect("insert matching path audit");
    drop(store);

    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();
    let output = run_ocfleet_output(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "probe",
        "observe",
        "source-node",
        "target-node",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("last_observation=found"));
    assert!(stdout.contains("root_request_id=matching-root"));
    assert!(stdout.contains("peer_request_id=matching-peer"));
    assert!(stdout.contains("ok=false"));
    assert!(stdout.contains("error_code=ENDPOINT_NOT_ALLOWED"));
    assert!(stdout.contains("duration_ms=42"));
    assert!(!stdout.contains("other-root"));
    assert!(!stdout.contains("other-peer"));
    assert!(stdout.contains("no_probe_executed=true"));
    assert!(stdout.contains("no_route_discovery=true"));

    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "probe.observe");
    assert_eq!(ok, 1);
    assert_eq!(detail["last_observation"], "found");
    assert_eq!(detail["root_request_id"], "matching-root");
    assert_eq!(detail["peer_request_id"], "matching-peer");
    assert_eq!(detail["error_code"], "ENDPOINT_NOT_ALLOWED");
}

#[cfg(unix)]
#[test]
fn ping_with_unsafe_controller_secret_key_writes_permission_error_audit() {
    use base64::Engine;
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("controller.secret");
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("store opens");
    store
        .add_node(
            &NodeInsert {
                node_id: "hk-ocserv-01".to_string(),
                endpoint_id: endpoint_id.clone(),
                name: "hk-ocserv-01".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            TEST_ACTOR,
        )
        .expect("insert node");
    drop(store);

    let key = iroh::SecretKey::generate();
    let encoded = base64::engine::general_purpose::STANDARD.encode(key.to_bytes());
    std::fs::write(&secret_key, format!("{encoded}\n")).expect("write key");
    std::fs::set_permissions(&secret_key, std::fs::Permissions::from_mode(0o644))
        .expect("chmod key");

    let database_arg = database.to_string_lossy().into_owned();
    let secret_key_arg = secret_key.to_string_lossy().into_owned();
    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "--secret-key",
        &secret_key_arg,
        "ping",
        "hk-ocserv-01",
    ]);

    assert!(String::from_utf8_lossy(&output.stderr).contains("SecretKey"));
    let audit = latest_rpc_audit(&database);
    assert_eq!(audit.event, "rpc.completed");
    assert_eq!(audit.actor, "audit-user");
    assert_eq!(audit.node_id.as_deref(), Some("hk-ocserv-01"));
    assert_eq!(audit.endpoint_id.as_deref(), Some(endpoint_id.as_str()));
    assert_eq!(audit.method.as_deref(), Some(NODE_PING));
    assert_eq!(audit.ok, 0);
    assert_eq!(
        audit.error_code.as_deref(),
        Some("SECRET_KEY_PERMISSION_INVALID")
    );
    assert_eq!(audit.detail["message"], "controller SecretKey unavailable");
    assert_eq!(audit.detail["error_code"], "SECRET_KEY_PERMISSION_INVALID");
    assert!(audit.detail.get("error").is_none());
    assert!(audit.detail.get("details").is_none());
    let detail_text = audit.detail.to_string();
    assert!(!detail_text.contains(secret_key.to_string_lossy().as_ref()));
    assert!(!detail_text.contains("InvalidPermissions"));
}
