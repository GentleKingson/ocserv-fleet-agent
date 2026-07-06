use ocfleet_cli::store::{NodeInsert, Store};
use ocfleet_protocol::method::{NODE_PING, PROBE_CONTROLLER_PING, PROBE_PATH_ECHO};
use rusqlite::Connection;
use serde_json::Value;
use std::path::Path;
use std::process::Command;

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
        .add_node(&NodeInsert {
            node_id: "hk-ocserv-01".to_string(),
            endpoint_id: endpoint_id.clone(),
            name: "hk-ocserv-01".to_string(),
            region: "hk".to_string(),
            role: "ocserv".to_string(),
        })
        .expect("insert node");
    store.disable_node("hk-ocserv-01").expect("disable node");
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
        .add_node(&NodeInsert {
            node_id: "hk-ocserv-01".to_string(),
            endpoint_id: endpoint_id.clone(),
            name: "hk-ocserv-01".to_string(),
            region: "hk".to_string(),
            role: "ocserv".to_string(),
        })
        .expect("insert node");
    store.disable_node("hk-ocserv-01").expect("disable node");
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
        .add_node(&NodeInsert {
            node_id: "source-node".to_string(),
            endpoint_id: source_endpoint_id.clone(),
            name: "source-node".to_string(),
            region: "hk".to_string(),
            role: "ocserv".to_string(),
        })
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
fn probe_summary_reports_existing_and_disabled_nodes_without_secret_key_or_rpc() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("unused-controller.secret");
    let source_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let target_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("store opens");
    store
        .add_node(&NodeInsert {
            node_id: "source-node".to_string(),
            endpoint_id: source_endpoint_id.clone(),
            name: "source-node".to_string(),
            region: "hk".to_string(),
            role: "ocserv".to_string(),
        })
        .expect("insert source node");
    store
        .add_node(&NodeInsert {
            node_id: "target-node".to_string(),
            endpoint_id: target_endpoint_id.clone(),
            name: "target-node".to_string(),
            region: "sg".to_string(),
            role: "ocserv".to_string(),
        })
        .expect("insert target node");
    store.disable_node("target-node").expect("disable target");
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
        .add_node(&NodeInsert {
            node_id: "source-node".to_string(),
            endpoint_id: source_endpoint_id,
            name: "source-node".to_string(),
            region: "hk".to_string(),
            role: "ocserv".to_string(),
        })
        .expect("insert source node");
    store
        .add_node(&NodeInsert {
            node_id: "target-node".to_string(),
            endpoint_id: target_endpoint_id,
            name: "target-node".to_string(),
            region: "sg".to_string(),
            role: "ocserv".to_string(),
        })
        .expect("insert target node");
    store.disable_node("source-node").expect("disable source");
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
        .add_node(&NodeInsert {
            node_id: "hk-ocserv-01".to_string(),
            endpoint_id: endpoint_id.clone(),
            name: "hk-ocserv-01".to_string(),
            region: "hk".to_string(),
            role: "ocserv".to_string(),
        })
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
}
