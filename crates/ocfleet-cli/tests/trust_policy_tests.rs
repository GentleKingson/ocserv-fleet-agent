use ocfleet_cli::store::{NodeInsert, Store};
use rusqlite::Connection;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn run_ocfleet(args: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_ocfleet"))
        .args(args)
        .env("USER", "trust-policy-user")
        .env_remove("OCFLEET_ACTOR")
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
        .env("USER", "trust-policy-user")
        .env_remove("OCFLEET_ACTOR")
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

fn write_policy(path: &Path, endpoint_a: &str, endpoint_b: &str) {
    fs::write(
        path,
        format!(
            r#"
version = 1

[[nodes]]
node_id = "node-a"
endpoint_id = "{endpoint_a}"
region = "hk"
role = "ocserv"
lifecycle = "active"
enabled = true

[[nodes]]
node_id = "node-b"
endpoint_id = "{endpoint_b}"
region = "sg"
role = "ocserv"
lifecycle = "active"
enabled = true

[[path_probes]]
source_node_id = "node-a"
target_node_id = "node-b"
enabled = true
"#
        ),
    )
    .expect("write policy");
}

fn audit_count(database: &Path) -> i64 {
    Connection::open(database)
        .expect("open db")
        .query_row("SELECT COUNT(*) FROM controller_audit_log", [], |row| {
            row.get(0)
        })
        .expect("audit count")
}

#[test]
fn trust_policy_validate_accepts_toml_schema() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let policy = dir.path().join("trust-policy.toml");
    let endpoint_a = iroh::SecretKey::generate().public().to_string();
    let endpoint_b = iroh::SecretKey::generate().public().to_string();
    write_policy(&policy, &endpoint_a, &endpoint_b);
    let policy_arg = policy.to_string_lossy().into_owned();

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "trust",
        "policy",
        "validate",
        &policy_arg,
        "--json",
    ]);
    let value: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["status"], "ok");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["node_count"], 2);
    assert_eq!(value["path_probe_count"], 1);
}

#[test]
fn trust_policy_validate_rejects_dangerous_unknown_fields() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let policy = dir.path().join("trust-policy.toml");
    let endpoint_a = iroh::SecretKey::generate().public().to_string();
    fs::write(
        &policy,
        format!(
            r#"
version = 1

[[nodes]]
node_id = "node-a"
endpoint_id = "{endpoint_a}"
region = "hk"
role = "ocserv"
lifecycle = "active"
command = "systemctl restart ocserv"
"#
        ),
    )
    .expect("write policy");
    let policy_arg = policy.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "trust",
        "policy",
        "validate",
        &policy_arg,
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed to parse TOML trust policy"));
    assert!(stderr.contains("unknown field"));
}

#[test]
fn trust_policy_diff_does_not_mutate_controller_state() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let policy = dir.path().join("trust-policy.toml");
    let endpoint_a = iroh::SecretKey::generate().public().to_string();
    let endpoint_b = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("open store");
    store
        .add_node(&NodeInsert {
            node_id: "node-a".to_string(),
            endpoint_id: endpoint_a.clone(),
            name: "node-a".to_string(),
            region: "hk".to_string(),
            role: "ocserv".to_string(),
        })
        .expect("add node a");
    store
        .add_node(&NodeInsert {
            node_id: "node-b".to_string(),
            endpoint_id: endpoint_b.clone(),
            name: "node-b".to_string(),
            region: "sg".to_string(),
            role: "ocserv".to_string(),
        })
        .expect("add node b");
    drop(store);
    write_policy(&policy, &endpoint_a, &endpoint_b);
    let before = audit_count(&database);
    let policy_arg = policy.to_string_lossy().into_owned();

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "trust",
        "policy",
        "diff",
        &policy_arg,
        "--json",
    ]);
    let value: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["status"], "ok");
    assert_eq!(value["diff_count"], 0);
    assert_eq!(audit_count(&database), before);
}
