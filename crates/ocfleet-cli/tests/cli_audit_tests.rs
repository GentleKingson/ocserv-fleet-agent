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

#[test]
fn node_list_writes_success_audit_with_node_count() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    run_ocfleet(&[
        "--database",
        &database_arg,
        "node",
        "add",
        "hk-ocserv-01",
        "--endpoint-id",
        "endpoint-one",
        "--region",
        "hk",
    ]);
    run_ocfleet(&["--database", &database_arg, "node", "list"]);

    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "node.list");
    assert_eq!(ok, 1);
    assert_eq!(detail, serde_json::json!({ "node_count": 1 }));
}
