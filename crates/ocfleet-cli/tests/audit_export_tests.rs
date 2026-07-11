use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ocfleet_cli::audit::AuditEvent;
use ocfleet_cli::store::Store;
use ring::rand::SystemRandom;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

fn run_ocfleet(args: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_ocfleet"))
        .args(args)
        .env("USER", "audit-export-user")
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
        .env("USER", "audit-export-user")
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

fn seed_audit(store: &Store, _database: &Path, id: usize, ts: &str) {
    let mut event = AuditEvent::new(format!("operator-{id}@example.test"), "probe.history");
    event.ts = ts.to_string();
    event.node_id = Some(format!("node-{id}"));
    event.endpoint_id = Some(format!("endpoint-{id}"));
    event.method = Some("probe.controller.ping".to_string());
    event.request_id = Some(format!("request-{id}"));
    event.params_hash = Some("sha256:abcdef".to_string());
    event.ok = Some(true);
    event.duration_ms = Some(12);
    event.detail_json = json!({"message": "safe summary"});
    store.insert_audit(&event).expect("insert audit");
}

fn exported_lines(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .expect("read export")
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid jsonl row"))
        .collect()
}

fn latest_audit(database: &Path) -> (String, i64, Value) {
    let (event, ok, detail): (String, i64, String) = Connection::open(database)
        .expect("open db")
        .query_row(
            "SELECT event, ok, detail_json FROM controller_audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("latest audit");
    (
        event,
        ok,
        serde_json::from_str(&detail).expect("parse detail json"),
    )
}

#[test]
#[cfg(unix)]
fn audit_export_tests_writes_jsonl_checksum_and_audit_not_included() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_path = dir.path().join("exports").join("audit.jsonl");
    let output_arg = output_path.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    seed_audit(&store, &database, 1, "2026-07-09T00:00:00Z");
    drop(store);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "audit",
        "export",
        "--from",
        "2026-07-08T00:00:00Z",
        "--to",
        "2026-07-10T00:00:00Z",
        "--format",
        "jsonl",
        "--output",
        &output_arg,
        "--include-checksum",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("status=ok"));
    assert!(stdout.contains("row_count=1"));

    let lines = exported_lines(&output_path);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["event"], "probe.history");
    assert_ne!(lines[0]["event"], "audit.export");

    let checksum_path = output_path.with_extension("jsonl.sha256");
    let checksum = fs::read_to_string(&checksum_path).expect("read checksum");
    let digest = Sha256::digest(fs::read(&output_path).expect("read output"));
    let expected = format!("{digest:x}");
    assert!(checksum.starts_with(&expected));

    let output_mode = fs::metadata(&output_path)
        .expect("output metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(output_mode, 0o600);
    let parent_mode = fs::metadata(output_path.parent().expect("parent"))
        .expect("parent metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(parent_mode, 0o700);

    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "audit.export");
    assert_eq!(ok, 1);
    assert_eq!(detail["row_count"], 1);
    assert_eq!(detail["checksum"], expected);
    assert!(detail.get("output_path_hash").is_some());
    assert!(detail.get("output").is_none());
}

#[test]
#[cfg(unix)]
fn audit_export_tests_writes_ed25519_signature_without_secret_leak() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_path = dir.path().join("exports").join("audit.jsonl");
    let output_arg = output_path.to_string_lossy().into_owned();
    let key_path = dir.path().join("audit-signing-key.pk8");
    let key_arg = key_path.to_string_lossy().into_owned();
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate key");
    fs::write(&key_path, pkcs8.as_ref()).expect("write signing key");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("chmod signing key");
    let store = Store::open(&database).expect("open store");
    seed_audit(&store, &database, 9, "2026-07-09T00:00:00Z");
    drop(store);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "audit",
        "export",
        "--from",
        "2026-07-08T00:00:00Z",
        "--to",
        "2026-07-10T00:00:00Z",
        "--output",
        &output_arg,
        "--sign-with-key-file",
        &key_arg,
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("signature_algorithm=Ed25519"));

    let signature_path = output_path.with_extension("jsonl.sig");
    let sidecar: Value =
        serde_json::from_str(&fs::read_to_string(&signature_path).expect("read signature"))
            .expect("signature json");
    assert_eq!(sidecar["schema"], "ocfleet.audit_export.signature.v1");
    assert_eq!(sidecar["algorithm"], "Ed25519");
    let public_key = BASE64
        .decode(sidecar["public_key"].as_str().expect("public key"))
        .expect("decode public key");
    let signature = BASE64
        .decode(sidecar["signature"].as_str().expect("signature"))
        .expect("decode signature");
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&fs::read(&output_path).expect("read export"), &signature)
        .expect("signature verifies");

    let exported_text = fs::read_to_string(&output_path).expect("read export text");
    let sidecar_text = fs::read_to_string(&signature_path).expect("read sidecar text");
    let private_key_marker = BASE64.encode(pkcs8.as_ref());
    assert!(!exported_text.contains(&private_key_marker));
    assert!(!sidecar_text.contains(&private_key_marker));
    assert!(!exported_text.contains("private-key-value"));

    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "audit.export");
    assert_eq!(ok, 1);
    assert_eq!(detail["signature_algorithm"], "Ed25519");
    assert!(detail.get("signing_key").is_none());
    assert!(detail.get("signature_public_key_fingerprint").is_some());
}

#[test]
#[cfg(unix)]
fn audit_export_tests_rejects_invalid_window() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_path = dir.path().join("exports").join("audit.jsonl");
    let output_arg = output_path.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "audit",
        "export",
        "--from",
        "2026-07-10T00:00:00Z",
        "--to",
        "2026-07-10T00:00:00Z",
        "--output",
        &output_arg,
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--from must be before --to"));
    assert!(!output_path.exists());
}

#[test]
#[cfg(unix)]
fn audit_export_tests_rejects_window_over_maximum() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_path = dir.path().join("exports").join("audit.jsonl");
    let output_arg = output_path.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "audit",
        "export",
        "--from",
        "2026-01-01T00:00:00Z",
        "--to",
        "2026-04-15T00:00:00Z",
        "--output",
        &output_arg,
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("audit export window must be at most"));
    assert!(!output_path.exists());
}

#[test]
#[cfg(unix)]
fn audit_export_tests_rejects_rows_over_max_rows() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_path = dir.path().join("exports").join("audit.jsonl");
    let output_arg = output_path.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    seed_audit(&store, &database, 1, "2026-07-09T00:00:00Z");
    seed_audit(&store, &database, 2, "2026-07-09T00:01:00Z");
    drop(store);

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "audit",
        "export",
        "--from",
        "2026-07-08T00:00:00Z",
        "--to",
        "2026-07-10T00:00:00Z",
        "--output",
        &output_arg,
        "--max-rows",
        "1",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("audit export row count exceeds --max-rows"));
    assert!(!output_path.exists());
    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "audit.export");
    assert_eq!(ok, 0);
    assert_eq!(detail["error_code"], "AUDIT_EXPORT_TOO_MANY_ROWS");
}

#[test]
#[cfg(unix)]
fn audit_export_tests_default_redaction_exports_only_typed_safe_detail() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_path = dir.path().join("exports").join("audit.jsonl");
    let output_arg = output_path.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    seed_audit(&store, &database, 1, "2026-07-09T00:00:00Z");
    drop(store);

    run_ocfleet(&[
        "--database",
        &database_arg,
        "audit",
        "export",
        "--from",
        "2026-07-08T00:00:00Z",
        "--to",
        "2026-07-10T00:00:00Z",
        "--output",
        &output_arg,
        "--redact",
        "default",
    ]);

    let row = exported_lines(&output_path).remove(0);
    assert_eq!(row["detail"]["message"], "<redacted>");
    assert!(row["detail"].get("_audit").is_none());
}

#[test]
#[cfg(unix)]
fn audit_export_tests_none_redaction_keeps_identifiers_but_still_redacts_secret_like_fields() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_path = dir.path().join("exports").join("audit.jsonl");
    let output_arg = output_path.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    seed_audit(&store, &database, 3, "2026-07-09T00:00:00Z");
    drop(store);

    run_ocfleet(&[
        "--database",
        &database_arg,
        "audit",
        "export",
        "--from",
        "2026-07-08T00:00:00Z",
        "--to",
        "2026-07-10T00:00:00Z",
        "--output",
        &output_arg,
        "--redact",
        "none",
    ]);

    let row = exported_lines(&output_path).remove(0);
    assert_eq!(row["actor"], "operator-3@example.test");
    assert_eq!(row["node_id"], "node-3");
    assert_eq!(row["endpoint_id"], "endpoint-3");
    assert_eq!(row["request_id"], "request-3");
    assert_eq!(row["detail"]["message"], "<redacted>");
    assert!(row["detail"].get("_audit").is_none());
}

#[test]
#[cfg(unix)]
fn audit_export_tests_fails_closed_on_contaminated_storage() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_path = dir.path().join("exports").join("audit.jsonl");
    let output_arg = output_path.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    drop(store);
    Connection::open(&database)
        .expect("open contaminated fixture")
        .execute(
            "INSERT INTO controller_audit_log
             (ts, actor, event, method, params_hash, ok, error_code, detail_json)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, '{}')",
            rusqlite::params![
                "2026-07-09T00:00:00Z/etc/passwd",
                "alice\nadmin",
                "shell exec /etc/passwd",
                "shell.exec",
                "/etc/ocserv.conf",
                "client_ip=10.0.0.2"
            ],
        )
        .expect("insert contaminated audit row");

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "audit",
        "export",
        "--from",
        "2026-07-08T00:00:00Z",
        "--to",
        "2026-07-10T00:00:00Z",
        "--output",
        &output_arg,
        "--redact",
        "none",
    ]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("audit detail payload is not closed v1 data"));
    assert!(!output_path.exists());
}

#[test]
#[cfg(unix)]
fn audit_export_tests_strict_redaction_hides_identifiers() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_path = dir.path().join("exports").join("audit.jsonl");
    let output_arg = output_path.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    seed_audit(&store, &database, 7, "2026-07-09T00:00:00Z");
    drop(store);

    run_ocfleet(&[
        "--database",
        &database_arg,
        "audit",
        "export",
        "--from",
        "2026-07-08T00:00:00Z",
        "--to",
        "2026-07-10T00:00:00Z",
        "--output",
        &output_arg,
        "--redact",
        "strict",
    ]);

    let row = exported_lines(&output_path).remove(0);
    assert_ne!(row["actor"], "operator-7@example.test");
    assert_ne!(row["node_id"], "node-7");
    assert_ne!(row["endpoint_id"], "endpoint-7");
    assert_ne!(row["request_id"], "request-7");
    assert!(
        row["node_id"]
            .as_str()
            .expect("node hash")
            .starts_with("sha256:")
    );
}

#[test]
#[cfg(unix)]
fn audit_export_tests_rejects_output_symlink() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_dir = dir.path().join("exports");
    fs::create_dir(&output_dir).expect("create output dir");
    fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o700)).expect("chmod dir");
    let target = output_dir.join("target.jsonl");
    fs::write(&target, "").expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("chmod target");
    let output_path = output_dir.join("audit.jsonl");
    std::os::unix::fs::symlink(&target, &output_path).expect("symlink");
    let output_arg = output_path.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "audit",
        "export",
        "--from",
        "2026-07-08T00:00:00Z",
        "--to",
        "2026-07-10T00:00:00Z",
        "--output",
        &output_arg,
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("audit export failed"));
}

#[test]
#[cfg(unix)]
fn audit_export_tests_rejects_world_writable_output_parent() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_dir = dir.path().join("exports");
    fs::create_dir(&output_dir).expect("create output dir");
    fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o777)).expect("chmod dir");
    let output_path = output_dir.join("audit.jsonl");
    let output_arg = output_path.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "audit",
        "export",
        "--from",
        "2026-07-08T00:00:00Z",
        "--to",
        "2026-07-10T00:00:00Z",
        "--output",
        &output_arg,
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("audit export failed"));
    assert!(!output_path.exists());
}

#[test]
#[cfg(unix)]
fn audit_export_tests_rejects_existing_output_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let output_dir = dir.path().join("exports");
    fs::create_dir(&output_dir).expect("create output dir");
    fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o700)).expect("chmod dir");
    let output_path = output_dir.join("audit.jsonl");
    fs::write(&output_path, "").expect("existing");
    fs::set_permissions(&output_path, fs::Permissions::from_mode(0o600)).expect("chmod file");
    let output_arg = output_path.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "audit",
        "export",
        "--from",
        "2026-07-08T00:00:00Z",
        "--to",
        "2026-07-10T00:00:00Z",
        "--output",
        &output_arg,
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("audit export failed"));
}
