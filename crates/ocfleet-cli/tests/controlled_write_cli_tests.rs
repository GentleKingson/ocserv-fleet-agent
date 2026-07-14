#![cfg(feature = "controlled-writes")]

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

#[test]
fn controlled_write_cli_completes_dry_run_approval_and_audit_without_dispatch() {
    let directory = tempfile::tempdir().expect("tempdir");
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private tempdir");
    let database = directory.path().join("controller.sqlite");
    let intent_path = directory.path().join("intent.json");
    let keyring_path = directory.path().join("trusted-keys.toml");
    let signature_path = directory.path().join("intent.sig");
    let policy_path = directory.path().join("policy.toml");
    let request_id = Uuid::new_v4().to_string();
    let expires_at = (OffsetDateTime::now_utc() + Duration::hours(2))
        .format(&Rfc3339)
        .expect("expiry");
    write_private(
        &intent_path,
        &serde_json::to_string_pretty(&json!({
            "request_id": request_id,
            "operation_id": format!("op:{}", Uuid::new_v4()),
            "operation_kind": "ocserv_reload",
            "endpoint_id": iroh::SecretKey::generate().public().to_string(),
            "reason": "Reviewed reload dry run",
            "change_ticket": "CHG-1234",
            "nonce": format!("nonce:{}", Uuid::new_v4()),
            "expires_at": expires_at,
            "params_summary": {"schema": "ocfleet.reload.v1"}
        }))
        .expect("intent JSON"),
    );

    let digest_output = run(
        &database,
        "operator-a",
        ["change", "digest", "--intent", path(&intent_path), "--json"],
    );
    let digest: Value = serde_json::from_slice(&digest_output).expect("digest JSON");
    let digest = digest["payload_sha256"].as_str().expect("digest");
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate key");
    let key = Ed25519KeyPair::from_pkcs8(key.as_ref()).expect("parse key");
    write_private(
        &keyring_path,
        &format!(
            "[[keys]]\nkey_id = \"operator-key\"\npublic_key_base64 = {:?}\nallowed_actors = [\"operator-a\"]\n",
            base64::engine::general_purpose::STANDARD.encode(key.public_key().as_ref())
        ),
    );
    write_private(
        &signature_path,
        &base64::engine::general_purpose::STANDARD.encode(key.sign(digest.as_bytes()).as_ref()),
    );
    write_private(
        &policy_path,
        "enabled = true\nallowed_operations = [\"ocserv_reload\"]\n",
    );

    let create = run(
        &database,
        "operator-a",
        [
            "change",
            "create",
            "--intent",
            path(&intent_path),
            "--trusted-keyring",
            path(&keyring_path),
            "--key-id",
            "operator-key",
            "--signature-file",
            path(&signature_path),
            "--json",
        ],
    );
    assert_eq!(parse_state(&create), "draft");
    let dry_run = run(
        &database,
        "operator-a",
        [
            "change",
            "dry-run",
            &request_id,
            "--policy-file",
            path(&policy_path),
            "--json",
        ],
    );
    assert_eq!(parse_state(&dry_run), "dry_run_succeeded");
    let approval_expiry = (OffsetDateTime::now_utc() + Duration::hours(1))
        .format(&Rfc3339)
        .expect("approval expiry");
    let approved = run(
        &database,
        "operator-b",
        [
            "change",
            "approve",
            &request_id,
            "--approval-id",
            "approval-1",
            "--role",
            "change-approver",
            "--reason",
            "Reviewed exact endpoint",
            "--expires-at",
            &approval_expiry,
            "--json",
        ],
    );
    let approved: Value = serde_json::from_slice(&approved).expect("approved JSON");
    assert_eq!(approved["request"]["state"], "approved");
    assert_eq!(approved["dispatch_available"], false);

    let audit = run(
        &database,
        "auditor-a",
        ["change", "audit", &request_id, "--json"],
    );
    let audit: Value = serde_json::from_slice(&audit).expect("audit JSON");
    assert_eq!(audit["count"], 3);
    let audit_text = audit.to_string();
    assert!(!audit_text.contains("signature"));
    assert!(!audit_text.contains("nonce"));
    for forbidden in ["dispatch", "reload", "restart", "apply"] {
        let output = Command::new(env!("CARGO_BIN_EXE_ocfleet"))
            .args(["--database", path(&database), "change", forbidden])
            .output()
            .expect("run forbidden command");
        assert!(!output.status.success());
    }
}

fn run<const N: usize>(database: &std::path::Path, actor: &str, args: [&str; N]) -> Vec<u8> {
    let output = Command::new(env!("CARGO_BIN_EXE_ocfleet"))
        .args(["--database", path(database), "--actor", actor])
        .args(args)
        .output()
        .expect("run ocfleet");
    assert!(
        output.status.success(),
        "ocfleet failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn parse_state(output: &[u8]) -> String {
    let value: Value = serde_json::from_slice(output).expect("record JSON");
    value["request"]["state"]
        .as_str()
        .expect("state")
        .to_string()
}

fn write_private(path: &std::path::Path, text: &str) {
    fs::write(path, text).expect("write private fixture");
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private fixture mode");
}

fn path(path: &std::path::Path) -> &str {
    path.to_str().expect("UTF-8 path")
}
