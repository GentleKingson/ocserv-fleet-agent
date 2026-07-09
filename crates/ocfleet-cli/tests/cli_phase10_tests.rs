use ocfleet_cli::store::{EnrollmentTokenInsert, JoinRequestInsert, NodeInsert, Store};
use ocfleet_protocol::enrollment::{EndpointStatus, JoinRequestStatus};
use rusqlite::Connection;
use serde_json::Value;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

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

fn run_ocfleet_with_stdin(args: &[&str], stdin: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ocfleet"))
        .args(args)
        .env("USER", "phase10-user")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ocfleet");
    {
        use std::io::Write;
        let mut child_stdin = child.stdin.take().expect("child stdin");
        child_stdin
            .write_all(stdin.as_bytes())
            .expect("write token stdin");
    }
    let output = child.wait_with_output().expect("wait ocfleet");
    assert!(
        output.status.success(),
        "ocfleet failed: stdout={} stderr={}",
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

    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    run_ocfleet(&[
        "--database",
        &database_arg,
        "enroll",
        "approve",
        &join.request_id,
        "--endpoint-id",
        &endpoint_id,
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
        Some(endpoint_id.as_str())
    );
    let endpoint = store
        .get_endpoint_trust(&endpoint_id)
        .expect("load endpoint")
        .expect("endpoint exists");
    assert_eq!(endpoint.status, EndpointStatus::Active);
}

#[test]
fn enroll_request_create_reads_token_from_file_and_stdin() {
    for source in ["file", "stdin"] {
        let dir = tempfile::tempdir().expect("temp dir");
        let database = dir.path().join(format!("{source}.sqlite"));
        let database_arg = database.to_string_lossy().into_owned();
        let token_plaintext = format!("request-token-{source}");
        let store = Store::open(&database).expect("store opens");
        store
            .create_enrollment_token(
                &EnrollmentTokenInsert {
                    token_id: format!("tok-request-{source}"),
                    token_hash: Store::hash_enrollment_token(&token_plaintext),
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
        drop(store);

        let token_file = dir.path().join("token.txt");
        let token_file_arg = token_file.to_string_lossy().into_owned();
        let mut args = vec![
            "--database",
            database_arg.as_str(),
            "enroll",
            "request",
            "create",
        ];
        let output = if source == "file" {
            std::fs::write(&token_file, format!("{token_plaintext}\n")).expect("write token file");
            #[cfg(unix)]
            fs::set_permissions(&token_file, fs::Permissions::from_mode(0o600))
                .expect("chmod token file");
            args.extend(["--token-file", token_file_arg.as_str()]);
            args.extend([
                "--agent-public-key",
                "agent-public-key",
                "--fingerprint",
                "agent-fingerprint",
                "--hostname",
                "hk-ocserv-01",
                "--agent-version",
                "0.1.0",
            ]);
            run_ocfleet(&args)
        } else {
            args.extend(["--token-stdin"]);
            args.extend([
                "--agent-public-key",
                "agent-public-key",
                "--fingerprint",
                "agent-fingerprint",
                "--hostname",
                "hk-ocserv-01",
                "--agent-version",
                "0.1.0",
            ]);
            run_ocfleet_with_stdin(&args, &format!("{token_plaintext}\n"))
        };

        let text = stdout(&output);
        assert_eq!(field(&text, "status"), "pending");

        let store = Store::open(&database).expect("store reopens");
        let token = store
            .get_enrollment_token(&format!("tok-request-{source}"))
            .expect("load token")
            .expect("token exists");
        assert_eq!(token.used_count, 1);
    }
}

#[test]
#[cfg(unix)]
fn enroll_request_create_rejects_unsafe_or_oversized_token_files() {
    for fixture in ["world-readable", "symlink", "hardlink", "oversized"] {
        let dir = tempfile::tempdir().expect("temp dir");
        let database = dir.path().join("controller.sqlite");
        let database_arg = database.to_string_lossy().into_owned();
        let source = dir.path().join("token.source");
        fs::write(
            &source,
            if fixture == "oversized" {
                "x".repeat(513)
            } else {
                "token".into()
            },
        )
        .expect("write token fixture");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("chmod source");
        let token_file = match fixture {
            "world-readable" => {
                fs::set_permissions(&source, fs::Permissions::from_mode(0o644))
                    .expect("chmod unsafe source");
                source.clone()
            }
            "symlink" => {
                let path = dir.path().join("token.link");
                std::os::unix::fs::symlink(&source, &path).expect("create symlink");
                path
            }
            "hardlink" => {
                let path = dir.path().join("token.hardlink");
                fs::hard_link(&source, &path).expect("create hardlink");
                path
            }
            "oversized" => source.clone(),
            _ => unreachable!(),
        };
        let token_file_arg = token_file.to_string_lossy().into_owned();

        let output = run_ocfleet_failure(&[
            "--database",
            &database_arg,
            "enroll",
            "request",
            "create",
            "--token-file",
            &token_file_arg,
            "--agent-public-key",
            "agent-public-key",
            "--fingerprint",
            "agent-fingerprint",
            "--hostname",
            "hk-ocserv-01",
            "--agent-version",
            "0.1.0",
        ]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("private enrollment token file")
                || stderr.contains("exceeds 512 bytes"),
            "unexpected error for {fixture}: {stderr}"
        );
    }
}

#[test]
fn enroll_approve_rejects_endpoint_mismatch_when_request_named_endpoint() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let token_plaintext = "approval-bound-token";
    let requested_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let different_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("store opens");
    store
        .create_enrollment_token(
            &EnrollmentTokenInsert {
                token_id: "tok-approve-bound".to_string(),
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
                requested_endpoint_id: Some(requested_endpoint_id.clone()),
                hostname: "hk-ocserv-01".to_string(),
                agent_version: "0.1.0".to_string(),
                requested_labels_json: serde_json::json!({}),
            },
            "agent",
        )
        .expect("join request");
    drop(store);

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "enroll",
        "approve",
        &join.request_id,
        "--endpoint-id",
        &different_endpoint_id,
        "--reason",
        "ticket-123",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requested_endpoint_id"));

    let store = Store::open(&database).expect("store reopens");
    assert!(
        store
            .get_endpoint_trust(&different_endpoint_id)
            .expect("query endpoint")
            .is_none()
    );
}

#[test]
fn enroll_approve_rejects_non_canonical_endpoint_id() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let token_plaintext = "approval-invalid-token";
    let store = Store::open(&database).expect("store opens");
    store
        .create_enrollment_token(
            &EnrollmentTokenInsert {
                token_id: "tok-approve-invalid".to_string(),
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

    let output = run_ocfleet_failure(&[
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
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("endpoint_id"));

    let store = Store::open(&database).expect("store reopens");
    assert!(
        store
            .get_endpoint_trust("endpoint-approved")
            .expect("query endpoint")
            .is_none()
    );
}

#[test]
fn enroll_request_create_rejects_control_characters_in_agent_fields() {
    for (hostname, agent_version) in [
        ("hk-ocserv-01\nadmin", "0.1.0"),
        ("hk-ocserv-01", "\x1b[31m0.1.0"),
    ] {
        let dir = tempfile::tempdir().expect("temp dir");
        let database = dir.path().join("controller.sqlite");
        let database_arg = database.to_string_lossy().into_owned();
        let token_plaintext = "request-token";
        let store = Store::open(&database).expect("store opens");
        store
            .create_enrollment_token(
                &EnrollmentTokenInsert {
                    token_id: "tok-request".to_string(),
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
        drop(store);

        let output = run_ocfleet_failure(&[
            "--database",
            &database_arg,
            "enroll",
            "request",
            "create",
            "--token",
            token_plaintext,
            "--agent-public-key",
            "agent-public-key",
            "--fingerprint",
            "agent-fingerprint",
            "--hostname",
            hostname,
            "--agent-version",
            agent_version,
        ]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("hostname") || stderr.contains("agent_version"),
            "stderr did not name rejected field: {stderr}"
        );
    }
}

#[test]
fn endpoint_lifecycle_commands_write_audit_and_update_registry() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("store opens");
    let endpoint_one = iroh::SecretKey::generate().public().to_string();
    let endpoint_two = iroh::SecretKey::generate().public().to_string();
    store
        .add_node(&NodeInsert {
            node_id: "hk-ocserv-01".to_string(),
            endpoint_id: endpoint_one.clone(),
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
        &endpoint_one,
        "--new-endpoint-id",
        &endpoint_two,
        "--reason",
        "key rotation",
    ]);
    run_ocfleet(&[
        "--database",
        &database_arg,
        "endpoint",
        "revoke",
        &endpoint_two,
        "--reason",
        "lost host",
    ]);
    run_ocfleet(&[
        "--database",
        &database_arg,
        "endpoint",
        "quarantine",
        &endpoint_two,
        "--reason",
        "suspicious traffic",
    ]);

    let store = Store::open(&database).expect("store reopens");
    assert_eq!(
        store
            .get_endpoint_trust(&endpoint_one)
            .expect("load old")
            .expect("old exists")
            .status,
        EndpointStatus::Rotated
    );
    assert_eq!(
        store
            .get_endpoint_trust(&endpoint_two)
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
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    store
        .add_node(&NodeInsert {
            node_id: "hk-ocserv-01".to_string(),
            endpoint_id: endpoint_id.clone(),
            name: "hk-ocserv-01".to_string(),
            region: "hk".to_string(),
            role: "ocserv".to_string(),
        })
        .expect("node added");
    store
        .revoke_endpoint(&endpoint_id, "operator", "lost host")
        .expect("endpoint revoked");
    drop(store);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "trust",
        "diff",
        "--endpoint",
        &endpoint_id,
        "--format",
        "json",
    ]);
    let value: Value = serde_json::from_slice(&output.stdout).expect("trust diff json");
    assert_eq!(value["endpoint_filter"], endpoint_id);
    assert_eq!(value["diffs"][0]["code"], "REVOKED_PEER_STILL_TRUSTED");

    let strict = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "trust",
        "diff",
        "--endpoint",
        &endpoint_id,
        "--strict",
    ]);
    assert!(stdout(&strict).contains("REVOKED_PEER_STILL_TRUSTED"));
}
