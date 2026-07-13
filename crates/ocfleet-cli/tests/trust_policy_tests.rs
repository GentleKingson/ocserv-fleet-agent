use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ocfleet_cli::store::{NodeInsert, Store, StoreError};
use ring::rand::SystemRandom;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
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

fn write_basic_policy(path: &Path, endpoint_a: &str, endpoint_b: &str) {
    fs::write(
        path,
        format!(
            r#"
version = 1

[metadata]
name = "fleet-trust"
revision = "rev-1"

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
"#
        ),
    )
    .expect("write policy");
}

fn write_topology_policy(path: &Path, endpoint_a: &str, endpoint_b: &str, controller: &str) {
    write_basic_policy(path, endpoint_a, endpoint_b);
    let mut policy = fs::read_to_string(path).expect("read basic policy");
    policy.push_str(&format!(
        r#"

[[controllers]]
endpoint_id = "{controller}"
role = "viewer"

[[peers]]
source_node_id = "node-a"
peer_node_id = "node-b"

[[path_probes]]
source_node_id = "node-a"
target_node_id = "node-b"
enabled = true
"#
    ));
    fs::write(path, policy).expect("write topology policy");
}

fn write_topology_yaml(path: &Path, endpoint_a: &str, endpoint_b: &str, controller: &str) {
    fs::write(
        path,
        format!(
            r#"version: 1
metadata:
  name: fleet-trust
  revision: rev-1
nodes:
  - node_id: node-a
    endpoint_id: "{endpoint_a}"
    region: hk
    role: ocserv
    lifecycle: active
    enabled: true
  - node_id: node-b
    endpoint_id: "{endpoint_b}"
    region: sg
    role: ocserv
    lifecycle: active
    enabled: true
controllers:
  - endpoint_id: "{controller}"
    role: viewer
peers:
  - source_node_id: node-a
    peer_node_id: node-b
path_probes:
  - source_node_id: node-a
    target_node_id: node-b
    enabled: true
"#
        ),
    )
    .expect("write YAML policy");
}

fn audit_count(database: &Path) -> i64 {
    Connection::open(database)
        .expect("open db")
        .query_row("SELECT COUNT(*) FROM controller_audit_log", [], |row| {
            row.get(0)
        })
        .expect("audit count")
}

fn write_signing_key(path: &Path) {
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate signing key");
    fs::write(path, key.as_ref()).expect("write signing key");
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod signing key");
}

fn write_reviewer_keyring(path: &Path, key_path: &Path, actor: &str, key_id: &str) {
    let key_bytes = fs::read(key_path).expect("read reviewer signing key");
    let key_pair = Ed25519KeyPair::from_pkcs8(&key_bytes).expect("parse reviewer signing key");
    let keyring = serde_json::json!({
        "schema": "ocfleet.trust_policy.reviewer-keyring.v1",
        "reviewers": [{
            "actor": actor,
            "key_id": key_id,
            "public_key": BASE64.encode(key_pair.public_key().as_ref()),
        }],
    });
    fs::write(path, serde_json::to_vec(&keyring).expect("keyring JSON"))
        .expect("write reviewer keyring");
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod reviewer keyring");
}

fn database_files(database: &Path) -> Vec<(String, String)> {
    [
        database.to_path_buf(),
        Path::new(&format!("{}-wal", database.display())).to_path_buf(),
        Path::new(&format!("{}-shm", database.display())).to_path_buf(),
    ]
    .into_iter()
    .filter(|path| path.exists())
    .map(|path| {
        (
            path.file_name()
                .expect("database filename")
                .to_string_lossy()
                .into_owned(),
            format!(
                "{:x}",
                Sha256::digest(fs::read(&path).expect("read database file"))
            ),
        )
    })
    .collect()
}

#[test]
fn trust_policy_validate_accepts_toml_schema() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let policy = dir.path().join("trust-policy.toml");
    let endpoint_a = iroh::SecretKey::generate().public().to_string();
    let endpoint_b = iroh::SecretKey::generate().public().to_string();
    let controller = iroh::SecretKey::generate().public().to_string();
    write_topology_policy(&policy, &endpoint_a, &endpoint_b, &controller);
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
    assert!(
        !database.exists(),
        "trust policy validate must not create or migrate the database"
    );
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
command = "sensitive-command-value"
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
    assert!(!stderr.contains("sensitive-command-value"));
    assert!(!stderr.contains("command ="));

    let yaml_policy = dir.path().join("trust-policy.yaml");
    fs::write(
        &yaml_policy,
        format!(
            r#"version: 1
nodes:
  - node_id: node-a
    endpoint_id: "{endpoint_a}"
    region: hk
    role: ocserv
    lifecycle: active
    username: sensitive-user-value
"#
        ),
    )
    .expect("write unsafe YAML policy");
    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "trust",
        "policy",
        "validate",
        &yaml_policy.to_string_lossy(),
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed to parse YAML trust policy"));
    assert!(!stderr.contains("sensitive-user-value"));
    assert!(!stderr.contains("username:"));
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
        .add_node(
            &NodeInsert {
                node_id: "node-a".to_string(),
                endpoint_id: endpoint_a.clone(),
                name: "node-a".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            "trust-policy-test",
        )
        .expect("add node a");
    store
        .add_node(
            &NodeInsert {
                node_id: "node-b".to_string(),
                endpoint_id: endpoint_b.clone(),
                name: "node-b".to_string(),
                region: "sg".to_string(),
                role: "ocserv".to_string(),
            },
            "trust-policy-test",
        )
        .expect("add node b");
    drop(store);
    write_basic_policy(&policy, &endpoint_a, &endpoint_b);
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

#[test]
fn trust_policy_diff_writes_markdown_review_summary() {
    let dir = tempfile::tempdir().expect("temp dir");
    #[cfg(unix)]
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
        .expect("chmod temp dir private");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let policy = dir.path().join("trust-policy.toml");
    let output_path = dir.path().join("trust-policy-diff.md");
    let endpoint_a = iroh::SecretKey::generate().public().to_string();
    let endpoint_b = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("open store");
    store
        .add_node(
            &NodeInsert {
                node_id: "node-a".to_string(),
                endpoint_id: endpoint_a.clone(),
                name: "node-a".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            "trust-policy-test",
        )
        .expect("add node a");
    drop(store);
    write_basic_policy(&policy, &endpoint_a, &endpoint_b);
    let before = audit_count(&database);
    let policy_arg = policy.to_string_lossy().into_owned();
    let output_arg = output_path.to_string_lossy().into_owned();

    run_ocfleet(&[
        "--database",
        &database_arg,
        "trust",
        "policy",
        "diff",
        &policy_arg,
        "--format",
        "markdown",
        "--output",
        &output_arg,
    ]);

    let markdown = fs::read_to_string(&output_path).expect("read markdown");
    assert!(markdown.contains("# Trust Policy Diff"));
    assert!(markdown.contains("mode: `review-only`"));
    assert!(markdown.contains("NODE_MISSING_FROM_CONTROLLER"));
    assert!(markdown.contains("| Severity | Code | Node | Endpoint | Field | Desired | Current |"));
    assert!(!markdown.contains("username"));
    assert!(!markdown.contains("client_ip"));
    assert!(markdown.contains("policy: `trust-policy.toml`"));
    assert!(!markdown.contains(&dir.path().to_string_lossy()[..]));
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&output_path)
            .expect("markdown metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(audit_count(&database), before);
}

#[test]
fn trust_policy_toml_and_yaml_validation_are_equivalent() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let toml_policy = dir.path().join("trust-policy.toml");
    let yaml_policy = dir.path().join("trust-policy.yaml");
    let endpoint_a = iroh::SecretKey::generate().public().to_string();
    let endpoint_b = iroh::SecretKey::generate().public().to_string();
    let controller = iroh::SecretKey::generate().public().to_string();
    write_topology_policy(&toml_policy, &endpoint_a, &endpoint_b, &controller);
    write_topology_yaml(&yaml_policy, &endpoint_a, &endpoint_b, &controller);

    let mut toml: Value = serde_json::from_slice(
        &run_ocfleet(&[
            "--database",
            &database_arg,
            "trust",
            "policy",
            "validate",
            &toml_policy.to_string_lossy(),
            "--json",
        ])
        .stdout,
    )
    .expect("TOML validation JSON");
    let mut yaml: Value = serde_json::from_slice(
        &run_ocfleet(&[
            "--database",
            &database_arg,
            "trust",
            "policy",
            "validate",
            &yaml_policy.to_string_lossy(),
            "--json",
        ])
        .stdout,
    )
    .expect("YAML validation JSON");
    toml.as_object_mut()
        .expect("TOML report")
        .remove("generated_at");
    yaml.as_object_mut()
        .expect("YAML report")
        .remove("generated_at");
    assert_eq!(toml, yaml);
}

#[test]
fn trust_policy_rejects_wildcards_duplicates_auto_trust_and_implicit_probe_trust() {
    let endpoint_a = iroh::SecretKey::generate().public().to_string();
    let endpoint_b = iroh::SecretKey::generate().public().to_string();
    let controller = iroh::SecretKey::generate().public().to_string();
    let cases = [
        (
            "wildcard",
            r#"version = 1
[[nodes]]
node_id = "node-a"
endpoint_id = "*"
region = "hk"
role = "ocserv"
lifecycle = "active"
"#
            .to_string(),
            "node endpoint_id",
        ),
        (
            "duplicate-endpoint",
            format!(
                r#"version = 1
[[nodes]]
node_id = "node-a"
endpoint_id = "{endpoint_a}"
region = "hk"
role = "ocserv"
lifecycle = "active"
[[nodes]]
node_id = "node-b"
endpoint_id = "{endpoint_a}"
region = "sg"
role = "ocserv"
lifecycle = "active"
"#
            ),
            "duplicate endpoint_id",
        ),
        (
            "automatic-trust",
            format!(
                r#"version = 1
automatic_trust = true
[[nodes]]
node_id = "node-a"
endpoint_id = "{endpoint_a}"
region = "hk"
role = "ocserv"
lifecycle = "active"
"#
            ),
            "failed to parse TOML trust policy",
        ),
        (
            "implicit-probe-peer",
            format!(
                r#"version = 1
[[nodes]]
node_id = "node-a"
endpoint_id = "{endpoint_a}"
region = "hk"
role = "ocserv"
lifecycle = "active"
[[nodes]]
node_id = "node-b"
endpoint_id = "{endpoint_b}"
region = "sg"
role = "ocserv"
lifecycle = "active"
[[controllers]]
endpoint_id = "{controller}"
role = "viewer"
[[path_probes]]
source_node_id = "node-a"
target_node_id = "node-b"
enabled = true
"#
            ),
            "matching explicit peer entry",
        ),
        (
            "active-quarantine",
            format!(
                r#"version = 1
[[nodes]]
node_id = "node-a"
endpoint_id = "{endpoint_a}"
region = "hk"
role = "ocserv"
lifecycle = "quarantined"
enabled = true
"#
            ),
            "enabled=false",
        ),
    ];

    for (name, body, expected_error) in cases {
        let dir = tempfile::tempdir().expect("temp dir");
        let database = dir.path().join("controller.sqlite");
        let policy = dir.path().join(format!("{name}.toml"));
        fs::write(&policy, body).expect("write invalid policy");
        let output = run_ocfleet_failure(&[
            "--database",
            &database.to_string_lossy(),
            "trust",
            "policy",
            "validate",
            &policy.to_string_lossy(),
        ]);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected_error),
            "{name} did not report {expected_error}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn trust_policy_diff_order_is_deterministic() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let endpoint_a = iroh::SecretKey::generate().public().to_string();
    let endpoint_b = iroh::SecretKey::generate().public().to_string();
    let policy_ab = dir.path().join("ab.toml");
    let policy_ba = dir.path().join("ba.toml");
    write_basic_policy(&policy_ab, &endpoint_a, &endpoint_b);
    fs::write(
        &policy_ba,
        format!(
            r#"version = 1
[[nodes]]
node_id = "node-b"
endpoint_id = "{endpoint_b}"
region = "sg"
role = "ocserv"
lifecycle = "active"
enabled = true
[[nodes]]
node_id = "node-a"
endpoint_id = "{endpoint_a}"
region = "hk"
role = "ocserv"
lifecycle = "active"
enabled = true
"#
        ),
    )
    .expect("write reversed policy");

    let read_diffs = |policy: &Path| {
        let output = run_ocfleet(&[
            "--database",
            &database.to_string_lossy(),
            "trust",
            "policy",
            "diff",
            &policy.to_string_lossy(),
            "--json",
        ]);
        serde_json::from_slice::<Value>(&output.stdout)
            .expect("diff JSON")
            .get("diffs")
            .expect("diff array")
            .clone()
    };
    assert_eq!(read_diffs(&policy_ab), read_diffs(&policy_ba));
}

#[test]
fn trust_policy_diff_reports_controller_peer_and_path_probe_allowlist_drift() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let endpoint_a = iroh::SecretKey::generate().public().to_string();
    let endpoint_b = iroh::SecretKey::generate().public().to_string();
    let controller = iroh::SecretKey::generate().public().to_string();
    let unexpected_controller = iroh::SecretKey::generate().public().to_string();
    let unexpected_peer = iroh::SecretKey::generate().public().to_string();
    let unexpected_target = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("open store");
    for (node_id, endpoint_id, region) in [
        ("node-a", endpoint_a.as_str(), "hk"),
        ("node-b", endpoint_b.as_str(), "sg"),
    ] {
        store
            .add_node(
                &NodeInsert {
                    node_id: node_id.to_string(),
                    endpoint_id: endpoint_id.to_string(),
                    name: node_id.to_string(),
                    region: region.to_string(),
                    role: "ocserv".to_string(),
                },
                "trust-policy-test",
            )
            .expect("add node");
    }
    drop(store);
    Connection::open(&database)
        .expect("open sqlite")
        .execute(
            "UPDATE endpoint_trust SET trust_bundle_json = ?1 WHERE endpoint_id = ?2",
            rusqlite::params![
                serde_json::json!({
                    "schema": "ocfleet.trust.bundle.v1",
                    "endpoint_id": endpoint_a.clone(),
                    "generation": 1,
                    "status": "active",
                    "trusted_controllers": [unexpected_controller.clone()],
                    "trusted_peers": [unexpected_peer],
                    "authorized_path_probes": [[unexpected_controller, unexpected_target]],
                })
                .to_string(),
                endpoint_a,
            ],
        )
        .expect("set drifted trust bundle");
    let policy = dir.path().join("trust-policy.toml");
    write_topology_policy(&policy, &endpoint_a, &endpoint_b, &controller);

    let output = run_ocfleet(&[
        "--database",
        &database.to_string_lossy(),
        "trust",
        "policy",
        "diff",
        &policy.to_string_lossy(),
        "--json",
    ]);
    let value: Value = serde_json::from_slice(&output.stdout).expect("diff JSON");
    let codes = value["diffs"]
        .as_array()
        .expect("diff array")
        .iter()
        .filter_map(|diff| diff["code"].as_str())
        .collect::<Vec<_>>();
    for code in [
        "CONTROLLER_ALLOWLIST_MISSING",
        "CONTROLLER_ALLOWLIST_UNEXPECTED",
        "PEER_ALLOWLIST_MISSING",
        "PEER_ALLOWLIST_UNEXPECTED",
        "PATH_PROBE_MISSING",
        "PATH_PROBE_UNEXPECTED",
    ] {
        assert!(codes.contains(&code), "missing drift code {code}: {value}");
    }
}

#[test]
fn trust_policy_diff_output_is_bounded_and_reports_truncation() {
    let dir = tempfile::tempdir().expect("temp dir");
    #[cfg(unix)]
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod private dir");
    let database = dir.path().join("controller.sqlite");
    let endpoint_a = iroh::SecretKey::generate().public().to_string();
    let endpoint_b = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("open store");
    for (node_id, endpoint_id, region) in [
        ("node-a", endpoint_a.as_str(), "hk"),
        ("node-b", endpoint_b.as_str(), "sg"),
    ] {
        store
            .add_node(
                &NodeInsert {
                    node_id: node_id.to_string(),
                    endpoint_id: endpoint_id.to_string(),
                    name: node_id.to_string(),
                    region: region.to_string(),
                    role: "ocserv".to_string(),
                },
                "trust-policy-test",
            )
            .expect("add node");
    }
    drop(store);
    let unexpected_controllers = (0..520)
        .map(|_| iroh::SecretKey::generate().public().to_string())
        .collect::<Vec<_>>();
    Connection::open(&database)
        .expect("open sqlite")
        .execute(
            "UPDATE endpoint_trust SET trust_bundle_json = ?1 WHERE endpoint_id = ?2",
            rusqlite::params![
                serde_json::json!({
                    "schema": "ocfleet.trust.bundle.v1",
                    "endpoint_id": endpoint_a.clone(),
                    "generation": 1,
                    "status": "active",
                    "trusted_controllers": unexpected_controllers,
                    "trusted_peers": [],
                    "authorized_path_probes": [],
                })
                .to_string(),
                endpoint_a,
            ],
        )
        .expect("set oversized drift set");
    let policy = dir.path().join("trust-policy.toml");
    write_basic_policy(&policy, &endpoint_a, &endpoint_b);

    let output = run_ocfleet(&[
        "--database",
        &database.to_string_lossy(),
        "trust",
        "policy",
        "diff",
        &policy.to_string_lossy(),
        "--json",
    ]);
    let value: Value = serde_json::from_slice(&output.stdout).expect("diff JSON");
    assert_eq!(value["diff_count"], 512);
    assert_eq!(value["total_diff_count"], 520);
    assert_eq!(value["truncated"], true);
    assert_eq!(value["diffs"].as_array().expect("diff array").len(), 512);

    let key = dir.path().join("policy.pk8");
    let signature = dir.path().join("signature.json");
    let public_key = dir.path().join("public-key.json");
    let plan = dir.path().join("plan.json");
    write_signing_key(&key);
    run_ocfleet(&[
        "trust",
        "policy",
        "sign",
        &policy.to_string_lossy(),
        "--key-file",
        &key.to_string_lossy(),
        "--key-id",
        "policy-ci-1",
        "--output",
        &signature.to_string_lossy(),
        "--public-key-output",
        &public_key.to_string_lossy(),
    ]);
    let output = run_ocfleet(&[
        "--database",
        &database.to_string_lossy(),
        "trust",
        "policy",
        "plan",
        &policy.to_string_lossy(),
        "--signature",
        &signature.to_string_lossy(),
        "--public-key",
        &public_key.to_string_lossy(),
        "--output",
        &plan.to_string_lossy(),
        "--json",
    ]);
    let plan: Value = serde_json::from_slice(&output.stdout).expect("plan JSON");
    assert_eq!(plan["change_count"], 512);
    assert_eq!(plan["total_change_count"], 520);
    assert_eq!(plan["truncated"], true);
    assert_eq!(plan["changes"].as_array().unwrap().len(), 512);

    let approval_key = dir.path().join("approval.pk8");
    let reviewer_keyring = dir.path().join("reviewer-keyring.json");
    let approval = dir.path().join("approval.json");
    write_signing_key(&approval_key);
    write_reviewer_keyring(
        &reviewer_keyring,
        &approval_key,
        "security-reviewer",
        "approval-1",
    );
    let rejected = run_ocfleet_failure(&[
        "--actor",
        "security-reviewer",
        "trust",
        "policy",
        "approve",
        &dir.path().join("plan.json").to_string_lossy(),
        "--key-file",
        &approval_key.to_string_lossy(),
        "--key-id",
        "approval-1",
        "--reviewer-keyring",
        &reviewer_keyring.to_string_lossy(),
        "--output",
        &approval.to_string_lossy(),
    ]);
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("truncated"));
    assert!(!approval.exists());
}

#[test]
fn trust_policy_diff_flags_active_state_for_quarantined_policy_endpoint() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let endpoint = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("open store");
    store
        .add_node(
            &NodeInsert {
                node_id: "node-a".to_string(),
                endpoint_id: endpoint.clone(),
                name: "node-a".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            "trust-policy-test",
        )
        .expect("add node");
    drop(store);
    let policy = dir.path().join("trust-policy.toml");
    fs::write(
        &policy,
        format!(
            r#"version = 1
[[nodes]]
node_id = "node-a"
endpoint_id = "{endpoint}"
region = "hk"
role = "ocserv"
lifecycle = "quarantined"
enabled = false
"#
        ),
    )
    .expect("write quarantined policy");

    let output = run_ocfleet(&[
        "--database",
        &database.to_string_lossy(),
        "trust",
        "policy",
        "diff",
        &policy.to_string_lossy(),
        "--json",
    ]);
    let value: Value = serde_json::from_slice(&output.stdout).expect("diff JSON");
    let codes = value["diffs"]
        .as_array()
        .expect("diff array")
        .iter()
        .filter_map(|diff| diff["code"].as_str())
        .collect::<Vec<_>>();
    assert!(codes.contains(&"ENDPOINT_LIFECYCLE_MISMATCH"));
    assert!(codes.contains(&"NODE_ENABLED_MISMATCH"));
}

#[test]
fn trust_policy_diff_does_not_echo_malformed_stored_projection_values() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let endpoint = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("open store");
    store
        .add_node(
            &NodeInsert {
                node_id: "node-a".to_string(),
                endpoint_id: endpoint.clone(),
                name: "node-a".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            "trust-policy-test",
        )
        .expect("add node");
    drop(store);
    Connection::open(&database)
        .expect("open sqlite")
        .execute(
            "UPDATE endpoint_trust SET trust_bundle_json = ?1 WHERE endpoint_id = ?2",
            rusqlite::params![
                r#"{"trusted_controllers":"sensitive-stored-value"}"#,
                endpoint,
            ],
        )
        .expect("set malformed trust bundle");
    let policy = dir.path().join("trust-policy.toml");
    fs::write(
        &policy,
        format!(
            r#"version = 1
[[nodes]]
node_id = "node-a"
endpoint_id = "{endpoint}"
region = "hk"
role = "ocserv"
lifecycle = "active"
"#
        ),
    )
    .expect("write policy");

    let output = run_ocfleet_failure(&[
        "--database",
        &database.to_string_lossy(),
        "trust",
        "policy",
        "diff",
        &policy.to_string_lossy(),
        "--json",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("controller trust bundle projection is invalid"));
    assert!(!stderr.contains("sensitive-stored-value"));
}

#[test]
fn trust_policy_signed_plan_approval_and_history_form_review_only_chain() {
    let dir = tempfile::tempdir().expect("temp dir");
    #[cfg(unix)]
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod private dir");
    let database = dir.path().join("controller.sqlite");
    let endpoint_a = iroh::SecretKey::generate().public().to_string();
    let endpoint_b = iroh::SecretKey::generate().public().to_string();
    let store = Store::open(&database).expect("open store");
    store
        .add_node(
            &NodeInsert {
                node_id: "node-a".to_string(),
                endpoint_id: endpoint_a.clone(),
                name: "node-a".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            "trust-policy-test",
        )
        .expect("add node");
    drop(store);
    let policy = dir.path().join("trust-policy.toml");
    write_basic_policy(&policy, &endpoint_a, &endpoint_b);
    let key = dir.path().join("policy.pk8");
    let signature = dir.path().join("policy.signature.json");
    let public_key = dir.path().join("policy.public-key.json");
    write_signing_key(&key);

    run_ocfleet(&[
        "trust",
        "policy",
        "sign",
        &policy.to_string_lossy(),
        "--key-file",
        &key.to_string_lossy(),
        "--key-id",
        "policy-ci-1",
        "--output",
        &signature.to_string_lossy(),
        "--public-key-output",
        &public_key.to_string_lossy(),
        "--json",
    ]);
    run_ocfleet(&[
        "trust",
        "policy",
        "validate",
        &policy.to_string_lossy(),
        "--signature",
        &signature.to_string_lossy(),
        "--public-key",
        &public_key.to_string_lossy(),
        "--json",
    ]);

    let audit_before = audit_count(&database);
    let before = database_files(&database);
    #[cfg(target_os = "linux")]
    let ci_plan = {
        let artifact_dir = dir.path().join("ci-artifacts");
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("scripts")
            .join("trust-policy-ci-review.sh");
        let output = Command::new("sh")
            .arg(script)
            .args([
                env!("CARGO_BIN_EXE_ocfleet"),
                database.to_str().unwrap(),
                policy.to_str().unwrap(),
                signature.to_str().unwrap(),
                public_key.to_str().unwrap(),
                artifact_dir.to_str().unwrap(),
            ])
            .env("USER", "trust-policy-user")
            .output()
            .expect("run isolated CI review helper");
        assert!(
            output.status.success(),
            "CI helper failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let plan = artifact_dir.join("trust-policy-plan.json");
        let report = artifact_dir.join("trust-policy-review.md");
        assert!(plan.exists());
        assert!(report.exists());
        assert_eq!(
            fs::metadata(&plan).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&report).unwrap().permissions().mode() & 0o777,
            0o600
        );
        plan
    };
    let plan_a = dir.path().join("plan-a.json");
    let plan_b = dir.path().join("plan-b.json");
    let markdown = dir.path().join("review.md");
    for (plan, report) in [(&plan_a, Some(&markdown)), (&plan_b, None)] {
        let mut args = vec![
            "--database",
            database.to_str().expect("database path"),
            "trust",
            "policy",
            "plan",
            policy.to_str().expect("policy path"),
            "--signature",
            signature.to_str().expect("signature path"),
            "--public-key",
            public_key.to_str().expect("public key path"),
            "--output",
            plan.to_str().expect("plan path"),
            "--json",
        ];
        if let Some(report) = report {
            args.extend(["--markdown-output", report.to_str().expect("report path")]);
        }
        run_ocfleet(&args);
    }
    assert_eq!(fs::read(&plan_a).unwrap(), fs::read(&plan_b).unwrap());
    #[cfg(target_os = "linux")]
    assert_eq!(fs::read(&plan_a).unwrap(), fs::read(ci_plan).unwrap());
    assert_eq!(database_files(&database), before);
    assert_eq!(audit_count(&database), audit_before);
    let plan: Value = serde_json::from_slice(&fs::read(&plan_a).unwrap()).unwrap();
    assert_eq!(plan["schema"], "ocfleet.trust_policy.plan.v1");
    assert_eq!(plan["mode"], "review-only");
    assert_eq!(plan["policy_revision"], "rev-1");
    assert_eq!(plan["drift_alert"]["active"], true);
    assert_eq!(plan["drift_alert"]["reason_code"], "TRUST_POLICY_DRIFT");
    assert_eq!(plan["total_change_count"], 2);
    let report = fs::read_to_string(&markdown).unwrap();
    assert!(report.contains("# Trust Policy Review Plan"));
    assert!(report.contains("policy_revision: `rev-1`"));
    assert!(!report.contains(&dir.path().to_string_lossy()[..]));
    #[cfg(unix)]
    for artifact in [&signature, &public_key, &plan_a, &plan_b, &markdown] {
        assert_eq!(
            fs::metadata(artifact).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let approval_key = dir.path().join("approval.pk8");
    let reviewer_keyring = dir.path().join("reviewer-keyring.json");
    let approval_path = dir.path().join("approval.json");
    write_signing_key(&approval_key);
    write_reviewer_keyring(
        &reviewer_keyring,
        &approval_key,
        "security-reviewer",
        "approval-1",
    );
    run_ocfleet(&[
        "--actor",
        "security-reviewer",
        "trust",
        "policy",
        "approve",
        &plan_a.to_string_lossy(),
        "--key-file",
        &approval_key.to_string_lossy(),
        "--key-id",
        "approval-1",
        "--reviewer-keyring",
        &reviewer_keyring.to_string_lossy(),
        "--output",
        &approval_path.to_string_lossy(),
        "--json",
    ]);
    let approval: Value = serde_json::from_slice(&fs::read(&approval_path).unwrap()).unwrap();
    assert_eq!(approval["schema"], "ocfleet.trust_policy.approval.v2");
    assert_eq!(approval["policy_revision"], "rev-1");
    assert_eq!(approval["approver"], "security-reviewer");
    assert!(approval.get("public_key").is_none());
    let payload = format!(
        "ocfleet.trust_policy.approval.v2\n{}\n{}\n{}\n{}\n{}\n",
        approval["policy_revision"].as_str().unwrap(),
        approval["plan_sha256"].as_str().unwrap(),
        approval["approver"].as_str().unwrap(),
        approval["approved_at"].as_str().unwrap(),
        approval["key_id"].as_str().unwrap(),
    );
    UnparsedPublicKey::new(
        &ED25519,
        Ed25519KeyPair::from_pkcs8(&fs::read(&approval_key).unwrap())
            .unwrap()
            .public_key()
            .as_ref(),
    )
    .verify(
        payload.as_bytes(),
        &BASE64
            .decode(approval["signature"].as_str().unwrap())
            .unwrap(),
    )
    .expect("approval signature verifies");

    let attacker_key = dir.path().join("attacker.pk8");
    let attacker_approval = dir.path().join("attacker-approval.json");
    write_signing_key(&attacker_key);
    let rejected = run_ocfleet_failure(&[
        "--actor",
        "security-reviewer",
        "trust",
        "policy",
        "approve",
        &plan_a.to_string_lossy(),
        "--key-file",
        &attacker_key.to_string_lossy(),
        "--key-id",
        "approval-1",
        "--reviewer-keyring",
        &reviewer_keyring.to_string_lossy(),
        "--output",
        &attacker_approval.to_string_lossy(),
    ]);
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("not authorized"));
    assert!(!attacker_approval.exists());

    let attacker_pair =
        Ed25519KeyPair::from_pkcs8(&fs::read(&attacker_key).unwrap()).expect("attacker key");
    let mut forged_approval = approval.clone();
    forged_approval["signature"] =
        Value::String(BASE64.encode(attacker_pair.sign(payload.as_bytes()).as_ref()));
    fs::write(
        &attacker_approval,
        serde_json::to_vec(&forged_approval).unwrap(),
    )
    .unwrap();
    #[cfg(unix)]
    fs::set_permissions(&attacker_approval, fs::Permissions::from_mode(0o600)).unwrap();
    let attacker_history = dir.path().join("attacker-history.jsonl");
    let rejected = run_ocfleet_failure(&[
        "trust",
        "policy",
        "history",
        "record",
        &plan_a.to_string_lossy(),
        "--approval",
        &attacker_approval.to_string_lossy(),
        "--reviewer-keyring",
        &reviewer_keyring.to_string_lossy(),
        "--history",
        &attacker_history.to_string_lossy(),
    ]);
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("verification failed"));
    assert!(!attacker_history.exists());

    let tampered_approval_path = dir.path().join("tampered-approval.json");
    let mut tampered_approval = approval.clone();
    tampered_approval["approver"] = Value::String("different-reviewer".to_string());
    fs::write(
        &tampered_approval_path,
        serde_json::to_vec(&tampered_approval).unwrap(),
    )
    .unwrap();
    #[cfg(unix)]
    fs::set_permissions(&tampered_approval_path, fs::Permissions::from_mode(0o600)).unwrap();
    let rejected_history = dir.path().join("rejected-history.jsonl");
    let rejected = run_ocfleet_failure(&[
        "trust",
        "policy",
        "history",
        "record",
        &plan_a.to_string_lossy(),
        "--approval",
        &tampered_approval_path.to_string_lossy(),
        "--reviewer-keyring",
        &reviewer_keyring.to_string_lossy(),
        "--history",
        &rejected_history.to_string_lossy(),
    ]);
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("not authorized"));
    assert!(!rejected_history.exists());

    let history = dir.path().join("policy-history.jsonl");
    run_ocfleet(&[
        "trust",
        "policy",
        "history",
        "record",
        &plan_a.to_string_lossy(),
        "--approval",
        &approval_path.to_string_lossy(),
        "--reviewer-keyring",
        &reviewer_keyring.to_string_lossy(),
        "--history",
        &history.to_string_lossy(),
        "--json",
    ]);
    let list = run_ocfleet(&[
        "trust",
        "policy",
        "history",
        "list",
        &history.to_string_lossy(),
        "--json",
    ]);
    let entries: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(entries.as_array().unwrap().len(), 1);
    assert_eq!(entries[0]["policy_revision"], "rev-1");
    assert_eq!(entries[0]["approved_by"], "security-reviewer");
    let duplicate = run_ocfleet_failure(&[
        "trust",
        "policy",
        "history",
        "record",
        &plan_a.to_string_lossy(),
        "--approval",
        &approval_path.to_string_lossy(),
        "--reviewer-keyring",
        &reviewer_keyring.to_string_lossy(),
        "--history",
        &history.to_string_lossy(),
    ]);
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already present"));

    let concurrent_history = dir.path().join("concurrent-history.jsonl");
    let mut writers = Vec::new();
    for _ in 0..2 {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ocfleet"));
        command
            .args(["trust", "policy", "history", "record"])
            .arg(&plan_a)
            .arg("--history")
            .arg(&concurrent_history)
            .env("USER", "trust-policy-user")
            .env_remove("OCFLEET_ACTOR");
        writers.push(command.spawn().expect("spawn concurrent history writer"));
    }
    let statuses = writers
        .into_iter()
        .map(|mut child| child.wait().expect("wait for history writer"))
        .collect::<Vec<_>>();
    assert_eq!(statuses.iter().filter(|status| status.success()).count(), 1);
    let concurrent_list = run_ocfleet(&[
        "trust",
        "policy",
        "history",
        "list",
        &concurrent_history.to_string_lossy(),
        "--json",
    ]);
    let concurrent_entries: Value = serde_json::from_slice(&concurrent_list.stdout).unwrap();
    assert_eq!(concurrent_entries.as_array().unwrap().len(), 1);
}

#[test]
fn trust_policy_signature_rejects_policy_tampering() {
    let dir = tempfile::tempdir().expect("temp dir");
    #[cfg(unix)]
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod private dir");
    let policy = dir.path().join("trust-policy.toml");
    let endpoint_a = iroh::SecretKey::generate().public().to_string();
    let endpoint_b = iroh::SecretKey::generate().public().to_string();
    write_basic_policy(&policy, &endpoint_a, &endpoint_b);
    let key = dir.path().join("policy.pk8");
    let signature = dir.path().join("policy.signature.json");
    let public_key = dir.path().join("policy.public-key.json");
    write_signing_key(&key);
    run_ocfleet(&[
        "trust",
        "policy",
        "sign",
        &policy.to_string_lossy(),
        "--key-file",
        &key.to_string_lossy(),
        "--key-id",
        "policy-ci-1",
        "--output",
        &signature.to_string_lossy(),
        "--public-key-output",
        &public_key.to_string_lossy(),
    ]);
    #[cfg(unix)]
    for artifact in [&signature, &public_key] {
        fs::set_permissions(artifact, fs::Permissions::from_mode(0o644)).unwrap();
    }
    run_ocfleet(&[
        "trust",
        "policy",
        "validate",
        &policy.to_string_lossy(),
        "--signature",
        &signature.to_string_lossy(),
        "--public-key",
        &public_key.to_string_lossy(),
    ]);
    let unknown_signature = dir.path().join("unknown.signature.json");
    let mut signature_value: Value =
        serde_json::from_slice(&fs::read(&signature).unwrap()).unwrap();
    signature_value["command"] = Value::String("must-not-be-accepted".to_string());
    fs::write(
        &unknown_signature,
        serde_json::to_vec(&signature_value).unwrap(),
    )
    .unwrap();
    #[cfg(unix)]
    fs::set_permissions(&unknown_signature, fs::Permissions::from_mode(0o600)).unwrap();
    let unknown = run_ocfleet_failure(&[
        "trust",
        "policy",
        "validate",
        &policy.to_string_lossy(),
        "--signature",
        &unknown_signature.to_string_lossy(),
        "--public-key",
        &public_key.to_string_lossy(),
    ]);
    let stderr = String::from_utf8_lossy(&unknown.stderr);
    assert!(stderr.contains("policy signature is invalid"));
    assert!(!stderr.contains("must-not-be-accepted"));
    let tampered = fs::read_to_string(&policy)
        .unwrap()
        .replace("revision = \"rev-1\"", "revision = \"rev-2\"");
    fs::write(&policy, tampered).unwrap();
    let output = run_ocfleet_failure(&[
        "trust",
        "policy",
        "validate",
        &policy.to_string_lossy(),
        "--signature",
        &signature.to_string_lossy(),
        "--public-key",
        &public_key.to_string_lossy(),
    ]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not match"));
}

#[test]
fn trust_policy_plan_on_missing_database_creates_no_controller_state() {
    let dir = tempfile::tempdir().expect("temp dir");
    #[cfg(unix)]
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod private dir");
    let database = dir.path().join("must-not-exist.sqlite");
    let policy = dir.path().join("trust-policy.toml");
    write_basic_policy(
        &policy,
        &iroh::SecretKey::generate().public().to_string(),
        &iroh::SecretKey::generate().public().to_string(),
    );
    let key = dir.path().join("policy.pk8");
    let signature = dir.path().join("signature.json");
    let public_key = dir.path().join("public-key.json");
    let plan = dir.path().join("plan.json");
    write_signing_key(&key);
    run_ocfleet(&[
        "trust",
        "policy",
        "sign",
        &policy.to_string_lossy(),
        "--key-file",
        &key.to_string_lossy(),
        "--key-id",
        "policy-ci-1",
        "--output",
        &signature.to_string_lossy(),
        "--public-key-output",
        &public_key.to_string_lossy(),
    ]);
    run_ocfleet(&[
        "--database",
        &database.to_string_lossy(),
        "trust",
        "policy",
        "plan",
        &policy.to_string_lossy(),
        "--signature",
        &signature.to_string_lossy(),
        "--public-key",
        &public_key.to_string_lossy(),
        "--output",
        &plan.to_string_lossy(),
    ]);
    assert!(!database.exists());
    assert!(!Path::new(&format!("{}-wal", database.display())).exists());
    assert!(!Path::new(&format!("{}-shm", database.display())).exists());
}

#[test]
fn trust_policy_read_only_snapshot_rejects_active_wal_without_checkpointing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let store = Store::open(&database).expect("open store");
    store
        .add_node(
            &NodeInsert {
                node_id: "node-a".to_string(),
                endpoint_id: iroh::SecretKey::generate().public().to_string(),
                name: "node-a".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            "trust-policy-test",
        )
        .expect("add node");
    let before = database_files(&database);
    let error = match Store::open_read_only_policy_snapshot(&database) {
        Ok(_) => panic!("active WAL must fail closed"),
        Err(error) => error,
    };
    assert!(matches!(error, StoreError::ReadOnlySnapshotWalActive));
    assert_eq!(database_files(&database), before);
    drop(store);
}

#[test]
fn trust_policy_review_module_has_no_agent_or_mutation_adapter() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("trust_policy.rs"),
    )
    .expect("read trust policy source");
    for forbidden in [
        "execute_fixed_node_rpc",
        "execute_node_rpc_raw",
        "StoreWriter",
        ".add_node(",
        ".approve_join_request(",
        ".set_endpoint_trust(",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden adapter: {forbidden}"
        );
    }
}
