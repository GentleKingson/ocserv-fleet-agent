use ocfleet_cli::store::{NodeInsert, Store};
use rusqlite::Connection;
use serde_json::Value;
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
