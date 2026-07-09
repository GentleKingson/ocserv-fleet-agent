#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

use ocfleet_agent::ocserv::{CollectorSnapshotOcservReadonlyProvider, OcservReadonlyProvider};
use serde_json::Value;
use tempfile::TempDir;

fn collector_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ocfleet-ocserv-collector"))
}

#[test]
fn collector_prints_example_config_without_forbidden_sources() {
    let output = Command::new(collector_bin())
        .arg("--print-example-config")
        .output()
        .expect("run collector");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(text.contains("service_identity = \"ocserv\""));
    for forbidden in [
        "systemctl",
        "journalctl",
        "occtl",
        "script",
        "username",
        "client_ip",
        "session_id",
    ] {
        assert!(
            !text.to_ascii_lowercase().contains(forbidden),
            "example config must not mention forbidden source: {forbidden}"
        );
    }

    let source = include_str!("../src/bin/ocfleet-ocserv-collector.rs");
    for forbidden_api in ["std::process::Command", "Command::new(", ".spawn("] {
        assert!(
            !source.contains(forbidden_api),
            "collector must not execute local commands via {forbidden_api}"
        );
    }
}

#[test]
fn collector_writes_snapshot_v2_that_agent_provider_can_read() {
    let dir = private_tempdir();
    let output_path = dir.path().join("ocserv-snapshot.json");
    let config_path = dir.path().join("collector.toml");
    let collected_at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("format timestamp");
    write_private(
        &config_path,
        &format!(
            r#"
service_identity = "ocserv"
output_path = {}
collected_at = {}
collector_status = "ok"
service_state = "running"
enabled_state = "enabled"
version = "ocserv 1.3.0"
session_total = 7
auth_failure_count_rolling = 2
connection_failure_count_rolling = 3
cert_min_days_remaining = 42
config_fingerprint_short = "abcdef12"
"#,
            toml_string(&output_path),
            serde_json::to_string(&collected_at).expect("quote timestamp")
        ),
    );

    let output = Command::new(collector_bin())
        .arg("--config")
        .arg(&config_path)
        .arg("--output")
        .arg(&output_path)
        .output()
        .expect("run collector");
    assert_success(&output);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&output_path.to_string_lossy()[..]));

    let snapshot: Value =
        serde_json::from_slice(&fs::read(&output_path).expect("read snapshot")).expect("json");
    assert_eq!(snapshot["schema_version"], "ocfleet.ocserv.snapshot.v2");
    assert_eq!(snapshot["collected_at"], collected_at);
    assert_eq!(snapshot["collector_status"], "ok");
    assert_eq!(snapshot["service_state"], "running");
    assert_eq!(snapshot["enabled_state"], "enabled");
    assert_eq!(snapshot["session_total"], 7);

    let snapshot_text = serde_json::to_string(&snapshot).expect("json text");
    for forbidden in [
        "username",
        "account",
        "client_ip",
        "assigned_vpn_ip",
        "source_address",
        "destination_address",
        "source_port",
        "destination_port",
        "session_id",
        "cookie",
        "token",
        "raw_config",
        "raw_logs",
        "stdout",
        "stderr",
        "systemctl",
        "journalctl",
        "occtl",
        "subject",
        "san",
        "issuer",
        "serial",
        "pem",
        "private_key",
        "journal_selector",
        "script",
    ] {
        assert!(
            !snapshot_text.to_ascii_lowercase().contains(forbidden),
            "snapshot must not emit forbidden marker: {forbidden}"
        );
    }

    assert_eq!(
        fs::metadata(&output_path)
            .expect("snapshot metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let provider = CollectorSnapshotOcservReadonlyProvider::new(output_path);
    let service = provider.service_summary().expect("provider reads snapshot");
    assert_eq!(service.service.state.to_string(), "running");
    assert_eq!(
        service
            .live
            .expect("live metadata")
            .collector_status
            .to_string(),
        "ok"
    );
}

#[test]
fn collector_check_rejects_unknown_fields_and_invalid_values() {
    let cases = [
        (
            "unknown-field",
            r#"
service_identity = "ocserv"
collected_at = "2026-07-09T12:00:00Z"
collector_status = "ok"
service_state = "running"
enabled_state = "enabled"
username = "alice"
"#,
        ),
        (
            "bad-version",
            r#"
service_identity = "ocserv"
collected_at = "2026-07-09T12:00:00Z"
collector_status = "ok"
service_state = "running"
enabled_state = "enabled"
version = "ocserv /etc/ocserv.conf"
"#,
        ),
        (
            "bad-fingerprint",
            r#"
service_identity = "ocserv"
collected_at = "2026-07-09T12:00:00Z"
collector_status = "ok"
service_state = "running"
enabled_state = "enabled"
config_fingerprint_short = "not-hex"
"#,
        ),
        (
            "bad-count",
            r#"
service_identity = "ocserv"
collected_at = "2026-07-09T12:00:00Z"
collector_status = "ok"
service_state = "running"
enabled_state = "enabled"
auth_failure_count_rolling = 1000001
"#,
        ),
        (
            "bad-session-total",
            r#"
service_identity = "ocserv"
collected_at = "2026-07-09T12:00:00Z"
collector_status = "ok"
service_state = "running"
enabled_state = "enabled"
session_total = 1000001
"#,
        ),
        (
            "bad-cert-days",
            r#"
service_identity = "ocserv"
collected_at = "2026-07-09T12:00:00Z"
collector_status = "ok"
service_state = "running"
enabled_state = "enabled"
cert_min_days_remaining = 36501
"#,
        ),
        (
            "bad-service-identity",
            r#"
service_identity = "other"
collected_at = "2026-07-09T12:00:00Z"
collector_status = "ok"
service_state = "running"
enabled_state = "enabled"
"#,
        ),
        (
            "future-timestamp",
            r#"
service_identity = "ocserv"
collected_at = "2999-01-01T00:00:00Z"
collector_status = "unknown"
service_state = "unknown"
enabled_state = "unknown"
"#,
        ),
    ];

    for (name, body) in cases {
        let dir = private_tempdir();
        let config_path = dir.path().join(format!("{name}.toml"));
        let output_path = dir.path().join("out.json");
        write_private(&config_path, body);
        let output = Command::new(collector_bin())
            .arg("--check")
            .arg("--config")
            .arg(&config_path)
            .arg("--output")
            .arg(&output_path)
            .output()
            .expect("run collector");
        assert!(
            !output.status.success(),
            "{name} unexpectedly succeeded: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn collector_parse_errors_do_not_echo_forbidden_fields_or_values() {
    let dir = private_tempdir();
    let config_path = dir.path().join("collector.toml");
    let output_path = dir.path().join("snapshot.json");
    write_private(
        &config_path,
        r#"
service_identity = "ocserv"
collected_at = "2026-07-09T12:00:00Z"
collector_status = "unknown"
service_state = "unknown"
enabled_state = "unknown"
username = "sensitive-user-value"
command = "sensitive-command-value"
"#,
    );
    let output = run_collector_check(&config_path, &output_path);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    for forbidden in [
        "username",
        "sensitive-user-value",
        "command",
        "sensitive-command-value",
    ] {
        assert!(
            !stderr.contains(forbidden),
            "collector parse error echoed {forbidden}: {stderr}"
        );
    }
    assert!(stderr.contains("collector TOML config is invalid"));
}

#[test]
fn collector_preserves_producer_timestamp_across_rewrites() {
    let dir = private_tempdir();
    let config_path = dir.path().join("collector.toml");
    let output_path = dir.path().join("snapshot.json");
    let producer_timestamp = "2020-01-02T03:04:05Z";
    write_private(
        &config_path,
        &format!(
            r#"
service_identity = "ocserv"
output_path = {}
collected_at = "{producer_timestamp}"
collector_status = "unknown"
service_state = "unknown"
enabled_state = "unknown"
"#,
            toml_string(&output_path)
        ),
    );

    for _ in 0..2 {
        let output = Command::new(collector_bin())
            .arg("--config")
            .arg(&config_path)
            .arg("--output")
            .arg(&output_path)
            .output()
            .expect("run collector");
        assert_success(&output);
        let snapshot: Value = serde_json::from_slice(
            &fs::read(&output_path).expect("read rewritten collector snapshot"),
        )
        .expect("snapshot JSON");
        assert_eq!(snapshot["collected_at"], producer_timestamp);
    }
}

#[test]
fn collector_rejects_unsafe_output_parent() {
    let dir = private_tempdir();
    let unsafe_dir = dir.path().join("unsafe");
    fs::create_dir(&unsafe_dir).expect("create unsafe dir");
    fs::set_permissions(&unsafe_dir, fs::Permissions::from_mode(0o777)).expect("chmod unsafe dir");
    let config_path = dir.path().join("collector.toml");
    let output_path = unsafe_dir.join("snapshot.json");
    write_private(
        &config_path,
        r#"
service_identity = "ocserv"
collected_at = "2026-07-09T12:00:00Z"
collector_status = "ok"
service_state = "running"
enabled_state = "enabled"
"#,
    );

    let output = Command::new(collector_bin())
        .arg("--config")
        .arg(&config_path)
        .arg("--output")
        .arg(&output_path)
        .output()
        .expect("run collector");
    assert!(!output.status.success());
    assert!(!output_path.exists());
}

#[test]
fn collector_check_validates_output_safety_without_writing() {
    let dir = private_tempdir();
    let config_path = dir.path().join("collector.toml");
    let output_path = dir.path().join("snapshot.json");
    write_private(
        &config_path,
        r#"
service_identity = "ocserv"
collected_at = "2026-07-09T12:00:00Z"
collector_status = "unknown"
service_state = "unknown"
enabled_state = "unknown"
"#,
    );

    let output = Command::new(collector_bin())
        .arg("--check")
        .arg("--config")
        .arg(&config_path)
        .arg("--output")
        .arg(&output_path)
        .output()
        .expect("run collector check");
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "collector_config=ok\n"
    );
    assert!(!output_path.exists(), "--check must not write a snapshot");

    let unsafe_dir = dir.path().join("unsafe");
    fs::create_dir(&unsafe_dir).expect("create unsafe dir");
    fs::set_permissions(&unsafe_dir, fs::Permissions::from_mode(0o755)).expect("chmod unsafe dir");
    let output = Command::new(collector_bin())
        .arg("--check")
        .arg("--config")
        .arg(&config_path)
        .arg("--output")
        .arg(unsafe_dir.join("snapshot.json"))
        .output()
        .expect("run unsafe collector check");
    assert!(!output.status.success());
}

#[test]
fn collector_rejects_unsafe_config_and_output_links() {
    let dir = private_tempdir();
    let body = r#"
service_identity = "ocserv"
collected_at = "2026-07-09T12:00:00Z"
collector_status = "unknown"
service_state = "unknown"
enabled_state = "unknown"
"#;
    let config_path = dir.path().join("collector.toml");
    fs::write(&config_path, body).expect("write public config");
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o644))
        .expect("chmod public config");
    let output = run_collector_check(&config_path, &dir.path().join("out.json"));
    assert!(!output.status.success(), "public config must be rejected");

    let real_config = dir.path().join("real-config.toml");
    let linked_config = dir.path().join("linked-config.toml");
    write_private(&real_config, body);
    symlink(&real_config, &linked_config).expect("symlink config");
    let output = run_collector_check(&linked_config, &dir.path().join("out.json"));
    assert!(!output.status.success(), "symlink config must be rejected");

    let target = dir.path().join("existing.json");
    let linked_output = dir.path().join("linked.json");
    write_private(&target, "{}");
    symlink(&target, &linked_output).expect("symlink output");
    let output = run_collector_check(&real_config, &linked_output);
    assert!(!output.status.success(), "symlink output must be rejected");

    let hardlinked_output = dir.path().join("hardlinked.json");
    fs::hard_link(&target, &hardlinked_output).expect("hardlink output");
    let output = run_collector_check(&real_config, &hardlinked_output);
    assert!(!output.status.success(), "hardlink output must be rejected");
}

#[test]
fn collector_rejects_output_parent_traversal_and_mismatch() {
    let dir = private_tempdir();
    let config_path = dir.path().join("collector.toml");
    let configured_output = dir.path().join("configured.json");
    write_private(
        &config_path,
        &format!(
            r#"
service_identity = "ocserv"
output_path = {}
collected_at = "2026-07-09T12:00:00Z"
collector_status = "unknown"
service_state = "unknown"
enabled_state = "unknown"
"#,
            toml_string(&configured_output)
        ),
    );

    let output = run_collector_check(&config_path, &dir.path().join("different.json"));
    assert!(
        !output.status.success(),
        "configured output mismatch must fail"
    );

    let traversal = dir.path().join("child").join("..").join("snapshot.json");
    let config_without_output = dir.path().join("collector-without-output.toml");
    write_private(
        &config_without_output,
        r#"
service_identity = "ocserv"
collected_at = "2026-07-09T12:00:00Z"
collector_status = "unknown"
service_state = "unknown"
enabled_state = "unknown"
"#,
    );
    let output = run_collector_check(&config_without_output, &traversal);
    assert!(!output.status.success(), "parent traversal must fail");
}

fn write_private(path: &Path, body: &str) {
    fs::write(path, body).expect("write private file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod private file");
}

fn private_tempdir() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir private");
    dir
}

fn toml_string(path: &Path) -> String {
    serde_json::to_string(&path.to_string_lossy()).expect("quoted path")
}

fn run_collector_check(config: &Path, output: &Path) -> std::process::Output {
    Command::new(collector_bin())
        .arg("--check")
        .arg("--config")
        .arg(config)
        .arg("--output")
        .arg(output)
        .output()
        .expect("run collector check")
}

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "collector failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
