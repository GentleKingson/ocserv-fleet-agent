use ocfleet_agent::ocserv::{
    CertificateExpiryProvider, CollectorSnapshotOcservReadonlyProvider, ConfigFingerprintProvider,
    DisabledOcservReadonlyProvider, OcservReadonlyProvider, SnapshotOcservReadonlyProvider,
};
use ocfleet_config::agent::{OcservCertificateConfig, OcservConfigFingerprintConfig};
use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::ocserv::{OcservCertStatus, OcservCollectorStatus, OcservFieldStatus};
use std::path::Path;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

#[test]
fn disabled_ocserv_provider_returns_low_sensitive_unavailable_error() {
    let provider = DisabledOcservReadonlyProvider;

    let err = provider
        .service_summary()
        .expect_err("disabled provider rejects service summary");

    assert_eq!(err.code(), ErrorCode::OcservReadonlyDisabled);
    assert!(err.message().len() <= 128);
    assert!(!err.message().contains("/etc/"));
}

#[test]
fn snapshot_provider_accepts_fixed_schema_and_returns_typed_summary() {
    let dir = tempfile::tempdir().expect("temp dir");
    let snapshot = dir.path().join("ocserv-readonly.json");
    std::fs::write(
        &snapshot,
        r#"{"service":{"state":"running","enabled":"enabled","since":"2026-07-07T12:00:00Z"},"version":"1.3.0","sessions":{"total":12}}"#,
    )
    .expect("write snapshot");
    make_private(&snapshot);
    let provider = SnapshotOcservReadonlyProvider::new(snapshot);

    let service = provider.service_summary().expect("service summary");
    assert_eq!(service.service.state.to_string(), "running");
    assert_eq!(service.service.enabled.to_string(), "enabled");

    let version = provider.version().expect("version");
    assert_eq!(version.version.as_deref(), Some("1.3.0"));
    assert_eq!(version.status, OcservFieldStatus::Available);

    let sessions = provider.sessions_summary().expect("sessions summary");
    assert_eq!(sessions.sessions.total, Some(12));
    assert_eq!(sessions.sessions.status, OcservFieldStatus::Available);
}

#[test]
fn snapshot_provider_rejects_unknown_raw_fields_and_unbounded_values() {
    let dir = tempfile::tempdir().expect("temp dir");
    let snapshot = dir.path().join("ocserv-readonly.json");
    std::fs::write(
        &snapshot,
        r#"{"service":{"state":"running","enabled":"enabled"},"version":"1.3.0\nraw command output","raw":"do not pass through"}"#,
    )
    .expect("write snapshot");
    make_private(&snapshot);
    let provider = SnapshotOcservReadonlyProvider::new(snapshot);

    let err = provider
        .version()
        .expect_err("raw snapshot fields rejected");
    assert_eq!(err.code(), ErrorCode::OcservProviderInvalidData);
    assert!(!err.message().contains("raw command output"));
}

#[test]
fn snapshot_provider_rejects_files_over_16_kib() {
    let dir = tempfile::tempdir().expect("temp dir");
    let snapshot = dir.path().join("ocserv-readonly.json");
    std::fs::write(&snapshot, " ".repeat(16 * 1024 + 1)).expect("write large snapshot");
    make_private(&snapshot);
    let provider = SnapshotOcservReadonlyProvider::new(snapshot);

    let err = provider
        .sessions_summary()
        .expect_err("oversized snapshot rejected");
    assert_eq!(err.code(), ErrorCode::OcservOutputBoundExceeded);
}

#[cfg(unix)]
#[test]
fn snapshot_provider_rejects_hardlinked_snapshot_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    let snapshot = dir.path().join("ocserv-readonly.json");
    let hardlink = dir.path().join("ocserv-readonly-hardlink.json");
    std::fs::write(
        &snapshot,
        r#"{"service":{"state":"running","enabled":"enabled"},"version":"1.3.0"}"#,
    )
    .expect("write snapshot");
    make_private(&snapshot);
    std::fs::hard_link(&snapshot, &hardlink).expect("create hardlink");
    let provider = SnapshotOcservReadonlyProvider::new(snapshot);

    let err = provider
        .service_summary()
        .expect_err("hardlinked snapshot source rejected");

    assert_eq!(err.code(), ErrorCode::OcservProviderUnsafeSource);
}

#[test]
fn snapshot_collected_at_rejects_control_chars() {
    let dir = tempfile::tempdir().expect("temp dir");
    let snapshot = dir.path().join("ocserv-readonly.json");
    std::fs::write(
        &snapshot,
        r#"{"service":{"state":"running","enabled":"enabled"},"collected_at":"2026-07-07T12:00:00Z\n"}"#,
    )
    .expect("write snapshot");
    make_private(&snapshot);
    let provider = SnapshotOcservReadonlyProvider::new(snapshot);

    let err = provider
        .service_summary()
        .expect_err("control chars in collected_at rejected");
    assert_eq!(err.code(), ErrorCode::OcservProviderInvalidData);
}

#[test]
fn snapshot_collected_at_rejects_path_like_content() {
    let dir = tempfile::tempdir().expect("temp dir");
    let snapshot = dir.path().join("ocserv-readonly.json");
    std::fs::write(
        &snapshot,
        r#"{"service":{"state":"running","enabled":"enabled"},"collected_at":"/etc/ocserv/ocserv.conf"}"#,
    )
    .expect("write snapshot");
    make_private(&snapshot);
    let provider = SnapshotOcservReadonlyProvider::new(snapshot);

    let err = provider
        .service_summary()
        .expect_err("path-like collected_at rejected");
    assert_eq!(err.code(), ErrorCode::OcservProviderInvalidData);
    assert!(!err.message().contains("/etc/ocserv"));
}

#[test]
fn collector_snapshot_provider_accepts_v2_low_sensitive_schema() {
    let dir = tempfile::tempdir().expect("temp dir");
    let snapshot = write_collector_snapshot(
        dir.path(),
        &format!(
            r#"{{
  "schema_version": "ocfleet.ocserv.snapshot.v2",
  "collected_at": "{}",
  "collector_status": "ok",
  "service_state": "running",
  "enabled_state": "enabled",
  "version": "1.3.0",
  "session_total": 12,
  "auth_failure_count_rolling": 2,
  "connection_failure_count_rolling": 1,
  "cert_min_days_remaining": 42,
  "config_fingerprint_short": "abcdef123456"
}}"#,
            fresh_timestamp()
        ),
    );
    let provider = CollectorSnapshotOcservReadonlyProvider::new(snapshot);

    let service = provider.service_summary().expect("service summary");
    assert_eq!(service.service.state.to_string(), "running");
    assert_eq!(service.service.enabled.to_string(), "enabled");
    let live = service.live.expect("live metadata");
    assert_eq!(live.collector_status, OcservCollectorStatus::Ok);
    assert_eq!(live.auth_failure_count_rolling, Some(2));
    assert_eq!(live.connection_failure_count_rolling, Some(1));
    assert_eq!(live.cert_min_days_remaining, Some(42));
    assert_eq!(
        live.config_fingerprint_short.as_deref(),
        Some("abcdef123456")
    );

    let version = provider.version().expect("version");
    assert_eq!(version.version.as_deref(), Some("1.3.0"));
    assert_eq!(version.status, OcservFieldStatus::Available);

    let sessions = provider.sessions_summary().expect("sessions");
    assert_eq!(sessions.sessions.total, Some(12));
    assert_eq!(sessions.sessions.status, OcservFieldStatus::Available);
}

#[test]
fn collector_snapshot_provider_rejects_stale_snapshot() {
    let dir = tempfile::tempdir().expect("temp dir");
    let snapshot = write_collector_snapshot(
        dir.path(),
        &format!(
            r#"{{
  "schema_version": "ocfleet.ocserv.snapshot.v2",
  "collected_at": "{}",
  "collector_status": "stale",
  "service_state": "unknown",
  "enabled_state": "unknown"
}}"#,
            stale_timestamp()
        ),
    );
    let provider = CollectorSnapshotOcservReadonlyProvider::new(snapshot);

    let err = provider
        .service_summary()
        .expect_err("stale collector snapshot rejected");
    assert_eq!(err.code(), ErrorCode::OcservProviderUnavailable);
    assert!(!err.message().contains("journal"));
}

#[test]
fn collector_snapshot_provider_rejects_forbidden_fields() {
    let dir = tempfile::tempdir().expect("temp dir");
    let snapshot = write_collector_snapshot(
        dir.path(),
        &format!(
            r#"{{
  "schema_version": "ocfleet.ocserv.snapshot.v2",
  "collected_at": "{}",
  "collector_status": "ok",
  "service_state": "running",
  "enabled_state": "enabled",
  "username": "alice"
}}"#,
            fresh_timestamp()
        ),
    );
    let provider = CollectorSnapshotOcservReadonlyProvider::new(snapshot);

    let err = provider
        .service_summary()
        .expect_err("forbidden field rejected");
    assert_eq!(err.code(), ErrorCode::OcservProviderInvalidData);
    assert!(!err.message().contains("alice"));
}

#[test]
fn collector_snapshot_provider_rejects_oversized_string() {
    let dir = tempfile::tempdir().expect("temp dir");
    let snapshot = write_collector_snapshot(
        dir.path(),
        &format!(
            r#"{{
  "schema_version": "ocfleet.ocserv.snapshot.v2",
  "collected_at": "{}",
  "collector_status": "ok",
  "service_state": "running",
  "enabled_state": "enabled",
  "version": "{}"
}}"#,
            fresh_timestamp(),
            "1".repeat(65)
        ),
    );
    let provider = CollectorSnapshotOcservReadonlyProvider::new(snapshot);

    let err = provider.version().expect_err("oversized version rejected");
    assert_eq!(err.code(), ErrorCode::OcservProviderInvalidData);
}

#[test]
fn collector_snapshot_provider_rejects_invalid_schema() {
    let dir = tempfile::tempdir().expect("temp dir");
    let snapshot = write_collector_snapshot(
        dir.path(),
        &format!(
            r#"{{
  "schema_version": "ocfleet.ocserv.snapshot.v1",
  "collected_at": "{}",
  "collector_status": "ok",
  "service_state": "running",
  "enabled_state": "enabled"
}}"#,
            fresh_timestamp()
        ),
    );
    let provider = CollectorSnapshotOcservReadonlyProvider::new(snapshot);

    let err = provider
        .service_summary()
        .expect_err("invalid schema rejected");
    assert_eq!(err.code(), ErrorCode::OcservProviderInvalidData);
}

#[test]
fn collector_snapshot_provider_rejects_invalid_ranges_and_fingerprints() {
    let dir = tempfile::tempdir().expect("temp dir");
    let snapshot = write_collector_snapshot(
        dir.path(),
        &format!(
            r#"{{
  "schema_version": "ocfleet.ocserv.snapshot.v2",
  "collected_at": "{}",
  "collector_status": "ok",
  "service_state": "running",
  "enabled_state": "enabled",
  "auth_failure_count_rolling": 1000001,
  "config_fingerprint_short": "not-hex"
}}"#,
            fresh_timestamp()
        ),
    );
    let provider = CollectorSnapshotOcservReadonlyProvider::new(snapshot);

    let err = provider
        .service_summary()
        .expect_err("invalid ranges rejected");
    assert_eq!(err.code(), ErrorCode::OcservProviderInvalidData);
}

#[test]
fn collector_snapshot_provider_output_is_low_sensitive() {
    let dir = tempfile::tempdir().expect("temp dir");
    let snapshot = write_collector_snapshot(
        dir.path(),
        &format!(
            r#"{{
  "schema_version": "ocfleet.ocserv.snapshot.v2",
  "collected_at": "{}",
  "collector_status": "partial",
  "service_state": "failed",
  "enabled_state": "enabled",
  "session_total": 0,
  "cert_min_days_remaining": -1
}}"#,
            fresh_timestamp()
        ),
    );
    let provider = CollectorSnapshotOcservReadonlyProvider::new(snapshot);
    let text = serde_json::to_string(&provider.service_summary().expect("service")).expect("json");

    for marker in [
        "username",
        "client_ip",
        "session_id",
        "/etc/ocserv",
        "BEGIN CERTIFICATE",
    ] {
        assert!(!text.contains(marker), "forbidden marker leaked: {marker}");
    }
}

#[test]
fn provider_error_message_drops_paths() {
    let err = ocfleet_agent::ocserv::OcservReadonlyError::new(
        ErrorCode::OcservProviderUnavailable,
        "failed to read /etc/ocserv/ocserv.conf",
    );

    assert_eq!(err.message(), "ocserv readonly provider error");
}

#[test]
fn provider_error_message_drops_command_markers() {
    let err = ocfleet_agent::ocserv::OcservReadonlyError::new(
        ErrorCode::OcservProviderUnavailable,
        "systemctl status ocserv wrote stderr",
    );

    assert_eq!(err.message(), "ocserv readonly provider error");
}

#[test]
fn provider_error_message_replaces_control_chars() {
    let err = ocfleet_agent::ocserv::OcservReadonlyError::new(
        ErrorCode::OcservProviderUnavailable,
        "temporary\tcollector\nfailure",
    );

    assert_eq!(err.message(), "temporary collector failure");
}

#[test]
fn invalid_certificate_returns_invalid_without_leaking_pem_or_path() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cert_path = dir.path().join("server.pem");
    std::fs::write(
        &cert_path,
        "-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n",
    )
    .expect("write invalid cert");
    let provider = CertificateExpiryProvider::new(vec![OcservCertificateConfig {
        name: "server".to_string(),
        cert_path,
    }]);

    let response = provider.cert_expiry().expect("invalid cert is typed data");
    assert_eq!(response.certs.len(), 1);
    assert_eq!(response.certs[0].status, OcservCertStatus::Invalid);
    let text = serde_json::to_string(&response).expect("response json");
    assert!(!text.contains("BEGIN CERTIFICATE"));
    assert!(!text.contains("/server.pem"));
}

#[test]
fn valid_certificate_pem_parses_expiry_without_subject_or_path() {
    use base64::Engine;

    let dir = tempfile::tempdir().expect("temp dir");
    let cert_path = dir.path().join("server.pem");
    let der = minimal_certificate_der("260101000000Z", "491101000000Z");
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    std::fs::write(
        &cert_path,
        format!("-----BEGIN CERTIFICATE-----\n{encoded}\n-----END CERTIFICATE-----\n"),
    )
    .expect("write valid cert");
    let provider = CertificateExpiryProvider::new(vec![OcservCertificateConfig {
        name: "server".to_string(),
        cert_path,
    }]);

    let response = provider.cert_expiry().expect("cert expiry");
    assert_eq!(response.certs.len(), 1);
    let cert = &response.certs[0];
    assert_eq!(cert.status, OcservCertStatus::Valid);
    assert_eq!(cert.not_before.as_deref(), Some("2026-01-01T00:00:00Z"));
    assert_eq!(cert.not_after.as_deref(), Some("2049-11-01T00:00:00Z"));
    assert_eq!(
        cert.fingerprint_sha256.as_ref().expect("fingerprint").len(),
        64
    );
    let text = serde_json::to_string(&response).expect("response json");
    assert!(!text.contains("subject"));
    assert!(!text.contains("server.pem"));
}

#[test]
fn certificate_provider_rejects_files_over_1_mib() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cert_path = dir.path().join("server.pem");
    std::fs::write(&cert_path, "x".repeat(1024 * 1024 + 1)).expect("write large cert");
    let provider = CertificateExpiryProvider::new(vec![OcservCertificateConfig {
        name: "server".to_string(),
        cert_path,
    }]);

    let err = provider.cert_expiry().expect_err("oversized cert rejected");
    assert_eq!(err.code(), ErrorCode::OcservOutputBoundExceeded);
}

#[cfg(unix)]
#[test]
fn certificate_provider_rejects_group_writable_certificate_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let cert_path = dir.path().join("server.pem");
    std::fs::write(&cert_path, "not a cert").expect("write cert");
    std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(0o620))
        .expect("chmod cert");
    let provider = CertificateExpiryProvider::new(vec![OcservCertificateConfig {
        name: "server".to_string(),
        cert_path,
    }]);

    let err = provider
        .cert_expiry()
        .expect_err("group-writable cert source rejected");

    assert_eq!(err.code(), ErrorCode::OcservProviderUnsafeSource);
}

#[test]
fn config_fingerprint_provider_returns_only_sha256_hash() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config_path = dir.path().join("ocserv.conf");
    std::fs::write(&config_path, "auth = plain[/etc/ocserv/passwd]\n").expect("write config");
    let provider = ConfigFingerprintProvider::new(Some(OcservConfigFingerprintConfig {
        name: "main".to_string(),
        config_path,
    }));

    let response = provider.config_fingerprint().expect("fingerprint");
    assert_eq!(response.fingerprint.algorithm, "sha256");
    assert_eq!(response.fingerprint.status, OcservFieldStatus::Available);
    assert_eq!(response.fingerprint.hash.as_ref().expect("hash").len(), 64);
    let text = serde_json::to_string(&response).expect("response json");
    assert!(!text.contains("plain"));
    assert!(!text.contains("ocserv.conf"));
    assert!(!text.contains("/etc/ocserv"));
}

#[test]
fn config_fingerprint_provider_rejects_files_over_1_mib() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config_path = dir.path().join("ocserv.conf");
    std::fs::write(&config_path, "x".repeat(1024 * 1024 + 1)).expect("write large config");
    let provider = ConfigFingerprintProvider::new(Some(OcservConfigFingerprintConfig {
        name: "main".to_string(),
        config_path,
    }));

    let err = provider
        .config_fingerprint()
        .expect_err("oversized config rejected");
    assert_eq!(err.code(), ErrorCode::OcservOutputBoundExceeded);
}

#[cfg(unix)]
#[test]
fn config_fingerprint_provider_rejects_group_writable_config_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let config_path = dir.path().join("ocserv.conf");
    std::fs::write(&config_path, "auth = plain[/etc/ocserv/passwd]\n").expect("write config");
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o620))
        .expect("chmod config");
    let provider = ConfigFingerprintProvider::new(Some(OcservConfigFingerprintConfig {
        name: "main".to_string(),
        config_path,
    }));

    let err = provider
        .config_fingerprint()
        .expect_err("group-writable config source rejected");

    assert_eq!(err.code(), ErrorCode::OcservProviderUnsafeSource);
}

#[test]
fn ocserv_provider_source_does_not_use_dangerous_adapters() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_dir = manifest_dir.join("src").join("ocserv");
    let mut violations = Vec::new();
    collect_forbidden_provider_source(&src_dir, &mut violations);

    assert!(
        violations.is_empty(),
        "ocserv provider source contains dangerous adapter markers: {violations:?}"
    );
}

#[test]
fn ocserv_production_paths_do_not_use_command_execution_or_raw_passthrough() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();
    for path in [
        manifest_dir.join("src").join("ocserv"),
        manifest_dir.join("src").join("server.rs"),
        manifest_dir
            .join("..")
            .join("ocfleet-cli")
            .join("src")
            .join("ocserv_output.rs"),
    ] {
        collect_forbidden_production_source(&path, &mut violations);
    }

    assert!(
        violations.is_empty(),
        "ocserv production source contains forbidden passthrough markers: {violations:?}"
    );
}

fn collect_forbidden_provider_source(dir: &Path, violations: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).expect("read ocserv source dir") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            collect_forbidden_provider_source(&path, violations);
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read source file");
        for forbidden in [
            "std::process::Command",
            "systemctl",
            "occtl",
            "journalctl",
            "shell",
            "raw_file",
        ] {
            if text.contains(forbidden) {
                violations.push(format!("{} contains {forbidden}", path.display()));
            }
        }
    }
}

fn collect_forbidden_production_source(path: &Path, violations: &mut Vec<String>) {
    if path.is_dir() {
        for entry in std::fs::read_dir(path).expect("read source dir") {
            collect_forbidden_production_source(&entry.expect("source entry").path(), violations);
        }
        return;
    }
    if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
        return;
    }
    let text = std::fs::read_to_string(path).expect("read production source file");
    for forbidden in [
        "std::process::Command",
        "tokio::process",
        "Command::new",
        "duct::",
        "xshell",
        "systemctl",
        "occtl",
        "journalctl",
        "tail -f",
        "cat /etc",
        "raw_stdout",
        "raw_stderr",
        "raw_output",
        "raw_file",
        "shell_exec",
        "command_run",
        "service_name",
        "journal_unit",
    ] {
        if text.contains(forbidden) {
            violations.push(format!("{} contains {forbidden}", path.display()));
        }
    }
}

fn minimal_certificate_der(not_before: &str, not_after: &str) -> Vec<u8> {
    let serial = der_tlv(0x02, &[1]);
    let signature = der_tlv(0x30, &[]);
    let issuer = der_tlv(0x30, &[]);
    let validity = der_tlv(
        0x30,
        &[
            der_tlv(0x17, not_before.as_bytes()),
            der_tlv(0x17, not_after.as_bytes()),
        ]
        .concat(),
    );
    let tbs = der_tlv(0x30, &[serial, signature, issuer, validity].concat());
    der_tlv(0x30, &tbs)
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else {
        out.push(0x82);
        out.push(((value.len() >> 8) & 0xff) as u8);
        out.push((value.len() & 0xff) as u8);
    }
    out.extend_from_slice(value);
    out
}

fn write_collector_snapshot(dir: &Path, text: &str) -> std::path::PathBuf {
    let snapshot = dir.join("ocserv-live-snapshot.json");
    std::fs::write(&snapshot, text).expect("write collector snapshot");
    make_private(&snapshot);
    snapshot
}

fn fresh_timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("format fresh timestamp")
}

fn stale_timestamp() -> String {
    (OffsetDateTime::now_utc() - Duration::hours(2))
        .format(&Rfc3339)
        .expect("format stale timestamp")
}

#[cfg(unix)]
fn make_private(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod private");
}

#[cfg(not(unix))]
fn make_private(_path: &Path) {}
