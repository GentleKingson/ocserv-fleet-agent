use ocfleet_cli::ocserv_output::{
    assert_low_sensitive_ocserv_output, format_cert_human, format_sessions_human,
    format_status_human,
};
use ocfleet_protocol::ocserv::{
    OcservCertExpiry, OcservCertExpiryResponse, OcservCertStatus, OcservConfigFingerprint,
    OcservConfigFingerprintResponse, OcservFieldStatus, OcservFreshness, OcservReadonlyMeta,
    OcservReadonlySource, OcservServiceEnabledState, OcservServiceState, OcservServiceSummary,
    OcservServiceSummaryResponse, OcservSessionsSummary, OcservSessionsSummaryResponse,
    OcservVersionResponse,
};

fn meta() -> OcservReadonlyMeta {
    OcservReadonlyMeta {
        source: OcservReadonlySource::Provider,
        collected_at: "2026-07-07T12:00:00Z".to_string(),
        freshness: OcservFreshness::Live,
    }
}

#[test]
fn formats_ocserv_status_human_output_as_low_sensitive_summary() {
    let output = format_status_human(
        "hk-ocserv-01",
        &OcservServiceSummaryResponse {
            service: OcservServiceSummary {
                state: OcservServiceState::Running,
                enabled: OcservServiceEnabledState::Enabled,
                since: Some("2026-07-07T12:00:00Z".to_string()),
            },
            meta: meta(),
        },
        &OcservVersionResponse {
            version: Some("1.3.0".to_string()),
            status: OcservFieldStatus::Available,
            meta: meta(),
        },
        &OcservSessionsSummaryResponse {
            sessions: OcservSessionsSummary {
                total: Some(12),
                status: OcservFieldStatus::Available,
            },
            meta: meta(),
        },
        &OcservConfigFingerprintResponse {
            fingerprint: OcservConfigFingerprint {
                algorithm: "sha256".to_string(),
                hash: Some("a".repeat(64)),
                status: OcservFieldStatus::Available,
            },
            meta: meta(),
        },
    )
    .expect("format status");

    assert!(output.contains("node_id=hk-ocserv-01"));
    assert!(output.contains("service_state=running"));
    assert!(output.contains("service_enabled=enabled"));
    assert!(output.contains("version=1.3.0"));
    assert!(output.contains("sessions_total=12"));
    assert!(output.contains("config_fingerprint_sha256="));
    assert_low_sensitive_ocserv_output(&output).expect("status output is low-sensitive");
}

#[test]
fn formats_unavailable_ocserv_status_fields_without_paths_or_raw_output() {
    let output = format_status_human(
        "hk-ocserv-01",
        &OcservServiceSummaryResponse {
            service: OcservServiceSummary {
                state: OcservServiceState::Unavailable,
                enabled: OcservServiceEnabledState::Unavailable,
                since: None,
            },
            meta: meta(),
        },
        &OcservVersionResponse {
            version: None,
            status: OcservFieldStatus::Unavailable,
            meta: meta(),
        },
        &OcservSessionsSummaryResponse {
            sessions: OcservSessionsSummary {
                total: None,
                status: OcservFieldStatus::Unavailable,
            },
            meta: meta(),
        },
        &OcservConfigFingerprintResponse {
            fingerprint: OcservConfigFingerprint {
                algorithm: "sha256".to_string(),
                hash: None,
                status: OcservFieldStatus::Unavailable,
            },
            meta: meta(),
        },
    )
    .expect("format status");

    assert!(output.contains("version=<unavailable>"));
    assert!(output.contains("sessions_total=<unavailable>"));
    assert!(output.contains("config_fingerprint_sha256=<unavailable>"));
    assert_low_sensitive_ocserv_output(&output).expect("unavailable output is low-sensitive");
}

#[test]
fn formats_ocserv_cert_human_output_without_certificate_material() {
    let output = format_cert_human(
        "hk-ocserv-01",
        &OcservCertExpiryResponse {
            certs: vec![OcservCertExpiry {
                name: "server".to_string(),
                not_before: Some("2026-01-01T00:00:00Z".to_string()),
                not_after: Some("2026-11-01T00:00:00Z".to_string()),
                days_remaining: Some(117),
                status: OcservCertStatus::Valid,
                fingerprint_sha256: Some("b".repeat(64)),
            }],
            meta: meta(),
        },
    )
    .expect("format cert");

    assert!(output.contains("node_id=hk-ocserv-01"));
    assert!(output.contains("cert=server status=valid"));
    assert!(output.contains("days_remaining=117"));
    assert!(!output.contains("BEGIN CERTIFICATE"));
    assert!(!output.contains("subject"));
    assert_low_sensitive_ocserv_output(&output).expect("cert output is low-sensitive");
}

#[test]
fn formats_ocserv_sessions_summary_without_session_details() {
    let output = format_sessions_human(
        "hk-ocserv-01",
        &OcservSessionsSummaryResponse {
            sessions: OcservSessionsSummary {
                total: Some(12),
                status: OcservFieldStatus::Available,
            },
            meta: meta(),
        },
    )
    .expect("format sessions");

    assert_eq!(output, "node_id=hk-ocserv-01\nsessions_total=12\n");
    assert_low_sensitive_ocserv_output(&output).expect("sessions output is low-sensitive");
}
