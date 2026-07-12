use ocfleet_cli::ocserv_output::{
    OcservStatusView, assert_low_sensitive_ocserv_output, format_cert_human, format_cert_json,
    format_sessions_human, format_status_human, format_status_json, format_status_view_human,
    low_sensitive_ocserv_audit_message,
};
use ocfleet_protocol::ocserv::{
    OcservCertExpiry, OcservCertExpiryResponse, OcservCertStatus, OcservCollectorStatus,
    OcservConfigFingerprint, OcservConfigFingerprintResponse, OcservFieldStatus, OcservFreshness,
    OcservLiveReadonlyMetadata, OcservReadonlyMeta, OcservReadonlySource,
    OcservServiceEnabledState, OcservServiceState, OcservServiceSummary,
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
            live: None,
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
                key_id: None,
                hash: Some("a".repeat(64)),
                previous: None,
                status: OcservFieldStatus::Available,
            },
            meta: meta(),
        },
    )
    .expect("format status");

    assert!(output.contains("node_id=hk-ocserv-01"));
    assert!(output.contains("service_state=running"));
    assert!(output.contains("service_enabled=enabled"));
    assert!(output.contains("status=ok"));
    assert!(output.contains("version=1.3.0"));
    assert!(output.contains("sessions_total=12"));
    assert!(output.contains("config_fingerprint_sha256=aaaaaaaaaaaa..."));
    assert!(!output.contains(&"a".repeat(64)));
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
            live: None,
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
                key_id: None,
                hash: None,
                previous: None,
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
fn human_status_output_shortens_config_fingerprint() {
    let output = format_status_human(
        "hk-ocserv-01",
        &OcservServiceSummaryResponse {
            service: OcservServiceSummary {
                state: OcservServiceState::Running,
                enabled: OcservServiceEnabledState::Enabled,
                since: None,
            },
            meta: meta(),
            live: None,
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
                key_id: None,
                hash: Some("c".repeat(64)),
                previous: None,
                status: OcservFieldStatus::Available,
            },
            meta: meta(),
        },
    )
    .expect("format status");

    assert!(output.contains("config_fingerprint_sha256=cccccccccccc..."));
    assert!(!output.contains(&"c".repeat(64)));
}

#[test]
fn json_status_output_shortens_config_fingerprint() {
    let hash = "d".repeat(64);
    let output = format_status_json(&OcservStatusView {
        node_id: "hk-ocserv-01".to_string(),
        service: Some(OcservServiceSummary {
            state: OcservServiceState::Running,
            enabled: OcservServiceEnabledState::Enabled,
            since: None,
        }),
        version: Some("1.3.0".to_string()),
        version_status: OcservFieldStatus::Available,
        sessions_total: Some(12),
        sessions_status: OcservFieldStatus::Available,
        config_algorithm: Some("sha256".to_string()),
        config_key_id: None,
        config_hash: Some(hash.clone()),
        config_previous_key_id: None,
        config_previous_hash: None,
        config_status: OcservFieldStatus::Available,
        live: None,
        degraded_methods: Vec::new(),
    })
    .expect("format json status");

    assert!(output.contains("\"config_fingerprint_prefix\": \"dddddddddddd\""));
    assert!(!output.contains(&hash));
    assert_low_sensitive_ocserv_output(&output).expect("json status is low-sensitive");
}

#[test]
fn hmac_status_output_exposes_only_key_ids_and_short_rotation_digests() {
    let current_hash = "a".repeat(64);
    let previous_hash = "b".repeat(64);
    let view = OcservStatusView {
        node_id: "hk-ocserv-01".to_string(),
        service: None,
        version: None,
        version_status: OcservFieldStatus::Unavailable,
        sessions_total: None,
        sessions_status: OcservFieldStatus::Unavailable,
        config_algorithm: Some("hmac-sha256".to_string()),
        config_key_id: Some("key-2026-07".to_string()),
        config_hash: Some(current_hash.clone()),
        config_previous_key_id: Some("key-2026-06".to_string()),
        config_previous_hash: Some(previous_hash.clone()),
        config_status: OcservFieldStatus::Available,
        live: None,
        degraded_methods: Vec::new(),
    };

    let human = format_status_view_human(&view).expect("format HMAC human status");
    let json = format_status_json(&view).expect("format HMAC JSON status");

    for output in [&human, &json] {
        assert!(output.contains("key-2026-07"));
        assert!(output.contains("key-2026-06"));
        assert!(output.contains("aaaaaaaaaaaa"));
        assert!(output.contains("bbbbbbbbbbbb"));
        assert!(!output.contains(&current_hash));
        assert!(!output.contains(&previous_hash));
        assert_low_sensitive_ocserv_output(output).expect("HMAC output is low-sensitive");
    }
    assert!(human.contains("config_fingerprint_hmac_sha256=aaaaaaaaaaaa..."));
}

#[test]
fn json_status_output_includes_live_readonly_metadata() {
    let output = format_status_json(&OcservStatusView {
        node_id: "hk-ocserv-01".to_string(),
        service: Some(OcservServiceSummary {
            state: OcservServiceState::Running,
            enabled: OcservServiceEnabledState::Enabled,
            since: None,
        }),
        version: Some("1.3.0".to_string()),
        version_status: OcservFieldStatus::Available,
        sessions_total: Some(12),
        sessions_status: OcservFieldStatus::Available,
        config_algorithm: Some("sha256".to_string()),
        config_key_id: None,
        config_hash: None,
        config_previous_key_id: None,
        config_previous_hash: None,
        config_status: OcservFieldStatus::Unavailable,
        live: Some(OcservLiveReadonlyMetadata {
            collector_status: OcservCollectorStatus::Ok,
            last_snapshot_at: "2026-07-07T12:00:00Z".to_string(),
            auth_failure_count_rolling: Some(2),
            connection_failure_count_rolling: Some(1),
            cert_min_days_remaining: Some(42),
            config_fingerprint_short: Some("abcdef123456".to_string()),
        }),
        degraded_methods: Vec::new(),
    })
    .expect("format live status");

    assert!(output.contains("\"collector_status\": \"ok\""));
    assert!(output.contains("\"auth_failure_count_rolling\": 2"));
    assert!(output.contains("\"connection_failure_count_rolling\": 1"));
    assert!(output.contains("\"cert_min_days_remaining\": 42"));
    assert!(output.contains("\"config_fingerprint_short\": \"abcdef123456\""));
    assert_low_sensitive_ocserv_output(&output).expect("live status is low-sensitive");
}

#[test]
fn formats_status_degraded_without_raw_errors() {
    let output = format_status_view_human(&OcservStatusView {
        node_id: "hk-ocserv-01".to_string(),
        service: Some(OcservServiceSummary {
            state: OcservServiceState::Running,
            enabled: OcservServiceEnabledState::Enabled,
            since: None,
        }),
        version: None,
        version_status: OcservFieldStatus::Unavailable,
        sessions_total: Some(12),
        sessions_status: OcservFieldStatus::Available,
        config_algorithm: Some("sha256".to_string()),
        config_key_id: None,
        config_hash: None,
        config_previous_key_id: None,
        config_previous_hash: None,
        config_status: OcservFieldStatus::Unavailable,
        live: None,
        degraded_methods: vec!["ocserv.version", "ocserv.config.fingerprint"],
    })
    .expect("format degraded status");

    assert!(output.contains("status=degraded"));
    assert!(output.contains("version=<unavailable>"));
    assert!(output.contains("config_fingerprint_sha256=<unavailable>"));
    assert!(output.contains("degraded_methods=ocserv.version,ocserv.config.fingerprint"));
    assert_low_sensitive_ocserv_output(&output).expect("degraded output is low-sensitive");
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
    assert!(output.contains("fingerprint_sha256=bbbbbbbbbbbb..."));
    assert!(!output.contains(&"b".repeat(64)));
    assert!(!output.contains("BEGIN CERTIFICATE"));
    assert!(!output.contains("subject"));
    assert_low_sensitive_ocserv_output(&output).expect("cert output is low-sensitive");
}

#[test]
fn json_cert_output_uses_low_sensitive_summary_without_full_fingerprint() {
    let response = OcservCertExpiryResponse {
        certs: vec![OcservCertExpiry {
            name: "server".to_string(),
            not_before: Some("2026-01-01T00:00:00Z".to_string()),
            not_after: Some("2026-11-01T00:00:00Z".to_string()),
            days_remaining: Some(117),
            status: OcservCertStatus::Valid,
            fingerprint_sha256: Some("e".repeat(64)),
        }],
        meta: meta(),
    };
    let output = format_cert_json("hk-ocserv-01", &response).expect("format cert json");

    assert!(output.contains("\"cert_count\": 1"));
    assert!(output.contains("\"days_remaining\": 117"));
    assert!(output.contains("\"status\": \"valid\""));
    assert!(output.contains("\"fingerprint_sha256_prefix\": \"eeeeeeeeeeee\""));
    assert!(!output.contains(&"e".repeat(64)));
    assert!(!output.contains("not_before"));
    assert!(!output.contains("not_after"));
    assert!(!output.contains("\"certs\""));
    assert_low_sensitive_ocserv_output(&output).expect("json cert is low-sensitive");
}

#[test]
fn cli_output_rejects_full_sha256_fingerprints() {
    let output = format!("fingerprint_sha256={}", "f".repeat(64));

    assert!(assert_low_sensitive_ocserv_output(&output).is_err());
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

#[test]
fn cli_output_rejects_forbidden_low_sensitive_fixtures() {
    for fixture in [
        "192.168.1.10",
        "fd00::1",
        "/etc/ocserv/ocserv.conf",
        "CN=vpn.example.com",
        "DNS:vpn.example.com",
        "issuer=ca",
        "serial=01",
        "subject=vpn",
        "session_id=abc username=alice client_ip=10.0.0.2",
        "session-id=abc client-ip=10.0.0.2",
        "session id abc client ip 10.0.0.2",
        "systemctl status ocserv",
        "occtl show users",
    ] {
        assert!(
            assert_low_sensitive_ocserv_output(fixture).is_err(),
            "fixture should be rejected: {fixture}"
        );
    }
}

#[test]
fn ocserv_failure_detail_sanitizes_path_like_message() {
    assert_eq!(
        low_sensitive_ocserv_audit_message("failed to read /etc/ocserv/ocserv.conf"),
        "ocserv readonly command failed"
    );
}

#[test]
fn ocserv_failure_detail_sanitizes_command_like_message() {
    assert_eq!(
        low_sensitive_ocserv_audit_message("systemctl status ocserv wrote stderr"),
        "ocserv readonly command failed"
    );
}

#[test]
fn ocserv_schema_decode_failure_audit_excludes_raw_error_text() {
    let message = low_sensitive_ocserv_audit_message(
        "missing field `sessions` at /etc/ocserv/ocserv.conf line 1 column 2",
    );

    assert_eq!(message, "ocserv readonly command failed");
}
