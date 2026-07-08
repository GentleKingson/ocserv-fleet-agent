use ocfleet_protocol::method::{
    MethodStatus, OCSERV_CERT_EXPIRY, OCSERV_CONFIG_FINGERPRINT, OCSERV_SERVICE_SUMMARY,
    OCSERV_SESSIONS_SUMMARY, OCSERV_VERSION, classify_phase_one_method,
};
use ocfleet_protocol::ocserv::{
    OcservCertExpiry, OcservCertExpiryResponse, OcservCertStatus, OcservConfigFingerprint,
    OcservConfigFingerprintResponse, OcservFieldStatus, OcservFreshness, OcservReadonlyMeta,
    OcservReadonlySource, OcservServiceEnabledState, OcservServiceState, OcservServiceSummary,
    OcservServiceSummaryRequest, OcservServiceSummaryResponse, OcservSessionsSummary,
    OcservSessionsSummaryRequest, OcservSessionsSummaryResponse, OcservVersionRequest,
    OcservVersionResponse, is_valid_ocserv_collected_at, is_valid_ocserv_name,
    is_valid_ocserv_version, is_valid_sha256_hex, validate_ocserv_response_json_size,
};
use serde_json::json;

fn meta() -> OcservReadonlyMeta {
    OcservReadonlyMeta {
        source: OcservReadonlySource::Snapshot,
        collected_at: "2026-07-07T12:00:00Z".to_string(),
        freshness: OcservFreshness::Cached,
    }
}

#[test]
fn ocserv_method_constants_are_fixed_and_allowed_for_controller() {
    let expected = [
        (OCSERV_SERVICE_SUMMARY, "ocserv.service.summary"),
        (OCSERV_VERSION, "ocserv.version"),
        (OCSERV_SESSIONS_SUMMARY, "ocserv.sessions.summary"),
        (OCSERV_CERT_EXPIRY, "ocserv.cert.expiry"),
        (OCSERV_CONFIG_FINGERPRINT, "ocserv.config.fingerprint"),
    ];

    for (actual, expected) in expected {
        assert_eq!(actual, expected);
        assert_eq!(classify_phase_one_method(actual), MethodStatus::Allowed);
    }
}

#[test]
fn ocserv_enums_serialize_as_stable_snake_case() {
    assert_eq!(
        serde_json::to_value(OcservServiceState::Running).expect("serialize state"),
        json!("running")
    );
    assert_eq!(
        serde_json::to_value(OcservServiceEnabledState::Unavailable).expect("serialize enabled"),
        json!("unavailable")
    );
    assert_eq!(
        serde_json::to_value(OcservCertStatus::ExpiringSoon).expect("serialize cert status"),
        json!("expiring_soon")
    );
    assert_eq!(
        serde_json::to_value(OcservFieldStatus::Unavailable).expect("serialize field status"),
        json!("unavailable")
    );
}

#[test]
fn ocserv_empty_request_serializes_as_closed_object() {
    let value = serde_json::to_value(OcservServiceSummaryRequest {}).expect("serialize request");
    assert_eq!(value, json!({}));
}

#[test]
fn all_ocserv_request_types_reject_unknown_fields() {
    serde_json::from_value::<OcservServiceSummaryRequest>(json!({"path": "/etc/ocserv"}))
        .expect_err("service summary request rejects selectors");
    serde_json::from_value::<OcservVersionRequest>(json!({"command": "occtl show users"}))
        .expect_err("version request rejects commands");
    serde_json::from_value::<OcservSessionsSummaryRequest>(json!({"journal": "ocserv"}))
        .expect_err("sessions request rejects journals");
    serde_json::from_value::<ocfleet_protocol::ocserv::OcservCertExpiryRequest>(
        json!({"file": "/etc/ocserv/server-cert.pem"}),
    )
    .expect_err("cert request rejects files");
    serde_json::from_value::<ocfleet_protocol::ocserv::OcservConfigFingerprintRequest>(
        json!({"path": "/etc/ocserv/ocserv.conf"}),
    )
    .expect_err("config request rejects paths");
}

#[test]
fn all_ocserv_response_types_reject_unknown_fields() {
    serde_json::from_value::<OcservServiceSummaryResponse>(json!({
        "service": {"state": "running", "enabled": "enabled"},
        "meta": meta(),
        "raw": "nope"
    }))
    .expect_err("service response rejects raw");
    serde_json::from_value::<OcservVersionResponse>(json!({
        "version": "1.3.0",
        "status": "available",
        "meta": {"source": "snapshot", "collected_at": "2026-07-07T12:00:00Z", "freshness": "cached", "path": "/etc/ocserv"}
    }))
    .expect_err("meta rejects unknown path field");
    serde_json::from_value::<OcservSessionsSummaryResponse>(json!({
        "sessions": {"total": 12, "status": "available", "username": "alice"},
        "meta": meta()
    }))
    .expect_err("sessions response rejects details");
}

#[test]
fn ocserv_meta_collected_at_is_bounded() {
    assert!(is_valid_ocserv_collected_at("2026-07-07T12:00:00Z"));
    assert!(!is_valid_ocserv_collected_at(&"2".repeat(65)));
    assert!(!is_valid_ocserv_collected_at("2026-07-07T12:00:00Z\n"));
    assert!(!is_valid_ocserv_collected_at("/etc/ocserv/ocserv.conf"));
}

#[test]
fn ocserv_responses_are_closed_low_sensitive_shapes() {
    let response = OcservServiceSummaryResponse {
        service: OcservServiceSummary {
            state: OcservServiceState::Running,
            enabled: OcservServiceEnabledState::Enabled,
            since: Some("2026-07-07T12:00:00Z".to_string()),
        },
        meta: meta(),
    };
    let value = serde_json::to_value(&response).expect("serialize service summary");
    let object = value.as_object().expect("response object");
    let mut fields = object.keys().map(String::as_str).collect::<Vec<_>>();
    fields.sort_unstable();
    assert_eq!(fields, ["meta", "service"]);

    let text = serde_json::to_string(&response).expect("response json");
    for forbidden in [
        "raw",
        "path",
        "command",
        "systemctl",
        "journalctl",
        "occtl",
        "username",
        "client_ip",
        "session_id",
    ] {
        assert!(
            !text.contains(forbidden),
            "ocserv response must not contain {forbidden}: {text}"
        );
    }
}

#[test]
fn ocserv_response_json_never_contains_forbidden_field_names() {
    let responses = [
        serde_json::to_value(OcservServiceSummaryResponse {
            service: OcservServiceSummary {
                state: OcservServiceState::Running,
                enabled: OcservServiceEnabledState::Enabled,
                since: Some("2026-07-07T12:00:00Z".to_string()),
            },
            meta: meta(),
        })
        .expect("service json"),
        serde_json::to_value(OcservVersionResponse {
            version: Some("1.3.0".to_string()),
            status: OcservFieldStatus::Available,
            meta: meta(),
        })
        .expect("version json"),
        serde_json::to_value(OcservSessionsSummaryResponse {
            sessions: OcservSessionsSummary {
                total: Some(12),
                status: OcservFieldStatus::Available,
            },
            meta: meta(),
        })
        .expect("sessions json"),
    ];
    for value in responses {
        let text = value.to_string();
        for forbidden in [
            "raw",
            "stdout",
            "stderr",
            "command",
            "path",
            "file",
            "log",
            "journal",
            "unit",
            "username",
            "\"user\"",
            "client_ip",
            "vpn_ip",
            "session_id",
            "subject",
            "issuer",
            "serial",
            "san",
            "pem",
            "der",
        ] {
            assert!(!text.contains(forbidden), "forbidden {forbidden} in {text}");
        }
    }
}

#[test]
fn ocserv_known_but_forbidden_methods_remain_not_allowed() {
    for method in [
        "ocserv.reload",
        "ocserv.restart",
        "ocserv.user.list",
        "ocserv.sessions.list",
        "ocserv.logs.query",
        "ocserv.command.exec",
        "ocserv.file.read",
        "ocserv.occtl",
        "ocserv.systemctl",
        "ocserv.journalctl",
    ] {
        assert_ne!(
            classify_phase_one_method(method),
            MethodStatus::Allowed,
            "{method} must not become allowed"
        );
    }
}

#[test]
fn ocserv_version_and_name_bounds_are_enforced() {
    assert!(is_valid_ocserv_version("1.3.0"));
    assert!(is_valid_ocserv_version("ocserv 1.3.0"));
    assert!(!is_valid_ocserv_version(&"v".repeat(65)));
    assert!(!is_valid_ocserv_version("1.3.0\nextra"));
    assert!(!is_valid_ocserv_version("1.3.0; cat /etc/passwd"));

    assert!(is_valid_ocserv_name("server"));
    assert!(is_valid_ocserv_name("server-1.prod"));
    assert!(!is_valid_ocserv_name(""));
    assert!(!is_valid_ocserv_name(&"a".repeat(65)));
    assert!(!is_valid_ocserv_name("../server"));
}

#[test]
fn ocserv_fingerprint_hash_must_be_sha256_hex() {
    let good = "a".repeat(64);
    assert!(is_valid_sha256_hex(&good));
    assert!(!is_valid_sha256_hex("a"));
    assert!(!is_valid_sha256_hex(&"g".repeat(64)));
    assert!(!is_valid_sha256_hex(&format!("{good}\n")));
}

#[test]
fn ocserv_response_size_helper_bounds_serialized_json() {
    let response = OcservCertExpiryResponse {
        certs: vec![OcservCertExpiry {
            name: "server".to_string(),
            not_before: Some("2026-01-01T00:00:00Z".to_string()),
            not_after: Some("2026-11-01T00:00:00Z".to_string()),
            days_remaining: Some(117),
            status: OcservCertStatus::Valid,
            fingerprint_sha256: Some("b".repeat(64)),
        }],
        meta: meta(),
    };
    validate_ocserv_response_json_size(&response).expect("small response is bounded");

    let oversized = OcservVersionResponse {
        version: Some("x".repeat(9 * 1024)),
        status: OcservFieldStatus::Available,
        meta: meta(),
    };
    validate_ocserv_response_json_size(&oversized).expect_err("oversized response rejected");
}

#[test]
fn ocserv_config_fingerprint_round_trips_without_config_content() {
    let response = OcservConfigFingerprintResponse {
        fingerprint: OcservConfigFingerprint {
            algorithm: "sha256".to_string(),
            hash: Some("c".repeat(64)),
            status: OcservFieldStatus::Available,
        },
        meta: meta(),
    };
    let value = serde_json::to_value(&response).expect("serialize config fingerprint");
    let round_trip: OcservConfigFingerprintResponse =
        serde_json::from_value(value.clone()).expect("deserialize config fingerprint");
    assert_eq!(round_trip.fingerprint.algorithm, "sha256");
    let expected_hash = "c".repeat(64);
    assert_eq!(
        round_trip.fingerprint.hash.as_deref(),
        Some(expected_hash.as_str())
    );
    assert!(!value.to_string().contains("ocserv.conf"));
}

#[test]
fn ocserv_sessions_summary_only_exposes_aggregate_count() {
    let response = OcservSessionsSummaryResponse {
        sessions: OcservSessionsSummary {
            total: Some(12),
            status: OcservFieldStatus::Available,
        },
        meta: meta(),
    };
    let text = serde_json::to_string(&response).expect("serialize sessions summary");
    assert!(text.contains("\"total\":12"));
    assert!(!text.contains("username"));
    assert!(!text.contains("client_ip"));
    assert!(!text.contains("session_id"));
}
