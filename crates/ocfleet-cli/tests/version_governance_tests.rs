use ocfleet_cli::audit::AuditEvent;
use ocfleet_cli::backend::StoreWriter;
use ocfleet_cli::store::{NodeInsert, NodeMetadataRecord, Store};
use ocfleet_cli::version_governance::{
    CapabilityNegotiationStatus, CapabilitySnapshot, CompatibilityStatus, ReadinessStatus,
    VersionGovernanceInput, VersionStatus, build_fleet_version_report,
};
use ocfleet_protocol::constants::PROTOCOL_VERSION;
use ocfleet_protocol::method::NODE_CAPABILITIES;
use rusqlite::Connection;
use serde_json::json;

fn capability(node_id: &str, version: Option<&str>) -> CapabilitySnapshot {
    CapabilitySnapshot {
        node_id: node_id.to_string(),
        endpoint_id: format!("endpoint-{node_id}"),
        observed_at: "2026-07-12T00:00:00Z".to_string(),
        status: CapabilityNegotiationStatus::Compatible,
        agent_version: version.map(str::to_string),
        protocol_min: Some(PROTOCOL_VERSION),
        protocol_max: Some(PROTOCOL_VERSION),
        ocserv_snapshot_min: Some(2),
        ocserv_snapshot_max: Some(2),
        controlled_writes_compiled: Some(false),
        controlled_writes_locally_enabled: Some(false),
    }
}

fn input(node_id: &str, expected: Option<&str>, observed: Option<&str>) -> VersionGovernanceInput {
    VersionGovernanceInput {
        node_id: node_id.to_string(),
        enabled: true,
        expected_agent_version: expected.map(str::to_string),
        capability: observed.map(|version| capability(node_id, Some(version))),
    }
}

#[test]
fn semantic_versions_and_prereleases_drive_expected_policy() {
    let report = build_fleet_version_report(vec![
        input("current", Some("0.4.0"), Some("0.4.0")),
        input("ahead", Some("0.4.0"), Some("0.4.1")),
        input("prerelease", Some("0.4.0"), Some("0.4.0-rc.1")),
        input("invalid-expected", Some("latest"), Some("0.4.0")),
        input("invalid-observed", Some("0.4.0"), Some("dev-build")),
        input("policy-missing", None, Some("0.4.0")),
        input("unknown", Some("0.4.0"), None),
    ])
    .expect("report");

    let by_id = |id: &str| report.nodes.iter().find(|node| node.node_id == id).unwrap();
    assert_eq!(by_id("current").version_status, VersionStatus::Current);
    assert_eq!(by_id("current").readiness, ReadinessStatus::Ready);
    assert_eq!(by_id("ahead").version_status, VersionStatus::Ahead);
    assert_eq!(by_id("prerelease").version_status, VersionStatus::Outdated);
    assert_eq!(
        by_id("invalid-expected").version_status,
        VersionStatus::InvalidExpectedVersion
    );
    assert_eq!(
        by_id("invalid-observed").version_status,
        VersionStatus::InvalidObservedVersion
    );
    assert_eq!(
        by_id("policy-missing").version_status,
        VersionStatus::PolicyMissing
    );
    assert_eq!(
        by_id("unknown").version_status,
        VersionStatus::UnknownVersion
    );
    assert_eq!(report.outdated_count, 1);
    assert_eq!(report.alerts[0].reason_code, "AGENT_VERSION_OUTDATED");
}

#[test]
fn distribution_protocol_provider_and_readiness_are_bounded_and_fail_closed() {
    let mut protocol = capability("protocol", Some("0.4.0"));
    protocol.status = CapabilityNegotiationStatus::IncompatibleProtocol;
    protocol.protocol_min = Some(PROTOCOL_VERSION + 1);
    protocol.protocol_max = Some(PROTOCOL_VERSION + 1);
    let mut provider = capability("provider", Some("0.4.0"));
    provider.ocserv_snapshot_min = Some(3);
    provider.ocserv_snapshot_max = Some(3);
    let mut disabled = input("disabled", Some("0.4.0"), Some("0.3.0"));
    disabled.enabled = false;
    let report = build_fleet_version_report(vec![
        input("ready", Some("0.4.0"), Some("0.4.0")),
        VersionGovernanceInput {
            node_id: "protocol".to_string(),
            enabled: true,
            expected_agent_version: Some("0.4.0".to_string()),
            capability: Some(protocol),
        },
        VersionGovernanceInput {
            node_id: "provider".to_string(),
            enabled: true,
            expected_agent_version: Some("0.4.0".to_string()),
            capability: Some(provider),
        },
        disabled,
    ])
    .expect("report");

    assert_eq!(report.node_count, 4);
    assert_eq!(report.ready_count, 1);
    assert_eq!(report.blocked_count, 2);
    assert_eq!(report.disabled_count, 1);
    assert_eq!(report.protocol_incompatible_count, 1);
    assert_eq!(report.provider_incompatible_count, 1);
    assert_eq!(report.distribution.len(), 2);
    assert_eq!(report.distribution[0].version, "0.3.0");
    assert_eq!(report.distribution[1].version, "0.4.0");
    assert_eq!(report.distribution[1].node_count, 3);
    assert_eq!(report.alert_count, 2);
    assert!(
        report
            .alerts
            .iter()
            .any(|alert| alert.reason_code == "PROTOCOL_INCOMPATIBLE")
    );
    assert!(
        report
            .alerts
            .iter()
            .any(|alert| alert.reason_code == "PROVIDER_SCHEMA_INCOMPATIBLE")
    );
    assert!(report.nodes.iter().all(|node| !node.actions_enabled));
    assert!(!report.actions_enabled);
}

#[test]
fn legacy_unknown_and_sensitive_local_detail_are_not_in_report() {
    let mut legacy = capability("legacy", None);
    legacy.status = CapabilityNegotiationStatus::LegacyUnsupported;
    legacy.protocol_min = None;
    legacy.protocol_max = None;
    legacy.ocserv_snapshot_min = None;
    legacy.ocserv_snapshot_max = None;
    legacy.controlled_writes_compiled = None;
    legacy.controlled_writes_locally_enabled = None;
    legacy.validate().expect("legacy shape");
    let report = build_fleet_version_report(vec![VersionGovernanceInput {
        node_id: "legacy".to_string(),
        enabled: true,
        expected_agent_version: Some("0.4.0".to_string()),
        capability: Some(legacy),
    }])
    .expect("report");
    assert_eq!(
        report.nodes[0].protocol_status,
        CompatibilityStatus::Unknown
    );
    assert_eq!(report.nodes[0].readiness, ReadinessStatus::Unknown);
    let encoded = serde_json::to_string(&report).expect("serialize report");
    for forbidden in [
        "/etc/ocserv",
        "systemctl",
        "command",
        "local_policy",
        "secret",
        "package_manager",
    ] {
        assert!(!encoded.contains(forbidden));
    }
}

#[test]
fn report_rejects_duplicate_or_excessive_node_sets() {
    let duplicate = input("node-a", Some("0.4.0"), Some("0.4.0"));
    assert!(build_fleet_version_report(vec![duplicate.clone(), duplicate]).is_err());
    let oversized = (0..=1_000)
        .map(|index| input(&format!("node-{index:04}"), None, None))
        .collect();
    assert!(build_fleet_version_report(oversized).is_err());
}

#[test]
fn capability_snapshot_and_rpc_audit_commit_atomically() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let store = Store::open(&database).expect("store");
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    StoreWriter::write_node_add(
        &store,
        &NodeInsert {
            node_id: "node-a".to_string(),
            endpoint_id: endpoint_id.clone(),
            name: "node-a".to_string(),
            region: "hk".to_string(),
            role: "ocserv".to_string(),
        },
        "version-test",
    )
    .expect("node");
    StoreWriter::write_node_metadata(
        &store,
        &NodeMetadataRecord {
            node_id: "node-a".to_string(),
            environment: "prod".to_string(),
            site: "hk-1".to_string(),
            owner_team: "network".to_string(),
            service_tier: "tier-1".to_string(),
            labels_json: json!({}),
            expected_agent_version: Some("0.4.0".to_string()),
            updated_at: "2026-07-12T00:00:00Z".to_string(),
        },
        "version-test",
    )
    .expect("metadata");

    let snapshot = CapabilitySnapshot {
        node_id: "node-a".to_string(),
        endpoint_id: endpoint_id.clone(),
        observed_at: "2026-07-12T00:01:00Z".to_string(),
        status: CapabilityNegotiationStatus::Compatible,
        agent_version: Some("0.3.0".to_string()),
        protocol_min: Some(PROTOCOL_VERSION),
        protocol_max: Some(PROTOCOL_VERSION),
        ocserv_snapshot_min: Some(2),
        ocserv_snapshot_max: Some(2),
        controlled_writes_compiled: Some(false),
        controlled_writes_locally_enabled: Some(false),
    };
    let audit = capability_audit(&endpoint_id, "request-1", "2026-07-12T00:01:00Z");
    StoreWriter::write_node_capability_snapshot(&store, &snapshot, &audit)
        .expect("snapshot and audit");
    assert_eq!(
        store
            .get_node_capability_snapshot("node-a")
            .expect("read snapshot")
            .expect("snapshot"),
        snapshot
    );
    let report =
        build_fleet_version_report(store.list_version_governance_inputs(1_000).expect("inputs"))
            .expect("report");
    assert_eq!(report.outdated_count, 1);
    assert_eq!(report.alerts[0].reason_code, "AGENT_VERSION_OUTDATED");

    Connection::open(&database)
        .expect("sqlite")
        .execute_batch(
            "CREATE TRIGGER reject_capability_audit BEFORE INSERT ON controller_audit_log BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;",
        )
        .expect("trigger");
    let mut replacement = snapshot.clone();
    replacement.observed_at = "2026-07-12T00:02:00Z".to_string();
    replacement.agent_version = Some("0.4.0".to_string());
    let audit = capability_audit(&endpoint_id, "request-2", "2026-07-12T00:02:00Z");
    StoreWriter::write_node_capability_snapshot(&store, &replacement, &audit)
        .expect_err("audit failure rolls back snapshot");
    assert_eq!(
        store
            .get_node_capability_snapshot("node-a")
            .expect("read snapshot")
            .expect("snapshot"),
        snapshot
    );
}

fn capability_audit(endpoint_id: &str, request_id: &str, _observed_at: &str) -> AuditEvent {
    let mut event = AuditEvent::new("version-test", "rpc.completed");
    event.node_id = Some("node-a".to_string());
    event.endpoint_id = Some(endpoint_id.to_string());
    event.method = Some(NODE_CAPABILITIES.to_string());
    event.request_id = Some(request_id.to_string());
    event.params_hash = Some("a".repeat(64));
    event.ok = Some(true);
    event.duration_ms = Some(1);
    event.detail_json = json!({
        "result_class": "capability_negotiation",
        "status": "compatible",
        "compatible": true,
        "actions_enabled": false,
        "agent_version": "0.3.0",
        "protocol_min": PROTOCOL_VERSION,
        "protocol_max": PROTOCOL_VERSION,
        "ocserv_snapshot_min": 2,
        "ocserv_snapshot_max": 2,
        "controlled_writes_compiled": false,
        "controlled_writes_locally_enabled": false
    });
    event
}
