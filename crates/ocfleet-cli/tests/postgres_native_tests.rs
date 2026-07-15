#![cfg(feature = "postgres-native-experimental")]

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Barrier};
use std::thread;

use ocfleet_cli::audit::AuditEvent;
use ocfleet_cli::backend::MAX_STORE_READER_ROWS;
use ocfleet_cli::postgres_backend::{PostgresConnectionSource, PostgresError};
use ocfleet_cli::postgres_native::{NATIVE_BACKEND_SCHEMA_VERSION, connect_native};
use ocfleet_cli::storage_payloads::{
    AlertDetailPayloadV1, AlertSummaryFieldsV1, HealthDegradedMethodsPayloadV1,
    HealthSummaryPayloadV1, SchedulerSelectorPayloadV1, TrustBundlePayloadV1,
};
use ocfleet_cli::store::{
    AlertDeliveryAttemptRecord, AlertDeliveryQueueEnqueue, AlertDeliveryQueueOutcome,
    AlertEvaluationEntry, AlertEvaluationWrite, AlertEventRecord, AlertWebhookHookRecord,
    ApprovalInput, EnrollmentTokenInsert, HealthEvaluationFinish, HealthEvaluationStart,
    HealthPolicyRecord, HealthRollupRecord, HealthRollupWrite, HealthSnapshotRecord,
    JoinRequestInsert, LegacyEnrollmentClaimInput, NodeInsert, NodeMaintenanceWindow,
    NodeMetadataRecord, ObservabilityJobRecord, ProbeObservationInsert, RetentionApplyInput,
    RetentionPolicyRecord, SchedulerJobClaim, SchedulerJobClockUpdate, SchedulerMaintenanceWindow,
    SchedulerOutcomeEntry, SchedulerOutcomeWrite, SchedulerRunFinish, SchedulerRunStart, Store,
};
use ocfleet_cli::version_governance::{CapabilityNegotiationStatus, CapabilitySnapshot};
use ocfleet_protocol::method::{NODE_CAPABILITIES, PROBE_CONTROLLER_PING};
use serde_json::json;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::SyncRunner;
use testcontainers::{GenericImage, ImageExt};

fn postgres_source(dsn: &str) -> (tempfile::TempDir, PostgresConnectionSource) {
    let dir = tempfile::tempdir().expect("private temp dir");
    #[cfg(unix)]
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("private dir");
    let path = dir.path().join("postgres.toml");
    fs::write(&path, format!("dsn = {dsn:?}\npool_size = 4\n")).expect("write config");
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private config");
    (dir, PostgresConnectionSource::PrivateConfigFile { path })
}

#[test]
fn native_postgres_core_is_relational_atomic_and_future_schema_safe() {
    let container = GenericImage::new("postgres", "17-alpine")
        .with_exposed_port(5432.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_USER", "ocfleet")
        .with_env_var("POSTGRES_PASSWORD", "test-only-password")
        .with_env_var("POSTGRES_DB", "ocfleet_native_test")
        .start()
        .expect("start isolated Postgres");
    let port = container
        .get_host_port_ipv4(5432.tcp())
        .expect("mapped Postgres port");
    let base_dsn =
        format!("postgresql://ocfleet:test-only-password@127.0.0.1:{port}/ocfleet_native_test");
    let mut admin = postgres::Client::connect(&base_dsn, postgres::NoTls).expect("admin client");
    admin
        .batch_execute(
            "CREATE SCHEMA shadow;
             CREATE TABLE public.nodes (foreign_marker TEXT PRIMARY KEY);
             INSERT INTO public.nodes (foreign_marker) VALUES ('unrelated');",
        )
        .expect("install unrelated search-path object");
    let dsn = format!("{base_dsn}?options=-csearch_path%3Dshadow%2Cpublic");
    let (_dir, source) = postgres_source(&dsn);

    let barrier = Arc::new(Barrier::new(3));
    let mut clients = Vec::new();
    for _ in 0..2 {
        let source = source.clone();
        let barrier = Arc::clone(&barrier);
        clients.push(thread::spawn(move || {
            barrier.wait();
            connect_native(&source).expect("contending native migration client")
        }));
    }
    barrier.wait();
    let store = clients.remove(0).join().expect("first native client");
    let second = clients.remove(0).join().expect("second native client");
    assert_eq!(
        store.schema_version().expect("native schema version"),
        NATIVE_BACKEND_SCHEMA_VERSION
    );
    assert_eq!(
        second.schema_version().expect("second schema version"),
        NATIVE_BACKEND_SCHEMA_VERSION
    );
    let node = NodeInsert {
        node_id: "node-native-a".into(),
        endpoint_id: iroh::SecretKey::generate().public().to_string(),
        name: "Native node A".into(),
        region: "test".into(),
        role: "ocserv".into(),
    };
    store.add_node(&node, "operator-a").expect("add node");
    assert_eq!(
        store
            .get_node(&node.node_id)
            .expect("get node")
            .expect("stored node")
            .endpoint_id,
        node.endpoint_id
    );
    assert_eq!(store.list_nodes(10).expect("list nodes").len(), 1);
    assert_eq!(store.audit_count("node.add").expect("audit count"), 1);

    let trust = admin
        .query_one(
            "SELECT status, generation, trust_bundle_json->>'schema'
             FROM ocfleet_native.endpoint_trust WHERE endpoint_id = $1",
            &[&node.endpoint_id],
        )
        .expect("relational trust row");
    assert_eq!(trust.get::<_, String>(0), "active");
    assert_eq!(trust.get::<_, i64>(1), 1);
    assert_eq!(trust.get::<_, String>(2), "ocfleet.trust.bundle.v1");
    let audit_schema: String = admin
        .query_one(
            "SELECT detail_json->'_audit'->>'schema'
             FROM ocfleet_native.controller_audit_log WHERE event = 'node.add'",
            &[],
        )
        .expect("typed audit row")
        .get(0);
    assert_eq!(audit_schema, "ocfleet.audit.detail.v1");

    let metadata = NodeMetadataRecord {
        node_id: node.node_id.clone(),
        environment: "test".into(),
        site: "lab-a".into(),
        owner_team: "platform".into(),
        service_tier: "tier-1".into(),
        labels_json: json!({"purpose": "native-parity"}),
        expected_agent_version: Some("0.3.0".into()),
        updated_at: "2026-07-14T20:00:00.123456+08:00".into(),
    };
    store
        .set_node_metadata(&metadata, "operator-a")
        .expect("set native node metadata");
    let stored_metadata = store
        .get_node_metadata(&node.node_id)
        .expect("get native node metadata")
        .expect("stored native node metadata");
    assert_eq!(stored_metadata.updated_at, "2026-07-14T12:00:00.123456Z");
    assert_eq!(stored_metadata.node_id, metadata.node_id);
    assert_eq!(stored_metadata.labels_json, metadata.labels_json);
    assert_eq!(
        store
            .list_nodes_by_role_limited("ocserv", 10)
            .expect("list native nodes by role")
            .len(),
        1
    );
    assert_eq!(
        store
            .list_nodes_by_metadata_limited("label.purpose", "native-parity", 10)
            .expect("list native nodes by label")
            .len(),
        1
    );
    let maintenance = NodeMaintenanceWindow {
        node_id: node.node_id.clone(),
        starts_at: "2026-07-14T21:00:00.123456+08:00".into(),
        ends_at: "2026-07-14T07:00:00.999999-07:00".into(),
        reason: "native maintenance test".into(),
        updated_at: "2026-07-14T20:00:00.654321+08:00".into(),
    };
    store
        .set_node_maintenance(&maintenance, "operator-a")
        .expect("set native maintenance");
    let stored_maintenance = store
        .get_node_maintenance(&node.node_id)
        .expect("get native maintenance")
        .expect("stored native maintenance");
    assert_eq!(stored_maintenance.starts_at, "2026-07-14T13:00:00.123456Z");
    assert_eq!(stored_maintenance.ends_at, "2026-07-14T14:00:00.999999Z");
    assert_eq!(stored_maintenance.updated_at, "2026-07-14T12:00:00.654321Z");
    assert!(
        store
            .node_maintenance_active_at(&node.node_id, "2026-07-14T21:30:00.5+08:00")
            .expect("check native active maintenance")
    );
    assert!(
        store
            .clear_node_maintenance(&node.node_id, "operator-a")
            .expect("clear native maintenance")
    );

    let capability = CapabilitySnapshot {
        node_id: node.node_id.clone(),
        endpoint_id: node.endpoint_id.clone(),
        observed_at: "2026-07-14T05:01:00.999999-07:00".into(),
        status: CapabilityNegotiationStatus::Compatible,
        agent_version: Some("0.3.0".into()),
        protocol_min: Some(1),
        protocol_max: Some(1),
        ocserv_snapshot_min: Some(2),
        ocserv_snapshot_max: Some(2),
        controlled_writes_compiled: Some(false),
        controlled_writes_locally_enabled: Some(false),
    };
    let mut capability_audit = AuditEvent::new("controller", "node.capability.observe");
    capability_audit.node_id = Some(node.node_id.clone());
    capability_audit.endpoint_id = Some(node.endpoint_id.clone());
    capability_audit.method = Some(NODE_CAPABILITIES.into());
    capability_audit.ok = Some(true);
    capability_audit.detail_json = json!({"result_class": "compatible"});
    store
        .upsert_node_capability_snapshot_with_audit(&capability, &capability_audit)
        .expect("upsert native capability");
    let stored_capability = store
        .get_node_capability_snapshot(&node.node_id)
        .expect("get native capability")
        .expect("stored native capability");
    assert_eq!(stored_capability.observed_at, "2026-07-14T12:01:00.999999Z");
    assert_eq!(stored_capability.node_id, capability.node_id);
    assert_eq!(stored_capability.status, capability.status);
    assert_eq!(
        store
            .list_version_governance_inputs(10)
            .expect("list native version governance inputs")
            .len(),
        1
    );

    for (suffix, node_id) in [("unbound", None), ("missing-node", Some("node-missing"))] {
        let endpoint_id = iroh::SecretKey::generate().public().to_string();
        let payload = TrustBundlePayloadV1::new(
            endpoint_id.clone(),
            1,
            "active".into(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("valid invalid-binding fixture payload")
        .to_value();
        admin
            .execute(
                "INSERT INTO ocfleet_native.endpoint_trust
                 (endpoint_id, node_id, status, generation, trust_bundle_json)
                 VALUES ($1, $2, 'active', 1, CAST($3 AS text)::jsonb)",
                &[&endpoint_id, &node_id, &payload.to_string()],
            )
            .expect("insert invalid rotation binding fixture");
        let destination = iroh::SecretKey::generate().public().to_string();
        assert!(
            store
                .rotate_endpoint(
                    &endpoint_id,
                    &destination,
                    "operator-a",
                    &format!("reject {suffix} rotation"),
                )
                .is_err()
        );
        assert_eq!(
            store
                .get_endpoint_trust(&endpoint_id)
                .expect("load rejected rotation source")
                .expect("rejected rotation source exists")
                .status
                .as_str(),
            "active"
        );
        assert!(
            store
                .get_endpoint_trust(&destination)
                .expect("load rejected rotation destination")
                .is_none()
        );
        admin
            .execute(
                "DELETE FROM ocfleet_native.endpoint_trust WHERE endpoint_id = $1",
                &[&endpoint_id],
            )
            .expect("remove invalid rotation binding fixture");
    }

    let rotated_endpoint = iroh::SecretKey::generate().public().to_string();
    let rotated = store
        .rotate_endpoint(
            &node.endpoint_id,
            &rotated_endpoint,
            "operator-a",
            "scheduled key rotation",
        )
        .expect("rotate native endpoint");
    assert_eq!(rotated.endpoint_id, rotated_endpoint);
    assert_eq!(rotated.generation, 2);
    assert_eq!(
        store
            .get_node(&node.node_id)
            .expect("get rotated native node")
            .expect("rotated node exists")
            .endpoint_id,
        rotated.endpoint_id
    );
    assert_eq!(
        store
            .trust_snapshot(None)
            .expect("native trust snapshot")
            .endpoints
            .len(),
        2
    );
    admin
        .execute(
            "UPDATE ocfleet_native.endpoint_trust
             SET previous_endpoint_id = NULL WHERE endpoint_id = $1",
            &[&rotated_endpoint],
        )
        .expect("corrupt rotation child lineage");
    assert!(
        store
            .rotate_endpoint(
                &node.endpoint_id,
                &rotated_endpoint,
                "operator-a",
                "retry corrupt rotation",
            )
            .is_err()
    );
    admin
        .execute(
            "UPDATE ocfleet_native.endpoint_trust
             SET previous_endpoint_id = $1 WHERE endpoint_id = $2",
            &[&node.endpoint_id, &rotated_endpoint],
        )
        .expect("restore rotation child lineage");
    assert_eq!(
        store
            .rotate_endpoint(
                &node.endpoint_id,
                &rotated_endpoint,
                "operator-a",
                "retry valid rotation",
            )
            .expect("retry valid rotation")
            .endpoint_id,
        rotated_endpoint
    );
    let quarantined = store
        .quarantine_endpoint(&rotated.endpoint_id, "operator-a", "test quarantine")
        .expect("quarantine native endpoint");
    assert_eq!(quarantined.status.as_str(), "quarantined");
    assert!(store.enable_node(&node.node_id, "operator-a").is_err());

    admin
        .batch_execute(
            r#"
CREATE FUNCTION fail_native_node_audit() RETURNS trigger AS $$
BEGIN
  IF NEW.event = 'node.add' THEN
    RAISE EXCEPTION 'injected native audit failure';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER fail_native_node_audit
BEFORE INSERT ON ocfleet_native.controller_audit_log
FOR EACH ROW EXECUTE FUNCTION fail_native_node_audit();
"#,
        )
        .expect("install audit failure trigger");
    let rejected = NodeInsert {
        node_id: "node-native-rollback".into(),
        endpoint_id: iroh::SecretKey::generate().public().to_string(),
        name: "Native rollback node".into(),
        region: "test".into(),
        role: "ocserv".into(),
    };
    assert!(store.add_node(&rejected, "operator-a").is_err());
    assert!(
        store
            .get_node(&rejected.node_id)
            .expect("query rolled back node")
            .is_none()
    );
    let trust_count: i64 = admin
        .query_one(
            "SELECT COUNT(*) FROM ocfleet_native.endpoint_trust WHERE endpoint_id = $1",
            &[&rejected.endpoint_id],
        )
        .expect("rolled back trust query")
        .get(0);
    assert_eq!(trust_count, 0);
    admin
        .batch_execute(
            "DROP TRIGGER fail_native_node_audit ON ocfleet_native.controller_audit_log;
             DROP FUNCTION fail_native_node_audit();",
        )
        .expect("remove audit failure trigger");

    let token_plaintext = "native-enrollment-secret";
    let token = EnrollmentTokenInsert {
        token_id: "tok-native-c1-2".into(),
        token_hash: Store::hash_enrollment_token(token_plaintext),
        expires_at: "2030-01-01T08:00:00+08:00".into(),
        max_uses: 3,
        description: Some("native C1.2 integration".into()),
        labels_json: json!({"environment": "audit-secret-token-label"}),
        scope_json: json!({"role": "audit-secret-token-scope"}),
    };
    let created_token = store
        .create_enrollment_token(&token, "enrollment-admin")
        .expect("create native enrollment token");
    assert_eq!(created_token.used_count, 0);
    assert_eq!(created_token.expires_at, "2030-01-01T00:00:00Z");
    assert_eq!(
        store
            .create_enrollment_token(&token, "enrollment-admin")
            .expect("retry offset native enrollment token")
            .token_id,
        token.token_id
    );
    for (index, (expires_at, canonical)) in [
        ("2030-01-01T00:00:00.123456Z", "2030-01-01T00:00:00.123456Z"),
        (
            "2030-01-01T00:00:00.999999-07:00",
            "2030-01-01T07:00:00.999999Z",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let retry_token = EnrollmentTokenInsert {
            token_id: format!("tok-native-time-{index}"),
            token_hash: Store::hash_enrollment_token(&format!("native-time-secret-{index}")),
            expires_at: expires_at.into(),
            max_uses: 1,
            description: Some("native timestamp retry".into()),
            labels_json: json!({}),
            scope_json: json!({}),
        };
        let created = store
            .create_enrollment_token(&retry_token, "enrollment-admin")
            .expect("create fractional native enrollment token");
        assert_eq!(created.expires_at, canonical);
        assert_eq!(
            store
                .create_enrollment_token(&retry_token, "enrollment-admin")
                .expect("retry fractional native enrollment token")
                .token_id,
            retry_token.token_id
        );
    }

    let enrolled_endpoint = iroh::SecretKey::generate().public().to_string();
    let request = JoinRequestInsert {
        request_id: "join-11111111-1111-4111-8111-111111111111".into(),
        token_plaintext: token_plaintext.into(),
        agent_public_key: "agent-public-key-a".into(),
        fingerprint: "sha256:fingerprint-a".into(),
        requested_endpoint_id: Some(enrolled_endpoint.clone()),
        hostname: "native-a.example.test".into(),
        agent_version: "0.3.0".into(),
        requested_labels_json: json!({"site": "audit-secret-request-label"}),
    };
    let pending = store
        .submit_join_request(&request, "enrollment-agent")
        .expect("submit native join request");
    assert_eq!(pending.status.as_str(), "pending");
    assert_eq!(
        store
            .submit_join_request(&request, "enrollment-agent")
            .expect("same-actor native join retry")
            .request_id,
        request.request_id
    );
    assert!(
        store
            .submit_join_request(&request, "different-enrollment-agent")
            .is_err()
    );
    let approval = ApprovalInput {
        request_id: request.request_id.clone(),
        endpoint_id: enrolled_endpoint.clone(),
        node_id: "node-native-enrolled".into(),
        region: "test".into(),
        role: "ocserv".into(),
        reason: "approved in native integration".into(),
        approved_labels_json: json!({"site": "audit-secret-approved-label", "approved": true}),
    };
    let approved = store
        .approve_join_request(&approval, "enrollment-admin")
        .expect("approve native join request");
    assert_eq!(approved.status.as_str(), "approved");
    assert_eq!(
        store
            .approve_join_request(&approval, "enrollment-admin")
            .expect("retry exact native approval")
            .request_id,
        request.request_id
    );
    let wrong_node_approval = ApprovalInput {
        node_id: node.node_id.clone(),
        ..approval.clone()
    };
    assert!(
        store
            .approve_join_request(&wrong_node_approval, "enrollment-admin")
            .is_err()
    );
    assert_eq!(
        store
            .get_endpoint_trust(&enrolled_endpoint)
            .expect("get enrolled endpoint")
            .expect("enrolled endpoint exists")
            .fingerprint
            .as_deref(),
        Some("sha256:fingerprint-a")
    );
    admin
        .execute(
            "DELETE FROM ocfleet_native.nodes WHERE node_id = $1",
            &[&approval.node_id],
        )
        .expect("remove native node to emulate legacy approved state");
    admin
        .execute(
            "UPDATE ocfleet_native.endpoint_trust SET node_id = NULL WHERE endpoint_id = $1",
            &[&enrolled_endpoint],
        )
        .expect("unbind native legacy endpoint");
    admin
        .execute(
            "UPDATE ocfleet_native.controller_audit_log SET node_id = NULL
             WHERE event = 'enrollment.approve' AND request_id = $1",
            &[&request.request_id],
        )
        .expect("make native approval audit legacy-compatible");
    let claim = LegacyEnrollmentClaimInput {
        request_id: request.request_id.clone(),
        endpoint_id: enrolled_endpoint.clone(),
        node_id: approval.node_id.clone(),
        region: approval.region.clone(),
        role: approval.role.clone(),
        reason: "claim imported legacy binding".into(),
    };
    admin
        .execute(
            "UPDATE ocfleet_native.endpoint_trust SET fingerprint = $1 WHERE endpoint_id = $2",
            &[&"sha256:wrong-legacy-origin", &enrolled_endpoint],
        )
        .expect("corrupt native legacy endpoint origin");
    assert!(
        store
            .claim_legacy_enrollment(&claim, "enrollment-admin")
            .is_err()
    );
    assert!(
        store
            .get_node(&claim.node_id)
            .expect("query rejected native legacy claim")
            .is_none()
    );
    admin
        .execute(
            "UPDATE ocfleet_native.endpoint_trust SET fingerprint = $1 WHERE endpoint_id = $2",
            &[&request.fingerprint, &enrolled_endpoint],
        )
        .expect("restore native legacy endpoint origin");
    let nonempty_legacy_payload = TrustBundlePayloadV1::new(
        enrolled_endpoint.clone(),
        1,
        "active".into(),
        vec!["controller-unexpected".into()],
        Vec::new(),
        Vec::new(),
    )
    .expect("valid nonempty legacy payload")
    .to_value();
    admin
        .execute(
            "UPDATE ocfleet_native.endpoint_trust
             SET trust_bundle_json = CAST($1 AS text)::jsonb WHERE endpoint_id = $2",
            &[&nonempty_legacy_payload.to_string(), &enrolled_endpoint],
        )
        .expect("install nonempty legacy trust bundle");
    assert!(
        store
            .claim_legacy_enrollment(&claim, "enrollment-admin")
            .is_err()
    );
    let empty_legacy_payload = TrustBundlePayloadV1::new(
        enrolled_endpoint.clone(),
        1,
        "active".into(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .expect("valid empty legacy payload")
    .to_value();
    admin
        .execute(
            "UPDATE ocfleet_native.endpoint_trust
             SET trust_bundle_json = CAST($1 AS text)::jsonb WHERE endpoint_id = $2",
            &[&empty_legacy_payload.to_string(), &enrolled_endpoint],
        )
        .expect("restore empty legacy trust bundle");
    store
        .claim_legacy_enrollment(&claim, "enrollment-admin")
        .expect("claim native legacy enrollment");
    assert!(
        store
            .get_node(&claim.node_id)
            .expect("get claimed native node")
            .is_some()
    );
    store
        .claim_legacy_enrollment(&claim, "enrollment-admin")
        .expect("retry exact native legacy claim");
    assert!(
        store
            .claim_legacy_enrollment(&claim, "different-enrollment-admin")
            .is_err()
    );

    let rejected_request = JoinRequestInsert {
        request_id: "join-22222222-2222-4222-8222-222222222222".into(),
        token_plaintext: token_plaintext.into(),
        agent_public_key: "agent-public-key-b".into(),
        fingerprint: "sha256:fingerprint-b".into(),
        requested_endpoint_id: None,
        hostname: "native-b.example.test".into(),
        agent_version: "0.3.0".into(),
        requested_labels_json: json!({}),
    };
    store
        .submit_join_request(&rejected_request, "enrollment-agent")
        .expect("submit rejected native request");
    let rejected_join = store
        .reject_join_request(
            &rejected_request.request_id,
            "enrollment-admin",
            "inventory mismatch",
        )
        .expect("reject native request");
    assert_eq!(rejected_join.status.as_str(), "rejected");
    store
        .reject_join_request(
            &rejected_request.request_id,
            "enrollment-admin",
            "inventory mismatch",
        )
        .expect("retry exact native rejection");
    assert!(
        store
            .reject_join_request(
                &rejected_request.request_id,
                "different-enrollment-admin",
                "inventory mismatch",
            )
            .is_err()
    );
    assert!(
        store
            .reject_join_request(
                &rejected_request.request_id,
                "enrollment-admin",
                "different reason",
            )
            .is_err()
    );

    let expired_plaintext = "native-expired-enrollment-secret";
    let expired_token = EnrollmentTokenInsert {
        token_id: "tok-native-expired".into(),
        token_hash: Store::hash_enrollment_token(expired_plaintext),
        expires_at: "2020-01-01T00:00:00Z".into(),
        max_uses: 1,
        description: Some("native lazy expiry".into()),
        labels_json: json!({}),
        scope_json: json!({}),
    };
    store
        .create_enrollment_token(&expired_token, "enrollment-admin")
        .expect("create expired native token fixture");
    let expired_request = JoinRequestInsert {
        request_id: "join-44444444-4444-4444-8444-444444444444".into(),
        token_plaintext: expired_plaintext.into(),
        agent_public_key: "agent-public-key-expired".into(),
        fingerprint: "sha256:fingerprint-expired".into(),
        requested_endpoint_id: None,
        hostname: "expired.example.test".into(),
        agent_version: "0.3.0".into(),
        requested_labels_json: json!({}),
    };
    admin
        .batch_execute(
            r#"
CREATE FUNCTION fail_native_expiry_rejection_audit() RETURNS trigger AS $$
BEGIN
  IF NEW.event = 'enrollment.token.reject' THEN
    RAISE EXCEPTION 'injected native expiry rejection audit failure';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER fail_native_expiry_rejection_audit
BEFORE INSERT ON ocfleet_native.controller_audit_log
FOR EACH ROW EXECUTE FUNCTION fail_native_expiry_rejection_audit();
"#,
        )
        .expect("install expiry rejection audit failure trigger");
    assert!(
        store
            .submit_join_request(&expired_request, "enrollment-agent")
            .is_err()
    );
    assert_eq!(
        store
            .get_enrollment_token(&expired_token.token_id)
            .expect("load rolled-back expired token")
            .expect("rolled-back expired token exists")
            .status
            .as_str(),
        "active"
    );
    assert_eq!(
        store
            .audit_count("enrollment.token.expire")
            .expect("rolled-back expiry audit count"),
        0
    );
    admin
        .batch_execute(
            "DROP TRIGGER fail_native_expiry_rejection_audit
               ON ocfleet_native.controller_audit_log;
             DROP FUNCTION fail_native_expiry_rejection_audit();",
        )
        .expect("remove expiry rejection audit failure trigger");
    assert!(
        store
            .submit_join_request(&expired_request, "enrollment-agent")
            .is_err()
    );
    assert_eq!(
        store
            .get_enrollment_token(&expired_token.token_id)
            .expect("load lazily expired token")
            .expect("lazily expired token exists")
            .status
            .as_str(),
        "expired"
    );
    assert_eq!(
        store
            .audit_count("enrollment.token.expire")
            .expect("expiry audit count"),
        1
    );
    assert_eq!(
        store
            .audit_count("enrollment.token.reject")
            .expect("enrollment rejection audit count"),
        1
    );

    let rollback_endpoint = iroh::SecretKey::generate().public().to_string();
    let rollback_request = JoinRequestInsert {
        request_id: "join-33333333-3333-4333-8333-333333333333".into(),
        token_plaintext: token_plaintext.into(),
        agent_public_key: "agent-public-key-c".into(),
        fingerprint: "sha256:fingerprint-c".into(),
        requested_endpoint_id: Some(rollback_endpoint.clone()),
        hostname: "native-c.example.test".into(),
        agent_version: "0.3.0".into(),
        requested_labels_json: json!({}),
    };
    store
        .submit_join_request(&rollback_request, "enrollment-agent")
        .expect("submit rollback native request");
    admin
        .batch_execute(
            r#"
CREATE FUNCTION fail_native_approval_audit() RETURNS trigger AS $$
BEGIN
  IF NEW.event = 'enrollment.approve' THEN
    RAISE EXCEPTION 'injected native approval audit failure';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER fail_native_approval_audit
BEFORE INSERT ON ocfleet_native.controller_audit_log
FOR EACH ROW EXECUTE FUNCTION fail_native_approval_audit();
"#,
        )
        .expect("install native approval failure trigger");
    let rollback_approval = ApprovalInput {
        request_id: rollback_request.request_id.clone(),
        endpoint_id: rollback_endpoint.clone(),
        node_id: "node-native-enrollment-rollback".into(),
        region: "test".into(),
        role: "ocserv".into(),
        reason: "exercise atomic rollback".into(),
        approved_labels_json: json!({}),
    };
    assert!(
        store
            .approve_join_request(&rollback_approval, "enrollment-admin")
            .is_err()
    );
    assert_eq!(
        store
            .get_join_request(&rollback_request.request_id)
            .expect("get rolled-back native request")
            .expect("rolled-back native request exists")
            .status
            .as_str(),
        "pending"
    );
    assert!(
        store
            .get_node(&rollback_approval.node_id)
            .expect("get rolled-back enrollment node")
            .is_none()
    );
    assert!(
        store
            .get_endpoint_trust(&rollback_endpoint)
            .expect("get rolled-back enrollment endpoint")
            .is_none()
    );
    admin
        .batch_execute(
            "DROP TRIGGER fail_native_approval_audit ON ocfleet_native.controller_audit_log;
             DROP FUNCTION fail_native_approval_audit();",
        )
        .expect("remove native approval failure trigger");
    let revoked_token = store
        .revoke_enrollment_token(&token.token_id, "enrollment-admin", "integration complete")
        .expect("revoke native enrollment token");
    assert_eq!(revoked_token.status.as_str(), "revoked");
    store
        .revoke_enrollment_token(&token.token_id, "enrollment-admin", "integration complete")
        .expect("retry exact native token revocation");
    assert!(
        store
            .revoke_enrollment_token(
                &token.token_id,
                "different-enrollment-admin",
                "integration complete",
            )
            .is_err()
    );
    assert!(
        store
            .revoke_enrollment_token(&token.token_id, "enrollment-admin", "different reason")
            .is_err()
    );

    let enrollment_audits: String = admin
        .query_one(
            "SELECT COALESCE(string_agg(detail_json::text, E'\\n'), '')
             FROM ocfleet_native.controller_audit_log
             WHERE event LIKE 'enrollment.%'",
            &[],
        )
        .expect("load enrollment audit projections")
        .get(0);
    for secret in [
        "audit-secret-token-label",
        "audit-secret-token-scope",
        "audit-secret-request-label",
        "audit-secret-approved-label",
    ] {
        assert!(
            !enrollment_audits.contains(secret),
            "enrollment audit leaked label/scope value {secret}"
        );
    }

    let scheduler_maintenance = SchedulerMaintenanceWindow {
        starts_at: "2031-01-01T00:00:00.123456Z".into(),
        ends_at: "2031-01-01T01:00:00.654321Z".into(),
        reason: "native scheduler maintenance".into(),
        updated_at: "2030-12-31T23:59:00.111111Z".into(),
    };
    store
        .set_scheduler_maintenance(&scheduler_maintenance, "scheduler-admin")
        .expect("set native scheduler maintenance");
    assert_eq!(
        store
            .get_scheduler_maintenance()
            .expect("get scheduler maintenance")
            .expect("stored scheduler maintenance"),
        scheduler_maintenance
    );
    assert!(
        store
            .scheduler_maintenance_active_at("2031-01-01T00:30:00Z")
            .expect("check scheduler maintenance")
            .is_some()
    );
    assert!(
        store
            .clear_scheduler_maintenance("2031-01-01T01:00:00.654321Z", "scheduler-admin")
            .expect("clear scheduler maintenance")
    );

    let job = ObservabilityJobRecord {
        job_id: "native-controller-ping".into(),
        kind: "controller-ping".into(),
        selector_json: SchedulerSelectorPayloadV1::new(
            format!("node_id={}", node.node_id),
            Some("native C1.3".into()),
        )
        .expect("valid scheduler selector")
        .to_value(),
        pair_selector_json: None,
        interval_seconds: 60,
        jitter_seconds: 5,
        timeout_ms: 5_000,
        enabled: true,
        next_run_at: Some("2020-01-01T00:00:00.123456+00:00".into()),
        last_run_at: None,
        created_at: "2030-12-31T16:00:00.123456-08:00".into(),
        updated_at: "2030-12-31T16:00:00.123456-08:00".into(),
    };
    store
        .insert_observability_job(&job, "scheduler-admin")
        .expect("insert native observability job");
    let stored_job = store
        .get_observability_job(&job.job_id)
        .expect("get native observability job")
        .expect("stored native observability job");
    assert_eq!(stored_job.created_at, "2031-01-01T00:00:00.123456Z");
    assert_eq!(
        store.list_observability_jobs(10).expect("list jobs").len(),
        1
    );

    let contention_job = ObservabilityJobRecord {
        job_id: "native-claim-contention".into(),
        next_run_at: Some("2099-01-01T00:00:00Z".into()),
        ..job.clone()
    };
    store
        .insert_observability_job(&contention_job, "scheduler-admin")
        .expect("insert native contention job");
    let claim_barrier = Arc::new(Barrier::new(3));
    let mut contenders = Vec::new();
    for (client, owner, event_time) in [
        (
            store.clone(),
            "scheduler-contender-a",
            "2000-01-01T00:00:00Z",
        ),
        (
            second.clone(),
            "scheduler-contender-b",
            "2099-01-01T00:00:00Z",
        ),
    ] {
        let job_id = contention_job.job_id.clone();
        let barrier = Arc::clone(&claim_barrier);
        contenders.push(thread::spawn(move || {
            barrier.wait();
            client
                .claim_scheduler_job(&job_id, owner, event_time, 300, owner)
                .expect("contending native claim")
        }));
    }
    claim_barrier.wait();
    let claims = contenders
        .into_iter()
        .map(|contender| contender.join().expect("native claim contender"))
        .collect::<Vec<_>>();
    assert_eq!(claims.iter().filter(|claim| claim.is_some()).count(), 1);
    let contention_claim = claims
        .into_iter()
        .flatten()
        .next()
        .expect("one native contention winner");
    admin
        .execute(
            "UPDATE ocfleet_native.scheduler_job_claims
             SET claimed_at = clock_timestamp() - interval '2 seconds',
                 lease_expires_at = clock_timestamp() - interval '1 second'
             WHERE job_id = $1",
            &[&contention_job.job_id],
        )
        .expect("expire inactive native claim");
    assert!(
        store
            .release_scheduler_job_claim(
                &contention_claim,
                "2099-01-01T00:00:01Z",
                &contention_claim.owner_id,
            )
            .is_err()
    );
    let cleanup_claim = store
        .claim_scheduler_job(
            &contention_job.job_id,
            "scheduler-contention-cleanup",
            "2000-01-01T00:00:00Z",
            300,
            "scheduler-contention-cleanup",
        )
        .expect("take over expired contention claim")
        .expect("contention cleanup claim");
    assert_eq!(cleanup_claim.fence_token, 2);
    store
        .release_scheduler_job_claim(
            &cleanup_claim,
            "2000-01-01T00:00:01Z",
            "scheduler-contention-cleanup",
        )
        .expect("release contention cleanup claim");

    let claim = store
        .claim_next_due_scheduler_job(
            "scheduler-a",
            "2031-01-01T00:00:01.123456Z",
            300,
            "scheduler-a",
        )
        .expect("claim next due native job")
        .expect("due native claim");
    assert_eq!(claim.fence_token, 1);
    let database_time_authoritative: bool = admin
        .query_one(
            "SELECT claimed_at BETWEEN clock_timestamp() - interval '10 seconds'
                                   AND clock_timestamp() + interval '10 seconds'
                    AND lease_expires_at <= clock_timestamp() + interval '301 seconds'
             FROM ocfleet_native.scheduler_job_claims WHERE job_id = $1",
            &[&job.job_id],
        )
        .expect("verify authoritative native claim clock")
        .get(0);
    assert!(database_time_authoritative);
    assert!(
        store
            .claim_scheduler_job(
                &job.job_id,
                "scheduler-b",
                "2031-01-01T00:00:02Z",
                300,
                "scheduler-b",
            )
            .expect("contending native scheduler claim")
            .is_none()
    );
    let start = SchedulerRunStart {
        run_id: "native-run-1".into(),
        job_id: job.job_id.clone(),
        started_at: "2031-01-01T00:00:10.222222Z".into(),
    };
    store
        .write_scheduler_claimed_run_start(&start, &claim, "scheduler-a")
        .expect("start claimed native run");
    let observation = ProbeObservationInsert {
        observation_id: "native-observation-1".into(),
        run_id: Some(start.run_id.clone()),
        node_id: Some(node.node_id.clone()),
        endpoint_id: Some(node.endpoint_id.clone()),
        method: PROBE_CONTROLLER_PING.into(),
        ok: Some(true),
        error_code: None,
        duration_ms: Some(12),
        observed_at: "2031-01-01T00:00:11.333333Z".into(),
        expires_at: Some("2031-02-01T00:00:11.333333Z".into()),
        result_class: "scheduler_summary".into(),
        summary_json: json!({
            "job_id": job.job_id,
            "kind": job.kind,
            "ok": true,
        }),
    };
    let mut outcome_audit = AuditEvent::new("scheduler-a", "scheduler.task.outcome");
    outcome_audit.node_id = observation.node_id.clone();
    outcome_audit.endpoint_id = observation.endpoint_id.clone();
    outcome_audit.method = Some(observation.method.clone());
    outcome_audit.ok = observation.ok;
    outcome_audit.duration_ms = observation.duration_ms;
    outcome_audit.detail_json = json!({"result_class": "scheduler_summary"});
    let outcome = SchedulerOutcomeWrite {
        job_id: job.job_id.clone(),
        run_id: Some(start.run_id.clone()),
        entries: vec![SchedulerOutcomeEntry {
            observation: observation.clone(),
            audit: outcome_audit,
        }],
        job_clock: None,
    };
    let wrong_owner_claim = SchedulerJobClaim {
        owner_id: "scheduler-spoofed".into(),
        ..claim.clone()
    };
    assert!(
        store
            .write_scheduler_outcome(&outcome, &wrong_owner_claim, "scheduler-a")
            .is_err()
    );
    assert!(
        store
            .get_probe_observation(&observation.observation_id)
            .expect("check rejected native observation")
            .is_none()
    );
    store
        .write_scheduler_outcome(&outcome, &claim, "scheduler-a")
        .expect("write native scheduler outcome");
    assert_eq!(
        store
            .retention_candidate_report("observations", Some("2040-01-01T00:00:00Z"), None,)
            .expect("report running-run observation retention")
            .matched_count,
        0
    );
    assert_eq!(
        store
            .retention_candidate_report("observability-runs", Some("2040-01-01T00:00:00Z"), None,)
            .expect("report running-run retention")
            .matched_count,
        0
    );
    let protected_observations = RetentionApplyInput {
        operation_id: "retention-22222222-2222-4222-8222-222222222222".into(),
        scope: "observations".into(),
        cutoff: Some("2040-01-01T00:00:00Z".into()),
        max_age_days: None,
        max_rows: None,
        limit: Some(10),
        batch_size: 10,
    };
    assert_eq!(
        store
            .apply_retention(&protected_observations, "retention-admin")
            .expect("protect running-run observations")
            .rows_deleted,
        0
    );
    let protected_runs = RetentionApplyInput {
        operation_id: "retention-33333333-3333-4333-8333-333333333333".into(),
        scope: "observability-runs".into(),
        ..protected_observations.clone()
    };
    assert_eq!(
        store
            .apply_retention(&protected_runs, "retention-admin")
            .expect("protect running scheduler run")
            .rows_deleted,
        0
    );
    assert!(
        store
            .get_probe_observation(&observation.observation_id)
            .expect("load protected running observation")
            .is_some()
    );
    assert_eq!(
        store
            .get_observability_run(&start.run_id)
            .expect("load protected running run")
            .expect("protected running run exists")
            .status,
        "running"
    );
    let finish = SchedulerRunFinish {
        run_id: start.run_id.clone(),
        finished_at: "2031-01-01T00:00:12.444444Z".into(),
        job_clock: SchedulerJobClockUpdate {
            job_id: job.job_id.clone(),
            next_run_at: "2031-01-01T00:01:12.444444Z".into(),
            last_run_at: "2031-01-01T00:00:12.444444Z".into(),
        },
    };
    let wrong_fence_claim = SchedulerJobClaim {
        fence_token: claim.fence_token + 1,
        ..claim.clone()
    };
    assert!(
        store
            .write_scheduler_run_finish(&finish, &wrong_fence_claim, "scheduler-a")
            .is_err()
    );
    store
        .write_scheduler_run_finish(&finish, &claim, "scheduler-a")
        .expect("finish native scheduler run");
    let stored_run = store
        .get_observability_run(&start.run_id)
        .expect("get native run")
        .expect("stored native run");
    assert_eq!(stored_run.status, "succeeded");
    assert_eq!(stored_run.observation_count, 1);
    assert_eq!(
        store
            .get_probe_observation(&observation.observation_id)
            .expect("get native observation")
            .expect("stored native observation")
            .summary_json["ok"],
        true
    );
    assert_eq!(
        store
            .list_probe_observations_filtered(
                Some(&node.node_id),
                Some(PROBE_CONTROLLER_PING),
                Some("2031-01-01T00:00:00Z"),
                10,
            )
            .expect("filter native observations")
            .len(),
        1
    );

    store
        .release_scheduler_job_claim(&claim, "2031-01-01T00:00:13.555555Z", "scheduler-a")
        .expect("release first native claim");
    let takeover = store
        .claim_scheduler_job(
            &job.job_id,
            "scheduler-b",
            "2031-01-01T00:00:14.666666Z",
            300,
            "scheduler-b",
        )
        .expect("take over released native job")
        .expect("native takeover claim");
    assert_eq!(takeover.fence_token, 2);
    assert!(
        store
            .renew_scheduler_job_claim(&claim, "2031-01-01T00:00:15Z", 300, "scheduler-a",)
            .is_err()
    );
    let abandoned_start = SchedulerRunStart {
        run_id: "native-run-abandoned".into(),
        job_id: job.job_id.clone(),
        started_at: "2031-01-01T00:00:20Z".into(),
    };
    store
        .write_scheduler_claimed_run_start(&abandoned_start, &takeover, "scheduler-b")
        .expect("start native run that will lose its lease");
    assert!(
        store
            .release_scheduler_job_claim(&takeover, "2031-01-01T00:00:21Z", "scheduler-b",)
            .is_err()
    );
    assert_eq!(
        store
            .get_scheduler_job_claim(&job.job_id)
            .expect("load active native claim")
            .expect("active native claim exists")
            .active_run_id
            .as_deref(),
        Some(abandoned_start.run_id.as_str())
    );
    admin
        .execute(
            "UPDATE ocfleet_native.scheduler_job_claims
             SET claimed_at = clock_timestamp() - interval '2 seconds',
                 lease_expires_at = clock_timestamp() - interval '1 second'
             WHERE job_id = $1",
            &[&job.job_id],
        )
        .expect("expire native claim using database time");
    assert!(
        store
            .release_scheduler_job_claim(&takeover, "2031-01-01T00:06:00Z", "scheduler-b",)
            .is_err()
    );
    let recovered_claim = store
        .claim_scheduler_job(
            &job.job_id,
            "scheduler-c",
            "2000-01-01T00:00:00Z",
            300,
            "scheduler-c",
        )
        .expect("take over expired native claim")
        .expect("recovered native claim");
    assert_eq!(recovered_claim.fence_token, 3);
    assert_eq!(
        store
            .get_observability_run(&abandoned_start.run_id)
            .expect("load recovered native run")
            .expect("recovered native run exists")
            .status,
        "failed"
    );
    assert_eq!(
        store
            .audit_count("scheduler.run.recover")
            .expect("count native recovery audit"),
        1
    );

    let policy = RetentionPolicyRecord {
        scope: "observations".into(),
        max_age_days: Some(30),
        max_rows: Some(100),
        updated_at: "2031-01-02T00:00:00.123456Z".into(),
    };
    assert_eq!(
        store
            .set_retention_policy(&policy, "retention-admin")
            .expect("set native retention policy"),
        policy
    );
    let apply = RetentionApplyInput {
        operation_id: "retention-11111111-1111-4111-8111-111111111111".into(),
        scope: "observations".into(),
        cutoff: Some("2031-01-02T00:00:00Z".into()),
        max_age_days: None,
        max_rows: None,
        limit: Some(1),
        batch_size: 1,
    };
    let retention = store
        .apply_retention(&apply, "retention-admin")
        .expect("apply native retention");
    assert_eq!(retention.rows_deleted, 1);
    assert_eq!(
        store
            .apply_retention(&apply, "retention-admin")
            .expect("replay native retention"),
        retention
    );
    assert!(
        store
            .apply_retention(&apply, "different-retention-admin")
            .is_err()
    );

    let health_policy = HealthPolicyRecord {
        stale_window_seconds: 7_200,
        unreachable_consecutive_failures: 4,
        cert_warning_days: 21,
        cert_critical_days: 5,
        updated_at: "2031-01-02T01:00:00.123456+08:00".into(),
    };
    store
        .set_health_policy(&health_policy, "health-controller")
        .expect("set native health policy");
    assert_eq!(
        store.get_health_policy().expect("get native health policy"),
        health_policy
    );
    let health_evaluation_id = "health-eval-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let health_start = HealthEvaluationStart {
        evaluation_id: health_evaluation_id.into(),
        input_watermark: "1".repeat(64),
        policy_version: "2".repeat(64),
        computation_version: "native-c1.4".into(),
        started_at: "2031-01-02T02:00:00.123456+08:00".into(),
    };
    store
        .write_health_evaluation_start(&health_start, "health-controller")
        .expect("start native health evaluation");
    store
        .write_health_evaluation_start(&health_start, "health-controller")
        .expect("replay native health evaluation start");
    let health_snapshot = HealthSnapshotRecord {
        node_id: node.node_id.clone(),
        endpoint_id: Some(node.endpoint_id.clone()),
        computed_at: "2031-01-02T02:00:01.654321+08:00".into(),
        status: "healthy".into(),
        freshness_seconds: Some(1),
        last_success_at: Some("2031-01-02T02:00:01.654321+08:00".into()),
        last_failure_at: None,
        last_error_code: None,
        degraded_methods_json: HealthDegradedMethodsPayloadV1::new(Vec::new())
            .expect("empty degraded methods")
            .to_value(),
        summary_json: HealthSummaryPayloadV1::new(
            Some("test".into()),
            Some("ocserv".into()),
            "healthy".into(),
            Some("active".into()),
            Some(0),
        )
        .expect("health summary")
        .to_value(),
    };
    let health_finish = HealthEvaluationFinish {
        evaluation_id: health_evaluation_id.into(),
        finished_at: "2031-01-02T02:00:02.999999+08:00".into(),
        snapshots: vec![health_snapshot.clone()],
    };
    admin
        .batch_execute(
            r#"
CREATE FUNCTION fail_native_health_audit() RETURNS trigger AS $$
BEGIN
  IF NEW.event = 'health.evaluation.finish' THEN
    RAISE EXCEPTION 'injected native health audit failure';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER fail_native_health_audit
BEFORE INSERT ON ocfleet_native.controller_audit_log
FOR EACH ROW EXECUTE FUNCTION fail_native_health_audit();
"#,
        )
        .expect("install native health audit failure trigger");
    assert!(
        store
            .write_health_evaluation_finish(&health_finish, "health-controller")
            .is_err()
    );
    assert_eq!(
        store
            .get_health_evaluation_run(health_evaluation_id)
            .expect("read rolled-back health evaluation")
            .expect("running health evaluation")
            .status,
        "running"
    );
    assert!(
        store
            .list_health_snapshots(10)
            .expect("read rolled-back health snapshots")
            .is_empty()
    );
    admin
        .batch_execute(
            "DROP TRIGGER fail_native_health_audit ON ocfleet_native.controller_audit_log;
             DROP FUNCTION fail_native_health_audit();",
        )
        .expect("remove native health audit failure trigger");
    store
        .write_health_evaluation_finish(&health_finish, "health-controller")
        .expect("finish native health evaluation");
    let stored_health = store
        .list_health_snapshots(10)
        .expect("list native health snapshots");
    assert_eq!(stored_health.len(), 1);
    assert_eq!(stored_health[0].computed_at, "2031-01-01T18:00:01.654321Z");
    assert_eq!(
        store
            .list_health_history(
                Some(&node.node_id),
                "2031-01-01T17:00:00Z",
                "2031-01-01T19:00:00Z",
                10,
            )
            .expect("list native health history")
            .len(),
        1
    );
    assert!(
        admin
            .execute(
                "UPDATE ocfleet_native.health_history SET status = 'unknown'
                 WHERE evaluation_id = $1 AND node_id = $2",
                &[&health_evaluation_id, &node.node_id],
            )
            .is_err()
    );
    let health_rollup = HealthRollupRecord {
        node_id: node.node_id.clone(),
        bucket_seconds: 300,
        bucket_start: "2031-01-01T18:00:00Z".into(),
        bucket_end: "2031-01-01T18:05:00Z".into(),
        input_watermark: "3".repeat(64),
        health_samples: 1,
        covered_slots: 1,
        expected_slots: 1,
        healthy_count: 1,
        degraded_count: 0,
        unreachable_count: 0,
        stale_count: 0,
        disabled_count: 0,
        unknown_count: 0,
        observation_count: 1,
        observation_error_count: 0,
        duration_sample_count: 1,
        duration_p50_ms: Some(10),
        duration_p95_ms: Some(10),
        cert_warning_count: 0,
        cert_critical_count: 0,
        fingerprint_sample_count: 0,
        fingerprint_change_count: 0,
        computed_at: "2031-01-01T18:05:01Z".into(),
    };
    store
        .write_health_rollups(
            &HealthRollupWrite {
                operation_id: "health-rollup-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
                rows: vec![health_rollup.clone()],
            },
            "health-controller",
        )
        .expect("write native health rollup");
    assert_eq!(
        store
            .list_health_rollups(
                Some(&node.node_id),
                300,
                "2031-01-01T18:00:00Z",
                "2031-01-01T19:00:00Z",
                10,
            )
            .expect("list native health rollups"),
        vec![health_rollup]
    );

    let alert = AlertEventRecord {
        alert_id: "alert-native-a".into(),
        dedupe_key: "node-native-a:unreachable".into(),
        node_id: Some(node.node_id.clone()),
        severity: "critical".into(),
        state: "open".into(),
        reason_code: "NODE_UNREACHABLE".into(),
        first_seen_at: "2031-01-01T18:01:00.123456Z".into(),
        last_seen_at: "2031-01-01T18:02:00.654321Z".into(),
        last_sent_at: None,
        resolved_at: None,
        detail_json: AlertDetailPayloadV1::new(
            vec![PROBE_CONTROLLER_PING.into()],
            AlertSummaryFieldsV1 {
                status: Some("unreachable".into()),
                endpoint_id: Some(node.endpoint_id.clone()),
                consecutive_failures: Some(4),
                ..AlertSummaryFieldsV1::default()
            },
            None,
            None,
            None,
        )
        .expect("alert detail")
        .public_detail(),
    };
    let alert_evaluation = AlertEvaluationWrite {
        evaluation_id: "alert-eval-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
        entries: vec![AlertEvaluationEntry {
            before: None,
            after: alert.clone(),
        }],
    };
    admin
        .batch_execute(
            r#"
CREATE FUNCTION fail_native_alert_audit() RETURNS trigger AS $$
BEGIN
  IF NEW.event = 'alert.evaluate' THEN
    RAISE EXCEPTION 'injected native alert audit failure';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER fail_native_alert_audit
BEFORE INSERT ON ocfleet_native.controller_audit_log
FOR EACH ROW EXECUTE FUNCTION fail_native_alert_audit();
"#,
        )
        .expect("install native alert audit failure trigger");
    assert!(
        store
            .write_alert_evaluation(&alert_evaluation, "alert-controller")
            .is_err()
    );
    assert!(
        store
            .list_alert_events(10)
            .expect("read rolled-back native alerts")
            .is_empty()
    );
    admin
        .batch_execute(
            "DROP TRIGGER fail_native_alert_audit ON ocfleet_native.controller_audit_log;
             DROP FUNCTION fail_native_alert_audit();",
        )
        .expect("remove native alert audit failure trigger");
    store
        .write_alert_evaluation(&alert_evaluation, "alert-controller")
        .expect("write native alert evaluation");
    store
        .write_alert_evaluation(&alert_evaluation, "alert-controller")
        .expect("replay native alert evaluation");
    assert_eq!(
        store.list_alert_events(10).expect("list native alerts"),
        vec![alert.clone()]
    );
    let hook = AlertWebhookHookRecord {
        hook_id: "hook-native-a".into(),
        name: "Native webhook".into(),
        hook_type: "webhook".into(),
        endpoint_url: "https://alerts.example.test/ocfleet".into(),
        endpoint_url_redacted: "https://alerts.example.test/ocfleet".into(),
        endpoint_host: "alerts.example.test".into(),
        host_allow: vec!["alerts.example.test".into()],
        hmac_key_id: "native-hmac-a".into(),
        enabled: true,
        max_attempts: 3,
        timeout_ms: 2_000,
        created_at: "2031-01-01T18:03:00.123456Z".into(),
        updated_at: "2031-01-01T18:03:00.123456Z".into(),
    };
    store
        .write_alert_webhook_hook_create(&hook, "alert-controller")
        .expect("create native alert hook");
    let enqueue = AlertDeliveryQueueEnqueue {
        queue_id: "delivery-queue-native-a".into(),
        alert_id: alert.alert_id.clone(),
        hook_id: hook.hook_id.clone(),
        idempotency_key: "4".repeat(64),
        group_key: "native-critical".into(),
        enqueued_at: "2020-01-01T18:04:00.123456Z".into(),
    };
    store
        .write_alert_delivery_queue_enqueue(&enqueue, "alert-controller")
        .expect("enqueue native alert delivery");
    let delivery_claim = store
        .write_alert_delivery_queue_claim_next(
            "delivery-worker-a",
            "2031-01-01T18:04:01Z",
            300,
            "delivery-worker-a",
        )
        .expect("claim native alert delivery")
        .expect("due native alert delivery");
    assert_eq!(
        store
            .retention_candidate_report("alert-events", Some("2040-01-01T00:00:00Z"), None)
            .expect("report claimed-alert retention")
            .matched_count,
        0
    );
    assert!(
        store
            .write_alert_delivery_queue_renew(
                &delivery_claim,
                "2031-01-01T18:04:02Z",
                300,
                "spoofed-delivery-worker",
            )
            .is_err()
    );
    let mut tampered_delivery_claim = delivery_claim.clone();
    tampered_delivery_claim.group_key = "forged-group".into();
    assert!(
        store
            .write_alert_delivery_queue_renew(
                &tampered_delivery_claim,
                "2031-01-01T18:04:02Z",
                300,
                "delivery-worker-a",
            )
            .is_err()
    );
    let delivery_attempt = AlertDeliveryAttemptRecord {
        attempt_id: "attempt-native-a".into(),
        alert_id: alert.alert_id.clone(),
        hook_id: hook.hook_id.clone(),
        attempt_no: 1,
        attempted_at: delivery_claim.claimed_at.clone(),
        status: "succeeded".into(),
        http_status_class: Some("2xx".into()),
        error_code: None,
        bytes_sent: 256,
    };
    let delivery_outcome = AlertDeliveryQueueOutcome {
        claim: delivery_claim.clone(),
        attempt: delivery_attempt.clone(),
        completed_at: delivery_claim.claimed_at.clone(),
        retry_at: None,
        retryable: false,
        max_attempts: 3,
    };
    assert!(
        store
            .write_alert_delivery_queue_outcome(&delivery_outcome, "spoofed-delivery-worker")
            .is_err()
    );
    store
        .write_alert_delivery_queue_outcome(&delivery_outcome, "delivery-worker-a")
        .expect("finish native alert delivery");
    assert_eq!(
        store
            .list_alert_delivery_attempts(10)
            .expect("list native delivery attempts"),
        vec![delivery_attempt]
    );
    let queue_health = store
        .alert_delivery_queue_health("2031-01-01T18:05:00Z")
        .expect("native delivery queue health");
    assert_eq!(queue_health.succeeded, 1);
    assert_eq!(queue_health.claimed, 0);

    let health_retention = RetentionPolicyRecord {
        scope: "health-history".into(),
        max_age_days: Some(30),
        max_rows: Some(1_000),
        updated_at: "2031-01-02T03:00:00Z".into(),
    };
    assert_eq!(
        store
            .set_retention_policy(&health_retention, "retention-admin")
            .expect("set native health retention policy"),
        health_retention
    );

    admin
        .batch_execute(
            r#"
CREATE FUNCTION fail_native_scheduler_audit() RETURNS trigger AS $$
BEGIN
  IF NEW.event = 'scheduler.job.invalid' THEN
    RAISE EXCEPTION 'injected native scheduler audit failure';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER fail_native_scheduler_audit
BEFORE INSERT ON ocfleet_native.controller_audit_log
FOR EACH ROW EXECUTE FUNCTION fail_native_scheduler_audit();
"#,
        )
        .expect("install native scheduler audit failure trigger");
    let rejected_observation = ProbeObservationInsert {
        observation_id: "native-observation-audit-rollback".into(),
        run_id: None,
        node_id: Some(node.node_id.clone()),
        endpoint_id: Some(node.endpoint_id.clone()),
        method: PROBE_CONTROLLER_PING.into(),
        ok: Some(false),
        error_code: Some("SCHEDULER_JOB_INVALID".into()),
        duration_ms: Some(1),
        observed_at: "2031-01-01T00:07:00Z".into(),
        expires_at: None,
        result_class: "scheduler_summary".into(),
        summary_json: json!({
            "job_id": job.job_id,
            "kind": job.kind,
            "error_code": "SCHEDULER_JOB_INVALID",
            "reason_code": "INJECTED_TEST",
        }),
    };
    let mut rejected_audit = AuditEvent::new("scheduler-c", "scheduler.job.invalid");
    rejected_audit.node_id = rejected_observation.node_id.clone();
    rejected_audit.endpoint_id = rejected_observation.endpoint_id.clone();
    rejected_audit.method = Some(rejected_observation.method.clone());
    rejected_audit.ok = Some(false);
    rejected_audit.error_code = rejected_observation.error_code.clone();
    rejected_audit.duration_ms = rejected_observation.duration_ms;
    rejected_audit.detail_json = json!({"result_class": "scheduler_summary"});
    assert!(
        store
            .write_scheduler_outcome(
                &SchedulerOutcomeWrite {
                    job_id: job.job_id.clone(),
                    run_id: None,
                    entries: vec![SchedulerOutcomeEntry {
                        observation: rejected_observation.clone(),
                        audit: rejected_audit,
                    }],
                    job_clock: None,
                },
                &recovered_claim,
                "scheduler-c",
            )
            .is_err()
    );
    assert!(
        store
            .get_probe_observation(&rejected_observation.observation_id)
            .expect("load rolled-back native observation")
            .is_none()
    );
    admin
        .batch_execute(
            "DROP TRIGGER fail_native_scheduler_audit ON ocfleet_native.controller_audit_log;
             DROP FUNCTION fail_native_scheduler_audit();",
        )
        .expect("remove native scheduler audit failure trigger");

    let mut overflow_tx = admin
        .transaction()
        .expect("start trust overflow transaction");
    let overflow_insert = overflow_tx
        .prepare(
            "INSERT INTO ocfleet_native.endpoint_trust
             (endpoint_id, node_id, status, generation, trust_bundle_json)
             VALUES ($1, NULL, 'revoked', 1, CAST($2 AS text)::jsonb)",
        )
        .expect("prepare trust overflow insert");
    for _ in 0..=MAX_STORE_READER_ROWS {
        let endpoint_id = iroh::SecretKey::generate().public().to_string();
        let payload = TrustBundlePayloadV1::new(
            endpoint_id.clone(),
            1,
            "revoked".into(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("valid overflow trust payload")
        .to_value();
        overflow_tx
            .execute(&overflow_insert, &[&endpoint_id, &payload.to_string()])
            .expect("insert overflow trust row");
    }
    overflow_tx.commit().expect("commit trust overflow rows");
    assert!(matches!(
        store.trust_snapshot(None),
        Err(PostgresError::InvalidState(message))
            if message.contains("trust snapshot exceeds bounded limit")
    ));

    let public_rows: i64 = admin
        .query_one("SELECT COUNT(*) FROM public.nodes", &[])
        .expect("unrelated public nodes table")
        .get(0);
    assert_eq!(public_rows, 1);

    admin
        .execute(
            "UPDATE ocfleet_native.migrations SET name = 'unexpected' WHERE version = 1",
            &[],
        )
        .expect("corrupt migration name");
    assert!(matches!(
        connect_native(&source),
        Err(PostgresError::InvalidState(message))
            if message.contains("migration history is inconsistent")
    ));
    admin
        .execute(
            "UPDATE ocfleet_native.migrations SET name = '0001_native_core' WHERE version = 1",
            &[],
        )
        .expect("restore migration name");

    admin
        .execute(
            "INSERT INTO ocfleet_native.migrations (version, name) VALUES ($1, $2)",
            &[&(NATIVE_BACKEND_SCHEMA_VERSION + 1), &"future_schema"],
        )
        .expect("install future migration marker");
    let row = admin
        .query_one(
            "SELECT
               (SELECT COUNT(*) FROM ocfleet_native.migrations),
               (SELECT COUNT(*) FROM ocfleet_native.nodes),
               (SELECT COUNT(*) FROM ocfleet_native.controller_audit_log)",
            &[],
        )
        .expect("snapshot before rejected connect");
    let before: (i64, i64, i64) = (row.get(0), row.get(1), row.get(2));
    assert!(matches!(
        connect_native(&source),
        Err(PostgresError::UnsupportedBackendSchema(version))
            if version == NATIVE_BACKEND_SCHEMA_VERSION + 1
    ));
    let row = admin
        .query_one(
            "SELECT
               (SELECT COUNT(*) FROM ocfleet_native.migrations),
               (SELECT COUNT(*) FROM ocfleet_native.nodes),
               (SELECT COUNT(*) FROM ocfleet_native.controller_audit_log)",
            &[],
        )
        .expect("snapshot after rejected connect");
    let after: (i64, i64, i64) = (row.get(0), row.get(1), row.get(2));
    assert_eq!(after, before);

    admin
        .batch_execute(
            "DROP SCHEMA ocfleet_native CASCADE;
             CREATE SCHEMA ocfleet_native;
             CREATE TABLE ocfleet_native.nodes (unexpected TEXT);",
        )
        .expect("install incompatible native object");
    assert!(matches!(
        connect_native(&source),
        Err(PostgresError::Database(_))
    ));
    let migrations_created: bool = admin
        .query_one(
            "SELECT to_regclass('ocfleet_native.migrations') IS NOT NULL",
            &[],
        )
        .expect("check rolled-back migration table")
        .get(0);
    assert!(!migrations_created);
    let incompatible_survived: bool = admin
        .query_one(
            "SELECT EXISTS (
               SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'ocfleet_native'
                 AND table_name = 'nodes'
                 AND column_name = 'unexpected'
             )",
            &[],
        )
        .expect("check incompatible object")
        .get(0);
    assert!(incompatible_survived);

    admin
        .batch_execute(
            r#"
DROP SCHEMA ocfleet_native CASCADE;
CREATE SCHEMA ocfleet_native;
CREATE TABLE ocfleet_native.migrations (
  version INTEGER PRIMARY KEY CHECK (version > 0),
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE ocfleet_native.nodes (
  node_id TEXT PRIMARY KEY CHECK (length(node_id) BETWEEN 1 AND 128),
  endpoint_id TEXT NOT NULL UNIQUE CHECK (length(endpoint_id) BETWEEN 1 AND 128),
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  region TEXT NOT NULL CHECK (length(region) BETWEEN 1 AND 64),
  role TEXT NOT NULL CHECK (length(role) BETWEEN 1 AND 64),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE ocfleet_native.endpoint_trust (
  endpoint_id TEXT PRIMARY KEY REFERENCES ocfleet_native.nodes(endpoint_id) ON DELETE CASCADE,
  node_id TEXT NOT NULL UNIQUE REFERENCES ocfleet_native.nodes(node_id) ON DELETE CASCADE,
  fingerprint TEXT,
  status TEXT NOT NULL CHECK (status IN ('active', 'rotated', 'revoked', 'quarantined')),
  generation BIGINT NOT NULL CHECK (generation > 0),
  previous_endpoint_id TEXT,
  rotated_to TEXT,
  trust_bundle_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE ocfleet_native.controller_audit_log (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL,
  actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 128),
  event TEXT NOT NULL CHECK (length(event) BETWEEN 1 AND 128),
  node_id TEXT,
  endpoint_id TEXT,
  method TEXT,
  request_id TEXT,
  params_hash TEXT,
  ok BOOLEAN,
  error_code TEXT,
  duration_ms BIGINT CHECK (duration_ms IS NULL OR duration_ms >= 0),
  detail_json JSONB NOT NULL
);
CREATE INDEX idx_native_audit_ts_id
  ON ocfleet_native.controller_audit_log(ts, id);
INSERT INTO ocfleet_native.migrations (version, name)
VALUES (1, '0001_native_core');
"#,
        )
        .expect("install native v1 schema");
    let upgraded = connect_native(&source).expect("upgrade native v1 to current schema");
    assert_eq!(
        upgraded.schema_version().expect("upgraded native version"),
        NATIVE_BACKEND_SCHEMA_VERSION
    );
    let registry_tables: i64 = admin
        .query_one(
            "SELECT COUNT(*) FROM information_schema.tables
             WHERE table_schema = 'ocfleet_native'
               AND table_name IN (
                 'node_metadata', 'node_maintenance_windows',
                 'node_capability_snapshots', 'enrollment_tokens', 'join_requests'
               )",
            &[],
        )
        .expect("count upgraded registry tables")
        .get(0);
    assert_eq!(registry_tables, 5);
    let scheduler_tables: i64 = admin
        .query_one(
            "SELECT COUNT(*) FROM information_schema.tables
             WHERE table_schema = 'ocfleet_native'
               AND table_name IN (
                 'observability_jobs', 'observability_runs', 'probe_observations',
                 'scheduler_job_claims', 'scheduler_maintenance',
                 'retention_policies', 'retention_operations'
               )",
            &[],
        )
        .expect("count upgraded scheduler tables")
        .get(0);
    assert_eq!(scheduler_tables, 7);
    let health_alert_tables: i64 = admin
        .query_one(
            "SELECT COUNT(*) FROM information_schema.tables
             WHERE table_schema = 'ocfleet_native'
               AND table_name IN (
                 'health_policy', 'health_evaluation_runs', 'health_snapshots',
                 'health_history', 'health_rollups', 'alert_events', 'alert_hooks',
                 'alert_delivery_attempts', 'alert_delivery_queue'
               )",
            &[],
        )
        .expect("count upgraded health and alert tables")
        .get(0);
    assert_eq!(health_alert_tables, 9);
}
