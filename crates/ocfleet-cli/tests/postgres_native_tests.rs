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
use ocfleet_cli::storage_payloads::TrustBundlePayloadV1;
use ocfleet_cli::store::{
    ApprovalInput, EnrollmentTokenInsert, JoinRequestInsert, LegacyEnrollmentClaimInput,
    NodeInsert, NodeMaintenanceWindow, NodeMetadataRecord, Store,
};
use ocfleet_cli::version_governance::{CapabilityNegotiationStatus, CapabilitySnapshot};
use ocfleet_protocol::method::NODE_CAPABILITIES;
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
        labels_json: json!({"environment": "test"}),
        scope_json: json!({"role": "ocserv"}),
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
        requested_labels_json: json!({"site": "lab-a"}),
    };
    let pending = store
        .submit_join_request(&request, "enrollment-agent")
        .expect("submit native join request");
    assert_eq!(pending.status.as_str(), "pending");
    let approval = ApprovalInput {
        request_id: request.request_id.clone(),
        endpoint_id: enrolled_endpoint.clone(),
        node_id: "node-native-enrolled".into(),
        region: "test".into(),
        role: "ocserv".into(),
        reason: "approved in native integration".into(),
        approved_labels_json: json!({"site": "lab-a", "approved": true}),
    };
    let approved = store
        .approve_join_request(&approval, "enrollment-admin")
        .expect("approve native join request");
    assert_eq!(approved.status.as_str(), "approved");
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
    store
        .claim_legacy_enrollment(&claim, "enrollment-admin")
        .expect("claim native legacy enrollment");
    assert!(
        store
            .get_node(&claim.node_id)
            .expect("get claimed native node")
            .is_some()
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
    let upgraded = connect_native(&source).expect("upgrade native v1 to v2");
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
}
