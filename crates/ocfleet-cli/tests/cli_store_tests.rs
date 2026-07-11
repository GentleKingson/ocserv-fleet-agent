use ocfleet_cli::audit::AuditEvent;
use ocfleet_cli::backend::StoreWriter;
use ocfleet_cli::doctor::{CheckStatus, DoctorOptions, run_doctor};
use ocfleet_cli::store::{
    ApprovalInput, CURRENT_SCHEMA_VERSION, EnrollmentTokenInsert, JoinRequestInsert,
    JoinRequestRecord, LegacyEnrollmentClaimInput, NodeInsert, Store, StoreError,
};
use ocfleet_protocol::enrollment::{EndpointStatus, EnrollmentTokenStatus, JoinRequestStatus};
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Barrier, Mutex, OnceLock};

const TEST_ACTOR: &str = "store-test";

fn cwd_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct CurrentDirGuard {
    original: std::path::PathBuf,
}

impl CurrentDirGuard {
    fn enter(path: &Path) -> Self {
        let original = std::env::current_dir().expect("current dir");
        std::env::set_current_dir(path).expect("set current dir");
        Self { original }
    }
}

impl Drop for CurrentDirGuard {
    fn drop(&mut self) {
        std::env::set_current_dir(&self.original).expect("restore current dir");
    }
}

fn assert_node_not_found(result: Result<(), StoreError>, expected_node_id: &str) {
    match result {
        Err(StoreError::NodeNotFound(node_id)) => assert_eq!(node_id, expected_node_id),
        other => panic!("expected NodeNotFound for {expected_node_id}, got {other:?}"),
    }
}

#[test]
fn initializes_schema_and_migration_version() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    assert_eq!(
        store.current_schema_version().expect("version"),
        CURRENT_SCHEMA_VERSION
    );
}

#[test]
fn endpoint_trust_writes_versioned_bundle_and_reader_rejects_contamination() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let node = seed_generated_node(&store, "typed-trust-bundle-node");
    let conn = Connection::open(&db).expect("open database");
    let raw: String = conn
        .query_row(
            "SELECT trust_bundle_json FROM endpoint_trust WHERE endpoint_id = ?1",
            [node.endpoint_id.as_str()],
            |row| row.get(0),
        )
        .expect("read stored trust bundle");
    let mut raw: serde_json::Value = serde_json::from_str(&raw).expect("typed trust bundle");
    assert_eq!(raw["schema"], "ocfleet.trust.bundle.v1");
    assert_eq!(raw["endpoint_id"], node.endpoint_id);
    raw["client_address"] = serde_json::json!("10.0.0.2");
    conn.execute(
        "UPDATE endpoint_trust SET trust_bundle_json = ?1 WHERE endpoint_id = ?2",
        rusqlite::params![raw.to_string(), node.endpoint_id],
    )
    .expect("contaminate trust bundle");

    let error = store
        .get_endpoint_trust(&node.endpoint_id)
        .expect_err("contaminated trust bundle must fail closed");
    assert!(error.to_string().contains("trust bundle"));
    assert!(!error.to_string().contains("10.0.0.2"));
}

#[test]
fn open_with_status_reports_database_creation() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");

    let first = Store::open_with_status(&db).expect("create store with status");
    assert!(first.created_database);
    assert_eq!(
        first.store.current_schema_version().expect("version"),
        CURRENT_SCHEMA_VERSION
    );
    drop(first);

    let second = Store::open_with_status(&db).expect("reopen store with status");
    assert!(!second.created_database);
    assert_eq!(
        second.store.current_schema_version().expect("version"),
        CURRENT_SCHEMA_VERSION
    );
}

#[test]
fn open_with_status_supports_single_file_relative_path() {
    let _guard = cwd_lock().lock().expect("cwd lock");
    let dir = tempfile::tempdir().expect("temp dir");
    let _cwd = CurrentDirGuard::enter(dir.path());
    let path = Path::new("controller.sqlite");

    let opened = Store::open_with_status(path).expect("open relative store");

    assert!(opened.created_database);
    assert!(dir.path().join(path).is_file());
}

#[cfg(unix)]
#[test]
fn open_with_status_rejects_single_file_relative_path_in_unsafe_current_directory() {
    use std::os::unix::fs::PermissionsExt;

    let _guard = cwd_lock().lock().expect("cwd lock");
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777))
        .expect("chmod unsafe cwd");
    let _cwd = CurrentDirGuard::enter(dir.path());

    let result = Store::open_with_status(Path::new("controller.sqlite"));

    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("restore tempdir permissions");
    assert!(matches!(result, Err(StoreError::UnsafePermissions)));
}

#[cfg(unix)]
#[test]
fn open_with_status_creates_private_database_and_parent_directory() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("state").join("controller.sqlite");

    let opened = Store::open_with_status(&db).expect("open store");
    drop(opened);

    let db_mode = std::fs::metadata(&db)
        .expect("db metadata")
        .permissions()
        .mode()
        & 0o777;
    let parent_mode = std::fs::metadata(db.parent().expect("parent"))
        .expect("parent metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(db_mode, 0o600);
    assert_eq!(parent_mode, 0o700);

    for sidecar in [
        db.with_extension("sqlite-wal"),
        db.with_extension("sqlite-shm"),
    ] {
        if sidecar.exists() {
            let mode = std::fs::metadata(&sidecar)
                .expect("sidecar metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode & 0o077, 0);
        }
    }
}

#[cfg(unix)]
#[test]
fn open_with_status_rejects_existing_world_readable_database() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    std::fs::write(&db, b"").expect("write db placeholder");
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).expect("chmod");

    assert!(Store::open_with_status(&db).is_err());
}

#[cfg(unix)]
#[test]
fn open_with_status_rejects_final_path_symlink() {
    let dir = tempfile::tempdir().expect("temp dir");
    let real_db = dir.path().join("real.sqlite");
    let link_db = dir.path().join("controller.sqlite");
    std::fs::write(&real_db, b"").expect("write real db placeholder");
    std::os::unix::fs::symlink(&real_db, &link_db).expect("symlink");

    assert!(Store::open_with_status(&link_db).is_err());
}

#[cfg(unix)]
#[test]
fn open_with_status_rejects_existing_database_with_hardlink() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let opened = Store::open_with_status(&db).expect("create store");
    drop(opened);

    let hardlink = dir.path().join("controller-copy.sqlite");
    std::fs::hard_link(&db, &hardlink).expect("create hardlink");

    assert!(Store::open_with_status(&db).is_err());
}

#[cfg(unix)]
#[test]
fn open_with_status_rejects_unsafe_existing_wal_or_shm_sidecar() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let opened = Store::open_with_status(&db).expect("create store");
    drop(opened);

    let wal = db.with_extension("sqlite-wal");
    std::fs::write(&wal, b"unsafe wal").expect("write wal");
    std::fs::set_permissions(&wal, std::fs::Permissions::from_mode(0o644)).expect("chmod wal");

    assert!(Store::open_with_status(&db).is_err());
}

#[cfg(unix)]
#[test]
fn open_with_status_rejects_existing_sidecar_with_hardlink() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let opened = Store::open_with_status(&db).expect("create store");
    drop(opened);

    let wal = db.with_extension("sqlite-wal");
    std::fs::write(&wal, b"private wal").expect("write wal");
    std::fs::set_permissions(&wal, std::fs::Permissions::from_mode(0o600)).expect("chmod wal");
    let hardlink = dir.path().join("controller-copy.sqlite-wal");
    std::fs::hard_link(&wal, &hardlink).expect("create sidecar hardlink");

    assert!(Store::open_with_status(&db).is_err());
}

#[cfg(unix)]
#[test]
fn open_with_status_rejects_existing_sidecar_symlink() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let opened = Store::open_with_status(&db).expect("create store");
    drop(opened);

    let wal = db.with_extension("sqlite-wal");
    let target = dir.path().join("missing-wal-target");
    std::os::unix::fs::symlink(&target, &wal).expect("symlink wal");

    assert!(Store::open_with_status(&db).is_err());
}

#[test]
fn node_endpoint_id_must_be_unique() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let first = NodeInsert {
        node_id: "hk-ocserv-01".into(),
        endpoint_id: "endpoint-one".into(),
        name: "hk-ocserv-01".into(),
        region: "hk".into(),
        role: "ocserv".into(),
    };
    let second = NodeInsert {
        node_id: "hk-ocserv-02".into(),
        endpoint_id: "endpoint-one".into(),
        name: "hk-ocserv-02".into(),
        region: "hk".into(),
        role: "ocserv".into(),
    };
    store.add_node(&first, TEST_ACTOR).expect("first insert");
    assert!(store.add_node(&second, TEST_ACTOR).is_err());
}

#[test]
fn disabled_node_is_visible_but_not_enabled() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let node = NodeInsert {
        node_id: "hk-ocserv-01".into(),
        endpoint_id: "endpoint-one".into(),
        name: "hk-ocserv-01".into(),
        region: "hk".into(),
        role: "ocserv".into(),
    };
    store.add_node(&node, TEST_ACTOR).expect("insert");
    store
        .disable_node("hk-ocserv-01", TEST_ACTOR)
        .expect("disable");
    let loaded = store
        .get_node("hk-ocserv-01")
        .expect("load")
        .expect("exists");
    assert!(!loaded.enabled);
}

#[test]
fn missing_node_mutations_return_node_not_found() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");

    assert_node_not_found(
        store.disable_node("missing-disable", TEST_ACTOR),
        "missing-disable",
    );
    assert_node_not_found(
        store.enable_node("missing-enable", TEST_ACTOR),
        "missing-enable",
    );
    assert_node_not_found(
        store.remove_node("missing-remove", TEST_ACTOR),
        "missing-remove",
    );
}

#[test]
fn node_lifecycle_writes_actor_bound_before_after_audit() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let node = NodeInsert {
        node_id: "hk-ocserv-01".into(),
        endpoint_id: "endpoint-one".into(),
        name: "hk-ocserv-01".into(),
        region: "hk".into(),
        role: "ocserv".into(),
    };

    StoreWriter::write_node_add(&store, &node, "alice").expect("add node");
    let (actor, event, node_id, endpoint_id, detail) = latest_node_audit(&db);
    assert_eq!(actor, "alice");
    assert_eq!(event, "node.add");
    assert_eq!(node_id.as_deref(), Some("hk-ocserv-01"));
    assert_eq!(endpoint_id.as_deref(), Some("endpoint-one"));
    assert_eq!(detail["actor_type"], "user");
    assert_eq!(detail["target_type"], "node");
    assert_eq!(detail["target_id"], "hk-ocserv-01");
    assert_eq!(detail["before"], serde_json::Value::Null);
    assert_eq!(detail["after"]["enabled"], true);
    assert_eq!(detail["reason"], serde_json::Value::Null);
    assert!(detail["after"].get("name").is_none());

    StoreWriter::write_node_disable(&store, "hk-ocserv-01", "bob").expect("disable node");
    let (actor, event, _, _, detail) = latest_node_audit(&db);
    assert_eq!(actor, "bob");
    assert_eq!(event, "node.disable");
    assert_eq!(detail["before"]["enabled"], true);
    assert_eq!(detail["after"]["enabled"], false);

    StoreWriter::write_node_enable(&store, "hk-ocserv-01", "carol").expect("enable node");
    let (actor, event, _, _, detail) = latest_node_audit(&db);
    assert_eq!(actor, "carol");
    assert_eq!(event, "node.enable");
    assert_eq!(detail["before"]["enabled"], false);
    assert_eq!(detail["after"]["enabled"], true);

    StoreWriter::write_node_remove(&store, "hk-ocserv-01", "dave").expect("remove node");
    let (actor, event, _, _, detail) = latest_node_audit(&db);
    assert_eq!(actor, "dave");
    assert_eq!(event, "node.remove");
    assert_eq!(detail["before"]["node"]["node_id"], "hk-ocserv-01");
    assert_eq!(detail["before"]["registry_endpoint"]["status"], "active");
    assert_eq!(detail["after"]["node"], serde_json::Value::Null);
    assert_eq!(detail["after"]["registry_endpoint"]["status"], "revoked");
    assert_eq!(detail["after"]["active_endpoint"]["status"], "revoked");
}

#[test]
fn node_add_rolls_back_registry_and_trust_when_audit_insert_fails() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    inject_audit_insert_failure(&db);
    let node = NodeInsert {
        node_id: "hk-ocserv-01".into(),
        endpoint_id: "endpoint-one".into(),
        name: "hk-ocserv-01".into(),
        region: "hk".into(),
        role: "ocserv".into(),
    };

    assert!(matches!(
        StoreWriter::write_node_add(&store, &node, TEST_ACTOR),
        Err(StoreError::Sqlite(_))
    ));
    assert!(store.get_node(&node.node_id).expect("load node").is_none());
    assert!(
        store
            .get_endpoint_trust(&node.endpoint_id)
            .expect("load endpoint trust")
            .is_none()
    );
    assert_eq!(store.audit_count().expect("audit count"), 0);
}

#[test]
fn node_state_and_remove_drop_transaction_when_audit_insert_fails() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let node = NodeInsert {
        node_id: "hk-ocserv-01".into(),
        endpoint_id: "endpoint-one".into(),
        name: "hk-ocserv-01".into(),
        region: "hk".into(),
        role: "ocserv".into(),
    };
    StoreWriter::write_node_add(&store, &node, TEST_ACTOR).expect("seed node");
    let endpoint_before = store
        .get_endpoint_trust(&node.endpoint_id)
        .expect("load endpoint trust")
        .expect("endpoint exists");
    inject_audit_insert_failure(&db);

    assert!(matches!(
        StoreWriter::write_node_disable(&store, &node.node_id, TEST_ACTOR),
        Err(StoreError::Sqlite(_))
    ));
    assert!(
        store
            .get_node(&node.node_id)
            .expect("load node")
            .expect("node exists")
            .enabled
    );

    assert!(matches!(
        StoreWriter::write_node_remove(&store, &node.node_id, TEST_ACTOR),
        Err(StoreError::Sqlite(_))
    ));
    assert!(store.get_node(&node.node_id).expect("load node").is_some());
    assert_eq!(
        store
            .get_endpoint_trust(&node.endpoint_id)
            .expect("load endpoint trust")
            .expect("endpoint exists"),
        endpoint_before
    );
    assert_eq!(store.audit_count().expect("audit count"), 1);
}

#[test]
fn audit_ok_can_be_null_for_started_events() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let event = AuditEvent::new("local-cli", "rpc.started");
    store.insert_audit(&event).expect("audit insert");
    assert_eq!(store.audit_count().expect("count"), 1);
}

#[test]
fn removed_node_does_not_remove_audit_rows() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let node = NodeInsert {
        node_id: "hk-ocserv-01".into(),
        endpoint_id: "endpoint-one".into(),
        name: "hk-ocserv-01".into(),
        region: "hk".into(),
        role: "ocserv".into(),
    };
    store.add_node(&node, TEST_ACTOR).expect("insert");
    store
        .remove_node("hk-ocserv-01", TEST_ACTOR)
        .expect("remove");
    assert!(store.get_node("hk-ocserv-01").expect("load").is_none());
    let endpoint = store
        .get_endpoint_trust(&node.endpoint_id)
        .expect("load endpoint")
        .expect("endpoint tombstone exists");
    assert_eq!(endpoint.status, EndpointStatus::Revoked);
    assert_eq!(endpoint.generation, 2);
    assert_eq!(store.audit_count().expect("count"), 2);
}

fn future_time() -> String {
    "2099-01-01T00:00:00Z".to_string()
}

fn past_time() -> String {
    "2000-01-01T00:00:00Z".to_string()
}

fn generated_endpoint_id() -> String {
    iroh::SecretKey::generate().public().to_string()
}

fn seed_generated_node(store: &Store, node_id: &str) -> NodeInsert {
    let node = NodeInsert {
        node_id: node_id.to_string(),
        endpoint_id: generated_endpoint_id(),
        name: node_id.to_string(),
        region: "test".to_string(),
        role: "ocserv".to_string(),
    };
    StoreWriter::write_node_add(store, &node, TEST_ACTOR).expect("seed generated node");
    node
}

fn trust_bundle_fixture(endpoint_id: &str, generation: u64, status: EndpointStatus) -> String {
    serde_json::json!({
        "schema": "ocfleet.trust.bundle.v1",
        "endpoint_id": endpoint_id,
        "generation": generation,
        "status": status.as_str(),
        "trusted_controllers": [],
        "trusted_peers": [],
        "authorized_path_probes": [],
    })
    .to_string()
}

fn insert_active_endpoint_fixture(database: &Path, endpoint_id: &str, node_id: &str) {
    Connection::open(database)
        .expect("open database for endpoint fixture")
        .execute(
            "INSERT INTO endpoint_trust
             (endpoint_id, node_id, fingerprint, status, generation, previous_endpoint_id, rotated_to, trust_bundle_json, created_at, updated_at)
             VALUES (?1, ?2, NULL, 'active', 1, NULL, NULL, ?3, '2026-07-11T00:00:00Z', '2026-07-11T00:00:00Z')",
            rusqlite::params![
                endpoint_id,
                node_id,
                trust_bundle_fixture(endpoint_id, 1, EndpointStatus::Active),
            ],
        )
        .expect("insert active endpoint fixture");
}

fn latest_audit_event(database: &Path) -> (String, serde_json::Value) {
    let conn = Connection::open(database).expect("open db");
    let (event, detail): (String, String) = conn
        .query_row(
            "SELECT event, detail_json FROM controller_audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("latest audit");
    (
        event,
        serde_json::from_str(&detail).expect("parse audit detail"),
    )
}

fn latest_node_audit(
    database: &Path,
) -> (
    String,
    String,
    Option<String>,
    Option<String>,
    serde_json::Value,
) {
    let conn = Connection::open(database).expect("open db");
    let (actor, event, node_id, endpoint_id, detail): (
        String,
        String,
        Option<String>,
        Option<String>,
        String,
    ) = conn
        .query_row(
            "SELECT actor, event, node_id, endpoint_id, detail_json FROM controller_audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .expect("latest node audit");
    (
        actor,
        event,
        node_id,
        endpoint_id,
        serde_json::from_str(&detail).expect("parse audit detail"),
    )
}

fn inject_audit_insert_failure(database: &Path) {
    let conn = Connection::open(database).expect("open db for audit failure injection");
    // ABORT fails only the audit statement; the writer transaction must roll back on drop.
    conn.execute_batch(
        "CREATE TRIGGER fail_controller_audit_insert
         BEFORE INSERT ON controller_audit_log
         BEGIN
           SELECT RAISE(ABORT, 'injected audit insert failure');
         END;",
    )
    .expect("install audit failure trigger");
}

fn inject_audit_event_failure(database: &Path, event: &str) {
    assert!(matches!(
        event,
        "enrollment.token.reject" | "enrollment.token.expire"
    ));
    let conn = Connection::open(database).expect("open db for audit failure injection");
    conn.execute_batch(&format!(
        "CREATE TRIGGER fail_selected_controller_audit_insert
         BEFORE INSERT ON controller_audit_log
         WHEN NEW.event = '{event}'
         BEGIN
           SELECT RAISE(ABORT, 'injected selected audit insert failure');
         END;"
    ))
    .expect("install selected audit failure trigger");
}

fn seed_pending_enrollment(
    store: &Store,
    token_id: &str,
    token_plaintext: &str,
    requested_endpoint_id: Option<String>,
) -> JoinRequestRecord {
    store
        .create_enrollment_token(
            &EnrollmentTokenInsert {
                token_id: token_id.to_string(),
                token_hash: Store::hash_enrollment_token(token_plaintext),
                expires_at: future_time(),
                max_uses: 1,
                description: None,
                labels_json: serde_json::json!({}),
                scope_json: serde_json::json!({}),
            },
            "operator",
        )
        .expect("create enrollment token");
    store
        .submit_join_request(
            &JoinRequestInsert {
                request_id: format!("join-{}", uuid::Uuid::new_v4()),
                token_plaintext: token_plaintext.to_string(),
                agent_public_key: "agent-public-key".to_string(),
                fingerprint: "agent-fingerprint".to_string(),
                requested_endpoint_id,
                hostname: "agent-self-reported.example".to_string(),
                agent_version: "0.2.0".to_string(),
                requested_labels_json: serde_json::json!({"node_id": "must-not-be-used"}),
            },
            "agent",
        )
        .expect("create pending join request")
}

fn approval_input(request_id: &str, endpoint_id: &str, node_id: &str) -> ApprovalInput {
    ApprovalInput {
        request_id: request_id.to_string(),
        endpoint_id: endpoint_id.to_string(),
        node_id: node_id.to_string(),
        region: "hk".to_string(),
        role: "ocserv".to_string(),
        reason: "ticket-123".to_string(),
        approved_labels_json: serde_json::json!({}),
    }
}

fn enrollment_token_input(
    token_id: &str,
    token_plaintext: &str,
    expires_at: &str,
) -> EnrollmentTokenInsert {
    EnrollmentTokenInsert {
        token_id: token_id.to_string(),
        token_hash: Store::hash_enrollment_token(token_plaintext),
        expires_at: expires_at.to_string(),
        max_uses: 1,
        description: Some("operator enrollment".to_string()),
        labels_json: serde_json::json!({}),
        scope_json: serde_json::json!({}),
    }
}

fn join_request_input(request_id: &str, token_plaintext: &str) -> JoinRequestInsert {
    JoinRequestInsert {
        request_id: request_id.to_string(),
        token_plaintext: token_plaintext.to_string(),
        agent_public_key: "agent-public-key".to_string(),
        fingerprint: "agent-fingerprint".to_string(),
        requested_endpoint_id: None,
        hostname: "agent-supplied.example".to_string(),
        agent_version: "0.2.0".to_string(),
        requested_labels_json: serde_json::json!({}),
    }
}

fn legacy_claim_input(
    request_id: &str,
    endpoint_id: &str,
    node_id: &str,
) -> LegacyEnrollmentClaimInput {
    LegacyEnrollmentClaimInput {
        request_id: request_id.to_string(),
        endpoint_id: endpoint_id.to_string(),
        node_id: node_id.to_string(),
        region: "hk".to_string(),
        role: "ocserv".to_string(),
        reason: "legacy reconciliation".to_string(),
    }
}

fn make_approved_binding_legacy_unbound(database: &Path, node_id: &str, endpoint_id: &str) {
    let conn = Connection::open(database).expect("open database for legacy fixture");
    let deleted = conn
        .execute("DELETE FROM nodes WHERE node_id = ?1", [node_id])
        .expect("remove node from legacy fixture");
    assert_eq!(deleted, 1);
    let updated = conn
        .execute(
            "UPDATE endpoint_trust SET node_id = NULL WHERE endpoint_id = ?1",
            [endpoint_id],
        )
        .expect("make endpoint trust legacy unbound");
    assert_eq!(updated, 1);
    let updated_audit = conn
        .execute(
            "UPDATE controller_audit_log
             SET node_id = NULL
             WHERE event = 'enrollment.approve' AND endpoint_id = ?1",
            [endpoint_id],
        )
        .expect("make approval audit match legacy unbound shape");
    assert_eq!(updated_audit, 1);
}

fn audit_event_count(database: &Path, event: &str) -> i64 {
    Connection::open(database)
        .expect("open database for audit count")
        .query_row(
            "SELECT COUNT(*) FROM controller_audit_log WHERE event = ?1",
            [event],
            |row| row.get(0),
        )
        .expect("count audit events")
}

#[test]
fn enrollment_token_is_hash_only_and_use_creates_pending_join_request() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let token_plaintext = "ocfleet_enroll_test_secret";
    let token_hash = Store::hash_enrollment_token(token_plaintext);

    store
        .create_enrollment_token(
            &EnrollmentTokenInsert {
                token_id: "tok-1".to_string(),
                token_hash: token_hash.clone(),
                expires_at: future_time(),
                max_uses: 1,
                description: Some("prod node onboarding".to_string()),
                labels_json: serde_json::json!({"env": "prod"}),
                scope_json: serde_json::json!({"region": "hk"}),
            },
            "operator",
        )
        .expect("token created");

    let stored = store
        .get_enrollment_token("tok-1")
        .expect("load token")
        .expect("token exists");
    assert_eq!(stored.token_hash, token_hash);
    assert_ne!(stored.token_hash, token_plaintext);
    assert_eq!(stored.status, EnrollmentTokenStatus::Active);
    assert_eq!(stored.used_count, 0);

    let join = store
        .submit_join_request(
            &JoinRequestInsert {
                request_id: format!("join-{}", uuid::Uuid::new_v4()),
                token_plaintext: token_plaintext.to_string(),
                agent_public_key: "agent-public-key".to_string(),
                fingerprint: "agent-fingerprint".to_string(),
                requested_endpoint_id: None,
                hostname: "hk-ocserv-01".to_string(),
                agent_version: "0.1.0".to_string(),
                requested_labels_json: serde_json::json!({"role": "ocserv"}),
            },
            "agent",
        )
        .expect("join request created");

    assert_eq!(join.token_id, "tok-1");
    assert_eq!(join.status, JoinRequestStatus::Pending);
    assert_eq!(join.hostname, "hk-ocserv-01");

    let stored_after_use = store
        .get_enrollment_token("tok-1")
        .expect("load token after use")
        .expect("token exists");
    assert_eq!(stored_after_use.used_count, 1);
}

#[test]
fn enrollment_token_rejects_expired_or_overused_tokens_and_audits_rejection() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let token_plaintext = "ocfleet_enroll_single_use";

    store
        .create_enrollment_token(
            &EnrollmentTokenInsert {
                token_id: "tok-1".to_string(),
                token_hash: Store::hash_enrollment_token(token_plaintext),
                expires_at: future_time(),
                max_uses: 1,
                description: None,
                labels_json: serde_json::json!({}),
                scope_json: serde_json::json!({}),
            },
            "operator",
        )
        .expect("token created");
    store
        .submit_join_request(
            &JoinRequestInsert {
                request_id: format!("join-{}", uuid::Uuid::new_v4()),
                token_plaintext: token_plaintext.to_string(),
                agent_public_key: "agent-public-key".to_string(),
                fingerprint: "agent-fingerprint".to_string(),
                requested_endpoint_id: None,
                hostname: "hk-ocserv-01".to_string(),
                agent_version: "0.1.0".to_string(),
                requested_labels_json: serde_json::json!({}),
            },
            "agent",
        )
        .expect("first use succeeds");

    let second_use = store.submit_join_request(
        &JoinRequestInsert {
            request_id: format!("join-{}", uuid::Uuid::new_v4()),
            token_plaintext: token_plaintext.to_string(),
            agent_public_key: "agent-public-key-2".to_string(),
            fingerprint: "agent-fingerprint-2".to_string(),
            requested_endpoint_id: None,
            hostname: "hk-ocserv-02".to_string(),
            agent_version: "0.1.0".to_string(),
            requested_labels_json: serde_json::json!({}),
        },
        "agent",
    );
    assert!(matches!(second_use, Err(StoreError::EnrollmentRejected(_))));

    let (event, detail) = latest_audit_event(&db);
    assert_eq!(event, "enrollment.token.reject");
    assert_eq!(detail["reason"], "max_uses_exhausted");

    store
        .create_enrollment_token(
            &EnrollmentTokenInsert {
                token_id: "tok-expired".to_string(),
                token_hash: Store::hash_enrollment_token("expired-token"),
                expires_at: past_time(),
                max_uses: 1,
                description: None,
                labels_json: serde_json::json!({}),
                scope_json: serde_json::json!({}),
            },
            "operator",
        )
        .expect("expired token inserted for test");

    let expired = store.submit_join_request(
        &JoinRequestInsert {
            request_id: format!("join-{}", uuid::Uuid::new_v4()),
            token_plaintext: "expired-token".to_string(),
            agent_public_key: "agent-public-key-3".to_string(),
            fingerprint: "agent-fingerprint-3".to_string(),
            requested_endpoint_id: None,
            hostname: "hk-ocserv-03".to_string(),
            agent_version: "0.1.0".to_string(),
            requested_labels_json: serde_json::json!({}),
        },
        "agent",
    );
    assert!(matches!(expired, Err(StoreError::EnrollmentRejected(_))));
}

#[test]
fn enrollment_token_create_is_actor_owned_idempotent_and_low_sensitive() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let input = enrollment_token_input(
        "tok-create-idempotent",
        "private-token-value",
        &future_time(),
    );

    let first = StoreWriter::write_enrollment_token_create(&store, &input, "issuing-operator")
        .expect("create token");
    for debug in [format!("{input:?}"), format!("{first:?}")] {
        assert!(!debug.contains("private-token-value"));
        assert!(!debug.contains(&input.token_hash));
    }
    let retry = StoreWriter::write_enrollment_token_create(&store, &input, "issuing-operator")
        .expect("exact token create retry");
    assert_eq!(retry, first);
    assert_eq!(first.created_by, "issuing-operator");
    assert_eq!(audit_event_count(&db, "enrollment.token.create"), 1);

    let different_actor =
        StoreWriter::write_enrollment_token_create(&store, &input, "different-operator")
            .expect_err("a different actor cannot adopt an issued token id");
    assert!(matches!(
        different_actor,
        StoreError::EnrollmentTokenConflict { .. }
    ));

    let (event, detail) = latest_audit_event(&db);
    assert_eq!(event, "enrollment.token.create");
    let detail_text = detail.to_string();
    assert!(!detail_text.contains("private-token-value"));
    assert!(!detail_text.contains(&input.token_hash));
    assert_eq!(detail["after"]["status"], "active");
    assert_eq!(detail["after"]["used_count"], 0);
}

#[test]
fn enrollment_writer_boundaries_reject_invalid_ids_hashes_counts_and_plaintext() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");

    for (token_id, token_hash, max_uses) in [
        ("invalid/id", Store::hash_enrollment_token("value"), 1),
        ("tok-invalid-hash", "not-a-hash".to_string(), 1),
        ("tok-zero", Store::hash_enrollment_token("zero"), 0),
        (
            "tok-too-many",
            Store::hash_enrollment_token("too-many"),
            ocfleet_cli::store::MAX_ENROLLMENT_TOKEN_USES + 1,
        ),
    ] {
        let input = EnrollmentTokenInsert {
            token_id: token_id.to_string(),
            token_hash,
            expires_at: future_time(),
            max_uses,
            description: None,
            labels_json: serde_json::json!({}),
            scope_json: serde_json::json!({}),
        };
        assert!(matches!(
            StoreWriter::write_enrollment_token_create(&store, &input, "operator"),
            Err(StoreError::InvalidInput(_))
        ));
    }

    let token = enrollment_token_input("tok-request-validation", "valid-token", &future_time());
    StoreWriter::write_enrollment_token_create(&store, &token, "operator")
        .expect("create valid token");
    let invalid_id = join_request_input("not-a-join-uuid", "valid-token");
    assert!(matches!(
        StoreWriter::write_enrollment_request_submit(&store, &invalid_id, "operator"),
        Err(StoreError::InvalidInput(_))
    ));
    let request_id = format!("join-{}", uuid::Uuid::new_v4());
    let mut invalid_plaintext = join_request_input(&request_id, "valid-token");
    invalid_plaintext.token_plaintext = "value with whitespace".to_string();
    assert!(matches!(
        StoreWriter::write_enrollment_request_submit(&store, &invalid_plaintext, "operator"),
        Err(StoreError::InvalidInput(_))
    ));
    assert_eq!(
        store
            .get_enrollment_token("tok-request-validation")
            .expect("load token")
            .expect("token exists")
            .used_count,
        0
    );
}

#[test]
fn enrollment_token_create_and_revoke_roll_back_when_audit_fails() {
    let create_dir = tempfile::tempdir().expect("temp dir");
    let create_db = create_dir.path().join("controller.sqlite");
    let create_store = Store::open(&create_db).expect("store opens");
    inject_audit_insert_failure(&create_db);
    let create_input = enrollment_token_input(
        "tok-create-rollback",
        "create-rollback-value",
        &future_time(),
    );
    let create_error =
        StoreWriter::write_enrollment_token_create(&create_store, &create_input, "operator")
            .expect_err("audit failure rejects token creation");
    assert!(matches!(create_error, StoreError::Sqlite(_)));
    assert!(
        create_store
            .get_enrollment_token("tok-create-rollback")
            .expect("query rolled-back token")
            .is_none()
    );

    let revoke_dir = tempfile::tempdir().expect("temp dir");
    let revoke_db = revoke_dir.path().join("controller.sqlite");
    let revoke_store = Store::open(&revoke_db).expect("store opens");
    let revoke_input = enrollment_token_input(
        "tok-revoke-rollback",
        "revoke-rollback-value",
        &future_time(),
    );
    StoreWriter::write_enrollment_token_create(&revoke_store, &revoke_input, "operator")
        .expect("seed token");
    inject_audit_insert_failure(&revoke_db);
    let revoke_error = StoreWriter::write_enrollment_token_revoke(
        &revoke_store,
        "tok-revoke-rollback",
        "operator",
        "ticket-rollback",
    )
    .expect_err("audit failure rejects token revocation");
    assert!(matches!(revoke_error, StoreError::Sqlite(_)));
    assert_eq!(
        revoke_store
            .get_enrollment_token("tok-revoke-rollback")
            .expect("load token after rollback")
            .expect("token exists")
            .status,
        EnrollmentTokenStatus::Active
    );
}

#[test]
fn enrollment_token_revoke_has_closed_idempotent_transitions() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let active = enrollment_token_input("tok-revoke", "revoke-token-value", &future_time());
    StoreWriter::write_enrollment_token_create(&store, &active, "creator")
        .expect("create active token");

    let revoked = StoreWriter::write_enrollment_token_revoke(
        &store,
        "tok-revoke",
        "revoking-operator",
        "ticket-123",
    )
    .expect("revoke active token");
    assert_eq!(revoked.status, EnrollmentTokenStatus::Revoked);
    let revoke_audits = audit_event_count(&db, "enrollment.token.revoke");
    let retry = StoreWriter::write_enrollment_token_revoke(
        &store,
        "tok-revoke",
        "revoking-operator",
        "ticket-123",
    )
    .expect("exact revoked token retry is a no-op");
    assert_eq!(retry, revoked);
    assert_eq!(
        audit_event_count(&db, "enrollment.token.revoke"),
        revoke_audits
    );
    assert!(matches!(
        StoreWriter::write_enrollment_token_revoke(
            &store,
            "tok-revoke",
            "different-operator",
            "ticket-123",
        ),
        Err(StoreError::EnrollmentTokenConflict { .. })
    ));
    assert!(matches!(
        StoreWriter::write_enrollment_token_revoke(
            &store,
            "tok-revoke",
            "revoking-operator",
            "different retry text",
        ),
        Err(StoreError::EnrollmentTokenConflict { .. })
    ));

    let create_retry = StoreWriter::write_enrollment_token_create(&store, &active, "creator")
        .expect("token creation remains idempotent after later transitions");
    assert_eq!(create_retry.status, EnrollmentTokenStatus::Revoked);
    assert_eq!(audit_event_count(&db, "enrollment.token.create"), 1);

    let expired = enrollment_token_input("tok-expired-revoke", "expired-revoke", &past_time());
    StoreWriter::write_enrollment_token_create(&store, &expired, "creator")
        .expect("create expired-by-time token");
    assert!(matches!(
        StoreWriter::write_enrollment_token_revoke(
            &store,
            "tok-expired-revoke",
            "operator",
            "late revoke",
        ),
        Err(StoreError::InvalidEnrollmentTokenTransition { .. })
    ));
    let request_id = format!("join-{}", uuid::Uuid::new_v4());
    assert!(matches!(
        StoreWriter::write_enrollment_request_submit(
            &store,
            &join_request_input(&request_id, "expired-revoke"),
            "operator",
        ),
        Err(StoreError::EnrollmentRejected(_))
    ));
    let error = StoreWriter::write_enrollment_token_revoke(
        &store,
        "tok-expired-revoke",
        "operator",
        "late revoke",
    )
    .expect_err("expired token cannot transition to revoked");
    assert!(matches!(
        error,
        StoreError::InvalidEnrollmentTokenTransition { .. }
    ));
}

#[test]
fn join_request_submission_is_idempotent_and_does_not_consume_twice() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let token = enrollment_token_input("tok-submit-retry", "submit-retry-value", &future_time());
    StoreWriter::write_enrollment_token_create(&store, &token, "operator").expect("create token");
    let request_id = format!("join-{}", uuid::Uuid::new_v4());
    let request = join_request_input(&request_id, "submit-retry-value");
    let request_debug = format!("{request:?}");
    for forbidden in [
        "submit-retry-value",
        "agent-public-key",
        "agent-fingerprint",
    ] {
        assert!(!request_debug.contains(forbidden));
    }

    let first = StoreWriter::write_enrollment_request_submit(&store, &request, "request-operator")
        .expect("submit request");
    let response_debug = format!("{first:?}");
    for forbidden in [
        "agent-public-key",
        "agent-fingerprint",
        "agent-supplied.example",
    ] {
        assert!(!response_debug.contains(forbidden));
    }
    let retry = StoreWriter::write_enrollment_request_submit(&store, &request, "request-operator")
        .expect("exact request retry");
    assert_eq!(retry, first);
    assert_eq!(audit_event_count(&db, "enrollment.token.use"), 1);
    assert_eq!(
        store
            .get_enrollment_token("tok-submit-retry")
            .expect("load token")
            .expect("token exists")
            .used_count,
        1
    );
    assert!(matches!(
        StoreWriter::write_enrollment_request_submit(&store, &request, "different-operator"),
        Err(StoreError::EnrollmentRequestConflict { .. })
    ));

    let mut mismatch = request.clone();
    mismatch.hostname = "different.example".to_string();
    assert!(matches!(
        StoreWriter::write_enrollment_request_submit(&store, &mismatch, "request-operator"),
        Err(StoreError::EnrollmentRequestConflict { .. })
    ));
    let (_, detail) = latest_audit_event(&db);
    let detail_text = detail.to_string();
    assert!(!detail_text.contains("submit-retry-value"));
    assert!(!detail_text.contains("agent-public-key"));
    assert!(!detail_text.contains("agent-fingerprint"));
    assert!(!detail_text.contains("agent-supplied.example"));
}

#[test]
fn join_request_submission_serializes_the_final_token_use() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let token = enrollment_token_input("tok-final-use", "final-use-value", &future_time());
    StoreWriter::write_enrollment_token_create(&store, &token, "operator")
        .expect("create single-use token");
    drop(store);

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let database = db.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let store = Store::open(&database).expect("open racing store");
            let request_id = format!("join-{}", uuid::Uuid::new_v4());
            let request = join_request_input(&request_id, "final-use-value");
            barrier.wait();
            StoreWriter::write_enrollment_request_submit(&store, &request, "operator")
        }));
    }
    let results = handles
        .into_iter()
        .map(|handle| handle.join().expect("racing writer joins"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(StoreError::EnrollmentRejected(reason)) if reason == "max_uses_exhausted"))
            .count(),
        1
    );

    let store = Store::open(&db).expect("reopen store");
    assert_eq!(
        store
            .get_enrollment_token("tok-final-use")
            .expect("load token")
            .expect("token exists")
            .used_count,
        1
    );
    assert_eq!(audit_event_count(&db, "enrollment.token.use"), 1);
    assert_eq!(audit_event_count(&db, "enrollment.token.reject"), 1);
}

#[test]
fn lazy_token_expiry_and_rejection_roll_back_together_on_audit_failure() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let token = enrollment_token_input("tok-expire-rollback", "expire-rollback", &past_time());
    StoreWriter::write_enrollment_token_create(&store, &token, "operator")
        .expect("create expired-by-time token");
    inject_audit_insert_failure(&db);
    let request_id = format!("join-{}", uuid::Uuid::new_v4());
    let error = StoreWriter::write_enrollment_request_submit(
        &store,
        &join_request_input(&request_id, "expire-rollback"),
        "operator",
    )
    .expect_err("expiry audit failure rejects the whole transition");
    assert!(matches!(error, StoreError::Sqlite(_)));
    assert_eq!(
        store
            .get_enrollment_token("tok-expire-rollback")
            .expect("load token")
            .expect("token exists")
            .status,
        EnrollmentTokenStatus::Active
    );
    assert!(
        store
            .get_join_request(&request_id)
            .expect("query join")
            .is_none()
    );
}

#[test]
fn lazy_token_expiry_rolls_back_when_the_second_audit_fails() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let token = enrollment_token_input(
        "tok-expire-second-audit",
        "expire-second-audit",
        &past_time(),
    );
    StoreWriter::write_enrollment_token_create(&store, &token, "operator")
        .expect("create expired-by-time token");
    inject_audit_event_failure(&db, "enrollment.token.reject");
    let request_id = format!("join-{}", uuid::Uuid::new_v4());
    let error = StoreWriter::write_enrollment_request_submit(
        &store,
        &join_request_input(&request_id, "expire-second-audit"),
        "operator",
    )
    .expect_err("second audit failure rejects the whole expiry transition");
    assert!(matches!(error, StoreError::Sqlite(_)));
    assert_eq!(
        store
            .get_enrollment_token("tok-expire-second-audit")
            .expect("load token")
            .expect("token exists")
            .status,
        EnrollmentTokenStatus::Active
    );
    assert_eq!(audit_event_count(&db, "enrollment.token.expire"), 0);
    assert!(
        store
            .get_join_request(&request_id)
            .expect("query join")
            .is_none()
    );
}

#[test]
fn join_request_rejection_is_atomic_closed_and_idempotent() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let join = seed_pending_enrollment(&store, "tok-reject-request", "reject-request-token", None);

    let rejected = StoreWriter::write_enrollment_request_reject(
        &store,
        &join.request_id,
        "rejecting-operator",
        "identity mismatch",
    )
    .expect("reject pending request");
    assert_eq!(rejected.status, JoinRequestStatus::Rejected);
    assert_eq!(
        rejected.rejection_reason.as_deref(),
        Some("identity mismatch")
    );
    let rejection_audits = audit_event_count(&db, "enrollment.reject");
    let retry = StoreWriter::write_enrollment_request_reject(
        &store,
        &join.request_id,
        "rejecting-operator",
        "identity mismatch",
    )
    .expect("exact rejection retry");
    assert_eq!(retry, rejected);
    assert_eq!(
        audit_event_count(&db, "enrollment.reject"),
        rejection_audits
    );
    assert!(matches!(
        StoreWriter::write_enrollment_request_reject(
            &store,
            &join.request_id,
            "different-operator",
            "identity mismatch",
        ),
        Err(StoreError::EnrollmentRequestConflict { .. })
    ));
    assert!(matches!(
        StoreWriter::write_enrollment_request_reject(
            &store,
            &join.request_id,
            "operator",
            "different reason",
        ),
        Err(StoreError::EnrollmentRequestConflict { .. })
    ));
    assert!(matches!(
        store.approve_join_request(
            &approval_input(&join.request_id, &generated_endpoint_id(), "rejected-node"),
            "operator",
        ),
        Err(StoreError::InvalidJoinRequestStatus { .. })
    ));
}

#[test]
fn join_request_rejection_rolls_back_when_audit_fails() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let join =
        seed_pending_enrollment(&store, "tok-reject-rollback", "reject-rollback-token", None);
    inject_audit_insert_failure(&db);
    let error = StoreWriter::write_enrollment_request_reject(
        &store,
        &join.request_id,
        "operator",
        "ticket-rollback",
    )
    .expect_err("audit failure rejects request rejection");
    assert!(matches!(error, StoreError::Sqlite(_)));
    let unchanged = store
        .get_join_request(&join.request_id)
        .expect("load request")
        .expect("request exists");
    assert_eq!(unchanged.status, JoinRequestStatus::Pending);
    assert!(unchanged.rejection_reason.is_none());
}

#[test]
fn approving_join_request_creates_active_endpoint_and_audit_before_after() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let token_plaintext = "ocfleet_enroll_approval";

    store
        .create_enrollment_token(
            &EnrollmentTokenInsert {
                token_id: "tok-approval".to_string(),
                token_hash: Store::hash_enrollment_token(token_plaintext),
                expires_at: future_time(),
                max_uses: 1,
                description: None,
                labels_json: serde_json::json!({}),
                scope_json: serde_json::json!({}),
            },
            "operator",
        )
        .expect("token created");
    let join = store
        .submit_join_request(
            &JoinRequestInsert {
                request_id: format!("join-{}", uuid::Uuid::new_v4()),
                token_plaintext: token_plaintext.to_string(),
                agent_public_key: "agent-public-key".to_string(),
                fingerprint: "agent-fingerprint".to_string(),
                requested_endpoint_id: None,
                hostname: "hk-ocserv-01".to_string(),
                agent_version: "0.1.0".to_string(),
                requested_labels_json: serde_json::json!({"region": "hk"}),
            },
            "agent",
        )
        .expect("join request created");

    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    let approved = store
        .approve_join_request(
            &ApprovalInput {
                request_id: join.request_id.clone(),
                endpoint_id: endpoint_id.clone(),
                node_id: "approved-node".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
                reason: "ticket-123".to_string(),
                approved_labels_json: serde_json::json!({"region": "hk", "role": "ocserv"}),
            },
            "operator",
        )
        .expect("join request approved");

    assert_eq!(approved.status, JoinRequestStatus::Approved);
    assert_eq!(
        approved.assigned_endpoint_id.as_deref(),
        Some(endpoint_id.as_str())
    );

    let endpoint = store
        .get_endpoint_trust(&endpoint_id)
        .expect("load endpoint")
        .expect("endpoint exists");
    assert_eq!(endpoint.status, EndpointStatus::Active);
    assert_eq!(endpoint.generation, 1);
    assert_eq!(endpoint.fingerprint.as_deref(), Some("agent-fingerprint"));
    assert_eq!(endpoint.node_id.as_deref(), Some("approved-node"));
    let node = store
        .get_node("approved-node")
        .expect("load approved node")
        .expect("approved node exists");
    assert_eq!(node.name, "approved-node");
    assert_eq!(node.endpoint_id, endpoint_id);
    assert!(node.enabled);

    let (event, detail) = latest_audit_event(&db);
    assert_eq!(event, "enrollment.approve");
    assert_eq!(detail["before"]["join_request"]["status"], "pending");
    assert_eq!(detail["after"]["join_request"]["status"], "approved");
    assert_eq!(detail["before"]["node"], serde_json::Value::Null);
    assert_eq!(detail["after"]["node"]["node_id"], "approved-node");
    assert_eq!(detail["after"]["endpoint"]["fingerprint_present"], true);
    let detail_text = detail.to_string();
    for forbidden in [
        token_plaintext,
        "agent-public-key",
        "agent-fingerprint",
        "hk-ocserv-01",
        "0.1.0",
    ] {
        assert!(!detail_text.contains(forbidden));
    }
    assert_eq!(detail["reason"], "ticket-123");
}

#[test]
fn enrollment_approval_audit_failure_rolls_back_join_node_and_trust() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    let join = seed_pending_enrollment(
        &store,
        "tok-approval-rollback",
        "approval-rollback-token",
        Some(endpoint_id.clone()),
    );
    inject_audit_insert_failure(&db);

    let err = store
        .approve_join_request(
            &approval_input(&join.request_id, &endpoint_id, "approval-rollback-node"),
            "operator",
        )
        .expect_err("audit failure rejects approval");
    assert!(matches!(err, StoreError::Sqlite(_)));

    let unchanged = store
        .get_join_request(&join.request_id)
        .expect("load join after rollback")
        .expect("join remains");
    assert_eq!(unchanged.status, JoinRequestStatus::Pending);
    assert!(unchanged.assigned_endpoint_id.is_none());
    assert!(
        store
            .get_node("approval-rollback-node")
            .expect("query rolled-back node")
            .is_none()
    );
    assert!(
        store
            .get_endpoint_trust(&endpoint_id)
            .expect("query rolled-back trust")
            .is_none()
    );
}

#[test]
fn enrollment_approval_exact_retry_is_noop_and_does_not_reenable_node() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    let join = seed_pending_enrollment(
        &store,
        "tok-approval-retry",
        "approval-retry-token",
        Some(endpoint_id.clone()),
    );
    let approval = approval_input(&join.request_id, &endpoint_id, "approval-retry-node");
    let first = store
        .approve_join_request(&approval, "first-operator")
        .expect("first approval succeeds");
    let not_legacy = store
        .claim_legacy_enrollment(
            &legacy_claim_input(&join.request_id, &endpoint_id, "approval-retry-node"),
            "claiming-operator",
        )
        .expect_err("new bound approval is not a legacy claim candidate");
    assert!(matches!(
        not_legacy,
        StoreError::InvalidEnrollmentBinding {
            detail: "approval audit provenance is missing or ambiguous",
            ..
        }
    ));
    StoreWriter::write_node_disable(&store, "approval-retry-node", "security-operator")
        .expect("disable approved node");
    let endpoint_before = store
        .get_endpoint_trust(&endpoint_id)
        .expect("load endpoint before retry")
        .expect("endpoint exists");
    let approval_audits_before = audit_event_count(&db, "enrollment.approve");

    let retry = store
        .approve_join_request(&approval, "retrying-operator")
        .expect("exact approval retry succeeds");

    assert_eq!(retry, first);
    assert_eq!(
        store
            .get_endpoint_trust(&endpoint_id)
            .expect("load endpoint after retry")
            .expect("endpoint exists"),
        endpoint_before
    );
    assert!(
        !store
            .get_node("approval-retry-node")
            .expect("load node after retry")
            .expect("node exists")
            .enabled
    );
    assert_eq!(
        audit_event_count(&db, "enrollment.approve"),
        approval_audits_before
    );
}

#[test]
fn legacy_enrollment_claim_repairs_only_explicit_provenance_and_is_idempotent() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("missing-controller-secret");
    let store = Store::open(&db).expect("store opens");
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    let join = seed_pending_enrollment(
        &store,
        "tok-legacy-claim",
        "legacy-claim-token",
        Some(endpoint_id.clone()),
    );
    store
        .approve_join_request(
            &approval_input(&join.request_id, &endpoint_id, "legacy-original-node"),
            "legacy-operator",
        )
        .expect("seed approved binding");
    make_approved_binding_legacy_unbound(&db, "legacy-original-node", &endpoint_id);
    let endpoint_before = store
        .get_endpoint_trust(&endpoint_id)
        .expect("load legacy trust")
        .expect("legacy trust exists");
    assert!(endpoint_before.node_id.is_none());

    let before_report = run_doctor(&DoctorOptions {
        database: db.clone(),
        secret_key: secret_key.clone(),
    });
    let before_binding = before_report
        .checks
        .iter()
        .find(|check| check.id == "registry.endpoint_trust.bindings")
        .expect("binding check exists");
    assert_eq!(before_binding.details["active_unbound"], 1);

    let claim = legacy_claim_input(&join.request_id, &endpoint_id, "operator-chosen-node");
    let claimed = store
        .claim_legacy_enrollment(&claim, "claiming-operator")
        .expect("legacy claim succeeds");
    assert_eq!(claimed.status, JoinRequestStatus::Approved);
    let endpoint_after = store
        .get_endpoint_trust(&endpoint_id)
        .expect("load claimed trust")
        .expect("claimed trust exists");
    assert_eq!(
        endpoint_after.node_id.as_deref(),
        Some("operator-chosen-node")
    );
    assert_eq!(endpoint_after.generation, endpoint_before.generation);
    assert_eq!(
        endpoint_after.trust_bundle_json,
        endpoint_before.trust_bundle_json
    );
    let node = store
        .get_node("operator-chosen-node")
        .expect("load claimed node")
        .expect("claimed node exists");
    assert_eq!(node.name, "operator-chosen-node");
    assert_ne!(node.name, join.hostname);
    assert!(node.enabled);

    let (event, detail) = latest_audit_event(&db);
    assert_eq!(event, "enrollment.claim");
    assert_eq!(detail["before"]["node"], serde_json::Value::Null);
    assert_eq!(
        detail["before"]["endpoint"]["node_id"],
        serde_json::Value::Null
    );
    assert_eq!(
        detail["after"]["endpoint"]["node_id"],
        "operator-chosen-node"
    );
    let detail_text = detail.to_string();
    for forbidden in [
        "legacy-claim-token",
        "agent-public-key",
        "agent-fingerprint",
        "agent-self-reported.example",
        "must-not-be-used",
    ] {
        assert!(!detail_text.contains(forbidden));
    }

    StoreWriter::write_node_disable(&store, "operator-chosen-node", "security-operator")
        .expect("disable claimed node");
    let claim_audits_before = audit_event_count(&db, "enrollment.claim");
    store
        .claim_legacy_enrollment(&claim, "retrying-operator")
        .expect("exact claim retry succeeds");
    assert!(
        !store
            .get_node("operator-chosen-node")
            .expect("load node after claim retry")
            .expect("node exists")
            .enabled
    );
    assert_eq!(
        audit_event_count(&db, "enrollment.claim"),
        claim_audits_before
    );

    let after_report = run_doctor(&DoctorOptions {
        database: db,
        secret_key,
    });
    let after_binding = after_report
        .checks
        .iter()
        .find(|check| check.id == "registry.endpoint_trust.bindings")
        .expect("binding check exists");
    assert_eq!(after_binding.status, CheckStatus::Ok);
    for key in [
        "active_unbound",
        "active_orphan",
        "current_binding_mismatch",
        "inactive_current",
        "active_extra_for_node",
    ] {
        assert_eq!(after_binding.details[key], 0, "unexpected {key}");
    }
}

#[test]
fn legacy_enrollment_claim_audit_failure_rolls_back_node_and_binding() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    let join = seed_pending_enrollment(
        &store,
        "tok-claim-rollback",
        "claim-rollback-token",
        Some(endpoint_id.clone()),
    );
    store
        .approve_join_request(
            &approval_input(&join.request_id, &endpoint_id, "claim-rollback-old"),
            "operator",
        )
        .expect("seed approved binding");
    make_approved_binding_legacy_unbound(&db, "claim-rollback-old", &endpoint_id);
    inject_audit_insert_failure(&db);

    let err = store
        .claim_legacy_enrollment(
            &legacy_claim_input(&join.request_id, &endpoint_id, "claim-rollback-new"),
            "operator",
        )
        .expect_err("audit failure rejects legacy claim");
    assert!(matches!(err, StoreError::Sqlite(_)));
    assert!(
        store
            .get_node("claim-rollback-new")
            .expect("query rolled-back node")
            .is_none()
    );
    assert!(
        store
            .get_endpoint_trust(&endpoint_id)
            .expect("load endpoint after rollback")
            .expect("endpoint remains")
            .node_id
            .is_none()
    );
}

#[test]
fn legacy_enrollment_claim_rejects_contamination_and_approval_requires_claim() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    let join = seed_pending_enrollment(
        &store,
        "tok-claim-contamination",
        "claim-contamination-token",
        Some(endpoint_id.clone()),
    );
    let approval = approval_input(&join.request_id, &endpoint_id, "claim-contamination-old");
    store
        .approve_join_request(&approval, "operator")
        .expect("seed approved binding");
    make_approved_binding_legacy_unbound(&db, "claim-contamination-old", &endpoint_id);

    let approve_retry = store
        .approve_join_request(&approval, "operator")
        .expect_err("approval never implicitly claims legacy trust");
    assert!(matches!(
        approve_retry,
        StoreError::InvalidEnrollmentBinding {
            detail: "legacy claim required",
            ..
        }
    ));

    Connection::open(&db)
        .expect("open database for contamination")
        .execute(
            "UPDATE endpoint_trust SET fingerprint = 'different-fingerprint' WHERE endpoint_id = ?1",
            [&endpoint_id],
        )
        .expect("contaminate endpoint fingerprint");
    let claim_err = store
        .claim_legacy_enrollment(
            &legacy_claim_input(&join.request_id, &endpoint_id, "claim-contamination-new"),
            "operator",
        )
        .expect_err("contaminated fingerprint rejects claim");
    assert!(matches!(
        claim_err,
        StoreError::InvalidEnrollmentBinding {
            detail: "endpoint fingerprint does not match join request",
            ..
        }
    ));
    assert!(
        store
            .get_node("claim-contamination-new")
            .expect("query rejected claim node")
            .is_none()
    );
    assert_eq!(audit_event_count(&db, "enrollment.claim"), 0);
}

#[test]
fn legacy_enrollment_claim_rejects_status_lineage_and_bundle_contamination() {
    for contamination in [
        "status",
        "generation",
        "previous",
        "rotated_to",
        "bundle_authority",
    ] {
        let dir = tempfile::tempdir().expect("temp dir");
        let db = dir.path().join("controller.sqlite");
        let store = Store::open(&db).expect("store opens");
        let endpoint_id = generated_endpoint_id();
        let join = seed_pending_enrollment(
            &store,
            &format!("tok-claim-{contamination}"),
            &format!("claim-{contamination}-token"),
            Some(endpoint_id.clone()),
        );
        let original_node_id = format!("legacy-{contamination}-old");
        store
            .approve_join_request(
                &approval_input(&join.request_id, &endpoint_id, &original_node_id),
                "operator",
            )
            .expect("seed approved binding");
        make_approved_binding_legacy_unbound(&db, &original_node_id, &endpoint_id);

        let conn = Connection::open(&db).expect("open database for contamination");
        match contamination {
            "status" => {
                conn.execute(
                    "UPDATE endpoint_trust
                     SET status = 'quarantined', trust_bundle_json = ?1
                     WHERE endpoint_id = ?2",
                    rusqlite::params![
                        trust_bundle_fixture(&endpoint_id, 1, EndpointStatus::Quarantined,),
                        endpoint_id,
                    ],
                )
                .expect("contaminate status");
            }
            "generation" => {
                conn.execute(
                    "UPDATE endpoint_trust SET generation = 2, trust_bundle_json = ?1
                     WHERE endpoint_id = ?2",
                    rusqlite::params![
                        trust_bundle_fixture(&endpoint_id, 2, EndpointStatus::Active),
                        endpoint_id,
                    ],
                )
                .expect("contaminate generation");
            }
            "previous" => {
                conn.execute(
                    "UPDATE endpoint_trust SET previous_endpoint_id = ?1 WHERE endpoint_id = ?2",
                    rusqlite::params![generated_endpoint_id(), endpoint_id],
                )
                .expect("contaminate predecessor");
            }
            "rotated_to" => {
                conn.execute(
                    "UPDATE endpoint_trust SET rotated_to = ?1 WHERE endpoint_id = ?2",
                    rusqlite::params![generated_endpoint_id(), endpoint_id],
                )
                .expect("contaminate successor");
            }
            "bundle_authority" => {
                let bundle = serde_json::json!({
                    "schema": "ocfleet.trust.bundle.v1",
                    "endpoint_id": endpoint_id.clone(),
                    "generation": 1,
                    "status": "active",
                    "trusted_controllers": [generated_endpoint_id()],
                    "trusted_peers": [],
                    "authorized_path_probes": [],
                });
                conn.execute(
                    "UPDATE endpoint_trust SET trust_bundle_json = ?1 WHERE endpoint_id = ?2",
                    rusqlite::params![bundle.to_string(), endpoint_id],
                )
                .expect("contaminate trust bundle authority");
            }
            _ => unreachable!(),
        }
        drop(conn);

        let claimed_node_id = format!("legacy-{contamination}-new");
        let error = store
            .claim_legacy_enrollment(
                &legacy_claim_input(&join.request_id, &endpoint_id, &claimed_node_id),
                "operator",
            )
            .expect_err("contaminated legacy trust must fail closed");
        assert!(
            matches!(error, StoreError::InvalidEnrollmentBinding { .. }),
            "unexpected {contamination} error: {error}"
        );
        assert!(
            store
                .get_node(&claimed_node_id)
                .expect("query rejected claim node")
                .is_none()
        );
        assert_eq!(audit_event_count(&db, "enrollment.claim"), 0);
    }
}

#[test]
fn legacy_enrollment_claim_rejects_ambiguous_approved_assignment() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    let join = seed_pending_enrollment(
        &store,
        "tok-claim-ambiguous",
        "claim-ambiguous-token",
        Some(endpoint_id.clone()),
    );
    store
        .approve_join_request(
            &approval_input(&join.request_id, &endpoint_id, "claim-ambiguous-old"),
            "operator",
        )
        .expect("seed approved binding");
    make_approved_binding_legacy_unbound(&db, "claim-ambiguous-old", &endpoint_id);
    Connection::open(&db)
        .expect("open database for duplicate approval")
        .execute(
            "INSERT INTO join_requests
             (request_id, token_id, status, agent_public_key, fingerprint,
              requested_endpoint_id, assigned_endpoint_id, hostname, agent_version,
              requested_labels_json, approved_labels_json, created_at, approved_at,
              approved_by, rejection_reason, audit_correlation_id)
             SELECT 'join-ambiguous-copy', token_id, status, agent_public_key, fingerprint,
                    requested_endpoint_id, assigned_endpoint_id, hostname, agent_version,
                    requested_labels_json, approved_labels_json, created_at, approved_at,
                    approved_by, rejection_reason, 'corr-ambiguous-copy'
             FROM join_requests WHERE request_id = ?1",
            [&join.request_id],
        )
        .expect("insert duplicate approved assignment");

    let err = store
        .claim_legacy_enrollment(
            &legacy_claim_input(&join.request_id, &endpoint_id, "claim-ambiguous-new"),
            "operator",
        )
        .expect_err("ambiguous approved assignment rejects claim");
    assert!(matches!(
        err,
        StoreError::InvalidEnrollmentBinding {
            detail: "approved endpoint assignment is ambiguous",
            ..
        }
    ));
    assert!(
        store
            .get_node("claim-ambiguous-new")
            .expect("query rejected claim node")
            .is_none()
    );
}

#[test]
fn legacy_enrollment_claim_rejects_reusing_a_node_identity_with_trust_history() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let endpoint_id = generated_endpoint_id();
    let join = seed_pending_enrollment(
        &store,
        "tok-claim-history",
        "claim-history-token",
        Some(endpoint_id.clone()),
    );
    store
        .approve_join_request(
            &approval_input(&join.request_id, &endpoint_id, "claim-history-old"),
            "operator",
        )
        .expect("seed approved binding");
    make_approved_binding_legacy_unbound(&db, "claim-history-old", &endpoint_id);

    let historical_node = seed_generated_node(&store, "reused-node-id");
    StoreWriter::write_node_remove(&store, &historical_node.node_id, "operator")
        .expect("remove historical node while retaining trust tombstone");
    assert!(
        store
            .get_node(&historical_node.node_id)
            .expect("query removed node")
            .is_none()
    );

    let error = store
        .claim_legacy_enrollment(
            &legacy_claim_input(&join.request_id, &endpoint_id, &historical_node.node_id),
            "operator",
        )
        .expect_err("trust history must not be conflated with a new enrollment binding");
    assert!(matches!(
        error,
        StoreError::InvalidEnrollmentBinding {
            detail: "node id has existing endpoint trust history",
            ..
        }
    ));
    assert_eq!(audit_event_count(&db, "enrollment.claim"), 0);
}

#[test]
fn legacy_enrollment_claim_requires_exact_approval_audit_provenance() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    let join = seed_pending_enrollment(
        &store,
        "tok-claim-audit-provenance",
        "claim-audit-provenance-token",
        Some(endpoint_id.clone()),
    );
    store
        .approve_join_request(
            &approval_input(&join.request_id, &endpoint_id, "claim-audit-old"),
            "approving-operator",
        )
        .expect("seed approved binding");
    make_approved_binding_legacy_unbound(&db, "claim-audit-old", &endpoint_id);
    Connection::open(&db)
        .expect("open database for audit contamination")
        .execute(
            "UPDATE controller_audit_log
             SET actor = 'different-operator'
             WHERE event = 'enrollment.approve' AND request_id = ?1",
            [&join.request_id],
        )
        .expect("break approval audit provenance");

    let err = store
        .claim_legacy_enrollment(
            &legacy_claim_input(&join.request_id, &endpoint_id, "claim-audit-new"),
            "claiming-operator",
        )
        .expect_err("mismatched approval audit rejects claim");
    assert!(matches!(
        err,
        StoreError::InvalidEnrollmentBinding {
            detail: "approval audit provenance is missing or ambiguous",
            ..
        }
    ));
    assert!(
        store
            .get_node("claim-audit-new")
            .expect("query rejected claim node")
            .is_none()
    );
}

#[test]
fn enrollment_binding_writer_validates_operator_node_fields() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    let join = seed_pending_enrollment(
        &store,
        "tok-binding-validation",
        "binding-validation-token",
        Some(endpoint_id.clone()),
    );

    for (node_id, region, role) in [
        ("invalid/node", "hk", "ocserv"),
        ("valid-node", "invalid region", "ocserv"),
        ("valid-node", "hk", "viewer"),
    ] {
        let mut approval = approval_input(&join.request_id, &endpoint_id, node_id);
        approval.region = region.to_string();
        approval.role = role.to_string();
        assert!(matches!(
            store.approve_join_request(&approval, "operator"),
            Err(StoreError::InvalidInput(_))
        ));
    }
    assert_eq!(
        store
            .get_join_request(&join.request_id)
            .expect("load unchanged join")
            .expect("join remains")
            .status,
        JoinRequestStatus::Pending
    );
    assert!(store.list_nodes().expect("list nodes").is_empty());
    assert!(
        store
            .get_endpoint_trust(&endpoint_id)
            .expect("query trust")
            .is_none()
    );
}

#[test]
fn enrollment_approval_rejects_pending_rows_with_decision_metadata() {
    for contamination in [
        "assigned_endpoint_id",
        "approved_at",
        "approved_by",
        "rejection_reason",
        "approved_labels_json",
    ] {
        let dir = tempfile::tempdir().expect("temp dir");
        let db = dir.path().join("controller.sqlite");
        let store = Store::open(&db).expect("store opens");
        let endpoint_id = generated_endpoint_id();
        let join = seed_pending_enrollment(
            &store,
            &format!("tok-pending-{contamination}"),
            &format!("pending-{contamination}-token"),
            Some(endpoint_id.clone()),
        );
        let sql = match contamination {
            "assigned_endpoint_id" => {
                "UPDATE join_requests SET assigned_endpoint_id = 'contaminated' WHERE request_id = ?1"
            }
            "approved_at" => {
                "UPDATE join_requests SET approved_at = '2026-07-11T00:00:00Z' WHERE request_id = ?1"
            }
            "approved_by" => {
                "UPDATE join_requests SET approved_by = 'unexpected-operator' WHERE request_id = ?1"
            }
            "rejection_reason" => {
                "UPDATE join_requests SET rejection_reason = 'unexpected-decision' WHERE request_id = ?1"
            }
            "approved_labels_json" => {
                "UPDATE join_requests SET approved_labels_json = '{\"unexpected\":true}' WHERE request_id = ?1"
            }
            _ => unreachable!(),
        };
        Connection::open(&db)
            .expect("open database for pending contamination")
            .execute(sql, [&join.request_id])
            .expect("contaminate pending decision metadata");

        let error = store
            .approve_join_request(
                &approval_input(&join.request_id, &endpoint_id, "pending-contamination-node"),
                "operator",
            )
            .expect_err("contaminated pending request must fail closed");
        assert!(matches!(
            error,
            StoreError::InvalidEnrollmentBinding {
                detail: "pending join request has decision metadata",
                ..
            }
        ));
        assert!(
            store
                .get_node("pending-contamination-node")
                .expect("query rejected approval node")
                .is_none()
        );
        assert!(
            store
                .get_endpoint_trust(&endpoint_id)
                .expect("query rejected approval trust")
                .is_none()
        );
        assert_eq!(audit_event_count(&db, "enrollment.approve"), 0);
    }
}

#[test]
fn enrollment_approval_immediate_transactions_serialize_conflicting_writers() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    let join = seed_pending_enrollment(
        &store,
        "tok-approval-race",
        "approval-race-token",
        Some(endpoint_id.clone()),
    );
    drop(store);

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for node_id in ["race-node-one", "race-node-two"] {
        let database = db.clone();
        let barrier = Arc::clone(&barrier);
        let request_id = join.request_id.clone();
        let endpoint_id = endpoint_id.clone();
        handles.push(std::thread::spawn(move || {
            let store = Store::open(&database).expect("open racing store");
            barrier.wait();
            store.approve_join_request(&approval_input(&request_id, &endpoint_id, node_id), node_id)
        }));
    }
    let results = handles
        .into_iter()
        .map(|handle| handle.join().expect("racing writer joins"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(StoreError::InvalidEnrollmentBinding { .. })))
            .count(),
        1
    );

    let store = Store::open(&db).expect("reopen raced store");
    let nodes = store.list_nodes().expect("list raced nodes");
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].endpoint_id, endpoint_id);
    assert_eq!(audit_event_count(&db, "enrollment.approve"), 1);
}

#[test]
fn legacy_enrollment_claim_immediate_transactions_collapse_exact_races() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let endpoint_id = generated_endpoint_id();
    let join = seed_pending_enrollment(
        &store,
        "tok-claim-race",
        "claim-race-token",
        Some(endpoint_id.clone()),
    );
    store
        .approve_join_request(
            &approval_input(&join.request_id, &endpoint_id, "claim-race-old"),
            "operator",
        )
        .expect("seed approved binding");
    make_approved_binding_legacy_unbound(&db, "claim-race-old", &endpoint_id);
    drop(store);

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let database = db.clone();
        let barrier = Arc::clone(&barrier);
        let request_id = join.request_id.clone();
        let endpoint_id = endpoint_id.clone();
        handles.push(std::thread::spawn(move || {
            let store = Store::open(&database).expect("open racing store");
            let claim = legacy_claim_input(&request_id, &endpoint_id, "claim-race-new");
            barrier.wait();
            store.claim_legacy_enrollment(&claim, "operator")
        }));
    }
    let results = handles
        .into_iter()
        .map(|handle| handle.join().expect("racing writer joins"))
        .collect::<Vec<_>>();
    assert!(results.iter().all(Result::is_ok));

    let store = Store::open(&db).expect("reopen raced store");
    let nodes = store.list_nodes().expect("list raced nodes");
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].node_id, "claim-race-new");
    assert_eq!(nodes[0].endpoint_id, endpoint_id);
    assert_eq!(audit_event_count(&db, "enrollment.claim"), 1);
}

#[test]
fn submit_join_request_validates_agent_key_fingerprint_and_requested_endpoint() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let token_plaintext = "ocfleet_enroll_validate_fields";

    store
        .create_enrollment_token(
            &EnrollmentTokenInsert {
                token_id: "tok-validate-fields".to_string(),
                token_hash: Store::hash_enrollment_token(token_plaintext),
                expires_at: future_time(),
                max_uses: 10,
                description: None,
                labels_json: serde_json::json!({}),
                scope_json: serde_json::json!({}),
            },
            "operator",
        )
        .expect("token created");

    for (agent_public_key, fingerprint, requested_endpoint_id, expected_field) in [
        (
            "agent-public-key\ninjected",
            "agent-fingerprint",
            None,
            "agent_public_key",
        ),
        ("agent-public-key", "", None, "fingerprint"),
        (
            "agent-public-key",
            "agent-fingerprint",
            Some("not-an-endpoint-id"),
            "requested_endpoint_id",
        ),
    ] {
        let err = store
            .submit_join_request(
                &JoinRequestInsert {
                    request_id: format!("join-{}", uuid::Uuid::new_v4()),
                    token_plaintext: token_plaintext.to_string(),
                    agent_public_key: agent_public_key.to_string(),
                    fingerprint: fingerprint.to_string(),
                    requested_endpoint_id: requested_endpoint_id.map(ToString::to_string),
                    hostname: "hk-ocserv-01".to_string(),
                    agent_version: "0.1.0".to_string(),
                    requested_labels_json: serde_json::json!({}),
                },
                "agent",
            )
            .expect_err("invalid join request field rejected");

        assert!(
            matches!(err, StoreError::InvalidInput(ref message) if message.contains(expected_field)),
            "unexpected error for {expected_field}: {err}"
        );
    }
}

#[test]
fn approving_join_request_requires_requested_endpoint_match_when_present() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let token_plaintext = "ocfleet_enroll_endpoint_binding";
    let requested_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let different_endpoint_id = iroh::SecretKey::generate().public().to_string();

    store
        .create_enrollment_token(
            &EnrollmentTokenInsert {
                token_id: "tok-endpoint-binding".to_string(),
                token_hash: Store::hash_enrollment_token(token_plaintext),
                expires_at: future_time(),
                max_uses: 1,
                description: None,
                labels_json: serde_json::json!({}),
                scope_json: serde_json::json!({}),
            },
            "operator",
        )
        .expect("token created");
    let join = store
        .submit_join_request(
            &JoinRequestInsert {
                request_id: format!("join-{}", uuid::Uuid::new_v4()),
                token_plaintext: token_plaintext.to_string(),
                agent_public_key: "agent-public-key".to_string(),
                fingerprint: "agent-fingerprint".to_string(),
                requested_endpoint_id: Some(requested_endpoint_id.clone()),
                hostname: "hk-ocserv-01".to_string(),
                agent_version: "0.1.0".to_string(),
                requested_labels_json: serde_json::json!({}),
            },
            "agent",
        )
        .expect("join request created");

    let err = store
        .approve_join_request(
            &ApprovalInput {
                request_id: join.request_id,
                endpoint_id: different_endpoint_id.clone(),
                node_id: "approved-node".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
                reason: "ticket-123".to_string(),
                approved_labels_json: serde_json::json!({}),
            },
            "operator",
        )
        .expect_err("different endpoint id rejected");

    assert!(
        matches!(err, StoreError::InvalidEnrollmentBinding { detail, .. } if detail.contains("requested endpoint")),
        "unexpected approval error: {err}"
    );
    assert!(
        store
            .get_endpoint_trust(&different_endpoint_id)
            .expect("query trust")
            .is_none()
    );
}

#[test]
fn approving_join_request_rejects_non_canonical_endpoint_id() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let token_plaintext = "ocfleet_enroll_invalid_endpoint";

    store
        .create_enrollment_token(
            &EnrollmentTokenInsert {
                token_id: "tok-invalid-endpoint".to_string(),
                token_hash: Store::hash_enrollment_token(token_plaintext),
                expires_at: future_time(),
                max_uses: 1,
                description: None,
                labels_json: serde_json::json!({}),
                scope_json: serde_json::json!({}),
            },
            "operator",
        )
        .expect("token created");
    let join = store
        .submit_join_request(
            &JoinRequestInsert {
                request_id: format!("join-{}", uuid::Uuid::new_v4()),
                token_plaintext: token_plaintext.to_string(),
                agent_public_key: "agent-public-key".to_string(),
                fingerprint: "agent-fingerprint".to_string(),
                requested_endpoint_id: None,
                hostname: "hk-ocserv-01".to_string(),
                agent_version: "0.1.0".to_string(),
                requested_labels_json: serde_json::json!({"hostname": "trusted-controller"}),
            },
            "agent",
        )
        .expect("join request created");

    let err = store
        .approve_join_request(
            &ApprovalInput {
                request_id: join.request_id,
                endpoint_id: "endpoint-approved".to_string(),
                node_id: "approved-node".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
                reason: "ticket-123".to_string(),
                approved_labels_json: serde_json::json!({}),
            },
            "operator",
        )
        .expect_err("invalid endpoint id must be rejected");

    assert!(matches!(err, StoreError::InvalidInput(_)));
    assert!(
        store
            .get_endpoint_trust("endpoint-approved")
            .expect("query trust")
            .is_none()
    );
}

#[test]
fn endpoint_lifecycle_quarantine_rotate_and_revoke_updates_binding_and_generation() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let endpoint_one = iroh::SecretKey::generate().public().to_string();
    let endpoint_two = iroh::SecretKey::generate().public().to_string();
    let node = NodeInsert {
        node_id: "hk-ocserv-01".into(),
        endpoint_id: endpoint_one.clone(),
        name: "hk-ocserv-01".into(),
        region: "hk".into(),
        role: "ocserv".into(),
    };
    StoreWriter::write_node_add(&store, &node, TEST_ACTOR).expect("insert node and endpoint trust");

    let quarantined = StoreWriter::write_endpoint_quarantine(
        &store,
        &endpoint_one,
        "operator",
        "suspicious traffic",
    )
    .expect("quarantine endpoint");
    assert_eq!(quarantined.status, EndpointStatus::Quarantined);
    assert_eq!(quarantined.generation, 2);
    assert!(
        !store
            .get_node(&node.node_id)
            .expect("load node")
            .expect("node exists")
            .enabled
    );

    let rotated = StoreWriter::write_endpoint_rotation(
        &store,
        &endpoint_one,
        &endpoint_two,
        "operator",
        "key rotation",
    )
    .expect("rotate endpoint");
    assert_eq!(rotated.status, EndpointStatus::Active);
    assert_eq!(rotated.generation, 3);
    assert_eq!(
        rotated.previous_endpoint_id.as_deref(),
        Some(endpoint_one.as_str())
    );
    let old = store
        .get_endpoint_trust(&endpoint_one)
        .expect("load old endpoint")
        .expect("old endpoint exists");
    assert_eq!(old.status, EndpointStatus::Rotated);
    assert_eq!(old.rotated_to.as_deref(), Some(endpoint_two.as_str()));
    assert_eq!(old.generation, 3);
    let bound_node = store
        .get_node(&node.node_id)
        .expect("load rotated node")
        .expect("rotated node exists");
    assert_eq!(bound_node.endpoint_id, endpoint_two);
    assert!(!bound_node.enabled, "quarantine rotation stays disabled");

    StoreWriter::write_node_enable(&store, &node.node_id, "operator")
        .expect("enable clean rotated binding");

    let revoked =
        StoreWriter::write_endpoint_revocation(&store, &endpoint_two, "operator", "lost host")
            .expect("revoke endpoint");
    assert_eq!(revoked.status, EndpointStatus::Revoked);
    assert_eq!(revoked.generation, 4);
    assert!(
        !store
            .get_node(&node.node_id)
            .expect("load node")
            .expect("node exists")
            .enabled
    );

    let (actor, event, audit_node_id, audit_endpoint_id, detail) = latest_node_audit(&db);
    assert_eq!(actor, "operator");
    assert_eq!(event, "endpoint.revoke");
    assert_eq!(audit_node_id.as_deref(), Some(node.node_id.as_str()));
    assert_eq!(audit_endpoint_id.as_deref(), Some(endpoint_two.as_str()));
    assert_eq!(detail["target_id"], endpoint_two);
    assert_eq!(detail["reason"], "lost host");
    assert_eq!(detail["before"]["node"]["enabled"], true);
    assert_eq!(detail["after"]["node"]["enabled"], false);
    assert_eq!(detail["after"]["endpoint"]["status"], "revoked");
    assert_eq!(detail["after"]["endpoint"]["fingerprint_present"], false);
    assert!(detail["after"]["endpoint"].get("fingerprint").is_none());
}

#[test]
fn endpoint_rotate_rejects_non_canonical_new_endpoint_id() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let endpoint_one = iroh::SecretKey::generate().public().to_string();
    let node = NodeInsert {
        node_id: "hk-ocserv-01".into(),
        endpoint_id: endpoint_one.clone(),
        name: "hk-ocserv-01".into(),
        region: "hk".into(),
        role: "ocserv".into(),
    };
    StoreWriter::write_node_add(&store, &node, TEST_ACTOR).expect("insert node and endpoint trust");

    let err = StoreWriter::write_endpoint_rotation(
        &store,
        &endpoint_one,
        "endpoint-two",
        "operator",
        "key rotation",
    )
    .expect_err("invalid endpoint id must be rejected");

    assert!(matches!(err, StoreError::InvalidInput(_)));
    assert!(
        store
            .get_endpoint_trust("endpoint-two")
            .expect("query trust")
            .is_none()
    );
}

#[test]
fn endpoint_terminal_transitions_and_retries_are_closed_and_idempotent() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let node = seed_generated_node(&store, "closed-status-node");

    let quarantined = StoreWriter::write_endpoint_quarantine(
        &store,
        &node.endpoint_id,
        "operator",
        "investigate",
    )
    .expect("quarantine active endpoint");
    let quarantine_audit_count = store.audit_count().expect("audit count");
    let quarantine_retry = StoreWriter::write_endpoint_quarantine(
        &store,
        &node.endpoint_id,
        "operator",
        "same request retry",
    )
    .expect("same quarantine is idempotent");
    assert_eq!(quarantine_retry, quarantined);
    assert_eq!(
        store.audit_count().expect("audit count"),
        quarantine_audit_count
    );

    let revoked = StoreWriter::write_endpoint_revocation(
        &store,
        &node.endpoint_id,
        "operator",
        "permanent revoke",
    )
    .expect("quarantined endpoint can be revoked");
    assert_eq!(revoked.status, EndpointStatus::Revoked);
    assert_eq!(revoked.generation, quarantined.generation + 1);
    let revoke_audit_count = store.audit_count().expect("audit count");
    let revoke_retry = StoreWriter::write_endpoint_revocation(
        &store,
        &node.endpoint_id,
        "operator",
        "same request retry",
    )
    .expect("same revoke is idempotent");
    assert_eq!(revoke_retry, revoked);
    assert_eq!(
        store.audit_count().expect("audit count"),
        revoke_audit_count
    );

    let replacement = generated_endpoint_id();
    assert!(matches!(
        StoreWriter::write_endpoint_rotation(
            &store,
            &node.endpoint_id,
            &replacement,
            "operator",
            "must stay terminal",
        ),
        Err(StoreError::InvalidEndpointTransition { .. })
    ));
    assert!(matches!(
        StoreWriter::write_endpoint_quarantine(
            &store,
            &node.endpoint_id,
            "operator",
            "must stay terminal",
        ),
        Err(StoreError::InvalidEndpointTransition { .. })
    ));
    assert!(
        store
            .get_endpoint_trust(&replacement)
            .expect("load replacement")
            .is_none()
    );
    assert_eq!(
        store
            .get_endpoint_trust(&node.endpoint_id)
            .expect("load endpoint")
            .expect("endpoint exists"),
        revoked
    );
    assert_eq!(
        store.audit_count().expect("audit count"),
        revoke_audit_count
    );

    let rotated_dir = tempfile::tempdir().expect("rotated temp dir");
    let rotated_db = rotated_dir.path().join("controller.sqlite");
    let rotated_store = Store::open(&rotated_db).expect("rotated store opens");
    let rotated_node = seed_generated_node(&rotated_store, "closed-rotation-node");
    let rotated_to = generated_endpoint_id();
    let new_endpoint = StoreWriter::write_endpoint_rotation(
        &rotated_store,
        &rotated_node.endpoint_id,
        &rotated_to,
        "operator",
        "rotate",
    )
    .expect("rotate active endpoint");
    let old_endpoint = rotated_store
        .get_endpoint_trust(&rotated_node.endpoint_id)
        .expect("load old endpoint")
        .expect("old endpoint exists");
    let bound_node = rotated_store
        .get_node(&rotated_node.node_id)
        .expect("load node")
        .expect("node exists");
    let rotation_audit_count = rotated_store.audit_count().expect("audit count");
    let (actor, event, audit_node_id, audit_endpoint_id, detail) = latest_node_audit(&rotated_db);
    assert_eq!(actor, "operator");
    assert_eq!(event, "endpoint.rotate");
    assert_eq!(
        audit_node_id.as_deref(),
        Some(rotated_node.node_id.as_str())
    );
    assert_eq!(
        audit_endpoint_id.as_deref(),
        Some(rotated_node.endpoint_id.as_str())
    );
    assert_eq!(
        detail["before"]["node"]["endpoint_id"],
        rotated_node.endpoint_id
    );
    assert_eq!(detail["after"]["node"]["endpoint_id"], rotated_to);
    assert_eq!(detail["after"]["old_endpoint"]["status"], "rotated");
    assert_eq!(detail["after"]["new_endpoint"]["status"], "active");
    assert!(
        detail["after"]["new_endpoint"]
            .get("trust_bundle_json")
            .is_none()
    );
    assert!(detail["after"]["new_endpoint"].get("fingerprint").is_none());
    let retry = StoreWriter::write_endpoint_rotation(
        &rotated_store,
        &rotated_node.endpoint_id,
        &rotated_to,
        "operator",
        "same request retry",
    )
    .expect("exact rotation retry is idempotent");
    assert_eq!(retry, new_endpoint);
    assert_eq!(
        rotated_store
            .get_endpoint_trust(&rotated_node.endpoint_id)
            .expect("load old endpoint")
            .expect("old endpoint exists"),
        old_endpoint
    );
    assert_eq!(
        rotated_store
            .get_node(&rotated_node.node_id)
            .expect("load node")
            .expect("node exists"),
        bound_node
    );
    assert_eq!(
        rotated_store.audit_count().expect("audit count"),
        rotation_audit_count
    );
    let different_child = generated_endpoint_id();
    for result in [
        StoreWriter::write_endpoint_rotation(
            &rotated_store,
            &rotated_node.endpoint_id,
            &different_child,
            "operator",
            "branch",
        ),
        StoreWriter::write_endpoint_revocation(
            &rotated_store,
            &rotated_node.endpoint_id,
            "operator",
            "terminal",
        ),
        StoreWriter::write_endpoint_quarantine(
            &rotated_store,
            &rotated_node.endpoint_id,
            "operator",
            "terminal",
        ),
    ] {
        assert!(matches!(
            result,
            Err(StoreError::InvalidEndpointTransition { .. })
        ));
    }
    assert_eq!(
        rotated_store.audit_count().expect("audit count"),
        rotation_audit_count
    );
}

#[test]
fn endpoint_same_state_retry_rejects_contaminated_lineage() {
    let quarantine_dir = tempfile::tempdir().expect("quarantine temp dir");
    let quarantine_db = quarantine_dir.path().join("controller.sqlite");
    let quarantine_store = Store::open(&quarantine_db).expect("quarantine store opens");
    let quarantine_node = seed_generated_node(&quarantine_store, "retry-lineage-quarantine");
    StoreWriter::write_endpoint_quarantine(
        &quarantine_store,
        &quarantine_node.endpoint_id,
        "operator",
        "quarantine",
    )
    .expect("quarantine endpoint");
    Connection::open(&quarantine_db)
        .expect("open database")
        .execute(
            "UPDATE endpoint_trust SET rotated_to = ?1 WHERE endpoint_id = ?2",
            rusqlite::params![
                generated_endpoint_id(),
                quarantine_node.endpoint_id.as_str()
            ],
        )
        .expect("contaminate quarantined endpoint lineage");
    let quarantine_before = quarantine_store
        .get_endpoint_trust(&quarantine_node.endpoint_id)
        .expect("load endpoint")
        .expect("endpoint exists");
    let quarantine_audit_count = quarantine_store.audit_count().expect("audit count");
    assert!(matches!(
        StoreWriter::write_endpoint_quarantine(
            &quarantine_store,
            &quarantine_node.endpoint_id,
            "operator",
            "retry contaminated endpoint",
        ),
        Err(StoreError::EndpointLineageInvalid(ref endpoint_id))
            if endpoint_id == &quarantine_node.endpoint_id
    ));
    assert_eq!(
        quarantine_store
            .get_endpoint_trust(&quarantine_node.endpoint_id)
            .expect("load endpoint")
            .expect("endpoint exists"),
        quarantine_before
    );
    assert_eq!(
        quarantine_store.audit_count().expect("audit count"),
        quarantine_audit_count
    );

    let revoke_dir = tempfile::tempdir().expect("revoke temp dir");
    let revoke_db = revoke_dir.path().join("controller.sqlite");
    let revoke_store = Store::open(&revoke_db).expect("revoke store opens");
    let revoke_node = seed_generated_node(&revoke_store, "retry-lineage-revoke");
    let revoke_child = generated_endpoint_id();
    StoreWriter::write_endpoint_rotation(
        &revoke_store,
        &revoke_node.endpoint_id,
        &revoke_child,
        "operator",
        "rotate",
    )
    .expect("rotate endpoint");
    StoreWriter::write_endpoint_revocation(&revoke_store, &revoke_child, "operator", "revoke")
        .expect("revoke endpoint");
    Connection::open(&revoke_db)
        .expect("open database")
        .execute(
            "UPDATE endpoint_trust SET previous_endpoint_id = ?1 WHERE endpoint_id = ?2",
            rusqlite::params![generated_endpoint_id(), revoke_child.as_str()],
        )
        .expect("break previous endpoint lineage");
    let revoke_before = revoke_store
        .get_endpoint_trust(&revoke_child)
        .expect("load endpoint")
        .expect("endpoint exists");
    let revoke_audit_count = revoke_store.audit_count().expect("audit count");
    assert!(matches!(
        StoreWriter::write_endpoint_revocation(
            &revoke_store,
            &revoke_child,
            "operator",
            "retry contaminated endpoint",
        ),
        Err(StoreError::EndpointLineageInvalid(ref endpoint_id))
            if endpoint_id == &revoke_child
    ));
    assert_eq!(
        revoke_store
            .get_endpoint_trust(&revoke_child)
            .expect("load endpoint")
            .expect("endpoint exists"),
        revoke_before
    );
    assert_eq!(
        revoke_store.audit_count().expect("audit count"),
        revoke_audit_count
    );
}

#[test]
fn endpoint_generation_exhaustion_rejects_status_and_rotation_without_writes() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let node = seed_generated_node(&store, "generation-node");
    let max_generation = i64::MAX as u64;
    Connection::open(&db)
        .expect("open database")
        .execute(
            "UPDATE endpoint_trust
             SET generation = ?1, trust_bundle_json = ?2
             WHERE endpoint_id = ?3",
            rusqlite::params![
                i64::MAX,
                trust_bundle_fixture(&node.endpoint_id, max_generation, EndpointStatus::Active,),
                node.endpoint_id.as_str(),
            ],
        )
        .expect("set maximum generation");
    let before = store
        .get_endpoint_trust(&node.endpoint_id)
        .expect("load endpoint")
        .expect("endpoint exists");
    let audit_count = store.audit_count().expect("audit count");

    assert!(matches!(
        StoreWriter::write_endpoint_revocation(
            &store,
            &node.endpoint_id,
            "operator",
            "overflow",
        ),
        Err(StoreError::EndpointGenerationExhausted(ref endpoint_id))
            if endpoint_id == &node.endpoint_id
    ));
    let replacement = generated_endpoint_id();
    assert!(matches!(
        StoreWriter::write_endpoint_rotation(
            &store,
            &node.endpoint_id,
            &replacement,
            "operator",
            "overflow",
        ),
        Err(StoreError::EndpointGenerationExhausted(ref endpoint_id))
            if endpoint_id == &node.endpoint_id
    ));
    assert_eq!(
        store
            .get_endpoint_trust(&node.endpoint_id)
            .expect("load endpoint")
            .expect("endpoint exists"),
        before
    );
    assert!(
        store
            .get_endpoint_trust(&replacement)
            .expect("load replacement")
            .is_none()
    );
    assert_eq!(store.audit_count().expect("audit count"), audit_count);
}

#[test]
fn endpoint_rotation_reconciles_only_a_deterministic_legacy_pointer() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let node = seed_generated_node(&store, "legacy-rotation-node");
    let replacement = generated_endpoint_id();
    StoreWriter::write_endpoint_rotation(
        &store,
        &node.endpoint_id,
        &replacement,
        "operator",
        "initial rotation",
    )
    .expect("rotate endpoint");
    Connection::open(&db)
        .expect("open database")
        .execute(
            "UPDATE nodes SET endpoint_id = ?1 WHERE node_id = ?2",
            rusqlite::params![node.endpoint_id.as_str(), node.node_id.as_str()],
        )
        .expect("restore legacy stale pointer");
    let old_before = store
        .get_endpoint_trust(&node.endpoint_id)
        .expect("load old")
        .expect("old exists");
    let new_before = store
        .get_endpoint_trust(&replacement)
        .expect("load new")
        .expect("new exists");
    let audit_count = store.audit_count().expect("audit count");

    let retried = StoreWriter::write_endpoint_rotation(
        &store,
        &node.endpoint_id,
        &replacement,
        "operator",
        "reconcile legacy pointer",
    )
    .expect("reconcile deterministic rotation");
    assert_eq!(retried, new_before);
    assert_eq!(
        store
            .get_endpoint_trust(&node.endpoint_id)
            .expect("load old")
            .expect("old exists"),
        old_before
    );
    assert_eq!(
        store
            .get_endpoint_trust(&replacement)
            .expect("load new")
            .expect("new exists"),
        new_before
    );
    assert_eq!(
        store
            .get_node(&node.node_id)
            .expect("load node")
            .expect("node exists")
            .endpoint_id,
        replacement
    );
    assert_eq!(store.audit_count().expect("audit count"), audit_count + 1);
    let (actor, event, audit_node_id, audit_endpoint_id, detail) = latest_node_audit(&db);
    assert_eq!(actor, "operator");
    assert_eq!(event, "endpoint.rotate.reconcile");
    assert_eq!(audit_node_id.as_deref(), Some(node.node_id.as_str()));
    assert_eq!(
        audit_endpoint_id.as_deref(),
        Some(node.endpoint_id.as_str())
    );
    assert_eq!(detail["before"]["node"]["endpoint_id"], node.endpoint_id);
    assert_eq!(detail["after"]["node"]["endpoint_id"], replacement);
    assert_eq!(detail["after"]["old_endpoint"]["generation"], 2);
    assert_eq!(detail["after"]["new_endpoint"]["generation"], 2);

    let reconciled_audit_count = store.audit_count().expect("audit count");
    StoreWriter::write_endpoint_rotation(
        &store,
        &node.endpoint_id,
        &replacement,
        "operator",
        "clean retry",
    )
    .expect("clean retry");
    assert_eq!(
        store.audit_count().expect("audit count"),
        reconciled_audit_count
    );
}

#[test]
fn endpoint_rotation_exact_retry_rejects_contaminated_children() {
    let ambiguous_dir = tempfile::tempdir().expect("ambiguous temp dir");
    let ambiguous_db = ambiguous_dir.path().join("controller.sqlite");
    let ambiguous_store = Store::open(&ambiguous_db).expect("ambiguous store opens");
    let ambiguous_node = seed_generated_node(&ambiguous_store, "retry-ambiguous-node");
    let ambiguous_child = generated_endpoint_id();
    StoreWriter::write_endpoint_rotation(
        &ambiguous_store,
        &ambiguous_node.endpoint_id,
        &ambiguous_child,
        "operator",
        "rotate",
    )
    .expect("rotate endpoint");
    insert_active_endpoint_fixture(
        &ambiguous_db,
        &generated_endpoint_id(),
        &ambiguous_node.node_id,
    );
    let audit_count = ambiguous_store.audit_count().expect("audit count");
    assert!(matches!(
        StoreWriter::write_endpoint_rotation(
            &ambiguous_store,
            &ambiguous_node.endpoint_id,
            &ambiguous_child,
            "operator",
            "retry",
        ),
        Err(StoreError::AmbiguousActiveEndpointBinding(ref node_id))
            if node_id == &ambiguous_node.node_id
    ));
    assert_eq!(
        ambiguous_store.audit_count().expect("audit count"),
        audit_count
    );

    let inactive_dir = tempfile::tempdir().expect("inactive temp dir");
    let inactive_db = inactive_dir.path().join("controller.sqlite");
    let inactive_store = Store::open(&inactive_db).expect("inactive store opens");
    let inactive_node = seed_generated_node(&inactive_store, "retry-inactive-node");
    let inactive_child = generated_endpoint_id();
    StoreWriter::write_endpoint_rotation(
        &inactive_store,
        &inactive_node.endpoint_id,
        &inactive_child,
        "operator",
        "rotate",
    )
    .expect("rotate endpoint");
    StoreWriter::write_endpoint_revocation(
        &inactive_store,
        &inactive_child,
        "operator",
        "revoke child",
    )
    .expect("revoke child");
    Connection::open(&inactive_db)
        .expect("open database")
        .execute(
            "UPDATE nodes SET enabled = 1 WHERE node_id = ?1",
            [inactive_node.node_id.as_str()],
        )
        .expect("contaminate inactive binding");
    assert!(matches!(
        StoreWriter::write_endpoint_rotation(
            &inactive_store,
            &inactive_node.endpoint_id,
            &inactive_child,
            "operator",
            "retry",
        ),
        Err(StoreError::EndpointBindingMismatch { .. })
    ));

    let descendant_dir = tempfile::tempdir().expect("descendant temp dir");
    let descendant_db = descendant_dir.path().join("controller.sqlite");
    let descendant_store = Store::open(&descendant_db).expect("descendant store opens");
    let descendant_node = seed_generated_node(&descendant_store, "retry-descendant-node");
    let child = generated_endpoint_id();
    let grandchild = generated_endpoint_id();
    StoreWriter::write_endpoint_rotation(
        &descendant_store,
        &descendant_node.endpoint_id,
        &child,
        "operator",
        "first rotation",
    )
    .expect("rotate to child");
    StoreWriter::write_endpoint_rotation(
        &descendant_store,
        &child,
        &grandchild,
        "operator",
        "second rotation",
    )
    .expect("rotate child to grandchild");
    assert!(matches!(
        StoreWriter::write_endpoint_rotation(
            &descendant_store,
            &descendant_node.endpoint_id,
            &child,
            "operator",
            "retry old edge",
        ),
        Err(StoreError::EndpointBindingMismatch { .. })
    ));

    let stray_dir = tempfile::tempdir().expect("stray lineage temp dir");
    let stray_db = stray_dir.path().join("controller.sqlite");
    let stray_store = Store::open(&stray_db).expect("stray lineage store opens");
    let stray_node = seed_generated_node(&stray_store, "retry-stray-lineage-node");
    let stray_child = generated_endpoint_id();
    StoreWriter::write_endpoint_rotation(
        &stray_store,
        &stray_node.endpoint_id,
        &stray_child,
        "operator",
        "rotate",
    )
    .expect("rotate endpoint");
    Connection::open(&stray_db)
        .expect("open database")
        .execute(
            "UPDATE endpoint_trust SET rotated_to = ?1 WHERE endpoint_id = ?2",
            rusqlite::params![generated_endpoint_id(), stray_child.as_str()],
        )
        .expect("contaminate child lineage");
    let stray_old_before = stray_store
        .get_endpoint_trust(&stray_node.endpoint_id)
        .expect("load old endpoint")
        .expect("old endpoint exists");
    let stray_child_before = stray_store
        .get_endpoint_trust(&stray_child)
        .expect("load child endpoint")
        .expect("child endpoint exists");
    let stray_node_before = stray_store
        .get_node(&stray_node.node_id)
        .expect("load node")
        .expect("node exists");
    let stray_audit_count = stray_store.audit_count().expect("audit count");
    assert!(matches!(
        StoreWriter::write_endpoint_rotation(
            &stray_store,
            &stray_node.endpoint_id,
            &stray_child,
            "operator",
            "retry contaminated edge",
        ),
        Err(StoreError::EndpointLineageInvalid(ref endpoint_id))
            if endpoint_id == &stray_child
    ));
    assert_eq!(
        stray_store
            .get_endpoint_trust(&stray_node.endpoint_id)
            .expect("load old endpoint")
            .expect("old endpoint exists"),
        stray_old_before
    );
    assert_eq!(
        stray_store
            .get_endpoint_trust(&stray_child)
            .expect("load child endpoint")
            .expect("child endpoint exists"),
        stray_child_before
    );
    assert_eq!(
        stray_store
            .get_node(&stray_node.node_id)
            .expect("load node")
            .expect("node exists"),
        stray_node_before
    );
    assert_eq!(
        stray_store.audit_count().expect("audit count"),
        stray_audit_count
    );

    let unbound_dir = tempfile::tempdir().expect("unbound edge temp dir");
    let unbound_db = unbound_dir.path().join("controller.sqlite");
    let unbound_store = Store::open(&unbound_db).expect("unbound edge store opens");
    let unbound_node = seed_generated_node(&unbound_store, "retry-unbound-edge-node");
    let unbound_child = generated_endpoint_id();
    StoreWriter::write_endpoint_rotation(
        &unbound_store,
        &unbound_node.endpoint_id,
        &unbound_child,
        "operator",
        "rotate",
    )
    .expect("rotate endpoint");
    Connection::open(&unbound_db)
        .expect("open database")
        .execute(
            "UPDATE endpoint_trust SET node_id = NULL WHERE endpoint_id IN (?1, ?2)",
            rusqlite::params![unbound_node.endpoint_id.as_str(), unbound_child.as_str()],
        )
        .expect("unbind rotation edge");
    let unbound_old_before = unbound_store
        .get_endpoint_trust(&unbound_node.endpoint_id)
        .expect("load old endpoint")
        .expect("old endpoint exists");
    let unbound_child_before = unbound_store
        .get_endpoint_trust(&unbound_child)
        .expect("load child endpoint")
        .expect("child endpoint exists");
    let unbound_audit_count = unbound_store.audit_count().expect("audit count");
    assert!(matches!(
        StoreWriter::write_endpoint_rotation(
            &unbound_store,
            &unbound_node.endpoint_id,
            &unbound_child,
            "operator",
            "retry unbound edge",
        ),
        Err(StoreError::EndpointBindingMismatch { .. })
    ));
    assert_eq!(
        unbound_store
            .get_endpoint_trust(&unbound_node.endpoint_id)
            .expect("load old endpoint")
            .expect("old endpoint exists"),
        unbound_old_before
    );
    assert_eq!(
        unbound_store
            .get_endpoint_trust(&unbound_child)
            .expect("load child endpoint")
            .expect("child endpoint exists"),
        unbound_child_before
    );
    assert_eq!(
        unbound_store.audit_count().expect("audit count"),
        unbound_audit_count
    );
}

#[test]
fn endpoint_effective_rotation_rejects_unbound_trust() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let node = seed_generated_node(&store, "unbound-rotation-node");
    Connection::open(&db)
        .expect("open database")
        .execute(
            "UPDATE endpoint_trust SET node_id = NULL WHERE endpoint_id = ?1",
            [node.endpoint_id.as_str()],
        )
        .expect("unbind endpoint");
    let before = store
        .get_endpoint_trust(&node.endpoint_id)
        .expect("load endpoint")
        .expect("endpoint exists");
    let audit_count = store.audit_count().expect("audit count");
    let replacement = generated_endpoint_id();

    assert!(matches!(
        StoreWriter::write_endpoint_rotation(
            &store,
            &node.endpoint_id,
            &replacement,
            "operator",
            "must be bound",
        ),
        Err(StoreError::EndpointBindingMismatch { .. })
    ));
    assert_eq!(
        store
            .get_endpoint_trust(&node.endpoint_id)
            .expect("load endpoint")
            .expect("endpoint exists"),
        before
    );
    assert!(
        store
            .get_endpoint_trust(&replacement)
            .expect("load replacement")
            .is_none()
    );
    assert_eq!(store.audit_count().expect("audit count"), audit_count);
}

#[test]
fn node_remove_revokes_unique_legacy_active_descendant_and_keeps_tombstones() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let node = seed_generated_node(&store, "legacy-remove-node");
    let replacement = generated_endpoint_id();
    StoreWriter::write_endpoint_rotation(
        &store,
        &node.endpoint_id,
        &replacement,
        "operator",
        "rotate",
    )
    .expect("rotate endpoint");
    Connection::open(&db)
        .expect("open database")
        .execute(
            "UPDATE nodes SET endpoint_id = ?1 WHERE node_id = ?2",
            rusqlite::params![node.endpoint_id.as_str(), node.node_id.as_str()],
        )
        .expect("restore legacy stale pointer");

    StoreWriter::write_node_remove(&store, &node.node_id, "operator")
        .expect("remove node and revoke active descendant");

    assert!(store.get_node(&node.node_id).expect("load node").is_none());
    let old = store
        .get_endpoint_trust(&node.endpoint_id)
        .expect("load old")
        .expect("old tombstone exists");
    let replacement = store
        .get_endpoint_trust(&replacement)
        .expect("load replacement")
        .expect("replacement tombstone exists");
    assert_eq!(old.status, EndpointStatus::Rotated);
    assert_eq!(replacement.status, EndpointStatus::Revoked);
    assert_eq!(replacement.generation, 3);
    let (_, event, _, _, detail) = latest_node_audit(&db);
    assert_eq!(event, "node.remove");
    assert_eq!(detail["before"]["registry_endpoint"]["status"], "rotated");
    assert_eq!(detail["before"]["active_endpoint"]["status"], "active");
    assert_eq!(detail["after"]["registry_endpoint"]["status"], "rotated");
    assert_eq!(detail["after"]["active_endpoint"]["status"], "revoked");
}

#[test]
fn node_remove_revokes_unbound_current_active_and_rejects_ambiguous_candidates() {
    let unbound_dir = tempfile::tempdir().expect("unbound temp dir");
    let unbound_db = unbound_dir.path().join("controller.sqlite");
    let unbound_store = Store::open(&unbound_db).expect("unbound store opens");
    let unbound_node = seed_generated_node(&unbound_store, "unbound-remove-node");
    Connection::open(&unbound_db)
        .expect("open database")
        .execute(
            "UPDATE endpoint_trust SET node_id = NULL WHERE endpoint_id = ?1",
            [unbound_node.endpoint_id.as_str()],
        )
        .expect("unbind current endpoint");

    StoreWriter::write_node_remove(&unbound_store, &unbound_node.node_id, "operator")
        .expect("remove node with unbound current endpoint");
    assert!(
        unbound_store
            .get_node(&unbound_node.node_id)
            .expect("load node")
            .is_none()
    );
    assert_eq!(
        unbound_store
            .get_endpoint_trust(&unbound_node.endpoint_id)
            .expect("load endpoint")
            .expect("endpoint tombstone exists")
            .status,
        EndpointStatus::Revoked
    );

    let ambiguous_dir = tempfile::tempdir().expect("ambiguous temp dir");
    let ambiguous_db = ambiguous_dir.path().join("controller.sqlite");
    let ambiguous_store = Store::open(&ambiguous_db).expect("ambiguous store opens");
    let ambiguous_node = seed_generated_node(&ambiguous_store, "ambiguous-remove-node");
    let extra_endpoint = generated_endpoint_id();
    insert_active_endpoint_fixture(&ambiguous_db, &extra_endpoint, &ambiguous_node.node_id);
    let node_before = ambiguous_store
        .get_node(&ambiguous_node.node_id)
        .expect("load node")
        .expect("node exists");
    let primary_before = ambiguous_store
        .get_endpoint_trust(&ambiguous_node.endpoint_id)
        .expect("load primary")
        .expect("primary exists");
    let extra_before = ambiguous_store
        .get_endpoint_trust(&extra_endpoint)
        .expect("load extra")
        .expect("extra exists");
    let audit_count = ambiguous_store.audit_count().expect("audit count");

    assert!(matches!(
        StoreWriter::write_node_remove(&ambiguous_store, &ambiguous_node.node_id, "operator"),
        Err(StoreError::AmbiguousActiveEndpointBinding(ref node_id))
            if node_id == &ambiguous_node.node_id
    ));
    assert_eq!(
        ambiguous_store
            .get_node(&ambiguous_node.node_id)
            .expect("load node")
            .expect("node exists"),
        node_before
    );
    assert_eq!(
        ambiguous_store
            .get_endpoint_trust(&ambiguous_node.endpoint_id)
            .expect("load primary")
            .expect("primary exists"),
        primary_before
    );
    assert_eq!(
        ambiguous_store
            .get_endpoint_trust(&extra_endpoint)
            .expect("load extra")
            .expect("extra exists"),
        extra_before
    );
    assert_eq!(
        ambiguous_store.audit_count().expect("audit count"),
        audit_count
    );
}

#[test]
fn node_enable_requires_one_clean_active_bidirectional_binding() {
    let inactive_dir = tempfile::tempdir().expect("inactive temp dir");
    let inactive_db = inactive_dir.path().join("controller.sqlite");
    let inactive_store = Store::open(&inactive_db).expect("inactive store opens");
    let inactive_node = seed_generated_node(&inactive_store, "inactive-enable-node");
    StoreWriter::write_endpoint_revocation(
        &inactive_store,
        &inactive_node.endpoint_id,
        "operator",
        "revoke",
    )
    .expect("revoke endpoint");
    assert!(matches!(
        StoreWriter::write_node_enable(&inactive_store, &inactive_node.node_id, "operator"),
        Err(StoreError::EndpointBindingMismatch { .. })
    ));

    let unbound_dir = tempfile::tempdir().expect("unbound temp dir");
    let unbound_db = unbound_dir.path().join("controller.sqlite");
    let unbound_store = Store::open(&unbound_db).expect("unbound store opens");
    let unbound_node = seed_generated_node(&unbound_store, "unbound-enable-node");
    StoreWriter::write_node_disable(&unbound_store, &unbound_node.node_id, "operator")
        .expect("disable node");
    Connection::open(&unbound_db)
        .expect("open database")
        .execute(
            "UPDATE endpoint_trust SET node_id = NULL WHERE endpoint_id = ?1",
            [unbound_node.endpoint_id.as_str()],
        )
        .expect("unbind endpoint");
    assert!(matches!(
        StoreWriter::write_node_enable(&unbound_store, &unbound_node.node_id, "operator"),
        Err(StoreError::EndpointBindingMismatch { .. })
    ));

    let ambiguous_dir = tempfile::tempdir().expect("ambiguous temp dir");
    let ambiguous_db = ambiguous_dir.path().join("controller.sqlite");
    let ambiguous_store = Store::open(&ambiguous_db).expect("ambiguous store opens");
    let ambiguous_node = seed_generated_node(&ambiguous_store, "ambiguous-enable-node");
    StoreWriter::write_node_disable(&ambiguous_store, &ambiguous_node.node_id, "operator")
        .expect("disable node");
    insert_active_endpoint_fixture(
        &ambiguous_db,
        &generated_endpoint_id(),
        &ambiguous_node.node_id,
    );
    assert!(matches!(
        StoreWriter::write_node_enable(&ambiguous_store, &ambiguous_node.node_id, "operator"),
        Err(StoreError::AmbiguousActiveEndpointBinding(ref node_id))
            if node_id == &ambiguous_node.node_id
    ));
}

#[test]
fn endpoint_rotation_audit_failure_rolls_back_registry_and_both_trust_rows() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let node = seed_generated_node(&store, "rotation-rollback-node");
    let node_before = store
        .get_node(&node.node_id)
        .expect("load node")
        .expect("node exists");
    let endpoint_before = store
        .get_endpoint_trust(&node.endpoint_id)
        .expect("load endpoint")
        .expect("endpoint exists");
    let audit_count = store.audit_count().expect("audit count");
    inject_audit_insert_failure(&db);
    let replacement = generated_endpoint_id();

    assert!(matches!(
        StoreWriter::write_endpoint_rotation(
            &store,
            &node.endpoint_id,
            &replacement,
            "operator",
            "rotation rollback",
        ),
        Err(StoreError::Sqlite(_))
    ));
    assert_eq!(
        store
            .get_node(&node.node_id)
            .expect("load node")
            .expect("node exists"),
        node_before
    );
    assert_eq!(
        store
            .get_endpoint_trust(&node.endpoint_id)
            .expect("load endpoint")
            .expect("endpoint exists"),
        endpoint_before
    );
    assert!(
        store
            .get_endpoint_trust(&replacement)
            .expect("load replacement")
            .is_none()
    );
    assert_eq!(store.audit_count().expect("audit count"), audit_count);
}

#[test]
fn endpoint_rotation_reconcile_audit_failure_rolls_back_pointer_only_repair() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let node = seed_generated_node(&store, "reconcile-rollback-node");
    let replacement = generated_endpoint_id();
    StoreWriter::write_endpoint_rotation(
        &store,
        &node.endpoint_id,
        &replacement,
        "operator",
        "initial rotation",
    )
    .expect("rotate endpoint");
    Connection::open(&db)
        .expect("open database")
        .execute(
            "UPDATE nodes SET endpoint_id = ?1 WHERE node_id = ?2",
            rusqlite::params![node.endpoint_id.as_str(), node.node_id.as_str()],
        )
        .expect("restore legacy stale pointer");
    let node_before = store
        .get_node(&node.node_id)
        .expect("load node")
        .expect("node exists");
    let old_before = store
        .get_endpoint_trust(&node.endpoint_id)
        .expect("load old endpoint")
        .expect("old endpoint exists");
    let new_before = store
        .get_endpoint_trust(&replacement)
        .expect("load new endpoint")
        .expect("new endpoint exists");
    let audit_count = store.audit_count().expect("audit count");
    inject_audit_insert_failure(&db);

    assert!(matches!(
        StoreWriter::write_endpoint_rotation(
            &store,
            &node.endpoint_id,
            &replacement,
            "operator",
            "reconcile rollback",
        ),
        Err(StoreError::Sqlite(_))
    ));
    assert_eq!(
        store
            .get_node(&node.node_id)
            .expect("load node")
            .expect("node exists"),
        node_before
    );
    assert_eq!(
        store
            .get_endpoint_trust(&node.endpoint_id)
            .expect("load old endpoint")
            .expect("old endpoint exists"),
        old_before
    );
    assert_eq!(
        store
            .get_endpoint_trust(&replacement)
            .expect("load new endpoint")
            .expect("new endpoint exists"),
        new_before
    );
    assert_eq!(store.audit_count().expect("audit count"), audit_count);
}

#[test]
fn endpoint_status_audit_failure_rolls_back_trust_and_node_disable() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    let node = seed_generated_node(&store, "status-rollback-node");
    let node_before = store
        .get_node(&node.node_id)
        .expect("load node")
        .expect("node exists");
    let endpoint_before = store
        .get_endpoint_trust(&node.endpoint_id)
        .expect("load endpoint")
        .expect("endpoint exists");
    let audit_count = store.audit_count().expect("audit count");
    inject_audit_insert_failure(&db);

    assert!(matches!(
        StoreWriter::write_endpoint_quarantine(
            &store,
            &node.endpoint_id,
            "operator",
            "status rollback",
        ),
        Err(StoreError::Sqlite(_))
    ));
    assert_eq!(
        store
            .get_node(&node.node_id)
            .expect("load node")
            .expect("node exists"),
        node_before
    );
    assert_eq!(
        store
            .get_endpoint_trust(&node.endpoint_id)
            .expect("load endpoint")
            .expect("endpoint exists"),
        endpoint_before
    );
    assert_eq!(store.audit_count().expect("audit count"), audit_count);

    let revoke_dir = tempfile::tempdir().expect("revoke temp dir");
    let revoke_db = revoke_dir.path().join("controller.sqlite");
    let revoke_store = Store::open(&revoke_db).expect("revoke store opens");
    let revoke_node = seed_generated_node(&revoke_store, "revoke-rollback-node");
    let revoke_node_before = revoke_store
        .get_node(&revoke_node.node_id)
        .expect("load node")
        .expect("node exists");
    let revoke_endpoint_before = revoke_store
        .get_endpoint_trust(&revoke_node.endpoint_id)
        .expect("load endpoint")
        .expect("endpoint exists");
    let revoke_audit_count = revoke_store.audit_count().expect("audit count");
    inject_audit_insert_failure(&revoke_db);
    assert!(matches!(
        StoreWriter::write_endpoint_revocation(
            &revoke_store,
            &revoke_node.endpoint_id,
            "operator",
            "revoke rollback",
        ),
        Err(StoreError::Sqlite(_))
    ));
    assert_eq!(
        revoke_store
            .get_node(&revoke_node.node_id)
            .expect("load node")
            .expect("node exists"),
        revoke_node_before
    );
    assert_eq!(
        revoke_store
            .get_endpoint_trust(&revoke_node.endpoint_id)
            .expect("load endpoint")
            .expect("endpoint exists"),
        revoke_endpoint_before
    );
    assert_eq!(
        revoke_store.audit_count().expect("audit count"),
        revoke_audit_count
    );
}
