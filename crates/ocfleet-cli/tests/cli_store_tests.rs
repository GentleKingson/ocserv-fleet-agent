use ocfleet_cli::audit::AuditEvent;
use ocfleet_cli::backend::StoreWriter;
use ocfleet_cli::store::{
    ApprovalInput, CURRENT_SCHEMA_VERSION, EnrollmentTokenInsert, JoinRequestInsert, NodeInsert,
    Store, StoreError,
};
use ocfleet_protocol::enrollment::{EndpointStatus, EnrollmentTokenStatus, JoinRequestStatus};
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

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
                created_by: "operator".to_string(),
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
                created_by: "operator".to_string(),
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
                created_by: "operator".to_string(),
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
                created_by: "operator".to_string(),
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
        .approve_join_request(&ApprovalInput {
            request_id: join.request_id.clone(),
            endpoint_id: endpoint_id.clone(),
            approved_by: "operator".to_string(),
            reason: "ticket-123".to_string(),
            approved_labels_json: serde_json::json!({"region": "hk", "role": "ocserv"}),
        })
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
    assert_eq!(
        endpoint.node_id, None,
        "approval must not trust or bind agent self-reported hostname"
    );

    let (event, detail) = latest_audit_event(&db);
    assert_eq!(event, "enrollment.approve");
    assert_eq!(detail["before"]["status"], "pending");
    assert_eq!(detail["after"]["status"], "approved");
    assert_eq!(detail["reason"], "ticket-123");
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
                created_by: "operator".to_string(),
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
                created_by: "operator".to_string(),
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
        .approve_join_request(&ApprovalInput {
            request_id: join.request_id,
            endpoint_id: different_endpoint_id.clone(),
            approved_by: "operator".to_string(),
            reason: "ticket-123".to_string(),
            approved_labels_json: serde_json::json!({}),
        })
        .expect_err("different endpoint id rejected");

    assert!(
        matches!(err, StoreError::InvalidInput(ref message) if message.contains("requested_endpoint_id")),
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
                created_by: "operator".to_string(),
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
        .approve_join_request(&ApprovalInput {
            request_id: join.request_id,
            endpoint_id: "endpoint-approved".to_string(),
            approved_by: "operator".to_string(),
            reason: "ticket-123".to_string(),
            approved_labels_json: serde_json::json!({}),
        })
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
