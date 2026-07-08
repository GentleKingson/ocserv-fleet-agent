use ocfleet_cli::audit::AuditEvent;
use ocfleet_cli::store::{
    ApprovalInput, CURRENT_SCHEMA_VERSION, EnrollmentTokenInsert, JoinRequestInsert, NodeInsert,
    Store, StoreError,
};
use ocfleet_protocol::enrollment::{EndpointStatus, EnrollmentTokenStatus, JoinRequestStatus};
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

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
    store.add_node(&first).expect("first insert");
    assert!(store.add_node(&second).is_err());
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
    store.add_node(&node).expect("insert");
    store.disable_node("hk-ocserv-01").expect("disable");
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

    assert_node_not_found(store.disable_node("missing-disable"), "missing-disable");
    assert_node_not_found(store.enable_node("missing-enable"), "missing-enable");
    assert_node_not_found(store.remove_node("missing-remove"), "missing-remove");
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
    store.add_node(&node).expect("insert");
    let mut event = AuditEvent::new("local-cli", "node.add");
    event.node_id = Some("hk-ocserv-01".into());
    event.endpoint_id = Some("endpoint-one".into());
    event.ok = Some(true);
    store.insert_audit(&event).expect("audit insert");
    store.remove_node("hk-ocserv-01").expect("remove");
    assert!(store.get_node("hk-ocserv-01").expect("load").is_none());
    assert_eq!(store.audit_count().expect("count"), 1);
}

fn future_time() -> String {
    "2099-01-01T00:00:00Z".to_string()
}

fn past_time() -> String {
    "2000-01-01T00:00:00Z".to_string()
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
fn endpoint_lifecycle_rotate_revoke_and_quarantine_update_status_and_generation() {
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
    store
        .add_node(&node)
        .expect("insert node and endpoint trust");

    let rotated = store
        .rotate_endpoint(&endpoint_one, &endpoint_two, "operator", "key rotation")
        .expect("rotate endpoint");
    assert_eq!(rotated.status, EndpointStatus::Active);
    assert_eq!(rotated.generation, 2);
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

    let revoked = store
        .revoke_endpoint(&endpoint_two, "operator", "lost host")
        .expect("revoke endpoint");
    assert_eq!(revoked.status, EndpointStatus::Revoked);
    assert_eq!(revoked.generation, 3);

    let quarantined = store
        .quarantine_endpoint(&endpoint_two, "operator", "suspicious traffic")
        .expect("quarantine endpoint");
    assert_eq!(quarantined.status, EndpointStatus::Quarantined);
    assert_eq!(quarantined.generation, 4);

    let (event, detail) = latest_audit_event(&db);
    assert_eq!(event, "endpoint.quarantine");
    assert_eq!(detail["target_id"], endpoint_two);
    assert_eq!(detail["reason"], "suspicious traffic");
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
    store
        .add_node(&node)
        .expect("insert node and endpoint trust");

    let err = store
        .rotate_endpoint(&endpoint_one, "endpoint-two", "operator", "key rotation")
        .expect_err("invalid endpoint id must be rejected");

    assert!(matches!(err, StoreError::InvalidInput(_)));
    assert!(
        store
            .get_endpoint_trust("endpoint-two")
            .expect("query trust")
            .is_none()
    );
}
