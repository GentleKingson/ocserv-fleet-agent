use ocfleet_cli::audit::AuditEvent;
use ocfleet_cli::store::{NodeInsert, Store, StoreError};
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
    assert_eq!(store.current_schema_version().expect("version"), 1);
}

#[test]
fn open_with_status_reports_database_creation() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");

    let first = Store::open_with_status(&db).expect("create store with status");
    assert!(first.created_database);
    assert_eq!(first.store.current_schema_version().expect("version"), 1);
    drop(first);

    let second = Store::open_with_status(&db).expect("reopen store with status");
    assert!(!second.created_database);
    assert_eq!(second.store.current_schema_version().expect("version"), 1);
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
