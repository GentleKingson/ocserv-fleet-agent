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
    let loaded = store.get_node("hk-ocserv-01").expect("load").expect("exists");
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
