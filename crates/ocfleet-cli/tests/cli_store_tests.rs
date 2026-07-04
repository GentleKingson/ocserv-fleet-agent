use ocfleet_cli::audit::AuditEvent;
use ocfleet_cli::store::{NodeInsert, Store};

#[test]
fn initializes_schema_and_migration_version() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    assert_eq!(store.current_schema_version().expect("version"), 1);
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
