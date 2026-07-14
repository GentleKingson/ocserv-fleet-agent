#![cfg(feature = "postgres-backend")]

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Barrier};
use std::thread;

use ocfleet_cli::postgres_backend::{PostgresConnectionSource, PostgresError};
use ocfleet_cli::postgres_native::{NATIVE_BACKEND_SCHEMA_VERSION, connect_native};
use ocfleet_cli::store::NodeInsert;
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
    let dsn =
        format!("postgresql://ocfleet:test-only-password@127.0.0.1:{port}/ocfleet_native_test");
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

    let mut admin = postgres::Client::connect(&dsn, postgres::NoTls).expect("admin client");
    let trust = admin
        .query_one(
            "SELECT status, generation, trust_bundle_json->>'schema'
             FROM endpoint_trust WHERE endpoint_id = $1",
            &[&node.endpoint_id],
        )
        .expect("relational trust row");
    assert_eq!(trust.get::<_, String>(0), "active");
    assert_eq!(trust.get::<_, i64>(1), 1);
    assert_eq!(trust.get::<_, String>(2), "ocfleet.trust.bundle.v1");
    let audit_schema: String = admin
        .query_one(
            "SELECT detail_json->'_audit'->>'schema'
             FROM controller_audit_log WHERE event = 'node.add'",
            &[],
        )
        .expect("typed audit row")
        .get(0);
    assert_eq!(audit_schema, "ocfleet.audit.detail.v1");

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
BEFORE INSERT ON controller_audit_log
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
            "SELECT COUNT(*) FROM endpoint_trust WHERE endpoint_id = $1",
            &[&rejected.endpoint_id],
        )
        .expect("rolled back trust query")
        .get(0);
    assert_eq!(trust_count, 0);
    admin
        .batch_execute(
            "DROP TRIGGER fail_native_node_audit ON controller_audit_log;
             DROP FUNCTION fail_native_node_audit();",
        )
        .expect("remove audit failure trigger");

    admin
        .execute(
            "INSERT INTO ocfleet_native_migrations (version, name) VALUES ($1, $2)",
            &[&(NATIVE_BACKEND_SCHEMA_VERSION + 1), &"future_schema"],
        )
        .expect("install future migration marker");
    let row = admin
        .query_one(
            "SELECT
               (SELECT COUNT(*) FROM ocfleet_native_migrations),
               (SELECT COUNT(*) FROM nodes),
               (SELECT COUNT(*) FROM controller_audit_log)",
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
               (SELECT COUNT(*) FROM ocfleet_native_migrations),
               (SELECT COUNT(*) FROM nodes),
               (SELECT COUNT(*) FROM controller_audit_log)",
            &[],
        )
        .expect("snapshot after rejected connect");
    let after: (i64, i64, i64) = (row.get(0), row.get(1), row.get(2));
    assert_eq!(after, before);
}
