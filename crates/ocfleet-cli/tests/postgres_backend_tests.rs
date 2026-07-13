#![cfg(feature = "postgres-backend")]

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Barrier};
use std::thread;

use ocfleet_cli::backend::{StoreReader, StoreWriter};
use ocfleet_cli::postgres_backend::{PostgresConnectionSource, PostgresError, connect};
use ocfleet_cli::store::{NodeInsert, Store};
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
fn postgres_migration_contention_and_transactional_fencing() {
    let container = GenericImage::new("postgres", "17-alpine")
        .with_exposed_port(5432.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_USER", "ocfleet")
        .with_env_var("POSTGRES_PASSWORD", "test-only-password")
        .with_env_var("POSTGRES_DB", "ocfleet_test")
        .start()
        .expect("start isolated Postgres");
    let port = container
        .get_host_port_ipv4(5432.tcp())
        .expect("mapped Postgres port");
    let dsn = format!("postgresql://ocfleet:test-only-password@127.0.0.1:{port}/ocfleet_test");
    let (_dir, source) = postgres_source(&dsn);

    let barrier = Arc::new(Barrier::new(3));
    let mut clients = Vec::new();
    for _ in 0..2 {
        let source = source.clone();
        let barrier = Arc::clone(&barrier);
        clients.push(thread::spawn(move || {
            barrier.wait();
            connect(&source).expect("contending migration client")
        }));
    }
    barrier.wait();
    let first = clients.remove(0).join().expect("first client");
    let second = clients.remove(0).join().expect("second client");
    assert_eq!(first.doctor().expect("doctor").schema_version, 28);
    assert_eq!(second.doctor().expect("doctor").schema_version, 28);

    let unfenced_node = NodeInsert {
        node_id: "node-pg-unfenced".into(),
        endpoint_id: iroh::SecretKey::generate().public().to_string(),
        name: "node-pg-unfenced".into(),
        region: "test".into(),
        role: "ocserv".into(),
    };
    assert!(matches!(
        StoreWriter::write_node_add(&first, &unfenced_node, "operator"),
        Err(PostgresError::FenceRequired)
    ));

    let lease_one = first
        .acquire_lease("controller-writer", "replica-a", 30)
        .expect("lease query")
        .expect("lease acquired");
    let writer_one = first.fenced(lease_one.clone()).expect("fenced writer");

    let import_dir = tempfile::tempdir().expect("import dir");
    let import_path = import_dir.path().join("controller.sqlite3");
    let import_store = Store::open(&import_path).expect("create import source");
    let imported_node = NodeInsert {
        node_id: "node-pg-imported".into(),
        endpoint_id: iroh::SecretKey::generate().public().to_string(),
        name: "node-pg-imported".into(),
        region: "test".into(),
        role: "ocserv".into(),
    };
    import_store
        .add_node(&imported_node, "operator")
        .expect("populate import source");
    drop(import_store);
    let dry_run = first
        .import_sqlite(&import_path, true)
        .expect("unfenced dry-run import");
    assert!(dry_run.dry_run);
    assert!(matches!(
        first.import_sqlite(&import_path, false),
        Err(PostgresError::FenceRequired)
    ));
    writer_one
        .import_sqlite(&import_path, false)
        .expect("fenced import");
    assert!(
        StoreReader::read_node(&writer_one, "node-pg-imported")
            .expect("read imported node")
            .is_some()
    );

    let node_one = NodeInsert {
        node_id: "node-pg-one".into(),
        endpoint_id: iroh::SecretKey::generate().public().to_string(),
        name: "node-pg-one".into(),
        region: "test".into(),
        role: "ocserv".into(),
    };
    StoreWriter::write_node_add(&writer_one, &node_one, "operator").expect("fenced write");

    let mut admin = postgres::Client::connect(&dsn, postgres::NoTls).expect("admin connection");
    admin
        .execute(
            "UPDATE ocfleet_controller_leases SET lease_until = now() - interval '1 second'
             WHERE lease_name = 'controller-writer'",
            &[],
        )
        .expect("expire lease");
    let lease_two = second
        .acquire_lease("controller-writer", "replica-a", 30)
        .expect("same-owner reacquire")
        .expect("lease reacquired");
    assert!(lease_two.fencing_token > lease_one.fencing_token);

    let stale_node = NodeInsert {
        node_id: "node-pg-stale".into(),
        endpoint_id: iroh::SecretKey::generate().public().to_string(),
        name: "node-pg-stale".into(),
        region: "test".into(),
        role: "ocserv".into(),
    };
    assert!(matches!(
        StoreWriter::write_node_add(&writer_one, &stale_node, "operator"),
        Err(PostgresError::StaleFence)
    ));

    let writer_two = second.fenced(lease_two).expect("new fenced writer");
    StoreWriter::write_node_add(&writer_two, &stale_node, "operator").expect("takeover write");
    assert!(
        StoreReader::read_node(&writer_two, "node-pg-stale")
            .expect("read")
            .is_some()
    );
}
