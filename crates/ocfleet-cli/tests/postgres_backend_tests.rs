#![cfg(feature = "postgres-backend")]

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Barrier};
use std::thread;

use ocfleet_cli::backend::{StoreReader, StoreWriter};
use ocfleet_cli::postgres_backend::{PostgresConnectionSource, PostgresError, connect};
use ocfleet_cli::store::{NodeInsert, Store};
use rusqlite::OpenFlags;
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
    let first_doctor = first.doctor().expect("doctor");
    assert_eq!(first_doctor.backend_schema_version, 2);
    assert_eq!(first_doctor.schema_version, 28);
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
    let old_schema_path = import_dir.path().join("schema-27.sqlite3");
    drop(Store::open(&old_schema_path).expect("create schema 27 fixture"));
    let old_schema = rusqlite::Connection::open(&old_schema_path).expect("open schema 27 fixture");
    old_schema
        .execute_batch(
            "DROP TABLE signed_bundles;
             DROP TABLE write_operation_audit;
             DROP TABLE write_operation_attempts;
             DROP TABLE change_approvals;
             DROP TABLE change_requests;
             DELETE FROM schema_migrations WHERE version = 28;",
        )
        .expect("downgrade fixture to schema 27");
    drop(old_schema);
    assert!(matches!(
        first.import_sqlite(&old_schema_path, true),
        Err(PostgresError::InvalidState(_))
    ));
    let old_schema = rusqlite::Connection::open_with_flags(
        &old_schema_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("inspect rejected schema 27 fixture");
    let old_version: i64 = old_schema
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .expect("read old schema without migration");
    assert_eq!(
        old_version, 27,
        "import validation must not migrate its source"
    );

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
    assert!(!dry_run.already_current);
    assert!(matches!(
        first.import_sqlite(&import_path, false),
        Err(PostgresError::FenceRequired)
    ));
    writer_one
        .import_sqlite(&import_path, false)
        .expect("fenced import");
    assert!(
        writer_one
            .import_sqlite(&import_path, false)
            .expect("idempotent resumed import")
            .already_current
    );
    assert!(
        StoreReader::read_node(&writer_one, "node-pg-imported")
            .expect("read imported node")
            .is_some()
    );

    let wal_path = import_dir.path().join("controller-active-wal.sqlite3");
    let wal_store = Store::open(&wal_path).expect("create active WAL source");
    let wal_node = NodeInsert {
        node_id: "node-pg-active-wal".into(),
        endpoint_id: iroh::SecretKey::generate().public().to_string(),
        name: "node-pg-active-wal".into(),
        region: "test".into(),
        role: "ocserv".into(),
    };
    wal_store
        .add_node(&wal_node, "operator")
        .expect("commit node into active WAL");
    let wal_sidecar = std::path::PathBuf::from(format!("{}-wal", wal_path.display()));
    assert!(
        fs::metadata(&wal_sidecar)
            .expect("active WAL sidecar")
            .len()
            > 0,
        "fixture must retain committed data in WAL"
    );
    writer_one
        .import_sqlite(&wal_path, false)
        .expect("online backup import with active WAL");
    assert!(
        StoreReader::read_node(&writer_one, "node-pg-active-wal")
            .expect("read WAL-backed imported node")
            .is_some(),
        "successful import must include committed WAL data"
    );
    drop(wal_store);

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

    let export_dir = tempfile::tempdir().expect("export dir");
    #[cfg(unix)]
    fs::set_permissions(export_dir.path(), fs::Permissions::from_mode(0o700))
        .expect("private export dir");
    let export_path = export_dir.path().join("exported.sqlite3");
    let export = writer_two
        .export_sqlite(&export_path)
        .expect("verified SQLite export");
    assert_eq!(export.schema_version, 28);
    assert!(export.counts_verified >= 1);
    let exported_schema = rusqlite::Connection::open_with_flags(
        &export_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("inspect export without migrations");
    let exported_version: i64 = exported_schema
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .expect("read exported schema");
    assert_eq!(exported_version, export.schema_version);
    drop(exported_schema);
    let exported = Store::open(&export_path).expect("open exported state");
    assert!(exported.get_node("node-pg-stale").expect("node").is_some());

    admin
        .execute(
            "UPDATE ocfleet_runtime_state SET sqlite_schema_version = 27 WHERE singleton = TRUE",
            &[],
        )
        .expect("inject mismatched schema metadata");
    assert!(matches!(
        writer_two.doctor(),
        Err(PostgresError::InvalidState(_))
    ));
    admin
        .execute(
            "UPDATE ocfleet_runtime_state SET sqlite_schema_version = 28 WHERE singleton = TRUE",
            &[],
        )
        .expect("restore schema metadata");
    assert_eq!(
        writer_two
            .doctor()
            .expect("consistent doctor")
            .schema_version,
        28
    );

    let rollback_dir = tempfile::tempdir().expect("rollback fixture dir");
    let rollback_path = rollback_dir.path().join("rollback.sqlite3");
    drop(Store::open(&rollback_path).expect("rollback fixture store"));
    let rollback_conn = rusqlite::Connection::open(&rollback_path).expect("open rollback fixture");
    rollback_conn
        .execute_batch(
            "CREATE TRIGGER reject_controller_audit BEFORE INSERT ON controller_audit_log
             BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;",
        )
        .expect("install audit trigger");
    drop(rollback_conn);
    writer_two
        .import_sqlite(&rollback_path, false)
        .expect("import audit-failure fixture");
    let rollback_node = NodeInsert {
        node_id: "node-pg-rollback".into(),
        endpoint_id: iroh::SecretKey::generate().public().to_string(),
        name: "node-pg-rollback".into(),
        region: "test".into(),
        role: "ocserv".into(),
    };
    assert!(StoreWriter::write_node_add(&writer_two, &rollback_node, "operator").is_err());
    assert!(
        StoreReader::read_node(&writer_two, "node-pg-rollback")
            .expect("read rolled-back state")
            .is_none()
    );
}
