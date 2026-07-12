use ocfleet_cli::store::{CURRENT_SCHEMA_VERSION, Store, StoreError};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

const NOW: &str = "2026-07-09T00:00:00Z";

#[test]
fn migration_tests_new_database_creates_all_current_tables_and_indexes() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");

    let store = Store::open(&db).expect("open new store");
    assert_eq!(
        store.current_schema_version().expect("schema version"),
        CURRENT_SCHEMA_VERSION
    );
    drop(store);

    let conn = Connection::open(&db).expect("open db");
    for table in [
        "schema_migrations",
        "nodes",
        "controller_audit_log",
        "enrollment_tokens",
        "join_requests",
        "endpoint_trust",
        "observability_jobs",
        "observability_runs",
        "probe_observations",
        "health_snapshots",
        "alert_events",
        "retention_policies",
        "health_policy",
        "alert_hooks",
        "alert_delivery_attempts",
        "scheduler_job_claims",
        "scheduler_maintenance",
        "health_evaluation_runs",
        "alert_delivery_queue",
        "health_history",
        "health_rollups",
        "node_metadata",
        "node_maintenance_windows",
        "node_capability_snapshots",
    ] {
        assert_schema_object_exists(&conn, "table", table);
    }
    for index in [
        "idx_observability_jobs_enabled_next_run_at",
        "idx_probe_observations_node_observed_at",
        "idx_probe_observations_run_id",
        "idx_alert_events_state_last_seen_at",
        "idx_alert_delivery_attempts_alert_hook",
        "idx_alert_hooks_enabled_type",
        "idx_scheduler_job_claims_expiry",
        "idx_health_evaluation_runs_input",
        "idx_health_evaluation_runs_status_started",
        "idx_alert_delivery_queue_alert_hook_key",
        "idx_node_metadata_environment",
        "idx_node_maintenance_active",
        "idx_alert_delivery_queue_due",
        "idx_alert_delivery_queue_lease",
        "idx_health_history_node_computed",
        "idx_health_history_computed",
        "idx_health_rollups_window",
        "idx_health_rollups_node_window",
        "idx_node_capability_snapshots_observed",
    ] {
        assert_schema_object_exists(&conn, "index", index);
    }
    assert_eq!(table_count(&conn, "health_policy"), 1);
    assert_sqlite_checks_pass(&conn);
}

#[test]
fn migration_tests_rejects_future_schema_without_backup_or_rebuild() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("open new store");
    drop(store);

    let conn = Connection::open(&db).expect("open db");
    conn.execute(
        "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
        (CURRENT_SCHEMA_VERSION + 1, NOW),
    )
    .expect("insert future schema");
    drop(conn);

    let err = match Store::open(&db) {
        Ok(_) => panic!("future schema must be refused"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            StoreError::UnsupportedFutureSchema {
                found,
                supported
            } if found == CURRENT_SCHEMA_VERSION + 1 && supported == CURRENT_SCHEMA_VERSION
        ),
        "unexpected error: {err:?}"
    );
    assert!(
        backup_files(dir.path()).is_empty(),
        "future refusal must not create backups"
    );

    let conn = Connection::open(&db).expect("reopen raw db");
    let future_count: i64 = conn
        .query_row(
            "SELECT count(*) FROM schema_migrations WHERE version = ?1",
            [CURRENT_SCHEMA_VERSION + 1],
            |row| row.get(0),
        )
        .expect("future migration row remains");
    assert_eq!(future_count, 1);
}

#[test]
fn migration_tests_legacy_fixtures_upgrade_to_current() {
    for version in 1..CURRENT_SCHEMA_VERSION {
        let dir = tempfile::tempdir().expect("temp dir");
        let db = dir.path().join("controller.sqlite");
        create_legacy_fixture(&db, version, 1);

        let store = Store::open(&db)
            .unwrap_or_else(|err| panic!("v{version} fixture should upgrade to current: {err:?}"));
        assert_eq!(
            store.current_schema_version().expect("schema version"),
            CURRENT_SCHEMA_VERSION
        );
        drop(store);

        let conn = Connection::open(&db).expect("open upgraded db");
        assert_sqlite_checks_pass(&conn);
        assert_eq!(table_count(&conn, "nodes"), 1, "v{version} node count");
        assert_eq!(
            table_count(&conn, "controller_audit_log"),
            1,
            "v{version} audit count"
        );
        if version >= 2 {
            assert_eq!(
                table_count(&conn, "enrollment_tokens"),
                1,
                "v{version} token count"
            );
        }
        if version >= 3 {
            assert_eq!(
                table_count(&conn, "endpoint_trust"),
                1,
                "v{version} endpoint trust count"
            );
        }
        if version >= 4 {
            for table in [
                "observability_jobs",
                "observability_runs",
                "probe_observations",
                "health_snapshots",
                "alert_events",
            ] {
                assert_eq!(table_count(&conn, table), 1, "v{version} {table} count");
            }
        }
        assert_schema_object_exists(&conn, "table", "retention_policies");
        assert_schema_object_exists(&conn, "table", "health_policy");
        assert_schema_object_exists(&conn, "table", "alert_hooks");
        assert_schema_object_exists(&conn, "table", "alert_delivery_attempts");
        assert_eq!(table_count(&conn, "health_policy"), 1);
        assert_schema_object_exists(&conn, "index", "idx_probe_observations_run_id");
        assert_schema_object_exists(&conn, "index", "idx_alert_delivery_attempts_alert_hook");

        let backups = backup_files(dir.path());
        if version < CURRENT_SCHEMA_VERSION {
            assert_eq!(backups.len(), 1, "v{version} backup count");
            assert!(
                backups[0]
                    .file_name()
                    .and_then(|value| value.to_str())
                    .expect("utf8 backup name")
                    .contains(&format!("from-v{version}-to-v{CURRENT_SCHEMA_VERSION}"))
            );
        } else {
            assert!(
                backups.is_empty(),
                "current fixture should not be backed up"
            );
        }
    }
}

#[test]
fn migration_tests_backup_before_migrate_is_private_and_checksummed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 5, 3);

    let store = Store::open(&db).expect("upgrade v5 fixture");
    assert_eq!(
        store.current_schema_version().expect("schema version"),
        CURRENT_SCHEMA_VERSION
    );
    drop(store);

    let backups = backup_files(dir.path());
    assert_eq!(backups.len(), 1);
    let backup = &backups[0];
    let backup_name = backup
        .file_name()
        .and_then(|value| value.to_str())
        .expect("utf8 backup filename");
    assert!(backup_name.contains("controller.sqlite"));
    assert!(backup_name.contains(&format!("from-v5-to-v{CURRENT_SCHEMA_VERSION}")));
    assert_private_file_mode(backup, 0o600);
    assert_private_file_mode(backup.parent().expect("backup parent"), 0o700);

    let checksum = checksum_path(backup);
    assert!(checksum.is_file(), "missing checksum sidecar");
    assert_private_file_mode(&checksum, 0o600);
    let checksum_text = std::fs::read_to_string(&checksum).expect("read checksum");
    let digest = checksum_text
        .split_ascii_whitespace()
        .next()
        .expect("checksum digest");
    assert_eq!(digest.len(), 64);
    assert!(digest.chars().all(|ch| ch.is_ascii_hexdigit()));

    let backup_conn = Connection::open(backup).expect("open backup");
    let backup_version: i64 = backup_conn
        .query_row("SELECT max(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .expect("backup schema version");
    assert_eq!(backup_version, 5);
}

#[test]
fn migration_tests_reopening_upgraded_database_is_idempotent() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 4, 2);

    let first = Store::open(&db).expect("first upgrade");
    assert_eq!(
        first.current_schema_version().expect("schema version"),
        CURRENT_SCHEMA_VERSION
    );
    drop(first);
    assert_eq!(backup_files(dir.path()).len(), 1);

    let second = Store::open(&db).expect("second open");
    assert_eq!(
        second.current_schema_version().expect("schema version"),
        CURRENT_SCHEMA_VERSION
    );
    drop(second);
    assert_eq!(
        backup_files(dir.path()).len(),
        1,
        "current schema reopen must not create a second backup"
    );

    let conn = Connection::open(&db).expect("open db");
    assert_sqlite_checks_pass(&conn);
    for version in 1..=CURRENT_SCHEMA_VERSION {
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM schema_migrations WHERE version = ?1",
                [version],
                |row| row.get(0),
            )
            .expect("version count");
        assert_eq!(count, 1, "schema version {version} should be recorded once");
    }
}

#[test]
fn migration_tests_large_v5_database_smoke_upgrades_without_data_loss() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 5, 0);

    let conn = Connection::open(&db).expect("open fixture");
    insert_large_v5_dataset(&conn, 250, 1_000);
    drop(conn);
    make_private_database_file(&db);

    let store = Store::open(&db).expect("upgrade large v5 database");
    assert_eq!(
        store.current_schema_version().expect("schema version"),
        CURRENT_SCHEMA_VERSION
    );
    drop(store);

    let conn = Connection::open(&db).expect("open upgraded db");
    assert_eq!(table_count(&conn, "nodes"), 250);
    assert_eq!(table_count(&conn, "controller_audit_log"), 250);
    assert_eq!(table_count(&conn, "endpoint_trust"), 250);
    assert_eq!(table_count(&conn, "observability_runs"), 250);
    assert_eq!(table_count(&conn, "probe_observations"), 1_000);
    assert_eq!(table_count(&conn, "health_snapshots"), 250);
    assert_eq!(table_count(&conn, "alert_events"), 250);
    assert_schema_object_exists(&conn, "index", "idx_probe_observations_node_observed_at");
    assert_schema_object_exists(&conn, "index", "idx_alert_events_state_last_seen_at");
    assert_sqlite_checks_pass(&conn);
}

#[test]
fn migration_tests_legacy_retention_policy_constraints_rebuild_to_current() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 5, 0);

    let conn = Connection::open(&db).expect("open v5 fixture");
    conn.execute_batch(
        r#"
        CREATE TABLE retention_policies (
          scope TEXT PRIMARY KEY,
          max_age_days INTEGER,
          max_rows INTEGER,
          updated_at TEXT NOT NULL
        );
        INSERT INTO retention_policies
          (scope, max_age_days, max_rows, updated_at)
        VALUES
          ('observations', 30, 1000, '2026-07-09T00:00:00Z');
        "#,
    )
    .expect("legacy retention table");
    drop(conn);
    make_private_database_file(&db);

    let store = Store::open(&db).expect("upgrade v5 retention fixture");
    assert_eq!(
        store.current_schema_version().expect("schema version"),
        CURRENT_SCHEMA_VERSION
    );
    drop(store);

    let conn = Connection::open(&db).expect("open upgraded db");
    assert_eq!(table_count(&conn, "retention_policies"), 1);
    let err = conn
        .execute(
            "INSERT INTO retention_policies
             (scope, max_age_days, max_rows, updated_at)
             VALUES ('unbounded', 1, 1, '2026-07-09T00:00:00Z')",
            [],
        )
        .expect_err("invalid retention scope must be rejected after migration");
    assert!(err.to_string().contains("CHECK"));
    assert_sqlite_checks_pass(&conn);
}

#[test]
fn migration_tests_invalid_legacy_observability_data_is_refused_after_backup() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 4, 0);

    let conn = Connection::open(&db).expect("open v4 fixture");
    conn.execute(
        "INSERT INTO observability_jobs
         (job_id, kind, selector_json, interval_seconds, jitter_seconds, timeout_ms, enabled, created_at, updated_at)
         VALUES ('bad-job', 'unsupported-kind', '{}', 60, 0, 5000, 1, '2026-07-09T00:00:00Z', '2026-07-09T00:00:00Z')",
        [],
    )
    .expect("insert invalid legacy job");
    drop(conn);
    make_private_database_file(&db);

    assert!(
        Store::open(&db).is_err(),
        "invalid legacy observability data must fail migration"
    );
    assert_eq!(
        backup_files(dir.path()).len(),
        1,
        "failed migration should still leave a pre-migration backup"
    );

    let conn = Connection::open(&db).expect("open original db after failed migration");
    let version: i64 = conn
        .query_row("SELECT max(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .expect("schema version");
    assert_eq!(version, 4, "failed migration must roll back version writes");
    assert_eq!(table_count(&conn, "observability_jobs"), 1);
}

#[test]
fn migration_tests_scheduler_selector_v1_migrates_or_fails_closed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 8, 1);
    make_private_database_file(&db);
    let store = Store::open(&db).expect("migrate v8 selector");
    drop(store);
    let conn = Connection::open(&db).expect("open migrated db");
    let (selector, enabled): (String, i64) = conn
        .query_row(
            "SELECT selector_json, enabled FROM observability_jobs LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read migrated selector");
    let selector: serde_json::Value = serde_json::from_str(&selector).expect("selector json");
    assert_eq!(
        selector["schema"], "ocfleet.scheduler.selector.v1",
        "migrated payload must be explicitly versioned"
    );
    assert_eq!(selector["selector"], "role=ocserv");
    assert_eq!(enabled, 0, "empty legacy selector must be quarantined");
    drop(conn);

    let pair_dir = tempfile::tempdir().expect("pair temp dir");
    let pair_db = pair_dir.path().join("controller.sqlite");
    create_legacy_fixture(&pair_db, 8, 1);
    let conn = Connection::open(&pair_db).expect("open v8 pair db");
    conn.execute(
        "UPDATE observability_jobs
         SET kind = 'path-probe', selector_json = ?1, pair_selector_json = ?2
         WHERE job_id = 'job-0000'",
        (
            r#"{"selector":"explicit-pair","name":"fixed path"}"#,
            r#"{"source_node_id":"source-node","target_node_id":"target-node"}"#,
        ),
    )
    .expect("seed legacy pair selector");
    drop(conn);
    let store = Store::open(&pair_db).expect("migrate legacy pair selector");
    drop(store);
    let conn = Connection::open(&pair_db).expect("open migrated pair db");
    let (selector, pair, enabled): (String, String, i64) = conn
        .query_row(
            "SELECT selector_json, pair_selector_json, enabled
             FROM observability_jobs WHERE job_id = 'job-0000'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read migrated pair selector");
    let selector: serde_json::Value = serde_json::from_str(&selector).expect("selector json");
    let pair: serde_json::Value = serde_json::from_str(&pair).expect("pair json");
    assert_eq!(selector["schema"], "ocfleet.scheduler.selector.v1");
    assert_eq!(pair["schema"], "ocfleet.scheduler.pair.v1");
    assert_eq!(pair["source_node_id"], "source-node");
    assert_eq!(pair["target_node_id"], "target-node");
    assert_eq!(enabled, 1, "valid legacy pair remains enabled");
    drop(conn);

    let bad_dir = tempfile::tempdir().expect("bad temp dir");
    let bad_db = bad_dir.path().join("controller.sqlite");
    create_legacy_fixture(&bad_db, 8, 1);
    let conn = Connection::open(&bad_db).expect("open v8 db");
    conn.execute(
        "UPDATE observability_jobs SET selector_json = ?1",
        [r#"{"selector":"role=ocserv","client_address":"10.0.0.2"}"#],
    )
    .expect("contaminate selector");
    drop(conn);
    make_private_database_file(&bad_db);
    assert!(Store::open(&bad_db).is_err());
    assert_eq!(backup_files(bad_dir.path()).len(), 1);
}

#[test]
fn migration_tests_health_snapshot_v1_migrates_or_fails_closed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 9, 1);
    let conn = Connection::open(&db).expect("open v9 db");
    conn.execute(
        "UPDATE health_snapshots
         SET degraded_methods_json = ?1, summary_json = ?2
         WHERE node_id = 'node-0000'",
        (
            r#"["ocserv.version","ocserv.cert.expiry"]"#,
            r#"{"region":"hk","role":"ocserv","status":"healthy","endpoint_status":"active","consecutive_failures":0}"#,
        ),
    )
    .expect("seed legacy health payloads");
    drop(conn);

    let store = Store::open(&db).expect("migrate v9 health payloads");
    drop(store);
    let conn = Connection::open(&db).expect("open migrated db");
    let (methods, summary): (String, String) = conn
        .query_row(
            "SELECT degraded_methods_json, summary_json
             FROM health_snapshots WHERE node_id = 'node-0000'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read migrated health payloads");
    let methods: serde_json::Value = serde_json::from_str(&methods).expect("methods json");
    let summary: serde_json::Value = serde_json::from_str(&summary).expect("summary json");
    assert_eq!(methods["schema"], "ocfleet.health.degraded-methods.v1");
    assert_eq!(
        methods["methods"],
        serde_json::json!(["ocserv.cert.expiry", "ocserv.version"])
    );
    assert_eq!(summary["schema"], "ocfleet.health.summary.v1");
    assert_eq!(summary["status"], "healthy");
    drop(conn);

    let bad_dir = tempfile::tempdir().expect("bad temp dir");
    let bad_db = bad_dir.path().join("controller.sqlite");
    create_legacy_fixture(&bad_db, 9, 1);
    let conn = Connection::open(&bad_db).expect("open contaminated v9 db");
    conn.execute(
        "UPDATE health_snapshots SET summary_json = ?1",
        [r#"{"status":"healthy","client_address":"10.0.0.2"}"#],
    )
    .expect("contaminate health summary");
    drop(conn);
    make_private_database_file(&bad_db);
    assert!(Store::open(&bad_db).is_err());
    assert_eq!(backup_files(bad_dir.path()).len(), 1);
}

#[test]
fn migration_tests_observation_summary_v1_migrates_or_fails_closed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 10, 1);
    let conn = Connection::open(&db).expect("open v10 db");
    conn.execute(
        "UPDATE probe_observations SET summary_json = ?1 WHERE observation_id = 'obs-0000'",
        [r#"{"message":"pong","result_class":"controller_rpc_summary"}"#],
    )
    .expect("seed legacy observation summary");
    drop(conn);

    let store = Store::open(&db).expect("migrate v10 observation summary");
    drop(store);
    let conn = Connection::open(&db).expect("open migrated db");
    let summary: String = conn
        .query_row(
            "SELECT summary_json FROM probe_observations WHERE observation_id = 'obs-0000'",
            [],
            |row| row.get(0),
        )
        .expect("read migrated observation summary");
    let summary: serde_json::Value = serde_json::from_str(&summary).expect("summary json");
    assert_eq!(summary["schema"], "ocfleet.observation.summary.v1");
    assert_eq!(summary["method"], "probe.controller.ping");
    assert_eq!(summary["result_class"], "controller_rpc_summary");
    assert_eq!(summary["fields"]["message"], "pong");
    drop(conn);

    let bad_dir = tempfile::tempdir().expect("bad temp dir");
    let bad_db = bad_dir.path().join("controller.sqlite");
    create_legacy_fixture(&bad_db, 10, 1);
    let conn = Connection::open(&bad_db).expect("open contaminated v10 db");
    conn.execute(
        "UPDATE probe_observations SET summary_json = ?1",
        [r#"{"message":"pong","client_address":"10.0.0.2"}"#],
    )
    .expect("contaminate observation summary");
    drop(conn);
    make_private_database_file(&bad_db);
    assert!(Store::open(&bad_db).is_err());
    assert_eq!(backup_files(bad_dir.path()).len(), 1);
}

#[test]
fn migration_tests_run_summary_v1_migrates_or_fails_closed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 11, 1);
    let conn = Connection::open(&db).expect("open v11 db");
    conn.execute(
        "UPDATE observability_runs SET summary_json = ?1 WHERE run_id = 'run-0000'",
        [r#"{"result_class":"scheduler_summary","status":"succeeded","observations":1,"failed_observations":0}"#],
    )
    .expect("seed legacy run summary");
    drop(conn);

    let store = Store::open(&db).expect("migrate v11 run summary");
    drop(store);
    let conn = Connection::open(&db).expect("open migrated db");
    let summary: String = conn
        .query_row(
            "SELECT summary_json FROM observability_runs WHERE run_id = 'run-0000'",
            [],
            |row| row.get(0),
        )
        .expect("read migrated run summary");
    let summary: serde_json::Value = serde_json::from_str(&summary).expect("summary json");
    assert_eq!(summary["schema"], "ocfleet.run.summary.v1");
    assert_eq!(summary["job_id"], "job-0000");
    assert_eq!(summary["kind"], "controller-ping");
    assert_eq!(summary["status"], "succeeded");
    assert_eq!(summary["observations"], 1);
    drop(conn);

    let bad_dir = tempfile::tempdir().expect("bad temp dir");
    let bad_db = bad_dir.path().join("controller.sqlite");
    create_legacy_fixture(&bad_db, 11, 1);
    let conn = Connection::open(&bad_db).expect("open contaminated v11 db");
    conn.execute(
        "UPDATE observability_runs SET summary_json = ?1",
        [r#"{"status":"succeeded","client_address":"10.0.0.2"}"#],
    )
    .expect("contaminate run summary");
    drop(conn);
    make_private_database_file(&bad_db);
    assert!(Store::open(&bad_db).is_err());
    assert_eq!(backup_files(bad_dir.path()).len(), 1);
}

#[test]
fn migration_tests_trust_bundle_v1_migrates_or_fails_closed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 12, 1);
    let store = Store::open(&db).expect("migrate v12 trust bundle");
    drop(store);
    let conn = Connection::open(&db).expect("open migrated db");
    let bundle: String = conn
        .query_row(
            "SELECT trust_bundle_json FROM endpoint_trust WHERE endpoint_id = 'endpoint-0000'",
            [],
            |row| row.get(0),
        )
        .expect("read migrated trust bundle");
    let bundle: serde_json::Value = serde_json::from_str(&bundle).expect("bundle json");
    assert_eq!(bundle["schema"], "ocfleet.trust.bundle.v1");
    assert_eq!(bundle["endpoint_id"], "endpoint-0000");
    assert_eq!(bundle["generation"], 1);
    assert_eq!(bundle["status"], "active");
    assert_eq!(bundle["trusted_controllers"], serde_json::json!([]));
    drop(conn);

    let bad_dir = tempfile::tempdir().expect("bad temp dir");
    let bad_db = bad_dir.path().join("controller.sqlite");
    create_legacy_fixture(&bad_db, 12, 1);
    let conn = Connection::open(&bad_db).expect("open contaminated v12 db");
    conn.execute(
        "UPDATE endpoint_trust SET trust_bundle_json = ?1",
        [r#"{"endpoint_id":"endpoint-0000","generation":1,"status":"active","trusted_controllers":[],"trusted_peers":[],"authorized_path_probes":[],"client_address":"10.0.0.2"}"#],
    )
    .expect("contaminate trust bundle");
    drop(conn);
    make_private_database_file(&bad_db);
    assert!(Store::open(&bad_db).is_err());
    assert_eq!(backup_files(bad_dir.path()).len(), 1);
}

#[test]
fn migration_tests_alert_detail_v1_migrates_or_fails_closed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 13, 1);
    let conn = Connection::open(&db).expect("open v13 db");
    conn.execute(
        "UPDATE alert_events SET detail_json = ?1 WHERE alert_id = 'alert-0000'",
        [r#"{"methods":["ocserv.cert.expiry"],"days_remaining":12,"status":"warning"}"#],
    )
    .expect("seed legacy alert detail");
    drop(conn);
    let store = Store::open(&db).expect("migrate v13 alert detail");
    drop(store);
    let conn = Connection::open(&db).expect("open migrated db");
    let detail: String = conn
        .query_row(
            "SELECT detail_json FROM alert_events WHERE alert_id = 'alert-0000'",
            [],
            |row| row.get(0),
        )
        .expect("read migrated alert detail");
    let detail: serde_json::Value = serde_json::from_str(&detail).expect("detail json");
    assert_eq!(detail["schema"], "ocfleet.alert.detail.v1");
    assert_eq!(detail["methods"], serde_json::json!(["ocserv.cert.expiry"]));
    assert_eq!(detail["summary"]["days_remaining"], 12);
    assert_eq!(detail["summary"]["status"], "warning");
    drop(conn);

    let bad_dir = tempfile::tempdir().expect("bad temp dir");
    let bad_db = bad_dir.path().join("controller.sqlite");
    create_legacy_fixture(&bad_db, 13, 1);
    let conn = Connection::open(&bad_db).expect("open contaminated v13 db");
    conn.execute(
        "UPDATE alert_events SET detail_json = ?1",
        [r#"{"methods":[],"summary":{},"client_address":"10.0.0.2"}"#],
    )
    .expect("contaminate alert detail");
    drop(conn);
    make_private_database_file(&bad_db);
    assert!(Store::open(&bad_db).is_err());
    assert_eq!(backup_files(bad_dir.path()).len(), 1);
}

#[test]
fn migration_tests_alert_host_allow_v1_migrates_or_fails_closed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 14, 1);
    let conn = Connection::open(&db).expect("open v14 db");
    insert_legacy_alert_hook(&conn, r#"["alerts.example.com.","93.184.216.34"]"#);
    drop(conn);
    let store = Store::open(&db).expect("migrate v14 alert host allowlist");
    let hook = store
        .get_alert_webhook_hook("webhook-legacy")
        .expect("read migrated hook")
        .expect("migrated hook exists");
    assert_eq!(hook.host_allow, vec!["93.184.216.34", "alerts.example.com"]);
    drop(store);
    let conn = Connection::open(&db).expect("open migrated db");
    let hosts: String = conn
        .query_row(
            "SELECT host_allow_json FROM alert_hooks WHERE hook_id = 'webhook-legacy'",
            [],
            |row| row.get(0),
        )
        .expect("read typed host allowlist");
    let hosts: serde_json::Value = serde_json::from_str(&hosts).expect("host allowlist JSON");
    assert_eq!(hosts["schema"], "ocfleet.alert.host-allow.v1");
    assert_eq!(
        hosts["hosts"],
        serde_json::json!(["93.184.216.34", "alerts.example.com"])
    );

    let bad_dir = tempfile::tempdir().expect("bad temp dir");
    let bad_db = bad_dir.path().join("controller.sqlite");
    create_legacy_fixture(&bad_db, 14, 1);
    let conn = Connection::open(&bad_db).expect("open contaminated v14 db");
    insert_legacy_alert_hook(
        &conn,
        r#"{"hosts":["93.184.216.34"],"client_address":"10.0.0.2"}"#,
    );
    drop(conn);
    make_private_database_file(&bad_db);
    assert!(Store::open(&bad_db).is_err());
    assert_eq!(backup_files(bad_dir.path()).len(), 1);
}

#[test]
fn migration_tests_enrollment_metadata_v1_migrates_or_fails_closed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 15, 1);
    let conn = Connection::open(&db).expect("open v15 db");
    conn.execute(
        "UPDATE enrollment_tokens SET labels_json = ?1, scope_json = ?2 WHERE token_id = 'token-0000'",
        (r#"{"env":"prod","enabled":true}"#, r#"{"region":"hk","priority":3}"#),
    )
    .expect("seed legacy token metadata");
    insert_legacy_join_request(&conn, r#"{"role":"ocserv"}"#, "{}", "pending");
    drop(conn);
    let store = Store::open(&db).expect("migrate v15 enrollment metadata");
    let token = store
        .get_enrollment_token("token-0000")
        .expect("read migrated token")
        .expect("token exists");
    assert_eq!(token.labels_json["env"], "prod");
    assert_eq!(token.scope_json["priority"], 3);
    let join = store
        .get_join_request("join-legacy")
        .expect("read migrated join")
        .expect("join exists");
    assert_eq!(join.requested_labels_json["role"], "ocserv");
    assert_eq!(join.approved_labels_json, serde_json::json!({}));
    drop(store);
    let conn = Connection::open(&db).expect("open migrated db");
    let raw: String = conn
        .query_row(
            "SELECT labels_json FROM enrollment_tokens WHERE token_id = 'token-0000'",
            [],
            |row| row.get(0),
        )
        .expect("read typed token labels");
    let raw: serde_json::Value = serde_json::from_str(&raw).expect("typed token labels JSON");
    assert_eq!(raw["schema"], "ocfleet.enrollment.metadata.v1");
    assert_eq!(raw["kind"], "token_labels");
    assert_eq!(raw["values"]["env"], "prod");

    let bad_dir = tempfile::tempdir().expect("bad temp dir");
    let bad_db = bad_dir.path().join("controller.sqlite");
    create_legacy_fixture(&bad_db, 15, 1);
    let conn = Connection::open(&bad_db).expect("open contaminated v15 db");
    conn.execute(
        "UPDATE enrollment_tokens SET labels_json = ?1 WHERE token_id = 'token-0000'",
        [r#"{"client_address":"10.0.0.2"}"#],
    )
    .expect("contaminate token metadata");
    drop(conn);
    make_private_database_file(&bad_db);
    assert!(Store::open(&bad_db).is_err());
    assert_eq!(backup_files(bad_dir.path()).len(), 1);

    let decision_dir = tempfile::tempdir().expect("decision temp dir");
    let decision_db = decision_dir.path().join("controller.sqlite");
    create_legacy_fixture(&decision_db, 15, 1);
    let conn = Connection::open(&decision_db).expect("open inconsistent v15 db");
    insert_legacy_join_request(
        &conn,
        r#"{"role":"ocserv"}"#,
        r#"{"approved":true}"#,
        "pending",
    );
    drop(conn);
    make_private_database_file(&decision_db);
    assert!(Store::open(&decision_db).is_err());
    assert_eq!(backup_files(decision_dir.path()).len(), 1);
}

#[test]
fn migration_tests_delivery_attempt_detail_v1_migrates_or_fails_closed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 16, 1);
    let conn = Connection::open(&db).expect("open v16 db");
    insert_legacy_alert_hook(
        &conn,
        r#"{"schema":"ocfleet.alert.host-allow.v1","hosts":["93.184.216.34"]}"#,
    );
    insert_legacy_delivery_attempt(&conn, 512);
    drop(conn);
    let store = Store::open(&db).expect("migrate v16 delivery attempt detail");
    let attempts = store
        .list_alert_delivery_attempts()
        .expect("read migrated attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].attempt_id, "attempt-legacy");
    assert_eq!(attempts[0].bytes_sent, 512);
    drop(store);
    let conn = Connection::open(&db).expect("open migrated db");
    let raw: String = conn
        .query_row(
            "SELECT detail_json FROM alert_delivery_attempts WHERE attempt_id = 'attempt-legacy'",
            [],
            |row| row.get(0),
        )
        .expect("read typed delivery detail");
    let raw: serde_json::Value = serde_json::from_str(&raw).expect("delivery detail JSON");
    assert_eq!(raw["schema"], "ocfleet.delivery-attempt.detail.v1");
    assert_eq!(raw["attempt_id"], "attempt-legacy");
    assert_eq!(raw["bytes_sent"], 512);

    let bad_dir = tempfile::tempdir().expect("bad temp dir");
    let bad_db = bad_dir.path().join("controller.sqlite");
    create_legacy_fixture(&bad_db, 16, 1);
    let conn = Connection::open(&bad_db).expect("open contaminated v16 db");
    insert_legacy_alert_hook(
        &conn,
        r#"{"schema":"ocfleet.alert.host-allow.v1","hosts":["93.184.216.34"]}"#,
    );
    insert_legacy_delivery_attempt(&conn, 1_048_577);
    drop(conn);
    make_private_database_file(&bad_db);
    assert!(Store::open(&bad_db).is_err());
    assert_eq!(backup_files(bad_dir.path()).len(), 1);
}

#[test]
fn migration_tests_audit_detail_v1_migrates_or_fails_closed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 17, 1);
    let store = Store::open(&db).expect("migrate v17 audit detail");
    let records = store
        .list_audit_window("2026-07-08T00:00:00Z", "2026-07-10T00:00:00Z", 10)
        .expect("read migrated audit");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].event, "node.add");
    assert_eq!(records[0].detail_json, serde_json::json!({}));
    drop(store);
    let conn = Connection::open(&db).expect("open migrated db");
    let raw: String = conn
        .query_row(
            "SELECT detail_json FROM controller_audit_log WHERE event = 'node.add'",
            [],
            |row| row.get(0),
        )
        .expect("read typed audit detail");
    let raw: serde_json::Value = serde_json::from_str(&raw).expect("audit detail JSON");
    assert_eq!(raw["_audit"]["schema"], "ocfleet.audit.detail.v1");
    assert_eq!(raw["_audit"]["event"], "node.add");

    let bad_dir = tempfile::tempdir().expect("bad temp dir");
    let bad_db = bad_dir.path().join("controller.sqlite");
    create_legacy_fixture(&bad_db, 17, 1);
    let conn = Connection::open(&bad_db).expect("open contaminated v17 db");
    conn.execute(
        "UPDATE controller_audit_log SET detail_json = ?1 WHERE event = 'node.add'",
        [r#"{"future":true}"#],
    )
    .expect("contaminate audit detail");
    drop(conn);
    make_private_database_file(&bad_db);
    assert!(Store::open(&bad_db).is_err());
    assert_eq!(backup_files(bad_dir.path()).len(), 1);
}

#[test]
fn migration_tests_scheduler_claim_table_upgrades_schema_18() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 18, 1);

    let store = Store::open(&db).expect("migrate v18 scheduler claims");
    assert_eq!(
        store.current_schema_version().expect("schema version"),
        CURRENT_SCHEMA_VERSION
    );
    drop(store);
    let conn = Connection::open(&db).expect("open migrated db");
    assert_schema_object_exists(&conn, "table", "scheduler_job_claims");
    assert_schema_object_exists(&conn, "index", "idx_scheduler_job_claims_expiry");
    assert_schema_object_exists(&conn, "table", "scheduler_maintenance");
    assert_eq!(backup_files(dir.path()).len(), 1);
    assert_sqlite_checks_pass(&conn);
}

#[test]
fn migration_tests_scheduler_maintenance_upgrades_schema_19() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 19, 1);

    let store = Store::open(&db).expect("migrate v19 scheduler maintenance");
    assert_eq!(
        store.current_schema_version().expect("schema version"),
        CURRENT_SCHEMA_VERSION
    );
    drop(store);
    let conn = Connection::open(&db).expect("open migrated db");
    assert_schema_object_exists(&conn, "table", "scheduler_maintenance");
    assert_eq!(backup_files(dir.path()).len(), 1);
    assert_sqlite_checks_pass(&conn);
}

#[test]
fn migration_tests_health_evaluation_runs_upgrade_schema_20() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 20, 1);

    let store = Store::open(&db).expect("migrate v20 health evaluator runs");
    assert_eq!(
        store.current_schema_version().expect("schema version"),
        CURRENT_SCHEMA_VERSION
    );
    drop(store);
    let conn = Connection::open(&db).expect("open migrated db");
    assert_schema_object_exists(&conn, "table", "health_evaluation_runs");
    assert_schema_object_exists(&conn, "index", "idx_health_evaluation_runs_input");
    assert_schema_object_exists(&conn, "index", "idx_health_evaluation_runs_status_started");
    assert!(
        conn.execute(
            "INSERT INTO health_evaluation_runs
             (evaluation_id, input_watermark, policy_version, computation_version, started_at, status)
             VALUES ('health-eval-invalid', ?1, ?1, 'health-v1', ?2, 'completed')",
            ("0".repeat(64), NOW),
        )
        .is_err(),
        "completed runs must include a finish timestamp"
    );
    assert!(
        conn.execute(
            "INSERT INTO health_evaluation_runs
             (evaluation_id, input_watermark, policy_version, computation_version, started_at, finished_at, status, failure_code)
             VALUES ('health-eval-invalid-failure', ?1, ?1, 'health-v1', ?2, ?2, 'failed', NULL)",
            ("0".repeat(64), NOW),
        )
        .is_err(),
        "failed runs must include a bounded failure code"
    );
    assert_eq!(backup_files(dir.path()).len(), 1);
    assert_sqlite_checks_pass(&conn);
}

#[test]
fn migration_tests_alert_delivery_queue_upgrades_schema_21() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 21, 1);

    let store = Store::open(&db).expect("migrate v21 alert delivery queue");
    assert_eq!(
        store.current_schema_version().expect("schema version"),
        CURRENT_SCHEMA_VERSION
    );
    drop(store);
    let conn = Connection::open(&db).expect("open migrated db");
    assert_schema_object_exists(&conn, "table", "alert_delivery_queue");
    for index in [
        "idx_alert_delivery_queue_alert_hook_key",
        "idx_alert_delivery_queue_due",
        "idx_alert_delivery_queue_lease",
    ] {
        assert_schema_object_exists(&conn, "index", index);
    }
    assert_eq!(backup_files(dir.path()).len(), 1);
    assert_sqlite_checks_pass(&conn);
}

#[test]
fn migration_tests_health_history_upgrades_schema_22() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 22, 0);

    let store = Store::open(&db).expect("migrate v22 health history");
    assert_eq!(
        store.current_schema_version().expect("schema version"),
        CURRENT_SCHEMA_VERSION
    );
    drop(store);

    let conn = Connection::open(&db).expect("open migrated db");
    assert_schema_object_exists(&conn, "table", "health_history");
    assert_schema_object_exists(&conn, "index", "idx_health_history_node_computed");
    assert_schema_object_exists(&conn, "index", "idx_health_history_computed");
    assert_schema_object_exists(&conn, "trigger", "health_history_reject_update");
    conn.execute(
        "INSERT INTO retention_policies
         (scope, max_age_days, max_rows, updated_at)
         VALUES ('health-history', 90, 1000000, ?1)",
        [NOW],
    )
    .expect("health history has independent retention policy");
    assert_eq!(table_count(&conn, "retention_policies"), 1);
    assert_sqlite_checks_pass(&conn);
}

#[test]
fn migration_tests_health_rollups_upgrade_schema_23() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 23, 0);

    let store = Store::open(&db).expect("migrate v23 health rollups");
    assert_eq!(
        store.current_schema_version().expect("schema version"),
        CURRENT_SCHEMA_VERSION
    );
    drop(store);

    let conn = Connection::open(&db).expect("open migrated db");
    assert_schema_object_exists(&conn, "table", "health_rollups");
    assert_schema_object_exists(&conn, "index", "idx_health_rollups_window");
    assert_schema_object_exists(&conn, "index", "idx_health_rollups_node_window");
    assert_sqlite_checks_pass(&conn);
}

#[test]
fn migration_tests_health_rollup_slot_semantics_upgrade_schema_24() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    create_legacy_fixture(&db, 24, 0);

    let store = Store::open(&db).expect("migrate v24 health rollup slots");
    assert_eq!(
        store.current_schema_version().expect("schema version"),
        CURRENT_SCHEMA_VERSION
    );
    drop(store);

    let conn = Connection::open(&db).expect("open migrated db");
    assert_schema_object_exists(&conn, "table", "health_rollups");
    assert!(
        conn.execute(
            "INSERT INTO health_rollups
             (node_id, bucket_seconds, bucket_start, bucket_end, input_watermark,
              health_samples, covered_slots, expected_slots, healthy_count,
              degraded_count, unreachable_count, stale_count, disabled_count,
              unknown_count, observation_count, observation_error_count,
              duration_sample_count, duration_p50_ms, duration_p95_ms,
              cert_warning_count, cert_critical_count, fingerprint_sample_count,
              fingerprint_change_count, computed_at)
             VALUES ('node-a', 300, '2026-07-11T00:00:00Z',
                     '2026-07-11T00:05:00Z', ?1, 2, 1, 1, 1, 1, 0, 0, 0, 0,
                     0, 0, 0, NULL, NULL, 0, 0, 0, 0,
                     '2026-07-11T00:05:00Z')",
            ["a".repeat(64)],
        )
        .is_err(),
        "multiple health samples in one five-minute slot must be rejected"
    );
    assert_sqlite_checks_pass(&conn);
}

fn insert_legacy_delivery_attempt(conn: &Connection, bytes_sent: i64) {
    conn.execute(
        "INSERT INTO alert_delivery_attempts
         (attempt_id, alert_id, hook_id, attempt_no, attempted_at, status, http_status_class, error_code, bytes_sent)
         VALUES ('attempt-legacy', 'alert-0000', 'webhook-legacy', 1, ?1, 'failed', '5xx', 'WEBHOOK_HTTP_5XX', ?2)",
        (NOW, bytes_sent),
    )
    .expect("insert legacy delivery attempt");
}

fn insert_legacy_join_request(
    conn: &Connection,
    requested_labels_json: &str,
    approved_labels_json: &str,
    status: &str,
) {
    conn.execute(
        "INSERT INTO join_requests
         (request_id, token_id, status, agent_public_key, fingerprint, requested_endpoint_id, assigned_endpoint_id, hostname, agent_version, requested_labels_json, approved_labels_json, created_at, approved_at, approved_by, rejection_reason, audit_correlation_id)
         VALUES ('join-legacy', 'token-0000', ?1, 'agent-public-key', 'agent-fingerprint', NULL, NULL, 'legacy.example', '0.2.0', ?2, ?3, ?4, NULL, NULL, NULL, 'corr-legacy')",
        (status, requested_labels_json, approved_labels_json, NOW),
    )
    .expect("insert legacy join request");
}

fn insert_legacy_alert_hook(conn: &Connection, host_allow_json: &str) {
    conn.execute(
        "INSERT INTO alert_hooks
         (hook_id, name, hook_type, endpoint_url, endpoint_url_redacted, endpoint_host, host_allow_json, hmac_key_id, enabled, max_attempts, timeout_ms, created_at, updated_at)
         VALUES ('webhook-legacy', 'legacy', 'webhook', 'https://93.184.216.34/alerts', 'https://93.184.216.34/<redacted>', '93.184.216.34', ?1, 'abcd1234abcd1234', 1, 2, 1500, ?2, ?2)",
        (host_allow_json, NOW),
    )
    .expect("insert legacy alert hook");
}

fn create_legacy_fixture(path: &Path, version: i64, rows: usize) {
    assert!((1..CURRENT_SCHEMA_VERSION).contains(&version));
    let conn = Connection::open(path).expect("create fixture db");
    conn.pragma_update(None, "foreign_keys", "ON")
        .expect("enable foreign keys");
    conn.execute_batch(SCHEMA_MIGRATIONS_SQL)
        .expect("schema migrations table");
    conn.execute_batch(V1_CORE_SQL).expect("v1 schema");
    if version >= 2 {
        conn.execute_batch(V2_ENROLLMENT_SQL).expect("v2 schema");
    }
    if version >= 3 {
        conn.execute_batch(V3_ENDPOINT_TRUST_SQL)
            .expect("v3 schema");
    }
    if version >= 4 {
        conn.execute_batch(V4_OBSERVABILITY_BASE_SQL)
            .expect("v4 schema");
    }
    if version >= 5 {
        conn.execute_batch(V5_OBSERVABILITY_CONSTRAINED_SQL)
            .expect("v5 schema");
    }
    if version >= 6 {
        conn.execute_batch(V6_RETENTION_AND_INDEX_SQL)
            .expect("v6 schema");
    }
    if version >= 7 {
        conn.execute_batch(V7_HEALTH_POLICY_SQL).expect("v7 schema");
    }
    if version >= 8 {
        conn.execute_batch(V8_ALERT_WEBHOOK_SQL).expect("v8 schema");
    }
    for applied in 1..=version {
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
            (applied, NOW),
        )
        .expect("insert migration row");
    }
    insert_legacy_rows(&conn, version, rows);
    drop(conn);
    make_private_database_file(path);
}

fn insert_legacy_rows(conn: &Connection, version: i64, rows: usize) {
    for idx in 0..rows {
        let node_id = format!("node-{idx:04}");
        let endpoint_id = format!("endpoint-{idx:04}");
        conn.execute(
            "INSERT INTO nodes
             (node_id, endpoint_id, name, region, role, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, 'hk', 'ocserv', 1, ?4, ?4)",
            (&node_id, &endpoint_id, &node_id, NOW),
        )
        .expect("insert node");
        conn.execute(
            "INSERT INTO controller_audit_log
             (ts, actor, event, node_id, endpoint_id, method, request_id, params_hash, ok, error_code, duration_ms, detail_json)
             VALUES (?1, 'operator', 'node.add', ?2, ?3, NULL, NULL, NULL, 1, NULL, 1, '{}')",
            (NOW, &node_id, &endpoint_id),
        )
        .expect("insert audit");
        if version >= 2 {
            let token_id = format!("token-{idx:04}");
            let labels_json = if version >= 16 {
                r#"{"schema":"ocfleet.enrollment.metadata.v1","kind":"token_labels","values":{}}"#
            } else {
                "{}"
            };
            let scope_json = if version >= 16 {
                r#"{"schema":"ocfleet.enrollment.metadata.v1","kind":"token_scope","values":{}}"#
            } else {
                "{}"
            };
            conn.execute(
                "INSERT INTO enrollment_tokens
                 (token_id, token_hash, created_at, created_by, expires_at, max_uses, used_count, status, description, labels_json, scope_json)
                 VALUES (?1, ?2, ?3, 'operator', '2099-01-01T00:00:00Z', 10, 0, 'active', NULL, ?4, ?5)",
                (
                    &token_id,
                    format!("hash-{idx:04}"),
                    NOW,
                    labels_json,
                    scope_json,
                ),
            )
            .expect("insert enrollment token");
        }
        if version >= 3 {
            let trust_bundle_json = if version >= 13 {
                format!(
                    r#"{{"schema":"ocfleet.trust.bundle.v1","endpoint_id":"{endpoint_id}","generation":1,"status":"active","trusted_controllers":[],"trusted_peers":[],"authorized_path_probes":[]}}"#
                )
            } else {
                "{}".to_string()
            };
            conn.execute(
                "INSERT INTO endpoint_trust
                 (endpoint_id, node_id, fingerprint, status, generation, previous_endpoint_id, rotated_to, trust_bundle_json, created_at, updated_at)
                 VALUES (?1, ?2, NULL, 'active', 1, NULL, NULL, ?3, ?4, ?4)",
                (&endpoint_id, &node_id, &trust_bundle_json, NOW),
            )
            .expect("insert endpoint trust");
        }
        if version >= 4 {
            insert_observability_rows(conn, version, idx, &node_id, &endpoint_id);
        }
    }
}

fn insert_observability_rows(
    conn: &Connection,
    version: i64,
    idx: usize,
    node_id: &str,
    endpoint_id: &str,
) {
    let job_id = format!("job-{idx:04}");
    let run_id = format!("run-{idx:04}");
    let observation_id = format!("obs-{idx:04}");
    let selector_json = if version >= 9 {
        r#"{"schema":"ocfleet.scheduler.selector.v1","selector":"role=ocserv","name":null}"#
    } else {
        "{}"
    };
    let (degraded_methods_json, health_summary_json) = if version >= 10 {
        (
            r#"{"schema":"ocfleet.health.degraded-methods.v1","methods":[]}"#,
            r#"{"schema":"ocfleet.health.summary.v1","region":null,"role":null,"status":"healthy","endpoint_status":null,"consecutive_failures":null}"#,
        )
    } else {
        ("[]", "{}")
    };
    let observation_summary_json = if version >= 11 {
        r#"{"schema":"ocfleet.observation.summary.v1","result_class":"controller_rpc_summary","method":"probe.controller.ping","fields":{}}"#
    } else {
        "{}"
    };
    let run_summary_json = if version >= 12 {
        format!(
            r#"{{"schema":"ocfleet.run.summary.v1","result_class":"scheduler_summary","job_id":"{job_id}","kind":"controller-ping","status":"succeeded","triggered_by":"manual","observations":null,"failed_observations":null}}"#
        )
    } else {
        "{}".to_string()
    };
    conn.execute(
        "INSERT INTO observability_jobs
         (job_id, kind, selector_json, pair_selector_json, interval_seconds, jitter_seconds, timeout_ms, enabled, next_run_at, last_run_at, created_at, updated_at)
         VALUES (?1, 'controller-ping', ?2, NULL, 60, 0, 5000, 1, NULL, NULL, ?3, ?3)",
        (&job_id, selector_json, NOW),
    )
    .expect("insert observability job");
    conn.execute(
        "INSERT INTO observability_runs
         (run_id, job_id, started_at, finished_at, status, triggered_by, summary_json)
         VALUES (?1, ?2, ?3, ?3, 'succeeded', 'manual', ?4)",
        (&run_id, &job_id, NOW, &run_summary_json),
    )
    .expect("insert observability run");
    conn.execute(
        "INSERT INTO probe_observations
         (observation_id, run_id, node_id, endpoint_id, method, ok, error_code, duration_ms, observed_at, expires_at, result_class, summary_json)
         VALUES (?1, ?2, ?3, ?4, 'probe.controller.ping', 1, NULL, 12, ?5, NULL, 'controller_rpc_summary', ?6)",
        (
            &observation_id,
            &run_id,
            node_id,
            endpoint_id,
            NOW,
            observation_summary_json,
        ),
    )
    .expect("insert probe observation");
    conn.execute(
        "INSERT INTO health_snapshots
         (node_id, endpoint_id, computed_at, status, freshness_seconds, last_success_at, last_failure_at, last_error_code, degraded_methods_json, summary_json)
         VALUES (?1, ?2, ?3, 'healthy', 30, ?3, NULL, NULL, ?4, ?5)",
        (
            node_id,
            endpoint_id,
            NOW,
            degraded_methods_json,
            health_summary_json,
        ),
    )
    .expect("insert health snapshot");
    let alert_detail_json = if version >= 14 {
        r#"{"schema":"ocfleet.alert.detail.v1","methods":[],"summary":{},"silenced_until":null,"silence_reason":null,"resolve_reason":null}"#
    } else {
        "{}"
    };
    conn.execute(
        "INSERT INTO alert_events
         (alert_id, dedupe_key, node_id, severity, state, reason_code, first_seen_at, last_seen_at, last_sent_at, resolved_at, detail_json)
         VALUES (?1, ?2, ?3, 'warning', 'open', 'NODE_STALE', ?4, ?4, NULL, NULL, ?5)",
        (
            format!("alert-{idx:04}"),
            format!("alert:{idx:04}"),
            node_id,
            NOW,
            alert_detail_json,
        ),
    )
    .expect("insert alert event");
}

fn insert_large_v5_dataset(conn: &Connection, nodes: usize, observations: usize) {
    insert_legacy_rows(conn, 3, nodes);
    for idx in 0..nodes {
        let node_id = format!("node-{idx:04}");
        let endpoint_id = format!("endpoint-{idx:04}");
        let run_id = format!("run-{idx:04}");
        conn.execute(
            "INSERT INTO observability_runs
             (run_id, job_id, started_at, finished_at, status, triggered_by, summary_json)
             VALUES (?1, NULL, ?2, ?2, 'succeeded', 'manual', '{}')",
            (&run_id, NOW),
        )
        .expect("insert large run");
        conn.execute(
            "INSERT INTO health_snapshots
             (node_id, endpoint_id, computed_at, status, freshness_seconds, last_success_at, last_failure_at, last_error_code, degraded_methods_json, summary_json)
             VALUES (?1, ?2, ?3, 'healthy', 30, ?3, NULL, NULL, '[]', '{}')",
            (&node_id, &endpoint_id, NOW),
        )
        .expect("insert large health");
        conn.execute(
            "INSERT INTO alert_events
             (alert_id, dedupe_key, node_id, severity, state, reason_code, first_seen_at, last_seen_at, last_sent_at, resolved_at, detail_json)
             VALUES (?1, ?2, ?3, 'warning', 'open', 'NODE_STALE', ?4, ?4, NULL, NULL, '{}')",
            (
                format!("large-alert-{idx:04}"),
                format!("large-alert:{idx:04}"),
                &node_id,
                NOW,
            ),
        )
        .expect("insert large alert");
    }
    for idx in 0..observations {
        let node_idx = idx % nodes;
        conn.execute(
            "INSERT INTO probe_observations
             (observation_id, run_id, node_id, endpoint_id, method, ok, error_code, duration_ms, observed_at, expires_at, result_class, summary_json)
             VALUES (?1, ?2, ?3, ?4, 'probe.controller.ping', 1, NULL, 12, ?5, NULL, 'controller_rpc_summary', '{}')",
            (
                format!("large-obs-{idx:04}"),
                format!("run-{node_idx:04}"),
                format!("node-{node_idx:04}"),
                format!("endpoint-{node_idx:04}"),
                NOW,
            ),
        )
        .expect("insert large observation");
    }
}

fn assert_schema_object_exists(conn: &Connection, kind: &str, name: &str) {
    let count: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            (kind, name),
            |row| row.get(0),
        )
        .expect("schema object query");
    assert_eq!(count, 1, "missing {kind} {name}");
}

fn assert_sqlite_checks_pass(conn: &Connection) {
    let foreign_key_violations: i64 = conn
        .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .expect("foreign_key_check");
    assert_eq!(foreign_key_violations, 0);
    let quick_check: String = conn
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .expect("quick_check");
    assert_eq!(quick_check, "ok");
}

fn table_count(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .expect("table count")
}

fn backup_files(parent: &Path) -> Vec<PathBuf> {
    let mut backups = Vec::new();
    collect_backup_files(parent, &mut backups);
    let backup_dir = parent.join(".ocfleet-migration-backups");
    if backup_dir.is_dir() {
        collect_backup_files(&backup_dir, &mut backups);
    }
    backups.sort();
    backups
}

fn collect_backup_files(parent: &Path, backups: &mut Vec<PathBuf>) {
    backups.extend(
        std::fs::read_dir(parent)
            .expect("read parent")
            .map(|entry| entry.expect("dir entry").path())
            .filter(|path| {
                path.file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|name| name.contains(".backup.") && !name.ends_with(".sha256"))
            }),
    );
}

fn checksum_path(path: &Path) -> PathBuf {
    let mut raw = path.as_os_str().to_os_string();
    raw.push(".sha256");
    PathBuf::from(raw)
}

#[cfg(unix)]
fn make_private_database_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod private db");
}

#[cfg(not(unix))]
fn make_private_database_file(_path: &Path) {}

#[cfg(unix)]
fn assert_private_file_mode(path: &Path, expected: u32) {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, expected, "unexpected mode for {}", path.display());
}

#[cfg(not(unix))]
fn assert_private_file_mode(_path: &Path, _expected: u32) {}

const SCHEMA_MIGRATIONS_SQL: &str = r#"
CREATE TABLE schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);
"#;

const V1_CORE_SQL: &str = r#"
CREATE TABLE nodes (
  node_id TEXT PRIMARY KEY,
  endpoint_id TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  region TEXT,
  role TEXT NOT NULL DEFAULT 'ocserv',
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE controller_audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor TEXT NOT NULL,
  event TEXT NOT NULL,
  node_id TEXT,
  endpoint_id TEXT,
  method TEXT,
  request_id TEXT,
  params_hash TEXT,
  ok INTEGER,
  error_code TEXT,
  duration_ms INTEGER,
  detail_json TEXT
);
"#;

const V2_ENROLLMENT_SQL: &str = r#"
CREATE TABLE enrollment_tokens (
  token_id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  max_uses INTEGER NOT NULL,
  used_count INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  description TEXT,
  labels_json TEXT NOT NULL,
  scope_json TEXT NOT NULL
);

CREATE TABLE join_requests (
  request_id TEXT PRIMARY KEY,
  token_id TEXT NOT NULL,
  status TEXT NOT NULL,
  agent_public_key TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  requested_endpoint_id TEXT,
  assigned_endpoint_id TEXT,
  hostname TEXT NOT NULL,
  agent_version TEXT NOT NULL,
  requested_labels_json TEXT NOT NULL,
  approved_labels_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  approved_at TEXT,
  approved_by TEXT,
  rejection_reason TEXT,
  audit_correlation_id TEXT NOT NULL,
  FOREIGN KEY(token_id) REFERENCES enrollment_tokens(token_id)
);
"#;

const V3_ENDPOINT_TRUST_SQL: &str = r#"
CREATE TABLE endpoint_trust (
  endpoint_id TEXT PRIMARY KEY,
  node_id TEXT,
  fingerprint TEXT,
  status TEXT NOT NULL,
  generation INTEGER NOT NULL,
  previous_endpoint_id TEXT,
  rotated_to TEXT,
  trust_bundle_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
"#;

const V4_OBSERVABILITY_BASE_SQL: &str = r#"
CREATE TABLE observability_jobs (
  job_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  selector_json TEXT NOT NULL,
  pair_selector_json TEXT,
  interval_seconds INTEGER NOT NULL,
  jitter_seconds INTEGER NOT NULL DEFAULT 0,
  timeout_ms INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  next_run_at TEXT,
  last_run_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE observability_runs (
  run_id TEXT PRIMARY KEY,
  job_id TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL,
  triggered_by TEXT NOT NULL,
  summary_json TEXT NOT NULL
);

CREATE TABLE probe_observations (
  observation_id TEXT PRIMARY KEY,
  run_id TEXT,
  node_id TEXT,
  endpoint_id TEXT,
  method TEXT NOT NULL,
  ok INTEGER,
  error_code TEXT,
  duration_ms INTEGER,
  observed_at TEXT NOT NULL,
  expires_at TEXT,
  result_class TEXT NOT NULL,
  summary_json TEXT NOT NULL
);

CREATE TABLE health_snapshots (
  node_id TEXT PRIMARY KEY,
  endpoint_id TEXT,
  computed_at TEXT NOT NULL,
  status TEXT NOT NULL,
  freshness_seconds INTEGER,
  last_success_at TEXT,
  last_failure_at TEXT,
  last_error_code TEXT,
  degraded_methods_json TEXT NOT NULL,
  summary_json TEXT NOT NULL
);

CREATE TABLE alert_events (
  alert_id TEXT PRIMARY KEY,
  dedupe_key TEXT NOT NULL UNIQUE,
  node_id TEXT,
  severity TEXT NOT NULL,
  state TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  last_sent_at TEXT,
  resolved_at TEXT,
  detail_json TEXT NOT NULL
);
"#;

const V5_OBSERVABILITY_CONSTRAINED_SQL: &str = r#"
DROP TABLE alert_events;
DROP TABLE health_snapshots;
DROP TABLE probe_observations;
DROP TABLE observability_runs;
DROP TABLE observability_jobs;

CREATE TABLE observability_jobs (
  job_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('controller-ping', 'ocserv-status', 'ocserv-cert', 'ocserv-sessions', 'path-probe')),
  selector_json TEXT NOT NULL CHECK (json_valid(selector_json)),
  pair_selector_json TEXT CHECK (pair_selector_json IS NULL OR json_valid(pair_selector_json)),
  interval_seconds INTEGER NOT NULL CHECK (interval_seconds BETWEEN 60 AND 86400),
  jitter_seconds INTEGER NOT NULL DEFAULT 0 CHECK (jitter_seconds BETWEEN 0 AND 3600),
  timeout_ms INTEGER NOT NULL CHECK (timeout_ms BETWEEN 1000 AND 30000),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  next_run_at TEXT,
  last_run_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE observability_runs (
  run_id TEXT PRIMARY KEY,
  job_id TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed', 'skipped')),
  triggered_by TEXT NOT NULL CHECK (triggered_by IN ('manual', 'scheduler.run.once')),
  summary_json TEXT NOT NULL CHECK (json_valid(summary_json)),
  FOREIGN KEY(job_id) REFERENCES observability_jobs(job_id) ON DELETE SET NULL
);

CREATE TABLE probe_observations (
  observation_id TEXT PRIMARY KEY,
  run_id TEXT,
  node_id TEXT,
  endpoint_id TEXT,
  method TEXT NOT NULL CHECK (method IN ('probe.controller.ping', 'probe.path.echo', 'ocserv.service.summary', 'ocserv.version', 'ocserv.sessions.summary', 'ocserv.cert.expiry', 'ocserv.config.fingerprint')),
  ok INTEGER CHECK (ok IS NULL OR ok IN (0, 1)),
  error_code TEXT,
  duration_ms INTEGER CHECK (duration_ms IS NULL OR duration_ms >= 0),
  observed_at TEXT NOT NULL,
  expires_at TEXT,
  result_class TEXT NOT NULL CHECK (result_class IN ('controller_rpc_summary', 'low_sensitive_summary', 'scheduler_summary')),
  summary_json TEXT NOT NULL CHECK (json_valid(summary_json)),
  FOREIGN KEY(run_id) REFERENCES observability_runs(run_id) ON DELETE SET NULL
);

CREATE TABLE health_snapshots (
  node_id TEXT PRIMARY KEY,
  endpoint_id TEXT,
  computed_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('healthy', 'degraded', 'unreachable', 'stale', 'disabled', 'unknown')),
  freshness_seconds INTEGER CHECK (freshness_seconds IS NULL OR freshness_seconds >= 0),
  last_success_at TEXT,
  last_failure_at TEXT,
  last_error_code TEXT,
  degraded_methods_json TEXT NOT NULL CHECK (json_valid(degraded_methods_json)),
  summary_json TEXT NOT NULL CHECK (json_valid(summary_json))
);

CREATE TABLE alert_events (
  alert_id TEXT PRIMARY KEY,
  dedupe_key TEXT NOT NULL UNIQUE,
  node_id TEXT,
  severity TEXT NOT NULL CHECK (severity IN ('warning', 'critical')),
  state TEXT NOT NULL CHECK (state IN ('open', 'resolved', 'silenced')),
  reason_code TEXT NOT NULL CHECK (reason_code IN ('NODE_UNREACHABLE', 'NODE_STALE', 'OCSERV_DEGRADED', 'CERT_EXPIRING_CRITICAL', 'CERT_EXPIRING_WARNING', 'ENDPOINT_INACTIVE')),
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  last_sent_at TEXT,
  resolved_at TEXT,
  detail_json TEXT NOT NULL CHECK (json_valid(detail_json))
);
"#;

const V6_RETENTION_AND_INDEX_SQL: &str = r#"
CREATE TABLE retention_policies (
  scope TEXT PRIMARY KEY CHECK (scope IN ('observations', 'observability-runs', 'health-snapshots', 'alert-events')),
  max_age_days INTEGER CHECK (max_age_days IS NULL OR max_age_days >= 1),
  max_rows INTEGER CHECK (max_rows IS NULL OR max_rows >= 1),
  updated_at TEXT NOT NULL
);

CREATE INDEX idx_observability_jobs_enabled_next_run_at
  ON observability_jobs(enabled, next_run_at);
CREATE INDEX idx_probe_observations_node_observed_at
  ON probe_observations(node_id, observed_at);
CREATE INDEX idx_probe_observations_run_id
  ON probe_observations(run_id);
CREATE INDEX idx_alert_events_state_last_seen_at
  ON alert_events(state, last_seen_at);
"#;

const V7_HEALTH_POLICY_SQL: &str = r#"
CREATE TABLE health_policy (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  stale_window_seconds INTEGER NOT NULL CHECK (stale_window_seconds BETWEEN 60 AND 2592000),
  unreachable_consecutive_failures INTEGER NOT NULL CHECK (unreachable_consecutive_failures BETWEEN 1 AND 100),
  cert_warning_days INTEGER NOT NULL CHECK (cert_warning_days BETWEEN 1 AND 3650),
  cert_critical_days INTEGER NOT NULL CHECK (cert_critical_days BETWEEN 0 AND 3650),
  updated_at TEXT NOT NULL,
  CHECK (cert_critical_days <= cert_warning_days)
);
INSERT INTO health_policy
  (id, stale_window_seconds, unreachable_consecutive_failures, cert_warning_days, cert_critical_days, updated_at)
VALUES
  (1, 86400, 3, 30, 7, 'default');
"#;

const V8_ALERT_WEBHOOK_SQL: &str = r#"
CREATE TABLE alert_hooks (
  hook_id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  hook_type TEXT NOT NULL CHECK (hook_type IN ('webhook')),
  endpoint_url TEXT NOT NULL,
  endpoint_url_redacted TEXT NOT NULL,
  endpoint_host TEXT NOT NULL,
  host_allow_json TEXT NOT NULL CHECK (json_valid(host_allow_json)),
  hmac_key_id TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  max_attempts INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 5),
  timeout_ms INTEGER NOT NULL CHECK (timeout_ms BETWEEN 1000 AND 5000),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE alert_delivery_attempts (
  attempt_id TEXT PRIMARY KEY,
  alert_id TEXT NOT NULL,
  hook_id TEXT NOT NULL,
  attempt_no INTEGER NOT NULL CHECK (attempt_no BETWEEN 1 AND 5),
  attempted_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('succeeded', 'failed', 'dry_run')),
  http_status_class TEXT,
  error_code TEXT,
  bytes_sent INTEGER NOT NULL CHECK (bytes_sent >= 0),
  FOREIGN KEY(alert_id) REFERENCES alert_events(alert_id) ON DELETE CASCADE,
  FOREIGN KEY(hook_id) REFERENCES alert_hooks(hook_id) ON DELETE CASCADE
);

CREATE INDEX idx_alert_delivery_attempts_alert_hook
  ON alert_delivery_attempts(alert_id, hook_id, attempted_at);
CREATE INDEX idx_alert_hooks_enabled_type
  ON alert_hooks(enabled, hook_type);
"#;
