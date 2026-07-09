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
    ] {
        assert_schema_object_exists(&conn, "table", table);
    }
    for index in [
        "idx_observability_jobs_enabled_next_run_at",
        "idx_probe_observations_node_observed_at",
        "idx_probe_observations_run_id",
        "idx_alert_events_state_last_seen_at",
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
    for version in 1..=CURRENT_SCHEMA_VERSION {
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
        assert_eq!(table_count(&conn, "health_policy"), 1);
        assert_schema_object_exists(&conn, "index", "idx_probe_observations_run_id");

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

fn create_legacy_fixture(path: &Path, version: i64, rows: usize) {
    assert!((1..=CURRENT_SCHEMA_VERSION).contains(&version));
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
            conn.execute(
                "INSERT INTO enrollment_tokens
                 (token_id, token_hash, created_at, created_by, expires_at, max_uses, used_count, status, description, labels_json, scope_json)
                 VALUES (?1, ?2, ?3, 'operator', '2099-01-01T00:00:00Z', 10, 0, 'active', NULL, '{}', '{}')",
                (&token_id, format!("hash-{idx:04}"), NOW),
            )
            .expect("insert enrollment token");
        }
        if version >= 3 {
            conn.execute(
                "INSERT INTO endpoint_trust
                 (endpoint_id, node_id, fingerprint, status, generation, previous_endpoint_id, rotated_to, trust_bundle_json, created_at, updated_at)
                 VALUES (?1, ?2, NULL, 'active', 1, NULL, NULL, '{}', ?3, ?3)",
                (&endpoint_id, &node_id, NOW),
            )
            .expect("insert endpoint trust");
        }
        if version >= 4 {
            insert_observability_rows(conn, idx, &node_id, &endpoint_id);
        }
    }
}

fn insert_observability_rows(conn: &Connection, idx: usize, node_id: &str, endpoint_id: &str) {
    let job_id = format!("job-{idx:04}");
    let run_id = format!("run-{idx:04}");
    let observation_id = format!("obs-{idx:04}");
    conn.execute(
        "INSERT INTO observability_jobs
         (job_id, kind, selector_json, pair_selector_json, interval_seconds, jitter_seconds, timeout_ms, enabled, next_run_at, last_run_at, created_at, updated_at)
         VALUES (?1, 'controller-ping', '{}', NULL, 60, 0, 5000, 1, NULL, NULL, ?2, ?2)",
        (&job_id, NOW),
    )
    .expect("insert observability job");
    conn.execute(
        "INSERT INTO observability_runs
         (run_id, job_id, started_at, finished_at, status, triggered_by, summary_json)
         VALUES (?1, ?2, ?3, ?3, 'succeeded', 'manual', '{}')",
        (&run_id, &job_id, NOW),
    )
    .expect("insert observability run");
    conn.execute(
        "INSERT INTO probe_observations
         (observation_id, run_id, node_id, endpoint_id, method, ok, error_code, duration_ms, observed_at, expires_at, result_class, summary_json)
         VALUES (?1, ?2, ?3, ?4, 'probe.controller.ping', 1, NULL, 12, ?5, NULL, 'controller_rpc_summary', '{}')",
        (&observation_id, &run_id, node_id, endpoint_id, NOW),
    )
    .expect("insert probe observation");
    conn.execute(
        "INSERT INTO health_snapshots
         (node_id, endpoint_id, computed_at, status, freshness_seconds, last_success_at, last_failure_at, last_error_code, degraded_methods_json, summary_json)
         VALUES (?1, ?2, ?3, 'healthy', 30, ?3, NULL, NULL, '[]', '{}')",
        (node_id, endpoint_id, NOW),
    )
    .expect("insert health snapshot");
    conn.execute(
        "INSERT INTO alert_events
         (alert_id, dedupe_key, node_id, severity, state, reason_code, first_seen_at, last_seen_at, last_sent_at, resolved_at, detail_json)
         VALUES (?1, ?2, ?3, 'warning', 'open', 'NODE_STALE', ?4, ?4, NULL, NULL, '{}')",
        (
            format!("alert-{idx:04}"),
            format!("alert:{idx:04}"),
            node_id,
            NOW,
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
