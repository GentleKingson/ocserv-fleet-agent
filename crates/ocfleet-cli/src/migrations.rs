use rusqlite::backup::{Backup, StepResult};
use rusqlite::{Connection, OptionalExtension, Transaction};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};
use time::{OffsetDateTime, macros::format_description};

use crate::private_file::{self, PrivateFileError};
use crate::storage_payloads::{
    AlertDetailPayloadV1, AlertHostAllowPayloadV1, DeliveryAttemptDetailPayloadV1,
    EnrollmentMetadataKindV1, EnrollmentMetadataPayloadV1, HEALTH_SUMMARY_SCHEMA_V1,
    HealthDegradedMethodsPayloadV1, HealthSummaryPayloadV1, ObservationSummaryPayloadV1,
    RunSummaryPayloadV1, SchedulerPairPayloadV1, SchedulerSelectorPayloadV1, TrustBundlePayloadV1,
    validate_health_payload_relationship, validate_scheduler_payload_relationship,
};
use crate::store::{CURRENT_SCHEMA_VERSION, StoreError};

const BACKUP_PAGES_PER_STEP: i32 = 128;
const BACKUP_BUSY_RETRY_LIMIT: usize = 50;
const BACKUP_BUSY_PAUSE: Duration = Duration::from_millis(10);
const BACKUP_MAX_DURATION: Duration = Duration::from_secs(300);
const BACKUP_PATH_ATTEMPTS: usize = 100;
const BACKUP_DIRECTORY_NAME: &str = ".ocfleet-migration-backups";

pub(crate) struct Migration {
    pub(crate) version: i64,
    pub(crate) name: &'static str,
    pub(crate) description: &'static str,
    pub(crate) apply: fn(&Transaction<'_>) -> Result<(), StoreError>,
}

pub(crate) const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "0001_initial_core",
        description: "Create schema tracking, node registry, and controller audit log.",
        apply: apply_0001_initial_core,
    },
    Migration {
        version: 2,
        name: "0002_enrollment",
        description: "Create enrollment token and join request tables.",
        apply: apply_0002_enrollment,
    },
    Migration {
        version: 3,
        name: "0003_endpoint_trust",
        description: "Create endpoint trust lifecycle table.",
        apply: apply_0003_endpoint_trust,
    },
    Migration {
        version: 4,
        name: "0004_observability_base",
        description: "Create base observability scheduler, history, health, and alert tables.",
        apply: apply_0004_observability_base,
    },
    Migration {
        version: 5,
        name: "0005_observability_constraints_or_rebuild",
        description: "Rebuild observability tables with bounded enums, JSON checks, and foreign keys.",
        apply: apply_0005_observability_constraints_or_rebuild,
    },
    Migration {
        version: 6,
        name: "0006_retention_and_indexes",
        description: "Create retention policies and observability query indexes.",
        apply: apply_0006_retention_and_indexes,
    },
    Migration {
        version: 7,
        name: "0007_health_policy",
        description: "Create controller-local health and alert threshold policy.",
        apply: apply_0007_health_policy,
    },
    Migration {
        version: 8,
        name: "0008_alert_webhooks",
        description: "Create controller-local alert webhook hooks and delivery attempts.",
        apply: apply_0008_alert_webhooks,
    },
    Migration {
        version: 9,
        name: "0009_versioned_scheduler_selectors",
        description: "Migrate scheduler selector JSON to closed versioned v1 payloads.",
        apply: apply_0009_versioned_scheduler_selectors,
    },
    Migration {
        version: 10,
        name: "0010_versioned_health_snapshots",
        description: "Migrate health snapshot JSON to closed versioned v1 payloads.",
        apply: apply_0010_versioned_health_snapshots,
    },
    Migration {
        version: 11,
        name: "0011_versioned_observation_summaries",
        description: "Migrate observation summaries to closed versioned v1 payloads.",
        apply: apply_0011_versioned_observation_summaries,
    },
    Migration {
        version: 12,
        name: "0012_versioned_run_summaries",
        description: "Migrate observability run summaries to closed versioned v1 payloads.",
        apply: apply_0012_versioned_run_summaries,
    },
    Migration {
        version: 13,
        name: "0013_versioned_trust_bundles",
        description: "Migrate endpoint trust bundles to closed versioned v1 payloads.",
        apply: apply_0013_versioned_trust_bundles,
    },
    Migration {
        version: 14,
        name: "0014_versioned_alert_details",
        description: "Migrate alert details to closed versioned v1 payloads.",
        apply: apply_0014_versioned_alert_details,
    },
    Migration {
        version: 15,
        name: "0015_versioned_alert_host_allowlists",
        description: "Migrate alert host allowlists to closed versioned v1 payloads.",
        apply: apply_0015_versioned_alert_host_allowlists,
    },
    Migration {
        version: 16,
        name: "0016_versioned_enrollment_metadata",
        description: "Migrate enrollment labels and scope to closed versioned v1 payloads.",
        apply: apply_0016_versioned_enrollment_metadata,
    },
    Migration {
        version: 17,
        name: "0017_versioned_delivery_attempt_details",
        description: "Add closed versioned delivery-attempt detail payloads.",
        apply: apply_0017_versioned_delivery_attempt_details,
    },
];

pub(crate) fn migrate_to_current(
    conn: &mut Connection,
    path: &Path,
    created_database: bool,
) -> Result<(), StoreError> {
    let current_version = read_schema_version(conn)?;
    if current_version > CURRENT_SCHEMA_VERSION {
        return Err(StoreError::UnsupportedFutureSchema {
            found: current_version,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    if current_version == CURRENT_SCHEMA_VERSION {
        return Ok(());
    }

    if should_backup_before_migrate(conn, created_database, current_version)? {
        backup_database_before_migrate(conn, path, current_version, CURRENT_SCHEMA_VERSION)?;
    }
    apply_pending_migrations(conn, current_version)
}

pub(crate) fn read_schema_version(conn: &Connection) -> Result<i64, StoreError> {
    if !table_exists_conn(conn, "schema_migrations")? {
        return Ok(0);
    }
    let version = conn.query_row("SELECT max(version) FROM schema_migrations", [], |row| {
        row.get::<_, Option<i64>>(0)
    })?;
    Ok(version.unwrap_or(0))
}

fn should_backup_before_migrate(
    conn: &Connection,
    created_database: bool,
    current_version: i64,
) -> Result<bool, StoreError> {
    if current_version > 0 {
        return Ok(true);
    }
    if created_database {
        return Ok(false);
    }
    database_has_user_tables(conn)
}

fn apply_pending_migrations(conn: &mut Connection, current_version: i64) -> Result<(), StoreError> {
    let tx = conn.transaction()?;
    for migration in MIGRATIONS
        .iter()
        .filter(|migration| migration.version > current_version)
    {
        tracing::debug!(
            version = migration.version,
            name = migration.name,
            description = migration.description,
            "applying sqlite schema migration"
        );
        (migration.apply)(&tx)?;
        tx.execute(
            "INSERT OR IGNORE INTO schema_migrations (version, applied_at)
             VALUES (?1, strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
            [migration.version],
        )?;
    }
    run_integrity_checks(&tx)?;
    tx.commit()?;
    Ok(())
}

fn backup_database_before_migrate(
    conn: &Connection,
    path: &Path,
    from_version: i64,
    to_version: i64,
) -> Result<(), StoreError> {
    let timestamp = backup_timestamp()?;
    backup_database_before_migrate_with_timestamp(conn, path, from_version, to_version, &timestamp)
}

fn backup_database_before_migrate_with_timestamp(
    conn: &Connection,
    path: &Path,
    from_version: i64,
    to_version: i64,
    timestamp: &str,
) -> Result<(), StoreError> {
    let backup_dir = ensure_backup_directory(path)?;
    let backup_path = allocate_backup_path(&backup_dir, path, from_version, to_version, timestamp)?;
    create_private_empty_file(&backup_path)?;

    let backup_result = run_sqlite_backup(conn, &backup_path)
        .and_then(|()| write_backup_checksum_file(&backup_path))
        .and_then(|()| validate_backup_outputs(&backup_path));

    match backup_result {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = std::fs::remove_file(&backup_path);
            let _ = std::fs::remove_file(checksum_path(&backup_path));
            Err(err)
        }
    }
}

fn run_sqlite_backup(conn: &Connection, backup_path: &Path) -> Result<(), StoreError> {
    let mut dst = Connection::open(backup_path).map_err(map_backup_sqlite_error)?;
    dst.pragma_update(None, "busy_timeout", 5_000)
        .map_err(map_backup_sqlite_error)?;
    let backup = Backup::new(conn, &mut dst).map_err(map_backup_sqlite_error)?;
    let mut busy_retries = 0usize;
    let started_at = Instant::now();
    loop {
        if started_at.elapsed() > BACKUP_MAX_DURATION {
            return Err(StoreError::MigrationBackup(
                "sqlite backup exceeded time limit".to_string(),
            ));
        }
        match backup
            .step(BACKUP_PAGES_PER_STEP)
            .map_err(map_backup_sqlite_error)?
        {
            StepResult::Done => break,
            StepResult::More => {
                busy_retries = 0;
            }
            StepResult::Busy | StepResult::Locked => {
                if busy_retries >= BACKUP_BUSY_RETRY_LIMIT {
                    return Err(StoreError::MigrationBackup(
                        "sqlite backup stayed busy past retry limit".to_string(),
                    ));
                }
                busy_retries += 1;
                thread::sleep(BACKUP_BUSY_PAUSE);
            }
            _ => {
                return Err(StoreError::MigrationBackup(
                    "sqlite backup returned an unsupported step result".to_string(),
                ));
            }
        }
    }
    drop(backup);
    Ok(())
}

fn write_backup_checksum_file(backup_path: &Path) -> Result<(), StoreError> {
    let checksum = sha256_file_hex(backup_path).map_err(map_backup_io_error)?;
    let checksum_path = checksum_path(backup_path);
    let mut file = private_file::open_private_create_new(&checksum_path)
        .map_err(map_backup_private_file_error)?;
    let file_name = backup_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("controller.sqlite.backup");
    writeln!(file, "{checksum}  {file_name}").map_err(map_backup_io_error)?;
    file.sync_all().map_err(map_backup_io_error)?;
    Ok(())
}

fn validate_backup_outputs(backup_path: &Path) -> Result<(), StoreError> {
    private_file::validate_existing_private_file(backup_path)
        .map_err(map_backup_private_file_error)?;
    private_file::validate_existing_private_file(&checksum_path(backup_path))
        .map_err(map_backup_private_file_error)?;
    Ok(())
}

fn sha256_file_hex(path: &Path) -> Result<String, std::io::Error> {
    let mut file = private_file::open_existing_private_read(path).map_err(|err| match err {
        PrivateFileError::Io(err) => err,
        PrivateFileError::MissingParent
        | PrivateFileError::UnsafeParent
        | PrivateFileError::UnsafeFile
        | PrivateFileError::UnsupportedPlatform => {
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, err.to_string())
        }
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn create_private_empty_file(path: &Path) -> Result<(), StoreError> {
    let file =
        private_file::open_private_create_new(path).map_err(map_backup_private_file_error)?;
    file.sync_all().map_err(map_backup_io_error)?;
    Ok(())
}

fn allocate_backup_path(
    backup_dir: &Path,
    db_path: &Path,
    from_version: i64,
    to_version: i64,
    timestamp: &str,
) -> Result<PathBuf, StoreError> {
    let base_name = db_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("controller.sqlite");
    for attempt in 0..BACKUP_PATH_ATTEMPTS {
        let suffix = if attempt == 0 {
            String::new()
        } else {
            format!(".{attempt}")
        };
        let file_name = format!(
            "{base_name}.backup.from-v{from_version}-to-v{to_version}.{timestamp}{suffix}.sqlite"
        );
        let candidate = backup_dir.join(file_name);
        match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StoreError::UnsafePermissions);
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(candidate),
            Err(err) => return Err(StoreError::MigrationBackup(err.to_string())),
        }
    }
    Err(StoreError::MigrationBackup(
        "could not allocate bounded backup path".to_string(),
    ))
}

fn ensure_backup_directory(db_path: &Path) -> Result<PathBuf, StoreError> {
    let parent = db_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let backup_dir = parent.join(BACKUP_DIRECTORY_NAME);
    ensure_private_backup_directory(&backup_dir)?;
    Ok(backup_dir)
}

#[cfg(unix)]
fn ensure_private_backup_directory(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;

    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(StoreError::UnsafePermissions);
    }
    private_file::ensure_private_parent(&path.join("backup.placeholder"))
        .map_err(map_backup_private_file_error)?;
    let metadata = std::fs::symlink_metadata(path).map_err(map_backup_io_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StoreError::UnsafePermissions);
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(map_backup_io_error)?;
    let mode = std::fs::metadata(path)
        .map_err(map_backup_io_error)?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o700 {
        return Err(StoreError::UnsafePermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_backup_directory(_path: &Path) -> Result<(), StoreError> {
    Err(StoreError::UnsafePermissions)
}

fn backup_timestamp() -> Result<String, StoreError> {
    let format = format_description!("[year][month][day]T[hour][minute][second]Z");
    OffsetDateTime::now_utc()
        .format(format)
        .map_err(|err| StoreError::MigrationBackup(err.to_string()))
}

fn checksum_path(path: &Path) -> PathBuf {
    let mut raw: OsString = path.as_os_str().to_os_string();
    raw.push(".sha256");
    PathBuf::from(raw)
}

fn run_integrity_checks(tx: &Transaction<'_>) -> Result<(), StoreError> {
    let violations: i64 =
        tx.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    if violations != 0 {
        return Err(StoreError::DatabaseIntegrityCheckFailed {
            check: "foreign_key_check",
            detail: format!("{violations} violation(s)"),
        });
    }

    let quick_check: String = tx.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if quick_check != "ok" {
        return Err(StoreError::DatabaseIntegrityCheckFailed {
            check: "quick_check",
            detail: quick_check,
        });
    }
    Ok(())
}

fn apply_0001_initial_core(tx: &Transaction<'_>) -> Result<(), StoreError> {
    tx.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS schema_migrations (
          version INTEGER PRIMARY KEY,
          applied_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS nodes (
          node_id TEXT PRIMARY KEY,
          endpoint_id TEXT NOT NULL UNIQUE,
          name TEXT NOT NULL,
          region TEXT,
          role TEXT NOT NULL DEFAULT 'ocserv',
          enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS controller_audit_log (
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
        "#,
    )?;
    Ok(())
}

fn apply_0002_enrollment(tx: &Transaction<'_>) -> Result<(), StoreError> {
    tx.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS enrollment_tokens (
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

        CREATE TABLE IF NOT EXISTS join_requests (
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
        "#,
    )?;
    Ok(())
}

fn apply_0003_endpoint_trust(tx: &Transaction<'_>) -> Result<(), StoreError> {
    tx.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS endpoint_trust (
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
        "#,
    )?;
    Ok(())
}

fn apply_0004_observability_base(tx: &Transaction<'_>) -> Result<(), StoreError> {
    tx.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS observability_jobs (
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

        CREATE TABLE IF NOT EXISTS observability_runs (
          run_id TEXT PRIMARY KEY,
          job_id TEXT,
          started_at TEXT NOT NULL,
          finished_at TEXT,
          status TEXT NOT NULL,
          triggered_by TEXT NOT NULL,
          summary_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS probe_observations (
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

        CREATE TABLE IF NOT EXISTS health_snapshots (
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

        CREATE TABLE IF NOT EXISTS alert_events (
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
        "#,
    )?;
    Ok(())
}

fn apply_0005_observability_constraints_or_rebuild(tx: &Transaction<'_>) -> Result<(), StoreError> {
    if observability_tables_have_current_constraints(tx)? {
        return Ok(());
    }
    for table in [
        "observability_jobs",
        "observability_runs",
        "probe_observations",
        "health_snapshots",
        "alert_events",
    ] {
        if table_sql(tx, table)?.is_empty() {
            return Err(StoreError::DatabaseIntegrityCheckFailed {
                check: "migration_0005_prerequisites",
                detail: format!("missing table {table}"),
            });
        }
    }
    tx.execute_batch(OBSERVABILITY_V5_STRICT_REBUILD_SQL)?;
    Ok(())
}

fn apply_0006_retention_and_indexes(tx: &Transaction<'_>) -> Result<(), StoreError> {
    let retention_sql = table_sql(tx, "retention_policies")?;
    if retention_sql.is_empty() {
        tx.execute_batch(CURRENT_RETENTION_POLICY_SQL)?;
    } else if !retention_sql.contains("observability-runs") {
        tx.execute_batch(RETENTION_POLICY_STRICT_REBUILD_SQL)?;
    }
    tx.execute_batch(OBSERVABILITY_INDEX_SQL)?;
    Ok(())
}

fn apply_0007_health_policy(tx: &Transaction<'_>) -> Result<(), StoreError> {
    tx.execute_batch(HEALTH_POLICY_SQL)?;
    Ok(())
}

fn apply_0008_alert_webhooks(tx: &Transaction<'_>) -> Result<(), StoreError> {
    tx.execute_batch(ALERT_WEBHOOK_SQL)?;
    Ok(())
}

fn apply_0009_versioned_scheduler_selectors(tx: &Transaction<'_>) -> Result<(), StoreError> {
    let rows = {
        let mut stmt = tx.prepare(
            "SELECT job_id, kind, selector_json, pair_selector_json
             FROM observability_jobs ORDER BY job_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    for (job_id, kind, selector_json, pair_selector_json) in rows {
        let (selector, selector_payload, quarantine) =
            migrate_scheduler_selector_payload(&selector_json)?;
        let pair = pair_selector_json
            .as_deref()
            .map(migrate_scheduler_pair_payload)
            .transpose()?;
        validate_scheduler_payload_relationship(
            &kind,
            &selector_payload,
            pair.as_ref().map(|(_, payload)| payload),
        )
        .map_err(StoreError::InvalidInput)?;
        tx.execute(
            "UPDATE observability_jobs
             SET selector_json = ?1,
                 pair_selector_json = ?2,
                 enabled = CASE WHEN ?3 THEN 0 ELSE enabled END
             WHERE job_id = ?4",
            rusqlite::params![
                selector,
                pair.map(|(encoded, _)| encoded),
                quarantine,
                job_id
            ],
        )?;
    }
    Ok(())
}

fn migrate_scheduler_selector_payload(
    raw: &str,
) -> Result<(String, SchedulerSelectorPayloadV1, bool), StoreError> {
    let mut value: Value = serde_json::from_str(raw).map_err(|_| {
        StoreError::InvalidInput("legacy scheduler selector JSON is invalid".to_string())
    })?;
    let object = value.as_object_mut().ok_or_else(|| {
        StoreError::InvalidInput("legacy scheduler selector must be an object".to_string())
    })?;
    let quarantine = object.is_empty();
    if quarantine {
        object.insert(
            "selector".to_string(),
            Value::String("role=ocserv".to_string()),
        );
        object.insert("name".to_string(), Value::Null);
    }
    if !object.contains_key("schema") {
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "selector" | "name"))
        {
            return Err(StoreError::InvalidInput(
                "legacy scheduler selector contains unknown fields".to_string(),
            ));
        }
        object.insert(
            "schema".to_string(),
            Value::String(crate::storage_payloads::SCHEDULER_SELECTOR_SCHEMA_V1.to_string()),
        );
    }
    let payload =
        SchedulerSelectorPayloadV1::from_value(&value).map_err(StoreError::InvalidInput)?;
    let encoded = serde_json::to_string(&payload)
        .map_err(|error| StoreError::InvalidInput(error.to_string()))?;
    Ok((encoded, payload, quarantine))
}

fn migrate_scheduler_pair_payload(
    raw: &str,
) -> Result<(String, SchedulerPairPayloadV1), StoreError> {
    let mut value: Value = serde_json::from_str(raw).map_err(|_| {
        StoreError::InvalidInput("legacy scheduler pair JSON is invalid".to_string())
    })?;
    let object = value.as_object_mut().ok_or_else(|| {
        StoreError::InvalidInput("legacy scheduler pair must be an object".to_string())
    })?;
    if !object.contains_key("schema") {
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "source_node_id" | "target_node_id"))
        {
            return Err(StoreError::InvalidInput(
                "legacy scheduler pair contains unknown fields".to_string(),
            ));
        }
        object.insert(
            "schema".to_string(),
            Value::String(crate::storage_payloads::SCHEDULER_PAIR_SCHEMA_V1.to_string()),
        );
    }
    let payload = SchedulerPairPayloadV1::from_value(&value).map_err(StoreError::InvalidInput)?;
    let encoded = serde_json::to_string(&payload)
        .map_err(|error| StoreError::InvalidInput(error.to_string()))?;
    Ok((encoded, payload))
}

fn apply_0010_versioned_health_snapshots(tx: &Transaction<'_>) -> Result<(), StoreError> {
    let rows = {
        let mut stmt = tx.prepare(
            "SELECT node_id, status, degraded_methods_json, summary_json
             FROM health_snapshots ORDER BY node_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    for (node_id, status, degraded_methods_json, summary_json) in rows {
        let degraded_methods = migrate_health_degraded_methods_payload(&degraded_methods_json)?;
        let summary = migrate_health_summary_payload(&summary_json, &status)?;
        tx.execute(
            "UPDATE health_snapshots
             SET degraded_methods_json = ?1, summary_json = ?2
             WHERE node_id = ?3",
            (&degraded_methods, &summary, &node_id),
        )?;
    }
    Ok(())
}

fn migrate_health_degraded_methods_payload(raw: &str) -> Result<String, StoreError> {
    let value: Value = serde_json::from_str(raw).map_err(|_| {
        StoreError::InvalidInput("legacy health degraded methods JSON is invalid".to_string())
    })?;
    let payload = if let Some(methods) = value.as_array() {
        let methods = methods
            .iter()
            .map(|method| {
                method.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                    StoreError::InvalidInput(
                        "legacy health degraded methods must contain strings".to_string(),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        HealthDegradedMethodsPayloadV1::new(methods).map_err(StoreError::InvalidInput)?
    } else {
        HealthDegradedMethodsPayloadV1::from_value(&value).map_err(StoreError::InvalidInput)?
    };
    serde_json::to_string(&payload).map_err(|error| StoreError::InvalidInput(error.to_string()))
}

fn migrate_health_summary_payload(raw: &str, status: &str) -> Result<String, StoreError> {
    let mut value: Value = serde_json::from_str(raw).map_err(|_| {
        StoreError::InvalidInput("legacy health summary JSON is invalid".to_string())
    })?;
    let object = value.as_object_mut().ok_or_else(|| {
        StoreError::InvalidInput("legacy health summary must be an object".to_string())
    })?;
    if !object.contains_key("schema") {
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "region" | "role" | "status" | "endpoint_status" | "consecutive_failures"
            )
        }) {
            return Err(StoreError::InvalidInput(
                "legacy health summary contains unknown fields".to_string(),
            ));
        }
        object.insert(
            "schema".to_string(),
            Value::String(HEALTH_SUMMARY_SCHEMA_V1.to_string()),
        );
        object.entry("region".to_string()).or_insert(Value::Null);
        object.entry("role".to_string()).or_insert(Value::Null);
        object
            .entry("status".to_string())
            .or_insert_with(|| Value::String(status.to_string()));
        object
            .entry("endpoint_status".to_string())
            .or_insert(Value::Null);
        object
            .entry("consecutive_failures".to_string())
            .or_insert(Value::Null);
    }
    let payload = HealthSummaryPayloadV1::from_value(&value).map_err(StoreError::InvalidInput)?;
    validate_health_payload_relationship(status, &payload).map_err(StoreError::InvalidInput)?;
    serde_json::to_string(&payload).map_err(|error| StoreError::InvalidInput(error.to_string()))
}

fn apply_0011_versioned_observation_summaries(tx: &Transaction<'_>) -> Result<(), StoreError> {
    let rows = {
        let mut stmt = tx.prepare(
            "SELECT observation_id, method, result_class, summary_json
             FROM probe_observations ORDER BY observation_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    for (observation_id, method, result_class, summary_json) in rows {
        let value: Value = serde_json::from_str(&summary_json).map_err(|_| {
            StoreError::InvalidInput("legacy observation summary JSON is invalid".to_string())
        })?;
        let payload = ObservationSummaryPayloadV1::from_value(&value)
            .or_else(|_| ObservationSummaryPayloadV1::from_legacy(&method, &result_class, &value))
            .map_err(StoreError::InvalidInput)?;
        if payload.method != method || payload.result_class != result_class {
            return Err(StoreError::InvalidInput(
                "observation summary does not match relational method/result class".to_string(),
            ));
        }
        tx.execute(
            "UPDATE probe_observations SET summary_json = ?1 WHERE observation_id = ?2",
            (payload.to_value().to_string(), observation_id),
        )?;
    }
    Ok(())
}

fn apply_0012_versioned_run_summaries(tx: &Transaction<'_>) -> Result<(), StoreError> {
    let rows = {
        let mut stmt = tx.prepare(
            "SELECT r.run_id, r.job_id, j.kind, r.status, r.triggered_by, r.summary_json
             FROM observability_runs r
             LEFT JOIN observability_jobs j ON j.job_id = r.job_id
             ORDER BY r.run_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    for (run_id, job_id, kind, status, triggered_by, summary_json) in rows {
        let value: Value = serde_json::from_str(&summary_json).map_err(|_| {
            StoreError::InvalidInput("legacy run summary JSON is invalid".to_string())
        })?;
        let payload = RunSummaryPayloadV1::from_value(&value)
            .or_else(|_| {
                RunSummaryPayloadV1::from_legacy(
                    job_id.as_deref(),
                    kind.as_deref(),
                    &status,
                    &triggered_by,
                    &value,
                )
            })
            .map_err(StoreError::InvalidInput)?;
        payload
            .validate_relationship(job_id.as_deref(), kind.as_deref(), &status, &triggered_by)
            .map_err(StoreError::InvalidInput)?;
        tx.execute(
            "UPDATE observability_runs SET summary_json = ?1 WHERE run_id = ?2",
            (payload.to_value().to_string(), run_id),
        )?;
    }
    Ok(())
}

fn apply_0013_versioned_trust_bundles(tx: &Transaction<'_>) -> Result<(), StoreError> {
    let rows = {
        let mut stmt = tx.prepare(
            "SELECT endpoint_id, generation, status, trust_bundle_json
             FROM endpoint_trust ORDER BY endpoint_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    for (endpoint_id, generation, status, trust_bundle_json) in rows {
        let generation = u64::try_from(generation).map_err(|_| {
            StoreError::InvalidInput("legacy trust bundle generation is invalid".to_string())
        })?;
        let value: Value = serde_json::from_str(&trust_bundle_json).map_err(|_| {
            StoreError::InvalidInput("legacy trust bundle JSON is invalid".to_string())
        })?;
        let payload = TrustBundlePayloadV1::from_value(&value)
            .or_else(|_| {
                TrustBundlePayloadV1::from_legacy(&endpoint_id, generation, &status, &value)
            })
            .map_err(StoreError::InvalidInput)?;
        payload
            .validate_relationship(&endpoint_id, generation, &status)
            .map_err(StoreError::InvalidInput)?;
        tx.execute(
            "UPDATE endpoint_trust SET trust_bundle_json = ?1 WHERE endpoint_id = ?2",
            (payload.to_value().to_string(), endpoint_id),
        )?;
    }
    Ok(())
}

fn apply_0014_versioned_alert_details(tx: &Transaction<'_>) -> Result<(), StoreError> {
    let rows = {
        let mut stmt =
            tx.prepare("SELECT alert_id, detail_json FROM alert_events ORDER BY alert_id")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    for (alert_id, detail_json) in rows {
        let value: Value = serde_json::from_str(&detail_json).map_err(|_| {
            StoreError::InvalidInput("legacy alert detail JSON is invalid".to_string())
        })?;
        let payload = AlertDetailPayloadV1::from_value(&value)
            .or_else(|_| AlertDetailPayloadV1::from_legacy(&value))
            .map_err(StoreError::InvalidInput)?;
        tx.execute(
            "UPDATE alert_events SET detail_json = ?1 WHERE alert_id = ?2",
            (payload.to_value().to_string(), alert_id),
        )?;
    }
    Ok(())
}

fn apply_0015_versioned_alert_host_allowlists(tx: &Transaction<'_>) -> Result<(), StoreError> {
    let rows = {
        let mut stmt = tx.prepare(
            "SELECT hook_id, endpoint_host, host_allow_json FROM alert_hooks ORDER BY hook_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    for (hook_id, endpoint_host, host_allow_json) in rows {
        let value: Value = serde_json::from_str(&host_allow_json).map_err(|_| {
            StoreError::InvalidInput("legacy alert host allowlist JSON is invalid".to_string())
        })?;
        let payload = AlertHostAllowPayloadV1::from_value(&value)
            .or_else(|_| AlertHostAllowPayloadV1::from_legacy(&value))
            .map_err(StoreError::InvalidInput)?;
        payload
            .validate_relationship(&endpoint_host)
            .map_err(StoreError::InvalidInput)?;
        tx.execute(
            "UPDATE alert_hooks SET host_allow_json = ?1 WHERE hook_id = ?2",
            (payload.to_value().to_string(), hook_id),
        )?;
    }
    Ok(())
}

fn apply_0016_versioned_enrollment_metadata(tx: &Transaction<'_>) -> Result<(), StoreError> {
    let tokens = {
        let mut stmt = tx.prepare(
            "SELECT token_id, labels_json, scope_json FROM enrollment_tokens ORDER BY token_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    for (token_id, labels_json, scope_json) in tokens {
        let labels =
            migrate_enrollment_metadata(EnrollmentMetadataKindV1::TokenLabels, &labels_json)?;
        let scope = migrate_enrollment_metadata(EnrollmentMetadataKindV1::TokenScope, &scope_json)?;
        tx.execute(
            "UPDATE enrollment_tokens SET labels_json = ?1, scope_json = ?2 WHERE token_id = ?3",
            (labels.to_string(), scope.to_string(), token_id),
        )?;
    }

    let requests = {
        let mut stmt = tx.prepare(
            "SELECT request_id, status, requested_labels_json, approved_labels_json FROM join_requests ORDER BY request_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    for (request_id, status, requested_labels_json, approved_labels_json) in requests {
        let requested = migrate_enrollment_metadata(
            EnrollmentMetadataKindV1::RequestedLabels,
            &requested_labels_json,
        )?;
        let approved = migrate_enrollment_metadata(
            EnrollmentMetadataKindV1::ApprovedLabels,
            &approved_labels_json,
        )?;
        if status != "approved"
            && approved
                .get("values")
                .and_then(Value::as_object)
                .is_none_or(|values| !values.is_empty())
        {
            return Err(StoreError::InvalidInput(
                "non-approved enrollment request contains approved labels".to_string(),
            ));
        }
        tx.execute(
            "UPDATE join_requests SET requested_labels_json = ?1, approved_labels_json = ?2 WHERE request_id = ?3",
            (requested.to_string(), approved.to_string(), request_id),
        )?;
    }
    Ok(())
}

fn migrate_enrollment_metadata(
    kind: EnrollmentMetadataKindV1,
    raw: &str,
) -> Result<Value, StoreError> {
    let value: Value = serde_json::from_str(raw).map_err(|_| {
        StoreError::InvalidInput("legacy enrollment metadata JSON is invalid".to_string())
    })?;
    let payload = EnrollmentMetadataPayloadV1::from_value(kind, &value)
        .or_else(|_| EnrollmentMetadataPayloadV1::from_legacy(kind, &value))
        .map_err(StoreError::InvalidInput)?;
    Ok(payload.to_value())
}

fn apply_0017_versioned_delivery_attempt_details(tx: &Transaction<'_>) -> Result<(), StoreError> {
    let rows = {
        let mut stmt = tx.prepare(
            "SELECT attempt_id, alert_id, hook_id, attempt_no, attempted_at, status, http_status_class, error_code, bytes_sent FROM alert_delivery_attempts ORDER BY attempt_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, i64>(8)?,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    tx.execute_batch(
        r#"
ALTER TABLE alert_delivery_attempts RENAME TO alert_delivery_attempts_legacy_v16;
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
  detail_json TEXT NOT NULL CHECK (json_valid(detail_json)),
  FOREIGN KEY(alert_id) REFERENCES alert_events(alert_id) ON DELETE CASCADE,
  FOREIGN KEY(hook_id) REFERENCES alert_hooks(hook_id) ON DELETE CASCADE
);
"#,
    )?;
    for (
        attempt_id,
        alert_id,
        hook_id,
        attempt_no,
        attempted_at,
        status,
        http_status_class,
        error_code,
        bytes_sent,
    ) in rows
    {
        let attempt_no = u64::try_from(attempt_no).map_err(|_| {
            StoreError::InvalidInput("legacy delivery attempt number is invalid".to_string())
        })?;
        let bytes_sent = u64::try_from(bytes_sent).map_err(|_| {
            StoreError::InvalidInput("legacy delivery byte count is invalid".to_string())
        })?;
        let payload = DeliveryAttemptDetailPayloadV1::new(
            attempt_id.clone(),
            alert_id.clone(),
            hook_id.clone(),
            attempt_no,
            status.clone(),
            http_status_class.clone(),
            error_code.clone(),
            bytes_sent,
        )
        .map_err(StoreError::InvalidInput)?;
        tx.execute(
            "INSERT INTO alert_delivery_attempts
             (attempt_id, alert_id, hook_id, attempt_no, attempted_at, status, http_status_class, error_code, bytes_sent, detail_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                attempt_id,
                alert_id,
                hook_id,
                attempt_no,
                attempted_at,
                status,
                http_status_class,
                error_code,
                bytes_sent,
                payload.to_value().to_string(),
            ],
        )?;
    }
    tx.execute_batch(
        r#"
DROP TABLE alert_delivery_attempts_legacy_v16;
CREATE INDEX idx_alert_delivery_attempts_alert_hook
  ON alert_delivery_attempts(alert_id, hook_id, attempted_at);
"#,
    )?;
    Ok(())
}

fn observability_tables_have_current_constraints(tx: &Transaction<'_>) -> Result<bool, StoreError> {
    let checks = [
        (
            "observability_jobs",
            "kind TEXT NOT NULL CHECK",
            "job kind constraint",
        ),
        (
            "observability_runs",
            "triggered_by TEXT NOT NULL CHECK",
            "run trigger constraint",
        ),
        (
            "probe_observations",
            "FOREIGN KEY(run_id)",
            "observation run foreign key",
        ),
        (
            "health_snapshots",
            "status TEXT NOT NULL CHECK",
            "health status constraint",
        ),
        (
            "alert_events",
            "reason_code TEXT NOT NULL CHECK",
            "alert reason constraint",
        ),
    ];
    for (table, marker, _label) in checks {
        let sql = table_sql(tx, table)?;
        if !sql.contains(marker) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn table_sql(tx: &Transaction<'_>, table: &str) -> Result<String, StoreError> {
    Ok(tx
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or_default())
}

fn table_exists_conn(conn: &Connection, table: &str) -> Result<bool, StoreError> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )
        .optional()?;
    Ok(exists.is_some())
}

fn database_has_user_tables(conn: &Connection) -> Result<bool, StoreError> {
    let count: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_schema
         WHERE type = 'table'
           AND name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

fn map_backup_sqlite_error(err: rusqlite::Error) -> StoreError {
    StoreError::MigrationBackup(err.to_string())
}

fn map_backup_io_error(err: std::io::Error) -> StoreError {
    StoreError::MigrationBackup(err.to_string())
}

fn map_backup_private_file_error(err: PrivateFileError) -> StoreError {
    match err {
        PrivateFileError::Io(err) => StoreError::MigrationBackup(err.to_string()),
        PrivateFileError::MissingParent
        | PrivateFileError::UnsafeParent
        | PrivateFileError::UnsafeFile
        | PrivateFileError::UnsupportedPlatform => StoreError::UnsafePermissions,
    }
}

const OBSERVABILITY_INDEX_SQL: &str = r#"
CREATE INDEX IF NOT EXISTS idx_observability_jobs_enabled_next_run_at
  ON observability_jobs(enabled, next_run_at);
CREATE INDEX IF NOT EXISTS idx_probe_observations_node_observed_at
  ON probe_observations(node_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_probe_observations_run_id
  ON probe_observations(run_id);
CREATE INDEX IF NOT EXISTS idx_alert_events_state_last_seen_at
  ON alert_events(state, last_seen_at);
"#;

const CURRENT_RETENTION_POLICY_SQL: &str = r#"
CREATE TABLE retention_policies (
  scope TEXT PRIMARY KEY CHECK (scope IN ('observations', 'observability-runs', 'health-snapshots', 'alert-events')),
  max_age_days INTEGER CHECK (max_age_days IS NULL OR max_age_days >= 1),
  max_rows INTEGER CHECK (max_rows IS NULL OR max_rows >= 1),
  updated_at TEXT NOT NULL
);
"#;

const RETENTION_POLICY_STRICT_REBUILD_SQL: &str = r#"
ALTER TABLE retention_policies RENAME TO retention_policies_legacy_v5;
CREATE TABLE retention_policies (
  scope TEXT PRIMARY KEY CHECK (scope IN ('observations', 'observability-runs', 'health-snapshots', 'alert-events')),
  max_age_days INTEGER CHECK (max_age_days IS NULL OR max_age_days >= 1),
  max_rows INTEGER CHECK (max_rows IS NULL OR max_rows >= 1),
  updated_at TEXT NOT NULL
);
INSERT INTO retention_policies
  (scope, max_age_days, max_rows, updated_at)
SELECT scope, max_age_days, max_rows, updated_at
FROM retention_policies_legacy_v5;
DROP TABLE retention_policies_legacy_v5;
"#;

const HEALTH_POLICY_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS health_policy (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  stale_window_seconds INTEGER NOT NULL CHECK (stale_window_seconds BETWEEN 60 AND 2592000),
  unreachable_consecutive_failures INTEGER NOT NULL CHECK (unreachable_consecutive_failures BETWEEN 1 AND 100),
  cert_warning_days INTEGER NOT NULL CHECK (cert_warning_days BETWEEN 1 AND 3650),
  cert_critical_days INTEGER NOT NULL CHECK (cert_critical_days BETWEEN 0 AND 3650),
  updated_at TEXT NOT NULL,
  CHECK (cert_critical_days <= cert_warning_days)
);

INSERT OR IGNORE INTO health_policy
  (id, stale_window_seconds, unreachable_consecutive_failures, cert_warning_days, cert_critical_days, updated_at)
VALUES
  (1, 86400, 3, 30, 7, 'default');
"#;

const ALERT_WEBHOOK_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS alert_hooks (
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

CREATE TABLE IF NOT EXISTS alert_delivery_attempts (
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

CREATE INDEX IF NOT EXISTS idx_alert_delivery_attempts_alert_hook
  ON alert_delivery_attempts(alert_id, hook_id, attempted_at);
CREATE INDEX IF NOT EXISTS idx_alert_hooks_enabled_type
  ON alert_hooks(enabled, hook_type);
"#;

const OBSERVABILITY_V5_STRICT_REBUILD_SQL: &str = r#"
ALTER TABLE observability_jobs RENAME TO observability_jobs_legacy_v4;
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
INSERT INTO observability_jobs
  (job_id, kind, selector_json, pair_selector_json, interval_seconds, jitter_seconds, timeout_ms, enabled, next_run_at, last_run_at, created_at, updated_at)
SELECT job_id, kind, selector_json, pair_selector_json, interval_seconds, jitter_seconds, timeout_ms, enabled, next_run_at, last_run_at, created_at, updated_at
FROM observability_jobs_legacy_v4;
DROP TABLE observability_jobs_legacy_v4;

ALTER TABLE observability_runs RENAME TO observability_runs_legacy_v4;
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
INSERT INTO observability_runs
  (run_id, job_id, started_at, finished_at, status, triggered_by, summary_json)
SELECT run_id, job_id, started_at, finished_at, status, triggered_by, summary_json
FROM observability_runs_legacy_v4;
DROP TABLE observability_runs_legacy_v4;

ALTER TABLE probe_observations RENAME TO probe_observations_legacy_v4;
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
INSERT INTO probe_observations
  (observation_id, run_id, node_id, endpoint_id, method, ok, error_code, duration_ms, observed_at, expires_at, result_class, summary_json)
SELECT observation_id, run_id, node_id, endpoint_id, method, ok, error_code, duration_ms, observed_at, expires_at, result_class, summary_json
FROM probe_observations_legacy_v4;
DROP TABLE probe_observations_legacy_v4;

ALTER TABLE health_snapshots RENAME TO health_snapshots_legacy_v4;
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
INSERT INTO health_snapshots
  (node_id, endpoint_id, computed_at, status, freshness_seconds, last_success_at, last_failure_at, last_error_code, degraded_methods_json, summary_json)
SELECT node_id, endpoint_id, computed_at, status, freshness_seconds, last_success_at, last_failure_at, last_error_code, degraded_methods_json, summary_json
FROM health_snapshots_legacy_v4;
DROP TABLE health_snapshots_legacy_v4;

ALTER TABLE alert_events RENAME TO alert_events_legacy_v4;
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
INSERT INTO alert_events
  (alert_id, dedupe_key, node_id, severity, state, reason_code, first_seen_at, last_seen_at, last_sent_at, resolved_at, detail_json)
SELECT alert_id, dedupe_key, node_id, severity, state, reason_code, first_seen_at, last_seen_at, last_sent_at, resolved_at, detail_json
FROM alert_events_legacy_v4;
DROP TABLE alert_events_legacy_v4;
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_failure_prevents_migration_from_running() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db = dir.path().join("controller.sqlite");
        {
            let conn = Connection::open(&db).expect("create db");
            conn.execute_batch(
                r#"
                CREATE TABLE schema_migrations (
                  version INTEGER PRIMARY KEY,
                  applied_at TEXT NOT NULL
                );
                INSERT INTO schema_migrations (version, applied_at)
                VALUES (1, '2026-07-09T00:00:00Z');
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
                "#,
            )
            .expect("v1 schema");
        }
        make_private(&db);

        let timestamp = "20260709T000000Z";
        let backup_dir = ensure_backup_directory(&db).expect("backup dir");
        for _ in 0..BACKUP_PATH_ATTEMPTS {
            let colliding_path =
                allocate_backup_path(&backup_dir, &db, 1, CURRENT_SCHEMA_VERSION, timestamp)
                    .expect("backup path");
            std::fs::create_dir(&colliding_path).expect("create collision directory");
        }

        let mut conn = Connection::open(&db).expect("open db");
        conn.pragma_update(None, "foreign_keys", "ON")
            .expect("foreign keys");
        let result = backup_database_before_migrate_with_timestamp(
            &conn,
            &db,
            1,
            CURRENT_SCHEMA_VERSION,
            timestamp,
        )
        .and_then(|()| apply_pending_migrations(&mut conn, 1));

        assert!(matches!(result, Err(StoreError::MigrationBackup(_))));
        let version = read_schema_version(&conn).expect("schema version");
        assert_eq!(version, 1);
        let enrollment_exists =
            table_exists_conn(&conn, "enrollment_tokens").expect("table exists query");
        assert!(
            !enrollment_exists,
            "migration must not run after backup failure"
        );
    }

    #[cfg(unix)]
    fn make_private(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod private");
    }

    #[cfg(not(unix))]
    fn make_private(_path: &Path) {}
}
