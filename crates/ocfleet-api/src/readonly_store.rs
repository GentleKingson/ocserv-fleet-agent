use std::io;
use std::path::{Path, PathBuf};

use ocfleet_cli::private_file::{self, PrivateFileError};
use ocfleet_cli::storage_payloads::{
    AlertDetailPayloadV1, AuditDetailPayloadV1, HealthDegradedMethodsPayloadV1,
    HealthSummaryPayloadV1, ObservationSummaryPayloadV1, RunSummaryPayloadV1,
    SchedulerPairPayloadV1, SchedulerSelectorPayloadV1, validate_health_payload_relationship,
    validate_scheduler_payload_relationship,
};
use ocfleet_cli::store::{
    AlertEventRecord, AuditRecord, CURRENT_SCHEMA_VERSION, HealthSnapshotRecord, NodeRecord,
    ObservabilityJobRecord, ObservabilityRunRecord, ProbeObservationRecord,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, params, types::Type};
use serde_json::Value;

#[derive(Clone)]
pub struct ReadOnlyStore {
    database: PathBuf,
}

#[derive(Debug, Clone)]
pub struct NodeHealthRecord {
    pub node: NodeRecord,
    pub snapshot: Option<HealthSnapshotRecord>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreValidationError {
    #[error("controller database private-file validation failed")]
    UnsafeDatabaseFiles(#[source] PrivateFileError),
    #[error("controller database SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("controller database schema version is {actual:?}; expected {expected}")]
    SchemaVersion { actual: Option<i64>, expected: i64 },
    #[error("controller database required table is missing: {0}")]
    MissingTable(&'static str),
    #[error("controller database quick_check failed")]
    QuickCheck,
}

pub trait ApiReadStore: Send + Sync {
    fn validate_startup(&self) -> Result<(), StoreValidationError>;
    fn check_readable(&self) -> rusqlite::Result<()>;
    fn list_node_health(&self, limit: u64) -> rusqlite::Result<Vec<NodeHealthRecord>>;
    fn get_node_health(&self, node_id: &str) -> rusqlite::Result<Option<NodeHealthRecord>>;
    fn list_jobs(&self, limit: u64) -> rusqlite::Result<Vec<ObservabilityJobRecord>>;
    fn get_job(&self, job_id: &str) -> rusqlite::Result<Option<ObservabilityJobRecord>>;
    fn list_runs(
        &self,
        limit: u64,
        job_id: Option<&str>,
        status: Option<&str>,
    ) -> rusqlite::Result<Vec<ObservabilityRunRecord>>;
    fn get_run(&self, run_id: &str) -> rusqlite::Result<Option<ObservabilityRunRecord>>;
    fn list_observations(
        &self,
        limit: u64,
        node_id: Option<&str>,
        method: Option<&str>,
    ) -> rusqlite::Result<Vec<ProbeObservationRecord>>;
    fn get_observation(
        &self,
        observation_id: &str,
    ) -> rusqlite::Result<Option<ProbeObservationRecord>>;
    fn list_alerts(
        &self,
        limit: u64,
        state: Option<&str>,
        severity: Option<&str>,
        node_id: Option<&str>,
    ) -> rusqlite::Result<Vec<AlertEventRecord>>;
    fn get_alert(&self, lookup: &str) -> rusqlite::Result<Option<AlertEventRecord>>;
    fn list_audit_window(
        &self,
        from: &str,
        to: &str,
        limit: u64,
    ) -> rusqlite::Result<Vec<AuditRecord>>;
}

impl ReadOnlyStore {
    pub fn new(database: PathBuf) -> Self {
        Self { database }
    }

    pub fn check_readable(&self) -> rusqlite::Result<()> {
        let conn = self.open_conn()?;
        let _: i64 = conn.query_row("SELECT count(*) FROM schema_migrations", [], |row| {
            row.get(0)
        })?;
        Ok(())
    }

    pub fn validate_startup(&self) -> Result<(), StoreValidationError> {
        prepare_database_files(&self.database)
            .map_err(StoreValidationError::UnsafeDatabaseFiles)?;
        let conn = self.open_conn()?;
        for table in REQUIRED_API_TABLES {
            if !table_exists(&conn, table)? {
                return Err(StoreValidationError::MissingTable(table));
            }
        }

        let actual = conn.query_row("SELECT max(version) FROM schema_migrations", [], |row| {
            row.get::<_, Option<i64>>(0)
        })?;
        if actual != Some(CURRENT_SCHEMA_VERSION) {
            return Err(StoreValidationError::SchemaVersion {
                actual,
                expected: CURRENT_SCHEMA_VERSION,
            });
        }

        let quick_check: String = conn.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        if quick_check != "ok" {
            return Err(StoreValidationError::QuickCheck);
        }
        Ok(())
    }

    pub fn list_node_health(&self, limit: u64) -> rusqlite::Result<Vec<NodeHealthRecord>> {
        let limit = u64_to_i64(limit, "limit")?;
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT n.node_id, n.endpoint_id, n.name, n.region, n.role, n.enabled,
                    h.node_id, h.endpoint_id, h.computed_at, h.status, h.freshness_seconds,
                    h.last_success_at, h.last_failure_at, h.last_error_code,
                    h.degraded_methods_json, h.summary_json
             FROM nodes n
             LEFT JOIN health_snapshots h ON h.node_id = n.node_id
             ORDER BY n.node_id
             LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], node_health_from_row)?;
        rows.collect()
    }

    pub fn get_node_health(&self, node_id: &str) -> rusqlite::Result<Option<NodeHealthRecord>> {
        let conn = self.open_conn()?;
        conn.query_row(
            "SELECT n.node_id, n.endpoint_id, n.name, n.region, n.role, n.enabled,
                    h.node_id, h.endpoint_id, h.computed_at, h.status, h.freshness_seconds,
                    h.last_success_at, h.last_failure_at, h.last_error_code,
                    h.degraded_methods_json, h.summary_json
             FROM nodes n
             LEFT JOIN health_snapshots h ON h.node_id = n.node_id
             WHERE n.node_id = ?1",
            [node_id],
            node_health_from_row,
        )
        .optional()
    }

    pub fn list_jobs(&self, limit: u64) -> rusqlite::Result<Vec<ObservabilityJobRecord>> {
        let limit = u64_to_i64(limit, "limit")?;
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT job_id, kind, selector_json, pair_selector_json, interval_seconds,
                    jitter_seconds, timeout_ms, enabled, next_run_at, last_run_at,
                    created_at, updated_at
             FROM observability_jobs
             ORDER BY job_id
             LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], observability_job_from_row)?;
        rows.collect()
    }

    pub fn get_job(&self, job_id: &str) -> rusqlite::Result<Option<ObservabilityJobRecord>> {
        let conn = self.open_conn()?;
        conn.query_row(
            "SELECT job_id, kind, selector_json, pair_selector_json, interval_seconds,
                    jitter_seconds, timeout_ms, enabled, next_run_at, last_run_at,
                    created_at, updated_at
             FROM observability_jobs
             WHERE job_id = ?1",
            [job_id],
            observability_job_from_row,
        )
        .optional()
    }

    pub fn list_runs(
        &self,
        limit: u64,
        job_id: Option<&str>,
        status: Option<&str>,
    ) -> rusqlite::Result<Vec<ObservabilityRunRecord>> {
        let limit = u64_to_i64(limit, "limit")?;
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT r.run_id, r.job_id, r.started_at, r.finished_at, r.status,
                    r.triggered_by, r.summary_json,
                    COUNT(o.observation_id) AS observation_count,
                    COALESCE(SUM(CASE WHEN o.ok = 0 THEN 1 ELSE 0 END), 0)
                      AS failed_observation_count,
                    j.kind
             FROM observability_runs r
             LEFT JOIN probe_observations o ON o.run_id = r.run_id
             LEFT JOIN observability_jobs j ON j.job_id = r.job_id
             WHERE (?1 IS NULL OR r.job_id = ?1)
               AND (?2 IS NULL OR r.status = ?2)
             GROUP BY r.run_id, r.job_id, r.started_at, r.finished_at, r.status,
                      r.triggered_by, r.summary_json, j.kind
             ORDER BY r.started_at DESC, r.run_id DESC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![job_id, status, limit], observability_run_from_row)?;
        rows.collect()
    }

    pub fn get_run(&self, run_id: &str) -> rusqlite::Result<Option<ObservabilityRunRecord>> {
        let conn = self.open_conn()?;
        conn.query_row(
            "SELECT r.run_id, r.job_id, r.started_at, r.finished_at, r.status,
                    r.triggered_by, r.summary_json,
                    COUNT(o.observation_id) AS observation_count,
                    COALESCE(SUM(CASE WHEN o.ok = 0 THEN 1 ELSE 0 END), 0)
                      AS failed_observation_count,
                    j.kind
             FROM observability_runs r
             LEFT JOIN probe_observations o ON o.run_id = r.run_id
             LEFT JOIN observability_jobs j ON j.job_id = r.job_id
             WHERE r.run_id = ?1
             GROUP BY r.run_id, r.job_id, r.started_at, r.finished_at, r.status,
                      r.triggered_by, r.summary_json, j.kind",
            [run_id],
            observability_run_from_row,
        )
        .optional()
    }

    pub fn list_observations(
        &self,
        limit: u64,
        node_id: Option<&str>,
        method: Option<&str>,
    ) -> rusqlite::Result<Vec<ProbeObservationRecord>> {
        let limit = u64_to_i64(limit, "limit")?;
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT observation_id, run_id, node_id, endpoint_id, method, ok, error_code,
                    duration_ms, observed_at, expires_at, result_class, summary_json
             FROM probe_observations
             WHERE (?1 IS NULL OR node_id = ?1)
               AND (?2 IS NULL OR method = ?2)
             ORDER BY observed_at DESC, observation_id DESC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![node_id, method, limit], probe_observation_from_row)?;
        rows.collect()
    }

    pub fn get_observation(
        &self,
        observation_id: &str,
    ) -> rusqlite::Result<Option<ProbeObservationRecord>> {
        let conn = self.open_conn()?;
        conn.query_row(
            "SELECT observation_id, run_id, node_id, endpoint_id, method, ok, error_code,
                    duration_ms, observed_at, expires_at, result_class, summary_json
             FROM probe_observations
             WHERE observation_id = ?1",
            [observation_id],
            probe_observation_from_row,
        )
        .optional()
    }

    pub fn list_alerts(
        &self,
        limit: u64,
        state: Option<&str>,
        severity: Option<&str>,
        node_id: Option<&str>,
    ) -> rusqlite::Result<Vec<AlertEventRecord>> {
        let limit = u64_to_i64(limit, "limit")?;
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT alert_id, dedupe_key, node_id, severity, state, reason_code,
                    first_seen_at, last_seen_at, last_sent_at, resolved_at, detail_json
             FROM alert_events
             WHERE (?1 IS NULL OR state = ?1)
               AND (?2 IS NULL OR severity = ?2)
               AND (?3 IS NULL OR node_id = ?3)
             ORDER BY last_seen_at DESC, alert_id
             LIMIT ?4",
        )?;
        let rows = stmt.query_map(
            params![state, severity, node_id, limit],
            alert_event_from_row,
        )?;
        rows.collect()
    }

    pub fn get_alert(&self, lookup: &str) -> rusqlite::Result<Option<AlertEventRecord>> {
        let conn = self.open_conn()?;
        conn.query_row(
            "SELECT alert_id, dedupe_key, node_id, severity, state, reason_code,
                    first_seen_at, last_seen_at, last_sent_at, resolved_at, detail_json
             FROM alert_events
             WHERE alert_id = ?1 OR dedupe_key = ?1
             ORDER BY last_seen_at DESC, alert_id
             LIMIT 1",
            [lookup],
            alert_event_from_row,
        )
        .optional()
    }

    pub fn list_audit_window(
        &self,
        from: &str,
        to: &str,
        limit: u64,
    ) -> rusqlite::Result<Vec<AuditRecord>> {
        let limit = u64_to_i64(limit, "limit")?;
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, ts, actor, event, node_id, endpoint_id, method, request_id,
                    params_hash, ok, error_code, duration_ms, detail_json
             FROM controller_audit_log
             WHERE ts >= ?1 AND ts < ?2
             ORDER BY ts ASC, id ASC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![from, to, limit], audit_record_from_row)?;
        rows.collect()
    }

    fn open_conn(&self) -> rusqlite::Result<Connection> {
        open_read_only_connection(&self.database)
    }
}

impl ApiReadStore for ReadOnlyStore {
    fn validate_startup(&self) -> Result<(), StoreValidationError> {
        Self::validate_startup(self)
    }

    fn check_readable(&self) -> rusqlite::Result<()> {
        Self::check_readable(self)
    }

    fn list_node_health(&self, limit: u64) -> rusqlite::Result<Vec<NodeHealthRecord>> {
        Self::list_node_health(self, limit)
    }

    fn get_node_health(&self, node_id: &str) -> rusqlite::Result<Option<NodeHealthRecord>> {
        Self::get_node_health(self, node_id)
    }

    fn list_jobs(&self, limit: u64) -> rusqlite::Result<Vec<ObservabilityJobRecord>> {
        Self::list_jobs(self, limit)
    }

    fn get_job(&self, job_id: &str) -> rusqlite::Result<Option<ObservabilityJobRecord>> {
        Self::get_job(self, job_id)
    }

    fn list_runs(
        &self,
        limit: u64,
        job_id: Option<&str>,
        status: Option<&str>,
    ) -> rusqlite::Result<Vec<ObservabilityRunRecord>> {
        Self::list_runs(self, limit, job_id, status)
    }

    fn get_run(&self, run_id: &str) -> rusqlite::Result<Option<ObservabilityRunRecord>> {
        Self::get_run(self, run_id)
    }

    fn list_observations(
        &self,
        limit: u64,
        node_id: Option<&str>,
        method: Option<&str>,
    ) -> rusqlite::Result<Vec<ProbeObservationRecord>> {
        Self::list_observations(self, limit, node_id, method)
    }

    fn get_observation(
        &self,
        observation_id: &str,
    ) -> rusqlite::Result<Option<ProbeObservationRecord>> {
        Self::get_observation(self, observation_id)
    }

    fn list_alerts(
        &self,
        limit: u64,
        state: Option<&str>,
        severity: Option<&str>,
        node_id: Option<&str>,
    ) -> rusqlite::Result<Vec<AlertEventRecord>> {
        Self::list_alerts(self, limit, state, severity, node_id)
    }

    fn get_alert(&self, lookup: &str) -> rusqlite::Result<Option<AlertEventRecord>> {
        Self::get_alert(self, lookup)
    }

    fn list_audit_window(
        &self,
        from: &str,
        to: &str,
        limit: u64,
    ) -> rusqlite::Result<Vec<AuditRecord>> {
        Self::list_audit_window(self, from, to, limit)
    }
}

fn open_read_only_connection(path: &Path) -> rusqlite::Result<Connection> {
    prepare_database_files(path).map_err(|_| rusqlite::Error::InvalidPath(path.to_path_buf()))?;
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.pragma_update(None, "busy_timeout", 5_000)?;
    conn.pragma_update(None, "query_only", "ON")?;
    conn.pragma_update(None, "trusted_schema", "OFF")?;
    validate_database_files(path).map_err(|_| rusqlite::Error::InvalidPath(path.to_path_buf()))?;
    Ok(conn)
}

const REQUIRED_API_TABLES: [&str; 11] = [
    "schema_migrations",
    "nodes",
    "health_snapshots",
    "observability_jobs",
    "observability_runs",
    "scheduler_job_claims",
    "scheduler_maintenance",
    "health_evaluation_runs",
    "probe_observations",
    "alert_events",
    "controller_audit_log",
];

fn table_exists(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )
}

fn validate_database_files(path: &Path) -> Result<(), PrivateFileError> {
    private_file::validate_existing_private_file(path)?;
    for sidecar in sqlite_sidecar_paths(path) {
        match std::fs::symlink_metadata(&sidecar) {
            Ok(_) => private_file::validate_existing_private_file(&sidecar)?,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(PrivateFileError::Io(err)),
        }
    }
    Ok(())
}

fn prepare_database_files(path: &Path) -> Result<(), PrivateFileError> {
    private_file::validate_existing_private_file(path)?;
    for sidecar in sqlite_sidecar_paths(path) {
        match std::fs::symlink_metadata(&sidecar) {
            Ok(_) => private_file::validate_existing_private_file(&sidecar)?,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                match private_file::open_private_create_new(&sidecar) {
                    Ok(file) => drop(file),
                    Err(PrivateFileError::Io(err))
                        if err.kind() == io::ErrorKind::AlreadyExists =>
                    {
                        private_file::validate_existing_private_file(&sidecar)?;
                    }
                    Err(err) => return Err(err),
                }
            }
            Err(err) => return Err(PrivateFileError::Io(err)),
        }
    }
    validate_database_files(path)
}

fn sqlite_sidecar_paths(path: &Path) -> [PathBuf; 2] {
    let mut wal = path.as_os_str().to_os_string();
    wal.push("-wal");
    let mut shm = path.as_os_str().to_os_string();
    shm.push("-shm");
    [PathBuf::from(wal), PathBuf::from(shm)]
}

fn node_health_from_row(row: &Row<'_>) -> rusqlite::Result<NodeHealthRecord> {
    let node = NodeRecord {
        node_id: row.get(0)?,
        endpoint_id: row.get(1)?,
        name: row.get(2)?,
        region: row.get(3)?,
        role: row.get(4)?,
        enabled: i64_to_bool(row.get(5)?, 5)?,
    };
    let snapshot_node_id: Option<String> = row.get(6)?;
    let snapshot = snapshot_node_id
        .map(|node_id| {
            let degraded_methods_json: String = row.get(14)?;
            let summary_json: String = row.get(15)?;
            let freshness_seconds: Option<i64> = row.get(10)?;
            let degraded_methods_json = parse_json_column(&degraded_methods_json, 14)?;
            HealthDegradedMethodsPayloadV1::from_value(&degraded_methods_json).map_err(
                |error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        14,
                        rusqlite::types::Type::Text,
                        Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
                    )
                },
            )?;
            let summary_json = parse_json_column(&summary_json, 15)?;
            let summary = HealthSummaryPayloadV1::from_value(&summary_json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    15,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
                )
            })?;
            let status: String = row.get(9)?;
            validate_health_payload_relationship(&status, &summary).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    15,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
                )
            })?;
            Ok::<HealthSnapshotRecord, rusqlite::Error>(HealthSnapshotRecord {
                node_id,
                endpoint_id: row.get(7)?,
                computed_at: row.get(8)?,
                status,
                freshness_seconds: freshness_seconds.and_then(|value| u64::try_from(value).ok()),
                last_success_at: row.get(11)?,
                last_failure_at: row.get(12)?,
                last_error_code: row.get(13)?,
                degraded_methods_json,
                summary_json,
            })
        })
        .transpose()?;
    Ok(NodeHealthRecord { node, snapshot })
}

fn observability_job_from_row(row: &Row<'_>) -> rusqlite::Result<ObservabilityJobRecord> {
    let selector_json: String = row.get(2)?;
    let pair_selector_json: Option<String> = row.get(3)?;
    let selector_json = parse_json_column(&selector_json, 2)?;
    let selector = SchedulerSelectorPayloadV1::from_value(&selector_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
        )
    })?;
    let pair_selector_json = pair_selector_json
        .as_deref()
        .map(|value| parse_json_column(value, 3))
        .transpose()?;
    let pair = pair_selector_json
        .as_ref()
        .map(SchedulerPairPayloadV1::from_value)
        .transpose()
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
            )
        })?;
    let kind: String = row.get(1)?;
    validate_scheduler_payload_relationship(&kind, &selector, pair.as_ref()).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
        )
    })?;
    Ok(ObservabilityJobRecord {
        job_id: row.get(0)?,
        kind,
        selector_json,
        pair_selector_json,
        interval_seconds: i64_to_u64(row.get(4)?, 4)?,
        jitter_seconds: i64_to_u64(row.get(5)?, 5)?,
        timeout_ms: i64_to_u64(row.get(6)?, 6)?,
        enabled: i64_to_bool(row.get(7)?, 7)?,
        next_run_at: row.get(8)?,
        last_run_at: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

fn observability_run_from_row(row: &Row<'_>) -> rusqlite::Result<ObservabilityRunRecord> {
    let summary_json: String = row.get(6)?;
    let job_id: Option<String> = row.get(1)?;
    let status: String = row.get(4)?;
    let triggered_by: String = row.get(5)?;
    let kind: Option<String> = row.get(9)?;
    let summary_json = parse_json_column(&summary_json, 6)?;
    let payload = RunSummaryPayloadV1::from_value(&summary_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            6,
            Type::Text,
            Box::new(io::Error::new(io::ErrorKind::InvalidData, error)),
        )
    })?;
    payload
        .validate_relationship(job_id.as_deref(), kind.as_deref(), &status, &triggered_by)
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                6,
                Type::Text,
                Box::new(io::Error::new(io::ErrorKind::InvalidData, error)),
            )
        })?;
    Ok(ObservabilityRunRecord {
        run_id: row.get(0)?,
        job_id,
        started_at: row.get(2)?,
        finished_at: row.get(3)?,
        status,
        triggered_by,
        summary_json: payload.public_summary(),
        observation_count: i64_to_u64(row.get(7)?, 7)?,
        failed_observation_count: i64_to_u64(row.get(8)?, 8)?,
    })
}

fn probe_observation_from_row(row: &Row<'_>) -> rusqlite::Result<ProbeObservationRecord> {
    let ok: Option<i64> = row.get(5)?;
    let duration_ms: Option<i64> = row.get(7)?;
    let summary_json: String = row.get(11)?;
    let method: String = row.get(4)?;
    let result_class: String = row.get(10)?;
    let summary_json = parse_json_column(&summary_json, 11)?;
    let payload = ObservationSummaryPayloadV1::from_value(&summary_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            11,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
        )
    })?;
    if payload.method != method || payload.result_class != result_class {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            11,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "observation summary does not match relational method/result class",
            )),
        ));
    }
    Ok(ProbeObservationRecord {
        observation_id: row.get(0)?,
        run_id: row.get(1)?,
        node_id: row.get(2)?,
        endpoint_id: row.get(3)?,
        method,
        ok: ok.map(|value| i64_to_bool(value, 5)).transpose()?,
        error_code: row.get(6)?,
        duration_ms: duration_ms.and_then(|value| u64::try_from(value).ok()),
        observed_at: row.get(8)?,
        expires_at: row.get(9)?,
        result_class,
        summary_json: payload.public_summary(),
    })
}

fn alert_event_from_row(row: &Row<'_>) -> rusqlite::Result<AlertEventRecord> {
    let detail_json: String = row.get(10)?;
    let detail_json = parse_json_column(&detail_json, 10)?;
    let payload = AlertDetailPayloadV1::from_value(&detail_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            10,
            Type::Text,
            Box::new(io::Error::new(io::ErrorKind::InvalidData, error)),
        )
    })?;
    Ok(AlertEventRecord {
        alert_id: row.get(0)?,
        dedupe_key: row.get(1)?,
        node_id: row.get(2)?,
        severity: row.get(3)?,
        state: row.get(4)?,
        reason_code: row.get(5)?,
        first_seen_at: row.get(6)?,
        last_seen_at: row.get(7)?,
        last_sent_at: row.get(8)?,
        resolved_at: row.get(9)?,
        detail_json: payload.public_detail(),
    })
}

fn audit_record_from_row(row: &Row<'_>) -> rusqlite::Result<AuditRecord> {
    let id = row.get(0)?;
    let ts: String = row.get(1)?;
    let actor: String = row.get(2)?;
    let event: String = row.get(3)?;
    let node_id: Option<String> = row.get(4)?;
    let endpoint_id: Option<String> = row.get(5)?;
    let method: Option<String> = row.get(6)?;
    let request_id: Option<String> = row.get(7)?;
    let params_hash: Option<String> = row.get(8)?;
    let ok: Option<i64> = row.get(9)?;
    let ok = ok.map(|value| i64_to_bool(value, 9)).transpose()?;
    let error_code: Option<String> = row.get(10)?;
    let duration_ms: Option<i64> = row.get(11)?;
    let duration_ms = duration_ms
        .map(|value| {
            u64::try_from(value).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(11, Type::Integer, Box::new(error))
            })
        })
        .transpose()?;
    let detail_json: String = row.get(12)?;
    let detail_json = parse_json_column(&detail_json, 12)?;
    let payload = AuditDetailPayloadV1::from_value(&detail_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            12,
            Type::Text,
            Box::new(io::Error::new(io::ErrorKind::InvalidData, error)),
        )
    })?;
    payload
        .validate_relationship(
            &ts,
            &actor,
            &event,
            node_id.as_deref(),
            endpoint_id.as_deref(),
            method.as_deref(),
            request_id.as_deref(),
            params_hash.as_deref(),
            ok,
            error_code.as_deref(),
            duration_ms,
        )
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                12,
                Type::Text,
                Box::new(io::Error::new(io::ErrorKind::InvalidData, error)),
            )
        })?;
    Ok(AuditRecord {
        id,
        ts,
        actor,
        event,
        node_id,
        endpoint_id,
        method,
        request_id,
        params_hash,
        ok,
        error_code,
        duration_ms,
        detail_json: payload.public_detail(),
    })
}

fn parse_json_column(value: &str, column: usize) -> rusqlite::Result<Value> {
    serde_json::from_str(value)
        .map_err(|err| rusqlite::Error::FromSqlConversionFailure(column, Type::Text, Box::new(err)))
}

fn i64_to_bool(value: i64, column: usize) -> rusqlite::Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            column,
            Type::Integer,
            format!("invalid bool integer: {value}").into(),
        )),
    }
}

fn i64_to_u64(value: i64, column: usize) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(column, Type::Integer, Box::new(err))
    })
}

fn u64_to_i64(value: u64, name: &'static str) -> rusqlite::Result<i64> {
    i64::try_from(value).map_err(|err| {
        rusqlite::Error::ToSqlConversionFailure(format!("{name} is too large: {err}").into())
    })
}
