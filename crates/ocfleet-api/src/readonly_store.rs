use std::fs;
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
    AlertEventRecord, AuditRecord, CURRENT_SCHEMA_VERSION, HealthHistoryRecord, HealthRollupRecord,
    HealthSnapshotRecord, NodeRecord, ObservabilityJobRecord, ObservabilityRunRecord,
    ProbeObservationRecord,
};
use ocfleet_cli::version_governance::{
    CapabilityNegotiationStatus, CapabilitySnapshot, VersionGovernanceInput,
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
    pub metadata: Option<Value>,
    pub maintenance: Option<Value>,
}

#[derive(Debug, Clone, Default)]
pub struct NodeListFilters<'a> {
    pub after_node_id: Option<&'a str>,
    pub region: Option<&'a str>,
    pub role: Option<&'a str>,
    pub environment: Option<&'a str>,
    pub label_key: Option<&'a str>,
    pub label_value: Option<&'a str>,
    pub status: Option<&'a str>,
}

pub struct HistoryPageFilters<'a> {
    pub after: Option<(&'a str, &'a str, &'a str)>,
    pub node_id: Option<&'a str>,
    pub status: Option<&'a str>,
    pub from: &'a str,
    pub to: &'a str,
}

pub struct AlertPageFilters<'a> {
    pub after: Option<(&'a str, &'a str)>,
    pub state: Option<&'a str>,
    pub severity: Option<&'a str>,
    pub node_id: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub from: &'a str,
    pub to: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerMetricsSnapshot {
    pub scheduler_jobs_due: u64,
    pub scheduler_claims_active: u64,
    pub scheduler_runs: [u64; 4],
    pub health_nodes: [u64; 4],
    pub alerts: [u64; 3],
    pub delivery_attempts: [u64; 2],
    pub delivery_queue: [u64; 5],
    pub rpc_calls: [u64; 2],
    pub rpc_duration_ms_sum: u64,
    pub rpc_duration_count: u64,
    pub observations_total: u64,
    pub observation_freshness_seconds: u64,
    pub sqlite_bytes: u64,
    pub audit_exports: [u64; 2],
    pub retention_deleted_rows: u64,
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
    fn list_node_health_page(
        &self,
        limit: u64,
        filters: &NodeListFilters<'_>,
    ) -> rusqlite::Result<Vec<NodeHealthRecord>> {
        let _ = (limit, filters);
        Err(rusqlite::Error::InvalidQuery)
    }
    fn fleet_health_summary(&self) -> rusqlite::Result<[u64; 6]> {
        Err(rusqlite::Error::InvalidQuery)
    }
    fn version_governance_inputs(
        &self,
        limit: u64,
    ) -> rusqlite::Result<Vec<VersionGovernanceInput>> {
        let _ = limit;
        Err(rusqlite::Error::InvalidQuery)
    }
    fn list_health_history_page(
        &self,
        limit: u64,
        filters: &HistoryPageFilters<'_>,
    ) -> rusqlite::Result<Vec<HealthHistoryRecord>> {
        let _ = (limit, filters);
        Err(rusqlite::Error::InvalidQuery)
    }
    fn list_alert_page(
        &self,
        limit: u64,
        filters: &AlertPageFilters<'_>,
    ) -> rusqlite::Result<Vec<AlertEventRecord>> {
        let _ = (limit, filters);
        Err(rusqlite::Error::InvalidQuery)
    }
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
    fn controller_metrics(&self, now: &str) -> rusqlite::Result<ControllerMetricsSnapshot>;
    fn health_slo_node_ids(
        &self,
        bucket_seconds: u64,
        from: &str,
        to: &str,
    ) -> rusqlite::Result<Vec<String>> {
        let _ = (bucket_seconds, from, to);
        Err(rusqlite::Error::InvalidQuery)
    }
    fn list_health_rollups(
        &self,
        node_id: &str,
        bucket_seconds: u64,
        from: &str,
        to: &str,
        limit: u64,
    ) -> rusqlite::Result<Vec<HealthRollupRecord>> {
        let _ = (node_id, bucket_seconds, from, to, limit);
        Err(rusqlite::Error::InvalidQuery)
    }
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
        let mut records = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        for record in &mut records {
            attach_node_advisory(&conn, record)?;
        }
        Ok(records)
    }

    pub fn get_node_health(&self, node_id: &str) -> rusqlite::Result<Option<NodeHealthRecord>> {
        let conn = self.open_conn()?;
        let mut record = conn
            .query_row(
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
            .optional()?;
        if let Some(record) = &mut record {
            attach_node_advisory(&conn, record)?;
        }
        Ok(record)
    }

    pub fn list_node_health_page(
        &self,
        limit: u64,
        filters: &NodeListFilters<'_>,
    ) -> rusqlite::Result<Vec<NodeHealthRecord>> {
        let limit = u64_to_i64(limit, "limit")?;
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT n.node_id, n.endpoint_id, n.name, n.region, n.role, n.enabled,
                    h.node_id, h.endpoint_id, h.computed_at, h.status, h.freshness_seconds,
                    h.last_success_at, h.last_failure_at, h.last_error_code,
                    h.degraded_methods_json, h.summary_json
             FROM nodes n
             LEFT JOIN health_snapshots h ON h.node_id = n.node_id
             LEFT JOIN node_metadata m ON m.node_id = n.node_id
             WHERE (?1 IS NULL OR n.node_id > ?1)
               AND (?2 IS NULL OR n.region = ?2)
               AND (?3 IS NULL OR n.role = ?3)
               AND (?4 IS NULL OR m.environment = ?4)
               AND (?5 IS NULL OR EXISTS (
                    SELECT 1 FROM json_each(m.labels_json) labels
                    WHERE labels.key = ?5 AND labels.type = 'text' AND labels.value = ?6
               ))
               AND (?7 IS NULL OR CASE
                    WHEN n.enabled = 0 THEN 'disabled'
                    ELSE COALESCE(h.status, 'unknown')
               END = ?7)
             ORDER BY n.node_id ASC
             LIMIT ?8",
        )?;
        let rows = stmt.query_map(
            params![
                filters.after_node_id,
                filters.region,
                filters.role,
                filters.environment,
                filters.label_key,
                filters.label_value,
                filters.status,
                limit,
            ],
            node_health_from_row,
        )?;
        let mut records = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        for record in &mut records {
            attach_node_advisory(&conn, record)?;
        }
        Ok(records)
    }

    pub fn fleet_health_summary(&self) -> rusqlite::Result<[u64; 6]> {
        let conn = self.open_conn()?;
        let mut counts = [0_u64; 6];
        let mut stmt = conn.prepare(
            "SELECT CASE WHEN n.enabled = 0 THEN 'disabled' ELSE COALESCE(h.status, 'unknown') END AS effective_status,
                    COUNT(*)
             FROM nodes n LEFT JOIN health_snapshots h ON h.node_id = n.node_id
             GROUP BY effective_status",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (status, count) = row?;
            let index = match status.as_str() {
                "healthy" => 0,
                "degraded" => 1,
                "unreachable" => 2,
                "stale" => 3,
                "disabled" => 4,
                _ => 5,
            };
            counts[index] = i64_to_u64(count, 1)?;
        }
        Ok(counts)
    }

    pub fn version_governance_inputs(
        &self,
        limit: u64,
    ) -> rusqlite::Result<Vec<VersionGovernanceInput>> {
        let limit = u64_to_i64(limit, "limit")?;
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT n.node_id, n.enabled, m.expected_agent_version,
                    c.node_id, c.endpoint_id, c.observed_at, c.status, c.agent_version,
                    c.protocol_min, c.protocol_max, c.ocserv_snapshot_min,
                    c.ocserv_snapshot_max, c.controlled_writes_compiled,
                    c.controlled_writes_locally_enabled
             FROM nodes n
             LEFT JOIN node_metadata m ON m.node_id = n.node_id
             LEFT JOIN node_capability_snapshots c ON c.node_id = n.node_id
             ORDER BY n.node_id
             LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], version_governance_input_from_row)?;
        rows.collect()
    }

    pub fn list_health_history_page(
        &self,
        limit: u64,
        filters: &HistoryPageFilters<'_>,
    ) -> rusqlite::Result<Vec<HealthHistoryRecord>> {
        let limit = u64_to_i64(limit, "limit")?;
        let conn = self.open_conn()?;
        let (after_ts, after_node, after_eval) = filters
            .after
            .map_or((None, None, None), |(a, b, c)| (Some(a), Some(b), Some(c)));
        let mut stmt=conn.prepare("SELECT evaluation_id,node_id,endpoint_id,computed_at,status,freshness_seconds,last_success_at,last_failure_at,last_error_code,degraded_methods_json,summary_json FROM health_history WHERE computed_at>=?1 AND computed_at<?2 AND (?3 IS NULL OR node_id=?3) AND (?4 IS NULL OR status=?4) AND (?5 IS NULL OR (computed_at,node_id,evaluation_id) < (?5,?6,?7)) ORDER BY computed_at DESC,node_id DESC,evaluation_id DESC LIMIT ?8")?;
        stmt.query_map(
            params![
                filters.from,
                filters.to,
                filters.node_id,
                filters.status,
                after_ts,
                after_node,
                after_eval,
                limit
            ],
            health_history_from_row_api,
        )?
        .collect()
    }

    pub fn list_alert_page(
        &self,
        limit: u64,
        filters: &AlertPageFilters<'_>,
    ) -> rusqlite::Result<Vec<AlertEventRecord>> {
        let limit = u64_to_i64(limit, "limit")?;
        let conn = self.open_conn()?;
        let (after_ts, after_id) = filters
            .after
            .map_or((None, None), |(a, b)| (Some(a), Some(b)));
        let mut stmt=conn.prepare("SELECT alert_id,dedupe_key,node_id,severity,state,reason_code,first_seen_at,last_seen_at,last_sent_at,resolved_at,detail_json FROM alert_events WHERE last_seen_at>=?1 AND last_seen_at<?2 AND (?3 IS NULL OR state=?3) AND (?4 IS NULL OR severity=?4) AND (?5 IS NULL OR node_id=?5) AND (?6 IS NULL OR reason_code=?6) AND (?7 IS NULL OR (last_seen_at,alert_id) < (?7,?8)) ORDER BY last_seen_at DESC,alert_id DESC LIMIT ?9")?;
        stmt.query_map(
            params![
                filters.from,
                filters.to,
                filters.state,
                filters.severity,
                filters.node_id,
                filters.reason,
                after_ts,
                after_id,
                limit
            ],
            alert_event_from_row,
        )?
        .collect()
    }

    pub fn health_slo_node_ids(
        &self,
        bucket_seconds: u64,
        from: &str,
        to: &str,
    ) -> rusqlite::Result<Vec<String>> {
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT DISTINCT node_id FROM health_rollups
             WHERE bucket_seconds = ?1 AND bucket_start >= ?2 AND bucket_start < ?3
             ORDER BY node_id LIMIT 1001",
        )?;
        let rows = stmt
            .query_map(
                params![u64_to_i64(bucket_seconds, "bucket_seconds")?, from, to],
                |row| row.get(0),
            )?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        if rows.len() > 1_000 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok(rows)
    }

    pub fn list_health_rollups(
        &self,
        node_id: &str,
        bucket_seconds: u64,
        from: &str,
        to: &str,
        limit: u64,
    ) -> rusqlite::Result<Vec<HealthRollupRecord>> {
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT node_id, bucket_seconds, bucket_start, bucket_end, input_watermark,
                    health_samples, covered_slots, expected_slots, healthy_count,
                    degraded_count, unreachable_count, stale_count, disabled_count,
                    unknown_count, observation_count, observation_error_count,
                    duration_sample_count, duration_p50_ms, duration_p95_ms,
                    cert_warning_count, cert_critical_count, fingerprint_sample_count,
                    fingerprint_change_count, computed_at
             FROM health_rollups
             WHERE node_id = ?1 AND bucket_seconds = ?2
               AND bucket_start >= ?3 AND bucket_start < ?4
             ORDER BY bucket_start LIMIT ?5",
        )?;
        stmt.query_map(
            params![
                node_id,
                u64_to_i64(bucket_seconds, "bucket_seconds")?,
                from,
                to,
                u64_to_i64(limit, "limit")?
            ],
            health_rollup_from_row,
        )?
        .collect()
    }

    pub fn controller_metrics(&self, now: &str) -> rusqlite::Result<ControllerMetricsSnapshot> {
        let conn = self.open_conn()?;
        let scheduler_jobs_due = count_where(
            &conn,
            "SELECT count(*) FROM observability_jobs WHERE enabled = 1 AND next_run_at <= ?1",
            now,
        )?;
        let scheduler_claims_active = count_where(
            &conn,
            "SELECT count(*) FROM scheduler_job_claims WHERE owner_id IS NOT NULL AND lease_expires_at > ?1",
            now,
        )?;
        let scheduler_runs = fixed_counts(
            &conn,
            "observability_runs",
            "status",
            &["running", "succeeded", "failed", "skipped"],
        )?;
        let health_nodes = fixed_counts(
            &conn,
            "health_snapshots",
            "status",
            &["healthy", "degraded", "unreachable", "unknown"],
        )?;
        let alerts = fixed_counts(
            &conn,
            "alert_events",
            "state",
            &["open", "silenced", "resolved"],
        )?;
        let delivery_attempts = fixed_counts(
            &conn,
            "alert_delivery_attempts",
            "status",
            &["succeeded", "failed"],
        )?;
        let delivery_queue = fixed_counts(
            &conn,
            "alert_delivery_queue",
            "status",
            &["pending", "claimed", "retry", "dead_letter", "succeeded"],
        )?;
        let rpc_calls = [
            count_rpc_outcome(&conn, true)?,
            count_rpc_outcome(&conn, false)?,
        ];
        let (rpc_duration_ms_sum, rpc_duration_count) = conn.query_row(
            "SELECT COALESCE(SUM(duration_ms), 0), count(duration_ms)
             FROM controller_audit_log WHERE event = 'rpc.completed'",
            [],
            |row| Ok((i64_to_u64(row.get(0)?, 0)?, i64_to_u64(row.get(1)?, 1)?)),
        )?;
        let observations_total = count_all(&conn, "probe_observations")?;
        let observation_freshness_seconds = conn.query_row(
            "SELECT COALESCE(MAX(0, CAST((julianday(?1) - julianday(MAX(observed_at))) * 86400 AS INTEGER)), 0)
             FROM probe_observations",
            [now],
            |row| i64_to_u64(row.get(0)?, 0),
        )?;
        let sqlite_bytes = fs::metadata(&self.database)
            .map(|metadata| metadata.len())
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        let audit_exports = [
            count_audit_event_outcome(&conn, "audit.export", true)?,
            count_audit_event_outcome(&conn, "audit.export", false)?,
        ];
        let retention_deleted_rows = conn.query_row(
            "SELECT COALESCE(SUM(CAST(json_extract(detail_json, '$.deleted_count') AS INTEGER)), 0)
             FROM controller_audit_log WHERE event = 'retention.apply' AND ok = 1",
            [],
            |row| i64_to_u64(row.get(0)?, 0),
        )?;
        Ok(ControllerMetricsSnapshot {
            scheduler_jobs_due,
            scheduler_claims_active,
            scheduler_runs,
            health_nodes,
            alerts,
            delivery_attempts,
            delivery_queue,
            rpc_calls,
            rpc_duration_ms_sum,
            rpc_duration_count,
            observations_total,
            observation_freshness_seconds,
            sqlite_bytes,
            audit_exports,
            retention_deleted_rows,
        })
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

    fn list_node_health_page(
        &self,
        limit: u64,
        filters: &NodeListFilters<'_>,
    ) -> rusqlite::Result<Vec<NodeHealthRecord>> {
        Self::list_node_health_page(self, limit, filters)
    }

    fn fleet_health_summary(&self) -> rusqlite::Result<[u64; 6]> {
        Self::fleet_health_summary(self)
    }
    fn version_governance_inputs(
        &self,
        limit: u64,
    ) -> rusqlite::Result<Vec<VersionGovernanceInput>> {
        Self::version_governance_inputs(self, limit)
    }
    fn list_health_history_page(
        &self,
        limit: u64,
        filters: &HistoryPageFilters<'_>,
    ) -> rusqlite::Result<Vec<HealthHistoryRecord>> {
        Self::list_health_history_page(self, limit, filters)
    }
    fn list_alert_page(
        &self,
        limit: u64,
        filters: &AlertPageFilters<'_>,
    ) -> rusqlite::Result<Vec<AlertEventRecord>> {
        Self::list_alert_page(self, limit, filters)
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

    fn controller_metrics(&self, now: &str) -> rusqlite::Result<ControllerMetricsSnapshot> {
        Self::controller_metrics(self, now)
    }

    fn health_slo_node_ids(
        &self,
        bucket_seconds: u64,
        from: &str,
        to: &str,
    ) -> rusqlite::Result<Vec<String>> {
        Self::health_slo_node_ids(self, bucket_seconds, from, to)
    }

    fn list_health_rollups(
        &self,
        node_id: &str,
        bucket_seconds: u64,
        from: &str,
        to: &str,
        limit: u64,
    ) -> rusqlite::Result<Vec<HealthRollupRecord>> {
        Self::list_health_rollups(self, node_id, bucket_seconds, from, to, limit)
    }
}

fn count_where(conn: &Connection, sql: &str, value: &str) -> rusqlite::Result<u64> {
    conn.query_row(sql, [value], |row| i64_to_u64(row.get(0)?, 0))
}

fn count_all(conn: &Connection, table: &str) -> rusqlite::Result<u64> {
    let sql = match table {
        "probe_observations" => "SELECT count(*) FROM probe_observations",
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    conn.query_row(sql, [], |row| i64_to_u64(row.get(0)?, 0))
}

fn fixed_counts<const N: usize>(
    conn: &Connection,
    table: &str,
    column: &str,
    values: &[&str; N],
) -> rusqlite::Result<[u64; N]> {
    let sql = match (table, column) {
        ("observability_runs", "status") => {
            "SELECT count(*) FROM observability_runs WHERE status = ?1"
        }
        ("health_snapshots", "status") => "SELECT count(*) FROM health_snapshots WHERE status = ?1",
        ("alert_events", "state") => "SELECT count(*) FROM alert_events WHERE state = ?1",
        ("alert_delivery_attempts", "status") => {
            "SELECT count(*) FROM alert_delivery_attempts WHERE status = ?1"
        }
        ("alert_delivery_queue", "status") => {
            "SELECT count(*) FROM alert_delivery_queue WHERE status = ?1"
        }
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let mut counts = [0_u64; N];
    for (index, value) in values.iter().enumerate() {
        counts[index] = count_where(conn, sql, value)?;
    }
    Ok(counts)
}

fn count_rpc_outcome(conn: &Connection, ok: bool) -> rusqlite::Result<u64> {
    conn.query_row(
        "SELECT count(*) FROM controller_audit_log WHERE event = 'rpc.completed' AND ok = ?1",
        [ok],
        |row| i64_to_u64(row.get(0)?, 0),
    )
}

fn count_audit_event_outcome(conn: &Connection, event: &str, ok: bool) -> rusqlite::Result<u64> {
    conn.query_row(
        "SELECT count(*) FROM controller_audit_log WHERE event = ?1 AND ok = ?2",
        params![event, ok],
        |row| i64_to_u64(row.get(0)?, 0),
    )
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

const REQUIRED_API_TABLES: [&str; 17] = [
    "schema_migrations",
    "nodes",
    "health_snapshots",
    "health_rollups",
    "observability_jobs",
    "observability_runs",
    "scheduler_job_claims",
    "scheduler_maintenance",
    "health_evaluation_runs",
    "alert_delivery_queue",
    "alert_delivery_attempts",
    "probe_observations",
    "alert_events",
    "controller_audit_log",
    "node_metadata",
    "node_maintenance_windows",
    "node_capability_snapshots",
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

fn health_rollup_from_row(row: &Row<'_>) -> rusqlite::Result<HealthRollupRecord> {
    let value = |index| i64_to_u64(row.get(index)?, index);
    let optional = |index| {
        row.get::<_, Option<i64>>(index)?
            .map(|value| i64_to_u64(value, index))
            .transpose()
    };
    Ok(HealthRollupRecord {
        node_id: row.get(0)?,
        bucket_seconds: value(1)?,
        bucket_start: row.get(2)?,
        bucket_end: row.get(3)?,
        input_watermark: row.get(4)?,
        health_samples: value(5)?,
        covered_slots: value(6)?,
        expected_slots: value(7)?,
        healthy_count: value(8)?,
        degraded_count: value(9)?,
        unreachable_count: value(10)?,
        stale_count: value(11)?,
        disabled_count: value(12)?,
        unknown_count: value(13)?,
        observation_count: value(14)?,
        observation_error_count: value(15)?,
        duration_sample_count: value(16)?,
        duration_p50_ms: optional(17)?,
        duration_p95_ms: optional(18)?,
        cert_warning_count: value(19)?,
        cert_critical_count: value(20)?,
        fingerprint_sample_count: value(21)?,
        fingerprint_change_count: value(22)?,
        computed_at: row.get(23)?,
    })
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
    Ok(NodeHealthRecord {
        node,
        snapshot,
        metadata: None,
        maintenance: None,
    })
}

fn health_history_from_row_api(row: &Row<'_>) -> rusqlite::Result<HealthHistoryRecord> {
    let freshness: Option<i64> = row.get(5)?;
    let degraded_text: String = row.get(9)?;
    let summary_text: String = row.get(10)?;
    let degraded = parse_json_column(&degraded_text, 9)?;
    HealthDegradedMethodsPayloadV1::from_value(&degraded).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            9,
            Type::Text,
            Box::new(io::Error::new(io::ErrorKind::InvalidData, e)),
        )
    })?;
    let summary = parse_json_column(&summary_text, 10)?;
    let typed = HealthSummaryPayloadV1::from_value(&summary).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            10,
            Type::Text,
            Box::new(io::Error::new(io::ErrorKind::InvalidData, e)),
        )
    })?;
    let status: String = row.get(4)?;
    validate_health_payload_relationship(&status, &typed).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            10,
            Type::Text,
            Box::new(io::Error::new(io::ErrorKind::InvalidData, e)),
        )
    })?;
    Ok(HealthHistoryRecord {
        evaluation_id: row.get(0)?,
        snapshot: HealthSnapshotRecord {
            node_id: row.get(1)?,
            endpoint_id: row.get(2)?,
            computed_at: row.get(3)?,
            status,
            freshness_seconds: freshness.map(|v| i64_to_u64(v, 5)).transpose()?,
            last_success_at: row.get(6)?,
            last_failure_at: row.get(7)?,
            last_error_code: row.get(8)?,
            degraded_methods_json: degraded,
            summary_json: summary,
        },
    })
}

fn attach_node_advisory(conn: &Connection, record: &mut NodeHealthRecord) -> rusqlite::Result<()> {
    record.metadata = conn.query_row(
        "SELECT environment, site, owner_team, service_tier, labels_json, expected_agent_version, updated_at FROM node_metadata WHERE node_id=?1",
        [&record.node.node_id],
        |row| {
            let labels: String = row.get(4)?;
            let labels: Value = serde_json::from_str(&labels).map_err(|error| rusqlite::Error::FromSqlConversionFailure(4, Type::Text, Box::new(error)))?;
            Ok(serde_json::json!({"environment":row.get::<_,String>(0)?,"site":row.get::<_,String>(1)?,"owner_team":row.get::<_,String>(2)?,"service_tier":row.get::<_,String>(3)?,"labels":labels,"expected_agent_version":row.get::<_,Option<String>>(5)?,"updated_at":row.get::<_,String>(6)?}))
        },
    ).optional()?;
    record.maintenance = conn.query_row(
        "SELECT starts_at, ends_at, reason, updated_at FROM node_maintenance_windows WHERE node_id=?1",
        [&record.node.node_id],
        |row| Ok(serde_json::json!({"from":row.get::<_,String>(0)?,"to":row.get::<_,String>(1)?,"reason":row.get::<_,String>(2)?,"updated_at":row.get::<_,String>(3)?})),
    ).optional()?;
    Ok(())
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

fn version_governance_input_from_row(row: &Row<'_>) -> rusqlite::Result<VersionGovernanceInput> {
    let capability = if row.get::<_, Option<String>>(3)?.is_some() {
        let status: String = row.get(6)?;
        let status = match status.as_str() {
            "compatible" => CapabilityNegotiationStatus::Compatible,
            "incompatible_protocol" => CapabilityNegotiationStatus::IncompatibleProtocol,
            "unsupported_capability" => CapabilityNegotiationStatus::UnsupportedCapability,
            "legacy_unsupported" => CapabilityNegotiationStatus::LegacyUnsupported,
            "invalid_response" => CapabilityNegotiationStatus::InvalidResponse,
            _ => return Err(invalid_data(6, "invalid capability negotiation status")),
        };
        let capability = CapabilitySnapshot {
            node_id: row.get(3)?,
            endpoint_id: row.get(4)?,
            observed_at: row.get(5)?,
            status,
            agent_version: row.get(7)?,
            protocol_min: optional_u32(row, 8)?,
            protocol_max: optional_u32(row, 9)?,
            ocserv_snapshot_min: optional_u32(row, 10)?,
            ocserv_snapshot_max: optional_u32(row, 11)?,
            controlled_writes_compiled: optional_bool(row, 12)?,
            controlled_writes_locally_enabled: optional_bool(row, 13)?,
        };
        capability
            .validate()
            .map_err(|error| invalid_data(3, &error))?;
        Some(capability)
    } else {
        None
    };
    Ok(VersionGovernanceInput {
        node_id: row.get(0)?,
        enabled: i64_to_bool(row.get(1)?, 1)?,
        expected_agent_version: row.get(2)?,
        capability,
    })
}

fn optional_u32(row: &Row<'_>, column: usize) -> rusqlite::Result<Option<u32>> {
    row.get::<_, Option<i64>>(column)?
        .map(|value| {
            u32::try_from(value).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(column, Type::Integer, Box::new(error))
            })
        })
        .transpose()
}

fn optional_bool(row: &Row<'_>, column: usize) -> rusqlite::Result<Option<bool>> {
    row.get::<_, Option<i64>>(column)?
        .map(|value| i64_to_bool(value, column))
        .transpose()
}

fn invalid_data(column: usize, message: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        Type::Text,
        Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            message.to_string(),
        )),
    )
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
