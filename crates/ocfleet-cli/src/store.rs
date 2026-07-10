use ocfleet_protocol::enrollment::{
    EndpointStatus, EnrollmentTokenStatus, JoinRequestStatus, TrustBundle,
};
use ocfleet_protocol::method::{PROBE_CONTROLLER_PING, PROBE_PATH_ECHO};
use rusqlite::{Connection, OptionalExtension, Transaction, params, types::Type};
use serde_json::Value;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::audit::AuditEvent;
use crate::input_validation::{
    validate_actor, validate_agent_fingerprint, validate_agent_public_key, validate_agent_version,
    validate_description, validate_endpoint_id, validate_hostname, validate_label_json,
    validate_reason,
};
use crate::migrations;
use crate::private_file::{self, PrivateFileError};

pub const CURRENT_SCHEMA_VERSION: i64 = 8;
pub const DEFAULT_HEALTH_STALE_WINDOW_SECONDS: u64 = 24 * 60 * 60;
pub const DEFAULT_HEALTH_UNREACHABLE_FAILURES: u64 = 3;
pub const DEFAULT_HEALTH_CERT_WARNING_DAYS: u64 = 30;
pub const DEFAULT_HEALTH_CERT_CRITICAL_DAYS: u64 = 7;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("controller state file permissions are unsafe")]
    UnsafePermissions,
    #[error(
        "unsupported future controller database schema {found}; this binary supports up to {supported}"
    )]
    UnsupportedFutureSchema { found: i64, supported: i64 },
    #[error("database migration backup failed: {0}")]
    MigrationBackup(String),
    #[error("database integrity check failed ({check}): {detail}")]
    DatabaseIntegrityCheckFailed { check: &'static str, detail: String },
    #[error("node not found: {0}")]
    NodeNotFound(String),
    #[error("enrollment rejected: {0}")]
    EnrollmentRejected(String),
    #[error("join request not found: {0}")]
    JoinRequestNotFound(String),
    #[error("join request {request_id} is {status}, expected pending")]
    InvalidJoinRequestStatus { request_id: String, status: String },
    #[error("endpoint not found: {0}")]
    EndpointNotFound(String),
    #[error("endpoint already exists: {0}")]
    EndpointAlreadyExists(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInsert {
    pub node_id: String,
    pub endpoint_id: String,
    pub name: String,
    pub region: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecord {
    pub node_id: String,
    pub endpoint_id: String,
    pub name: String,
    pub region: String,
    pub role: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeHistoryRecord {
    pub ts: String,
    pub node_id: Option<String>,
    pub endpoint_id: Option<String>,
    pub method: String,
    pub request_id: Option<String>,
    pub ok: Option<bool>,
    pub error_code: Option<String>,
    pub duration_ms: Option<u64>,
    pub detail_json: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservabilityJobRecord {
    pub job_id: String,
    pub kind: String,
    pub selector_json: Value,
    pub pair_selector_json: Option<Value>,
    pub interval_seconds: u64,
    pub jitter_seconds: u64,
    pub timeout_ms: u64,
    pub enabled: bool,
    pub next_run_at: Option<String>,
    pub last_run_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidObservabilityJobRecord {
    pub job_id: String,
    pub kind: String,
    pub enabled: bool,
    pub next_run_at: Option<String>,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservabilityJobLoadResult {
    Valid(ObservabilityJobRecord),
    Invalid(InvalidObservabilityJobRecord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservabilityRunInsert {
    pub run_id: String,
    pub job_id: Option<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub status: String,
    pub triggered_by: String,
    pub summary_json: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservabilityRunRecord {
    pub run_id: String,
    pub job_id: Option<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub status: String,
    pub triggered_by: String,
    pub summary_json: Value,
    pub observation_count: u64,
    pub failed_observation_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeObservationInsert {
    pub observation_id: String,
    pub run_id: Option<String>,
    pub node_id: Option<String>,
    pub endpoint_id: Option<String>,
    pub method: String,
    pub ok: Option<bool>,
    pub error_code: Option<String>,
    pub duration_ms: Option<u64>,
    pub observed_at: String,
    pub expires_at: Option<String>,
    pub result_class: String,
    pub summary_json: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeObservationRecord {
    pub observation_id: String,
    pub run_id: Option<String>,
    pub node_id: Option<String>,
    pub endpoint_id: Option<String>,
    pub method: String,
    pub ok: Option<bool>,
    pub error_code: Option<String>,
    pub duration_ms: Option<u64>,
    pub observed_at: String,
    pub expires_at: Option<String>,
    pub result_class: String,
    pub summary_json: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthSnapshotRecord {
    pub node_id: String,
    pub endpoint_id: Option<String>,
    pub computed_at: String,
    pub status: String,
    pub freshness_seconds: Option<u64>,
    pub last_success_at: Option<String>,
    pub last_failure_at: Option<String>,
    pub last_error_code: Option<String>,
    pub degraded_methods_json: Value,
    pub summary_json: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertEventRecord {
    pub alert_id: String,
    pub dedupe_key: String,
    pub node_id: Option<String>,
    pub severity: String,
    pub state: String,
    pub reason_code: String,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub last_sent_at: Option<String>,
    pub resolved_at: Option<String>,
    pub detail_json: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertWebhookHookRecord {
    pub hook_id: String,
    pub name: String,
    pub hook_type: String,
    pub endpoint_url: String,
    pub endpoint_url_redacted: String,
    pub endpoint_host: String,
    pub host_allow: Vec<String>,
    pub hmac_key_id: String,
    pub enabled: bool,
    pub max_attempts: u64,
    pub timeout_ms: u64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertDeliveryAttemptRecord {
    pub attempt_id: String,
    pub alert_id: String,
    pub hook_id: String,
    pub attempt_no: u64,
    pub attempted_at: String,
    pub status: String,
    pub http_status_class: Option<String>,
    pub error_code: Option<String>,
    pub bytes_sent: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPolicyRecord {
    pub scope: String,
    pub max_age_days: Option<u64>,
    pub max_rows: Option<u64>,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionCandidateReport {
    pub matched_count: u64,
    pub oldest_timestamp: Option<String>,
    pub newest_timestamp: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub id: i64,
    pub ts: String,
    pub actor: String,
    pub event: String,
    pub node_id: Option<String>,
    pub endpoint_id: Option<String>,
    pub method: Option<String>,
    pub request_id: Option<String>,
    pub params_hash: Option<String>,
    pub ok: Option<bool>,
    pub error_code: Option<String>,
    pub duration_ms: Option<u64>,
    pub detail_json: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthPolicyRecord {
    pub stale_window_seconds: u64,
    pub unreachable_consecutive_failures: u64,
    pub cert_warning_days: u64,
    pub cert_critical_days: u64,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct EnrollmentTokenInsert {
    pub token_id: String,
    pub token_hash: String,
    pub created_by: String,
    pub expires_at: String,
    pub max_uses: u32,
    pub description: Option<String>,
    pub labels_json: Value,
    pub scope_json: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentTokenRecord {
    pub token_id: String,
    pub token_hash: String,
    pub created_at: String,
    pub created_by: String,
    pub expires_at: String,
    pub max_uses: u32,
    pub used_count: u32,
    pub status: EnrollmentTokenStatus,
    pub description: Option<String>,
    pub labels_json: Value,
    pub scope_json: Value,
}

#[derive(Debug, Clone)]
pub struct JoinRequestInsert {
    pub token_plaintext: String,
    pub agent_public_key: String,
    pub fingerprint: String,
    pub requested_endpoint_id: Option<String>,
    pub hostname: String,
    pub agent_version: String,
    pub requested_labels_json: Value,
}

#[derive(Debug, Clone)]
pub struct ApprovalInput {
    pub request_id: String,
    pub endpoint_id: String,
    pub approved_by: String,
    pub reason: String,
    pub approved_labels_json: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequestRecord {
    pub request_id: String,
    pub token_id: String,
    pub status: JoinRequestStatus,
    pub agent_public_key: String,
    pub fingerprint: String,
    pub requested_endpoint_id: Option<String>,
    pub assigned_endpoint_id: Option<String>,
    pub hostname: String,
    pub agent_version: String,
    pub requested_labels_json: Value,
    pub approved_labels_json: Value,
    pub created_at: String,
    pub approved_at: Option<String>,
    pub approved_by: Option<String>,
    pub rejection_reason: Option<String>,
    pub audit_correlation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointTrustRecord {
    pub endpoint_id: String,
    pub node_id: Option<String>,
    pub fingerprint: Option<String>,
    pub status: EndpointStatus,
    pub generation: u64,
    pub previous_endpoint_id: Option<String>,
    pub rotated_to: Option<String>,
    pub trust_bundle_json: Value,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustSnapshot {
    pub endpoints: Vec<EndpointTrustRecord>,
}

pub struct Store {
    conn: Connection,
}

pub struct StoreOpenResult {
    pub store: Store,
    pub created_database: bool,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let created_database = create_database_file_if_missing(path)?;
        Self::open_existing_or_create(path, created_database)
    }

    pub fn open_with_status(path: &Path) -> Result<StoreOpenResult, StoreError> {
        let created_database = create_database_file_if_missing(path)?;
        let store = Self::open_existing_or_create(path, created_database)?;
        Ok(StoreOpenResult {
            store,
            created_database,
        })
    }

    fn open_existing_or_create(path: &Path, created_database: bool) -> Result<Self, StoreError> {
        validate_database_files(path)?;
        let mut conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", 5_000)?;

        migrations::migrate_to_current(&mut conn, path, created_database)?;
        validate_database_files(path)?;
        Ok(Self { conn })
    }

    pub fn current_schema_version(&self) -> Result<i64, StoreError> {
        migrations::read_schema_version(&self.conn)
    }

    pub fn add_node(&self, node: &NodeInsert, actor: &str) -> Result<(), StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO nodes (node_id, endpoint_id, name, region, role, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
            params![
                node.node_id.as_str(),
                node.endpoint_id.as_str(),
                node.name.as_str(),
                node.region.as_str(),
                node.role.as_str()
            ],
        )?;
        insert_endpoint_trust_tx(
            &tx,
            &EndpointTrustRecord {
                endpoint_id: node.endpoint_id.clone(),
                node_id: Some(node.node_id.clone()),
                fingerprint: None,
                status: EndpointStatus::Active,
                generation: 1,
                previous_endpoint_id: None,
                rotated_to: None,
                trust_bundle_json: trust_bundle_json(&node.endpoint_id, 1, EndpointStatus::Active),
                created_at: String::new(),
                updated_at: String::new(),
            },
        )?;
        let after = get_node_tx(&tx, &node.node_id)?
            .ok_or_else(|| StoreError::NodeNotFound(node.node_id.clone()))?;
        let mut event = AuditEvent::new(actor, "node.add");
        event.node_id = Some(after.node_id.clone());
        event.endpoint_id = Some(after.endpoint_id.clone());
        event.ok = Some(true);
        event.detail_json = json_detail(
            "node",
            &after.node_id,
            None,
            Some(node_audit_json(&after)),
            None,
        );
        insert_audit_tx(&tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_node(&self, node_id: &str) -> Result<Option<NodeRecord>, StoreError> {
        self.conn
            .query_row(
                "SELECT node_id, endpoint_id, name, region, role, enabled FROM nodes WHERE node_id = ?1",
                [node_id],
                node_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn list_nodes(&self) -> Result<Vec<NodeRecord>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT node_id, endpoint_id, name, region, role, enabled FROM nodes ORDER BY node_id",
        )?;
        let rows = stmt.query_map([], node_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn list_nodes_limited(&self, limit: u64) -> Result<Vec<NodeRecord>, StoreError> {
        let limit = u64_to_i64(limit)?;
        let mut stmt = self.conn.prepare(
            "SELECT node_id, endpoint_id, name, region, role, enabled
             FROM nodes ORDER BY node_id LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], node_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn list_probe_history(
        &self,
        node_filter: Option<&str>,
    ) -> Result<Vec<ProbeHistoryRecord>, StoreError> {
        self.list_probe_history_with_options(node_filter, None, 50)
    }

    pub fn list_probe_history_with_options(
        &self,
        node_filter: Option<&str>,
        since: Option<&str>,
        limit: u64,
    ) -> Result<Vec<ProbeHistoryRecord>, StoreError> {
        let limit = u64_to_i64(limit)?;
        if let Some(node_id) = node_filter {
            if let Some(since) = since {
                let mut stmt = self.conn.prepare(
                    "SELECT ts, node_id, endpoint_id, method, request_id, ok, error_code, duration_ms, detail_json
                     FROM controller_audit_log
                     WHERE method IN (?1, ?2) AND node_id = ?3 AND ts >= ?4
                     ORDER BY id DESC
                     LIMIT ?5",
                )?;
                let rows = stmt.query_map(
                    params![
                        PROBE_CONTROLLER_PING,
                        PROBE_PATH_ECHO,
                        node_id,
                        since,
                        limit
                    ],
                    probe_history_from_row,
                )?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(StoreError::from)
            } else {
                let mut stmt = self.conn.prepare(
                    "SELECT ts, node_id, endpoint_id, method, request_id, ok, error_code, duration_ms, detail_json
                     FROM controller_audit_log
                     WHERE method IN (?1, ?2) AND node_id = ?3
                     ORDER BY id DESC
                     LIMIT ?4",
                )?;
                let rows = stmt.query_map(
                    params![PROBE_CONTROLLER_PING, PROBE_PATH_ECHO, node_id, limit],
                    probe_history_from_row,
                )?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(StoreError::from)
            }
        } else if let Some(since) = since {
            let mut stmt = self.conn.prepare(
                "SELECT ts, node_id, endpoint_id, method, request_id, ok, error_code, duration_ms, detail_json
                 FROM controller_audit_log
                 WHERE method IN (?1, ?2) AND ts >= ?3
                 ORDER BY id DESC
                 LIMIT ?4",
            )?;
            let rows = stmt.query_map(
                params![PROBE_CONTROLLER_PING, PROBE_PATH_ECHO, since, limit],
                probe_history_from_row,
            )?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(StoreError::from)
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT ts, node_id, endpoint_id, method, request_id, ok, error_code, duration_ms, detail_json
                 FROM controller_audit_log
                 WHERE method IN (?1, ?2)
                 ORDER BY id DESC
                 LIMIT ?3",
            )?;
            let rows = stmt.query_map(
                params![PROBE_CONTROLLER_PING, PROBE_PATH_ECHO, limit],
                probe_history_from_row,
            )?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(StoreError::from)
        }
    }

    pub fn insert_observability_job(&self, job: &ObservabilityJobRecord) -> Result<(), StoreError> {
        validate_low_sensitive_json(&job.selector_json, "observability job selector")?;
        if let Some(pair) = &job.pair_selector_json {
            validate_low_sensitive_json(pair, "observability job pair selector")?;
        }
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO observability_jobs
             (job_id, kind, selector_json, pair_selector_json, interval_seconds, jitter_seconds, timeout_ms, enabled, next_run_at, last_run_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                job.job_id.as_str(),
                job.kind.as_str(),
                compact_json(&job.selector_json),
                job.pair_selector_json.as_ref().map(compact_json),
                u64_to_i64(job.interval_seconds)?,
                u64_to_i64(job.jitter_seconds)?,
                u64_to_i64(job.timeout_ms)?,
                bool_to_i64(job.enabled),
                job.next_run_at.as_deref(),
                job.last_run_at.as_deref(),
                job.created_at.as_str(),
                job.updated_at.as_str(),
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_observability_jobs(&self) -> Result<Vec<ObservabilityJobRecord>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT job_id, kind, selector_json, pair_selector_json, interval_seconds, jitter_seconds, timeout_ms, enabled, next_run_at, last_run_at, created_at, updated_at
             FROM observability_jobs
             ORDER BY job_id",
        )?;
        let rows = stmt.query_map([], observability_job_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn list_observability_jobs_limited(
        &self,
        limit: u64,
    ) -> Result<Vec<ObservabilityJobRecord>, StoreError> {
        let limit = u64_to_i64(limit)?;
        let mut stmt = self.conn.prepare(
            "SELECT job_id, kind, selector_json, pair_selector_json, interval_seconds, jitter_seconds, timeout_ms, enabled, next_run_at, last_run_at, created_at, updated_at
             FROM observability_jobs
             ORDER BY job_id
             LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], observability_job_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn get_observability_job(
        &self,
        job_id: &str,
    ) -> Result<Option<ObservabilityJobRecord>, StoreError> {
        self.conn
            .query_row(
                "SELECT job_id, kind, selector_json, pair_selector_json, interval_seconds, jitter_seconds, timeout_ms, enabled, next_run_at, last_run_at, created_at, updated_at
                 FROM observability_jobs
                 WHERE job_id = ?1",
                [job_id],
                observability_job_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn list_observability_jobs_tolerant(
        &self,
    ) -> Result<Vec<ObservabilityJobLoadResult>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT job_id, kind, selector_json, pair_selector_json, interval_seconds, jitter_seconds, timeout_ms, enabled, next_run_at, last_run_at, created_at, updated_at
             FROM observability_jobs
             ORDER BY job_id",
        )?;
        let rows = stmt.query_map([], raw_observability_job_from_row)?;
        let jobs = rows
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(observability_job_load_from_raw)
            .collect::<Vec<_>>();
        Ok(jobs)
    }

    pub fn get_observability_job_tolerant(
        &self,
        job_id: &str,
    ) -> Result<Option<ObservabilityJobLoadResult>, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT job_id, kind, selector_json, pair_selector_json, interval_seconds, jitter_seconds, timeout_ms, enabled, next_run_at, last_run_at, created_at, updated_at
                 FROM observability_jobs
                 WHERE job_id = ?1",
                [job_id],
                raw_observability_job_from_row,
            )
            .optional()?;
        Ok(row.map(observability_job_load_from_raw))
    }

    pub fn set_observability_job_enabled(
        &self,
        job_id: &str,
        enabled: bool,
    ) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE observability_jobs
             SET enabled = ?1,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
             WHERE job_id = ?2",
            params![bool_to_i64(enabled), job_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn update_observability_job_run_times(
        &self,
        job_id: &str,
        next_run_at: Option<&str>,
        last_run_at: Option<&str>,
    ) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE observability_jobs
             SET next_run_at = ?1,
                 last_run_at = ?2,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
             WHERE job_id = ?3",
            params![next_run_at, last_run_at, job_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn insert_observability_run(&self, run: &ObservabilityRunInsert) -> Result<(), StoreError> {
        validate_low_sensitive_json(&run.summary_json, "observability run summary")?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO observability_runs
             (run_id, job_id, started_at, finished_at, status, triggered_by, summary_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                run.run_id.as_str(),
                run.job_id.as_deref(),
                run.started_at.as_str(),
                run.finished_at.as_deref(),
                run.status.as_str(),
                run.triggered_by.as_str(),
                compact_json(&run.summary_json),
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn finish_observability_run(
        &self,
        run_id: &str,
        finished_at: &str,
        status: &str,
        summary_json: &Value,
    ) -> Result<(), StoreError> {
        validate_low_sensitive_json(summary_json, "observability run summary")?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE observability_runs
             SET finished_at = ?1,
                 status = ?2,
                 summary_json = ?3
             WHERE run_id = ?4",
            params![finished_at, status, compact_json(summary_json), run_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_observability_runs(
        &self,
        limit: u64,
    ) -> Result<Vec<ObservabilityRunRecord>, StoreError> {
        let limit = u64_to_i64(limit)?;
        let mut stmt = self.conn.prepare(
            "SELECT r.run_id, r.job_id, r.started_at, r.finished_at, r.status, r.triggered_by, r.summary_json,
                    COUNT(o.observation_id) AS observation_count,
                    COALESCE(SUM(CASE WHEN o.ok = 0 THEN 1 ELSE 0 END), 0) AS failed_observation_count
             FROM observability_runs r
             LEFT JOIN probe_observations o ON o.run_id = r.run_id
             GROUP BY r.run_id, r.job_id, r.started_at, r.finished_at, r.status, r.triggered_by, r.summary_json
             ORDER BY r.started_at DESC, r.run_id DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], observability_run_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn get_observability_run(
        &self,
        run_id: &str,
    ) -> Result<Option<ObservabilityRunRecord>, StoreError> {
        self.conn
            .query_row(
                "SELECT r.run_id, r.job_id, r.started_at, r.finished_at, r.status, r.triggered_by, r.summary_json,
                        COUNT(o.observation_id) AS observation_count,
                        COALESCE(SUM(CASE WHEN o.ok = 0 THEN 1 ELSE 0 END), 0) AS failed_observation_count
                 FROM observability_runs r
                 LEFT JOIN probe_observations o ON o.run_id = r.run_id
                 WHERE r.run_id = ?1
                 GROUP BY r.run_id, r.job_id, r.started_at, r.finished_at, r.status, r.triggered_by, r.summary_json",
                [run_id],
                observability_run_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn insert_probe_observation(
        &self,
        observation: &ProbeObservationInsert,
    ) -> Result<(), StoreError> {
        validate_low_sensitive_json(&observation.summary_json, "observation summary")?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO probe_observations
             (observation_id, run_id, node_id, endpoint_id, method, ok, error_code, duration_ms, observed_at, expires_at, result_class, summary_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                observation.observation_id.as_str(),
                observation.run_id.as_deref(),
                observation.node_id.as_deref(),
                observation.endpoint_id.as_deref(),
                observation.method.as_str(),
                observation.ok.map(bool_to_i64),
                observation.error_code.as_deref(),
                option_u64_to_i64(observation.duration_ms)?,
                observation.observed_at.as_str(),
                observation.expires_at.as_deref(),
                observation.result_class.as_str(),
                compact_json(&observation.summary_json),
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_probe_observations(
        &self,
        node_filter: Option<&str>,
        limit: u64,
    ) -> Result<Vec<ProbeObservationRecord>, StoreError> {
        self.list_probe_observations_since(node_filter, None, limit)
    }

    pub fn list_probe_observations_since(
        &self,
        node_filter: Option<&str>,
        since: Option<&str>,
        limit: u64,
    ) -> Result<Vec<ProbeObservationRecord>, StoreError> {
        let limit = u64_to_i64(limit)?;
        if let Some(node_id) = node_filter {
            if let Some(since) = since {
                let mut stmt = self.conn.prepare(
                    "SELECT observation_id, run_id, node_id, endpoint_id, method, ok, error_code, duration_ms, observed_at, expires_at, result_class, summary_json
                     FROM probe_observations
                     WHERE node_id = ?1 AND observed_at >= ?2
                     ORDER BY observed_at DESC, observation_id DESC
                     LIMIT ?3",
                )?;
                let rows =
                    stmt.query_map(params![node_id, since, limit], probe_observation_from_row)?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(StoreError::from)
            } else {
                let mut stmt = self.conn.prepare(
                    "SELECT observation_id, run_id, node_id, endpoint_id, method, ok, error_code, duration_ms, observed_at, expires_at, result_class, summary_json
                     FROM probe_observations
                     WHERE node_id = ?1
                     ORDER BY observed_at DESC, observation_id DESC
                     LIMIT ?2",
                )?;
                let rows = stmt.query_map(params![node_id, limit], probe_observation_from_row)?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(StoreError::from)
            }
        } else if let Some(since) = since {
            let mut stmt = self.conn.prepare(
                "SELECT observation_id, run_id, node_id, endpoint_id, method, ok, error_code, duration_ms, observed_at, expires_at, result_class, summary_json
                 FROM probe_observations
                 WHERE observed_at >= ?1
                 ORDER BY observed_at DESC, observation_id DESC
                 LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![since, limit], probe_observation_from_row)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(StoreError::from)
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT observation_id, run_id, node_id, endpoint_id, method, ok, error_code, duration_ms, observed_at, expires_at, result_class, summary_json
                 FROM probe_observations
                 ORDER BY observed_at DESC, observation_id DESC
                 LIMIT ?1",
            )?;
            let rows = stmt.query_map([limit], probe_observation_from_row)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(StoreError::from)
        }
    }

    pub fn list_probe_observations_filtered(
        &self,
        node_filter: Option<&str>,
        method_filter: Option<&str>,
        limit: u64,
    ) -> Result<Vec<ProbeObservationRecord>, StoreError> {
        let limit = u64_to_i64(limit)?;
        let mut stmt = self.conn.prepare(
            "SELECT observation_id, run_id, node_id, endpoint_id, method, ok, error_code, duration_ms, observed_at, expires_at, result_class, summary_json
             FROM probe_observations
             WHERE (?1 IS NULL OR node_id = ?1)
               AND (?2 IS NULL OR method = ?2)
             ORDER BY observed_at DESC, observation_id DESC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            params![node_filter, method_filter, limit],
            probe_observation_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn get_probe_observation(
        &self,
        observation_id: &str,
    ) -> Result<Option<ProbeObservationRecord>, StoreError> {
        self.conn
            .query_row(
                "SELECT observation_id, run_id, node_id, endpoint_id, method, ok, error_code, duration_ms, observed_at, expires_at, result_class, summary_json
                 FROM probe_observations
                 WHERE observation_id = ?1",
                [observation_id],
                probe_observation_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn upsert_health_snapshot(
        &self,
        snapshot: &HealthSnapshotRecord,
    ) -> Result<(), StoreError> {
        validate_low_sensitive_json(&snapshot.degraded_methods_json, "health degraded methods")?;
        validate_low_sensitive_json(&snapshot.summary_json, "health summary")?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO health_snapshots
             (node_id, endpoint_id, computed_at, status, freshness_seconds, last_success_at, last_failure_at, last_error_code, degraded_methods_json, summary_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(node_id) DO UPDATE SET
               endpoint_id = excluded.endpoint_id,
               computed_at = excluded.computed_at,
               status = excluded.status,
               freshness_seconds = excluded.freshness_seconds,
               last_success_at = excluded.last_success_at,
               last_failure_at = excluded.last_failure_at,
               last_error_code = excluded.last_error_code,
               degraded_methods_json = excluded.degraded_methods_json,
               summary_json = excluded.summary_json",
            params![
                snapshot.node_id.as_str(),
                snapshot.endpoint_id.as_deref(),
                snapshot.computed_at.as_str(),
                snapshot.status.as_str(),
                option_u64_to_i64(snapshot.freshness_seconds)?,
                snapshot.last_success_at.as_deref(),
                snapshot.last_failure_at.as_deref(),
                snapshot.last_error_code.as_deref(),
                compact_json(&snapshot.degraded_methods_json),
                compact_json(&snapshot.summary_json),
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_health_snapshots(&self) -> Result<Vec<HealthSnapshotRecord>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT node_id, endpoint_id, computed_at, status, freshness_seconds, last_success_at, last_failure_at, last_error_code, degraded_methods_json, summary_json
             FROM health_snapshots
             ORDER BY node_id",
        )?;
        let rows = stmt.query_map([], health_snapshot_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn list_health_snapshots_limited(
        &self,
        limit: u64,
    ) -> Result<Vec<HealthSnapshotRecord>, StoreError> {
        let limit = u64_to_i64(limit)?;
        let mut stmt = self.conn.prepare(
            "SELECT node_id, endpoint_id, computed_at, status, freshness_seconds, last_success_at, last_failure_at, last_error_code, degraded_methods_json, summary_json
             FROM health_snapshots
             ORDER BY computed_at DESC, node_id
             LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], health_snapshot_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn upsert_alert_event(&self, alert: &AlertEventRecord) -> Result<(), StoreError> {
        validate_low_sensitive_json(&alert.detail_json, "alert detail")?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO alert_events
             (alert_id, dedupe_key, node_id, severity, state, reason_code, first_seen_at, last_seen_at, last_sent_at, resolved_at, detail_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(dedupe_key) DO UPDATE SET
               alert_id = excluded.alert_id,
               node_id = excluded.node_id,
               severity = excluded.severity,
               state = excluded.state,
               reason_code = excluded.reason_code,
               first_seen_at = excluded.first_seen_at,
               last_seen_at = excluded.last_seen_at,
               last_sent_at = excluded.last_sent_at,
               resolved_at = excluded.resolved_at,
               detail_json = excluded.detail_json",
            params![
                alert.alert_id.as_str(),
                alert.dedupe_key.as_str(),
                alert.node_id.as_deref(),
                alert.severity.as_str(),
                alert.state.as_str(),
                alert.reason_code.as_str(),
                alert.first_seen_at.as_str(),
                alert.last_seen_at.as_str(),
                alert.last_sent_at.as_deref(),
                alert.resolved_at.as_deref(),
                compact_json(&alert.detail_json),
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_alert_events(&self) -> Result<Vec<AlertEventRecord>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT alert_id, dedupe_key, node_id, severity, state, reason_code, first_seen_at, last_seen_at, last_sent_at, resolved_at, detail_json
             FROM alert_events
             ORDER BY last_seen_at DESC, alert_id",
        )?;
        let rows = stmt.query_map([], alert_event_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn list_alert_events_limited(
        &self,
        limit: u64,
    ) -> Result<Vec<AlertEventRecord>, StoreError> {
        let limit = u64_to_i64(limit)?;
        let mut stmt = self.conn.prepare(
            "SELECT alert_id, dedupe_key, node_id, severity, state, reason_code, first_seen_at, last_seen_at, last_sent_at, resolved_at, detail_json
             FROM alert_events
             ORDER BY last_seen_at DESC, alert_id
             LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], alert_event_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn list_alert_events_filtered(
        &self,
        state: Option<&str>,
        severity: Option<&str>,
        node_id: Option<&str>,
    ) -> Result<Vec<AlertEventRecord>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT alert_id, dedupe_key, node_id, severity, state, reason_code, first_seen_at, last_seen_at, last_sent_at, resolved_at, detail_json
             FROM alert_events
             WHERE (?1 IS NULL OR state = ?1)
               AND (?2 IS NULL OR severity = ?2)
               AND (?3 IS NULL OR node_id = ?3)
             ORDER BY last_seen_at DESC, alert_id",
        )?;
        let rows = stmt.query_map(params![state, severity, node_id], alert_event_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn insert_alert_webhook_hook(
        &self,
        hook: &AlertWebhookHookRecord,
    ) -> Result<(), StoreError> {
        validate_alert_webhook_hook_record(hook)?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO alert_hooks
             (hook_id, name, hook_type, endpoint_url, endpoint_url_redacted, endpoint_host, host_allow_json, hmac_key_id, enabled, max_attempts, timeout_ms, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                hook.hook_id.as_str(),
                hook.name.as_str(),
                hook.hook_type.as_str(),
                hook.endpoint_url.as_str(),
                hook.endpoint_url_redacted.as_str(),
                hook.endpoint_host.as_str(),
                compact_json(&Value::Array(
                    hook.host_allow
                        .iter()
                        .map(|host| Value::String(host.clone()))
                        .collect()
                )),
                hook.hmac_key_id.as_str(),
                bool_to_i64(hook.enabled),
                u64_to_i64(hook.max_attempts)?,
                u64_to_i64(hook.timeout_ms)?,
                hook.created_at.as_str(),
                hook.updated_at.as_str(),
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_alert_webhook_hooks(&self) -> Result<Vec<AlertWebhookHookRecord>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT hook_id, name, hook_type, endpoint_url, endpoint_url_redacted, endpoint_host, host_allow_json, hmac_key_id, enabled, max_attempts, timeout_ms, created_at, updated_at
             FROM alert_hooks
             WHERE hook_type = 'webhook'
             ORDER BY name, hook_id",
        )?;
        let rows = stmt.query_map([], alert_webhook_hook_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn get_alert_webhook_hook(
        &self,
        hook_id: &str,
    ) -> Result<Option<AlertWebhookHookRecord>, StoreError> {
        self.conn
            .query_row(
                "SELECT hook_id, name, hook_type, endpoint_url, endpoint_url_redacted, endpoint_host, host_allow_json, hmac_key_id, enabled, max_attempts, timeout_ms, created_at, updated_at
                 FROM alert_hooks
                 WHERE hook_id = ?1 AND hook_type = 'webhook'",
                [hook_id],
                alert_webhook_hook_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn insert_alert_delivery_attempt(
        &self,
        attempt: &AlertDeliveryAttemptRecord,
    ) -> Result<(), StoreError> {
        validate_alert_delivery_attempt_record(attempt)?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO alert_delivery_attempts
             (attempt_id, alert_id, hook_id, attempt_no, attempted_at, status, http_status_class, error_code, bytes_sent)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                attempt.attempt_id.as_str(),
                attempt.alert_id.as_str(),
                attempt.hook_id.as_str(),
                u64_to_i64(attempt.attempt_no)?,
                attempt.attempted_at.as_str(),
                attempt.status.as_str(),
                attempt.http_status_class.as_deref(),
                attempt.error_code.as_deref(),
                u64_to_i64(attempt.bytes_sent)?,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_alert_delivery_attempts(
        &self,
    ) -> Result<Vec<AlertDeliveryAttemptRecord>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT attempt_id, alert_id, hook_id, attempt_no, attempted_at, status, http_status_class, error_code, bytes_sent
             FROM alert_delivery_attempts
             ORDER BY attempted_at DESC, attempt_id",
        )?;
        let rows = stmt.query_map([], alert_delivery_attempt_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn get_retention_policy(
        &self,
        scope: &str,
    ) -> Result<Option<RetentionPolicyRecord>, StoreError> {
        self.conn
            .query_row(
                "SELECT scope, max_age_days, max_rows, updated_at
                 FROM retention_policies
                 WHERE scope = ?1",
                [scope],
                retention_policy_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn set_retention_policy(&self, policy: &RetentionPolicyRecord) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO retention_policies
             (scope, max_age_days, max_rows, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(scope) DO UPDATE SET
               max_age_days = excluded.max_age_days,
               max_rows = excluded.max_rows,
               updated_at = excluded.updated_at",
            params![
                policy.scope.as_str(),
                option_u64_to_i64(policy.max_age_days)?,
                option_u64_to_i64(policy.max_rows)?,
                policy.updated_at.as_str(),
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn default_health_policy() -> HealthPolicyRecord {
        HealthPolicyRecord {
            stale_window_seconds: DEFAULT_HEALTH_STALE_WINDOW_SECONDS,
            unreachable_consecutive_failures: DEFAULT_HEALTH_UNREACHABLE_FAILURES,
            cert_warning_days: DEFAULT_HEALTH_CERT_WARNING_DAYS,
            cert_critical_days: DEFAULT_HEALTH_CERT_CRITICAL_DAYS,
            updated_at: "default".to_string(),
        }
    }

    pub fn get_health_policy(&self) -> Result<HealthPolicyRecord, StoreError> {
        self.conn
            .query_row(
                "SELECT stale_window_seconds, unreachable_consecutive_failures, cert_warning_days, cert_critical_days, updated_at
                 FROM health_policy
                 WHERE id = 1",
                [],
                health_policy_from_row,
            )
            .optional()
            .map(|policy| policy.unwrap_or_else(Self::default_health_policy))
            .map_err(StoreError::from)
    }

    pub fn set_health_policy(
        &self,
        policy: &HealthPolicyRecord,
        actor: &str,
    ) -> Result<(), StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_health_policy(policy)?;
        let tx = self.conn.unchecked_transaction()?;
        let old_policy = tx
            .query_row(
                "SELECT stale_window_seconds, unreachable_consecutive_failures, cert_warning_days, cert_critical_days, updated_at
                 FROM health_policy
                 WHERE id = 1",
                [],
                health_policy_from_row,
            )
            .optional()?
            .unwrap_or_else(Self::default_health_policy);
        tx.execute(
            "INSERT INTO health_policy
             (id, stale_window_seconds, unreachable_consecutive_failures, cert_warning_days, cert_critical_days, updated_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
               stale_window_seconds = excluded.stale_window_seconds,
               unreachable_consecutive_failures = excluded.unreachable_consecutive_failures,
               cert_warning_days = excluded.cert_warning_days,
               cert_critical_days = excluded.cert_critical_days,
               updated_at = excluded.updated_at",
            params![
                u64_to_i64(policy.stale_window_seconds)?,
                u64_to_i64(policy.unreachable_consecutive_failures)?,
                u64_to_i64(policy.cert_warning_days)?,
                u64_to_i64(policy.cert_critical_days)?,
                policy.updated_at.as_str(),
            ],
        )?;
        let mut event = AuditEvent::new(actor, "health.policy.set");
        event.ok = Some(true);
        event.detail_json = serde_json::json!({
            "policy_class": "health_thresholds",
            "old_value": health_policy_audit_json(&old_policy),
            "new_value": health_policy_audit_json(policy),
        });
        insert_audit_tx(&tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn count_retention_candidates(
        &self,
        scope: &str,
        cutoff: Option<&str>,
        max_rows: Option<u64>,
    ) -> Result<u64, StoreError> {
        Ok(self
            .retention_candidate_report(scope, cutoff, max_rows)?
            .matched_count)
    }

    pub fn retention_candidate_report(
        &self,
        scope: &str,
        cutoff: Option<&str>,
        max_rows: Option<u64>,
    ) -> Result<RetentionCandidateReport, StoreError> {
        let target = retention_target(scope)?;
        retention_candidate_report_for_target(&self.conn, target, cutoff, max_rows)
    }

    pub fn prune_retention_scope_batch(
        &self,
        scope: &str,
        cutoff: Option<&str>,
        max_rows: Option<u64>,
        batch_size: u64,
    ) -> Result<u64, StoreError> {
        let target = retention_target(scope)?;
        let tx = self.conn.unchecked_transaction()?;
        let deleted = prune_retention_target_batch(&tx, target, cutoff, max_rows, batch_size)?;
        tx.commit()?;
        Ok(deleted)
    }

    pub fn prune_probe_observations(
        &self,
        cutoff: Option<&str>,
        max_rows: Option<u64>,
    ) -> Result<u64, StoreError> {
        self.prune_retention_scope("observations", cutoff, max_rows)
    }

    pub fn prune_observability_runs(
        &self,
        cutoff: Option<&str>,
        max_rows: Option<u64>,
    ) -> Result<u64, StoreError> {
        self.prune_retention_scope("observability-runs", cutoff, max_rows)
    }

    pub fn prune_health_snapshots(
        &self,
        cutoff: Option<&str>,
        max_rows: Option<u64>,
    ) -> Result<u64, StoreError> {
        self.prune_retention_scope("health-snapshots", cutoff, max_rows)
    }

    pub fn prune_alert_events(
        &self,
        cutoff: Option<&str>,
        max_rows: Option<u64>,
    ) -> Result<u64, StoreError> {
        self.prune_retention_scope("alert-events", cutoff, max_rows)
    }

    fn prune_retention_scope(
        &self,
        scope: &str,
        cutoff: Option<&str>,
        max_rows: Option<u64>,
    ) -> Result<u64, StoreError> {
        let target = retention_target(scope)?;
        let tx = self.conn.unchecked_transaction()?;
        let deleted = prune_retention_target(&tx, target, cutoff, max_rows)?;
        tx.commit()?;
        Ok(deleted)
    }

    pub fn disable_node(&self, node_id: &str, actor: &str) -> Result<(), StoreError> {
        self.set_node_enabled(node_id, false, actor, "node.disable")
    }

    pub fn enable_node(&self, node_id: &str, actor: &str) -> Result<(), StoreError> {
        self.set_node_enabled(node_id, true, actor, "node.enable")
    }

    pub fn remove_node(&self, node_id: &str, actor: &str) -> Result<(), StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        let tx = self.conn.unchecked_transaction()?;
        let before = get_node_tx(&tx, node_id)?
            .ok_or_else(|| StoreError::NodeNotFound(node_id.to_string()))?;
        let affected = tx.execute("DELETE FROM nodes WHERE node_id = ?1", [node_id])?;
        if affected == 0 {
            return Err(StoreError::NodeNotFound(node_id.to_string()));
        }
        let mut event = AuditEvent::new(actor, "node.remove");
        event.node_id = Some(before.node_id.clone());
        event.endpoint_id = Some(before.endpoint_id.clone());
        event.ok = Some(true);
        event.detail_json = json_detail(
            "node",
            &before.node_id,
            Some(node_audit_json(&before)),
            None,
            None,
        );
        insert_audit_tx(&tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    fn set_node_enabled(
        &self,
        node_id: &str,
        enabled: bool,
        actor: &str,
        event_name: &str,
    ) -> Result<(), StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        let tx = self.conn.unchecked_transaction()?;
        let before = get_node_tx(&tx, node_id)?
            .ok_or_else(|| StoreError::NodeNotFound(node_id.to_string()))?;
        let affected = tx.execute(
            "UPDATE nodes SET enabled = ?1, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE node_id = ?2",
            params![bool_to_i64(enabled), node_id],
        )?;
        if affected == 0 {
            return Err(StoreError::NodeNotFound(node_id.to_string()));
        }
        let after = get_node_tx(&tx, node_id)?
            .ok_or_else(|| StoreError::NodeNotFound(node_id.to_string()))?;
        let mut event = AuditEvent::new(actor, event_name);
        event.node_id = Some(after.node_id.clone());
        event.endpoint_id = Some(after.endpoint_id.clone());
        event.ok = Some(true);
        event.detail_json = json_detail(
            "node",
            &after.node_id,
            Some(node_audit_json(&before)),
            Some(node_audit_json(&after)),
            None,
        );
        insert_audit_tx(&tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn insert_audit(&self, event: &AuditEvent) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        insert_audit_tx(&tx, event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn audit_count(&self) -> Result<i64, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT count(*) FROM controller_audit_log", [], |row| {
                row.get(0)
            })?)
    }

    pub fn list_audit_window(
        &self,
        from: &str,
        to: &str,
        limit: usize,
    ) -> Result<Vec<AuditRecord>, StoreError> {
        let limit = usize_to_i64(limit)?;
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, actor, event, node_id, endpoint_id, method, request_id, params_hash, ok, error_code, duration_ms, detail_json
             FROM controller_audit_log
             WHERE ts >= ?1 AND ts < ?2
             ORDER BY ts ASC, id ASC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![from, to, limit], audit_record_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn hash_enrollment_token(token: &str) -> String {
        blake3::hash(token.as_bytes()).to_hex().to_string()
    }

    pub fn create_enrollment_token(
        &self,
        token: &EnrollmentTokenInsert,
        actor: &str,
    ) -> Result<(), StoreError> {
        validate_actor(&token.created_by).map_err(StoreError::InvalidInput)?;
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        if let Some(description) = &token.description {
            validate_description(description).map_err(StoreError::InvalidInput)?;
        }
        validate_label_json(&token.labels_json, "labels").map_err(StoreError::InvalidInput)?;
        validate_label_json(&token.scope_json, "scope").map_err(StoreError::InvalidInput)?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO enrollment_tokens
             (token_id, token_hash, created_at, created_by, expires_at, max_uses, used_count, status, description, labels_json, scope_json)
             VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%SZ','now'), ?3, ?4, ?5, 0, ?6, ?7, ?8, ?9)",
            params![
                token.token_id.as_str(),
                token.token_hash.as_str(),
                token.created_by.as_str(),
                token.expires_at.as_str(),
                i64::from(token.max_uses),
                EnrollmentTokenStatus::Active.as_str(),
                token.description.as_deref(),
                token.labels_json.to_string(),
                token.scope_json.to_string(),
            ],
        )?;
        let mut event = AuditEvent::new(actor, "enrollment.token.create");
        event.ok = Some(true);
        event.detail_json = json_detail(
            "enrollment_token",
            &token.token_id,
            None,
            Some(serde_json::json!({
                "token_id": token.token_id.clone(),
                "status": EnrollmentTokenStatus::Active.as_str(),
                "expires_at": token.expires_at.clone(),
                "max_uses": token.max_uses,
                "description": token.description.clone(),
                "labels": token.labels_json.clone(),
                "scope": token.scope_json.clone(),
            })),
            None,
        );
        insert_audit_tx(&tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_enrollment_token(
        &self,
        token_id: &str,
    ) -> Result<Option<EnrollmentTokenRecord>, StoreError> {
        self.conn
            .query_row(
                "SELECT token_id, token_hash, created_at, created_by, expires_at, max_uses, used_count, status, description, labels_json, scope_json
                 FROM enrollment_tokens WHERE token_id = ?1",
                [token_id],
                enrollment_token_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn submit_join_request(
        &self,
        request: &JoinRequestInsert,
        actor: &str,
    ) -> Result<JoinRequestRecord, StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_agent_public_key(&request.agent_public_key).map_err(StoreError::InvalidInput)?;
        validate_agent_fingerprint(&request.fingerprint).map_err(StoreError::InvalidInput)?;
        let requested_endpoint_id = request
            .requested_endpoint_id
            .as_deref()
            .map(validate_endpoint_id)
            .transpose()
            .map_err(|err| StoreError::InvalidInput(format!("requested_endpoint_id: {err}")))?;
        validate_hostname(&request.hostname).map_err(StoreError::InvalidInput)?;
        validate_agent_version(&request.agent_version).map_err(StoreError::InvalidInput)?;
        validate_label_json(&request.requested_labels_json, "requested_labels")
            .map_err(StoreError::InvalidInput)?;
        let tx = self.conn.unchecked_transaction()?;
        let token_hash = Self::hash_enrollment_token(&request.token_plaintext);
        let token = tx
            .query_row(
                "SELECT token_id, token_hash, created_at, created_by, expires_at, max_uses, used_count, status, description, labels_json, scope_json
                 FROM enrollment_tokens WHERE token_hash = ?1",
                [token_hash],
                enrollment_token_from_row,
            )
            .optional()?;
        let Some(token) = token else {
            audit_join_rejection_tx(&tx, actor, None, "unknown_token")?;
            tx.commit()?;
            return Err(StoreError::EnrollmentRejected("unknown_token".to_string()));
        };

        if token.status != EnrollmentTokenStatus::Active {
            let reason = token.status.as_str();
            audit_join_rejection_tx(&tx, actor, Some(&token.token_id), reason)?;
            tx.commit()?;
            return Err(StoreError::EnrollmentRejected(reason.to_string()));
        }
        if token_is_expired(&token.expires_at) {
            tx.execute(
                "UPDATE enrollment_tokens SET status = ?1 WHERE token_id = ?2",
                params![
                    EnrollmentTokenStatus::Expired.as_str(),
                    token.token_id.as_str()
                ],
            )?;
            audit_join_rejection_tx(&tx, actor, Some(&token.token_id), "expired")?;
            tx.commit()?;
            return Err(StoreError::EnrollmentRejected("expired".to_string()));
        }
        if token.used_count >= token.max_uses {
            audit_join_rejection_tx(&tx, actor, Some(&token.token_id), "max_uses_exhausted")?;
            tx.commit()?;
            return Err(StoreError::EnrollmentRejected(
                "max_uses_exhausted".to_string(),
            ));
        }

        let request_id = format!("join-{}", Uuid::new_v4());
        let correlation_id = format!("corr-{}", Uuid::new_v4());
        tx.execute(
            "INSERT INTO join_requests
             (request_id, token_id, status, agent_public_key, fingerprint, requested_endpoint_id, assigned_endpoint_id, hostname, agent_version, requested_labels_json, approved_labels_json, created_at, approved_at, approved_by, rejection_reason, audit_correlation_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, ?9, '{}', strftime('%Y-%m-%dT%H:%M:%SZ','now'), NULL, NULL, NULL, ?10)",
            params![
                request_id.as_str(),
                token.token_id.as_str(),
                JoinRequestStatus::Pending.as_str(),
                request.agent_public_key.as_str(),
                request.fingerprint.as_str(),
                requested_endpoint_id.as_deref(),
                request.hostname.as_str(),
                request.agent_version.as_str(),
                request.requested_labels_json.to_string(),
                correlation_id.as_str(),
            ],
        )?;
        tx.execute(
            "UPDATE enrollment_tokens SET used_count = used_count + 1 WHERE token_id = ?1",
            [token.token_id.as_str()],
        )?;

        let mut event = AuditEvent::new(actor, "enrollment.token.use");
        event.ok = Some(true);
        event.request_id = Some(request_id.clone());
        event.detail_json = json_detail(
            "join_request",
            &request_id,
            None,
            Some(serde_json::json!({
                "request_id": request_id.clone(),
                "token_id": token.token_id.clone(),
                "status": JoinRequestStatus::Pending.as_str(),
                "fingerprint": request.fingerprint.clone(),
                "hostname": request.hostname.clone(),
                "agent_version": request.agent_version.clone(),
                "requested_endpoint_id": requested_endpoint_id.clone(),
                "requested_labels": request.requested_labels_json.clone(),
                "correlation_id": correlation_id.clone(),
            })),
            None,
        );
        insert_audit_tx(&tx, &event)?;
        let joined = get_join_request_tx(&tx, &event.request_id.clone().expect("request id set"))?
            .expect("join request inserted");
        tx.commit()?;
        Ok(joined)
    }

    pub fn get_join_request(
        &self,
        request_id: &str,
    ) -> Result<Option<JoinRequestRecord>, StoreError> {
        self.conn
            .query_row(
                "SELECT request_id, token_id, status, agent_public_key, fingerprint, requested_endpoint_id, assigned_endpoint_id, hostname, agent_version, requested_labels_json, approved_labels_json, created_at, approved_at, approved_by, rejection_reason, audit_correlation_id
                 FROM join_requests WHERE request_id = ?1",
                [request_id],
                join_request_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn approve_join_request(
        &self,
        approval: &ApprovalInput,
    ) -> Result<JoinRequestRecord, StoreError> {
        validate_actor(&approval.approved_by).map_err(StoreError::InvalidInput)?;
        validate_reason(&approval.reason).map_err(StoreError::InvalidInput)?;
        let endpoint_id =
            validate_endpoint_id(&approval.endpoint_id).map_err(StoreError::InvalidInput)?;
        validate_label_json(&approval.approved_labels_json, "approved_labels")
            .map_err(StoreError::InvalidInput)?;
        let tx = self.conn.unchecked_transaction()?;
        let before = get_join_request_tx(&tx, &approval.request_id)?
            .ok_or_else(|| StoreError::JoinRequestNotFound(approval.request_id.clone()))?;
        if before.status != JoinRequestStatus::Pending {
            return Err(StoreError::InvalidJoinRequestStatus {
                request_id: approval.request_id.clone(),
                status: before.status.as_str().to_string(),
            });
        }
        if let Some(requested_endpoint_id) = &before.requested_endpoint_id
            && requested_endpoint_id != &endpoint_id
        {
            return Err(StoreError::InvalidInput(
                "approved endpoint_id must match requested_endpoint_id".to_string(),
            ));
        }
        if get_endpoint_trust_tx(&tx, &endpoint_id)?.is_some() {
            return Err(StoreError::EndpointAlreadyExists(endpoint_id));
        }

        let bundle = trust_bundle_json(&endpoint_id, 1, EndpointStatus::Active);
        insert_endpoint_trust_tx(
            &tx,
            &EndpointTrustRecord {
                endpoint_id: endpoint_id.clone(),
                node_id: None,
                fingerprint: Some(before.fingerprint.clone()),
                status: EndpointStatus::Active,
                generation: 1,
                previous_endpoint_id: None,
                rotated_to: None,
                trust_bundle_json: bundle,
                created_at: String::new(),
                updated_at: String::new(),
            },
        )?;
        tx.execute(
            "UPDATE join_requests
             SET status = ?1,
                 assigned_endpoint_id = ?2,
                 approved_labels_json = ?3,
                 approved_at = strftime('%Y-%m-%dT%H:%M:%SZ','now'),
                 approved_by = ?4
             WHERE request_id = ?5",
            params![
                JoinRequestStatus::Approved.as_str(),
                endpoint_id.as_str(),
                approval.approved_labels_json.to_string(),
                approval.approved_by.as_str(),
                approval.request_id.as_str(),
            ],
        )?;
        let after =
            get_join_request_tx(&tx, &approval.request_id)?.expect("approved request exists");
        let mut event = AuditEvent::new(&approval.approved_by, "enrollment.approve");
        event.ok = Some(true);
        event.request_id = Some(approval.request_id.clone());
        event.endpoint_id = Some(endpoint_id);
        event.detail_json = json_detail(
            "join_request",
            &approval.request_id,
            Some(join_request_audit_json(&before)),
            Some(join_request_audit_json(&after)),
            Some(&approval.reason),
        );
        insert_audit_tx(&tx, &event)?;
        tx.commit()?;
        Ok(after)
    }

    pub fn get_endpoint_trust(
        &self,
        endpoint_id: &str,
    ) -> Result<Option<EndpointTrustRecord>, StoreError> {
        self.conn
            .query_row(
                "SELECT endpoint_id, node_id, fingerprint, status, generation, previous_endpoint_id, rotated_to, trust_bundle_json, created_at, updated_at
                 FROM endpoint_trust WHERE endpoint_id = ?1",
                [endpoint_id],
                endpoint_trust_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn rotate_endpoint(
        &self,
        old_endpoint_id: &str,
        new_endpoint_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<EndpointTrustRecord, StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_reason(reason).map_err(StoreError::InvalidInput)?;
        let old_endpoint_id =
            validate_endpoint_id(old_endpoint_id).map_err(StoreError::InvalidInput)?;
        let new_endpoint_id =
            validate_endpoint_id(new_endpoint_id).map_err(StoreError::InvalidInput)?;
        let tx = self.conn.unchecked_transaction()?;
        let old_before = get_endpoint_trust_tx(&tx, &old_endpoint_id)?
            .ok_or_else(|| StoreError::EndpointNotFound(old_endpoint_id.clone()))?;
        if get_endpoint_trust_tx(&tx, &new_endpoint_id)?.is_some() {
            return Err(StoreError::EndpointAlreadyExists(new_endpoint_id));
        }
        let new_generation = old_before.generation + 1;
        tx.execute(
            "UPDATE endpoint_trust
             SET status = ?1,
                 generation = ?2,
                 rotated_to = ?3,
                 trust_bundle_json = ?4,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
             WHERE endpoint_id = ?5",
            params![
                EndpointStatus::Rotated.as_str(),
                new_generation as i64,
                new_endpoint_id.as_str(),
                trust_bundle_json(&old_endpoint_id, new_generation, EndpointStatus::Rotated)
                    .to_string(),
                old_endpoint_id.as_str(),
            ],
        )?;
        insert_endpoint_trust_tx(
            &tx,
            &EndpointTrustRecord {
                endpoint_id: new_endpoint_id.clone(),
                node_id: old_before.node_id.clone(),
                fingerprint: old_before.fingerprint.clone(),
                status: EndpointStatus::Active,
                generation: new_generation,
                previous_endpoint_id: Some(old_endpoint_id.clone()),
                rotated_to: None,
                trust_bundle_json: trust_bundle_json(
                    &new_endpoint_id,
                    new_generation,
                    EndpointStatus::Active,
                ),
                created_at: String::new(),
                updated_at: String::new(),
            },
        )?;
        let old_after = get_endpoint_trust_tx(&tx, &old_endpoint_id)?.expect("old endpoint exists");
        let new_after = get_endpoint_trust_tx(&tx, &new_endpoint_id)?.expect("new endpoint exists");
        audit_endpoint_lifecycle_tx(
            &tx,
            actor,
            "endpoint.rotate",
            &new_endpoint_id,
            Some(endpoint_audit_json(&old_before)),
            Some(serde_json::json!({
                "old": endpoint_audit_json(&old_after),
                "new": endpoint_audit_json(&new_after),
            })),
            reason,
        )?;
        tx.commit()?;
        Ok(new_after)
    }

    pub fn revoke_endpoint(
        &self,
        endpoint_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<EndpointTrustRecord, StoreError> {
        self.update_endpoint_status(
            endpoint_id,
            EndpointStatus::Revoked,
            actor,
            reason,
            "endpoint.revoke",
        )
    }

    pub fn quarantine_endpoint(
        &self,
        endpoint_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<EndpointTrustRecord, StoreError> {
        self.update_endpoint_status(
            endpoint_id,
            EndpointStatus::Quarantined,
            actor,
            reason,
            "endpoint.quarantine",
        )
    }

    pub fn trust_snapshot(
        &self,
        endpoint_filter: Option<&str>,
    ) -> Result<TrustSnapshot, StoreError> {
        if let Some(endpoint_id) = endpoint_filter {
            let endpoints = self
                .get_endpoint_trust(endpoint_id)?
                .into_iter()
                .collect::<Vec<_>>();
            Ok(TrustSnapshot { endpoints })
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT endpoint_id, node_id, fingerprint, status, generation, previous_endpoint_id, rotated_to, trust_bundle_json, created_at, updated_at
                 FROM endpoint_trust ORDER BY endpoint_id",
            )?;
            let rows = stmt.query_map([], endpoint_trust_from_row)?;
            Ok(TrustSnapshot {
                endpoints: rows.collect::<Result<Vec<_>, _>>()?,
            })
        }
    }

    fn update_endpoint_status(
        &self,
        endpoint_id: &str,
        status: EndpointStatus,
        actor: &str,
        reason: &str,
        action: &str,
    ) -> Result<EndpointTrustRecord, StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_reason(reason).map_err(StoreError::InvalidInput)?;
        let endpoint_id = validate_endpoint_id(endpoint_id).map_err(StoreError::InvalidInput)?;
        let tx = self.conn.unchecked_transaction()?;
        let before = get_endpoint_trust_tx(&tx, &endpoint_id)?
            .ok_or_else(|| StoreError::EndpointNotFound(endpoint_id.clone()))?;
        let generation = before.generation + 1;
        tx.execute(
            "UPDATE endpoint_trust
             SET status = ?1,
                 generation = ?2,
                 trust_bundle_json = ?3,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
             WHERE endpoint_id = ?4",
            params![
                status.as_str(),
                generation as i64,
                trust_bundle_json(&endpoint_id, generation, status).to_string(),
                endpoint_id.as_str(),
            ],
        )?;
        let after = get_endpoint_trust_tx(&tx, &endpoint_id)?.expect("endpoint exists");
        audit_endpoint_lifecycle_tx(
            &tx,
            actor,
            action,
            &endpoint_id,
            Some(endpoint_audit_json(&before)),
            Some(endpoint_audit_json(&after)),
            reason,
        )?;
        tx.commit()?;
        Ok(after)
    }
}

fn create_database_file_if_missing(path: &Path) -> Result<bool, StoreError> {
    match private_file::open_private_create_new(path) {
        Ok(_) => Ok(true),
        Err(PrivateFileError::Io(err)) if err.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(map_private_file_error(err)),
    }
}

fn insert_audit_tx(tx: &Transaction<'_>, event: &AuditEvent) -> Result<(), StoreError> {
    validate_actor(&event.actor).map_err(StoreError::InvalidInput)?;
    if event.ts.len() > 64 || OffsetDateTime::parse(&event.ts, &Rfc3339).is_err() {
        return Err(StoreError::InvalidInput(
            "audit timestamp must be bounded RFC3339".to_string(),
        ));
    }
    validate_audit_text(&event.event, "audit event", 128)?;
    for (field, value, max) in [
        ("audit node_id", event.node_id.as_deref(), 128_usize),
        ("audit endpoint_id", event.endpoint_id.as_deref(), 128_usize),
        ("audit method", event.method.as_deref(), 128_usize),
        ("audit request_id", event.request_id.as_deref(), 128_usize),
        ("audit params_hash", event.params_hash.as_deref(), 128_usize),
        ("audit error_code", event.error_code.as_deref(), 128_usize),
    ] {
        if let Some(value) = value {
            validate_audit_text(value, field, max)?;
        }
    }
    validate_low_sensitive_json(&event.detail_json, "audit detail")?;
    let ok = event.ok.map(|v| if v { 1_i64 } else { 0_i64 });
    let duration_ms = event
        .duration_ms
        .map(i64::try_from)
        .transpose()
        .map_err(|_| StoreError::InvalidInput("audit duration_ms exceeds i64".to_string()))?;
    tx.execute(
        "INSERT INTO controller_audit_log
         (ts, actor, event, node_id, endpoint_id, method, request_id, params_hash, ok, error_code, duration_ms, detail_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            event.ts.as_str(),
            event.actor.as_str(),
            event.event.as_str(),
            event.node_id.as_deref(),
            event.endpoint_id.as_deref(),
            event.method.as_deref(),
            event.request_id.as_deref(),
            event.params_hash.as_deref(),
            ok,
            event.error_code.as_deref(),
            duration_ms,
            event.detail_json.to_string(),
        ],
    )?;
    Ok(())
}

fn validate_audit_text(value: &str, field: &str, max: usize) -> Result<(), StoreError> {
    if value.is_empty()
        || value.len() > max
        || value
            .bytes()
            .any(|byte| !byte.is_ascii() || byte.is_ascii_control())
        || forbidden_stored_value(value, None)
    {
        return Err(StoreError::InvalidInput(format!(
            "{field} is not a bounded low-sensitive value"
        )));
    }
    Ok(())
}

fn insert_endpoint_trust_tx(
    tx: &Transaction<'_>,
    endpoint: &EndpointTrustRecord,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO endpoint_trust
         (endpoint_id, node_id, fingerprint, status, generation, previous_endpoint_id, rotated_to, trust_bundle_json, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
        params![
            endpoint.endpoint_id.as_str(),
            endpoint.node_id.as_deref(),
            endpoint.fingerprint.as_deref(),
            endpoint.status.as_str(),
            endpoint.generation as i64,
            endpoint.previous_endpoint_id.as_deref(),
            endpoint.rotated_to.as_deref(),
            endpoint.trust_bundle_json.to_string(),
        ],
    )?;
    Ok(())
}

fn get_node_tx(tx: &Transaction<'_>, node_id: &str) -> Result<Option<NodeRecord>, StoreError> {
    tx.query_row(
        "SELECT node_id, endpoint_id, name, region, role, enabled FROM nodes WHERE node_id = ?1",
        [node_id],
        node_from_row,
    )
    .optional()
    .map_err(StoreError::from)
}

fn get_join_request_tx(
    tx: &Transaction<'_>,
    request_id: &str,
) -> Result<Option<JoinRequestRecord>, StoreError> {
    tx.query_row(
        "SELECT request_id, token_id, status, agent_public_key, fingerprint, requested_endpoint_id, assigned_endpoint_id, hostname, agent_version, requested_labels_json, approved_labels_json, created_at, approved_at, approved_by, rejection_reason, audit_correlation_id
         FROM join_requests WHERE request_id = ?1",
        [request_id],
        join_request_from_row,
    )
    .optional()
    .map_err(StoreError::from)
}

fn get_endpoint_trust_tx(
    tx: &Transaction<'_>,
    endpoint_id: &str,
) -> Result<Option<EndpointTrustRecord>, StoreError> {
    tx.query_row(
        "SELECT endpoint_id, node_id, fingerprint, status, generation, previous_endpoint_id, rotated_to, trust_bundle_json, created_at, updated_at
         FROM endpoint_trust WHERE endpoint_id = ?1",
        [endpoint_id],
        endpoint_trust_from_row,
    )
    .optional()
    .map_err(StoreError::from)
}

fn audit_join_rejection_tx(
    tx: &Transaction<'_>,
    actor: &str,
    token_id: Option<&str>,
    reason: &str,
) -> Result<(), StoreError> {
    let mut event = AuditEvent::new(actor, "enrollment.token.reject");
    event.ok = Some(false);
    event.error_code = Some("ENROLLMENT_REJECTED".to_string());
    event.detail_json = serde_json::json!({
        "actor_type": "agent",
        "action": "enrollment.token.reject",
        "target_type": "enrollment_token",
        "target_id": token_id,
        "reason": reason,
    });
    insert_audit_tx(tx, &event)
}

fn audit_endpoint_lifecycle_tx(
    tx: &Transaction<'_>,
    actor: &str,
    action: &str,
    endpoint_id: &str,
    before: Option<Value>,
    after: Option<Value>,
    reason: &str,
) -> Result<(), StoreError> {
    let mut event = AuditEvent::new(actor, action);
    event.ok = Some(true);
    event.endpoint_id = Some(endpoint_id.to_string());
    event.detail_json = json_detail("endpoint", endpoint_id, before, after, Some(reason));
    insert_audit_tx(tx, &event)
}

fn json_detail(
    target_type: &str,
    target_id: &str,
    before: Option<Value>,
    after: Option<Value>,
    reason: Option<&str>,
) -> Value {
    serde_json::json!({
        "actor_type": "user",
        "target_type": target_type,
        "target_id": target_id,
        "before": before,
        "after": after,
        "reason": reason,
    })
}

fn join_request_audit_json(join: &JoinRequestRecord) -> Value {
    serde_json::json!({
        "request_id": join.request_id.clone(),
        "token_id": join.token_id.clone(),
        "status": join.status.as_str(),
        "fingerprint": join.fingerprint.clone(),
        "requested_endpoint_id": join.requested_endpoint_id.clone(),
        "assigned_endpoint_id": join.assigned_endpoint_id.clone(),
        "hostname": join.hostname.clone(),
        "agent_version": join.agent_version.clone(),
        "requested_labels": join.requested_labels_json.clone(),
        "approved_labels": join.approved_labels_json.clone(),
        "approved_by": join.approved_by.clone(),
    })
}

fn node_audit_json(node: &NodeRecord) -> Value {
    serde_json::json!({
        "node_id": node.node_id.clone(),
        "endpoint_id": node.endpoint_id.clone(),
        "region": node.region.clone(),
        "role": node.role.clone(),
        "enabled": node.enabled,
    })
}

fn endpoint_audit_json(endpoint: &EndpointTrustRecord) -> Value {
    serde_json::json!({
        "endpoint_id": endpoint.endpoint_id.clone(),
        "node_id": endpoint.node_id.clone(),
        "fingerprint": endpoint.fingerprint.clone(),
        "status": endpoint.status.as_str(),
        "generation": endpoint.generation,
        "previous_endpoint_id": endpoint.previous_endpoint_id.clone(),
        "rotated_to": endpoint.rotated_to.clone(),
    })
}

fn trust_bundle_json(endpoint_id: &str, generation: u64, status: EndpointStatus) -> Value {
    serde_json::to_value(TrustBundle {
        endpoint_id: endpoint_id.to_string(),
        generation,
        status,
        trusted_controllers: Vec::new(),
        trusted_peers: Vec::new(),
        authorized_path_probes: Vec::new(),
    })
    .expect("trust bundle serialization succeeds")
}

fn token_is_expired(expires_at: &str) -> bool {
    OffsetDateTime::parse(expires_at, &Rfc3339)
        .map(|expires_at| expires_at <= OffsetDateTime::now_utc())
        .unwrap_or(true)
}

fn validate_database_files(path: &Path) -> Result<(), StoreError> {
    private_file::validate_existing_private_file(path).map_err(map_private_file_error)?;
    for sidecar in sqlite_sidecar_paths(path) {
        match std::fs::symlink_metadata(&sidecar) {
            Ok(_) => {
                private_file::validate_existing_private_file(&sidecar)
                    .map_err(map_private_file_error)?;
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(StoreError::Io(err)),
        }
    }
    Ok(())
}

fn sqlite_sidecar_paths(path: &Path) -> [PathBuf; 2] {
    let mut wal = path.as_os_str().to_os_string();
    wal.push("-wal");
    let mut shm = path.as_os_str().to_os_string();
    shm.push("-shm");
    [PathBuf::from(wal), PathBuf::from(shm)]
}

fn map_private_file_error(err: PrivateFileError) -> StoreError {
    match err {
        PrivateFileError::Io(err) => StoreError::Io(err),
        PrivateFileError::MissingParent
        | PrivateFileError::UnsafeParent
        | PrivateFileError::UnsafeFile
        | PrivateFileError::UnsupportedPlatform => StoreError::UnsafePermissions,
    }
}

fn node_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<NodeRecord> {
    Ok(NodeRecord {
        node_id: row.get(0)?,
        endpoint_id: row.get(1)?,
        name: row.get(2)?,
        region: row.get(3)?,
        role: row.get(4)?,
        enabled: i64_to_bool(row.get(5)?, 5)?,
    })
}

fn probe_history_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProbeHistoryRecord> {
    let ok: Option<i64> = row.get(5)?;
    let duration_ms: Option<i64> = row.get(7)?;
    let detail_json: String = row.get(8)?;
    Ok(ProbeHistoryRecord {
        ts: row.get(0)?,
        node_id: row.get(1)?,
        endpoint_id: row.get(2)?,
        method: row.get(3)?,
        request_id: row.get(4)?,
        ok: ok.map(|value| i64_to_bool(value, 5)).transpose()?,
        error_code: row.get(6)?,
        duration_ms: duration_ms.and_then(|value| u64::try_from(value).ok()),
        detail_json: serde_json::from_str(&detail_json).unwrap_or(Value::Null),
    })
}

fn audit_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditRecord> {
    let ok: Option<i64> = row.get(9)?;
    let duration_ms: Option<i64> = row.get(11)?;
    let detail_json: Option<String> = row.get(12)?;
    Ok(AuditRecord {
        id: row.get(0)?,
        ts: row.get(1)?,
        actor: row.get(2)?,
        event: row.get(3)?,
        node_id: row.get(4)?,
        endpoint_id: row.get(5)?,
        method: row.get(6)?,
        request_id: row.get(7)?,
        params_hash: row.get(8)?,
        ok: ok.map(|value| i64_to_bool(value, 9)).transpose()?,
        error_code: row.get(10)?,
        duration_ms: duration_ms.and_then(|value| u64::try_from(value).ok()),
        detail_json: detail_json
            .as_deref()
            .map(|value| parse_json_column(value, 12))
            .transpose()?
            .unwrap_or(Value::Null),
    })
}

fn observability_job_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ObservabilityJobRecord> {
    let selector_json: String = row.get(2)?;
    let pair_selector_json: Option<String> = row.get(3)?;
    Ok(ObservabilityJobRecord {
        job_id: row.get(0)?,
        kind: row.get(1)?,
        selector_json: parse_json_column(&selector_json, 2)?,
        pair_selector_json: pair_selector_json
            .as_deref()
            .map(|value| parse_json_column(value, 3))
            .transpose()?,
        interval_seconds: i64_to_u64(row.get(4)?)?,
        jitter_seconds: i64_to_u64(row.get(5)?)?,
        timeout_ms: i64_to_u64(row.get(6)?)?,
        enabled: i64_to_bool(row.get(7)?, 7)?,
        next_run_at: row.get(8)?,
        last_run_at: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

#[derive(Debug)]
struct RawObservabilityJobRow {
    job_id: String,
    kind: String,
    selector_json: String,
    pair_selector_json: Option<String>,
    interval_seconds: i64,
    jitter_seconds: i64,
    timeout_ms: i64,
    enabled: i64,
    next_run_at: Option<String>,
    last_run_at: Option<String>,
    created_at: String,
    updated_at: String,
}

fn raw_observability_job_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<RawObservabilityJobRow> {
    Ok(RawObservabilityJobRow {
        job_id: row.get(0)?,
        kind: row.get(1)?,
        selector_json: row.get(2)?,
        pair_selector_json: row.get(3)?,
        interval_seconds: row.get(4)?,
        jitter_seconds: row.get(5)?,
        timeout_ms: row.get(6)?,
        enabled: row.get(7)?,
        next_run_at: row.get(8)?,
        last_run_at: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

fn observability_job_load_from_raw(raw: RawObservabilityJobRow) -> ObservabilityJobLoadResult {
    let invalid = |raw: &RawObservabilityJobRow, reason_code: &str| {
        ObservabilityJobLoadResult::Invalid(InvalidObservabilityJobRecord {
            job_id: raw.job_id.clone(),
            kind: raw.kind.clone(),
            enabled: matches!(raw.enabled, 1),
            next_run_at: raw.next_run_at.clone(),
            reason_code: reason_code.to_string(),
        })
    };
    let selector_json = match serde_json::from_str(&raw.selector_json) {
        Ok(value) => value,
        Err(_) => return invalid(&raw, "INVALID_SELECTOR_JSON"),
    };
    let pair_selector_json = match raw
        .pair_selector_json
        .as_deref()
        .map(serde_json::from_str::<Value>)
        .transpose()
    {
        Ok(value) => value,
        Err(_) => return invalid(&raw, "INVALID_PAIR_SELECTOR_JSON"),
    };
    let interval_seconds = match i64_to_u64(raw.interval_seconds) {
        Ok(value) => value,
        Err(_) => return invalid(&raw, "INVALID_INTERVAL_SECONDS"),
    };
    let jitter_seconds = match i64_to_u64(raw.jitter_seconds) {
        Ok(value) => value,
        Err(_) => return invalid(&raw, "INVALID_JITTER_SECONDS"),
    };
    let timeout_ms = match i64_to_u64(raw.timeout_ms) {
        Ok(value) => value,
        Err(_) => return invalid(&raw, "INVALID_TIMEOUT_MS"),
    };
    let enabled = match i64_to_bool(raw.enabled, 7) {
        Ok(value) => value,
        Err(_) => return invalid(&raw, "INVALID_ENABLED"),
    };
    ObservabilityJobLoadResult::Valid(ObservabilityJobRecord {
        job_id: raw.job_id,
        kind: raw.kind,
        selector_json,
        pair_selector_json,
        interval_seconds,
        jitter_seconds,
        timeout_ms,
        enabled,
        next_run_at: raw.next_run_at,
        last_run_at: raw.last_run_at,
        created_at: raw.created_at,
        updated_at: raw.updated_at,
    })
}

fn observability_run_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ObservabilityRunRecord> {
    let summary_json: String = row.get(6)?;
    let observation_count: i64 = row.get(7)?;
    let failed_observation_count: i64 = row.get(8)?;
    Ok(ObservabilityRunRecord {
        run_id: row.get(0)?,
        job_id: row.get(1)?,
        started_at: row.get(2)?,
        finished_at: row.get(3)?,
        status: row.get(4)?,
        triggered_by: row.get(5)?,
        summary_json: parse_json_column(&summary_json, 6)?,
        observation_count: i64_to_u64(observation_count)?,
        failed_observation_count: i64_to_u64(failed_observation_count)?,
    })
}

fn probe_observation_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProbeObservationRecord> {
    let ok: Option<i64> = row.get(5)?;
    let duration_ms: Option<i64> = row.get(7)?;
    let summary_json: String = row.get(11)?;
    Ok(ProbeObservationRecord {
        observation_id: row.get(0)?,
        run_id: row.get(1)?,
        node_id: row.get(2)?,
        endpoint_id: row.get(3)?,
        method: row.get(4)?,
        ok: ok.map(|value| i64_to_bool(value, 5)).transpose()?,
        error_code: row.get(6)?,
        duration_ms: duration_ms.map(i64_to_u64).transpose()?,
        observed_at: row.get(8)?,
        expires_at: row.get(9)?,
        result_class: row.get(10)?,
        summary_json: parse_json_column(&summary_json, 11)?,
    })
}

fn health_snapshot_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<HealthSnapshotRecord> {
    let freshness_seconds: Option<i64> = row.get(4)?;
    let degraded_methods_json: String = row.get(8)?;
    let summary_json: String = row.get(9)?;
    Ok(HealthSnapshotRecord {
        node_id: row.get(0)?,
        endpoint_id: row.get(1)?,
        computed_at: row.get(2)?,
        status: row.get(3)?,
        freshness_seconds: freshness_seconds.map(i64_to_u64).transpose()?,
        last_success_at: row.get(5)?,
        last_failure_at: row.get(6)?,
        last_error_code: row.get(7)?,
        degraded_methods_json: parse_json_column(&degraded_methods_json, 8)?,
        summary_json: parse_json_column(&summary_json, 9)?,
    })
}

fn alert_event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AlertEventRecord> {
    let detail_json: String = row.get(10)?;
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
        detail_json: parse_json_column(&detail_json, 10)?,
    })
}

fn alert_webhook_hook_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<AlertWebhookHookRecord> {
    let host_allow_json: String = row.get(6)?;
    let host_allow = parse_string_array_column(&host_allow_json, 6)?;
    Ok(AlertWebhookHookRecord {
        hook_id: row.get(0)?,
        name: row.get(1)?,
        hook_type: row.get(2)?,
        endpoint_url: row.get(3)?,
        endpoint_url_redacted: row.get(4)?,
        endpoint_host: row.get(5)?,
        host_allow,
        hmac_key_id: row.get(7)?,
        enabled: i64_to_bool(row.get(8)?, 8)?,
        max_attempts: i64_to_u64(row.get(9)?)?,
        timeout_ms: i64_to_u64(row.get(10)?)?,
        created_at: row.get(11)?,
        updated_at: row.get(12)?,
    })
}

fn alert_delivery_attempt_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<AlertDeliveryAttemptRecord> {
    Ok(AlertDeliveryAttemptRecord {
        attempt_id: row.get(0)?,
        alert_id: row.get(1)?,
        hook_id: row.get(2)?,
        attempt_no: i64_to_u64(row.get(3)?)?,
        attempted_at: row.get(4)?,
        status: row.get(5)?,
        http_status_class: row.get(6)?,
        error_code: row.get(7)?,
        bytes_sent: i64_to_u64(row.get(8)?)?,
    })
}

fn retention_policy_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RetentionPolicyRecord> {
    let max_age_days: Option<i64> = row.get(1)?;
    let max_rows: Option<i64> = row.get(2)?;
    Ok(RetentionPolicyRecord {
        scope: row.get(0)?,
        max_age_days: max_age_days.map(i64_to_u64).transpose()?,
        max_rows: max_rows.map(i64_to_u64).transpose()?,
        updated_at: row.get(3)?,
    })
}

fn health_policy_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<HealthPolicyRecord> {
    Ok(HealthPolicyRecord {
        stale_window_seconds: i64_to_u64(row.get(0)?)?,
        unreachable_consecutive_failures: i64_to_u64(row.get(1)?)?,
        cert_warning_days: i64_to_u64(row.get(2)?)?,
        cert_critical_days: i64_to_u64(row.get(3)?)?,
        updated_at: row.get(4)?,
    })
}

fn validate_alert_webhook_hook_record(hook: &AlertWebhookHookRecord) -> Result<(), StoreError> {
    validate_description(&hook.name).map_err(StoreError::InvalidInput)?;
    validate_safe_id("hook_id", &hook.hook_id, 128)?;
    validate_safe_id("endpoint_host", &hook.endpoint_host, 253)?;
    validate_safe_id("hmac_key_id", &hook.hmac_key_id, 128)?;
    if hook.hook_type != "webhook" {
        return Err(StoreError::InvalidInput(
            "alert hook type must be webhook".to_string(),
        ));
    }
    if hook.host_allow.is_empty() || hook.host_allow.len() > 16 {
        return Err(StoreError::InvalidInput(
            "alert webhook host allowlist must contain 1-16 hosts".to_string(),
        ));
    }
    for host in &hook.host_allow {
        validate_safe_id("host_allow", host, 253)?;
    }
    validate_u64_range("max_attempts", hook.max_attempts, 1, 5)?;
    validate_u64_range("timeout_ms", hook.timeout_ms, 1_000, 5_000)?;
    Ok(())
}

fn validate_alert_delivery_attempt_record(
    attempt: &AlertDeliveryAttemptRecord,
) -> Result<(), StoreError> {
    validate_safe_id("attempt_id", &attempt.attempt_id, 128)?;
    validate_safe_id("alert_id", &attempt.alert_id, 128)?;
    validate_safe_id("hook_id", &attempt.hook_id, 128)?;
    validate_u64_range("attempt_no", attempt.attempt_no, 1, 5)?;
    validate_u64_range("bytes_sent", attempt.bytes_sent, 0, 1_048_576)?;
    if !matches!(attempt.status.as_str(), "succeeded" | "failed" | "dry_run") {
        return Err(StoreError::InvalidInput(
            "alert delivery attempt status is invalid".to_string(),
        ));
    }
    if let Some(class) = &attempt.http_status_class {
        validate_safe_id("http_status_class", class, 16)?;
    }
    if let Some(error_code) = &attempt.error_code {
        validate_safe_id("error_code", error_code, 64)?;
    }
    Ok(())
}

fn validate_safe_id(field: &'static str, value: &str, max_len: usize) -> Result<(), StoreError> {
    let ok_len = !value.is_empty() && value.len() <= max_len;
    let ok_chars = value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'));
    if ok_len && ok_chars {
        Ok(())
    } else {
        Err(StoreError::InvalidInput(format!(
            "{field} must be 1-{max_len} chars and contain only [a-zA-Z0-9._:-]"
        )))
    }
}

fn validate_health_policy(policy: &HealthPolicyRecord) -> Result<(), StoreError> {
    validate_u64_range(
        "stale_window_seconds",
        policy.stale_window_seconds,
        60,
        2_592_000,
    )?;
    validate_u64_range(
        "unreachable_consecutive_failures",
        policy.unreachable_consecutive_failures,
        1,
        100,
    )?;
    validate_u64_range("cert_warning_days", policy.cert_warning_days, 1, 3_650)?;
    validate_u64_range("cert_critical_days", policy.cert_critical_days, 0, 3_650)?;
    if policy.cert_critical_days > policy.cert_warning_days {
        return Err(StoreError::InvalidInput(
            "cert_critical_days must be less than or equal to cert_warning_days".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_low_sensitive_json(value: &Value, field: &str) -> Result<(), StoreError> {
    const MAX_BYTES: usize = 16 * 1024;
    let encoded = serde_json::to_vec(value)
        .map_err(|err| StoreError::InvalidInput(format!("{field} is invalid JSON: {err}")))?;
    if encoded.len() > MAX_BYTES {
        return Err(StoreError::InvalidInput(format!(
            "{field} exceeds {MAX_BYTES} bytes"
        )));
    }
    let mut entries = 0_usize;
    validate_low_sensitive_json_value(value, field, 0, &mut entries, None)
}

fn validate_low_sensitive_json_value(
    value: &Value,
    field: &str,
    depth: usize,
    entries: &mut usize,
    key_context: Option<&str>,
) -> Result<(), StoreError> {
    const MAX_DEPTH: usize = 8;
    const MAX_ENTRIES: usize = 256;
    const MAX_STRING_BYTES: usize = 512;

    if depth > MAX_DEPTH {
        return Err(StoreError::InvalidInput(format!(
            "{field} exceeds nesting limit"
        )));
    }
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                *entries += 1;
                if *entries > MAX_ENTRIES {
                    return Err(StoreError::InvalidInput(format!(
                        "{field} exceeds entry limit"
                    )));
                }
                if key.len() > 64 || forbidden_stored_key(key) {
                    return Err(StoreError::InvalidInput(format!(
                        "{field} contains a forbidden field"
                    )));
                }
                validate_low_sensitive_json_value(value, field, depth + 1, entries, Some(key))?;
            }
        }
        Value::Array(values) => {
            for value in values {
                *entries += 1;
                if *entries > MAX_ENTRIES {
                    return Err(StoreError::InvalidInput(format!(
                        "{field} exceeds entry limit"
                    )));
                }
                validate_low_sensitive_json_value(value, field, depth + 1, entries, key_context)?;
            }
        }
        Value::String(value) => {
            if value.len() > MAX_STRING_BYTES
                || value
                    .bytes()
                    .any(|byte| !byte.is_ascii() || byte.is_ascii_control())
                || forbidden_stored_value(value, key_context)
            {
                return Err(StoreError::InvalidInput(format!(
                    "{field} contains an unsafe string"
                )));
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn forbidden_stored_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    if matches!(key.as_str(), "token_id" | "hmac_key_id" | "key_id") {
        return false;
    }
    let compact = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>();
    if [
        "body",
        "user_name",
        "client_ip",
        "client_address",
        "ip_address",
        "assigned_vpn_ip",
        "session_id",
        "session_token",
        "certificate_san",
        "certificate_pem",
        "private_key",
        "config_content",
        "provider_selector",
    ]
    .contains(&key.as_str())
    {
        return true;
    }
    if [
        "rawbody",
        "username",
        "clientip",
        "sessionid",
        "sessiontoken",
        "privatekey",
        "apitoken",
        "apikey",
        "hmackey",
        "authorization",
        "bearertoken",
        "stdout",
        "stderr",
    ]
    .iter()
    .any(|marker| compact.contains(marker))
    {
        return true;
    }
    key.split(['_', '-']).any(|segment| {
        matches!(
            segment,
            "raw"
                | "stdout"
                | "stderr"
                | "username"
                | "user"
                | "account"
                | "password"
                | "secret"
                | "credential"
                | "token"
                | "cookie"
                | "authorization"
                | "san"
                | "subject"
                | "issuer"
                | "serial"
                | "command"
                | "shell"
                | "script"
                | "journal"
        )
    })
}

fn forbidden_stored_value(value: &str, key_context: Option<&str>) -> bool {
    let value = value.to_ascii_lowercase();
    if [
        "/etc/",
        "/home/",
        "/users/",
        "/run/secrets/",
        "/var/log",
        "systemctl",
        "journalctl",
        "occtl",
        "shell.exec",
        "command.run",
        "file.read",
        "username",
        "client_ip",
        "session_id",
        "password=",
        "password:",
        "secret=",
        "secret:",
        "token=",
        "token:",
        "authorization:",
        "bearer ",
        "-----begin certificate-----",
        "-----begin private key-----",
    ]
    .iter()
    .any(|marker| value.contains(marker))
    {
        return true;
    }
    let contains_ip = value
        .split(|character: char| !(character.is_ascii_hexdigit() || matches!(character, '.' | ':')))
        .any(|part| {
            let sentence_trimmed = part.trim_end_matches(['.', ':']);
            part.parse::<std::net::IpAddr>().is_ok()
                || part.parse::<std::net::SocketAddr>().is_ok()
                || sentence_trimmed.parse::<std::net::IpAddr>().is_ok()
                || sentence_trimmed.parse::<std::net::SocketAddr>().is_ok()
        });
    contains_ip && !matches!(key_context, Some("endpoint_host" | "host_allow"))
}

fn validate_u64_range(name: &str, value: u64, min: u64, max: u64) -> Result<(), StoreError> {
    if !(min..=max).contains(&value) {
        return Err(StoreError::InvalidInput(format!(
            "{name} must be between {min} and {max}"
        )));
    }
    Ok(())
}

fn health_policy_audit_json(policy: &HealthPolicyRecord) -> Value {
    serde_json::json!({
        "stale_window_seconds": policy.stale_window_seconds,
        "unreachable_consecutive_failures": policy.unreachable_consecutive_failures,
        "cert_warning_days": policy.cert_warning_days,
        "cert_critical_days": policy.cert_critical_days,
    })
}

#[derive(Clone, Copy)]
struct RetentionTarget {
    table: &'static str,
    timestamp_column: &'static str,
}

fn retention_target(scope: &str) -> Result<RetentionTarget, StoreError> {
    match scope {
        "observations" => Ok(RetentionTarget {
            table: "probe_observations",
            timestamp_column: "observed_at",
        }),
        "observability-runs" => Ok(RetentionTarget {
            table: "observability_runs",
            timestamp_column: "started_at",
        }),
        "health-snapshots" => Ok(RetentionTarget {
            table: "health_snapshots",
            timestamp_column: "computed_at",
        }),
        "alert-events" => Ok(RetentionTarget {
            table: "alert_events",
            timestamp_column: "last_seen_at",
        }),
        _ => Err(StoreError::Sqlite(rusqlite::Error::InvalidParameterName(
            scope.to_string(),
        ))),
    }
}

fn retention_candidate_report_for_target(
    conn: &Connection,
    target: RetentionTarget,
    cutoff: Option<&str>,
    max_rows: Option<u64>,
) -> Result<RetentionCandidateReport, StoreError> {
    let (count, oldest, newest): (i64, Option<String>, Option<String>) = match (cutoff, max_rows) {
        (None, None) => {
            return Ok(RetentionCandidateReport {
                matched_count: 0,
                oldest_timestamp: None,
                newest_timestamp: None,
            });
        }
        (Some(cutoff), None) => conn.query_row(
            &format!(
                "SELECT count(*), min({}), max({}) FROM {} WHERE {} < ?1",
                target.timestamp_column,
                target.timestamp_column,
                target.table,
                target.timestamp_column
            ),
            [cutoff],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?,
        (None, Some(max_rows)) => {
            let max_rows = u64_to_i64(max_rows)?;
            conn.query_row(
                &format!(
                    "SELECT count(*), min({}), max({}) FROM {} WHERE rowid IN (
                       SELECT rowid FROM {} ORDER BY {} DESC, rowid DESC LIMIT -1 OFFSET ?1
                     )",
                    target.timestamp_column,
                    target.timestamp_column,
                    target.table,
                    target.table,
                    target.timestamp_column
                ),
                [max_rows],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?
        }
        (Some(cutoff), Some(max_rows)) => {
            let max_rows = u64_to_i64(max_rows)?;
            conn.query_row(
                &format!(
                    "SELECT count(*), min({}), max({}) FROM {} WHERE {} < ?1 OR rowid IN (
                       SELECT rowid FROM {} ORDER BY {} DESC, rowid DESC LIMIT -1 OFFSET ?2
                     )",
                    target.timestamp_column,
                    target.timestamp_column,
                    target.table,
                    target.timestamp_column,
                    target.table,
                    target.timestamp_column
                ),
                params![cutoff, max_rows],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?
        }
    };
    Ok(RetentionCandidateReport {
        matched_count: u64::try_from(count).map_err(|err| {
            StoreError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(err)))
        })?,
        oldest_timestamp: oldest,
        newest_timestamp: newest,
    })
}

fn prune_retention_target(
    tx: &Transaction<'_>,
    target: RetentionTarget,
    cutoff: Option<&str>,
    max_rows: Option<u64>,
) -> Result<u64, StoreError> {
    let mut total = 0_u64;
    loop {
        let deleted = prune_retention_target_batch(tx, target, cutoff, max_rows, 1_000)?;
        if deleted == 0 {
            break;
        }
        total = total.checked_add(deleted).ok_or_else(|| {
            StoreError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(
                io::Error::other("retention delete count overflow"),
            )))
        })?;
    }
    Ok(total)
}

fn prune_retention_target_batch(
    tx: &Transaction<'_>,
    target: RetentionTarget,
    cutoff: Option<&str>,
    max_rows: Option<u64>,
    batch_size: u64,
) -> Result<u64, StoreError> {
    if batch_size == 0 {
        return Ok(0);
    }
    let batch_size = u64_to_i64(batch_size)?;
    let deleted = match (cutoff, max_rows) {
        (None, None) => 0,
        (Some(cutoff), None) => tx.execute(
            &format!(
                "DELETE FROM {} WHERE rowid IN (
                   SELECT rowid FROM {} WHERE {} < ?1
                   ORDER BY {} ASC, rowid ASC LIMIT ?2
                 )",
                target.table, target.table, target.timestamp_column, target.timestamp_column
            ),
            params![cutoff, batch_size],
        )?,
        (None, Some(max_rows)) => {
            let max_rows = u64_to_i64(max_rows)?;
            tx.execute(
                &format!(
                    "DELETE FROM {} WHERE rowid IN (
                       SELECT rowid FROM {} WHERE rowid IN (
                         SELECT rowid FROM {} ORDER BY {} DESC, rowid DESC LIMIT -1 OFFSET ?1
                       )
                       ORDER BY {} ASC, rowid ASC LIMIT ?2
                     )",
                    target.table,
                    target.table,
                    target.table,
                    target.timestamp_column,
                    target.timestamp_column
                ),
                params![max_rows, batch_size],
            )?
        }
        (Some(cutoff), Some(max_rows)) => {
            let max_rows = u64_to_i64(max_rows)?;
            tx.execute(
                &format!(
                    "DELETE FROM {} WHERE rowid IN (
                       SELECT rowid FROM {} WHERE {} < ?1 OR rowid IN (
                         SELECT rowid FROM {} ORDER BY {} DESC, rowid DESC LIMIT -1 OFFSET ?2
                       )
                       ORDER BY {} ASC, rowid ASC LIMIT ?3
                     )",
                    target.table,
                    target.table,
                    target.timestamp_column,
                    target.table,
                    target.timestamp_column,
                    target.timestamp_column
                ),
                params![cutoff, max_rows, batch_size],
            )?
        }
    };
    u64::try_from(deleted)
        .map_err(|err| StoreError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(err))))
}

fn enrollment_token_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EnrollmentTokenRecord> {
    let status: String = row.get(7)?;
    let labels_json: String = row.get(9)?;
    let scope_json: String = row.get(10)?;
    Ok(EnrollmentTokenRecord {
        token_id: row.get(0)?,
        token_hash: row.get(1)?,
        created_at: row.get(2)?,
        created_by: row.get(3)?,
        expires_at: row.get(4)?,
        max_uses: i64_to_u32(row.get(5)?)?,
        used_count: i64_to_u32(row.get(6)?)?,
        status: parse_status(&status, 7)?,
        description: row.get(8)?,
        labels_json: parse_json_column(&labels_json, 9)?,
        scope_json: parse_json_column(&scope_json, 10)?,
    })
}

fn join_request_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<JoinRequestRecord> {
    let status: String = row.get(2)?;
    let requested_labels_json: String = row.get(9)?;
    let approved_labels_json: String = row.get(10)?;
    Ok(JoinRequestRecord {
        request_id: row.get(0)?,
        token_id: row.get(1)?,
        status: parse_status(&status, 2)?,
        agent_public_key: row.get(3)?,
        fingerprint: row.get(4)?,
        requested_endpoint_id: row.get(5)?,
        assigned_endpoint_id: row.get(6)?,
        hostname: row.get(7)?,
        agent_version: row.get(8)?,
        requested_labels_json: parse_json_column(&requested_labels_json, 9)?,
        approved_labels_json: parse_json_column(&approved_labels_json, 10)?,
        created_at: row.get(11)?,
        approved_at: row.get(12)?,
        approved_by: row.get(13)?,
        rejection_reason: row.get(14)?,
        audit_correlation_id: row.get(15)?,
    })
}

fn endpoint_trust_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EndpointTrustRecord> {
    let status: String = row.get(3)?;
    let trust_bundle_json: String = row.get(7)?;
    Ok(EndpointTrustRecord {
        endpoint_id: row.get(0)?,
        node_id: row.get(1)?,
        fingerprint: row.get(2)?,
        status: parse_status(&status, 3)?,
        generation: i64_to_u64(row.get(4)?)?,
        previous_endpoint_id: row.get(5)?,
        rotated_to: row.get(6)?,
        trust_bundle_json: parse_json_column(&trust_bundle_json, 7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

fn parse_json_column(value: &str, column: usize) -> rusqlite::Result<Value> {
    serde_json::from_str(value)
        .map_err(|err| rusqlite::Error::FromSqlConversionFailure(column, Type::Text, Box::new(err)))
}

fn parse_string_array_column(value: &str, column: usize) -> rusqlite::Result<Vec<String>> {
    let value = parse_json_column(value, column)?;
    let Some(values) = value.as_array() else {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            column,
            Type::Text,
            Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected JSON array",
            )),
        ));
    };
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let Some(text) = value.as_str() else {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                column,
                Type::Text,
                Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected JSON string array",
                )),
            ));
        };
        output.push(text.to_string());
    }
    Ok(output)
}

fn compact_json(value: &Value) -> String {
    value.to_string()
}

fn bool_to_i64(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

fn i64_to_bool(value: i64, column: usize) -> rusqlite::Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            column,
            Type::Integer,
            Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid SQLite boolean value: {value}"),
            )),
        )),
    }
}

fn option_u64_to_i64(value: Option<u64>) -> Result<Option<i64>, StoreError> {
    value.map(u64_to_i64).transpose()
}

fn u64_to_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value)
        .map_err(|err| StoreError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(err))))
}

fn usize_to_i64(value: usize) -> Result<i64, StoreError> {
    i64::try_from(value)
        .map_err(|err| StoreError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(err))))
}

fn parse_status<T>(value: &str, column: usize) -> rusqlite::Result<T>
where
    T: FromStr,
    T::Err: std::fmt::Display + Send + Sync + 'static,
{
    value.parse::<T>().map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                err.to_string(),
            )),
        )
    })
}

fn i64_to_u32(value: i64) -> rusqlite::Result<u32> {
    u32::try_from(value)
        .map_err(|err| rusqlite::Error::FromSqlConversionFailure(0, Type::Integer, Box::new(err)))
}

fn i64_to_u64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value)
        .map_err(|err| rusqlite::Error::FromSqlConversionFailure(0, Type::Integer, Box::new(err)))
}
