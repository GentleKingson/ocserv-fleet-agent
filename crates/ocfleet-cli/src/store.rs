use ocfleet_config::validation::{validate_node_id, validate_region, validate_role};
use ocfleet_protocol::enrollment::{
    EndpointStatus, EnrollmentTokenStatus, JoinRequestStatus, TrustBundle,
};
use ocfleet_protocol::method::{
    OCSERV_CERT_EXPIRY, OCSERV_CONFIG_FINGERPRINT, OCSERV_SERVICE_SUMMARY, OCSERV_SESSIONS_SUMMARY,
    OCSERV_VERSION, PROBE_CONTROLLER_PING, PROBE_PATH_ECHO,
};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params, types::Type,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
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
use crate::storage_payloads::{
    AlertDetailPayloadV1, AlertHostAllowPayloadV1, EnrollmentMetadataKindV1,
    EnrollmentMetadataPayloadV1, HealthDegradedMethodsPayloadV1, HealthSummaryPayloadV1,
    ObservationSummaryPayloadV1, RunSummaryPayloadV1, SchedulerPairPayloadV1,
    SchedulerSelectorPayloadV1, TrustBundlePayloadV1, validate_health_payload_relationship,
    validate_scheduler_payload_relationship,
};

pub const CURRENT_SCHEMA_VERSION: i64 = 16;
pub const DEFAULT_HEALTH_STALE_WINDOW_SECONDS: u64 = 24 * 60 * 60;
pub const DEFAULT_HEALTH_UNREACHABLE_FAILURES: u64 = 3;
pub const DEFAULT_HEALTH_CERT_WARNING_DAYS: u64 = 30;
pub const DEFAULT_HEALTH_CERT_CRITICAL_DAYS: u64 = 7;
pub const MAX_SCHEDULER_OUTCOME_ENTRIES: usize = 4;
pub const MAX_ENROLLMENT_TOKEN_USES: u32 = 10_000;
pub const MAX_RETENTION_APPLY_LIMIT: u64 = 100_000;
pub const MAX_RETENTION_BATCH_SIZE: u64 = 1_000;
pub const MAX_RETENTION_POLICY_AGE_DAYS: u64 = 36_500;
pub const MAX_RETENTION_POLICY_ROWS: u64 = 10_000_000;
pub const MAX_HEALTH_SNAPSHOT_WRITE_RECORDS: usize = 1_000;
pub const MAX_ALERT_EVALUATION_RECORDS: usize = 1_000;
pub const MAX_ALERT_DELIVERY_FINALIZE_RECORDS: usize = 1_000;

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
    #[error("node already exists: {0}")]
    NodeAlreadyExists(String),
    #[error("observability job not found: {0}")]
    ObservabilityJobNotFound(String),
    #[error("observability run not found: {0}")]
    ObservabilityRunNotFound(String),
    #[error("observability run is not running: {0}")]
    ObservabilityRunNotRunning(String),
    #[error("enrollment rejected: {0}")]
    EnrollmentRejected(String),
    #[error("enrollment token not found: {0}")]
    EnrollmentTokenNotFound(String),
    #[error("enrollment token conflict for {token_id}: {detail}")]
    EnrollmentTokenConflict {
        token_id: String,
        detail: &'static str,
    },
    #[error("invalid enrollment token transition for {token_id}: {status} cannot {action}")]
    InvalidEnrollmentTokenTransition {
        token_id: String,
        status: String,
        action: &'static str,
    },
    #[error("join request not found: {0}")]
    JoinRequestNotFound(String),
    #[error("enrollment request conflict for {request_id}: {detail}")]
    EnrollmentRequestConflict {
        request_id: String,
        detail: &'static str,
    },
    #[error("retention operation conflict for {operation_id}: {detail}")]
    RetentionOperationConflict {
        operation_id: String,
        detail: &'static str,
    },
    #[error("health evaluation conflict for {evaluation_id}: {detail}")]
    HealthEvaluationConflict {
        evaluation_id: String,
        detail: &'static str,
    },
    #[error("alert evaluation conflict for {evaluation_id}: {detail}")]
    AlertEvaluationConflict {
        evaluation_id: String,
        detail: &'static str,
    },
    #[error("alert mutation conflict for {operation_id}: {detail}")]
    AlertMutationConflict {
        operation_id: String,
        detail: &'static str,
    },
    #[error("join request {request_id} is {status}, expected {expected}")]
    InvalidJoinRequestStatus {
        request_id: String,
        status: String,
        expected: &'static str,
    },
    #[error("enrollment binding rejected for join request {request_id}: {detail}")]
    InvalidEnrollmentBinding {
        request_id: String,
        detail: &'static str,
    },
    #[error("endpoint not found: {0}")]
    EndpointNotFound(String),
    #[error("endpoint already exists: {0}")]
    EndpointAlreadyExists(String),
    #[error("invalid endpoint transition for {endpoint_id}: {from} cannot {action}")]
    InvalidEndpointTransition {
        endpoint_id: String,
        from: String,
        action: &'static str,
    },
    #[error("endpoint binding is inconsistent for {endpoint_id}: {detail}")]
    EndpointBindingMismatch {
        endpoint_id: String,
        detail: &'static str,
    },
    #[error("node {0} has multiple active endpoint bindings")]
    AmbiguousActiveEndpointBinding(String),
    #[error("endpoint generation exhausted: {0}")]
    EndpointGenerationExhausted(String),
    #[error("endpoint rotation lineage is inconsistent: {0}")]
    EndpointLineageInvalid(String),
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
pub struct SchedulerRunStart {
    pub run_id: String,
    pub job_id: String,
    pub started_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerJobClockUpdate {
    pub job_id: String,
    pub next_run_at: String,
    pub last_run_at: String,
}

#[derive(Debug, Clone)]
pub struct SchedulerOutcomeEntry {
    pub observation: ProbeObservationInsert,
    pub audit: AuditEvent,
}

#[derive(Debug, Clone)]
pub struct SchedulerOutcomeWrite {
    pub job_id: String,
    pub run_id: Option<String>,
    pub entries: Vec<SchedulerOutcomeEntry>,
    pub job_clock: Option<SchedulerJobClockUpdate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerRunFinish {
    pub run_id: String,
    pub finished_at: String,
    pub job_clock: SchedulerJobClockUpdate,
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
pub struct HealthSnapshotWrite {
    pub evaluation_id: String,
    pub event: String,
    pub snapshots: Vec<HealthSnapshotRecord>,
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
pub struct AlertEvaluationWrite {
    pub evaluation_id: String,
    pub entries: Vec<AlertEvaluationEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertEvaluationEntry {
    pub before: Option<AlertEventRecord>,
    pub after: AlertEventRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertStateTransition {
    pub operation_id: String,
    pub event: String,
    pub before: AlertEventRecord,
    pub after: AlertEventRecord,
    pub reason: String,
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
pub struct AlertDeliveryAttemptWrite {
    pub attempt: AlertDeliveryAttemptRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertDeliveryFinalizeWrite {
    pub delivery_id: String,
    pub hook_type: String,
    pub ok: bool,
    pub dry_run: bool,
    pub alert_count: usize,
    pub bytes_written: usize,
    pub error_code: Option<String>,
    pub entries: Vec<AlertEvaluationEntry>,
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
pub struct RetentionApplyInput {
    pub operation_id: String,
    pub scope: String,
    pub cutoff: Option<String>,
    pub max_age_days: Option<u64>,
    pub max_rows: Option<u64>,
    pub limit: Option<u64>,
    pub batch_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionApplyResult {
    pub cutoff: Option<String>,
    pub candidate_report: RetentionCandidateReport,
    pub planned_delete_count: u64,
    pub rows_deleted: u64,
    pub batch_count: u64,
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

#[derive(Clone)]
pub struct EnrollmentTokenInsert {
    pub token_id: String,
    pub token_hash: String,
    pub expires_at: String,
    pub max_uses: u32,
    pub description: Option<String>,
    pub labels_json: Value,
    pub scope_json: Value,
}

impl fmt::Debug for EnrollmentTokenInsert {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrollmentTokenInsert")
            .field("token_id", &self.token_id)
            .field("token_hash", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("max_uses", &self.max_uses)
            .field("description_present", &self.description.is_some())
            .field(
                "label_count",
                &self.labels_json.as_object().map_or(0, serde_json::Map::len),
            )
            .field(
                "scope_count",
                &self.scope_json.as_object().map_or(0, serde_json::Map::len),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
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

impl fmt::Debug for EnrollmentTokenRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrollmentTokenRecord")
            .field("token_id", &self.token_id)
            .field("token_hash", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("created_by", &self.created_by)
            .field("expires_at", &self.expires_at)
            .field("max_uses", &self.max_uses)
            .field("used_count", &self.used_count)
            .field("status", &self.status)
            .field("description_present", &self.description.is_some())
            .field(
                "label_count",
                &self.labels_json.as_object().map_or(0, serde_json::Map::len),
            )
            .field(
                "scope_count",
                &self.scope_json.as_object().map_or(0, serde_json::Map::len),
            )
            .finish()
    }
}

#[derive(Clone)]
pub struct JoinRequestInsert {
    pub request_id: String,
    pub token_plaintext: String,
    pub agent_public_key: String,
    pub fingerprint: String,
    pub requested_endpoint_id: Option<String>,
    pub hostname: String,
    pub agent_version: String,
    pub requested_labels_json: Value,
}

impl fmt::Debug for JoinRequestInsert {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JoinRequestInsert")
            .field("request_id", &self.request_id)
            .field("token_plaintext", &"[REDACTED]")
            .field("agent_public_key", &"[REDACTED]")
            .field("fingerprint", &"[REDACTED]")
            .field(
                "requested_endpoint_id_present",
                &self.requested_endpoint_id.is_some(),
            )
            .field("hostname_present", &!self.hostname.is_empty())
            .field("agent_version", &self.agent_version)
            .field(
                "requested_label_count",
                &self
                    .requested_labels_json
                    .as_object()
                    .map_or(0, serde_json::Map::len),
            )
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct ApprovalInput {
    pub request_id: String,
    pub endpoint_id: String,
    pub node_id: String,
    pub region: String,
    pub role: String,
    pub reason: String,
    pub approved_labels_json: Value,
}

#[derive(Debug, Clone)]
pub struct LegacyEnrollmentClaimInput {
    pub request_id: String,
    pub endpoint_id: String,
    pub node_id: String,
    pub region: String,
    pub role: String,
    pub reason: String,
}

#[derive(Clone, PartialEq, Eq)]
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

impl fmt::Debug for JoinRequestRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JoinRequestRecord")
            .field("request_id", &self.request_id)
            .field("token_id", &self.token_id)
            .field("status", &self.status)
            .field("agent_public_key", &"[REDACTED]")
            .field("fingerprint", &"[REDACTED]")
            .field(
                "requested_endpoint_id_present",
                &self.requested_endpoint_id.is_some(),
            )
            .field(
                "assigned_endpoint_id_present",
                &self.assigned_endpoint_id.is_some(),
            )
            .field("hostname_present", &!self.hostname.is_empty())
            .field("agent_version", &self.agent_version)
            .field(
                "requested_label_count",
                &self
                    .requested_labels_json
                    .as_object()
                    .map_or(0, serde_json::Map::len),
            )
            .field(
                "approved_label_count",
                &self
                    .approved_labels_json
                    .as_object()
                    .map_or(0, serde_json::Map::len),
            )
            .field("created_at", &self.created_at)
            .field("approved_at", &self.approved_at)
            .field("approved_by", &self.approved_by)
            .field("rejection_reason", &self.rejection_reason)
            .field("audit_correlation_id", &self.audit_correlation_id)
            .finish()
    }
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
pub(crate) struct EndpointDispatchBinding {
    pub status: EndpointStatus,
    pub trust_node_id: Option<String>,
    pub registry_node_id: Option<String>,
    pub registry_endpoint_id: Option<String>,
    pub registry_enabled: Option<bool>,
    pub active_endpoint_count_for_node: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustSnapshot {
    pub endpoints: Vec<EndpointTrustRecord>,
}

pub struct Store {
    conn: Connection,
    database_path: PathBuf,
}

pub struct StoreOpenResult {
    pub store: Store,
    pub created_database: bool,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let database_path = absolute_database_path(path)?;
        let created_database = create_database_file_if_missing(&database_path)?;
        Self::open_existing_or_create(database_path, created_database)
    }

    pub fn open_with_status(path: &Path) -> Result<StoreOpenResult, StoreError> {
        let database_path = absolute_database_path(path)?;
        let created_database = create_database_file_if_missing(&database_path)?;
        let store = Self::open_existing_or_create(database_path, created_database)?;
        Ok(StoreOpenResult {
            store,
            created_database,
        })
    }

    pub(crate) fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub(crate) fn get_endpoint_dispatch_binding(
        &self,
        expected_node_id: &str,
        endpoint_id: &str,
    ) -> Result<Option<EndpointDispatchBinding>, StoreError> {
        get_endpoint_dispatch_binding_conn(&self.conn, expected_node_id, endpoint_id)
    }

    pub(crate) fn read_endpoint_dispatch_binding(
        database_path: &Path,
        expected_node_id: &str,
        endpoint_id: &str,
    ) -> Result<Option<EndpointDispatchBinding>, StoreError> {
        validate_database_files(database_path)?;
        let conn = Connection::open_with_flags(database_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        conn.pragma_update(None, "query_only", "ON")?;
        conn.pragma_update(None, "busy_timeout", 5_000)?;
        validate_database_files(database_path)?;
        get_endpoint_dispatch_binding_conn(&conn, expected_node_id, endpoint_id)
    }

    fn open_existing_or_create(
        database_path: PathBuf,
        created_database: bool,
    ) -> Result<Self, StoreError> {
        validate_database_files(&database_path)?;
        let mut conn = Connection::open(&database_path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", 5_000)?;

        migrations::migrate_to_current(&mut conn, &database_path, created_database)?;
        validate_database_files(&database_path)?;
        Ok(Self {
            conn,
            database_path,
        })
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

    pub fn insert_observability_job(
        &self,
        job: &ObservabilityJobRecord,
        actor: &str,
    ) -> Result<(), StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_scheduler_job_kind(&job.kind)?;
        let selector = SchedulerSelectorPayloadV1::from_value(&job.selector_json)
            .map_err(StoreError::InvalidInput)?;
        let pair = job
            .pair_selector_json
            .as_ref()
            .map(SchedulerPairPayloadV1::from_value)
            .transpose()
            .map_err(StoreError::InvalidInput)?;
        validate_scheduler_payload_relationship(&job.kind, &selector, pair.as_ref())
            .map_err(StoreError::InvalidInput)?;
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
        let after = get_observability_job_tx(&tx, &job.job_id)?
            .ok_or_else(|| StoreError::ObservabilityJobNotFound(job.job_id.clone()))?;
        let mut event = AuditEvent::new(actor, "scheduler.job.add");
        event.ok = Some(true);
        event.detail_json = scheduler_job_add_audit_detail(&after);
        insert_audit_tx(&tx, &event)?;
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
        actor: &str,
    ) -> Result<(), StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        let tx = self.conn.unchecked_transaction()?;
        let before = get_observability_job_tx(&tx, job_id)?
            .ok_or_else(|| StoreError::ObservabilityJobNotFound(job_id.to_string()))?;
        let affected = tx.execute(
            "UPDATE observability_jobs
             SET enabled = ?1,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
             WHERE job_id = ?2",
            params![bool_to_i64(enabled), job_id],
        )?;
        if affected == 0 {
            return Err(StoreError::ObservabilityJobNotFound(job_id.to_string()));
        }
        let after = get_observability_job_tx(&tx, job_id)?
            .ok_or_else(|| StoreError::ObservabilityJobNotFound(job_id.to_string()))?;
        let event_name = if enabled {
            "scheduler.job.enable"
        } else {
            "scheduler.job.disable"
        };
        let mut event = AuditEvent::new(actor, event_name);
        event.ok = Some(true);
        event.detail_json = scheduler_job_state_audit_detail(&before, &after);
        insert_audit_tx(&tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn write_scheduler_run_start(
        &self,
        start: &SchedulerRunStart,
        actor: &str,
    ) -> Result<(), StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_safe_id("scheduler run_id", &start.run_id, 128)?;
        validate_safe_id("scheduler job_id", &start.job_id, 128)?;
        validate_bounded_rfc3339(&start.started_at, "scheduler started_at")?;

        let tx = self.conn.unchecked_transaction()?;
        let (kind, enabled) = get_observability_job_start_state_tx(&tx, &start.job_id)?
            .ok_or_else(|| StoreError::ObservabilityJobNotFound(start.job_id.clone()))?;
        validate_scheduler_job_kind(&kind)?;
        if !enabled {
            return Err(StoreError::InvalidInput(format!(
                "scheduler job is disabled: {}",
                start.job_id
            )));
        }
        let summary_json = serde_json::json!({
            "job_id": start.job_id,
            "kind": kind,
            "status": "running",
            "result_class": "scheduler_summary",
        });
        insert_observability_run_tx(
            &tx,
            &ObservabilityRunInsert {
                run_id: start.run_id.clone(),
                job_id: Some(start.job_id.clone()),
                started_at: start.started_at.clone(),
                finished_at: None,
                status: "running".to_string(),
                triggered_by: "scheduler.run.once".to_string(),
                summary_json: summary_json.clone(),
            },
        )?;

        let mut event = AuditEvent::new(actor, "scheduler.run.start");
        event.ok = Some(true);
        event.detail_json = serde_json::json!({
            "run_id": start.run_id,
            "job_id": start.job_id,
            "kind": kind,
            "status": "running",
            "result_class": "scheduler_summary",
        });
        insert_audit_tx(&tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn write_scheduler_outcome(
        &self,
        outcome: &SchedulerOutcomeWrite,
        actor: &str,
    ) -> Result<(), StoreError> {
        validate_scheduler_outcome(outcome, actor)?;

        let tx = self.conn.unchecked_transaction()?;
        if let Some(run_id) = outcome.run_id.as_deref() {
            let run = get_observability_run_state_tx(&tx, run_id)?
                .ok_or_else(|| StoreError::ObservabilityRunNotFound(run_id.to_string()))?;
            ensure_running_observability_run(&run)?;
            if run.job_id.as_deref() != Some(outcome.job_id.as_str()) {
                return Err(StoreError::InvalidInput(
                    "scheduler outcome job_id does not match run".to_string(),
                ));
            }
            let kind = get_observability_job_kind_tx(&tx, &outcome.job_id)?
                .ok_or_else(|| StoreError::ObservabilityJobNotFound(outcome.job_id.clone()))?;
            validate_scheduler_job_kind(&kind)?;
            for entry in &outcome.entries {
                if !scheduler_job_kind_allows_method(&kind, &entry.observation.method) {
                    return Err(StoreError::InvalidInput(
                        "scheduler outcome method is not allowed for job kind".to_string(),
                    ));
                }
            }
        } else if !observability_job_exists_tx(&tx, &outcome.job_id)? {
            return Err(StoreError::ObservabilityJobNotFound(outcome.job_id.clone()));
        }

        for entry in &outcome.entries {
            insert_probe_observation_tx(&tx, &entry.observation)?;
            insert_audit_tx(&tx, &entry.audit)?;
        }
        if let Some(clock) = &outcome.job_clock {
            update_scheduler_job_clock_tx(&tx, clock)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn write_scheduler_run_finish(
        &self,
        finish: &SchedulerRunFinish,
        actor: &str,
    ) -> Result<(), StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_safe_id("scheduler run_id", &finish.run_id, 128)?;
        validate_bounded_rfc3339(&finish.finished_at, "scheduler finished_at")?;
        validate_scheduler_job_clock(&finish.job_clock)?;
        if finish.job_clock.last_run_at != finish.finished_at {
            return Err(StoreError::InvalidInput(
                "scheduler last_run_at must equal finished_at".to_string(),
            ));
        }

        let tx = self.conn.unchecked_transaction()?;
        let run = get_observability_run_state_tx(&tx, &finish.run_id)?
            .ok_or_else(|| StoreError::ObservabilityRunNotFound(finish.run_id.clone()))?;
        ensure_running_observability_run(&run)?;
        if run.job_id.as_deref() != Some(finish.job_clock.job_id.as_str()) {
            return Err(StoreError::InvalidInput(
                "scheduler finish job_id does not match run".to_string(),
            ));
        }
        if OffsetDateTime::parse(&finish.finished_at, &Rfc3339)
            .expect("validated scheduler finished_at parses")
            < OffsetDateTime::parse(&run.started_at, &Rfc3339).map_err(|_| {
                StoreError::InvalidInput(
                    "stored scheduler started_at is not bounded RFC3339".to_string(),
                )
            })?
        {
            return Err(StoreError::InvalidInput(
                "scheduler finished_at must not precede started_at".to_string(),
            ));
        }

        let kind = get_observability_job_kind_tx(&tx, &finish.job_clock.job_id)?
            .ok_or_else(|| StoreError::ObservabilityJobNotFound(finish.job_clock.job_id.clone()))?;
        validate_scheduler_job_kind(&kind)?;
        let (observation_count, failed_observation_count) =
            count_observability_run_outcomes_tx(&tx, &finish.run_id)?;
        let status = if observation_count == 0 {
            "skipped"
        } else if failed_observation_count == 0 {
            "succeeded"
        } else {
            "failed"
        };
        let summary_json = serde_json::json!({
            "job_id": finish.job_clock.job_id,
            "kind": kind,
            "status": status,
            "observations": observation_count,
            "failed_observations": failed_observation_count,
            "result_class": "scheduler_summary",
        });
        let summary_json = canonical_run_summary(
            run.job_id.as_deref(),
            Some(&kind),
            status,
            "scheduler.run.once",
            &summary_json,
        )?;
        let affected = tx.execute(
            "UPDATE observability_runs
             SET finished_at = ?1,
                 status = ?2,
                 summary_json = ?3
             WHERE run_id = ?4 AND status = 'running' AND finished_at IS NULL",
            params![
                finish.finished_at.as_str(),
                status,
                compact_json(&summary_json),
                finish.run_id.as_str(),
            ],
        )?;
        if affected != 1 {
            return Err(StoreError::ObservabilityRunNotRunning(
                finish.run_id.clone(),
            ));
        }
        update_scheduler_job_clock_tx(&tx, &finish.job_clock)?;

        let mut event = AuditEvent::new(actor, "scheduler.run.finish");
        event.ok = Some(status != "failed");
        event.detail_json = serde_json::json!({
            "run_id": finish.run_id,
            "job_id": finish.job_clock.job_id,
            "kind": kind,
            "status": status,
            "observations": observation_count,
            "failed_observations": failed_observation_count,
            "result_class": "scheduler_summary",
        });
        insert_audit_tx(&tx, &event)?;
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
        insert_observability_run_tx(&tx, run)?;
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
        let tx = self.conn.unchecked_transaction()?;
        let (job_id, kind, current_status, triggered_by, stored_summary): (
            Option<String>,
            Option<String>,
            String,
            String,
            String,
        ) = tx
            .query_row(
                "SELECT r.job_id, j.kind, r.status, r.triggered_by, r.summary_json
                 FROM observability_runs r
                 LEFT JOIN observability_jobs j ON j.job_id = r.job_id
                 WHERE r.run_id = ?1",
                [run_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| StoreError::ObservabilityRunNotFound(run_id.to_string()))?;
        let stored_value: Value = serde_json::from_str(&stored_summary).map_err(|_| {
            StoreError::InvalidInput("stored run summary JSON is invalid".to_string())
        })?;
        let stored_payload =
            RunSummaryPayloadV1::from_value(&stored_value).map_err(StoreError::InvalidInput)?;
        stored_payload
            .validate_relationship(
                job_id.as_deref(),
                kind.as_deref(),
                &current_status,
                &triggered_by,
            )
            .map_err(StoreError::InvalidInput)?;
        let summary_json = canonical_run_summary(
            job_id.as_deref(),
            kind.as_deref(),
            status,
            &triggered_by,
            summary_json,
        )?;
        tx.execute(
            "UPDATE observability_runs
             SET finished_at = ?1,
                 status = ?2,
                 summary_json = ?3
             WHERE run_id = ?4",
            params![finished_at, status, compact_json(&summary_json), run_id],
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
                    COALESCE(SUM(CASE WHEN o.ok = 0 THEN 1 ELSE 0 END), 0) AS failed_observation_count,
                    j.kind
             FROM observability_runs r
             LEFT JOIN probe_observations o ON o.run_id = r.run_id
             LEFT JOIN observability_jobs j ON j.job_id = r.job_id
             GROUP BY r.run_id, r.job_id, r.started_at, r.finished_at, r.status, r.triggered_by, r.summary_json, j.kind
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
                        COALESCE(SUM(CASE WHEN o.ok = 0 THEN 1 ELSE 0 END), 0) AS failed_observation_count,
                        j.kind
                 FROM observability_runs r
                 LEFT JOIN probe_observations o ON o.run_id = r.run_id
                 LEFT JOIN observability_jobs j ON j.job_id = r.job_id
                 WHERE r.run_id = ?1
                 GROUP BY r.run_id, r.job_id, r.started_at, r.finished_at, r.status, r.triggered_by, r.summary_json, j.kind",
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
        insert_probe_observation_tx(&tx, observation)?;
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

    pub fn write_health_snapshots(
        &self,
        write: &HealthSnapshotWrite,
        actor: &str,
    ) -> Result<(), StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_health_snapshot_write(write)?;
        let params_hash = health_snapshot_write_hash(write);
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        if health_snapshot_replay_tx(&tx, write, actor, &params_hash)? {
            tx.commit()?;
            return Ok(());
        }
        for snapshot in &write.snapshots {
            upsert_health_snapshot_tx(&tx, snapshot)?;
        }
        let mut status_counts = serde_json::Map::new();
        for status in [
            "healthy",
            "degraded",
            "unreachable",
            "stale",
            "disabled",
            "unknown",
        ] {
            status_counts.insert(
                status.to_string(),
                Value::from(
                    write
                        .snapshots
                        .iter()
                        .filter(|snapshot| snapshot.status == status)
                        .count(),
                ),
            );
        }
        let mut event = AuditEvent::new(actor, write.event.clone());
        event.ok = Some(true);
        event.request_id = Some(write.evaluation_id.clone());
        event.params_hash = Some(params_hash);
        event.detail_json = serde_json::json!({
            "actor_type": "user",
            "target_type": "health_snapshot_batch",
            "target_id": write.evaluation_id,
            "node_count": write.snapshots.len(),
            "status_counts": status_counts,
            "reason": Value::Null,
        });
        insert_audit_tx(&tx, &event)?;
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
        validate_alert_event_record(alert)?;
        let tx = self.conn.unchecked_transaction()?;
        upsert_alert_event_tx(&tx, alert)?;
        tx.commit()?;
        Ok(())
    }

    pub fn write_alert_evaluation(
        &self,
        write: &AlertEvaluationWrite,
        actor: &str,
    ) -> Result<(), StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_alert_evaluation_write(write)?;
        let params_hash = alert_evaluation_write_hash(write);
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        if alert_evaluation_replay_tx(&tx, write, actor, &params_hash)? {
            tx.commit()?;
            return Ok(());
        }
        for entry in &write.entries {
            let current = get_alert_event_tx(&tx, &entry.after.dedupe_key)?;
            if normalize_optional_alert(current.as_ref())?
                != normalize_optional_alert(entry.before.as_ref())?
            {
                return Err(StoreError::AlertEvaluationConflict {
                    evaluation_id: write.evaluation_id.clone(),
                    detail: "alert state changed after candidate evaluation",
                });
            }
            upsert_alert_event_tx(&tx, &entry.after)?;
        }
        let open_alerts = write
            .entries
            .iter()
            .filter(|entry| entry.after.state == "open")
            .count();
        let silenced_alerts = write.entries.len() - open_alerts;
        let mut event = AuditEvent::new(actor, "alert.evaluate");
        event.ok = Some(true);
        event.request_id = Some(write.evaluation_id.clone());
        event.params_hash = Some(params_hash);
        event.detail_json = serde_json::json!({
            "actor_type": "user",
            "target_type": "alert_evaluation",
            "target_id": write.evaluation_id,
            "evaluated_candidates": write.entries.len(),
            "upserted_alerts": write.entries.len(),
            "open_alerts": open_alerts,
            "silenced_alerts": silenced_alerts,
            "created_or_updated_count": write.entries.len(),
            "reason": Value::Null,
        });
        insert_audit_tx(&tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn write_alert_state_transition(
        &self,
        write: &AlertStateTransition,
        actor: &str,
    ) -> Result<(), StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_alert_state_transition(write)?;
        let params_hash = alert_state_transition_hash(write);
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        if alert_mutation_replay_tx(&tx, &write.operation_id, &write.event, actor, &params_hash)? {
            tx.commit()?;
            return Ok(());
        }
        let current = get_alert_event_tx(&tx, &write.before.dedupe_key)?;
        if normalize_optional_alert(current.as_ref())?
            != normalize_optional_alert(Some(&write.before))?
        {
            return Err(StoreError::AlertMutationConflict {
                operation_id: write.operation_id.clone(),
                detail: "alert state changed before operator transition",
            });
        }
        upsert_alert_event_tx(&tx, &write.after)?;
        let mut event = AuditEvent::new(actor, write.event.clone());
        event.ok = Some(true);
        event.request_id = Some(write.operation_id.clone());
        event.params_hash = Some(params_hash);
        event.detail_json = serde_json::json!({
            "actor_type": "user",
            "target_type": "alert",
            "target_id": write.after.alert_id,
            "dedupe_key": write.after.dedupe_key,
            "before_state": write.before.state,
            "after_state": write.after.state,
            "reason": write.reason,
        });
        insert_audit_tx(&tx, &event)?;
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

    pub fn write_alert_webhook_hook_create(
        &self,
        hook: &AlertWebhookHookRecord,
        actor: &str,
    ) -> Result<(), StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_alert_webhook_hook_record(hook)?;
        let params_hash = alert_webhook_hook_hash(hook);
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        if alert_mutation_replay_tx(
            &tx,
            &hook.hook_id,
            "alert.hook.add_webhook",
            actor,
            &params_hash,
        )? {
            tx.commit()?;
            return Ok(());
        }
        insert_alert_webhook_hook_tx(&tx, hook)?;
        let mut event = AuditEvent::new(actor, "alert.hook.add_webhook");
        event.ok = Some(true);
        event.request_id = Some(hook.hook_id.clone());
        event.params_hash = Some(params_hash);
        event.detail_json = serde_json::json!({
            "actor_type": "user",
            "target_type": "alert_webhook_hook",
            "target_id": hook.hook_id,
            "hook_type": hook.hook_type,
            "endpoint_host": hook.endpoint_host,
            "hmac_key_id": hook.hmac_key_id,
            "enabled": hook.enabled,
            "max_attempts": hook.max_attempts,
            "timeout_ms": hook.timeout_ms,
            "reason": Value::Null,
        });
        insert_audit_tx(&tx, &event)?;
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

    pub fn write_alert_delivery_attempt(
        &self,
        write: &AlertDeliveryAttemptWrite,
        actor: &str,
    ) -> Result<(), StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_alert_delivery_attempt_record(&write.attempt)?;
        let params_hash = alert_delivery_attempt_hash(&write.attempt);
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        if alert_mutation_replay_tx(
            &tx,
            &write.attempt.attempt_id,
            "alert.delivery.attempt",
            actor,
            &params_hash,
        )? {
            tx.commit()?;
            return Ok(());
        }
        insert_alert_delivery_attempt_tx(&tx, &write.attempt)?;
        let mut event = AuditEvent::new(actor, "alert.delivery.attempt");
        event.ok = Some(write.attempt.status != "failed");
        event.request_id = Some(write.attempt.attempt_id.clone());
        event.params_hash = Some(params_hash);
        event.detail_json = serde_json::json!({
            "actor_type": "user",
            "target_type": "alert_delivery_attempt",
            "target_id": write.attempt.attempt_id,
            "alert_id": write.attempt.alert_id,
            "hook_id": write.attempt.hook_id,
            "attempt_no": write.attempt.attempt_no,
            "status": write.attempt.status,
            "http_status_class": write.attempt.http_status_class,
            "error_code": write.attempt.error_code,
            "bytes_sent": write.attempt.bytes_sent,
            "reason": Value::Null,
        });
        insert_audit_tx(&tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn write_alert_delivery_finalize(
        &self,
        write: &AlertDeliveryFinalizeWrite,
        actor: &str,
    ) -> Result<(), StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_alert_delivery_finalize(write)?;
        let params_hash = alert_delivery_finalize_hash(write);
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        if alert_mutation_replay_tx(
            &tx,
            &write.delivery_id,
            "alert.delivery",
            actor,
            &params_hash,
        )? {
            tx.commit()?;
            return Ok(());
        }
        for entry in &write.entries {
            let current =
                get_alert_event_tx(&tx, &entry.before.as_ref().expect("validated").dedupe_key)?;
            if normalize_optional_alert(current.as_ref())?
                != normalize_optional_alert(entry.before.as_ref())?
            {
                return Err(StoreError::AlertMutationConflict {
                    operation_id: write.delivery_id.clone(),
                    detail: "alert state changed before delivery finalization",
                });
            }
            upsert_alert_event_tx(&tx, &entry.after)?;
        }
        let mut event = AuditEvent::new(actor, "alert.delivery");
        event.ok = Some(write.ok);
        event.request_id = Some(write.delivery_id.clone());
        event.params_hash = Some(params_hash);
        event.detail_json = serde_json::json!({
            "actor_type": "user",
            "target_type": "alert_delivery",
            "target_id": write.delivery_id,
            "ok": write.ok,
            "hook_type": write.hook_type,
            "alert_count": write.alert_count,
            "bytes_written": write.bytes_written,
            "dry_run": write.dry_run,
            "error_code": write.error_code,
            "updated_alerts": write.entries.len(),
            "reason": Value::Null,
        });
        insert_audit_tx(&tx, &event)?;
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

    pub fn set_retention_policy(
        &self,
        policy: &RetentionPolicyRecord,
        actor: &str,
    ) -> Result<RetentionPolicyRecord, StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_retention_policy(policy)?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let before = get_retention_policy_tx(&tx, &policy.scope)?;
        if let Some(existing) = &before
            && existing.max_age_days == policy.max_age_days
            && existing.max_rows == policy.max_rows
        {
            tx.commit()?;
            return Ok(existing.clone());
        }
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
        let after = get_retention_policy_tx(&tx, &policy.scope)?
            .expect("retention policy exists after upsert");
        let mut event = AuditEvent::new(actor, "retention.set");
        event.ok = Some(true);
        event.detail_json = serde_json::json!({
            "actor_type": "user",
            "target_type": "retention_policy",
            "target_id": policy.scope,
            "before": before.as_ref().map(retention_policy_audit_json),
            "after": retention_policy_audit_json(&after),
            "reason": Value::Null,
        });
        insert_audit_tx(&tx, &event)?;
        tx.commit()?;
        Ok(after)
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

    pub fn apply_retention(
        &self,
        input: &RetentionApplyInput,
        actor: &str,
    ) -> Result<RetentionApplyResult, StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_retention_apply_input(input)?;
        let target = retention_target(&input.scope)?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        if let Some(replayed) = retention_apply_replay_tx(&tx, input, actor)? {
            tx.commit()?;
            return Ok(replayed);
        }
        let cutoff = match (&input.cutoff, input.max_age_days) {
            (Some(cutoff), _) => Some(cutoff.clone()),
            (None, Some(days)) => Some(
                (OffsetDateTime::now_utc()
                    - time::Duration::days(i64::try_from(days).map_err(|_| {
                        StoreError::InvalidInput("retention max_age_days is too large".to_string())
                    })?))
                .format(&Rfc3339)
                .expect("RFC3339 formatting succeeds"),
            ),
            (None, None) => None,
        };
        let candidate_report =
            retention_candidate_report_for_target(&tx, target, cutoff.as_deref(), input.max_rows)?;
        let planned_delete_count = input
            .limit
            .map(|limit| candidate_report.matched_count.min(limit))
            .unwrap_or(candidate_report.matched_count);
        let mut rows_deleted = 0_u64;
        let mut batch_count = 0_u64;
        while rows_deleted < planned_delete_count {
            let remaining = planned_delete_count - rows_deleted;
            let deleted = prune_retention_target_batch(
                &tx,
                target,
                cutoff.as_deref(),
                input.max_rows,
                remaining.min(input.batch_size),
            )?;
            if deleted == 0 {
                break;
            }
            rows_deleted = rows_deleted.checked_add(deleted).ok_or_else(|| {
                StoreError::InvalidInput("retention deleted row count overflow".to_string())
            })?;
            batch_count = batch_count.checked_add(1).ok_or_else(|| {
                StoreError::InvalidInput("retention batch count overflow".to_string())
            })?;
        }
        let result = RetentionApplyResult {
            cutoff,
            candidate_report,
            planned_delete_count,
            rows_deleted,
            batch_count,
        };
        let mut event = AuditEvent::new(actor, "retention.apply");
        event.ok = Some(true);
        event.request_id = Some(input.operation_id.clone());
        event.detail_json = retention_apply_audit_json(input, &result);
        insert_audit_tx(&tx, &event)?;
        tx.commit()?;
        Ok(result)
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
        let registry_endpoint_before = get_endpoint_trust_tx(&tx, &before.endpoint_id)?;
        let mut active_candidates = get_active_endpoint_trust_for_node_tx(&tx, node_id)?;
        if let Some(endpoint) = &registry_endpoint_before
            && endpoint.status == EndpointStatus::Active
            && !active_candidates
                .iter()
                .any(|candidate| candidate.endpoint_id == endpoint.endpoint_id)
        {
            active_candidates.push(endpoint.clone());
        }
        if active_candidates.len() > 1 {
            return Err(StoreError::AmbiguousActiveEndpointBinding(
                node_id.to_string(),
            ));
        }

        let active_before = active_candidates.pop();
        if let Some(active) = &active_before
            && let Some(other_node) = get_node_by_endpoint_tx(&tx, &active.endpoint_id)?
            && other_node.node_id != node_id
        {
            return Err(StoreError::EndpointBindingMismatch {
                endpoint_id: active.endpoint_id.clone(),
                detail: "active endpoint is the current endpoint of another node",
            });
        }
        let active_after = active_before
            .as_ref()
            .map(|active| transition_endpoint_status_tx(&tx, active, EndpointStatus::Revoked))
            .transpose()?;
        let registry_endpoint_after = match (&registry_endpoint_before, &active_after) {
            (Some(registry), Some(active)) if registry.endpoint_id == active.endpoint_id => {
                Some(active.clone())
            }
            (registry, _) => registry.clone(),
        };
        let affected = tx.execute("DELETE FROM nodes WHERE node_id = ?1", [node_id])?;
        if affected == 0 {
            return Err(StoreError::NodeNotFound(node_id.to_string()));
        }
        let mut event = AuditEvent::new(actor, "node.remove");
        event.node_id = Some(before.node_id.clone());
        event.endpoint_id = Some(before.endpoint_id.clone());
        event.ok = Some(true);
        event.detail_json = serde_json::json!({
            "actor_type": "user",
            "target_type": "node",
            "target_id": before.node_id,
            "before": node_removal_audit_json(
                Some(&before),
                registry_endpoint_before.as_ref(),
                active_before.as_ref(),
            ),
            "after": node_removal_audit_json(
                None,
                registry_endpoint_after.as_ref(),
                active_after.as_ref(),
            ),
            "reason": Value::Null,
        });
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
        if enabled {
            validate_active_node_binding_tx(&tx, &before)?;
        }
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
    ) -> Result<EnrollmentTokenRecord, StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_enrollment_token_input(token)?;
        if let Some(description) = &token.description {
            validate_description(description).map_err(StoreError::InvalidInput)?;
        }
        validate_label_json(&token.labels_json, "labels").map_err(StoreError::InvalidInput)?;
        validate_label_json(&token.scope_json, "scope").map_err(StoreError::InvalidInput)?;
        validate_low_sensitive_json(&token.labels_json, "enrollment token labels")?;
        validate_low_sensitive_json(&token.scope_json, "enrollment token scope")?;
        let labels = canonical_enrollment_metadata(
            EnrollmentMetadataKindV1::TokenLabels,
            &token.labels_json,
        )?;
        let scope =
            canonical_enrollment_metadata(EnrollmentMetadataKindV1::TokenScope, &token.scope_json)?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        if let Some(existing) = get_enrollment_token_tx(&tx, &token.token_id)? {
            if enrollment_token_matches_create(&existing, token, actor) {
                validate_enrollment_token_audit_provenance_tx(
                    &tx,
                    "enrollment.token.create",
                    &token.token_id,
                    actor,
                    None,
                )?;
                tx.commit()?;
                return Ok(existing);
            }
            return Err(StoreError::EnrollmentTokenConflict {
                token_id: token.token_id.clone(),
                detail: "token id already exists with different issuance metadata",
            });
        }
        if get_enrollment_token_by_hash_tx(&tx, &token.token_hash)?.is_some() {
            return Err(StoreError::EnrollmentTokenConflict {
                token_id: token.token_id.clone(),
                detail: "token credential is already assigned to another token id",
            });
        }
        tx.execute(
            "INSERT INTO enrollment_tokens
             (token_id, token_hash, created_at, created_by, expires_at, max_uses, used_count, status, description, labels_json, scope_json)
             VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%SZ','now'), ?3, ?4, ?5, 0, ?6, ?7, ?8, ?9)",
            params![
                token.token_id.as_str(),
                token.token_hash.as_str(),
                actor,
                token.expires_at.as_str(),
                i64::from(token.max_uses),
                EnrollmentTokenStatus::Active.as_str(),
                token.description.as_deref(),
                labels.to_string(),
                scope.to_string(),
            ],
        )?;
        let after = get_enrollment_token_tx(&tx, &token.token_id)?
            .expect("created enrollment token exists");
        let mut event = AuditEvent::new(actor, "enrollment.token.create");
        event.ok = Some(true);
        event.detail_json =
            enrollment_token_transition_audit_json(&token.token_id, None, Some(&after), None);
        insert_audit_tx(&tx, &event)?;
        tx.commit()?;
        Ok(after)
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

    pub fn revoke_enrollment_token(
        &self,
        token_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<EnrollmentTokenRecord, StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_reason(reason).map_err(StoreError::InvalidInput)?;
        validate_enrollment_token_id(token_id)?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let before = get_enrollment_token_tx(&tx, token_id)?
            .ok_or_else(|| StoreError::EnrollmentTokenNotFound(token_id.to_string()))?;
        match before.status {
            EnrollmentTokenStatus::Revoked => {
                validate_enrollment_token_audit_provenance_tx(
                    &tx,
                    "enrollment.token.revoke",
                    token_id,
                    actor,
                    Some(reason),
                )?;
                tx.commit()?;
                return Ok(before);
            }
            EnrollmentTokenStatus::Expired => {
                return Err(StoreError::InvalidEnrollmentTokenTransition {
                    token_id: token_id.to_string(),
                    status: before.status.as_str().to_string(),
                    action: "revoke",
                });
            }
            EnrollmentTokenStatus::Active => {}
        }
        if token_is_expired(&before.expires_at) {
            return Err(StoreError::InvalidEnrollmentTokenTransition {
                token_id: token_id.to_string(),
                status: EnrollmentTokenStatus::Expired.as_str().to_string(),
                action: "revoke",
            });
        }
        let affected = tx.execute(
            "UPDATE enrollment_tokens SET status = ?1 WHERE token_id = ?2 AND status = ?3",
            params![
                EnrollmentTokenStatus::Revoked.as_str(),
                token_id,
                EnrollmentTokenStatus::Active.as_str(),
            ],
        )?;
        if affected != 1 {
            return Err(StoreError::EnrollmentTokenConflict {
                token_id: token_id.to_string(),
                detail: "token state changed during revocation",
            });
        }
        let after = get_enrollment_token_tx(&tx, token_id)?.expect("revoked token exists");
        let mut event = AuditEvent::new(actor, "enrollment.token.revoke");
        event.ok = Some(true);
        event.detail_json = enrollment_token_transition_audit_json(
            token_id,
            Some(&before),
            Some(&after),
            Some(reason),
        );
        insert_audit_tx(&tx, &event)?;
        tx.commit()?;
        Ok(after)
    }

    pub fn submit_join_request(
        &self,
        request: &JoinRequestInsert,
        actor: &str,
    ) -> Result<JoinRequestRecord, StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_enrollment_request_id(&request.request_id)?;
        validate_enrollment_token_plaintext(&request.token_plaintext)?;
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
        validate_low_sensitive_json(
            &request.requested_labels_json,
            "enrollment requested labels",
        )?;
        let requested_labels = canonical_enrollment_metadata(
            EnrollmentMetadataKindV1::RequestedLabels,
            &request.requested_labels_json,
        )?;
        let approved_labels = canonical_enrollment_metadata(
            EnrollmentMetadataKindV1::ApprovedLabels,
            &serde_json::json!({}),
        )?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let token_hash = Self::hash_enrollment_token(&request.token_plaintext);
        let token = get_enrollment_token_by_hash_tx(&tx, &token_hash)?;
        let Some(token) = token else {
            audit_join_rejection_tx(&tx, actor, Some(&request.request_id), None, "unknown_token")?;
            tx.commit()?;
            return Err(StoreError::EnrollmentRejected("unknown_token".to_string()));
        };

        if let Some(existing) = get_join_request_tx(&tx, &request.request_id)? {
            if join_request_matches_submission(
                &existing,
                request,
                &token.token_id,
                requested_endpoint_id.as_deref(),
            ) {
                validate_join_submission_audit_provenance_tx(&tx, &existing, actor)?;
                tx.commit()?;
                return Ok(existing);
            }
            return Err(StoreError::EnrollmentRequestConflict {
                request_id: request.request_id.clone(),
                detail: "request id already exists with different enrollment input",
            });
        }

        if token.status != EnrollmentTokenStatus::Active {
            let reason = token.status.as_str();
            audit_join_rejection_tx(
                &tx,
                actor,
                Some(&request.request_id),
                Some(&token.token_id),
                reason,
            )?;
            tx.commit()?;
            return Err(StoreError::EnrollmentRejected(reason.to_string()));
        }
        if token_is_expired(&token.expires_at) {
            let affected = tx.execute(
                "UPDATE enrollment_tokens SET status = ?1 WHERE token_id = ?2 AND status = ?3",
                params![
                    EnrollmentTokenStatus::Expired.as_str(),
                    token.token_id.as_str(),
                    EnrollmentTokenStatus::Active.as_str(),
                ],
            )?;
            if affected != 1 {
                return Err(StoreError::EnrollmentTokenConflict {
                    token_id: token.token_id.clone(),
                    detail: "token state changed during expiry",
                });
            }
            let expired = get_enrollment_token_tx(&tx, &token.token_id)?
                .expect("expired enrollment token exists");
            let mut event = AuditEvent::new(actor, "enrollment.token.expire");
            event.ok = Some(true);
            event.request_id = Some(request.request_id.clone());
            event.detail_json = enrollment_token_transition_audit_json(
                &token.token_id,
                Some(&token),
                Some(&expired),
                Some("expired"),
            );
            insert_audit_tx(&tx, &event)?;
            audit_join_rejection_tx(
                &tx,
                actor,
                Some(&request.request_id),
                Some(&token.token_id),
                "expired",
            )?;
            tx.commit()?;
            return Err(StoreError::EnrollmentRejected("expired".to_string()));
        }
        if token.used_count >= token.max_uses {
            audit_join_rejection_tx(
                &tx,
                actor,
                Some(&request.request_id),
                Some(&token.token_id),
                "max_uses_exhausted",
            )?;
            tx.commit()?;
            return Err(StoreError::EnrollmentRejected(
                "max_uses_exhausted".to_string(),
            ));
        }

        let correlation_id = format!("corr-{}", Uuid::new_v4());
        tx.execute(
            "INSERT INTO join_requests
             (request_id, token_id, status, agent_public_key, fingerprint, requested_endpoint_id, assigned_endpoint_id, hostname, agent_version, requested_labels_json, approved_labels_json, created_at, approved_at, approved_by, rejection_reason, audit_correlation_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, ?9, ?10, strftime('%Y-%m-%dT%H:%M:%SZ','now'), NULL, NULL, NULL, ?11)",
            params![
                request.request_id.as_str(),
                token.token_id.as_str(),
                JoinRequestStatus::Pending.as_str(),
                request.agent_public_key.as_str(),
                request.fingerprint.as_str(),
                requested_endpoint_id.as_deref(),
                request.hostname.as_str(),
                request.agent_version.as_str(),
                requested_labels.to_string(),
                approved_labels.to_string(),
                correlation_id.as_str(),
            ],
        )?;
        let affected = tx.execute(
            "UPDATE enrollment_tokens
             SET used_count = used_count + 1
             WHERE token_id = ?1 AND status = ?2 AND used_count = ?3 AND used_count < max_uses",
            params![
                token.token_id.as_str(),
                EnrollmentTokenStatus::Active.as_str(),
                i64::from(token.used_count),
            ],
        )?;
        if affected != 1 {
            return Err(StoreError::EnrollmentTokenConflict {
                token_id: token.token_id.clone(),
                detail: "token use count changed during request submission",
            });
        }

        let mut event = AuditEvent::new(actor, "enrollment.token.use");
        event.ok = Some(true);
        event.request_id = Some(request.request_id.clone());
        let joined = get_join_request_tx(&tx, &request.request_id)?.expect("join request inserted");
        let token_after =
            get_enrollment_token_tx(&tx, &token.token_id)?.expect("used enrollment token exists");
        event.detail_json = enrollment_token_use_audit_json(&token, &token_after, &joined);
        insert_audit_tx(&tx, &event)?;
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

    pub fn reject_join_request(
        &self,
        request_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<JoinRequestRecord, StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_reason(reason).map_err(StoreError::InvalidInput)?;
        validate_enrollment_request_id(request_id)?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let before = get_join_request_tx(&tx, request_id)?
            .ok_or_else(|| StoreError::JoinRequestNotFound(request_id.to_string()))?;
        if before.status == JoinRequestStatus::Rejected {
            if before.rejection_reason.as_deref() != Some(reason) {
                return Err(StoreError::EnrollmentRequestConflict {
                    request_id: request_id.to_string(),
                    detail: "request was already rejected for a different reason",
                });
            }
            validate_join_rejection_audit_provenance_tx(&tx, request_id, actor, reason)?;
            tx.commit()?;
            return Ok(before);
        }
        if before.status != JoinRequestStatus::Pending {
            return Err(StoreError::InvalidJoinRequestStatus {
                request_id: request_id.to_string(),
                status: before.status.as_str().to_string(),
                expected: "pending",
            });
        }
        validate_pending_join_for_approval(&before)?;
        let affected = tx.execute(
            "UPDATE join_requests
             SET status = ?1, rejection_reason = ?2
             WHERE request_id = ?3 AND status = ?4",
            params![
                JoinRequestStatus::Rejected.as_str(),
                reason,
                request_id,
                JoinRequestStatus::Pending.as_str(),
            ],
        )?;
        if affected != 1 {
            return Err(StoreError::EnrollmentRequestConflict {
                request_id: request_id.to_string(),
                detail: "request state changed during rejection",
            });
        }
        let after = get_join_request_tx(&tx, request_id)?.expect("rejected join request exists");
        let mut event = AuditEvent::new(actor, "enrollment.reject");
        event.ok = Some(true);
        event.request_id = Some(request_id.to_string());
        event.detail_json =
            enrollment_request_transition_audit_json(request_id, &before, &after, reason);
        insert_audit_tx(&tx, &event)?;
        tx.commit()?;
        Ok(after)
    }

    pub fn approve_join_request(
        &self,
        approval: &ApprovalInput,
        actor: &str,
    ) -> Result<JoinRequestRecord, StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_reason(&approval.reason).map_err(StoreError::InvalidInput)?;
        validate_enrollment_request_id(&approval.request_id)?;
        let node = enrollment_node_insert(
            &approval.node_id,
            &approval.endpoint_id,
            &approval.region,
            &approval.role,
        )?;
        validate_label_json(&approval.approved_labels_json, "approved_labels")
            .map_err(StoreError::InvalidInput)?;
        let approved_labels = canonical_enrollment_metadata(
            EnrollmentMetadataKindV1::ApprovedLabels,
            &approval.approved_labels_json,
        )?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let before = get_join_request_tx(&tx, &approval.request_id)?
            .ok_or_else(|| StoreError::JoinRequestNotFound(approval.request_id.clone()))?;

        if before.status == JoinRequestStatus::Approved {
            validate_approved_join_provenance_tx(&tx, &before, &node.endpoint_id)?;
            let endpoint = get_endpoint_trust_tx(&tx, &node.endpoint_id)?.ok_or_else(|| {
                invalid_enrollment_binding(
                    &approval.request_id,
                    "approved endpoint trust is missing",
                )
            })?;
            validate_enrollment_endpoint_origin(&before, &endpoint, &approval.request_id)?;
            if endpoint.node_id.is_none() {
                validate_approved_join_audit_provenance_tx(&tx, &before, &node.endpoint_id, None)?;
                return Err(invalid_enrollment_binding(
                    &approval.request_id,
                    "legacy claim required",
                ));
            }
            validate_approved_join_audit_provenance_tx(
                &tx,
                &before,
                &node.endpoint_id,
                Some(&node.node_id),
            )?;
            validate_exact_enrollment_binding_tx(
                &tx,
                &before,
                &endpoint,
                &node,
                Some(&approval.approved_labels_json),
                "approval retry does not match the existing binding",
            )?;
            tx.commit()?;
            return Ok(before);
        }

        if before.status != JoinRequestStatus::Pending {
            return Err(StoreError::InvalidJoinRequestStatus {
                request_id: approval.request_id.clone(),
                status: before.status.as_str().to_string(),
                expected: "pending",
            });
        }
        validate_pending_join_for_approval(&before)?;
        if before
            .requested_endpoint_id
            .as_deref()
            .is_some_and(|requested| requested != node.endpoint_id)
        {
            return Err(invalid_enrollment_binding(
                &approval.request_id,
                "approved endpoint does not match requested endpoint",
            ));
        }
        if get_node_tx(&tx, &node.node_id)?.is_some() {
            return Err(StoreError::NodeAlreadyExists(node.node_id));
        }
        if get_node_by_endpoint_tx(&tx, &node.endpoint_id)?.is_some() {
            return Err(StoreError::EndpointAlreadyExists(node.endpoint_id));
        }
        if get_endpoint_trust_tx(&tx, &node.endpoint_id)?.is_some() {
            return Err(StoreError::EndpointAlreadyExists(node.endpoint_id));
        }
        if endpoint_trust_count_for_node_tx(&tx, &node.node_id)? != 0 {
            return Err(invalid_enrollment_binding(
                &approval.request_id,
                "node id has existing endpoint trust history",
            ));
        }

        insert_node_tx(&tx, &node)?;
        insert_endpoint_trust_tx(
            &tx,
            &EndpointTrustRecord {
                endpoint_id: node.endpoint_id.clone(),
                node_id: Some(node.node_id.clone()),
                fingerprint: Some(before.fingerprint.clone()),
                status: EndpointStatus::Active,
                generation: 1,
                previous_endpoint_id: None,
                rotated_to: None,
                trust_bundle_json: trust_bundle_json(&node.endpoint_id, 1, EndpointStatus::Active),
                created_at: String::new(),
                updated_at: String::new(),
            },
        )?;
        let affected = tx.execute(
            "UPDATE join_requests
             SET status = ?1,
                 assigned_endpoint_id = ?2,
                 approved_labels_json = ?3,
                 approved_at = strftime('%Y-%m-%dT%H:%M:%SZ','now'),
                 approved_by = ?4
             WHERE request_id = ?5 AND status = ?6",
            params![
                JoinRequestStatus::Approved.as_str(),
                node.endpoint_id.as_str(),
                approved_labels.to_string(),
                actor,
                approval.request_id.as_str(),
                JoinRequestStatus::Pending.as_str(),
            ],
        )?;
        if affected != 1 {
            return Err(invalid_enrollment_binding(
                &approval.request_id,
                "join request changed during approval",
            ));
        }
        let after =
            get_join_request_tx(&tx, &approval.request_id)?.expect("approved request exists");
        let node_after = get_node_tx(&tx, &node.node_id)?.expect("approved node exists");
        let endpoint_after =
            get_endpoint_trust_tx(&tx, &node.endpoint_id)?.expect("approved endpoint trust exists");
        validate_exact_enrollment_binding_tx(
            &tx,
            &after,
            &endpoint_after,
            &node,
            Some(&approval.approved_labels_json),
            "approved binding is inconsistent",
        )?;
        audit_enrollment_binding_tx(
            &tx,
            actor,
            "enrollment.approve",
            &approval.request_id,
            &before,
            &after,
            None,
            Some(&node_after),
            None,
            Some(&endpoint_after),
            &approval.reason,
        )?;
        tx.commit()?;
        Ok(after)
    }

    pub fn claim_legacy_enrollment(
        &self,
        claim: &LegacyEnrollmentClaimInput,
        actor: &str,
    ) -> Result<JoinRequestRecord, StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_reason(&claim.reason).map_err(StoreError::InvalidInput)?;
        validate_enrollment_request_id(&claim.request_id)?;
        let node = enrollment_node_insert(
            &claim.node_id,
            &claim.endpoint_id,
            &claim.region,
            &claim.role,
        )?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let join = get_join_request_tx(&tx, &claim.request_id)?
            .ok_or_else(|| StoreError::JoinRequestNotFound(claim.request_id.clone()))?;
        if join.status != JoinRequestStatus::Approved {
            return Err(StoreError::InvalidJoinRequestStatus {
                request_id: claim.request_id.clone(),
                status: join.status.as_str().to_string(),
                expected: "approved",
            });
        }
        validate_approved_join_provenance_tx(&tx, &join, &node.endpoint_id)?;
        validate_approved_join_audit_provenance_tx(&tx, &join, &node.endpoint_id, None)?;
        let endpoint_before = get_endpoint_trust_tx(&tx, &node.endpoint_id)?.ok_or_else(|| {
            invalid_enrollment_binding(&claim.request_id, "approved endpoint trust is missing")
        })?;
        validate_enrollment_endpoint_origin(&join, &endpoint_before, &claim.request_id)?;

        if endpoint_before.node_id.is_some() {
            validate_enrollment_claim_audit_provenance_tx(
                &tx,
                &join,
                &node.endpoint_id,
                &node.node_id,
            )?;
            validate_exact_enrollment_binding_tx(
                &tx,
                &join,
                &endpoint_before,
                &node,
                None,
                "claim retry does not match the existing binding",
            )?;
            tx.commit()?;
            return Ok(join);
        }
        if get_node_tx(&tx, &node.node_id)?.is_some() {
            return Err(StoreError::NodeAlreadyExists(node.node_id));
        }
        if get_node_by_endpoint_tx(&tx, &node.endpoint_id)?.is_some() {
            return Err(StoreError::EndpointAlreadyExists(node.endpoint_id));
        }
        if endpoint_trust_count_for_node_tx(&tx, &node.node_id)? != 0 {
            return Err(invalid_enrollment_binding(
                &claim.request_id,
                "node id has existing endpoint trust history",
            ));
        }

        insert_node_tx(&tx, &node)?;
        let affected = tx.execute(
            "UPDATE endpoint_trust
             SET node_id = ?1,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
             WHERE endpoint_id = ?2
               AND node_id IS NULL
               AND status = 'active'
               AND generation = 1
               AND previous_endpoint_id IS NULL
               AND rotated_to IS NULL
               AND fingerprint = ?3",
            params![
                node.node_id.as_str(),
                node.endpoint_id.as_str(),
                join.fingerprint.as_str(),
            ],
        )?;
        if affected != 1 {
            return Err(invalid_enrollment_binding(
                &claim.request_id,
                "legacy endpoint trust changed during claim",
            ));
        }
        let node_after = get_node_tx(&tx, &node.node_id)?.expect("claimed node exists");
        let endpoint_after =
            get_endpoint_trust_tx(&tx, &node.endpoint_id)?.expect("claimed endpoint trust exists");
        validate_exact_enrollment_binding_tx(
            &tx,
            &join,
            &endpoint_after,
            &node,
            None,
            "claimed binding is inconsistent",
        )?;
        audit_enrollment_binding_tx(
            &tx,
            actor,
            "enrollment.claim",
            &claim.request_id,
            &join,
            &join,
            None,
            Some(&node_after),
            Some(&endpoint_before),
            Some(&endpoint_after),
            &claim.reason,
        )?;
        tx.commit()?;
        Ok(join)
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
        if old_endpoint_id == new_endpoint_id {
            return Err(StoreError::InvalidInput(
                "new endpoint_id must differ from old endpoint_id".to_string(),
            ));
        }
        let tx = self.conn.unchecked_transaction()?;
        let old_before = get_endpoint_trust_tx(&tx, &old_endpoint_id)?
            .ok_or_else(|| StoreError::EndpointNotFound(old_endpoint_id.clone()))?;
        validate_endpoint_bundle_projection(&old_before)?;

        if old_before.status == EndpointStatus::Rotated {
            if old_before.rotated_to.as_deref() != Some(new_endpoint_id.as_str()) {
                return Err(invalid_endpoint_transition(
                    &old_before,
                    "rotate to a different endpoint",
                ));
            }
            let new_after = get_endpoint_trust_tx(&tx, &new_endpoint_id)?
                .ok_or_else(|| StoreError::EndpointLineageInvalid(old_endpoint_id.clone()))?;
            validate_rotation_edge(&tx, &old_before, &new_after)?;
            let Some(node_id) = old_before.node_id.as_deref() else {
                return Err(StoreError::EndpointBindingMismatch {
                    endpoint_id: old_endpoint_id.clone(),
                    detail: "unbound rotation edge cannot be retried",
                });
            };
            let node_before =
                get_node_tx(&tx, node_id)?.ok_or_else(|| StoreError::EndpointBindingMismatch {
                    endpoint_id: old_endpoint_id.clone(),
                    detail: "bound node is missing",
                })?;
            validate_legacy_rotation_reconciliation_tx(&tx, node_id, &new_after)?;
            if node_before.endpoint_id == new_endpoint_id {
                if new_after.status != EndpointStatus::Active && node_before.enabled {
                    return Err(StoreError::EndpointBindingMismatch {
                        endpoint_id: new_endpoint_id.clone(),
                        detail: "inactive rotated endpoint is bound to an enabled node",
                    });
                }
                return Ok(new_after);
            }
            if node_before.endpoint_id != old_endpoint_id {
                return Err(StoreError::EndpointBindingMismatch {
                    endpoint_id: old_endpoint_id.clone(),
                    detail: "bound node does not point to the old or rotated endpoint",
                });
            }
            let disable = new_after.status != EndpointStatus::Active;
            let affected = tx.execute(
                "UPDATE nodes
                 SET endpoint_id = ?1,
                     enabled = CASE WHEN ?2 THEN 0 ELSE enabled END,
                     updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
                 WHERE node_id = ?3 AND endpoint_id = ?4",
                params![
                    new_endpoint_id.as_str(),
                    bool_to_i64(disable),
                    node_id,
                    old_endpoint_id.as_str(),
                ],
            )?;
            if affected != 1 {
                return Err(StoreError::EndpointBindingMismatch {
                    endpoint_id: old_endpoint_id.clone(),
                    detail: "legacy registry pointer changed during reconciliation",
                });
            }
            let node_after = get_node_tx(&tx, node_id)?.expect("reconciled node exists");
            audit_endpoint_rotation_tx(
                &tx,
                actor,
                "endpoint.rotate.reconcile",
                &old_endpoint_id,
                Some(&node_before),
                Some(&node_after),
                &old_before,
                &old_before,
                &new_after,
                reason,
            )?;
            tx.commit()?;
            return Ok(new_after);
        }

        if !matches!(
            old_before.status,
            EndpointStatus::Active | EndpointStatus::Quarantined
        ) {
            return Err(invalid_endpoint_transition(&old_before, "rotate"));
        }
        if get_endpoint_trust_tx(&tx, &new_endpoint_id)?.is_some() {
            return Err(StoreError::EndpointAlreadyExists(new_endpoint_id));
        }
        validate_unrotated_lineage(&tx, &old_before)?;
        let node_before = validate_rotation_binding_tx(&tx, &old_before)?;
        let new_generation = next_endpoint_generation(&old_before)?;
        let affected = tx.execute(
            "UPDATE endpoint_trust
             SET status = ?1,
                 generation = ?2,
                 rotated_to = ?3,
                 trust_bundle_json = ?4,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
             WHERE endpoint_id = ?5",
            params![
                EndpointStatus::Rotated.as_str(),
                endpoint_generation_to_i64(&old_endpoint_id, new_generation)?,
                new_endpoint_id.as_str(),
                canonical_trust_bundle(
                    &old_endpoint_id,
                    new_generation,
                    EndpointStatus::Rotated,
                    &trust_bundle_json(&old_endpoint_id, new_generation, EndpointStatus::Rotated,),
                )?
                .to_string(),
                old_endpoint_id.as_str(),
            ],
        )?;
        if affected != 1 {
            return Err(StoreError::EndpointNotFound(old_endpoint_id));
        }
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
        let node_after = if let Some(node_before) = &node_before {
            let affected = tx.execute(
                "UPDATE nodes
                 SET endpoint_id = ?1,
                     enabled = CASE WHEN ?2 THEN 0 ELSE enabled END,
                     updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
                 WHERE node_id = ?3 AND endpoint_id = ?4",
                params![
                    new_endpoint_id.as_str(),
                    bool_to_i64(old_before.status == EndpointStatus::Quarantined),
                    node_before.node_id.as_str(),
                    old_endpoint_id.as_str(),
                ],
            )?;
            if affected != 1 {
                return Err(StoreError::EndpointBindingMismatch {
                    endpoint_id: old_endpoint_id.clone(),
                    detail: "bound node endpoint changed during rotation",
                });
            }
            get_node_tx(&tx, &node_before.node_id)?
        } else {
            None
        };
        let old_after = get_endpoint_trust_tx(&tx, &old_endpoint_id)?.expect("old endpoint exists");
        let new_after = get_endpoint_trust_tx(&tx, &new_endpoint_id)?.expect("new endpoint exists");
        audit_endpoint_rotation_tx(
            &tx,
            actor,
            "endpoint.rotate",
            &old_endpoint_id,
            node_before.as_ref(),
            node_after.as_ref(),
            &old_before,
            &old_after,
            &new_after,
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
        action: &'static str,
    ) -> Result<EndpointTrustRecord, StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        validate_reason(reason).map_err(StoreError::InvalidInput)?;
        let endpoint_id = validate_endpoint_id(endpoint_id).map_err(StoreError::InvalidInput)?;
        let tx = self.conn.unchecked_transaction()?;
        let before = get_endpoint_trust_tx(&tx, &endpoint_id)?
            .ok_or_else(|| StoreError::EndpointNotFound(endpoint_id.clone()))?;
        validate_endpoint_bundle_projection(&before)?;
        if before.status == status {
            validate_unrotated_lineage(&tx, &before)?;
            return Ok(before);
        }
        let allowed = matches!(
            (before.status, status),
            (EndpointStatus::Active, EndpointStatus::Revoked)
                | (EndpointStatus::Active, EndpointStatus::Quarantined)
                | (EndpointStatus::Quarantined, EndpointStatus::Revoked)
        );
        if !allowed {
            let transition_action = action.strip_prefix("endpoint.").unwrap_or(action);
            return Err(invalid_endpoint_transition(&before, transition_action));
        }
        let node_before = get_exact_bound_node_tx(&tx, &before)?;
        let after = transition_endpoint_status_tx(&tx, &before, status)?;
        let node_after = if let Some(node) = &node_before
            && node.enabled
        {
            let affected = tx.execute(
                "UPDATE nodes
                 SET enabled = 0,
                     updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
                 WHERE node_id = ?1 AND endpoint_id = ?2",
                params![node.node_id.as_str(), endpoint_id.as_str()],
            )?;
            if affected != 1 {
                return Err(StoreError::EndpointBindingMismatch {
                    endpoint_id: endpoint_id.clone(),
                    detail: "bound node changed during endpoint status update",
                });
            }
            get_node_tx(&tx, &node.node_id)?
        } else {
            node_before.clone()
        };
        audit_endpoint_status_tx(
            &tx,
            actor,
            action,
            &endpoint_id,
            node_before.as_ref(),
            node_after.as_ref(),
            &before,
            &after,
            reason,
        )?;
        tx.commit()?;
        Ok(after)
    }
}

#[derive(Debug)]
struct ObservabilityRunState {
    run_id: String,
    job_id: Option<String>,
    started_at: String,
    finished_at: Option<String>,
    status: String,
}

fn validate_scheduler_outcome(
    outcome: &SchedulerOutcomeWrite,
    actor: &str,
) -> Result<(), StoreError> {
    validate_actor(actor).map_err(StoreError::InvalidInput)?;
    validate_safe_id("scheduler job_id", &outcome.job_id, 128)?;
    if outcome.entries.is_empty() || outcome.entries.len() > MAX_SCHEDULER_OUTCOME_ENTRIES {
        return Err(StoreError::InvalidInput(format!(
            "scheduler outcome must contain 1-{MAX_SCHEDULER_OUTCOME_ENTRIES} entries"
        )));
    }

    match outcome.run_id.as_deref() {
        Some(run_id) => {
            validate_safe_id("scheduler run_id", run_id, 128)?;
            if outcome.job_clock.is_some() {
                return Err(StoreError::InvalidInput(
                    "run-bound scheduler outcome cannot update job clocks".to_string(),
                ));
            }
            for entry in &outcome.entries {
                if entry.observation.run_id.as_deref() != Some(run_id) {
                    return Err(StoreError::InvalidInput(
                        "scheduler outcome contains a mismatched run_id".to_string(),
                    ));
                }
                if !matches!(
                    entry.audit.event.as_str(),
                    "rpc.completed" | "scheduler.task.outcome"
                ) {
                    return Err(StoreError::InvalidInput(
                        "run-bound scheduler outcome audit event is invalid".to_string(),
                    ));
                }
            }
        }
        None => {
            if outcome.entries.len() != 1
                || outcome.entries[0].observation.run_id.is_some()
                || outcome.entries[0].audit.event != "scheduler.job.invalid"
                || outcome.entries[0].observation.ok != Some(false)
                || outcome.entries[0].observation.error_code.as_deref()
                    != Some("SCHEDULER_JOB_INVALID")
            {
                return Err(StoreError::InvalidInput(
                    "runless scheduler outcome must contain one failed scheduler.job.invalid entry"
                        .to_string(),
                ));
            }
        }
    }

    if let Some(clock) = &outcome.job_clock {
        validate_scheduler_job_clock(clock)?;
        if clock.job_id != outcome.job_id {
            return Err(StoreError::InvalidInput(
                "scheduler outcome clock job_id does not match outcome".to_string(),
            ));
        }
    }
    for entry in &outcome.entries {
        validate_scheduler_observation(&entry.observation)?;
        validate_scheduler_outcome_audit(&entry.audit, &entry.observation, actor)?;
    }
    Ok(())
}

fn validate_scheduler_observation(observation: &ProbeObservationInsert) -> Result<(), StoreError> {
    validate_safe_id("scheduler observation_id", &observation.observation_id, 128)?;
    if let Some(run_id) = &observation.run_id {
        validate_safe_id("scheduler observation run_id", run_id, 128)?;
    }
    if let Some(node_id) = &observation.node_id {
        validate_safe_id("scheduler observation node_id", node_id, 128)?;
    }
    if let Some(endpoint_id) = &observation.endpoint_id {
        validate_safe_id("scheduler observation endpoint_id", endpoint_id, 128)?;
    }
    if !matches!(
        observation.method.as_str(),
        PROBE_CONTROLLER_PING
            | PROBE_PATH_ECHO
            | OCSERV_SERVICE_SUMMARY
            | OCSERV_VERSION
            | OCSERV_SESSIONS_SUMMARY
            | OCSERV_CERT_EXPIRY
            | OCSERV_CONFIG_FINGERPRINT
    ) {
        return Err(StoreError::InvalidInput(
            "scheduler observation method is invalid".to_string(),
        ));
    }
    if let Some(error_code) = &observation.error_code {
        validate_safe_id("scheduler observation error_code", error_code, 64)?;
    }
    if observation.ok.is_none() || observation.duration_ms.is_none() {
        return Err(StoreError::InvalidInput(
            "scheduler observation ok and duration_ms are required".to_string(),
        ));
    }
    if matches!(observation.ok, Some(true)) && observation.error_code.is_some()
        || matches!(observation.ok, Some(false)) && observation.error_code.is_none()
    {
        return Err(StoreError::InvalidInput(
            "scheduler observation result and error_code are inconsistent".to_string(),
        ));
    }
    validate_bounded_rfc3339(&observation.observed_at, "scheduler observed_at")?;
    if let Some(expires_at) = &observation.expires_at {
        validate_bounded_rfc3339(expires_at, "scheduler expires_at")?;
    }
    if !matches!(
        observation.result_class.as_str(),
        "controller_rpc_summary" | "low_sensitive_summary" | "scheduler_summary"
    ) {
        return Err(StoreError::InvalidInput(
            "scheduler observation result_class is invalid".to_string(),
        ));
    }
    validate_low_sensitive_json(&observation.summary_json, "observation summary")
}

fn validate_scheduler_outcome_audit(
    audit: &AuditEvent,
    observation: &ProbeObservationInsert,
    actor: &str,
) -> Result<(), StoreError> {
    if audit.actor != actor {
        return Err(StoreError::InvalidInput(
            "scheduler outcome audit actor does not match writer actor".to_string(),
        ));
    }
    if audit.node_id != observation.node_id
        || audit.endpoint_id != observation.endpoint_id
        || audit.method.as_deref() != Some(observation.method.as_str())
        || audit.ok != observation.ok
        || audit.duration_ms != observation.duration_ms
    {
        return Err(StoreError::InvalidInput(
            "scheduler outcome audit fields do not match observation".to_string(),
        ));
    }
    if matches!(audit.ok, Some(true)) && audit.error_code.is_some()
        || matches!(audit.ok, Some(false)) && audit.error_code.is_none()
    {
        return Err(StoreError::InvalidInput(
            "scheduler outcome audit result and error_code are inconsistent".to_string(),
        ));
    }
    if audit.event != "rpc.completed" && audit.error_code != observation.error_code {
        return Err(StoreError::InvalidInput(
            "scheduler outcome audit error_code does not match observation".to_string(),
        ));
    }
    Ok(())
}

fn validate_scheduler_job_clock(clock: &SchedulerJobClockUpdate) -> Result<(), StoreError> {
    validate_safe_id("scheduler clock job_id", &clock.job_id, 128)?;
    let next_run_at = validate_bounded_rfc3339(&clock.next_run_at, "scheduler next_run_at")?;
    let last_run_at = validate_bounded_rfc3339(&clock.last_run_at, "scheduler last_run_at")?;
    if next_run_at <= last_run_at {
        return Err(StoreError::InvalidInput(
            "scheduler next_run_at must be later than last_run_at".to_string(),
        ));
    }
    Ok(())
}

fn validate_bounded_rfc3339(
    value: &str,
    field: &'static str,
) -> Result<OffsetDateTime, StoreError> {
    if value.is_empty() || value.len() > 64 {
        return Err(StoreError::InvalidInput(format!(
            "{field} must be bounded RFC3339"
        )));
    }
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| StoreError::InvalidInput(format!("{field} must be bounded RFC3339")))
}

fn validate_scheduler_job_kind(kind: &str) -> Result<(), StoreError> {
    if matches!(
        kind,
        "controller-ping" | "ocserv-status" | "ocserv-cert" | "ocserv-sessions" | "path-probe"
    ) {
        Ok(())
    } else {
        Err(StoreError::InvalidInput(
            "scheduler job kind is invalid".to_string(),
        ))
    }
}

fn scheduler_job_kind_allows_method(kind: &str, method: &str) -> bool {
    match kind {
        "controller-ping" => method == PROBE_CONTROLLER_PING,
        "ocserv-status" => matches!(
            method,
            OCSERV_SERVICE_SUMMARY
                | OCSERV_VERSION
                | OCSERV_SESSIONS_SUMMARY
                | OCSERV_CONFIG_FINGERPRINT
        ),
        "ocserv-cert" => method == OCSERV_CERT_EXPIRY,
        "ocserv-sessions" => method == OCSERV_SESSIONS_SUMMARY,
        "path-probe" => method == PROBE_PATH_ECHO,
        _ => false,
    }
}

fn insert_observability_run_tx(
    tx: &Transaction<'_>,
    run: &ObservabilityRunInsert,
) -> Result<(), StoreError> {
    let summary_json = canonical_run_summary(
        run.job_id.as_deref(),
        match run.job_id.as_deref() {
            Some(job_id) => get_observability_job_kind_tx(tx, job_id)?,
            None => None,
        }
        .as_deref(),
        &run.status,
        &run.triggered_by,
        &run.summary_json,
    )?;
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
            compact_json(&summary_json),
        ],
    )?;
    Ok(())
}

fn canonical_run_summary(
    job_id: Option<&str>,
    kind_hint: Option<&str>,
    status: &str,
    triggered_by: &str,
    summary_json: &Value,
) -> Result<Value, StoreError> {
    let payload = RunSummaryPayloadV1::from_value(summary_json)
        .or_else(|_| {
            RunSummaryPayloadV1::from_legacy(job_id, kind_hint, status, triggered_by, summary_json)
        })
        .map_err(StoreError::InvalidInput)?;
    payload
        .validate_relationship(job_id, kind_hint, status, triggered_by)
        .map_err(StoreError::InvalidInput)?;
    Ok(payload.to_value())
}

fn canonical_observation_summary(
    observation: &ProbeObservationInsert,
) -> Result<Value, StoreError> {
    let payload = ObservationSummaryPayloadV1::from_value(&observation.summary_json)
        .or_else(|_| {
            ObservationSummaryPayloadV1::from_legacy(
                &observation.method,
                &observation.result_class,
                &observation.summary_json,
            )
        })
        .map_err(StoreError::InvalidInput)?;
    if payload.method != observation.method || payload.result_class != observation.result_class {
        return Err(StoreError::InvalidInput(
            "observation summary does not match relational method/result class".to_string(),
        ));
    }
    Ok(payload.to_value())
}

fn insert_probe_observation_tx(
    tx: &Transaction<'_>,
    observation: &ProbeObservationInsert,
) -> Result<(), StoreError> {
    let summary_json = canonical_observation_summary(observation)?;
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
            compact_json(&summary_json),
        ],
    )?;
    Ok(())
}

fn update_scheduler_job_clock_tx(
    tx: &Transaction<'_>,
    clock: &SchedulerJobClockUpdate,
) -> Result<(), StoreError> {
    let (existing_next_run_at, existing_last_run_at) = tx
        .query_row(
            "SELECT next_run_at, last_run_at FROM observability_jobs WHERE job_id = ?1",
            [clock.job_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| StoreError::ObservabilityJobNotFound(clock.job_id.clone()))?;
    let proposed_next_run_at =
        validate_bounded_rfc3339(&clock.next_run_at, "scheduler next_run_at")?;
    let proposed_last_run_at =
        validate_bounded_rfc3339(&clock.last_run_at, "scheduler last_run_at")?;
    if let Some(existing) = existing_last_run_at.as_deref() {
        let existing = validate_bounded_rfc3339(existing, "stored scheduler last_run_at")?;
        if existing > proposed_last_run_at {
            return Err(StoreError::InvalidInput(
                "scheduler job clock update would regress last_run_at".to_string(),
            ));
        }
        if existing == proposed_last_run_at
            && let Some(existing_next) = existing_next_run_at.as_deref()
        {
            let existing_next =
                validate_bounded_rfc3339(existing_next, "stored scheduler next_run_at")?;
            if existing_next > proposed_next_run_at {
                return Err(StoreError::InvalidInput(
                    "scheduler job clock update would regress next_run_at".to_string(),
                ));
            }
        }
    }
    let affected = tx.execute(
        "UPDATE observability_jobs
         SET next_run_at = ?1,
             last_run_at = ?2,
             updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
         WHERE job_id = ?3 AND last_run_at IS ?4 AND next_run_at IS ?5",
        params![
            clock.next_run_at.as_str(),
            clock.last_run_at.as_str(),
            clock.job_id.as_str(),
            existing_last_run_at.as_deref(),
            existing_next_run_at.as_deref(),
        ],
    )?;
    if affected != 1 {
        return Err(StoreError::InvalidInput(
            "scheduler job clock changed concurrently".to_string(),
        ));
    }
    Ok(())
}

fn get_observability_run_state_tx(
    tx: &Transaction<'_>,
    run_id: &str,
) -> Result<Option<ObservabilityRunState>, StoreError> {
    tx.query_row(
        "SELECT run_id, job_id, started_at, finished_at, status
         FROM observability_runs WHERE run_id = ?1",
        [run_id],
        |row| {
            Ok(ObservabilityRunState {
                run_id: row.get(0)?,
                job_id: row.get(1)?,
                started_at: row.get(2)?,
                finished_at: row.get(3)?,
                status: row.get(4)?,
            })
        },
    )
    .optional()
    .map_err(StoreError::from)
}

fn ensure_running_observability_run(run: &ObservabilityRunState) -> Result<(), StoreError> {
    if run.status != "running" || run.finished_at.is_some() {
        return Err(StoreError::ObservabilityRunNotRunning(run.run_id.clone()));
    }
    Ok(())
}

fn get_observability_job_kind_tx(
    tx: &Transaction<'_>,
    job_id: &str,
) -> Result<Option<String>, StoreError> {
    tx.query_row(
        "SELECT kind FROM observability_jobs WHERE job_id = ?1",
        [job_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(StoreError::from)
}

fn get_observability_job_start_state_tx(
    tx: &Transaction<'_>,
    job_id: &str,
) -> Result<Option<(String, bool)>, StoreError> {
    tx.query_row(
        "SELECT kind, enabled FROM observability_jobs WHERE job_id = ?1",
        [job_id],
        |row| {
            let kind = row.get(0)?;
            let enabled = i64_to_bool(row.get(1)?, 1)?;
            Ok((kind, enabled))
        },
    )
    .optional()
    .map_err(StoreError::from)
}

fn observability_job_exists_tx(tx: &Transaction<'_>, job_id: &str) -> Result<bool, StoreError> {
    let exists = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM observability_jobs WHERE job_id = ?1)",
        [job_id],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(exists == 1)
}

fn count_observability_run_outcomes_tx(
    tx: &Transaction<'_>,
    run_id: &str,
) -> Result<(u64, u64), StoreError> {
    let (observations, failures): (i64, i64) = tx.query_row(
        "SELECT COUNT(*), COALESCE(SUM(CASE WHEN ok = 0 THEN 1 ELSE 0 END), 0)
         FROM probe_observations WHERE run_id = ?1",
        [run_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((i64_to_u64(observations)?, i64_to_u64(failures)?))
}

fn absolute_database_path(path: &Path) -> Result<PathBuf, StoreError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
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
    let generation = endpoint_generation_to_i64(&endpoint.endpoint_id, endpoint.generation)?;
    let trust_bundle_json = canonical_trust_bundle(
        &endpoint.endpoint_id,
        endpoint.generation,
        endpoint.status,
        &endpoint.trust_bundle_json,
    )?;
    tx.execute(
        "INSERT INTO endpoint_trust
         (endpoint_id, node_id, fingerprint, status, generation, previous_endpoint_id, rotated_to, trust_bundle_json, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
        params![
            endpoint.endpoint_id.as_str(),
            endpoint.node_id.as_deref(),
            endpoint.fingerprint.as_deref(),
            endpoint.status.as_str(),
            generation,
            endpoint.previous_endpoint_id.as_deref(),
            endpoint.rotated_to.as_deref(),
            trust_bundle_json.to_string(),
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

fn get_node_by_endpoint_tx(
    tx: &Transaction<'_>,
    endpoint_id: &str,
) -> Result<Option<NodeRecord>, StoreError> {
    tx.query_row(
        "SELECT node_id, endpoint_id, name, region, role, enabled
         FROM nodes WHERE endpoint_id = ?1",
        [endpoint_id],
        node_from_row,
    )
    .optional()
    .map_err(StoreError::from)
}

fn get_enrollment_token_tx(
    tx: &Transaction<'_>,
    token_id: &str,
) -> Result<Option<EnrollmentTokenRecord>, StoreError> {
    tx.query_row(
        "SELECT token_id, token_hash, created_at, created_by, expires_at, max_uses, used_count, status, description, labels_json, scope_json
         FROM enrollment_tokens WHERE token_id = ?1",
        [token_id],
        enrollment_token_from_row,
    )
    .optional()
    .map_err(StoreError::from)
}

fn get_enrollment_token_by_hash_tx(
    tx: &Transaction<'_>,
    token_hash: &str,
) -> Result<Option<EnrollmentTokenRecord>, StoreError> {
    tx.query_row(
        "SELECT token_id, token_hash, created_at, created_by, expires_at, max_uses, used_count, status, description, labels_json, scope_json
         FROM enrollment_tokens WHERE token_hash = ?1",
        [token_hash],
        enrollment_token_from_row,
    )
    .optional()
    .map_err(StoreError::from)
}

fn insert_node_tx(tx: &Transaction<'_>, node: &NodeInsert) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO nodes
         (node_id, endpoint_id, name, region, role, enabled, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 1,
                 strftime('%Y-%m-%dT%H:%M:%SZ','now'),
                 strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
        params![
            node.node_id.as_str(),
            node.endpoint_id.as_str(),
            node.name.as_str(),
            node.region.as_str(),
            node.role.as_str(),
        ],
    )?;
    Ok(())
}

fn endpoint_trust_count_for_node_tx(
    tx: &Transaction<'_>,
    node_id: &str,
) -> Result<u64, StoreError> {
    let count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM endpoint_trust WHERE node_id = ?1",
        [node_id],
        |row| row.get(0),
    )?;
    Ok(i64_to_u64(count)?)
}

fn approved_join_assignment_count_tx(
    tx: &Transaction<'_>,
    endpoint_id: &str,
) -> Result<u64, StoreError> {
    let count: i64 = tx.query_row(
        "SELECT COUNT(*)
         FROM join_requests
         WHERE status = 'approved' AND assigned_endpoint_id = ?1",
        [endpoint_id],
        |row| row.get(0),
    )?;
    Ok(i64_to_u64(count)?)
}

fn approved_join_audit_count_tx(
    tx: &Transaction<'_>,
    join: &JoinRequestRecord,
    endpoint_id: &str,
    node_id: Option<&str>,
) -> Result<u64, StoreError> {
    let count: i64 = tx.query_row(
        "SELECT COUNT(*)
         FROM controller_audit_log
         WHERE event = 'enrollment.approve'
           AND request_id = ?1
           AND endpoint_id = ?2
           AND actor = ?3
           AND ok = 1
           AND node_id IS ?4",
        params![
            join.request_id.as_str(),
            endpoint_id,
            join.approved_by.as_deref(),
            node_id,
        ],
        |row| row.get(0),
    )?;
    Ok(i64_to_u64(count)?)
}

fn enrollment_claim_audit_count_tx(
    tx: &Transaction<'_>,
    request_id: &str,
    endpoint_id: &str,
    node_id: &str,
) -> Result<u64, StoreError> {
    let count: i64 = tx.query_row(
        "SELECT COUNT(*)
         FROM controller_audit_log
         WHERE event = 'enrollment.claim'
           AND request_id = ?1
           AND endpoint_id = ?2
           AND node_id = ?3
           AND ok = 1",
        params![request_id, endpoint_id, node_id],
        |row| row.get(0),
    )?;
    Ok(i64_to_u64(count)?)
}

fn validate_enrollment_token_audit_provenance_tx(
    tx: &Transaction<'_>,
    event: &str,
    token_id: &str,
    actor: &str,
    reason: Option<&str>,
) -> Result<(), StoreError> {
    let count: i64 = tx.query_row(
        "SELECT COUNT(*)
         FROM controller_audit_log
         WHERE event = ?1
           AND ok = 1
           AND json_extract(detail_json, '$.target_id') = ?2
           AND actor = ?3
           AND (?4 IS NULL OR json_extract(detail_json, '$.reason') = ?4)",
        params![event, token_id, actor, reason],
        |row| row.get(0),
    )?;
    if count != 1 {
        return Err(StoreError::EnrollmentTokenConflict {
            token_id: token_id.to_string(),
            detail: "token audit provenance is missing or ambiguous",
        });
    }
    Ok(())
}

fn validate_join_submission_audit_provenance_tx(
    tx: &Transaction<'_>,
    join: &JoinRequestRecord,
    actor: &str,
) -> Result<(), StoreError> {
    let count: i64 = tx.query_row(
        "SELECT COUNT(*)
         FROM controller_audit_log
         WHERE event = 'enrollment.token.use'
           AND request_id = ?1
           AND ok = 1
           AND json_extract(detail_json, '$.target_id') = ?1
           AND actor = ?2",
        params![join.request_id.as_str(), actor],
        |row| row.get(0),
    )?;
    if count != 1 {
        return Err(StoreError::EnrollmentRequestConflict {
            request_id: join.request_id.clone(),
            detail: "request submission audit provenance is missing or ambiguous",
        });
    }
    Ok(())
}

fn validate_join_rejection_audit_provenance_tx(
    tx: &Transaction<'_>,
    request_id: &str,
    actor: &str,
    reason: &str,
) -> Result<(), StoreError> {
    let count: i64 = tx.query_row(
        "SELECT COUNT(*)
         FROM controller_audit_log
         WHERE event = 'enrollment.reject'
           AND request_id = ?1
           AND ok = 1
           AND json_extract(detail_json, '$.target_id') = ?1
           AND actor = ?2
           AND json_extract(detail_json, '$.reason') = ?3",
        params![request_id, actor, reason],
        |row| row.get(0),
    )?;
    if count != 1 {
        return Err(StoreError::EnrollmentRequestConflict {
            request_id: request_id.to_string(),
            detail: "request rejection audit provenance is missing or ambiguous",
        });
    }
    Ok(())
}

fn get_active_endpoint_trust_for_node_tx(
    tx: &Transaction<'_>,
    node_id: &str,
) -> Result<Vec<EndpointTrustRecord>, StoreError> {
    let mut stmt = tx.prepare(
        "SELECT endpoint_id, node_id, fingerprint, status, generation, previous_endpoint_id, rotated_to, trust_bundle_json, created_at, updated_at
         FROM endpoint_trust
         WHERE node_id = ?1 AND status = 'active'
         ORDER BY endpoint_id
         LIMIT 2",
    )?;
    let rows = stmt.query_map([node_id], endpoint_trust_from_row)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

fn get_observability_job_tx(
    tx: &Transaction<'_>,
    job_id: &str,
) -> Result<Option<ObservabilityJobRecord>, StoreError> {
    tx.query_row(
        "SELECT job_id, kind, selector_json, pair_selector_json, interval_seconds, jitter_seconds, timeout_ms, enabled, next_run_at, last_run_at, created_at, updated_at
         FROM observability_jobs
         WHERE job_id = ?1",
        [job_id],
        observability_job_from_row,
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

fn get_endpoint_dispatch_binding_conn(
    conn: &Connection,
    expected_node_id: &str,
    endpoint_id: &str,
) -> Result<Option<EndpointDispatchBinding>, StoreError> {
    conn.query_row(
        "SELECT trust.status,
                trust.node_id,
                registry.node_id,
                registry.endpoint_id,
                registry.enabled,
                (SELECT COUNT(*)
                 FROM endpoint_trust AS active
                 WHERE active.node_id = ?1 AND active.status = 'active')
         FROM endpoint_trust AS trust
         LEFT JOIN nodes AS registry ON registry.node_id = ?1
         WHERE trust.endpoint_id = ?2",
        params![expected_node_id, endpoint_id],
        |row| {
            let status: String = row.get(0)?;
            let enabled = row
                .get::<_, Option<i64>>(4)?
                .map(|value| i64_to_bool(value, 4))
                .transpose()?;
            Ok(EndpointDispatchBinding {
                status: parse_status(&status, 0)?,
                trust_node_id: row.get(1)?,
                registry_node_id: row.get(2)?,
                registry_endpoint_id: row.get(3)?,
                registry_enabled: enabled,
                active_endpoint_count_for_node: i64_to_u64(row.get(5)?)?,
            })
        },
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

fn invalid_enrollment_binding(request_id: &str, detail: &'static str) -> StoreError {
    StoreError::InvalidEnrollmentBinding {
        request_id: request_id.to_string(),
        detail,
    }
}

fn validate_enrollment_request_id(request_id: &str) -> Result<(), StoreError> {
    validate_audit_text(request_id, "join request_id", 128)?;
    let Some(uuid) = request_id.strip_prefix("join-") else {
        return Err(StoreError::InvalidInput(
            "join request_id must use the join-<uuid> format".to_string(),
        ));
    };
    Uuid::parse_str(uuid)
        .map(|_| ())
        .map_err(|_| StoreError::InvalidInput("join request_id must contain a UUID".to_string()))
}

fn validate_enrollment_token_id(token_id: &str) -> Result<(), StoreError> {
    validate_audit_text(token_id, "enrollment token_id", 128)?;
    if !token_id.starts_with("tok-") {
        return Err(StoreError::InvalidInput(
            "enrollment token_id must start with tok-".to_string(),
        ));
    }
    Ok(())
}

fn validate_enrollment_token_input(token: &EnrollmentTokenInsert) -> Result<(), StoreError> {
    validate_enrollment_token_id(&token.token_id)?;
    if token.token_hash.len() != 64
        || !token
            .token_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StoreError::InvalidInput(
            "enrollment token hash must be lowercase BLAKE3 hex".to_string(),
        ));
    }
    if OffsetDateTime::parse(&token.expires_at, &Rfc3339).is_err() {
        return Err(StoreError::InvalidInput(
            "enrollment token expires_at must be RFC3339".to_string(),
        ));
    }
    if token.max_uses == 0 || token.max_uses > MAX_ENROLLMENT_TOKEN_USES {
        return Err(StoreError::InvalidInput(format!(
            "enrollment token max_uses must be 1-{MAX_ENROLLMENT_TOKEN_USES}"
        )));
    }
    Ok(())
}

fn validate_enrollment_token_plaintext(token: &str) -> Result<(), StoreError> {
    if token.is_empty() || token.len() > 512 || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(StoreError::InvalidInput(
            "enrollment token must be 1-512 ASCII non-whitespace characters".to_string(),
        ));
    }
    Ok(())
}

fn enrollment_token_matches_create(
    existing: &EnrollmentTokenRecord,
    requested: &EnrollmentTokenInsert,
    actor: &str,
) -> bool {
    existing.token_id == requested.token_id
        && existing.token_hash == requested.token_hash
        && existing.created_by == actor
        && existing.expires_at == requested.expires_at
        && existing.max_uses == requested.max_uses
        && existing.description == requested.description
        && existing.labels_json == requested.labels_json
        && existing.scope_json == requested.scope_json
}

fn join_request_matches_submission(
    existing: &JoinRequestRecord,
    requested: &JoinRequestInsert,
    token_id: &str,
    requested_endpoint_id: Option<&str>,
) -> bool {
    existing.request_id == requested.request_id
        && existing.token_id == token_id
        && existing.agent_public_key == requested.agent_public_key
        && existing.fingerprint == requested.fingerprint
        && existing.requested_endpoint_id.as_deref() == requested_endpoint_id
        && existing.hostname == requested.hostname
        && existing.agent_version == requested.agent_version
        && existing.requested_labels_json == requested.requested_labels_json
}

fn enrollment_node_insert(
    node_id: &str,
    endpoint_id: &str,
    region: &str,
    role: &str,
) -> Result<NodeInsert, StoreError> {
    validate_node_id(node_id).map_err(|err| StoreError::InvalidInput(err.to_string()))?;
    let endpoint_id = validate_endpoint_id(endpoint_id).map_err(StoreError::InvalidInput)?;
    validate_region(region).map_err(|err| StoreError::InvalidInput(err.to_string()))?;
    validate_role(role).map_err(|err| StoreError::InvalidInput(err.to_string()))?;
    Ok(NodeInsert {
        node_id: node_id.to_string(),
        endpoint_id,
        name: node_id.to_string(),
        region: region.to_string(),
        role: role.to_string(),
    })
}

fn validate_approved_join_provenance_tx(
    tx: &Transaction<'_>,
    join: &JoinRequestRecord,
    endpoint_id: &str,
) -> Result<(), StoreError> {
    let reject = |detail| invalid_enrollment_binding(&join.request_id, detail);
    if join.status != JoinRequestStatus::Approved {
        return Err(reject("join request is not approved"));
    }
    if join.assigned_endpoint_id.as_deref() != Some(endpoint_id) {
        return Err(reject("assigned endpoint does not match"));
    }
    if join
        .requested_endpoint_id
        .as_deref()
        .is_some_and(|requested| requested != endpoint_id)
    {
        return Err(reject(
            "assigned endpoint does not match requested endpoint",
        ));
    }
    let Some(approved_by) = join.approved_by.as_deref() else {
        return Err(reject("approval metadata is incomplete"));
    };
    if validate_actor(approved_by).is_err()
        || join
            .approved_at
            .as_deref()
            .is_none_or(|approved_at| OffsetDateTime::parse(approved_at, &Rfc3339).is_err())
        || join.rejection_reason.is_some()
    {
        return Err(reject("approval metadata is invalid"));
    }
    validate_agent_fingerprint(&join.fingerprint)
        .map_err(|_| reject("stored fingerprint is invalid"))?;
    validate_label_json(&join.approved_labels_json, "approved_labels")
        .map_err(|_| reject("approved labels are invalid"))?;
    if approved_join_assignment_count_tx(tx, endpoint_id)? != 1 {
        return Err(reject("approved endpoint assignment is ambiguous"));
    }
    Ok(())
}

fn validate_approved_join_audit_provenance_tx(
    tx: &Transaction<'_>,
    join: &JoinRequestRecord,
    endpoint_id: &str,
    node_id: Option<&str>,
) -> Result<(), StoreError> {
    if approved_join_audit_count_tx(tx, join, endpoint_id, node_id)? != 1 {
        return Err(invalid_enrollment_binding(
            &join.request_id,
            "approval audit provenance is missing or ambiguous",
        ));
    }
    Ok(())
}

fn validate_enrollment_claim_audit_provenance_tx(
    tx: &Transaction<'_>,
    join: &JoinRequestRecord,
    endpoint_id: &str,
    node_id: &str,
) -> Result<(), StoreError> {
    if enrollment_claim_audit_count_tx(tx, &join.request_id, endpoint_id, node_id)? != 1 {
        return Err(invalid_enrollment_binding(
            &join.request_id,
            "claim retry audit provenance is missing or ambiguous",
        ));
    }
    Ok(())
}

fn validate_enrollment_endpoint_origin(
    join: &JoinRequestRecord,
    endpoint: &EndpointTrustRecord,
    request_id: &str,
) -> Result<(), StoreError> {
    let reject = |detail| invalid_enrollment_binding(request_id, detail);
    if endpoint.endpoint_id != join.assigned_endpoint_id.as_deref().unwrap_or_default()
        || endpoint.status != EndpointStatus::Active
        || endpoint.generation != 1
        || endpoint.previous_endpoint_id.is_some()
        || endpoint.rotated_to.is_some()
    {
        return Err(reject(
            "endpoint trust is not an original active enrollment",
        ));
    }
    if endpoint.fingerprint.as_deref() != Some(join.fingerprint.as_str()) {
        return Err(reject("endpoint fingerprint does not match join request"));
    }
    validate_endpoint_bundle_projection(endpoint)
        .map_err(|_| reject("endpoint trust bundle is inconsistent"))?;
    if endpoint.trust_bundle_json
        != trust_bundle_json(&endpoint.endpoint_id, 1, EndpointStatus::Active)
    {
        return Err(reject("endpoint trust bundle is not the enrollment bundle"));
    }
    Ok(())
}

fn validate_pending_join_for_approval(join: &JoinRequestRecord) -> Result<(), StoreError> {
    let reject = |detail| invalid_enrollment_binding(&join.request_id, detail);
    if join.status != JoinRequestStatus::Pending
        || join.assigned_endpoint_id.is_some()
        || join.approved_at.is_some()
        || join.approved_by.is_some()
        || join.rejection_reason.is_some()
        || join
            .approved_labels_json
            .as_object()
            .is_none_or(|labels| !labels.is_empty())
    {
        return Err(reject("pending join request has decision metadata"));
    }
    validate_agent_public_key(&join.agent_public_key)
        .map_err(|_| reject("stored agent public key is invalid"))?;
    validate_agent_fingerprint(&join.fingerprint)
        .map_err(|_| reject("stored fingerprint is invalid"))?;
    validate_hostname(&join.hostname).map_err(|_| reject("stored hostname is invalid"))?;
    validate_agent_version(&join.agent_version)
        .map_err(|_| reject("stored agent version is invalid"))?;
    validate_label_json(&join.requested_labels_json, "requested_labels")
        .map_err(|_| reject("stored requested labels are invalid"))?;
    validate_audit_text(&join.audit_correlation_id, "join correlation_id", 128)
        .map_err(|_| reject("stored audit correlation is invalid"))?;
    Ok(())
}

fn validate_exact_enrollment_binding_tx(
    tx: &Transaction<'_>,
    join: &JoinRequestRecord,
    endpoint: &EndpointTrustRecord,
    expected_node: &NodeInsert,
    expected_approved_labels: Option<&Value>,
    failure_detail: &'static str,
) -> Result<(), StoreError> {
    validate_approved_join_provenance_tx(tx, join, &expected_node.endpoint_id)?;
    validate_enrollment_endpoint_origin(join, endpoint, &join.request_id)?;
    if expected_approved_labels.is_some_and(|expected| expected != &join.approved_labels_json)
        || endpoint.node_id.as_deref() != Some(expected_node.node_id.as_str())
    {
        return Err(invalid_enrollment_binding(&join.request_id, failure_detail));
    }
    let Some(node) = get_node_tx(tx, &expected_node.node_id)? else {
        return Err(invalid_enrollment_binding(&join.request_id, failure_detail));
    };
    if node.node_id != expected_node.node_id
        || node.endpoint_id != expected_node.endpoint_id
        || node.name != expected_node.name
        || node.region != expected_node.region
        || node.role != expected_node.role
        || get_node_by_endpoint_tx(tx, &expected_node.endpoint_id)?
            .is_none_or(|by_endpoint| by_endpoint.node_id != expected_node.node_id)
    {
        return Err(invalid_enrollment_binding(&join.request_id, failure_detail));
    }
    let active = get_active_endpoint_trust_for_node_tx(tx, &expected_node.node_id)?;
    if active.len() != 1 || active[0].endpoint_id != expected_node.endpoint_id {
        return Err(invalid_enrollment_binding(&join.request_id, failure_detail));
    }
    Ok(())
}

fn invalid_endpoint_transition(endpoint: &EndpointTrustRecord, action: &'static str) -> StoreError {
    StoreError::InvalidEndpointTransition {
        endpoint_id: endpoint.endpoint_id.clone(),
        from: endpoint.status.as_str().to_string(),
        action,
    }
}

fn endpoint_generation_to_i64(endpoint_id: &str, generation: u64) -> Result<i64, StoreError> {
    i64::try_from(generation)
        .map_err(|_| StoreError::EndpointGenerationExhausted(endpoint_id.to_string()))
}

fn next_endpoint_generation(endpoint: &EndpointTrustRecord) -> Result<u64, StoreError> {
    if endpoint.generation >= i64::MAX as u64 {
        return Err(StoreError::EndpointGenerationExhausted(
            endpoint.endpoint_id.clone(),
        ));
    }
    Ok(endpoint.generation + 1)
}

fn validate_endpoint_bundle_projection(endpoint: &EndpointTrustRecord) -> Result<(), StoreError> {
    let bundle: TrustBundle = serde_json::from_value(endpoint.trust_bundle_json.clone())
        .map_err(|_| StoreError::EndpointLineageInvalid(endpoint.endpoint_id.clone()))?;
    if bundle.endpoint_id != endpoint.endpoint_id
        || bundle.generation != endpoint.generation
        || bundle.status != endpoint.status
    {
        return Err(StoreError::EndpointLineageInvalid(
            endpoint.endpoint_id.clone(),
        ));
    }
    Ok(())
}

fn validate_unrotated_lineage(
    tx: &Transaction<'_>,
    endpoint: &EndpointTrustRecord,
) -> Result<(), StoreError> {
    validate_endpoint_bundle_projection(endpoint)?;
    if endpoint.rotated_to.is_some() {
        return Err(StoreError::EndpointLineageInvalid(
            endpoint.endpoint_id.clone(),
        ));
    }
    let Some(previous_endpoint_id) = endpoint.previous_endpoint_id.as_deref() else {
        return Ok(());
    };
    let previous = get_endpoint_trust_tx(tx, previous_endpoint_id)?
        .ok_or_else(|| StoreError::EndpointLineageInvalid(endpoint.endpoint_id.clone()))?;
    validate_endpoint_bundle_projection(&previous)?;
    if previous.status != EndpointStatus::Rotated
        || previous.rotated_to.as_deref() != Some(endpoint.endpoint_id.as_str())
        || previous.node_id != endpoint.node_id
        || previous.fingerprint != endpoint.fingerprint
        || previous.generation > endpoint.generation
    {
        return Err(StoreError::EndpointLineageInvalid(
            endpoint.endpoint_id.clone(),
        ));
    }
    Ok(())
}

fn validate_rotation_edge(
    tx: &Transaction<'_>,
    old: &EndpointTrustRecord,
    new: &EndpointTrustRecord,
) -> Result<(), StoreError> {
    validate_endpoint_bundle_projection(old)?;
    validate_endpoint_bundle_projection(new)?;
    if old.status != EndpointStatus::Rotated
        || old.rotated_to.as_deref() != Some(new.endpoint_id.as_str())
        || new.previous_endpoint_id.as_deref() != Some(old.endpoint_id.as_str())
        || old.node_id != new.node_id
        || old.fingerprint != new.fingerprint
        || old.generation > new.generation
    {
        return Err(StoreError::EndpointLineageInvalid(old.endpoint_id.clone()));
    }
    if new.status != EndpointStatus::Rotated {
        validate_unrotated_lineage(tx, new)?;
    }
    if let Some(previous_endpoint_id) = old.previous_endpoint_id.as_deref() {
        let previous = get_endpoint_trust_tx(tx, previous_endpoint_id)?
            .ok_or_else(|| StoreError::EndpointLineageInvalid(old.endpoint_id.clone()))?;
        if previous.status != EndpointStatus::Rotated
            || previous.rotated_to.as_deref() != Some(old.endpoint_id.as_str())
        {
            return Err(StoreError::EndpointLineageInvalid(old.endpoint_id.clone()));
        }
    }
    Ok(())
}

fn validate_rotation_binding_tx(
    tx: &Transaction<'_>,
    endpoint: &EndpointTrustRecord,
) -> Result<Option<NodeRecord>, StoreError> {
    let Some(node_id) = endpoint.node_id.as_deref() else {
        return Err(StoreError::EndpointBindingMismatch {
            endpoint_id: endpoint.endpoint_id.clone(),
            detail: "unbound endpoint cannot be rotated",
        });
    };
    let node = get_node_tx(tx, node_id)?.ok_or_else(|| StoreError::EndpointBindingMismatch {
        endpoint_id: endpoint.endpoint_id.clone(),
        detail: "bound node is missing",
    })?;
    if node.endpoint_id != endpoint.endpoint_id {
        return Err(StoreError::EndpointBindingMismatch {
            endpoint_id: endpoint.endpoint_id.clone(),
            detail: "bound node does not point to the endpoint",
        });
    }
    let active = get_active_endpoint_trust_for_node_tx(tx, node_id)?;
    let clean = match endpoint.status {
        EndpointStatus::Active => {
            active.len() == 1 && active[0].endpoint_id == endpoint.endpoint_id
        }
        EndpointStatus::Quarantined => active.is_empty(),
        EndpointStatus::Revoked | EndpointStatus::Rotated => false,
    };
    if !clean {
        return if active.len() > 1 {
            Err(StoreError::AmbiguousActiveEndpointBinding(
                node_id.to_string(),
            ))
        } else {
            Err(StoreError::EndpointBindingMismatch {
                endpoint_id: endpoint.endpoint_id.clone(),
                detail: "node has an inconsistent active endpoint binding",
            })
        };
    }
    Ok(Some(node))
}

fn validate_legacy_rotation_reconciliation_tx(
    tx: &Transaction<'_>,
    node_id: &str,
    rotated_to: &EndpointTrustRecord,
) -> Result<(), StoreError> {
    if rotated_to.status == EndpointStatus::Rotated {
        return Err(StoreError::EndpointBindingMismatch {
            endpoint_id: rotated_to.endpoint_id.clone(),
            detail: "rotated child is not a deterministic current endpoint",
        });
    }
    let active = get_active_endpoint_trust_for_node_tx(tx, node_id)?;
    let clean = match rotated_to.status {
        EndpointStatus::Active => {
            active.len() == 1 && active[0].endpoint_id == rotated_to.endpoint_id
        }
        EndpointStatus::Quarantined | EndpointStatus::Revoked => active.is_empty(),
        EndpointStatus::Rotated => false,
    };
    if !clean {
        return if active.len() > 1 {
            Err(StoreError::AmbiguousActiveEndpointBinding(
                node_id.to_string(),
            ))
        } else {
            Err(StoreError::EndpointBindingMismatch {
                endpoint_id: rotated_to.endpoint_id.clone(),
                detail: "legacy rotation does not have one deterministic child",
            })
        };
    }
    Ok(())
}

fn get_exact_bound_node_tx(
    tx: &Transaction<'_>,
    endpoint: &EndpointTrustRecord,
) -> Result<Option<NodeRecord>, StoreError> {
    let Some(node_id) = endpoint.node_id.as_deref() else {
        return Ok(None);
    };
    Ok(get_node_tx(tx, node_id)?.filter(|node| node.endpoint_id == endpoint.endpoint_id))
}

fn validate_active_node_binding_tx(
    tx: &Transaction<'_>,
    node: &NodeRecord,
) -> Result<(), StoreError> {
    let endpoint = get_endpoint_trust_tx(tx, &node.endpoint_id)?.ok_or_else(|| {
        StoreError::EndpointBindingMismatch {
            endpoint_id: node.endpoint_id.clone(),
            detail: "endpoint trust is missing",
        }
    })?;
    validate_unrotated_lineage(tx, &endpoint)?;
    if endpoint.status != EndpointStatus::Active
        || endpoint.node_id.as_deref() != Some(node.node_id.as_str())
    {
        return Err(StoreError::EndpointBindingMismatch {
            endpoint_id: node.endpoint_id.clone(),
            detail: "node does not have an active bidirectional endpoint binding",
        });
    }
    let active = get_active_endpoint_trust_for_node_tx(tx, &node.node_id)?;
    if active.len() > 1 {
        return Err(StoreError::AmbiguousActiveEndpointBinding(
            node.node_id.clone(),
        ));
    }
    if active.len() != 1 || active[0].endpoint_id != node.endpoint_id {
        return Err(StoreError::EndpointBindingMismatch {
            endpoint_id: node.endpoint_id.clone(),
            detail: "node does not have exactly one active endpoint binding",
        });
    }
    Ok(())
}

fn transition_endpoint_status_tx(
    tx: &Transaction<'_>,
    before: &EndpointTrustRecord,
    status: EndpointStatus,
) -> Result<EndpointTrustRecord, StoreError> {
    validate_unrotated_lineage(tx, before)?;
    let generation = next_endpoint_generation(before)?;
    let affected = tx.execute(
        "UPDATE endpoint_trust
         SET status = ?1,
             generation = ?2,
             trust_bundle_json = ?3,
             updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
         WHERE endpoint_id = ?4 AND status = ?5 AND generation = ?6",
        params![
            status.as_str(),
            endpoint_generation_to_i64(&before.endpoint_id, generation)?,
            canonical_trust_bundle(
                &before.endpoint_id,
                generation,
                status,
                &trust_bundle_json(&before.endpoint_id, generation, status),
            )?
            .to_string(),
            before.endpoint_id.as_str(),
            before.status.as_str(),
            endpoint_generation_to_i64(&before.endpoint_id, before.generation)?,
        ],
    )?;
    if affected != 1 {
        return Err(StoreError::EndpointBindingMismatch {
            endpoint_id: before.endpoint_id.clone(),
            detail: "endpoint state changed during transition",
        });
    }
    get_endpoint_trust_tx(tx, &before.endpoint_id)?
        .ok_or_else(|| StoreError::EndpointNotFound(before.endpoint_id.clone()))
}

fn audit_join_rejection_tx(
    tx: &Transaction<'_>,
    actor: &str,
    request_id: Option<&str>,
    token_id: Option<&str>,
    reason: &str,
) -> Result<(), StoreError> {
    let mut event = AuditEvent::new(actor, "enrollment.token.reject");
    event.ok = Some(false);
    event.request_id = request_id.map(ToString::to_string);
    event.error_code = Some("ENROLLMENT_REJECTED".to_string());
    event.detail_json = serde_json::json!({
        "actor_type": "user",
        "action": "enrollment.token.reject",
        "target_type": "enrollment_token",
        "target_id": token_id,
        "reason": reason,
    });
    insert_audit_tx(tx, &event)
}

#[allow(clippy::too_many_arguments)]
fn audit_endpoint_rotation_tx(
    tx: &Transaction<'_>,
    actor: &str,
    action: &str,
    old_endpoint_id: &str,
    node_before: Option<&NodeRecord>,
    node_after: Option<&NodeRecord>,
    old_before: &EndpointTrustRecord,
    old_after: &EndpointTrustRecord,
    new_after: &EndpointTrustRecord,
    reason: &str,
) -> Result<(), StoreError> {
    let mut event = AuditEvent::new(actor, action);
    event.ok = Some(true);
    event.node_id = old_before.node_id.clone();
    event.endpoint_id = Some(old_endpoint_id.to_string());
    event.detail_json = serde_json::json!({
        "actor_type": "user",
        "target_type": "endpoint_rotation",
        "target_id": old_endpoint_id,
        "new_endpoint_id": new_after.endpoint_id,
        "before": {
            "node": node_before.map(node_audit_json),
            "old_endpoint": endpoint_audit_json(old_before),
        },
        "after": {
            "node": node_after.map(node_audit_json),
            "old_endpoint": endpoint_audit_json(old_after),
            "new_endpoint": endpoint_audit_json(new_after),
        },
        "reason": reason,
    });
    insert_audit_tx(tx, &event)
}

#[allow(clippy::too_many_arguments)]
fn audit_endpoint_status_tx(
    tx: &Transaction<'_>,
    actor: &str,
    action: &str,
    endpoint_id: &str,
    node_before: Option<&NodeRecord>,
    node_after: Option<&NodeRecord>,
    endpoint_before: &EndpointTrustRecord,
    endpoint_after: &EndpointTrustRecord,
    reason: &str,
) -> Result<(), StoreError> {
    let mut event = AuditEvent::new(actor, action);
    event.ok = Some(true);
    event.node_id = endpoint_before.node_id.clone();
    event.endpoint_id = Some(endpoint_id.to_string());
    event.detail_json = serde_json::json!({
        "actor_type": "user",
        "target_type": "endpoint",
        "target_id": endpoint_id,
        "before": {
            "node": node_before.map(node_audit_json),
            "endpoint": endpoint_audit_json(endpoint_before),
        },
        "after": {
            "node": node_after.map(node_audit_json),
            "endpoint": endpoint_audit_json(endpoint_after),
        },
        "reason": reason,
    });
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

fn enrollment_join_audit_json(join: &JoinRequestRecord) -> Value {
    serde_json::json!({
        "request_id": join.request_id.clone(),
        "status": join.status.as_str(),
        "requested_endpoint_id_present": join.requested_endpoint_id.is_some(),
        "assigned_endpoint_id": join.assigned_endpoint_id.clone(),
    })
}

fn enrollment_token_audit_json(token: &EnrollmentTokenRecord) -> Value {
    serde_json::json!({
        "token_id": token.token_id,
        "status": token.status.as_str(),
        "expires_at": token.expires_at,
        "max_uses": token.max_uses,
        "used_count": token.used_count,
        "description_present": token.description.is_some(),
        "label_count": token.labels_json.as_object().map_or(0, serde_json::Map::len),
        "scope_count": token.scope_json.as_object().map_or(0, serde_json::Map::len),
    })
}

fn enrollment_token_transition_audit_json(
    token_id: &str,
    before: Option<&EnrollmentTokenRecord>,
    after: Option<&EnrollmentTokenRecord>,
    reason: Option<&str>,
) -> Value {
    serde_json::json!({
        "actor_type": "user",
        "target_type": "enrollment_token",
        "target_id": token_id,
        "before": before.map(enrollment_token_audit_json),
        "after": after.map(enrollment_token_audit_json),
        "reason": reason,
    })
}

fn enrollment_token_use_audit_json(
    before: &EnrollmentTokenRecord,
    after: &EnrollmentTokenRecord,
    join: &JoinRequestRecord,
) -> Value {
    serde_json::json!({
        "actor_type": "user",
        "target_type": "join_request",
        "target_id": join.request_id,
        "before": {
            "issuance": enrollment_token_audit_json(before),
            "join_request": Value::Null,
        },
        "after": {
            "issuance": enrollment_token_audit_json(after),
            "join_request": {
                "request_id": join.request_id,
                "token_id": join.token_id,
                "status": join.status.as_str(),
                "fingerprint_present": !join.fingerprint.is_empty(),
                "requested_endpoint_id_present": join.requested_endpoint_id.is_some(),
                "requested_label_count": join
                    .requested_labels_json
                    .as_object()
                    .map_or(0, serde_json::Map::len),
                "correlation_id": join.audit_correlation_id,
            },
        },
        "reason": Value::Null,
    })
}

fn enrollment_request_transition_audit_json(
    request_id: &str,
    before: &JoinRequestRecord,
    after: &JoinRequestRecord,
    reason: &str,
) -> Value {
    serde_json::json!({
        "actor_type": "user",
        "target_type": "join_request",
        "target_id": request_id,
        "before": enrollment_join_audit_json(before),
        "after": enrollment_join_audit_json(after),
        "reason": reason,
    })
}

#[allow(clippy::too_many_arguments)]
fn audit_enrollment_binding_tx(
    tx: &Transaction<'_>,
    actor: &str,
    action: &str,
    request_id: &str,
    join_before: &JoinRequestRecord,
    join_after: &JoinRequestRecord,
    node_before: Option<&NodeRecord>,
    node_after: Option<&NodeRecord>,
    endpoint_before: Option<&EndpointTrustRecord>,
    endpoint_after: Option<&EndpointTrustRecord>,
    reason: &str,
) -> Result<(), StoreError> {
    let mut event = AuditEvent::new(actor, action);
    event.ok = Some(true);
    event.request_id = Some(request_id.to_string());
    event.node_id = node_after.or(node_before).map(|node| node.node_id.clone());
    event.endpoint_id = endpoint_after
        .or(endpoint_before)
        .map(|endpoint| endpoint.endpoint_id.clone());
    event.detail_json = serde_json::json!({
        "actor_type": "user",
        "target_type": "enrollment_binding",
        "target_id": request_id,
        "before": {
            "join_request": enrollment_join_audit_json(join_before),
            "node": node_before.map(node_audit_json),
            "endpoint": endpoint_before.map(endpoint_audit_json),
        },
        "after": {
            "join_request": enrollment_join_audit_json(join_after),
            "node": node_after.map(node_audit_json),
            "endpoint": endpoint_after.map(endpoint_audit_json),
        },
        "reason": reason,
    });
    insert_audit_tx(tx, &event)
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

fn scheduler_job_add_audit_detail(job: &ObservabilityJobRecord) -> Value {
    serde_json::json!({
        "actor_type": "user",
        "target_type": "observability_job",
        "target_id": job.job_id.clone(),
        "job_id": job.job_id.clone(),
        "kind": job.kind.clone(),
        "interval_seconds": job.interval_seconds,
        "selector_class": scheduler_job_selector_class(job),
        "result_class": "scheduler_summary",
        "before": Value::Null,
        "after": observability_job_audit_json(job),
        "reason": Value::Null,
    })
}

fn scheduler_job_state_audit_detail(
    before: &ObservabilityJobRecord,
    after: &ObservabilityJobRecord,
) -> Value {
    serde_json::json!({
        "actor_type": "user",
        "target_type": "observability_job",
        "target_id": after.job_id.clone(),
        "job_id": after.job_id.clone(),
        "enabled": after.enabled,
        "result_class": "scheduler_summary",
        "before": observability_job_audit_json(before),
        "after": observability_job_audit_json(after),
        "reason": Value::Null,
    })
}

fn observability_job_audit_json(job: &ObservabilityJobRecord) -> Value {
    serde_json::json!({
        "job_id": job.job_id.clone(),
        "kind": job.kind.clone(),
        "selector_class": scheduler_job_selector_class(job),
        "interval_seconds": job.interval_seconds,
        "jitter_seconds": job.jitter_seconds,
        "timeout_ms": job.timeout_ms,
        "enabled": job.enabled,
    })
}

fn scheduler_job_selector_class(job: &ObservabilityJobRecord) -> &'static str {
    if job.pair_selector_json.is_some() {
        return "explicit_pair";
    }
    match job.selector_json.get("selector").and_then(Value::as_str) {
        Some("all") => "all",
        Some(selector) if selector.starts_with("role=") => "role",
        Some(selector) if selector.starts_with("node_id=") => "node_id",
        _ => "invalid",
    }
}

fn endpoint_audit_json(endpoint: &EndpointTrustRecord) -> Value {
    serde_json::json!({
        "endpoint_id": endpoint.endpoint_id.clone(),
        "node_id": endpoint.node_id.clone(),
        "fingerprint_present": endpoint.fingerprint.is_some(),
        "status": endpoint.status.as_str(),
        "generation": endpoint.generation,
        "previous_endpoint_id": endpoint.previous_endpoint_id.clone(),
        "rotated_to": endpoint.rotated_to.clone(),
    })
}

fn node_removal_audit_json(
    node: Option<&NodeRecord>,
    registry_endpoint: Option<&EndpointTrustRecord>,
    active_endpoint: Option<&EndpointTrustRecord>,
) -> Value {
    serde_json::json!({
        "node": node.map(node_audit_json),
        "registry_endpoint": registry_endpoint.map(endpoint_audit_json),
        "active_endpoint": active_endpoint.map(endpoint_audit_json),
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

fn canonical_trust_bundle(
    endpoint_id: &str,
    generation: u64,
    status: EndpointStatus,
    value: &Value,
) -> Result<Value, StoreError> {
    let payload = TrustBundlePayloadV1::from_value(value)
        .or_else(|_| {
            TrustBundlePayloadV1::from_legacy(endpoint_id, generation, status.as_str(), value)
        })
        .map_err(StoreError::InvalidInput)?;
    payload
        .validate_relationship(endpoint_id, generation, status.as_str())
        .map_err(StoreError::InvalidInput)?;
    Ok(payload.to_value())
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
    let selector_json = parse_json_column(&selector_json, 2)?;
    let selector = SchedulerSelectorPayloadV1::from_value(&selector_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            Type::Text,
            Box::new(io::Error::new(io::ErrorKind::InvalidData, error)),
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
                Type::Text,
                Box::new(io::Error::new(io::ErrorKind::InvalidData, error)),
            )
        })?;
    let kind: String = row.get(1)?;
    validate_scheduler_payload_relationship(&kind, &selector, pair.as_ref()).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            Type::Text,
            Box::new(io::Error::new(io::ErrorKind::InvalidData, error)),
        )
    })?;
    Ok(ObservabilityJobRecord {
        job_id: row.get(0)?,
        kind,
        selector_json,
        pair_selector_json,
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
    let selector = match SchedulerSelectorPayloadV1::from_value(&selector_json) {
        Ok(value) => value,
        Err(_) => return invalid(&raw, "UNSUPPORTED_SELECTOR_PAYLOAD"),
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
    let pair = match pair_selector_json
        .as_ref()
        .map(SchedulerPairPayloadV1::from_value)
        .transpose()
    {
        Ok(value) => value,
        Err(_) => return invalid(&raw, "UNSUPPORTED_PAIR_SELECTOR_PAYLOAD"),
    };
    if validate_scheduler_payload_relationship(&raw.kind, &selector, pair.as_ref()).is_err() {
        let reason = if raw.kind == "path-probe" {
            "INVALID_PATH_PAIR"
        } else {
            "INVALID_SELECTOR_RELATIONSHIP"
        };
        return invalid(&raw, reason);
    }
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
    let kind: Option<String> = row.get(9)?;
    let job_id: Option<String> = row.get(1)?;
    let status: String = row.get(4)?;
    let triggered_by: String = row.get(5)?;
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
        observation_count: i64_to_u64(observation_count)?,
        failed_observation_count: i64_to_u64(failed_observation_count)?,
    })
}

fn probe_observation_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProbeObservationRecord> {
    let ok: Option<i64> = row.get(5)?;
    let duration_ms: Option<i64> = row.get(7)?;
    let summary_json: String = row.get(11)?;
    let method: String = row.get(4)?;
    let result_class: String = row.get(10)?;
    let summary_json = parse_json_column(&summary_json, 11)?;
    let payload = ObservationSummaryPayloadV1::from_value(&summary_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            11,
            Type::Text,
            Box::new(io::Error::new(io::ErrorKind::InvalidData, error)),
        )
    })?;
    if payload.method != method || payload.result_class != result_class {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            11,
            Type::Text,
            Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
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
        duration_ms: duration_ms.map(i64_to_u64).transpose()?,
        observed_at: row.get(8)?,
        expires_at: row.get(9)?,
        result_class,
        summary_json: payload.public_summary(),
    })
}

fn health_snapshot_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<HealthSnapshotRecord> {
    let freshness_seconds: Option<i64> = row.get(4)?;
    let degraded_methods_json: String = row.get(8)?;
    let summary_json: String = row.get(9)?;
    let degraded_methods_json = parse_json_column(&degraded_methods_json, 8)?;
    HealthDegradedMethodsPayloadV1::from_value(&degraded_methods_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            8,
            Type::Text,
            Box::new(io::Error::new(io::ErrorKind::InvalidData, error)),
        )
    })?;
    let summary_json = parse_json_column(&summary_json, 9)?;
    let summary = HealthSummaryPayloadV1::from_value(&summary_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            9,
            Type::Text,
            Box::new(io::Error::new(io::ErrorKind::InvalidData, error)),
        )
    })?;
    let status: String = row.get(3)?;
    validate_health_payload_relationship(&status, &summary).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            9,
            Type::Text,
            Box::new(io::Error::new(io::ErrorKind::InvalidData, error)),
        )
    })?;
    Ok(HealthSnapshotRecord {
        node_id: row.get(0)?,
        endpoint_id: row.get(1)?,
        computed_at: row.get(2)?,
        status,
        freshness_seconds: freshness_seconds.map(i64_to_u64).transpose()?,
        last_success_at: row.get(5)?,
        last_failure_at: row.get(6)?,
        last_error_code: row.get(7)?,
        degraded_methods_json,
        summary_json,
    })
}

fn alert_event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AlertEventRecord> {
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

fn alert_webhook_hook_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<AlertWebhookHookRecord> {
    let host_allow_json: String = row.get(6)?;
    let host_allow_json = parse_json_column(&host_allow_json, 6)?;
    let payload = AlertHostAllowPayloadV1::from_value(&host_allow_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            6,
            Type::Text,
            Box::new(io::Error::new(io::ErrorKind::InvalidData, error)),
        )
    })?;
    let endpoint_host: String = row.get(5)?;
    payload
        .validate_relationship(&endpoint_host)
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                6,
                Type::Text,
                Box::new(io::Error::new(io::ErrorKind::InvalidData, error)),
            )
        })?;
    Ok(AlertWebhookHookRecord {
        hook_id: row.get(0)?,
        name: row.get(1)?,
        hook_type: row.get(2)?,
        endpoint_url: row.get(3)?,
        endpoint_url_redacted: row.get(4)?,
        endpoint_host,
        host_allow: payload.hosts,
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
    let payload =
        AlertHostAllowPayloadV1::new(hook.host_allow.clone()).map_err(StoreError::InvalidInput)?;
    if payload.hosts != hook.host_allow {
        return Err(StoreError::InvalidInput(
            "alert webhook host allowlist must be canonical".to_string(),
        ));
    }
    payload
        .validate_relationship(&hook.endpoint_host)
        .map_err(StoreError::InvalidInput)?;
    validate_u64_range("max_attempts", hook.max_attempts, 1, 5)?;
    validate_u64_range("timeout_ms", hook.timeout_ms, 1_000, 5_000)?;
    validate_rfc3339(&hook.created_at, "alert hook created_at")?;
    validate_rfc3339(&hook.updated_at, "alert hook updated_at")?;
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
    validate_rfc3339(&attempt.attempted_at, "alert attempt attempted_at")?;
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
    if attempt.status == "failed" && attempt.error_code.is_none() {
        return Err(StoreError::InvalidInput(
            "failed alert delivery attempt requires error_code".to_string(),
        ));
    }
    if attempt.status != "failed" && attempt.error_code.is_some() {
        return Err(StoreError::InvalidInput(
            "non-failed alert delivery attempt cannot have error_code".to_string(),
        ));
    }
    Ok(())
}

fn validate_alert_delivery_finalize(write: &AlertDeliveryFinalizeWrite) -> Result<(), StoreError> {
    validate_audit_text(&write.delivery_id, "alert delivery_id", 96)?;
    let Some(uuid) = write.delivery_id.strip_prefix("delivery-") else {
        return Err(StoreError::InvalidInput(
            "alert delivery_id must use delivery-<uuid> format".to_string(),
        ));
    };
    Uuid::parse_str(uuid).map_err(|_| {
        StoreError::InvalidInput("alert delivery_id must contain a UUID".to_string())
    })?;
    if !matches!(
        write.hook_type.as_str(),
        "jsonl_file" | "webhook" | "rejected"
    ) {
        return Err(StoreError::InvalidInput(
            "alert delivery hook_type is invalid".to_string(),
        ));
    }
    if write.entries.len() > MAX_ALERT_DELIVERY_FINALIZE_RECORDS {
        return Err(StoreError::InvalidInput(format!(
            "alert delivery finalization exceeds {MAX_ALERT_DELIVERY_FINALIZE_RECORDS} records"
        )));
    }
    if write.alert_count > MAX_ALERT_DELIVERY_FINALIZE_RECORDS {
        return Err(StoreError::InvalidInput(format!(
            "alert delivery count exceeds {MAX_ALERT_DELIVERY_FINALIZE_RECORDS} records"
        )));
    }
    if write.bytes_written > 16 * 1024 * 1024 {
        return Err(StoreError::InvalidInput(
            "alert delivery byte count exceeds 16 MiB".to_string(),
        ));
    }
    if write.ok == write.error_code.is_some() {
        return Err(StoreError::InvalidInput(
            "alert delivery error_code must be present exactly when delivery failed".to_string(),
        ));
    }
    if let Some(error_code) = &write.error_code {
        validate_safe_id("error_code", error_code, 64)?;
    }
    if write.dry_run || !write.ok {
        if !write.entries.is_empty() {
            return Err(StoreError::InvalidInput(
                "dry-run or failed delivery cannot update alerts".to_string(),
            ));
        }
    } else if write.entries.len() != write.alert_count {
        return Err(StoreError::InvalidInput(
            "successful delivery must update every delivered alert".to_string(),
        ));
    }
    let mut dedupe_keys = std::collections::BTreeSet::new();
    for entry in &write.entries {
        let before = entry.before.as_ref().ok_or_else(|| {
            StoreError::InvalidInput("delivery finalization requires before-state".to_string())
        })?;
        validate_alert_event_record(before)?;
        validate_alert_event_record(&entry.after)?;
        if before.alert_id != entry.after.alert_id
            || before.dedupe_key != entry.after.dedupe_key
            || !dedupe_keys.insert(before.dedupe_key.as_str())
        {
            return Err(StoreError::InvalidInput(
                "delivery finalization contains invalid alert identity".to_string(),
            ));
        }
        let mut expected = before.clone();
        expected.last_sent_at = entry.after.last_sent_at.clone();
        if entry.after.last_sent_at.is_none() || entry.after != expected {
            return Err(StoreError::InvalidInput(
                "delivery finalization may change only last_sent_at".to_string(),
            ));
        }
    }
    Ok(())
}

fn alert_delivery_attempt_hash(attempt: &AlertDeliveryAttemptRecord) -> String {
    let payload = serde_json::json!({
        "attempt_id": attempt.attempt_id,
        "alert_id": attempt.alert_id,
        "hook_id": attempt.hook_id,
        "attempt_no": attempt.attempt_no,
        "attempted_at": attempt.attempted_at,
        "status": attempt.status,
        "http_status_class": attempt.http_status_class,
        "error_code": attempt.error_code,
        "bytes_sent": attempt.bytes_sent,
    });
    blake3::hash(&serde_json::to_vec(&payload).expect("alert attempt hash JSON serializes"))
        .to_hex()
        .to_string()
}

fn alert_delivery_finalize_hash(write: &AlertDeliveryFinalizeWrite) -> String {
    let entries = write
        .entries
        .iter()
        .map(|entry| {
            serde_json::json!({
                "before": entry.before.as_ref().map(alert_event_hash_json),
                "after": alert_event_hash_json(&entry.after),
            })
        })
        .collect::<Vec<_>>();
    let payload = serde_json::json!({
        "hook_type": write.hook_type,
        "ok": write.ok,
        "dry_run": write.dry_run,
        "alert_count": write.alert_count,
        "bytes_written": write.bytes_written,
        "error_code": write.error_code,
        "entries": entries,
    });
    blake3::hash(&serde_json::to_vec(&payload).expect("alert delivery hash JSON serializes"))
        .to_hex()
        .to_string()
}

fn insert_alert_delivery_attempt_tx(
    tx: &Transaction<'_>,
    attempt: &AlertDeliveryAttemptRecord,
) -> Result<(), StoreError> {
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

fn get_retention_policy_tx(
    tx: &Transaction<'_>,
    scope: &str,
) -> Result<Option<RetentionPolicyRecord>, StoreError> {
    tx.query_row(
        "SELECT scope, max_age_days, max_rows, updated_at
         FROM retention_policies
         WHERE scope = ?1",
        [scope],
        retention_policy_from_row,
    )
    .optional()
    .map_err(StoreError::from)
}

fn validate_health_snapshot_write(write: &HealthSnapshotWrite) -> Result<(), StoreError> {
    validate_audit_text(&write.evaluation_id, "health evaluation_id", 96)?;
    let Some(uuid) = write.evaluation_id.strip_prefix("health-eval-") else {
        return Err(StoreError::InvalidInput(
            "health evaluation_id must use health-eval-<uuid> format".to_string(),
        ));
    };
    Uuid::parse_str(uuid).map_err(|_| {
        StoreError::InvalidInput("health evaluation_id must contain a UUID".to_string())
    })?;
    if !matches!(write.event.as_str(), "health.summary" | "health.node") {
        return Err(StoreError::InvalidInput(
            "health evaluation event is not allowed".to_string(),
        ));
    }
    if write.snapshots.len() > MAX_HEALTH_SNAPSHOT_WRITE_RECORDS {
        return Err(StoreError::InvalidInput(format!(
            "health snapshot batch exceeds {MAX_HEALTH_SNAPSHOT_WRITE_RECORDS} records"
        )));
    }
    if write.event == "health.node" && write.snapshots.len() != 1 {
        return Err(StoreError::InvalidInput(
            "health.node requires exactly one snapshot".to_string(),
        ));
    }
    let mut node_ids = std::collections::BTreeSet::new();
    for snapshot in &write.snapshots {
        validate_node_id(&snapshot.node_id)
            .map_err(|err| StoreError::InvalidInput(err.to_string()))?;
        if !node_ids.insert(snapshot.node_id.as_str()) {
            return Err(StoreError::InvalidInput(
                "health snapshot batch contains a duplicate node_id".to_string(),
            ));
        }
        snapshot
            .endpoint_id
            .as_deref()
            .map(validate_endpoint_id)
            .transpose()
            .map_err(StoreError::InvalidInput)?;
        validate_rfc3339(&snapshot.computed_at, "health computed_at")?;
        for (value, field) in [
            (
                snapshot.last_success_at.as_deref(),
                "health last_success_at",
            ),
            (
                snapshot.last_failure_at.as_deref(),
                "health last_failure_at",
            ),
        ] {
            if let Some(value) = value {
                validate_rfc3339(value, field)?;
            }
        }
        if !matches!(
            snapshot.status.as_str(),
            "healthy" | "degraded" | "unreachable" | "stale" | "disabled" | "unknown"
        ) {
            return Err(StoreError::InvalidInput(
                "health snapshot status is not allowed".to_string(),
            ));
        }
        if let Some(error_code) = &snapshot.last_error_code {
            validate_audit_text(error_code, "health last_error_code", 64)?;
        }
        HealthDegradedMethodsPayloadV1::from_value(&snapshot.degraded_methods_json)
            .map_err(StoreError::InvalidInput)?;
        let summary = HealthSummaryPayloadV1::from_value(&snapshot.summary_json)
            .map_err(StoreError::InvalidInput)?;
        validate_health_payload_relationship(&snapshot.status, &summary)
            .map_err(StoreError::InvalidInput)?;
    }
    Ok(())
}

fn validate_rfc3339(value: &str, field: &str) -> Result<(), StoreError> {
    if OffsetDateTime::parse(value, &Rfc3339).is_err() {
        return Err(StoreError::InvalidInput(format!("{field} must be RFC3339")));
    }
    Ok(())
}

fn health_snapshot_write_hash(write: &HealthSnapshotWrite) -> String {
    let snapshots = write
        .snapshots
        .iter()
        .map(|snapshot| {
            serde_json::json!({
                "node_id": snapshot.node_id,
                "endpoint_id": snapshot.endpoint_id,
                "computed_at": snapshot.computed_at,
                "status": snapshot.status,
                "freshness_seconds": snapshot.freshness_seconds,
                "last_success_at": snapshot.last_success_at,
                "last_failure_at": snapshot.last_failure_at,
                "last_error_code": snapshot.last_error_code,
                "degraded_methods": snapshot.degraded_methods_json,
                "summary": snapshot.summary_json,
            })
        })
        .collect::<Vec<_>>();
    let payload = serde_json::json!({"event": write.event, "snapshots": snapshots});
    blake3::hash(&serde_json::to_vec(&payload).expect("health snapshot hash JSON serializes"))
        .to_hex()
        .to_string()
}

fn health_snapshot_replay_tx(
    tx: &Transaction<'_>,
    write: &HealthSnapshotWrite,
    actor: &str,
    params_hash: &str,
) -> Result<bool, StoreError> {
    let mut stmt = tx.prepare(
        "SELECT event, actor, params_hash
         FROM controller_audit_log
         WHERE request_id = ?1
         ORDER BY id
         LIMIT 2",
    )?;
    let rows = stmt.query_map([write.evaluation_id.as_str()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })?;
    let existing = rows.collect::<Result<Vec<_>, _>>()?;
    if existing.is_empty() {
        return Ok(false);
    }
    if existing.len() == 1
        && existing[0].0 == write.event
        && existing[0].1 == actor
        && existing[0].2.as_deref() == Some(params_hash)
    {
        return Ok(true);
    }
    Err(StoreError::HealthEvaluationConflict {
        evaluation_id: write.evaluation_id.clone(),
        detail: "evaluation audit provenance is mismatched or ambiguous",
    })
}

fn upsert_health_snapshot_tx(
    tx: &Transaction<'_>,
    snapshot: &HealthSnapshotRecord,
) -> Result<(), StoreError> {
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
    Ok(())
}

fn validate_alert_evaluation_write(write: &AlertEvaluationWrite) -> Result<(), StoreError> {
    validate_audit_text(&write.evaluation_id, "alert evaluation_id", 96)?;
    let Some(uuid) = write.evaluation_id.strip_prefix("alert-eval-") else {
        return Err(StoreError::InvalidInput(
            "alert evaluation_id must use alert-eval-<uuid> format".to_string(),
        ));
    };
    Uuid::parse_str(uuid).map_err(|_| {
        StoreError::InvalidInput("alert evaluation_id must contain a UUID".to_string())
    })?;
    if write.entries.is_empty() || write.entries.len() > MAX_ALERT_EVALUATION_RECORDS {
        return Err(StoreError::InvalidInput(format!(
            "alert evaluation must contain 1-{MAX_ALERT_EVALUATION_RECORDS} records"
        )));
    }
    let mut alert_ids = std::collections::BTreeSet::new();
    let mut dedupe_keys = std::collections::BTreeSet::new();
    for entry in &write.entries {
        if let Some(before) = &entry.before {
            validate_alert_event_record(before)?;
            if before.alert_id != entry.after.alert_id
                || before.dedupe_key != entry.after.dedupe_key
            {
                return Err(StoreError::InvalidInput(
                    "alert evaluation cannot change alert identity".to_string(),
                ));
            }
        }
        validate_alert_event_record(&entry.after)?;
        if !alert_ids.insert(entry.after.alert_id.as_str())
            || !dedupe_keys.insert(entry.after.dedupe_key.as_str())
        {
            return Err(StoreError::InvalidInput(
                "alert evaluation contains duplicate alert identity".to_string(),
            ));
        }
        if !matches!(entry.after.state.as_str(), "open" | "silenced") {
            return Err(StoreError::InvalidInput(
                "alert evaluation can write only open or silenced candidates".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_alert_event_record(alert: &AlertEventRecord) -> Result<(), StoreError> {
    validate_safe_id("alert_id", &alert.alert_id, 128)?;
    validate_safe_id("dedupe_key", &alert.dedupe_key, 256)?;
    if let Some(node_id) = &alert.node_id {
        validate_node_id(node_id).map_err(|err| StoreError::InvalidInput(err.to_string()))?;
    }
    if !matches!(alert.severity.as_str(), "warning" | "critical") {
        return Err(StoreError::InvalidInput(
            "alert severity is not allowed".to_string(),
        ));
    }
    if !matches!(alert.state.as_str(), "open" | "silenced" | "resolved") {
        return Err(StoreError::InvalidInput(
            "alert state is not allowed".to_string(),
        ));
    }
    validate_safe_id("reason_code", &alert.reason_code, 64)?;
    validate_rfc3339(&alert.first_seen_at, "alert first_seen_at")?;
    validate_rfc3339(&alert.last_seen_at, "alert last_seen_at")?;
    for (value, field) in [
        (alert.last_sent_at.as_deref(), "alert last_sent_at"),
        (alert.resolved_at.as_deref(), "alert resolved_at"),
    ] {
        if let Some(value) = value {
            validate_rfc3339(value, field)?;
        }
    }
    validate_low_sensitive_json(&alert.detail_json, "alert detail")?;
    canonical_alert_detail(&alert.detail_json)?;
    Ok(())
}

fn alert_evaluation_write_hash(write: &AlertEvaluationWrite) -> String {
    let entries = write
        .entries
        .iter()
        .map(|entry| {
            serde_json::json!({
                "before": entry.before.as_ref().map(alert_event_hash_json),
                "after": alert_event_hash_json(&entry.after),
            })
        })
        .collect::<Vec<_>>();
    blake3::hash(&serde_json::to_vec(&entries).expect("alert evaluation hash JSON serializes"))
        .to_hex()
        .to_string()
}

fn alert_event_hash_json(alert: &AlertEventRecord) -> Value {
    serde_json::json!({
        "alert_id": alert.alert_id,
        "dedupe_key": alert.dedupe_key,
        "node_id": alert.node_id,
        "severity": alert.severity,
        "state": alert.state,
        "reason_code": alert.reason_code,
        "first_seen_at": alert.first_seen_at,
        "last_seen_at": alert.last_seen_at,
        "last_sent_at": alert.last_sent_at,
        "resolved_at": alert.resolved_at,
        "detail": alert.detail_json,
    })
}

fn alert_evaluation_replay_tx(
    tx: &Transaction<'_>,
    write: &AlertEvaluationWrite,
    actor: &str,
    params_hash: &str,
) -> Result<bool, StoreError> {
    let mut stmt = tx.prepare(
        "SELECT event, actor, params_hash
         FROM controller_audit_log
         WHERE request_id = ?1
         ORDER BY id
         LIMIT 2",
    )?;
    let rows = stmt.query_map([write.evaluation_id.as_str()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })?;
    let existing = rows.collect::<Result<Vec<_>, _>>()?;
    if existing.is_empty() {
        return Ok(false);
    }
    if existing.len() == 1
        && existing[0].0 == "alert.evaluate"
        && existing[0].1 == actor
        && existing[0].2.as_deref() == Some(params_hash)
    {
        return Ok(true);
    }
    Err(StoreError::AlertEvaluationConflict {
        evaluation_id: write.evaluation_id.clone(),
        detail: "evaluation audit provenance is mismatched or ambiguous",
    })
}

fn upsert_alert_event_tx(tx: &Transaction<'_>, alert: &AlertEventRecord) -> Result<(), StoreError> {
    let detail_json = canonical_alert_detail(&alert.detail_json)?;
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
            compact_json(&detail_json),
        ],
    )?;
    Ok(())
}

fn canonical_alert_detail(value: &Value) -> Result<Value, StoreError> {
    let payload = AlertDetailPayloadV1::from_value(value)
        .or_else(|_| AlertDetailPayloadV1::from_legacy(value))
        .map_err(StoreError::InvalidInput)?;
    Ok(payload.to_value())
}

fn canonical_enrollment_metadata(
    kind: EnrollmentMetadataKindV1,
    value: &Value,
) -> Result<Value, StoreError> {
    let payload = EnrollmentMetadataPayloadV1::from_value(kind, value)
        .or_else(|_| EnrollmentMetadataPayloadV1::from_legacy(kind, value))
        .map_err(StoreError::InvalidInput)?;
    Ok(payload.to_value())
}

fn normalize_optional_alert(
    alert: Option<&AlertEventRecord>,
) -> Result<Option<AlertEventRecord>, StoreError> {
    alert
        .map(|alert| {
            let mut normalized = alert.clone();
            let payload = AlertDetailPayloadV1::from_value(&alert.detail_json)
                .or_else(|_| AlertDetailPayloadV1::from_legacy(&alert.detail_json))
                .map_err(StoreError::InvalidInput)?;
            normalized.detail_json = payload.public_detail();
            Ok(normalized)
        })
        .transpose()
}

fn get_alert_event_tx(
    tx: &Transaction<'_>,
    dedupe_key: &str,
) -> Result<Option<AlertEventRecord>, StoreError> {
    tx.query_row(
        "SELECT alert_id, dedupe_key, node_id, severity, state, reason_code, first_seen_at, last_seen_at, last_sent_at, resolved_at, detail_json
         FROM alert_events
         WHERE dedupe_key = ?1",
        [dedupe_key],
        alert_event_from_row,
    )
    .optional()
    .map_err(StoreError::from)
}

fn validate_alert_state_transition(write: &AlertStateTransition) -> Result<(), StoreError> {
    validate_audit_text(&write.operation_id, "alert operation_id", 96)?;
    let Some(uuid) = write.operation_id.strip_prefix("alert-action-") else {
        return Err(StoreError::InvalidInput(
            "alert operation_id must use alert-action-<uuid> format".to_string(),
        ));
    };
    Uuid::parse_str(uuid).map_err(|_| {
        StoreError::InvalidInput("alert operation_id must contain a UUID".to_string())
    })?;
    if !matches!(write.event.as_str(), "alert.silence" | "alert.resolve") {
        return Err(StoreError::InvalidInput(
            "alert transition event is not allowed".to_string(),
        ));
    }
    validate_reason(&write.reason).map_err(StoreError::InvalidInput)?;
    validate_alert_event_record(&write.before)?;
    validate_alert_event_record(&write.after)?;
    if write.before.alert_id != write.after.alert_id
        || write.before.dedupe_key != write.after.dedupe_key
        || write.before.node_id != write.after.node_id
    {
        return Err(StoreError::InvalidInput(
            "alert transition cannot change alert identity".to_string(),
        ));
    }
    let expected_state = if write.event == "alert.silence" {
        "silenced"
    } else {
        "resolved"
    };
    if write.after.state != expected_state {
        return Err(StoreError::InvalidInput(
            "alert transition after-state does not match event".to_string(),
        ));
    }
    let reason_key = if write.event == "alert.silence" {
        "silence_reason"
    } else {
        "resolve_reason"
    };
    if write
        .after
        .detail_json
        .get(reason_key)
        .and_then(Value::as_str)
        != Some(write.reason.as_str())
    {
        return Err(StoreError::InvalidInput(
            "alert transition reason does not match stored detail".to_string(),
        ));
    }
    if write.event == "alert.silence" {
        let until = write
            .after
            .detail_json
            .get("silenced_until")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                StoreError::InvalidInput("alert silence requires silenced_until".to_string())
            })?;
        validate_rfc3339(until, "alert silenced_until")?;
        if write.after.resolved_at.is_some() {
            return Err(StoreError::InvalidInput(
                "silenced alert cannot have resolved_at".to_string(),
            ));
        }
    } else if write.after.resolved_at.as_deref() != Some(write.after.last_seen_at.as_str()) {
        return Err(StoreError::InvalidInput(
            "resolved alert timestamps must match".to_string(),
        ));
    }
    Ok(())
}

fn alert_state_transition_hash(write: &AlertStateTransition) -> String {
    let payload = serde_json::json!({
        "event": write.event,
        "before": alert_event_hash_json(&write.before),
        "after": alert_event_hash_json(&write.after),
        "reason": write.reason,
    });
    blake3::hash(&serde_json::to_vec(&payload).expect("alert transition hash JSON serializes"))
        .to_hex()
        .to_string()
}

fn alert_webhook_hook_hash(hook: &AlertWebhookHookRecord) -> String {
    let payload = serde_json::json!({
        "hook_id": hook.hook_id,
        "name": hook.name,
        "hook_type": hook.hook_type,
        "endpoint_url": hook.endpoint_url,
        "endpoint_url_redacted": hook.endpoint_url_redacted,
        "endpoint_host": hook.endpoint_host,
        "host_allow": hook.host_allow,
        "hmac_key_id": hook.hmac_key_id,
        "enabled": hook.enabled,
        "max_attempts": hook.max_attempts,
        "timeout_ms": hook.timeout_ms,
        "created_at": hook.created_at,
        "updated_at": hook.updated_at,
    });
    blake3::hash(&serde_json::to_vec(&payload).expect("alert hook hash JSON serializes"))
        .to_hex()
        .to_string()
}

fn alert_mutation_replay_tx(
    tx: &Transaction<'_>,
    operation_id: &str,
    event: &str,
    actor: &str,
    params_hash: &str,
) -> Result<bool, StoreError> {
    let mut stmt = tx.prepare(
        "SELECT event, actor, params_hash FROM controller_audit_log
         WHERE request_id = ?1 ORDER BY id LIMIT 2",
    )?;
    let rows = stmt.query_map([operation_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })?;
    let existing = rows.collect::<Result<Vec<_>, _>>()?;
    if existing.is_empty() {
        return Ok(false);
    }
    if existing.len() == 1
        && existing[0].0 == event
        && existing[0].1 == actor
        && existing[0].2.as_deref() == Some(params_hash)
    {
        return Ok(true);
    }
    Err(StoreError::AlertMutationConflict {
        operation_id: operation_id.to_string(),
        detail: "mutation audit provenance is mismatched or ambiguous",
    })
}

fn insert_alert_webhook_hook_tx(
    tx: &Transaction<'_>,
    hook: &AlertWebhookHookRecord,
) -> Result<(), StoreError> {
    let host_allow =
        AlertHostAllowPayloadV1::new(hook.host_allow.clone()).map_err(StoreError::InvalidInput)?;
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
            compact_json(&host_allow.to_value()),
            hook.hmac_key_id.as_str(),
            bool_to_i64(hook.enabled),
            u64_to_i64(hook.max_attempts)?,
            u64_to_i64(hook.timeout_ms)?,
            hook.created_at.as_str(),
            hook.updated_at.as_str(),
        ],
    )?;
    Ok(())
}

fn validate_retention_policy(policy: &RetentionPolicyRecord) -> Result<(), StoreError> {
    retention_target(&policy.scope)?;
    if policy
        .max_age_days
        .is_some_and(|days| days == 0 || days > MAX_RETENTION_POLICY_AGE_DAYS)
    {
        return Err(StoreError::InvalidInput(format!(
            "retention max_age_days must be 1-{MAX_RETENTION_POLICY_AGE_DAYS}"
        )));
    }
    if policy
        .max_rows
        .is_some_and(|rows| rows == 0 || rows > MAX_RETENTION_POLICY_ROWS)
    {
        return Err(StoreError::InvalidInput(format!(
            "retention max_rows must be 1-{MAX_RETENTION_POLICY_ROWS}"
        )));
    }
    if OffsetDateTime::parse(&policy.updated_at, &Rfc3339).is_err() {
        return Err(StoreError::InvalidInput(
            "retention updated_at must be RFC3339".to_string(),
        ));
    }
    Ok(())
}

fn validate_retention_apply_input(input: &RetentionApplyInput) -> Result<(), StoreError> {
    validate_audit_text(&input.operation_id, "retention operation_id", 96)?;
    let Some(uuid) = input.operation_id.strip_prefix("retention-") else {
        return Err(StoreError::InvalidInput(
            "retention operation_id must use retention-<uuid> format".to_string(),
        ));
    };
    Uuid::parse_str(uuid).map_err(|_| {
        StoreError::InvalidInput("retention operation_id must contain a UUID".to_string())
    })?;
    retention_target(&input.scope)?;
    if let Some(cutoff) = &input.cutoff
        && OffsetDateTime::parse(cutoff, &Rfc3339).is_err()
    {
        return Err(StoreError::InvalidInput(
            "retention cutoff must be RFC3339".to_string(),
        ));
    }
    if input
        .max_age_days
        .is_some_and(|days| days == 0 || days > MAX_RETENTION_POLICY_AGE_DAYS)
    {
        return Err(StoreError::InvalidInput(format!(
            "retention max_age_days must be 1-{MAX_RETENTION_POLICY_AGE_DAYS}"
        )));
    }
    if input
        .max_rows
        .is_some_and(|rows| rows == 0 || rows > MAX_RETENTION_POLICY_ROWS)
    {
        return Err(StoreError::InvalidInput(format!(
            "retention max_rows must be 1-{MAX_RETENTION_POLICY_ROWS}"
        )));
    }
    if input
        .limit
        .is_some_and(|limit| limit == 0 || limit > MAX_RETENTION_APPLY_LIMIT)
    {
        return Err(StoreError::InvalidInput(format!(
            "retention limit must be 1-{MAX_RETENTION_APPLY_LIMIT}"
        )));
    }
    if input.batch_size == 0 || input.batch_size > MAX_RETENTION_BATCH_SIZE {
        return Err(StoreError::InvalidInput(format!(
            "retention batch_size must be 1-{MAX_RETENTION_BATCH_SIZE}"
        )));
    }
    Ok(())
}

fn retention_policy_audit_json(policy: &RetentionPolicyRecord) -> Value {
    serde_json::json!({
        "scope": policy.scope,
        "max_age_days": policy.max_age_days,
        "max_rows": policy.max_rows,
        "updated_at": policy.updated_at,
    })
}

fn retention_apply_audit_json(input: &RetentionApplyInput, result: &RetentionApplyResult) -> Value {
    let checksum_payload = serde_json::json!({
        "scope": input.scope,
        "dry_run": false,
        "cutoff": result.cutoff,
        "max_rows": input.max_rows,
        "matched_count": result.candidate_report.matched_count,
        "planned_delete_count": result.planned_delete_count,
        "rows_deleted": result.rows_deleted,
        "batch_count": result.batch_count,
        "batch_size": input.batch_size,
        "limit": input.limit,
        "oldest_candidate": result.candidate_report.oldest_timestamp,
        "newest_candidate": result.candidate_report.newest_timestamp,
    });
    let mut hasher = Sha256::new();
    hasher
        .update(serde_json::to_vec(&checksum_payload).expect("retention checksum JSON serializes"));
    let report_checksum = format!("{:x}", hasher.finalize());
    serde_json::json!({
        "actor_type": "user",
        "target_type": "retention_scope",
        "target_id": input.scope,
        "scope": input.scope,
        "dry_run": false,
        "requested_cutoff": input.cutoff,
        "max_age_days": input.max_age_days,
        "cutoff": result.cutoff,
        "max_rows": input.max_rows,
        "limit": input.limit,
        "batch_size": input.batch_size,
        "matched_count": result.candidate_report.matched_count,
        "planned_delete_count": result.planned_delete_count,
        "deleted_count": result.rows_deleted,
        "batch_count": result.batch_count,
        "oldest_candidate": result.candidate_report.oldest_timestamp,
        "newest_candidate": result.candidate_report.newest_timestamp,
        "report_checksum": report_checksum,
        "reason": Value::Null,
    })
}

fn retention_apply_replay_tx(
    tx: &Transaction<'_>,
    input: &RetentionApplyInput,
    actor: &str,
) -> Result<Option<RetentionApplyResult>, StoreError> {
    let mut stmt = tx.prepare(
        "SELECT actor, detail_json
         FROM controller_audit_log
         WHERE event = 'retention.apply'
           AND request_id = ?1
           AND json_extract(detail_json, '$.target_id') = ?2
         ORDER BY id
         LIMIT 2",
    )?;
    let rows = stmt.query_map(
        params![input.operation_id.as_str(), input.scope.as_str()],
        |row| {
            let detail: String = row.get(1)?;
            Ok((row.get::<_, String>(0)?, parse_json_column(&detail, 1)?))
        },
    )?;
    let existing = rows.collect::<Result<Vec<_>, _>>()?;
    if existing.is_empty() {
        return Ok(None);
    }
    let conflict = || StoreError::RetentionOperationConflict {
        operation_id: input.operation_id.clone(),
        detail: "operation audit provenance is mismatched or ambiguous",
    };
    if existing.len() != 1 {
        return Err(conflict());
    }
    let (existing_actor, detail) = &existing[0];
    let required = [
        "requested_cutoff",
        "max_age_days",
        "cutoff",
        "max_rows",
        "limit",
        "batch_size",
        "matched_count",
        "planned_delete_count",
        "deleted_count",
        "batch_count",
        "oldest_candidate",
        "newest_candidate",
    ];
    if existing_actor != actor
        || required.iter().any(|key| detail.get(*key).is_none())
        || detail.get("requested_cutoff") != Some(&option_string_json(input.cutoff.as_deref()))
        || detail.get("max_age_days") != Some(&option_u64_json(input.max_age_days))
        || detail.get("max_rows") != Some(&option_u64_json(input.max_rows))
        || detail.get("limit") != Some(&option_u64_json(input.limit))
        || detail.get("batch_size").and_then(Value::as_u64) != Some(input.batch_size)
    {
        return Err(conflict());
    }
    let read_u64 = |key: &str| detail.get(key).and_then(Value::as_u64).ok_or_else(conflict);
    let read_optional_string = |key: &str| -> Result<Option<String>, StoreError> {
        match detail.get(key) {
            Some(Value::Null) => Ok(None),
            Some(Value::String(value)) => Ok(Some(value.clone())),
            _ => Err(conflict()),
        }
    };
    Ok(Some(RetentionApplyResult {
        cutoff: read_optional_string("cutoff")?,
        candidate_report: RetentionCandidateReport {
            matched_count: read_u64("matched_count")?,
            oldest_timestamp: read_optional_string("oldest_candidate")?,
            newest_timestamp: read_optional_string("newest_candidate")?,
        },
        planned_delete_count: read_u64("planned_delete_count")?,
        rows_deleted: read_u64("deleted_count")?,
        batch_count: read_u64("batch_count")?,
    }))
}

fn option_u64_json(value: Option<u64>) -> Value {
    value.map(Value::from).unwrap_or(Value::Null)
}

fn option_string_json(value: Option<&str>) -> Value {
    value
        .map(|value| Value::String(value.to_string()))
        .unwrap_or(Value::Null)
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
    let labels =
        enrollment_metadata_from_column(&labels_json, 9, EnrollmentMetadataKindV1::TokenLabels)?;
    let scope =
        enrollment_metadata_from_column(&scope_json, 10, EnrollmentMetadataKindV1::TokenScope)?;
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
        labels_json: labels.public_value(),
        scope_json: scope.public_value(),
    })
}

fn join_request_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<JoinRequestRecord> {
    let status: String = row.get(2)?;
    let status = parse_status(&status, 2)?;
    let requested_labels_json: String = row.get(9)?;
    let approved_labels_json: String = row.get(10)?;
    let requested_labels = enrollment_metadata_from_column(
        &requested_labels_json,
        9,
        EnrollmentMetadataKindV1::RequestedLabels,
    )?;
    let approved_labels = enrollment_metadata_from_column(
        &approved_labels_json,
        10,
        EnrollmentMetadataKindV1::ApprovedLabels,
    )?;
    if status != JoinRequestStatus::Approved && !approved_labels.values.is_empty() {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            10,
            Type::Text,
            Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                "non-approved enrollment request contains approved labels",
            )),
        ));
    }
    Ok(JoinRequestRecord {
        request_id: row.get(0)?,
        token_id: row.get(1)?,
        status,
        agent_public_key: row.get(3)?,
        fingerprint: row.get(4)?,
        requested_endpoint_id: row.get(5)?,
        assigned_endpoint_id: row.get(6)?,
        hostname: row.get(7)?,
        agent_version: row.get(8)?,
        requested_labels_json: requested_labels.public_value(),
        approved_labels_json: approved_labels.public_value(),
        created_at: row.get(11)?,
        approved_at: row.get(12)?,
        approved_by: row.get(13)?,
        rejection_reason: row.get(14)?,
        audit_correlation_id: row.get(15)?,
    })
}

fn enrollment_metadata_from_column(
    value: &str,
    column: usize,
    kind: EnrollmentMetadataKindV1,
) -> rusqlite::Result<EnrollmentMetadataPayloadV1> {
    let value = parse_json_column(value, column)?;
    EnrollmentMetadataPayloadV1::from_value(kind, &value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            Type::Text,
            Box::new(io::Error::new(io::ErrorKind::InvalidData, error)),
        )
    })
}

fn endpoint_trust_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EndpointTrustRecord> {
    let status: String = row.get(3)?;
    let trust_bundle_json: String = row.get(7)?;
    let endpoint_id: String = row.get(0)?;
    let generation = i64_to_u64(row.get(4)?)?;
    let trust_bundle_json = parse_json_column(&trust_bundle_json, 7)?;
    let payload = TrustBundlePayloadV1::from_value(&trust_bundle_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            7,
            Type::Text,
            Box::new(io::Error::new(io::ErrorKind::InvalidData, error)),
        )
    })?;
    payload
        .validate_relationship(&endpoint_id, generation, &status)
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                7,
                Type::Text,
                Box::new(io::Error::new(io::ErrorKind::InvalidData, error)),
            )
        })?;
    Ok(EndpointTrustRecord {
        endpoint_id,
        node_id: row.get(1)?,
        fingerprint: row.get(2)?,
        status: parse_status(&status, 3)?,
        generation,
        previous_endpoint_id: row.get(5)?,
        rotated_to: row.get(6)?,
        trust_bundle_json: payload.public_bundle(),
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

fn parse_json_column(value: &str, column: usize) -> rusqlite::Result<Value> {
    serde_json::from_str(value)
        .map_err(|err| rusqlite::Error::FromSqlConversionFailure(column, Type::Text, Box::new(err)))
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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ACTOR: &str = "store-test";

    #[test]
    fn store_binds_relative_database_path_to_opened_file() {
        let cwd = std::env::current_dir().expect("current directory");
        let dir = tempfile::Builder::new()
            .prefix("ocfleet-store-path-")
            .tempdir_in(&cwd)
            .expect("temp dir");
        let relative_db = dir
            .path()
            .strip_prefix(&cwd)
            .expect("temp dir below current directory")
            .join("controller.sqlite");

        let store = Store::open(&relative_db).expect("store opens");

        assert_eq!(store.database_path(), cwd.join(relative_db));
    }

    #[test]
    fn endpoint_dispatch_binding_returns_active_missing_and_inactive() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db = dir.path().join("controller.sqlite");
        let store = Store::open(&db).expect("store opens");
        let endpoint_id = iroh::SecretKey::generate().public().to_string();
        let node = NodeInsert {
            node_id: "readonly-node".into(),
            endpoint_id,
            name: "readonly-node".into(),
            region: "test".into(),
            role: "ocserv".into(),
        };
        store.add_node(&node, TEST_ACTOR).expect("insert node");

        let active = Store::read_endpoint_dispatch_binding(
            store.database_path(),
            &node.node_id,
            &node.endpoint_id,
        )
        .expect("read active endpoint")
        .expect("active endpoint exists");
        assert_eq!(active.status, EndpointStatus::Active);
        assert_eq!(active.trust_node_id.as_deref(), Some(node.node_id.as_str()));
        assert_eq!(
            active.registry_endpoint_id.as_deref(),
            Some(node.endpoint_id.as_str())
        );
        assert_eq!(active.registry_enabled, Some(true));
        assert_eq!(active.active_endpoint_count_for_node, 1);
        assert_eq!(
            store
                .get_endpoint_dispatch_binding(&node.node_id, &node.endpoint_id)
                .expect("read binding from open store"),
            Some(active)
        );
        assert!(
            Store::read_endpoint_dispatch_binding(
                store.database_path(),
                &node.node_id,
                "missing-endpoint",
            )
            .expect("read missing endpoint")
            .is_none()
        );

        store
            .quarantine_endpoint(&node.endpoint_id, TEST_ACTOR, "test quarantine")
            .expect("quarantine endpoint");
        let inactive = Store::read_endpoint_dispatch_binding(
            store.database_path(),
            &node.node_id,
            &node.endpoint_id,
        )
        .expect("read inactive endpoint")
        .expect("inactive endpoint exists");
        assert_eq!(inactive.status, EndpointStatus::Quarantined);
        assert_eq!(inactive.registry_enabled, Some(false));
        assert_eq!(inactive.active_endpoint_count_for_node, 0);
    }

    #[test]
    fn endpoint_dispatch_binding_is_query_only_and_does_not_run_migrations() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db = dir.path().join("controller.sqlite");
        let store = Store::open(&db).expect("store opens");
        let node = NodeInsert {
            node_id: "readonly-no-write-node".into(),
            endpoint_id: "readonly-no-write-endpoint".into(),
            name: "readonly-no-write-node".into(),
            region: "test".into(),
            role: "ocserv".into(),
        };
        store.add_node(&node, TEST_ACTOR).expect("insert node");
        let database_path = store.database_path().to_path_buf();
        drop(store);

        let conn = Connection::open(&database_path).expect("open database for test setup");
        conn.execute(
            "DELETE FROM schema_migrations WHERE version = ?1",
            [CURRENT_SCHEMA_VERSION],
        )
        .expect("mark schema as one version behind");
        let audit_count_before: i64 = conn
            .query_row("SELECT count(*) FROM controller_audit_log", [], |row| {
                row.get(0)
            })
            .expect("count audit rows");
        drop(conn);
        let database_before = std::fs::read(&database_path).expect("read database before lookup");

        let binding =
            Store::read_endpoint_dispatch_binding(&database_path, &node.node_id, &node.endpoint_id)
                .expect("read endpoint")
                .expect("endpoint exists");

        assert_eq!(binding.status, EndpointStatus::Active);
        assert_eq!(binding.active_endpoint_count_for_node, 1);
        assert_eq!(
            std::fs::read(&database_path).expect("read database after lookup"),
            database_before
        );
        let conn = Connection::open(&database_path).expect("reopen database for assertions");
        let version: i64 = conn
            .query_row("SELECT max(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("read schema version");
        let audit_count_after: i64 = conn
            .query_row("SELECT count(*) FROM controller_audit_log", [], |row| {
                row.get(0)
            })
            .expect("count audit rows");
        assert_eq!(version, CURRENT_SCHEMA_VERSION - 1);
        assert_eq!(audit_count_after, audit_count_before);
    }

    #[cfg(unix)]
    #[test]
    fn endpoint_dispatch_binding_rejects_unsafe_database_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let db = dir.path().join("controller.sqlite");
        drop(Store::open(&db).expect("store opens"));
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644))
            .expect("make database unsafe");

        assert!(matches!(
            Store::read_endpoint_dispatch_binding(&db, "node", "endpoint"),
            Err(StoreError::UnsafePermissions)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn endpoint_dispatch_binding_rejects_missing_database() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db = dir.path().join("missing.sqlite");

        assert!(matches!(
            Store::read_endpoint_dispatch_binding(&db, "node", "endpoint"),
            Err(StoreError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound
        ));
    }
}
