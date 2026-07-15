//! Native relational Postgres backend under construction for C1.
//!
//! This module is deliberately not wired into the CLI/runtime until every
//! `StoreReader` and `StoreWriter` contract has native parity. The current
//! dormant slices cover registry/trust, scheduler/observations, and
//! health/alerts while preserving fail-closed migrations and atomic audit.

use std::fmt;
use std::str::FromStr;

use ocfleet_config::validation::{validate_node_id, validate_region, validate_role};
use ocfleet_protocol::enrollment::{
    EndpointStatus, EnrollmentTokenStatus, JoinRequestStatus, TrustBundle,
};
use ocfleet_protocol::method::{
    OCSERV_CERT_EXPIRY, OCSERV_CONFIG_FINGERPRINT, OCSERV_SERVICE_SUMMARY, OCSERV_SESSIONS_SUMMARY,
    OCSERV_VERSION, PROBE_CONTROLLER_PING, PROBE_PATH_ECHO,
};
use postgres::{Config, GenericClient, NoTls, Transaction};
use r2d2::{Pool, PooledConnection};
use r2d2_postgres::PostgresConnectionManager;
use serde_json::{Value, json};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::audit::AuditEvent;
use crate::backend::MAX_STORE_READER_ROWS;
use crate::input_validation::{
    validate_actor, validate_agent_fingerprint, validate_agent_public_key, validate_agent_version,
    validate_description, validate_endpoint_id, validate_hostname, validate_label_json,
    validate_metadata_value, validate_reason,
};
use crate::postgres_backend::{PostgresConnectionSource, PostgresError, validate_transport};
use crate::storage_payloads::{
    AlertDetailPayloadV1, AlertHostAllowPayloadV1, AuditDetailPayloadV1, EnrollmentMetadataKindV1,
    EnrollmentMetadataPayloadV1, HealthDegradedMethodsPayloadV1, HealthSummaryPayloadV1,
    ObservationSummaryPayloadV1, RunSummaryPayloadV1, SchedulerPairPayloadV1,
    SchedulerSelectorPayloadV1, TrustBundlePayloadV1, validate_health_payload_relationship,
    validate_scheduler_payload_relationship,
};
use crate::store::{
    AlertDeliveryAttemptRecord, AlertDeliveryAttemptWrite, AlertDeliveryFinalizeWrite,
    AlertDeliveryQueueClaim, AlertDeliveryQueueEnqueue, AlertDeliveryQueueHealth,
    AlertDeliveryQueueOutcome, AlertEvaluationWrite, AlertEventRecord, AlertStateTransition,
    AlertWebhookHookRecord, ApprovalInput, EndpointTrustRecord, EnrollmentTokenInsert,
    EnrollmentTokenRecord, HealthEvaluationFailure, HealthEvaluationFinish,
    HealthEvaluationRunRecord, HealthEvaluationStart, HealthHistoryRecord, HealthPolicyRecord,
    HealthRollupRecord, HealthRollupSource, HealthRollupWrite, HealthSnapshotRecord,
    HealthSnapshotWrite, JoinRequestInsert, JoinRequestRecord, LegacyEnrollmentClaimInput,
    MAX_ENROLLMENT_TOKEN_USES, MAX_RETENTION_APPLY_LIMIT, MAX_RETENTION_BATCH_SIZE,
    MAX_RETENTION_POLICY_AGE_DAYS, MAX_RETENTION_POLICY_ROWS, MAX_SCHEDULER_LEASE_SECONDS,
    MIN_SCHEDULER_LEASE_SECONDS, NodeInsert, NodeMaintenanceWindow, NodeMetadataRecord, NodeRecord,
    ObservabilityJobRecord, ObservabilityRunInsert, ObservabilityRunRecord, ProbeObservationInsert,
    ProbeObservationRecord, RetentionApplyInput, RetentionApplyResult, RetentionCandidateReport,
    RetentionPolicyRecord, SchedulerJobClaim, SchedulerJobClockUpdate, SchedulerMaintenanceWindow,
    SchedulerOutcomeWrite, SchedulerRunFinish, SchedulerRunStart, Store, StoreError, TrustSnapshot,
    alert_delivery_attempt_hash, alert_delivery_finalize_hash, alert_evaluation_write_hash,
    alert_state_transition_hash, alert_webhook_hook_hash, delivery_attempt_detail_payload,
    health_rollup_write_hash, health_snapshot_write_hash, validate_alert_delivery_attempt_record,
    validate_alert_delivery_finalize, validate_alert_delivery_queue_claim,
    validate_alert_delivery_queue_claim_input, validate_alert_delivery_queue_enqueue,
    validate_alert_delivery_queue_outcome, validate_alert_evaluation_write,
    validate_alert_event_record, validate_alert_state_transition,
    validate_alert_webhook_hook_record, validate_health_evaluation_failure,
    validate_health_evaluation_finish, validate_health_evaluation_start, validate_health_policy,
    validate_health_rollup_bucket, validate_health_rollup_write, validate_health_snapshot_write,
    validate_low_sensitive_json, validate_node_maintenance_record, validate_node_metadata_record,
};
use crate::version_governance::{
    CapabilityNegotiationStatus, CapabilitySnapshot, MAX_VERSION_GOVERNANCE_NODES,
    VersionGovernanceInput,
};

type Manager = PostgresConnectionManager<NoTls>;
type Connection = PooledConnection<Manager>;

const MIGRATION_LOCK_ID: i64 = 0x4f43464c4e4154;
const OPERATION_LOCK_SALT: i64 = 0x4f43464c4f5053;
const NATIVE_MIGRATION_1_NAME: &str = "0001_native_core";
const NATIVE_MIGRATION_2_NAME: &str = "0002_registry_trust";
const NATIVE_MIGRATION_3_NAME: &str = "0003_scheduler_observations";
const NATIVE_MIGRATION_4_NAME: &str = "0004_health_alerts";
const MAX_SCHEDULER_OUTCOME_ENTRIES: usize = 4;
pub const NATIVE_BACKEND_SCHEMA_VERSION: i32 = 4;

#[derive(Clone)]
pub struct PostgresNativeStore {
    pool: Pool<Manager>,
}

impl fmt::Debug for PostgresNativeStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresNativeStore")
            .field("backend", &"postgres-native")
            .finish_non_exhaustive()
    }
}

pub fn connect_native(
    source: &PostgresConnectionSource,
) -> Result<PostgresNativeStore, PostgresError> {
    let private = source.load()?;
    let config = validated_native_config(&private.dsn)?;
    let manager = PostgresConnectionManager::new(config, NoTls);
    let pool = Pool::builder().max_size(private.pool_size).build(manager)?;
    let store = PostgresNativeStore { pool };
    store.migrate()?;
    Ok(store)
}

impl PostgresNativeStore {
    fn connection(&self) -> Result<Connection, PostgresError> {
        self.pool.get().map_err(PostgresError::from)
    }

    fn migrate(&self) -> Result<(), PostgresError> {
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK_ID])?;

        let schema_exists: bool = tx
            .query_one("SELECT to_regnamespace('ocfleet_native') IS NOT NULL", &[])?
            .get(0);
        let migrations_exist = if schema_exists {
            tx.query_one(
                "SELECT to_regclass('ocfleet_native.migrations') IS NOT NULL",
                &[],
            )?
            .get(0)
        } else {
            false
        };
        let existing = if migrations_exist {
            tx.query_one(
                "SELECT COALESCE(MAX(version), 0) FROM ocfleet_native.migrations",
                &[],
            )?
            .get::<_, i32>(0)
        } else {
            0
        };
        if existing > NATIVE_BACKEND_SCHEMA_VERSION {
            return Err(PostgresError::UnsupportedBackendSchema(existing));
        }
        for (version, expected_name) in [
            (1_i32, NATIVE_MIGRATION_1_NAME),
            (2_i32, NATIVE_MIGRATION_2_NAME),
            (3_i32, NATIVE_MIGRATION_3_NAME),
            (4_i32, NATIVE_MIGRATION_4_NAME),
        ] {
            if existing < version {
                continue;
            }
            let migration_name: Option<String> = tx
                .query_one(
                    "SELECT (SELECT name FROM ocfleet_native.migrations WHERE version = $1)",
                    &[&version],
                )?
                .get(0);
            if migration_name.as_deref() != Some(expected_name) {
                return Err(PostgresError::InvalidState(
                    "native Postgres migration history is inconsistent".to_string(),
                ));
            }
        }

        if !schema_exists {
            tx.batch_execute("CREATE SCHEMA ocfleet_native")?;
        }
        if !migrations_exist {
            tx.batch_execute(
                r#"
CREATE TABLE ocfleet_native.migrations (
  version INTEGER PRIMARY KEY CHECK (version > 0),
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
"#,
            )?;
        }

        if existing < 1 {
            tx.batch_execute(
                r#"
CREATE TABLE ocfleet_native.nodes (
  node_id TEXT PRIMARY KEY CHECK (length(node_id) BETWEEN 1 AND 128),
  endpoint_id TEXT NOT NULL UNIQUE CHECK (length(endpoint_id) BETWEEN 1 AND 128),
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  region TEXT NOT NULL CHECK (length(region) BETWEEN 1 AND 64),
  role TEXT NOT NULL CHECK (length(role) BETWEEN 1 AND 64),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE ocfleet_native.endpoint_trust (
  endpoint_id TEXT PRIMARY KEY REFERENCES ocfleet_native.nodes(endpoint_id) ON DELETE CASCADE,
  node_id TEXT NOT NULL UNIQUE REFERENCES ocfleet_native.nodes(node_id) ON DELETE CASCADE,
  fingerprint TEXT,
  status TEXT NOT NULL CHECK (status IN ('active', 'rotated', 'revoked', 'quarantined')),
  generation BIGINT NOT NULL CHECK (generation > 0),
  previous_endpoint_id TEXT,
  rotated_to TEXT,
  trust_bundle_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE ocfleet_native.controller_audit_log (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL,
  actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 128),
  event TEXT NOT NULL CHECK (length(event) BETWEEN 1 AND 128),
  node_id TEXT,
  endpoint_id TEXT,
  method TEXT,
  request_id TEXT,
  params_hash TEXT,
  ok BOOLEAN,
  error_code TEXT,
  duration_ms BIGINT CHECK (duration_ms IS NULL OR duration_ms >= 0),
  detail_json JSONB NOT NULL
);

CREATE INDEX idx_native_audit_ts_id
  ON ocfleet_native.controller_audit_log(ts, id);
"#,
            )?;
            tx.execute(
                "INSERT INTO ocfleet_native.migrations (version, name)
             VALUES ($1, $2)",
                &[&1_i32, &NATIVE_MIGRATION_1_NAME],
            )?;
        }

        if existing < 2 {
            tx.batch_execute(
                r#"
ALTER TABLE ocfleet_native.endpoint_trust
  DROP CONSTRAINT endpoint_trust_endpoint_id_fkey,
  DROP CONSTRAINT endpoint_trust_node_id_fkey,
  DROP CONSTRAINT endpoint_trust_node_id_key,
  ALTER COLUMN node_id DROP NOT NULL;

CREATE UNIQUE INDEX idx_native_endpoint_active_node
  ON ocfleet_native.endpoint_trust(node_id)
  WHERE node_id IS NOT NULL AND status = 'active';
CREATE INDEX idx_native_endpoint_node_generation
  ON ocfleet_native.endpoint_trust(node_id, generation, endpoint_id);

CREATE TABLE ocfleet_native.node_metadata (
  node_id TEXT PRIMARY KEY REFERENCES ocfleet_native.nodes(node_id) ON DELETE CASCADE,
  environment TEXT NOT NULL CHECK (length(environment) BETWEEN 1 AND 64),
  site TEXT NOT NULL CHECK (length(site) BETWEEN 1 AND 64),
  owner_team TEXT NOT NULL CHECK (length(owner_team) BETWEEN 1 AND 64),
  service_tier TEXT NOT NULL CHECK (length(service_tier) BETWEEN 1 AND 64),
  expected_agent_version TEXT
    CHECK (expected_agent_version IS NULL OR length(expected_agent_version) BETWEEN 1 AND 64),
  labels_json JSONB NOT NULL CHECK (jsonb_typeof(labels_json) = 'object'),
  updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_native_node_metadata_environment
  ON ocfleet_native.node_metadata(environment, node_id);
CREATE INDEX idx_native_node_metadata_site
  ON ocfleet_native.node_metadata(site, node_id);
CREATE INDEX idx_native_node_metadata_owner
  ON ocfleet_native.node_metadata(owner_team, node_id);
CREATE INDEX idx_native_node_metadata_tier
  ON ocfleet_native.node_metadata(service_tier, node_id);

CREATE TABLE ocfleet_native.node_maintenance_windows (
  node_id TEXT PRIMARY KEY REFERENCES ocfleet_native.nodes(node_id) ON DELETE CASCADE,
  starts_at TIMESTAMPTZ NOT NULL,
  ends_at TIMESTAMPTZ NOT NULL,
  reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 256),
  updated_at TIMESTAMPTZ NOT NULL,
  CHECK (ends_at > starts_at)
);
CREATE INDEX idx_native_node_maintenance_active
  ON ocfleet_native.node_maintenance_windows(starts_at, ends_at, node_id);

CREATE TABLE ocfleet_native.node_capability_snapshots (
  node_id TEXT PRIMARY KEY REFERENCES ocfleet_native.nodes(node_id) ON DELETE CASCADE,
  endpoint_id TEXT NOT NULL CHECK (length(endpoint_id) BETWEEN 1 AND 128),
  observed_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL CHECK (status IN (
    'compatible', 'incompatible_protocol', 'unsupported_capability',
    'legacy_unsupported', 'invalid_response'
  )),
  agent_version TEXT CHECK (agent_version IS NULL OR length(agent_version) BETWEEN 1 AND 64),
  protocol_min INTEGER CHECK (protocol_min IS NULL OR protocol_min BETWEEN 1 AND 65535),
  protocol_max INTEGER CHECK (protocol_max IS NULL OR protocol_max BETWEEN 1 AND 65535),
  ocserv_snapshot_min INTEGER
    CHECK (ocserv_snapshot_min IS NULL OR ocserv_snapshot_min BETWEEN 1 AND 65535),
  ocserv_snapshot_max INTEGER
    CHECK (ocserv_snapshot_max IS NULL OR ocserv_snapshot_max BETWEEN 1 AND 65535),
  controlled_writes_compiled BOOLEAN,
  controlled_writes_locally_enabled BOOLEAN,
  CHECK (protocol_min IS NULL OR protocol_max IS NULL OR protocol_min <= protocol_max),
  CHECK (
    ocserv_snapshot_min IS NULL OR ocserv_snapshot_max IS NULL
    OR ocserv_snapshot_min <= ocserv_snapshot_max
  ),
  CHECK (
    controlled_writes_locally_enabled IS DISTINCT FROM TRUE
    OR controlled_writes_compiled = TRUE
  )
);
CREATE INDEX idx_native_node_capability_observed
  ON ocfleet_native.node_capability_snapshots(observed_at, node_id);

CREATE TABLE ocfleet_native.enrollment_tokens (
  token_id TEXT PRIMARY KEY CHECK (length(token_id) BETWEEN 1 AND 128),
  token_hash TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  created_by TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 128),
  expires_at TIMESTAMPTZ NOT NULL,
  max_uses INTEGER NOT NULL CHECK (max_uses BETWEEN 1 AND 10000),
  used_count INTEGER NOT NULL DEFAULT 0 CHECK (used_count >= 0 AND used_count <= max_uses),
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'expired')),
  description TEXT CHECK (description IS NULL OR length(description) BETWEEN 1 AND 256),
  labels_json JSONB NOT NULL CHECK (jsonb_typeof(labels_json) = 'object'),
  scope_json JSONB NOT NULL CHECK (jsonb_typeof(scope_json) = 'object')
);

CREATE TABLE ocfleet_native.join_requests (
  request_id TEXT PRIMARY KEY CHECK (length(request_id) BETWEEN 1 AND 128),
  token_id TEXT NOT NULL REFERENCES ocfleet_native.enrollment_tokens(token_id),
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
  agent_public_key TEXT NOT NULL CHECK (length(agent_public_key) BETWEEN 1 AND 256),
  fingerprint TEXT NOT NULL CHECK (length(fingerprint) BETWEEN 1 AND 256),
  requested_endpoint_id TEXT,
  assigned_endpoint_id TEXT,
  hostname TEXT NOT NULL CHECK (length(hostname) BETWEEN 1 AND 253),
  agent_version TEXT NOT NULL CHECK (length(agent_version) BETWEEN 1 AND 64),
  requested_labels_json JSONB NOT NULL CHECK (jsonb_typeof(requested_labels_json) = 'object'),
  approved_labels_json JSONB NOT NULL CHECK (jsonb_typeof(approved_labels_json) = 'object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  approved_at TIMESTAMPTZ,
  approved_by TEXT,
  rejection_reason TEXT,
  audit_correlation_id TEXT NOT NULL CHECK (length(audit_correlation_id) BETWEEN 1 AND 128)
);
CREATE INDEX idx_native_join_token_status
  ON ocfleet_native.join_requests(token_id, status, created_at);
"#,
            )?;
            tx.execute(
                "INSERT INTO ocfleet_native.migrations (version, name) VALUES ($1, $2)",
                &[&2_i32, &NATIVE_MIGRATION_2_NAME],
            )?;
        }

        if existing < 3 {
            tx.batch_execute(
                r#"
CREATE TABLE ocfleet_native.observability_jobs (
  job_id TEXT PRIMARY KEY CHECK (length(job_id) BETWEEN 1 AND 128),
  kind TEXT NOT NULL CHECK (kind IN (
    'controller-ping', 'ocserv-status', 'ocserv-cert', 'ocserv-sessions', 'path-probe'
  )),
  selector_json JSONB NOT NULL CHECK (jsonb_typeof(selector_json) = 'object'),
  pair_selector_json JSONB CHECK (
    pair_selector_json IS NULL OR jsonb_typeof(pair_selector_json) = 'object'
  ),
  interval_seconds BIGINT NOT NULL CHECK (interval_seconds BETWEEN 60 AND 86400),
  jitter_seconds BIGINT NOT NULL DEFAULT 0 CHECK (jitter_seconds BETWEEN 0 AND 3600),
  timeout_ms BIGINT NOT NULL CHECK (timeout_ms BETWEEN 1000 AND 30000),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  next_run_at TIMESTAMPTZ,
  last_run_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  CHECK (jitter_seconds <= interval_seconds)
);
CREATE INDEX idx_native_jobs_enabled_next_run
  ON ocfleet_native.observability_jobs(enabled, next_run_at, job_id);

CREATE TABLE ocfleet_native.observability_runs (
  run_id TEXT PRIMARY KEY CHECK (length(run_id) BETWEEN 1 AND 128),
  job_id TEXT REFERENCES ocfleet_native.observability_jobs(job_id) ON DELETE SET NULL,
  started_at TIMESTAMPTZ NOT NULL,
  finished_at TIMESTAMPTZ,
  status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed', 'skipped')),
  triggered_by TEXT NOT NULL CHECK (triggered_by IN ('manual', 'scheduler.run.once')),
  summary_json JSONB NOT NULL CHECK (jsonb_typeof(summary_json) = 'object'),
  CHECK (
    (status = 'running' AND finished_at IS NULL)
    OR (status <> 'running' AND finished_at IS NOT NULL)
  ),
  CHECK (finished_at IS NULL OR finished_at >= started_at)
);
CREATE INDEX idx_native_runs_started
  ON ocfleet_native.observability_runs(started_at DESC, run_id DESC);
CREATE INDEX idx_native_runs_job_started
  ON ocfleet_native.observability_runs(job_id, started_at DESC, run_id DESC);

CREATE TABLE ocfleet_native.probe_observations (
  observation_id TEXT PRIMARY KEY CHECK (length(observation_id) BETWEEN 1 AND 128),
  run_id TEXT REFERENCES ocfleet_native.observability_runs(run_id) ON DELETE SET NULL,
  node_id TEXT,
  endpoint_id TEXT,
  method TEXT NOT NULL CHECK (method IN (
    'probe.controller.ping', 'probe.path.echo', 'ocserv.service.summary',
    'ocserv.version', 'ocserv.sessions.summary', 'ocserv.cert.expiry',
    'ocserv.config.fingerprint'
  )),
  ok BOOLEAN,
  error_code TEXT CHECK (error_code IS NULL OR length(error_code) BETWEEN 1 AND 64),
  duration_ms BIGINT CHECK (duration_ms IS NULL OR duration_ms >= 0),
  observed_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ,
  result_class TEXT NOT NULL CHECK (result_class IN (
    'controller_rpc_summary', 'low_sensitive_summary', 'scheduler_summary'
  )),
  summary_json JSONB NOT NULL CHECK (jsonb_typeof(summary_json) = 'object'),
  CHECK (
    (ok IS NULL AND error_code IS NULL)
    OR (ok = TRUE AND error_code IS NULL)
    OR (ok = FALSE AND error_code IS NOT NULL)
  )
);
CREATE INDEX idx_native_observations_node_observed
  ON ocfleet_native.probe_observations(node_id, observed_at DESC, observation_id DESC);
CREATE INDEX idx_native_observations_method_observed
  ON ocfleet_native.probe_observations(method, observed_at DESC, observation_id DESC);
CREATE INDEX idx_native_observations_run
  ON ocfleet_native.probe_observations(run_id, observation_id);
CREATE INDEX idx_native_observations_expires
  ON ocfleet_native.probe_observations(expires_at, observation_id);

CREATE TABLE ocfleet_native.scheduler_job_claims (
  job_id TEXT PRIMARY KEY REFERENCES ocfleet_native.observability_jobs(job_id) ON DELETE CASCADE,
  owner_id TEXT,
  owner_actor TEXT CHECK (owner_actor IS NULL OR length(owner_actor) BETWEEN 1 AND 128),
  fence_token BIGINT NOT NULL DEFAULT 0 CHECK (fence_token >= 0),
  claimed_at TIMESTAMPTZ,
  lease_expires_at TIMESTAMPTZ,
  active_run_id TEXT REFERENCES ocfleet_native.observability_runs(run_id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  CHECK (
    (owner_id IS NULL AND owner_actor IS NULL AND claimed_at IS NULL AND lease_expires_at IS NULL
      AND active_run_id IS NULL)
    OR
    (owner_id IS NOT NULL AND owner_actor IS NOT NULL
      AND claimed_at IS NOT NULL AND lease_expires_at IS NOT NULL
      AND fence_token > 0 AND lease_expires_at > claimed_at)
  )
);
CREATE INDEX idx_native_scheduler_claim_expiry
  ON ocfleet_native.scheduler_job_claims(lease_expires_at, job_id);
CREATE INDEX idx_native_scheduler_claim_active_run
  ON ocfleet_native.scheduler_job_claims(active_run_id)
  WHERE active_run_id IS NOT NULL;

CREATE TABLE ocfleet_native.scheduler_maintenance (
  singleton_id SMALLINT PRIMARY KEY CHECK (singleton_id = 1),
  starts_at TIMESTAMPTZ NOT NULL,
  ends_at TIMESTAMPTZ NOT NULL,
  reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 256),
  updated_at TIMESTAMPTZ NOT NULL,
  CHECK (ends_at > starts_at)
);

CREATE TABLE ocfleet_native.retention_policies (
  scope TEXT PRIMARY KEY CHECK (scope IN ('observations', 'observability-runs')),
  max_age_days BIGINT CHECK (max_age_days IS NULL OR max_age_days BETWEEN 1 AND 36500),
  max_rows BIGINT CHECK (max_rows IS NULL OR max_rows BETWEEN 1 AND 10000000),
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE ocfleet_native.retention_operations (
  operation_id TEXT PRIMARY KEY CHECK (length(operation_id) BETWEEN 1 AND 128),
  actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 128),
  input_json JSONB NOT NULL CHECK (jsonb_typeof(input_json) = 'object'),
  result_json JSONB NOT NULL CHECK (jsonb_typeof(result_json) = 'object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
"#,
            )?;
            tx.execute(
                "INSERT INTO ocfleet_native.migrations (version, name) VALUES ($1, $2)",
                &[&3_i32, &NATIVE_MIGRATION_3_NAME],
            )?;
        }

        if existing < 4 {
            tx.batch_execute(
                r#"
CREATE TABLE ocfleet_native.health_policy (
  singleton_id SMALLINT PRIMARY KEY CHECK (singleton_id = 1),
  stale_window_seconds BIGINT NOT NULL CHECK (stale_window_seconds BETWEEN 60 AND 2592000),
  unreachable_consecutive_failures BIGINT NOT NULL
    CHECK (unreachable_consecutive_failures BETWEEN 1 AND 100),
  cert_warning_days BIGINT NOT NULL CHECK (cert_warning_days BETWEEN 1 AND 3650),
  cert_critical_days BIGINT NOT NULL CHECK (cert_critical_days BETWEEN 0 AND 3650),
  updated_at TEXT NOT NULL CHECK (length(updated_at) BETWEEN 1 AND 64),
  CHECK (cert_critical_days <= cert_warning_days)
);
INSERT INTO ocfleet_native.health_policy
  (singleton_id, stale_window_seconds, unreachable_consecutive_failures,
   cert_warning_days, cert_critical_days, updated_at)
VALUES (1, 86400, 3, 30, 7, 'default');

CREATE TABLE ocfleet_native.health_evaluation_runs (
  evaluation_id TEXT PRIMARY KEY CHECK (length(evaluation_id) BETWEEN 1 AND 96),
  input_watermark TEXT NOT NULL CHECK (length(input_watermark) = 64),
  policy_version TEXT NOT NULL CHECK (length(policy_version) = 64),
  computation_version TEXT NOT NULL CHECK (length(computation_version) BETWEEN 1 AND 64),
  started_at TIMESTAMPTZ NOT NULL,
  finished_at TIMESTAMPTZ,
  status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
  snapshot_count BIGINT NOT NULL DEFAULT 0 CHECK (snapshot_count BETWEEN 0 AND 1000),
  failure_code TEXT CHECK (failure_code IS NULL OR length(failure_code) BETWEEN 1 AND 64),
  CHECK (
    (status = 'running' AND finished_at IS NULL AND failure_code IS NULL AND snapshot_count = 0)
    OR (status = 'completed' AND finished_at IS NOT NULL AND failure_code IS NULL)
    OR (status = 'failed' AND finished_at IS NOT NULL AND failure_code IS NOT NULL
        AND snapshot_count = 0)
  ),
  CHECK (finished_at IS NULL OR finished_at >= started_at)
);
CREATE UNIQUE INDEX idx_native_health_evaluation_input
  ON ocfleet_native.health_evaluation_runs(
    input_watermark, policy_version, computation_version
  );
CREATE INDEX idx_native_health_evaluation_status_started
  ON ocfleet_native.health_evaluation_runs(status, started_at, evaluation_id);

CREATE TABLE ocfleet_native.health_snapshots (
  node_id TEXT PRIMARY KEY CHECK (length(node_id) BETWEEN 1 AND 128),
  endpoint_id TEXT CHECK (endpoint_id IS NULL OR length(endpoint_id) BETWEEN 1 AND 256),
  computed_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL CHECK (status IN (
    'healthy', 'degraded', 'unreachable', 'stale', 'disabled', 'unknown'
  )),
  freshness_seconds BIGINT CHECK (freshness_seconds IS NULL OR freshness_seconds >= 0),
  last_success_at TIMESTAMPTZ,
  last_failure_at TIMESTAMPTZ,
  last_error_code TEXT CHECK (last_error_code IS NULL OR length(last_error_code) BETWEEN 1 AND 64),
  degraded_methods_json JSONB NOT NULL CHECK (jsonb_typeof(degraded_methods_json) = 'object'),
  summary_json JSONB NOT NULL CHECK (jsonb_typeof(summary_json) = 'object')
);
CREATE INDEX idx_native_health_snapshots_computed
  ON ocfleet_native.health_snapshots(computed_at DESC, node_id);

CREATE TABLE ocfleet_native.health_history (
  evaluation_id TEXT NOT NULL CHECK (length(evaluation_id) BETWEEN 1 AND 96),
  node_id TEXT NOT NULL CHECK (length(node_id) BETWEEN 1 AND 128),
  endpoint_id TEXT CHECK (endpoint_id IS NULL OR length(endpoint_id) BETWEEN 1 AND 256),
  computed_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL CHECK (status IN (
    'healthy', 'degraded', 'unreachable', 'stale', 'disabled', 'unknown'
  )),
  freshness_seconds BIGINT CHECK (freshness_seconds IS NULL OR freshness_seconds >= 0),
  last_success_at TIMESTAMPTZ,
  last_failure_at TIMESTAMPTZ,
  last_error_code TEXT CHECK (last_error_code IS NULL OR length(last_error_code) BETWEEN 1 AND 64),
  degraded_methods_json JSONB NOT NULL CHECK (jsonb_typeof(degraded_methods_json) = 'object'),
  summary_json JSONB NOT NULL CHECK (jsonb_typeof(summary_json) = 'object'),
  PRIMARY KEY (evaluation_id, node_id)
);
CREATE INDEX idx_native_health_history_node_computed
  ON ocfleet_native.health_history(node_id, computed_at DESC, evaluation_id);
CREATE INDEX idx_native_health_history_computed
  ON ocfleet_native.health_history(computed_at DESC, node_id, evaluation_id);
CREATE FUNCTION ocfleet_native.reject_health_history_update() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'native health history is append-only';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER native_health_history_reject_update
BEFORE UPDATE ON ocfleet_native.health_history
FOR EACH ROW EXECUTE FUNCTION ocfleet_native.reject_health_history_update();

CREATE TABLE ocfleet_native.health_rollups (
  node_id TEXT NOT NULL CHECK (length(node_id) BETWEEN 1 AND 128),
  bucket_seconds BIGINT NOT NULL CHECK (bucket_seconds IN (300, 3600, 86400)),
  bucket_start TIMESTAMPTZ NOT NULL,
  bucket_end TIMESTAMPTZ NOT NULL,
  input_watermark TEXT NOT NULL CHECK (length(input_watermark) = 64),
  health_samples BIGINT NOT NULL CHECK (health_samples >= 0),
  covered_slots BIGINT NOT NULL CHECK (covered_slots >= 0),
  expected_slots BIGINT NOT NULL CHECK (expected_slots > 0),
  healthy_count BIGINT NOT NULL CHECK (healthy_count >= 0),
  degraded_count BIGINT NOT NULL CHECK (degraded_count >= 0),
  unreachable_count BIGINT NOT NULL CHECK (unreachable_count >= 0),
  stale_count BIGINT NOT NULL CHECK (stale_count >= 0),
  disabled_count BIGINT NOT NULL CHECK (disabled_count >= 0),
  unknown_count BIGINT NOT NULL CHECK (unknown_count >= 0),
  observation_count BIGINT NOT NULL CHECK (observation_count >= 0),
  observation_error_count BIGINT NOT NULL CHECK (observation_error_count >= 0),
  duration_sample_count BIGINT NOT NULL CHECK (duration_sample_count >= 0),
  duration_p50_ms BIGINT CHECK (duration_p50_ms IS NULL OR duration_p50_ms >= 0),
  duration_p95_ms BIGINT CHECK (duration_p95_ms IS NULL OR duration_p95_ms >= 0),
  cert_warning_count BIGINT NOT NULL CHECK (cert_warning_count >= 0),
  cert_critical_count BIGINT NOT NULL CHECK (cert_critical_count >= 0),
  fingerprint_sample_count BIGINT NOT NULL CHECK (fingerprint_sample_count >= 0),
  fingerprint_change_count BIGINT NOT NULL CHECK (fingerprint_change_count >= 0),
  computed_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (node_id, bucket_seconds, bucket_start),
  CHECK (bucket_end > bucket_start),
  CHECK (expected_slots = bucket_seconds / 300),
  CHECK (health_samples = covered_slots),
  CHECK (covered_slots <= expected_slots),
  CHECK (
    healthy_count + degraded_count + unreachable_count + stale_count
      + disabled_count + unknown_count = health_samples
  ),
  CHECK (observation_error_count <= observation_count),
  CHECK (
    (duration_sample_count = 0 AND duration_p50_ms IS NULL AND duration_p95_ms IS NULL)
    OR (duration_sample_count > 0 AND duration_p50_ms IS NOT NULL AND duration_p95_ms IS NOT NULL)
  ),
  CHECK (duration_p50_ms IS NULL OR duration_p50_ms <= duration_p95_ms),
  CHECK (fingerprint_change_count <= fingerprint_sample_count)
);
CREATE INDEX idx_native_health_rollups_window
  ON ocfleet_native.health_rollups(bucket_seconds, bucket_start, node_id);

CREATE TABLE ocfleet_native.alert_events (
  alert_id TEXT PRIMARY KEY CHECK (length(alert_id) BETWEEN 1 AND 128),
  dedupe_key TEXT NOT NULL UNIQUE CHECK (length(dedupe_key) BETWEEN 1 AND 256),
  node_id TEXT CHECK (node_id IS NULL OR length(node_id) BETWEEN 1 AND 128),
  severity TEXT NOT NULL CHECK (severity IN ('warning', 'critical')),
  state TEXT NOT NULL CHECK (state IN ('open', 'resolved', 'silenced')),
  reason_code TEXT NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 64),
  first_seen_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL,
  last_sent_at TIMESTAMPTZ,
  resolved_at TIMESTAMPTZ,
  detail_json JSONB NOT NULL CHECK (jsonb_typeof(detail_json) = 'object'),
  CHECK (length(detail_json::text) <= 65536)
);
CREATE INDEX idx_native_alert_events_seen
  ON ocfleet_native.alert_events(last_seen_at DESC, alert_id);
CREATE INDEX idx_native_alert_events_filter
  ON ocfleet_native.alert_events(state, severity, node_id, last_seen_at DESC);

CREATE TABLE ocfleet_native.alert_hooks (
  hook_id TEXT PRIMARY KEY CHECK (length(hook_id) BETWEEN 1 AND 128),
  name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 256),
  hook_type TEXT NOT NULL CHECK (hook_type = 'webhook'),
  endpoint_url TEXT NOT NULL,
  endpoint_url_redacted TEXT NOT NULL,
  endpoint_host TEXT NOT NULL CHECK (length(endpoint_host) BETWEEN 1 AND 253),
  host_allow_json JSONB NOT NULL CHECK (jsonb_typeof(host_allow_json) = 'object'),
  hmac_key_id TEXT NOT NULL CHECK (length(hmac_key_id) BETWEEN 1 AND 128),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  max_attempts BIGINT NOT NULL CHECK (max_attempts BETWEEN 1 AND 5),
  timeout_ms BIGINT NOT NULL CHECK (timeout_ms BETWEEN 1000 AND 5000),
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_native_alert_hooks_enabled_type
  ON ocfleet_native.alert_hooks(enabled, hook_type);

CREATE TABLE ocfleet_native.alert_delivery_attempts (
  attempt_id TEXT PRIMARY KEY CHECK (length(attempt_id) BETWEEN 1 AND 128),
  alert_id TEXT NOT NULL REFERENCES ocfleet_native.alert_events(alert_id) ON DELETE CASCADE,
  hook_id TEXT NOT NULL REFERENCES ocfleet_native.alert_hooks(hook_id) ON DELETE CASCADE,
  attempt_no BIGINT NOT NULL CHECK (attempt_no BETWEEN 1 AND 5),
  attempted_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('succeeded', 'failed', 'dry_run')),
  http_status_class TEXT,
  error_code TEXT CHECK (error_code IS NULL OR length(error_code) BETWEEN 1 AND 64),
  bytes_sent BIGINT NOT NULL CHECK (bytes_sent BETWEEN 0 AND 1048576),
  detail_json JSONB NOT NULL CHECK (jsonb_typeof(detail_json) = 'object'),
  CHECK ((status = 'failed') = (error_code IS NOT NULL))
);
CREATE INDEX idx_native_alert_attempts_alert_hook
  ON ocfleet_native.alert_delivery_attempts(alert_id, hook_id, attempted_at);

CREATE TABLE ocfleet_native.alert_delivery_queue (
  queue_id TEXT PRIMARY KEY CHECK (length(queue_id) BETWEEN 1 AND 96),
  alert_id TEXT NOT NULL REFERENCES ocfleet_native.alert_events(alert_id) ON DELETE CASCADE,
  hook_id TEXT NOT NULL REFERENCES ocfleet_native.alert_hooks(hook_id) ON DELETE CASCADE,
  idempotency_key TEXT NOT NULL UNIQUE CHECK (length(idempotency_key) = 64),
  group_key TEXT NOT NULL CHECK (length(group_key) BETWEEN 1 AND 128),
  status TEXT NOT NULL CHECK (status IN (
    'pending', 'claimed', 'retry', 'dead_letter', 'succeeded'
  )),
  attempt_count BIGINT NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 5),
  next_attempt_at TIMESTAMPTZ NOT NULL,
  owner_id TEXT,
  owner_actor TEXT CHECK (owner_actor IS NULL OR length(owner_actor) BETWEEN 1 AND 128),
  fence_token BIGINT NOT NULL DEFAULT 0 CHECK (fence_token >= 0),
  claimed_at TIMESTAMPTZ,
  lease_expires_at TIMESTAMPTZ,
  last_error_code TEXT CHECK (last_error_code IS NULL OR length(last_error_code) BETWEEN 1 AND 64),
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  delivered_at TIMESTAMPTZ,
  CHECK (
    (status = 'claimed' AND owner_id IS NOT NULL AND owner_actor IS NOT NULL
      AND claimed_at IS NOT NULL AND lease_expires_at IS NOT NULL
      AND fence_token > 0 AND lease_expires_at > claimed_at)
    OR (status <> 'claimed' AND owner_id IS NULL AND owner_actor IS NULL
      AND claimed_at IS NULL AND lease_expires_at IS NULL)
  ),
  CHECK ((status = 'succeeded') = (delivered_at IS NOT NULL)),
  CHECK (status <> 'dead_letter' OR last_error_code IS NOT NULL)
);
CREATE UNIQUE INDEX idx_native_alert_queue_alert_hook_key
  ON ocfleet_native.alert_delivery_queue(alert_id, hook_id, idempotency_key);
CREATE INDEX idx_native_alert_queue_due
  ON ocfleet_native.alert_delivery_queue(status, next_attempt_at, queue_id);
CREATE INDEX idx_native_alert_queue_lease
  ON ocfleet_native.alert_delivery_queue(lease_expires_at, queue_id);

ALTER TABLE ocfleet_native.retention_policies
  DROP CONSTRAINT retention_policies_scope_check;
ALTER TABLE ocfleet_native.retention_policies
  ADD CONSTRAINT retention_policies_scope_check CHECK (scope IN (
    'observations', 'observability-runs', 'health-snapshots',
    'health-history', 'health-rollups', 'alert-events'
  ));
"#,
            )?;
            tx.execute(
                "INSERT INTO ocfleet_native.migrations (version, name) VALUES ($1, $2)",
                &[&4_i32, &NATIVE_MIGRATION_4_NAME],
            )?;
        }

        validate_native_schema(&mut tx)?;
        tx.commit()?;
        Ok(())
    }

    pub fn schema_version(&self) -> Result<i32, PostgresError> {
        let mut conn = self.connection()?;
        Ok(conn
            .query_one(
                "SELECT COALESCE(MAX(version), 0) FROM ocfleet_native.migrations",
                &[],
            )?
            .get(0))
    }

    pub fn add_node(&self, node: &NodeInsert, actor: &str) -> Result<(), PostgresError> {
        validate_node(node, actor)?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO ocfleet_native.nodes (node_id, endpoint_id, name, region, role)
             VALUES ($1, $2, $3, $4, $5)",
            &[
                &node.node_id,
                &node.endpoint_id,
                &node.name,
                &node.region,
                &node.role,
            ],
        )?;

        let trust_bundle = TrustBundlePayloadV1::new(
            node.endpoint_id.clone(),
            1,
            EndpointStatus::Active.as_str().to_string(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .map_err(PostgresError::InvalidInput)?
        .to_value();
        tx.execute(
            "INSERT INTO ocfleet_native.endpoint_trust
             (endpoint_id, node_id, status, generation, trust_bundle_json)
             VALUES ($1, $2, 'active', 1, CAST($3 AS text)::jsonb)",
            &[&node.endpoint_id, &node.node_id, &trust_bundle.to_string()],
        )?;

        let record = NodeRecord {
            node_id: node.node_id.clone(),
            endpoint_id: node.endpoint_id.clone(),
            name: node.name.clone(),
            region: node.region.clone(),
            role: node.role.clone(),
            enabled: true,
        };
        let mut event = AuditEvent::new(actor, "node.add");
        event.node_id = Some(node.node_id.clone());
        event.endpoint_id = Some(node.endpoint_id.clone());
        event.ok = Some(true);
        event.detail_json = json!({
            "actor_type": "user",
            "target_type": "node",
            "target_id": node.node_id,
            "before": Value::Null,
            "after": node_audit_json(&record),
            "reason": Value::Null,
        });
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_node(&self, node_id: &str) -> Result<Option<NodeRecord>, PostgresError> {
        validate_node_id(node_id)
            .map_err(|error| PostgresError::InvalidInput(error.to_string()))?;
        let mut conn = self.connection()?;
        conn.query_opt(
            "SELECT node_id, endpoint_id, name, region, role, enabled
             FROM ocfleet_native.nodes WHERE node_id = $1",
            &[&node_id],
        )?
        .map(|row| node_from_row(&row))
        .transpose()
    }

    pub fn list_nodes(&self, limit: u64) -> Result<Vec<NodeRecord>, PostgresError> {
        if limit == 0 || limit > MAX_STORE_READER_ROWS {
            return Err(PostgresError::InvalidInput(format!(
                "node query limit must be between 1 and {MAX_STORE_READER_ROWS}"
            )));
        }
        let limit = i64::try_from(limit)
            .map_err(|_| PostgresError::InvalidInput("node query limit is invalid".into()))?;
        let mut conn = self.connection()?;
        conn.query(
            "SELECT node_id, endpoint_id, name, region, role, enabled
             FROM ocfleet_native.nodes ORDER BY node_id LIMIT $1",
            &[&limit],
        )?
        .iter()
        .map(node_from_row)
        .collect()
    }

    pub fn list_nodes_by_role_limited(
        &self,
        role: &str,
        limit: u64,
    ) -> Result<Vec<NodeRecord>, PostgresError> {
        validate_role(role).map_err(|error| PostgresError::InvalidInput(error.to_string()))?;
        let limit = checked_query_limit(limit)?;
        let mut conn = self.connection()?;
        conn.query(
            "SELECT node_id, endpoint_id, name, region, role, enabled
             FROM ocfleet_native.nodes WHERE role = $1 ORDER BY node_id LIMIT $2",
            &[&role, &limit],
        )?
        .iter()
        .map(node_from_row)
        .collect()
    }

    pub fn list_nodes_by_metadata_limited(
        &self,
        field: &str,
        expected: &str,
        limit: u64,
    ) -> Result<Vec<NodeRecord>, PostgresError> {
        let limit = checked_query_limit(limit)?;
        let mut conn = self.connection()?;
        if let Some(key) = field.strip_prefix("label.") {
            validate_label_json(&json!({key: expected}), "selector label")
                .map_err(PostgresError::InvalidInput)?;
            return conn
                .query(
                    "SELECT n.node_id, n.endpoint_id, n.name, n.region, n.role, n.enabled
                     FROM ocfleet_native.nodes n
                     JOIN ocfleet_native.node_metadata m ON m.node_id = n.node_id
                     WHERE m.labels_json ->> $1 = $2
                     ORDER BY n.node_id LIMIT $3",
                    &[&key, &expected, &limit],
                )?
                .iter()
                .map(node_from_row)
                .collect();
        }
        validate_metadata_value(expected, "selector metadata value")
            .map_err(PostgresError::InvalidInput)?;
        let sql = match field {
            "environment" => {
                "SELECT n.node_id, n.endpoint_id, n.name, n.region, n.role, n.enabled
                 FROM ocfleet_native.nodes n
                 JOIN ocfleet_native.node_metadata m ON m.node_id = n.node_id
                 WHERE m.environment = $1 ORDER BY n.node_id LIMIT $2"
            }
            "site" => {
                "SELECT n.node_id, n.endpoint_id, n.name, n.region, n.role, n.enabled
                 FROM ocfleet_native.nodes n
                 JOIN ocfleet_native.node_metadata m ON m.node_id = n.node_id
                 WHERE m.site = $1 ORDER BY n.node_id LIMIT $2"
            }
            "owner_team" => {
                "SELECT n.node_id, n.endpoint_id, n.name, n.region, n.role, n.enabled
                 FROM ocfleet_native.nodes n
                 JOIN ocfleet_native.node_metadata m ON m.node_id = n.node_id
                 WHERE m.owner_team = $1 ORDER BY n.node_id LIMIT $2"
            }
            "service_tier" => {
                "SELECT n.node_id, n.endpoint_id, n.name, n.region, n.role, n.enabled
                 FROM ocfleet_native.nodes n
                 JOIN ocfleet_native.node_metadata m ON m.node_id = n.node_id
                 WHERE m.service_tier = $1 ORDER BY n.node_id LIMIT $2"
            }
            _ => {
                return Err(PostgresError::InvalidInput(
                    "unsupported metadata selector field".to_string(),
                ));
            }
        };
        conn.query(sql, &[&expected, &limit])?
            .iter()
            .map(node_from_row)
            .collect()
    }

    pub fn disable_node(&self, node_id: &str, actor: &str) -> Result<(), PostgresError> {
        self.set_node_enabled(node_id, false, actor, "node.disable")
    }

    pub fn enable_node(&self, node_id: &str, actor: &str) -> Result<(), PostgresError> {
        self.set_node_enabled(node_id, true, actor, "node.enable")
    }

    fn set_node_enabled(
        &self,
        node_id: &str,
        enabled: bool,
        actor: &str,
        event_name: &str,
    ) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        validate_node_id(node_id)
            .map_err(|error| PostgresError::InvalidInput(error.to_string()))?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let before = get_node_tx(&mut tx, node_id)?
            .ok_or_else(|| PostgresError::InvalidState("native node not found".to_string()))?;
        if enabled {
            let active: bool = tx
                .query_one(
                    "SELECT EXISTS (
                       SELECT 1 FROM ocfleet_native.endpoint_trust
                       WHERE endpoint_id = $1 AND node_id = $2 AND status = 'active'
                     )",
                    &[&before.endpoint_id, &before.node_id],
                )?
                .get(0);
            if !active {
                return Err(PostgresError::InvalidState(
                    "native node has no active current endpoint".to_string(),
                ));
            }
        }
        tx.execute(
            "UPDATE ocfleet_native.nodes
             SET enabled = $1, updated_at = clock_timestamp()
             WHERE node_id = $2",
            &[&enabled, &node_id],
        )?;
        let after = get_node_tx(&mut tx, node_id)?.expect("updated native node exists");
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
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn remove_node(&self, node_id: &str, actor: &str) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        validate_node_id(node_id)
            .map_err(|error| PostgresError::InvalidInput(error.to_string()))?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let before = get_node_tx(&mut tx, node_id)?
            .ok_or_else(|| PostgresError::InvalidState("native node not found".to_string()))?;
        let endpoint_before = get_endpoint_trust_tx(&mut tx, &before.endpoint_id)?;
        let endpoint_after = if let Some(endpoint) = endpoint_before.as_ref()
            && endpoint.status == EndpointStatus::Active
        {
            Some(transition_endpoint_status_tx(
                &mut tx,
                endpoint,
                EndpointStatus::Revoked,
            )?)
        } else {
            endpoint_before.clone()
        };
        tx.execute(
            "DELETE FROM ocfleet_native.nodes WHERE node_id = $1",
            &[&node_id],
        )?;
        let mut event = AuditEvent::new(actor, "node.remove");
        event.node_id = Some(before.node_id.clone());
        event.endpoint_id = Some(before.endpoint_id.clone());
        event.ok = Some(true);
        event.detail_json = json!({
            "actor_type": "user",
            "target_type": "node",
            "target_id": before.node_id,
            "before": {"node": node_audit_json(&before), "endpoint": endpoint_before.as_ref().map(endpoint_audit_json)},
            "after": {"node": Value::Null, "endpoint": endpoint_after.as_ref().map(endpoint_audit_json)},
            "reason": Value::Null,
        });
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn set_node_metadata(
        &self,
        metadata: &NodeMetadataRecord,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        map_store_validation(validate_node_metadata_record(metadata))?;
        let updated_at =
            parse_postgres_timestamp(&metadata.updated_at, "node metadata updated_at")?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        if get_node_tx(&mut tx, &metadata.node_id)?.is_none() {
            return Err(PostgresError::InvalidState(
                "native node not found".to_string(),
            ));
        }
        let before = get_node_metadata_tx(&mut tx, &metadata.node_id)?;
        tx.execute(
            "INSERT INTO ocfleet_native.node_metadata
             (node_id, environment, site, owner_team, service_tier, expected_agent_version,
              labels_json, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, CAST($7 AS text)::jsonb, $8)
             ON CONFLICT (node_id) DO UPDATE SET
               environment = EXCLUDED.environment,
               site = EXCLUDED.site,
               owner_team = EXCLUDED.owner_team,
               service_tier = EXCLUDED.service_tier,
               expected_agent_version = EXCLUDED.expected_agent_version,
               labels_json = EXCLUDED.labels_json,
               updated_at = EXCLUDED.updated_at",
            &[
                &metadata.node_id,
                &metadata.environment,
                &metadata.site,
                &metadata.owner_team,
                &metadata.service_tier,
                &metadata.expected_agent_version,
                &metadata.labels_json.to_string(),
                &updated_at,
            ],
        )?;
        let after = get_node_metadata_tx(&mut tx, &metadata.node_id)?
            .expect("native metadata upsert succeeded");
        let mut event = AuditEvent::new(actor, "node.metadata.set");
        event.node_id = Some(metadata.node_id.clone());
        event.ok = Some(true);
        event.detail_json = json!({
            "target_type": "node_metadata",
            "target_id": metadata.node_id,
            "before": before.as_ref().map(node_metadata_audit_json),
            "after": node_metadata_audit_json(&after),
            "result_class": "node_metadata",
        });
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_node_metadata(
        &self,
        node_id: &str,
    ) -> Result<Option<NodeMetadataRecord>, PostgresError> {
        validate_node_id(node_id)
            .map_err(|error| PostgresError::InvalidInput(error.to_string()))?;
        let mut conn = self.connection()?;
        get_node_metadata_conn(&mut *conn, node_id)
    }

    pub fn set_node_maintenance(
        &self,
        window: &NodeMaintenanceWindow,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        map_store_validation(validate_node_maintenance_record(window))?;
        let starts_at = parse_postgres_timestamp(&window.starts_at, "node maintenance starts_at")?;
        let ends_at = parse_postgres_timestamp(&window.ends_at, "node maintenance ends_at")?;
        let updated_at =
            parse_postgres_timestamp(&window.updated_at, "node maintenance updated_at")?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        if get_node_tx(&mut tx, &window.node_id)?.is_none() {
            return Err(PostgresError::InvalidState(
                "native node not found".to_string(),
            ));
        }
        tx.execute(
            "INSERT INTO ocfleet_native.node_maintenance_windows
             (node_id, starts_at, ends_at, reason, updated_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (node_id) DO UPDATE SET
               starts_at = EXCLUDED.starts_at,
               ends_at = EXCLUDED.ends_at,
               reason = EXCLUDED.reason,
               updated_at = EXCLUDED.updated_at",
            &[
                &window.node_id,
                &starts_at,
                &ends_at,
                &window.reason,
                &updated_at,
            ],
        )?;
        let mut event = AuditEvent::new(actor, "node.maintenance.set");
        event.node_id = Some(window.node_id.clone());
        event.ok = Some(true);
        event.detail_json = json!({
            "target_type": "node_maintenance",
            "target_id": window.node_id,
            "from": window.starts_at,
            "to": window.ends_at,
            "reason": window.reason,
            "result_class": "scheduling_advisory",
        });
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_node_maintenance(
        &self,
        node_id: &str,
    ) -> Result<Option<NodeMaintenanceWindow>, PostgresError> {
        validate_node_id(node_id)
            .map_err(|error| PostgresError::InvalidInput(error.to_string()))?;
        let mut conn = self.connection()?;
        conn.query_opt(
            "SELECT node_id, starts_at, ends_at, reason, updated_at
             FROM ocfleet_native.node_maintenance_windows WHERE node_id = $1",
            &[&node_id],
        )?
        .map(|row| node_maintenance_from_row(&row))
        .transpose()
    }

    pub fn node_maintenance_active_at(
        &self,
        node_id: &str,
        now: &str,
    ) -> Result<bool, PostgresError> {
        validate_node_id(node_id)
            .map_err(|error| PostgresError::InvalidInput(error.to_string()))?;
        let now = parse_postgres_timestamp(now, "node maintenance check timestamp")?;
        let mut conn = self.connection()?;
        Ok(conn
            .query_one(
                "SELECT EXISTS (
                   SELECT 1 FROM ocfleet_native.node_maintenance_windows
                   WHERE node_id = $1
                     AND starts_at <= $2
                     AND $2 < ends_at
                 )",
                &[&node_id, &now],
            )?
            .get(0))
    }

    pub fn clear_node_maintenance(
        &self,
        node_id: &str,
        actor: &str,
    ) -> Result<bool, PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        validate_node_id(node_id)
            .map_err(|error| PostgresError::InvalidInput(error.to_string()))?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let removed = tx.execute(
            "DELETE FROM ocfleet_native.node_maintenance_windows WHERE node_id = $1",
            &[&node_id],
        )? == 1;
        let mut event = AuditEvent::new(actor, "node.maintenance.clear");
        event.node_id = Some(node_id.to_string());
        event.ok = Some(true);
        event.detail_json = json!({
            "target_type": "node_maintenance",
            "target_id": node_id,
            "state": if removed { "cleared" } else { "already_clear" },
            "result_class": "scheduling_advisory",
        });
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(removed)
    }

    pub fn upsert_node_capability_snapshot_with_audit(
        &self,
        snapshot: &CapabilitySnapshot,
        audit: &AuditEvent,
    ) -> Result<(), PostgresError> {
        snapshot.validate().map_err(PostgresError::InvalidInput)?;
        validate_node_id(&snapshot.node_id)
            .map_err(|error| PostgresError::InvalidInput(error.to_string()))?;
        validate_endpoint_id(&snapshot.endpoint_id).map_err(PostgresError::InvalidInput)?;
        let observed_at =
            parse_postgres_timestamp(&snapshot.observed_at, "capability observed_at")?;
        if audit.node_id.as_deref() != Some(snapshot.node_id.as_str())
            || audit.endpoint_id.as_deref() != Some(snapshot.endpoint_id.as_str())
            || audit.method.as_deref() != Some(ocfleet_protocol::method::NODE_CAPABILITIES)
        {
            return Err(PostgresError::InvalidInput(
                "capability snapshot does not match its RPC audit".to_string(),
            ));
        }
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let node = get_node_tx(&mut tx, &snapshot.node_id)?
            .ok_or_else(|| PostgresError::InvalidState("native node not found".to_string()))?;
        if node.endpoint_id != snapshot.endpoint_id {
            return Err(PostgresError::InvalidInput(
                "capability endpoint is not current".to_string(),
            ));
        }
        let protocol_min = optional_u32_to_i32(snapshot.protocol_min)?;
        let protocol_max = optional_u32_to_i32(snapshot.protocol_max)?;
        let snapshot_min = optional_u32_to_i32(snapshot.ocserv_snapshot_min)?;
        let snapshot_max = optional_u32_to_i32(snapshot.ocserv_snapshot_max)?;
        tx.execute(
            "INSERT INTO ocfleet_native.node_capability_snapshots
             (node_id, endpoint_id, observed_at, status, agent_version,
              protocol_min, protocol_max, ocserv_snapshot_min, ocserv_snapshot_max,
              controlled_writes_compiled, controlled_writes_locally_enabled)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             ON CONFLICT (node_id) DO UPDATE SET
               endpoint_id = EXCLUDED.endpoint_id,
               observed_at = EXCLUDED.observed_at,
               status = EXCLUDED.status,
               agent_version = EXCLUDED.agent_version,
               protocol_min = EXCLUDED.protocol_min,
               protocol_max = EXCLUDED.protocol_max,
               ocserv_snapshot_min = EXCLUDED.ocserv_snapshot_min,
               ocserv_snapshot_max = EXCLUDED.ocserv_snapshot_max,
               controlled_writes_compiled = EXCLUDED.controlled_writes_compiled,
               controlled_writes_locally_enabled = EXCLUDED.controlled_writes_locally_enabled
             WHERE EXCLUDED.observed_at >= ocfleet_native.node_capability_snapshots.observed_at",
            &[
                &snapshot.node_id,
                &snapshot.endpoint_id,
                &observed_at,
                &snapshot.status.as_str(),
                &snapshot.agent_version,
                &protocol_min,
                &protocol_max,
                &snapshot_min,
                &snapshot_max,
                &snapshot.controlled_writes_compiled,
                &snapshot.controlled_writes_locally_enabled,
            ],
        )?;
        insert_audit(&mut tx, audit)?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_node_capability_snapshot(
        &self,
        node_id: &str,
    ) -> Result<Option<CapabilitySnapshot>, PostgresError> {
        validate_node_id(node_id)
            .map_err(|error| PostgresError::InvalidInput(error.to_string()))?;
        let mut conn = self.connection()?;
        conn.query_opt(
            "SELECT node_id, endpoint_id, observed_at, status, agent_version, protocol_min, protocol_max,
                    ocserv_snapshot_min, ocserv_snapshot_max,
                    controlled_writes_compiled, controlled_writes_locally_enabled
             FROM ocfleet_native.node_capability_snapshots WHERE node_id = $1",
            &[&node_id],
        )?
        .map(|row| capability_from_row(&row))
        .transpose()
    }

    pub fn list_version_governance_inputs(
        &self,
        limit: usize,
    ) -> Result<Vec<VersionGovernanceInput>, PostgresError> {
        if limit == 0 || limit > MAX_VERSION_GOVERNANCE_NODES {
            return Err(PostgresError::InvalidInput(format!(
                "version governance limit must be between 1 and {MAX_VERSION_GOVERNANCE_NODES}"
            )));
        }
        let query_limit = i64::try_from(limit.saturating_add(1)).map_err(|_| {
            PostgresError::InvalidInput("version governance limit exceeds i64".to_string())
        })?;
        let mut conn = self.connection()?;
        let rows = conn.query(
            "SELECT n.node_id, n.enabled, m.expected_agent_version,
                    c.node_id, c.endpoint_id, c.observed_at,
                    c.status, c.agent_version, c.protocol_min, c.protocol_max,
                    c.ocserv_snapshot_min, c.ocserv_snapshot_max,
                    c.controlled_writes_compiled, c.controlled_writes_locally_enabled
             FROM ocfleet_native.nodes n
             LEFT JOIN ocfleet_native.node_metadata m ON m.node_id = n.node_id
             LEFT JOIN ocfleet_native.node_capability_snapshots c ON c.node_id = n.node_id
             ORDER BY n.node_id LIMIT $1",
            &[&query_limit],
        )?;
        if rows.len() > limit {
            return Err(PostgresError::InvalidInput(format!(
                "version governance node count exceeds {limit}"
            )));
        }
        rows.iter()
            .map(|row| {
                let capability = if row.try_get::<_, Option<String>>(3)?.is_some() {
                    Some(capability_from_offset_row(row, 3)?)
                } else {
                    None
                };
                Ok(VersionGovernanceInput {
                    node_id: row.try_get(0)?,
                    enabled: row.try_get(1)?,
                    expected_agent_version: row.try_get(2)?,
                    capability,
                })
            })
            .collect()
    }

    pub fn get_endpoint_trust(
        &self,
        endpoint_id: &str,
    ) -> Result<Option<EndpointTrustRecord>, PostgresError> {
        let endpoint_id = validate_endpoint_id(endpoint_id).map_err(PostgresError::InvalidInput)?;
        let mut conn = self.connection()?;
        get_endpoint_trust_conn(&mut *conn, &endpoint_id, false)
    }

    pub fn trust_snapshot(
        &self,
        endpoint_filter: Option<&str>,
    ) -> Result<TrustSnapshot, PostgresError> {
        if let Some(endpoint_id) = endpoint_filter {
            return Ok(TrustSnapshot {
                endpoints: self.get_endpoint_trust(endpoint_id)?.into_iter().collect(),
            });
        }
        let mut conn = self.connection()?;
        let query_limit = i64::try_from(MAX_STORE_READER_ROWS.saturating_add(1)).map_err(|_| {
            PostgresError::InvalidState("native trust snapshot bound exceeds i64".to_string())
        })?;
        let rows = conn.query(
            "SELECT endpoint_id, node_id, fingerprint, status, generation,
                    previous_endpoint_id, rotated_to, trust_bundle_json::text,
                    created_at, updated_at
             FROM ocfleet_native.endpoint_trust ORDER BY endpoint_id
             LIMIT $1",
            &[&query_limit],
        )?;
        if rows.len() > MAX_STORE_READER_ROWS as usize {
            return Err(PostgresError::InvalidState(format!(
                "native trust snapshot exceeds bounded limit of {MAX_STORE_READER_ROWS} endpoints"
            )));
        }
        Ok(TrustSnapshot {
            endpoints: rows
                .iter()
                .map(endpoint_trust_from_row)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    pub fn rotate_endpoint(
        &self,
        old_endpoint_id: &str,
        new_endpoint_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<EndpointTrustRecord, PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        validate_reason(reason).map_err(PostgresError::InvalidInput)?;
        let old_endpoint_id =
            validate_endpoint_id(old_endpoint_id).map_err(PostgresError::InvalidInput)?;
        let new_endpoint_id =
            validate_endpoint_id(new_endpoint_id).map_err(PostgresError::InvalidInput)?;
        if old_endpoint_id == new_endpoint_id {
            return Err(PostgresError::InvalidInput(
                "new endpoint must differ from old endpoint".to_string(),
            ));
        }

        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let old_before = get_endpoint_trust_tx(&mut tx, &old_endpoint_id)?
            .ok_or_else(|| PostgresError::InvalidState("native endpoint not found".to_string()))?;
        if old_before.status == EndpointStatus::Rotated {
            if old_before.rotated_to.as_deref() != Some(new_endpoint_id.as_str()) {
                return Err(PostgresError::InvalidState(
                    "native endpoint was rotated to a different endpoint".to_string(),
                ));
            }
            let new_after = get_endpoint_trust_tx(&mut tx, &new_endpoint_id)?.ok_or_else(|| {
                PostgresError::InvalidState(
                    "native endpoint rotation lineage is broken".to_string(),
                )
            })?;
            validate_rotation_edge(&mut tx, &old_before, &new_after)?;
            validate_rotation_binding_tx(&mut tx, &new_after)?;
            return Ok(new_after);
        }
        if !matches!(
            old_before.status,
            EndpointStatus::Active | EndpointStatus::Quarantined
        ) {
            return Err(PostgresError::InvalidState(
                "native endpoint cannot be rotated from its current status".to_string(),
            ));
        }
        if get_endpoint_trust_tx(&mut tx, &new_endpoint_id)?.is_some() {
            return Err(PostgresError::InvalidState(
                "native endpoint already exists".to_string(),
            ));
        }
        validate_unrotated_lineage(&mut tx, &old_before)?;
        let node_before = validate_rotation_binding_tx(&mut tx, &old_before)?;
        let generation = old_before.generation.checked_add(1).ok_or_else(|| {
            PostgresError::InvalidState("native endpoint generation exhausted".to_string())
        })?;
        let generation_i64 = i64::try_from(generation).map_err(|_| {
            PostgresError::InvalidState("native endpoint generation exceeds i64".to_string())
        })?;
        let old_payload = trust_payload(&old_endpoint_id, generation, EndpointStatus::Rotated)?;
        tx.execute(
            "UPDATE ocfleet_native.endpoint_trust
             SET status = 'rotated', generation = $1, rotated_to = $2,
                 trust_bundle_json = CAST($3 AS text)::jsonb,
                 updated_at = clock_timestamp()
             WHERE endpoint_id = $4",
            &[
                &generation_i64,
                &new_endpoint_id,
                &old_payload.to_string(),
                &old_endpoint_id,
            ],
        )?;
        let new_payload = trust_payload(&new_endpoint_id, generation, EndpointStatus::Active)?;
        tx.execute(
            "INSERT INTO ocfleet_native.endpoint_trust
             (endpoint_id, node_id, fingerprint, status, generation,
              previous_endpoint_id, rotated_to, trust_bundle_json)
             VALUES ($1, $2, $3, 'active', $4, $5, NULL, CAST($6 AS text)::jsonb)",
            &[
                &new_endpoint_id,
                &old_before.node_id,
                &old_before.fingerprint,
                &generation_i64,
                &old_endpoint_id,
                &new_payload.to_string(),
            ],
        )?;
        let enabled = node_before.enabled && old_before.status != EndpointStatus::Quarantined;
        let affected = tx.execute(
            "UPDATE ocfleet_native.nodes
             SET endpoint_id = $1, enabled = $2, updated_at = clock_timestamp()
             WHERE node_id = $3 AND endpoint_id = $4",
            &[
                &new_endpoint_id,
                &enabled,
                &node_before.node_id,
                &old_endpoint_id,
            ],
        )?;
        if affected != 1 {
            return Err(PostgresError::InvalidState(
                "native node endpoint binding changed during rotation".to_string(),
            ));
        }
        let node_after = get_node_tx(&mut tx, &node_before.node_id)?
            .ok_or_else(|| PostgresError::InvalidState("native bound node is missing".into()))?;
        let old_after = get_endpoint_trust_tx(&mut tx, &old_endpoint_id)?
            .expect("rotated native endpoint exists");
        let new_after =
            get_endpoint_trust_tx(&mut tx, &new_endpoint_id)?.expect("new native endpoint exists");
        let mut event = AuditEvent::new(actor, "endpoint.rotate");
        event.node_id = old_before.node_id.clone();
        event.endpoint_id = Some(old_endpoint_id.clone());
        event.ok = Some(true);
        event.detail_json = json!({
            "actor_type": "user",
            "target_type": "endpoint_rotation",
            "target_id": old_endpoint_id,
            "before": {"node": node_audit_json(&node_before), "old_endpoint": endpoint_audit_json(&old_before)},
            "after": {"node": node_audit_json(&node_after), "old_endpoint": endpoint_audit_json(&old_after), "new_endpoint": endpoint_audit_json(&new_after)},
            "reason": reason,
        });
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(new_after)
    }

    pub fn revoke_endpoint(
        &self,
        endpoint_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<EndpointTrustRecord, PostgresError> {
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
    ) -> Result<EndpointTrustRecord, PostgresError> {
        self.update_endpoint_status(
            endpoint_id,
            EndpointStatus::Quarantined,
            actor,
            reason,
            "endpoint.quarantine",
        )
    }

    fn update_endpoint_status(
        &self,
        endpoint_id: &str,
        status: EndpointStatus,
        actor: &str,
        reason: &str,
        action: &str,
    ) -> Result<EndpointTrustRecord, PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        validate_reason(reason).map_err(PostgresError::InvalidInput)?;
        let endpoint_id = validate_endpoint_id(endpoint_id).map_err(PostgresError::InvalidInput)?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let before = get_endpoint_trust_tx(&mut tx, &endpoint_id)?
            .ok_or_else(|| PostgresError::InvalidState("native endpoint not found".to_string()))?;
        if before.status == status {
            return Ok(before);
        }
        let allowed = matches!(
            (before.status, status),
            (EndpointStatus::Active, EndpointStatus::Revoked)
                | (EndpointStatus::Active, EndpointStatus::Quarantined)
                | (EndpointStatus::Quarantined, EndpointStatus::Revoked)
        );
        if !allowed {
            return Err(PostgresError::InvalidState(
                "native endpoint status transition is invalid".to_string(),
            ));
        }
        let node_before = if let Some(node_id) = before.node_id.as_deref() {
            get_node_tx(&mut tx, node_id)?
        } else {
            None
        };
        if let Some(node) = node_before.as_ref()
            && node.endpoint_id != endpoint_id
        {
            return Err(PostgresError::InvalidState(
                "native endpoint binding is inconsistent".to_string(),
            ));
        }
        let after = transition_endpoint_status_tx(&mut tx, &before, status)?;
        let node_after = if let Some(node) = node_before.as_ref()
            && node.enabled
        {
            tx.execute(
                "UPDATE ocfleet_native.nodes
                 SET enabled = FALSE, updated_at = clock_timestamp()
                 WHERE node_id = $1 AND endpoint_id = $2",
                &[&node.node_id, &endpoint_id],
            )?;
            get_node_tx(&mut tx, &node.node_id)?
        } else {
            node_before.clone()
        };
        let mut event = AuditEvent::new(actor, action);
        event.node_id = before.node_id.clone();
        event.endpoint_id = Some(endpoint_id.clone());
        event.ok = Some(true);
        event.detail_json = json!({
            "actor_type": "user",
            "target_type": "endpoint",
            "target_id": endpoint_id,
            "before": {"node": node_before.as_ref().map(node_audit_json), "endpoint": endpoint_audit_json(&before)},
            "after": {"node": node_after.as_ref().map(node_audit_json), "endpoint": endpoint_audit_json(&after)},
            "reason": reason,
        });
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(after)
    }

    pub fn create_enrollment_token(
        &self,
        token: &EnrollmentTokenInsert,
        actor: &str,
    ) -> Result<EnrollmentTokenRecord, PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        validate_enrollment_token_input(token)?;
        if let Some(description) = token.description.as_deref() {
            validate_description(description).map_err(PostgresError::InvalidInput)?;
        }
        validate_label_json(&token.labels_json, "labels").map_err(PostgresError::InvalidInput)?;
        validate_label_json(&token.scope_json, "scope").map_err(PostgresError::InvalidInput)?;
        validate_low_sensitive_json(&token.labels_json, "native enrollment token labels")?;
        validate_low_sensitive_json(&token.scope_json, "native enrollment token scope")?;
        let labels =
            enrollment_metadata_payload(EnrollmentMetadataKindV1::TokenLabels, &token.labels_json)?;
        let scope =
            enrollment_metadata_payload(EnrollmentMetadataKindV1::TokenScope, &token.scope_json)?;
        let max_uses = i32::try_from(token.max_uses)
            .map_err(|_| PostgresError::InvalidInput("token max uses exceeds i32".into()))?;
        let expires_at =
            parse_postgres_timestamp(&token.expires_at, "enrollment token expires_at")?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        if let Some(existing) = get_enrollment_token_tx(&mut tx, &token.token_id)? {
            if enrollment_token_matches(&existing, token, actor) {
                validate_enrollment_token_audit_provenance_tx(
                    &mut tx,
                    "enrollment.token.create",
                    &token.token_id,
                    actor,
                    None,
                )?;
                return Ok(existing);
            }
            return Err(PostgresError::InvalidState(
                "native enrollment token conflicts with existing token".to_string(),
            ));
        }
        let hash_exists: bool = tx
            .query_one(
                "SELECT EXISTS (
                   SELECT 1 FROM ocfleet_native.enrollment_tokens WHERE token_hash = $1
                 )",
                &[&token.token_hash],
            )?
            .get(0);
        if hash_exists {
            return Err(PostgresError::InvalidState(
                "native enrollment credential is already assigned".to_string(),
            ));
        }
        tx.execute(
            "INSERT INTO ocfleet_native.enrollment_tokens
             (token_id, token_hash, created_by, expires_at, max_uses, status,
              description, labels_json, scope_json)
             VALUES ($1, $2, $3, $4, $5, 'active', $6,
                     CAST($7 AS text)::jsonb, CAST($8 AS text)::jsonb)",
            &[
                &token.token_id,
                &token.token_hash,
                &actor,
                &expires_at,
                &max_uses,
                &token.description,
                &labels.to_string(),
                &scope.to_string(),
            ],
        )?;
        let after = get_enrollment_token_tx(&mut tx, &token.token_id)?
            .expect("native enrollment token inserted");
        let mut event = AuditEvent::new(actor, "enrollment.token.create");
        event.ok = Some(true);
        event.detail_json =
            enrollment_token_transition_audit_json(&token.token_id, None, Some(&after), None);
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(after)
    }

    pub fn get_enrollment_token(
        &self,
        token_id: &str,
    ) -> Result<Option<EnrollmentTokenRecord>, PostgresError> {
        validate_enrollment_token_id(token_id)?;
        let mut conn = self.connection()?;
        get_enrollment_token_conn(&mut *conn, token_id, false)
    }

    pub fn revoke_enrollment_token(
        &self,
        token_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<EnrollmentTokenRecord, PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        validate_reason(reason).map_err(PostgresError::InvalidInput)?;
        validate_enrollment_token_id(token_id)?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let before = get_enrollment_token_tx(&mut tx, token_id)?.ok_or_else(|| {
            PostgresError::InvalidState("native enrollment token not found".to_string())
        })?;
        if before.status == EnrollmentTokenStatus::Revoked {
            validate_enrollment_token_audit_provenance_tx(
                &mut tx,
                "enrollment.token.revoke",
                token_id,
                actor,
                Some(reason),
            )?;
            return Ok(before);
        }
        if before.status != EnrollmentTokenStatus::Active || token_is_expired(&before.expires_at) {
            return Err(PostgresError::InvalidState(
                "native enrollment token cannot be revoked from its current state".to_string(),
            ));
        }
        tx.execute(
            "UPDATE ocfleet_native.enrollment_tokens
             SET status = 'revoked' WHERE token_id = $1 AND status = 'active'",
            &[&token_id],
        )?;
        let after = get_enrollment_token_tx(&mut tx, token_id)?
            .expect("native revoked enrollment token exists");
        let mut event = AuditEvent::new(actor, "enrollment.token.revoke");
        event.ok = Some(true);
        event.detail_json = enrollment_token_transition_audit_json(
            token_id,
            Some(&before),
            Some(&after),
            Some(reason),
        );
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(after)
    }

    pub fn submit_join_request(
        &self,
        request: &JoinRequestInsert,
        actor: &str,
    ) -> Result<JoinRequestRecord, PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        validate_enrollment_request_id(&request.request_id)?;
        validate_enrollment_token_plaintext(&request.token_plaintext)?;
        validate_agent_public_key(&request.agent_public_key)
            .map_err(PostgresError::InvalidInput)?;
        validate_agent_fingerprint(&request.fingerprint).map_err(PostgresError::InvalidInput)?;
        let requested_endpoint_id = request
            .requested_endpoint_id
            .as_deref()
            .map(validate_endpoint_id)
            .transpose()
            .map_err(PostgresError::InvalidInput)?;
        validate_hostname(&request.hostname).map_err(PostgresError::InvalidInput)?;
        validate_agent_version(&request.agent_version).map_err(PostgresError::InvalidInput)?;
        validate_label_json(&request.requested_labels_json, "requested_labels")
            .map_err(PostgresError::InvalidInput)?;
        validate_low_sensitive_json(
            &request.requested_labels_json,
            "native enrollment requested labels",
        )?;
        let requested_labels = enrollment_metadata_payload(
            EnrollmentMetadataKindV1::RequestedLabels,
            &request.requested_labels_json,
        )?;
        let approved_labels =
            enrollment_metadata_payload(EnrollmentMetadataKindV1::ApprovedLabels, &json!({}))?;
        let token_hash = Store::hash_enrollment_token(&request.token_plaintext);
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let token = get_enrollment_token_by_hash_tx(&mut tx, &token_hash)?;
        let Some(token) = token else {
            insert_enrollment_rejection_audit(
                &mut tx,
                actor,
                &request.request_id,
                None,
                "unknown_token",
            )?;
            tx.commit()?;
            return Err(PostgresError::InvalidState(
                "native enrollment rejected: unknown_token".to_string(),
            ));
        };
        if let Some(existing) = get_join_request_tx(&mut tx, &request.request_id)? {
            if join_request_matches(
                &existing,
                request,
                &token.token_id,
                requested_endpoint_id.as_deref(),
            ) {
                validate_join_submission_audit_provenance_tx(&mut tx, &existing, actor)?;
                return Ok(existing);
            }
            return Err(PostgresError::InvalidState(
                "native enrollment request conflicts with existing request".to_string(),
            ));
        }
        if token.status != EnrollmentTokenStatus::Active {
            insert_enrollment_rejection_audit(
                &mut tx,
                actor,
                &request.request_id,
                Some(&token.token_id),
                token.status.as_str(),
            )?;
            tx.commit()?;
            return Err(PostgresError::InvalidState(format!(
                "native enrollment rejected: {}",
                token.status.as_str()
            )));
        }
        if token_is_expired(&token.expires_at) {
            let affected = tx.execute(
                "UPDATE ocfleet_native.enrollment_tokens
                 SET status = 'expired' WHERE token_id = $1 AND status = 'active'",
                &[&token.token_id],
            )?;
            if affected != 1 {
                return Err(PostgresError::InvalidState(
                    "native enrollment token changed during expiry".to_string(),
                ));
            }
            let expired = get_enrollment_token_tx(&mut tx, &token.token_id)?.ok_or_else(|| {
                PostgresError::InvalidState("native expired token is missing".into())
            })?;
            let mut expire_event = AuditEvent::new(actor, "enrollment.token.expire");
            expire_event.ok = Some(true);
            expire_event.request_id = Some(request.request_id.clone());
            expire_event.detail_json = enrollment_token_transition_audit_json(
                &token.token_id,
                Some(&token),
                Some(&expired),
                Some("expired"),
            );
            insert_audit(&mut tx, &expire_event)?;
            insert_enrollment_rejection_audit(
                &mut tx,
                actor,
                &request.request_id,
                Some(&token.token_id),
                "expired",
            )?;
            tx.commit()?;
            return Err(PostgresError::InvalidState(
                "native enrollment rejected: expired".to_string(),
            ));
        }
        if token.used_count >= token.max_uses {
            insert_enrollment_rejection_audit(
                &mut tx,
                actor,
                &request.request_id,
                Some(&token.token_id),
                "max_uses_exhausted",
            )?;
            tx.commit()?;
            return Err(PostgresError::InvalidState(
                "native enrollment rejected: max_uses_exhausted".to_string(),
            ));
        }
        let correlation_id = format!("corr-{}", Uuid::new_v4());
        tx.execute(
            "INSERT INTO ocfleet_native.join_requests
             (request_id, token_id, status, agent_public_key, fingerprint,
              requested_endpoint_id, hostname, agent_version, requested_labels_json,
              approved_labels_json, audit_correlation_id)
             VALUES ($1, $2, 'pending', $3, $4, $5, $6, $7,
                     CAST($8 AS text)::jsonb, CAST($9 AS text)::jsonb, $10)",
            &[
                &request.request_id,
                &token.token_id,
                &request.agent_public_key,
                &request.fingerprint,
                &requested_endpoint_id,
                &request.hostname,
                &request.agent_version,
                &requested_labels.to_string(),
                &approved_labels.to_string(),
                &correlation_id,
            ],
        )?;
        let used_count = i32::try_from(token.used_count).map_err(|_| {
            PostgresError::InvalidState("native enrollment used count exceeds i32".to_string())
        })?;
        let affected = tx.execute(
            "UPDATE ocfleet_native.enrollment_tokens
             SET used_count = used_count + 1
             WHERE token_id = $1 AND status = 'active'
               AND used_count = $2 AND used_count < max_uses",
            &[&token.token_id, &used_count],
        )?;
        if affected != 1 {
            return Err(PostgresError::InvalidState(
                "native enrollment token changed during submission".to_string(),
            ));
        }
        let joined = get_join_request_tx(&mut tx, &request.request_id)?
            .expect("native join request inserted");
        let token_after = get_enrollment_token_tx(&mut tx, &token.token_id)?
            .ok_or_else(|| PostgresError::InvalidState("native used token is missing".into()))?;
        let mut event = AuditEvent::new(actor, "enrollment.token.use");
        event.ok = Some(true);
        event.request_id = Some(request.request_id.clone());
        event.detail_json = enrollment_token_use_audit_json(&token, &token_after, &joined);
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(joined)
    }

    pub fn get_join_request(
        &self,
        request_id: &str,
    ) -> Result<Option<JoinRequestRecord>, PostgresError> {
        validate_enrollment_request_id(request_id)?;
        let mut conn = self.connection()?;
        get_join_request_conn(&mut *conn, request_id, false)
    }

    pub fn reject_join_request(
        &self,
        request_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<JoinRequestRecord, PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        validate_reason(reason).map_err(PostgresError::InvalidInput)?;
        validate_enrollment_request_id(request_id)?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let before = get_join_request_tx(&mut tx, request_id)?.ok_or_else(|| {
            PostgresError::InvalidState("native join request not found".to_string())
        })?;
        if before.status == JoinRequestStatus::Rejected {
            if before.rejection_reason.as_deref() == Some(reason) {
                validate_join_rejection_audit_provenance_tx(&mut tx, request_id, actor, reason)?;
                return Ok(before);
            }
            return Err(PostgresError::InvalidState(
                "native join request was rejected for a different reason".to_string(),
            ));
        }
        if before.status != JoinRequestStatus::Pending {
            return Err(PostgresError::InvalidState(
                "native join request is not pending".to_string(),
            ));
        }
        tx.execute(
            "UPDATE ocfleet_native.join_requests
             SET status = 'rejected', rejection_reason = $1
             WHERE request_id = $2 AND status = 'pending'",
            &[&reason, &request_id],
        )?;
        let after =
            get_join_request_tx(&mut tx, request_id)?.expect("native rejected join request exists");
        let mut event = AuditEvent::new(actor, "enrollment.reject");
        event.ok = Some(true);
        event.request_id = Some(request_id.to_string());
        event.detail_json =
            enrollment_request_transition_audit_json(request_id, &before, &after, reason);
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(after)
    }

    pub fn approve_join_request(
        &self,
        approval: &ApprovalInput,
        actor: &str,
    ) -> Result<JoinRequestRecord, PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        validate_reason(&approval.reason).map_err(PostgresError::InvalidInput)?;
        validate_enrollment_request_id(&approval.request_id)?;
        validate_label_json(&approval.approved_labels_json, "approved_labels")
            .map_err(PostgresError::InvalidInput)?;
        validate_low_sensitive_json(
            &approval.approved_labels_json,
            "native enrollment approved labels",
        )?;
        let node = NodeInsert {
            node_id: approval.node_id.clone(),
            endpoint_id: approval.endpoint_id.clone(),
            name: approval.node_id.clone(),
            region: approval.region.clone(),
            role: approval.role.clone(),
        };
        validate_node(&node, actor)?;
        let approved_labels = enrollment_metadata_payload(
            EnrollmentMetadataKindV1::ApprovedLabels,
            &approval.approved_labels_json,
        )?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let before = get_join_request_tx(&mut tx, &approval.request_id)?.ok_or_else(|| {
            PostgresError::InvalidState("native join request not found".to_string())
        })?;
        if before.status == JoinRequestStatus::Approved {
            validate_approved_join_provenance_tx(&mut tx, &before, &node.endpoint_id)?;
            let endpoint = get_endpoint_trust_tx(&mut tx, &node.endpoint_id)?.ok_or_else(|| {
                invalid_enrollment_binding(
                    &approval.request_id,
                    "approved endpoint trust is missing",
                )
            })?;
            validate_enrollment_endpoint_origin(&before, &endpoint, &approval.request_id)?;
            if endpoint.node_id.is_none() {
                validate_approved_join_audit_provenance_tx(
                    &mut tx,
                    &before,
                    &node.endpoint_id,
                    None,
                )?;
                return Err(invalid_enrollment_binding(
                    &approval.request_id,
                    "legacy claim required",
                ));
            }
            validate_approved_join_audit_provenance_tx(
                &mut tx,
                &before,
                &node.endpoint_id,
                Some(&node.node_id),
            )?;
            validate_exact_enrollment_binding_tx(
                &mut tx,
                &before,
                &endpoint,
                &node,
                Some(&approval.approved_labels_json),
                "approval retry does not match the existing binding",
            )?;
            return Ok(before);
        }
        if before.status != JoinRequestStatus::Pending {
            return Err(PostgresError::InvalidState(
                "native join request is not pending".to_string(),
            ));
        }
        validate_pending_join_for_approval(&before)?;
        if before
            .requested_endpoint_id
            .as_deref()
            .is_some_and(|requested| requested != node.endpoint_id)
        {
            return Err(PostgresError::InvalidState(
                "native approved endpoint differs from requested endpoint".to_string(),
            ));
        }
        if get_node_tx(&mut tx, &node.node_id)?.is_some()
            || get_node_by_endpoint_tx(&mut tx, &node.endpoint_id)?.is_some()
            || get_endpoint_trust_tx(&mut tx, &node.endpoint_id)?.is_some()
            || endpoint_trust_count_for_node_tx(&mut tx, &node.node_id)? != 0
        {
            return Err(PostgresError::InvalidState(
                "native enrollment node or endpoint already exists".to_string(),
            ));
        }
        tx.execute(
            "INSERT INTO ocfleet_native.nodes (node_id, endpoint_id, name, region, role)
             VALUES ($1, $2, $3, $4, $5)",
            &[
                &node.node_id,
                &node.endpoint_id,
                &node.name,
                &node.region,
                &node.role,
            ],
        )?;
        let payload = trust_payload(&node.endpoint_id, 1, EndpointStatus::Active)?;
        tx.execute(
            "INSERT INTO ocfleet_native.endpoint_trust
             (endpoint_id, node_id, fingerprint, status, generation, trust_bundle_json)
             VALUES ($1, $2, $3, 'active', 1, CAST($4 AS text)::jsonb)",
            &[
                &node.endpoint_id,
                &node.node_id,
                &before.fingerprint,
                &payload.to_string(),
            ],
        )?;
        let affected = tx.execute(
            "UPDATE ocfleet_native.join_requests
             SET status = 'approved', assigned_endpoint_id = $1,
                 approved_labels_json = CAST($2 AS text)::jsonb,
                 approved_at = clock_timestamp(), approved_by = $3
             WHERE request_id = $4 AND status = 'pending'",
            &[
                &node.endpoint_id,
                &approved_labels.to_string(),
                &actor,
                &approval.request_id,
            ],
        )?;
        if affected != 1 {
            return Err(PostgresError::InvalidState(
                "native join request changed during approval".to_string(),
            ));
        }
        let after = get_join_request_tx(&mut tx, &approval.request_id)?
            .expect("native approved join request exists");
        let node_after = get_node_tx(&mut tx, &node.node_id)?.expect("native approved node exists");
        let endpoint_after = get_endpoint_trust_tx(&mut tx, &node.endpoint_id)?
            .expect("native approved endpoint exists");
        validate_exact_enrollment_binding_tx(
            &mut tx,
            &after,
            &endpoint_after,
            &node,
            Some(&approval.approved_labels_json),
            "approved binding is inconsistent",
        )?;
        let mut event = AuditEvent::new(actor, "enrollment.approve");
        event.ok = Some(true);
        event.request_id = Some(approval.request_id.clone());
        event.node_id = Some(node.node_id.clone());
        event.endpoint_id = Some(node.endpoint_id.clone());
        event.detail_json = enrollment_binding_audit_json(
            &approval.request_id,
            &before,
            &after,
            None,
            Some(&node_after),
            None,
            Some(&endpoint_after),
            &approval.reason,
        );
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(after)
    }

    pub fn claim_legacy_enrollment(
        &self,
        claim: &LegacyEnrollmentClaimInput,
        actor: &str,
    ) -> Result<JoinRequestRecord, PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        validate_reason(&claim.reason).map_err(PostgresError::InvalidInput)?;
        validate_enrollment_request_id(&claim.request_id)?;
        let node = NodeInsert {
            node_id: claim.node_id.clone(),
            endpoint_id: claim.endpoint_id.clone(),
            name: claim.node_id.clone(),
            region: claim.region.clone(),
            role: claim.role.clone(),
        };
        validate_node(&node, actor)?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let join = get_join_request_tx(&mut tx, &claim.request_id)?.ok_or_else(|| {
            PostgresError::InvalidState("native join request not found".to_string())
        })?;
        validate_approved_join_provenance_tx(&mut tx, &join, &node.endpoint_id)?;
        validate_approved_join_audit_provenance_tx(&mut tx, &join, &node.endpoint_id, None)?;
        let endpoint_before =
            get_endpoint_trust_tx(&mut tx, &node.endpoint_id)?.ok_or_else(|| {
                PostgresError::InvalidState("native approved endpoint is missing".to_string())
            })?;
        validate_enrollment_endpoint_origin(&join, &endpoint_before, &claim.request_id)?;
        if endpoint_before.node_id.is_some() {
            validate_enrollment_claim_audit_provenance_tx(
                &mut tx,
                &join,
                &node.endpoint_id,
                &node.node_id,
                actor,
                &claim.reason,
            )?;
            validate_exact_enrollment_binding_tx(
                &mut tx,
                &join,
                &endpoint_before,
                &node,
                None,
                "claim retry does not match the existing binding",
            )?;
            return Ok(join);
        }
        if get_node_tx(&mut tx, &node.node_id)?.is_some()
            || get_node_by_endpoint_tx(&mut tx, &node.endpoint_id)?.is_some()
            || endpoint_trust_count_for_node_tx(&mut tx, &node.node_id)? != 0
        {
            return Err(PostgresError::InvalidState(
                "native legacy node or endpoint binding already exists".to_string(),
            ));
        }
        tx.execute(
            "INSERT INTO ocfleet_native.nodes (node_id, endpoint_id, name, region, role)
             VALUES ($1, $2, $3, $4, $5)",
            &[
                &node.node_id,
                &node.endpoint_id,
                &node.name,
                &node.region,
                &node.role,
            ],
        )?;
        let affected = tx.execute(
            "UPDATE ocfleet_native.endpoint_trust
             SET node_id = $1, updated_at = clock_timestamp()
             WHERE endpoint_id = $2 AND node_id IS NULL AND status = 'active'
               AND generation = 1 AND previous_endpoint_id IS NULL AND rotated_to IS NULL
               AND fingerprint = $3",
            &[&node.node_id, &node.endpoint_id, &join.fingerprint],
        )?;
        if affected != 1 {
            return Err(PostgresError::InvalidState(
                "native legacy endpoint changed during claim".to_string(),
            ));
        }
        let node_after =
            get_node_tx(&mut tx, &node.node_id)?.expect("native claimed legacy node exists");
        let endpoint_after = get_endpoint_trust_tx(&mut tx, &node.endpoint_id)?
            .expect("native claimed legacy endpoint exists");
        validate_exact_enrollment_binding_tx(
            &mut tx,
            &join,
            &endpoint_after,
            &node,
            None,
            "claimed binding is inconsistent",
        )?;
        let mut event = AuditEvent::new(actor, "enrollment.claim");
        event.ok = Some(true);
        event.request_id = Some(claim.request_id.clone());
        event.node_id = Some(node.node_id.clone());
        event.endpoint_id = Some(node.endpoint_id.clone());
        event.detail_json = enrollment_binding_audit_json(
            &claim.request_id,
            &join,
            &join,
            None,
            Some(&node_after),
            Some(&endpoint_before),
            Some(&endpoint_after),
            &claim.reason,
        );
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(join)
    }

    pub fn insert_observability_job(
        &self,
        job: &ObservabilityJobRecord,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_observability_job(job, actor)?;
        let created_at = parse_postgres_timestamp(&job.created_at, "job created_at")?;
        let updated_at = parse_postgres_timestamp(&job.updated_at, "job updated_at")?;
        let next_run_at = parse_optional_postgres_timestamp(&job.next_run_at, "job next_run_at")?;
        let last_run_at = parse_optional_postgres_timestamp(&job.last_run_at, "job last_run_at")?;
        let interval_seconds = checked_i64(job.interval_seconds, "interval_seconds")?;
        let jitter_seconds = checked_i64(job.jitter_seconds, "jitter_seconds")?;
        let timeout_ms = checked_i64(job.timeout_ms, "timeout_ms")?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO ocfleet_native.observability_jobs
             (job_id, kind, selector_json, pair_selector_json, interval_seconds,
              jitter_seconds, timeout_ms, enabled, next_run_at, last_run_at, created_at, updated_at)
             VALUES ($1, $2, CAST($3 AS text)::jsonb, CAST($4 AS text)::jsonb, $5, $6,
                     $7, $8, $9, $10, $11, $12)",
            &[
                &job.job_id,
                &job.kind,
                &job.selector_json.to_string(),
                &job.pair_selector_json.as_ref().map(Value::to_string),
                &interval_seconds,
                &jitter_seconds,
                &timeout_ms,
                &job.enabled,
                &next_run_at,
                &last_run_at,
                &created_at,
                &updated_at,
            ],
        )?;
        let after = get_observability_job_tx(&mut tx, &job.job_id)?
            .ok_or_else(|| PostgresError::InvalidState("native job insert disappeared".into()))?;
        let mut event = AuditEvent::new(actor, "scheduler.job.add");
        event.ok = Some(true);
        event.detail_json = scheduler_job_audit_detail(&after, "created");
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_observability_jobs(
        &self,
        limit: u64,
    ) -> Result<Vec<ObservabilityJobRecord>, PostgresError> {
        let limit = checked_query_limit(limit)?;
        let mut conn = self.connection()?;
        conn.query(
            "SELECT job_id, kind, selector_json::text, pair_selector_json::text,
                    interval_seconds, jitter_seconds, timeout_ms, enabled,
                    next_run_at, last_run_at, created_at, updated_at
             FROM ocfleet_native.observability_jobs ORDER BY job_id LIMIT $1",
            &[&limit],
        )?
        .iter()
        .map(observability_job_from_row)
        .collect()
    }

    pub fn get_observability_job(
        &self,
        job_id: &str,
    ) -> Result<Option<ObservabilityJobRecord>, PostgresError> {
        validate_native_id("scheduler job_id", job_id, 128)?;
        let mut conn = self.connection()?;
        conn.query_opt(
            "SELECT job_id, kind, selector_json::text, pair_selector_json::text,
                    interval_seconds, jitter_seconds, timeout_ms, enabled,
                    next_run_at, last_run_at, created_at, updated_at
             FROM ocfleet_native.observability_jobs WHERE job_id = $1",
            &[&job_id],
        )?
        .as_ref()
        .map(observability_job_from_row)
        .transpose()
    }

    pub fn set_observability_job_enabled(
        &self,
        job_id: &str,
        enabled: bool,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_native_id("scheduler job_id", job_id, 128)?;
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let before = get_observability_job_tx(&mut tx, job_id)?.ok_or_else(|| {
            PostgresError::InvalidState(format!("native job not found: {job_id}"))
        })?;
        tx.execute(
            "UPDATE ocfleet_native.observability_jobs
             SET enabled = $1, updated_at = clock_timestamp() WHERE job_id = $2",
            &[&enabled, &job_id],
        )?;
        let after = get_observability_job_tx(&mut tx, job_id)?
            .ok_or_else(|| PostgresError::InvalidState("native job update disappeared".into()))?;
        let mut event = AuditEvent::new(
            actor,
            if enabled {
                "scheduler.job.enable"
            } else {
                "scheduler.job.disable"
            },
        );
        event.ok = Some(true);
        event.detail_json = json!({
            "job_id": job_id,
            "kind": after.kind,
            "before_enabled": before.enabled,
            "after_enabled": after.enabled,
            "result_class": "scheduler_summary",
        });
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_scheduler_maintenance(
        &self,
    ) -> Result<Option<SchedulerMaintenanceWindow>, PostgresError> {
        let mut conn = self.connection()?;
        conn.query_opt(
            "SELECT starts_at, ends_at, reason, updated_at
             FROM ocfleet_native.scheduler_maintenance WHERE singleton_id = 1",
            &[],
        )?
        .as_ref()
        .map(scheduler_maintenance_from_row)
        .transpose()
    }

    pub fn scheduler_maintenance_active_at(
        &self,
        now: &str,
    ) -> Result<Option<SchedulerMaintenanceWindow>, PostgresError> {
        let now = parse_postgres_timestamp(now, "scheduler maintenance check timestamp")?;
        Ok(self.get_scheduler_maintenance()?.filter(|window| {
            let starts =
                parse_postgres_timestamp(&window.starts_at, "stored maintenance starts_at");
            let ends = parse_postgres_timestamp(&window.ends_at, "stored maintenance ends_at");
            matches!((starts, ends), (Ok(starts), Ok(ends)) if starts <= now && now < ends)
        }))
    }

    pub fn set_scheduler_maintenance(
        &self,
        window: &SchedulerMaintenanceWindow,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        let (starts_at, ends_at, updated_at) = validate_scheduler_maintenance(window)?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO ocfleet_native.scheduler_maintenance
             (singleton_id, starts_at, ends_at, reason, updated_at)
             VALUES (1, $1, $2, $3, $4)
             ON CONFLICT (singleton_id) DO UPDATE SET starts_at = EXCLUDED.starts_at,
               ends_at = EXCLUDED.ends_at, reason = EXCLUDED.reason,
               updated_at = EXCLUDED.updated_at",
            &[&starts_at, &ends_at, &window.reason, &updated_at],
        )?;
        let mut event = AuditEvent::new(actor, "scheduler.maintenance.set");
        event.ok = Some(true);
        event.detail_json = json!({
            "from": window.starts_at,
            "to": window.ends_at,
            "reason": window.reason,
            "state": "configured",
            "result_class": "scheduler_summary",
        });
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn clear_scheduler_maintenance(
        &self,
        cleared_at: &str,
        actor: &str,
    ) -> Result<bool, PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        parse_postgres_timestamp(cleared_at, "scheduler maintenance cleared_at")?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let removed = tx.execute(
            "DELETE FROM ocfleet_native.scheduler_maintenance WHERE singleton_id = 1",
            &[],
        )? == 1;
        let mut event = AuditEvent::new(actor, "scheduler.maintenance.clear");
        event.ok = Some(true);
        event.detail_json = json!({
            "state": if removed { "cleared" } else { "already_clear" },
            "result_class": "scheduler_summary",
        });
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(removed)
    }

    pub fn claim_next_due_scheduler_job(
        &self,
        owner_id: &str,
        now: &str,
        lease_seconds: u64,
        actor: &str,
    ) -> Result<Option<SchedulerJobClaim>, PostgresError> {
        validate_scheduler_claim_input(owner_id, now, lease_seconds, actor)?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let job_id: Option<String> = tx
            .query_opt(
                "SELECT j.job_id
             FROM ocfleet_native.observability_jobs j
             LEFT JOIN ocfleet_native.scheduler_job_claims c ON c.job_id = j.job_id
             WHERE j.enabled AND (j.next_run_at IS NULL OR j.next_run_at <= clock_timestamp())
               AND (c.owner_id IS NULL OR c.lease_expires_at <= clock_timestamp())
             ORDER BY j.next_run_at NULLS FIRST, j.job_id
             FOR UPDATE OF j SKIP LOCKED LIMIT 1",
                &[],
            )?
            .map(|row| row.try_get(0))
            .transpose()?;
        let Some(job_id) = job_id else {
            tx.commit()?;
            return Ok(None);
        };
        let claim =
            acquire_scheduler_claim_tx(&mut tx, &job_id, owner_id, lease_seconds, actor, true)?;
        tx.commit()?;
        Ok(claim)
    }

    pub fn claim_scheduler_job(
        &self,
        job_id: &str,
        owner_id: &str,
        now: &str,
        lease_seconds: u64,
        actor: &str,
    ) -> Result<Option<SchedulerJobClaim>, PostgresError> {
        self.claim_scheduler_job_inner(job_id, owner_id, now, lease_seconds, actor, false)
    }

    pub fn claim_due_scheduler_job(
        &self,
        job_id: &str,
        owner_id: &str,
        now: &str,
        lease_seconds: u64,
        actor: &str,
    ) -> Result<Option<SchedulerJobClaim>, PostgresError> {
        self.claim_scheduler_job_inner(job_id, owner_id, now, lease_seconds, actor, true)
    }

    fn claim_scheduler_job_inner(
        &self,
        job_id: &str,
        owner_id: &str,
        now: &str,
        lease_seconds: u64,
        actor: &str,
        require_due: bool,
    ) -> Result<Option<SchedulerJobClaim>, PostgresError> {
        validate_native_id("scheduler job_id", job_id, 128)?;
        validate_scheduler_claim_input(owner_id, now, lease_seconds, actor)?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let claim = acquire_scheduler_claim_tx(
            &mut tx,
            job_id,
            owner_id,
            lease_seconds,
            actor,
            require_due,
        )?;
        tx.commit()?;
        Ok(claim)
    }

    pub fn renew_scheduler_job_claim(
        &self,
        claim: &SchedulerJobClaim,
        now: &str,
        lease_seconds: u64,
        actor: &str,
    ) -> Result<SchedulerJobClaim, PostgresError> {
        validate_scheduler_claim(claim)?;
        validate_scheduler_claim_input(&claim.owner_id, now, lease_seconds, actor)?;
        let fence_token = checked_i64(claim.fence_token, "fence token")?;
        let lease_seconds = checked_i64(lease_seconds, "lease")?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let renewed = tx.query_opt(
            "WITH authority AS (SELECT clock_timestamp() AS now)
             UPDATE ocfleet_native.scheduler_job_claims AS claim
             SET lease_expires_at = authority.now + $1 * interval '1 second',
                 updated_at = authority.now
             FROM authority
             WHERE claim.job_id = $2 AND claim.owner_id = $3 AND claim.fence_token = $4
               AND claim.owner_actor = $5 AND claim.lease_expires_at > authority.now
             RETURNING claim.lease_expires_at",
            &[
                &lease_seconds,
                &claim.job_id,
                &claim.owner_id,
                &fence_token,
                &actor,
            ],
        )?;
        let Some(renewed) = renewed else {
            return Err(scheduler_claim_lost(&claim.job_id));
        };
        let lease_expires_at: OffsetDateTime = renewed.try_get(0)?;
        let renewed = SchedulerJobClaim {
            lease_expires_at: format_postgres_timestamp(lease_expires_at, "lease_expires_at")?,
            ..claim.clone()
        };
        insert_scheduler_claim_audit(&mut tx, "scheduler.claim.renew", &renewed, actor, "renewed")?;
        tx.commit()?;
        Ok(renewed)
    }

    pub fn release_scheduler_job_claim(
        &self,
        claim: &SchedulerJobClaim,
        released_at: &str,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_scheduler_claim(claim)?;
        parse_postgres_timestamp(released_at, "scheduler released_at")?;
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        let fence_token = checked_i64(claim.fence_token, "fence token")?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let affected = tx.execute(
            "WITH authority AS (SELECT clock_timestamp() AS now)
             UPDATE ocfleet_native.scheduler_job_claims AS claim
             SET owner_id = NULL, claimed_at = NULL, lease_expires_at = NULL,
                 owner_actor = NULL, active_run_id = NULL, updated_at = authority.now
             FROM authority
             WHERE claim.job_id = $1 AND claim.owner_id = $2 AND claim.fence_token = $3
               AND claim.owner_actor = $4 AND claim.lease_expires_at > authority.now
               AND claim.active_run_id IS NULL",
            &[&claim.job_id, &claim.owner_id, &fence_token, &actor],
        )?;
        if affected != 1 {
            return Err(scheduler_claim_lost(&claim.job_id));
        }
        insert_scheduler_claim_audit(&mut tx, "scheduler.claim.release", claim, actor, "released")?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_scheduler_job_claim(
        &self,
        job_id: &str,
    ) -> Result<Option<SchedulerJobClaim>, PostgresError> {
        validate_native_id("scheduler job_id", job_id, 128)?;
        let mut conn = self.connection()?;
        conn.query_opt(
            "SELECT job_id, owner_id, fence_token, claimed_at, lease_expires_at, active_run_id
             FROM ocfleet_native.scheduler_job_claims
             WHERE job_id = $1 AND owner_id IS NOT NULL",
            &[&job_id],
        )?
        .as_ref()
        .map(scheduler_claim_from_row)
        .transpose()
    }

    pub fn write_scheduler_claimed_run_start(
        &self,
        start: &SchedulerRunStart,
        claim: &SchedulerJobClaim,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        validate_native_id("scheduler run_id", &start.run_id, 128)?;
        validate_native_id("scheduler job_id", &start.job_id, 128)?;
        let started_at = parse_postgres_timestamp(&start.started_at, "scheduler started_at")?;
        validate_scheduler_claim(claim)?;
        if claim.job_id != start.job_id {
            return Err(PostgresError::InvalidInput(
                "scheduler claim job_id does not match run start".into(),
            ));
        }
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let job = get_observability_job_tx(&mut tx, &start.job_id)?.ok_or_else(|| {
            PostgresError::InvalidState(format!("native job not found: {}", start.job_id))
        })?;
        if !job.enabled {
            return Err(PostgresError::InvalidInput(format!(
                "scheduler job is disabled: {}",
                start.job_id
            )));
        }
        let summary = RunSummaryPayloadV1::new(
            Some(start.job_id.clone()),
            Some(job.kind.clone()),
            "running".to_string(),
            "scheduler.run.once".to_string(),
            None,
            None,
        )
        .map_err(PostgresError::InvalidInput)?;
        tx.execute(
            "INSERT INTO ocfleet_native.observability_runs
             (run_id, job_id, started_at, finished_at, status, triggered_by, summary_json)
             VALUES ($1, $2, $3, NULL, 'running', 'scheduler.run.once', CAST($4 AS text)::jsonb)",
            &[
                &start.run_id,
                &start.job_id,
                &started_at,
                &summary.to_value().to_string(),
            ],
        )?;
        let fence_token = checked_i64(claim.fence_token, "fence token")?;
        let affected = tx.execute(
            "UPDATE ocfleet_native.scheduler_job_claims
             SET active_run_id = $1, updated_at = clock_timestamp()
             WHERE job_id = $2 AND owner_id = $3 AND fence_token = $4
               AND owner_actor = $5 AND active_run_id IS NULL
               AND lease_expires_at > clock_timestamp()",
            &[
                &start.run_id,
                &claim.job_id,
                &claim.owner_id,
                &fence_token,
                &actor,
            ],
        )?;
        if affected != 1 {
            return Err(scheduler_claim_lost(&start.job_id));
        }
        let mut event = AuditEvent::new(actor, "scheduler.run.start");
        event.ok = Some(true);
        event.detail_json = json!({
            "run_id": start.run_id,
            "job_id": start.job_id,
            "kind": job.kind,
            "status": "running",
            "result_class": "scheduler_summary",
        });
        insert_audit(&mut tx, &event)?;
        ensure_scheduler_job_claim_tx(&mut tx, claim, Some(&start.run_id), actor)?;
        tx.commit()?;
        Ok(())
    }

    pub fn insert_observability_run(
        &self,
        run: &ObservabilityRunInsert,
    ) -> Result<(), PostgresError> {
        validate_observability_run_insert(run)?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        insert_observability_run_tx(&mut tx, run)?;
        tx.commit()?;
        Ok(())
    }

    pub fn write_scheduler_outcome(
        &self,
        outcome: &SchedulerOutcomeWrite,
        claim: &SchedulerJobClaim,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_scheduler_outcome(outcome, actor)?;
        validate_scheduler_outcome_claim(outcome, claim)?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        ensure_scheduler_job_claim_tx(&mut tx, claim, outcome.run_id.as_deref(), actor)?;
        let job = get_observability_job_tx(&mut tx, &outcome.job_id)?.ok_or_else(|| {
            PostgresError::InvalidState(format!("native job not found: {}", outcome.job_id))
        })?;
        if let Some(run_id) = outcome.run_id.as_deref() {
            let run = get_observability_run_state_tx(&mut tx, run_id)?.ok_or_else(|| {
                PostgresError::InvalidState(format!("native run not found: {run_id}"))
            })?;
            if run.job_id.as_deref() != Some(outcome.job_id.as_str()) {
                return Err(PostgresError::InvalidInput(
                    "scheduler outcome job_id does not match run".into(),
                ));
            }
            if run.status != "running" || run.finished_at.is_some() {
                return Err(PostgresError::Store(
                    StoreError::ObservabilityRunNotRunning(run_id.to_string()),
                ));
            }
            for entry in &outcome.entries {
                if !scheduler_job_kind_allows_method(&job.kind, &entry.observation.method) {
                    return Err(PostgresError::InvalidInput(
                        "scheduler outcome method is not allowed for job kind".into(),
                    ));
                }
            }
        }
        for entry in &outcome.entries {
            insert_probe_observation_tx(&mut tx, &entry.observation)?;
            insert_audit(&mut tx, &entry.audit)?;
        }
        if let Some(clock) = &outcome.job_clock {
            update_scheduler_job_clock_tx(&mut tx, clock)?;
        }
        ensure_scheduler_job_claim_tx(&mut tx, claim, outcome.run_id.as_deref(), actor)?;
        tx.commit()?;
        Ok(())
    }

    pub fn write_scheduler_run_finish(
        &self,
        finish: &SchedulerRunFinish,
        claim: &SchedulerJobClaim,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        validate_native_id("scheduler run_id", &finish.run_id, 128)?;
        validate_scheduler_claim(claim)?;
        if claim.job_id != finish.job_clock.job_id {
            return Err(PostgresError::InvalidInput(
                "scheduler claim job_id does not match run finish".into(),
            ));
        }
        let finished_at = parse_postgres_timestamp(&finish.finished_at, "scheduler finished_at")?;
        let (next_run_at, last_run_at) = validate_scheduler_job_clock(&finish.job_clock)?;
        if finished_at != last_run_at {
            return Err(PostgresError::InvalidInput(
                "scheduler last_run_at must equal finished_at".into(),
            ));
        }
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let job = get_observability_job_tx(&mut tx, &finish.job_clock.job_id)?
            .ok_or_else(|| PostgresError::InvalidState("native finish job disappeared".into()))?;
        ensure_scheduler_job_claim_tx(&mut tx, claim, Some(&finish.run_id), actor)?;
        let run = get_observability_run_state_tx(&mut tx, &finish.run_id)?.ok_or_else(|| {
            PostgresError::InvalidState(format!("native run not found: {}", finish.run_id))
        })?;
        if run.status != "running" || run.finished_at.is_some() {
            return Err(PostgresError::Store(
                StoreError::ObservabilityRunNotRunning(finish.run_id.clone()),
            ));
        }
        if run.job_id.as_deref() != Some(finish.job_clock.job_id.as_str()) {
            return Err(PostgresError::InvalidInput(
                "scheduler finish job_id does not match run".into(),
            ));
        }
        if finished_at < run.started_at {
            return Err(PostgresError::InvalidInput(
                "scheduler finished_at must not precede started_at".into(),
            ));
        }
        let counts = tx.query_one(
            "SELECT COUNT(*), COUNT(*) FILTER (WHERE ok = FALSE)
             FROM ocfleet_native.probe_observations WHERE run_id = $1",
            &[&finish.run_id],
        )?;
        let observation_count = checked_u64(counts.try_get(0)?, "observation count")?;
        let failed_observation_count = checked_u64(counts.try_get(1)?, "failed observation count")?;
        let status = if observation_count == 0 {
            "skipped"
        } else if failed_observation_count == 0 {
            "succeeded"
        } else {
            "failed"
        };
        let summary = RunSummaryPayloadV1::new(
            Some(finish.job_clock.job_id.clone()),
            Some(job.kind.clone()),
            status.to_string(),
            "scheduler.run.once".to_string(),
            Some(observation_count),
            Some(failed_observation_count),
        )
        .map_err(PostgresError::InvalidState)?;
        let affected = tx.execute(
            "UPDATE ocfleet_native.observability_runs
             SET finished_at = $1, status = $2, summary_json = CAST($3 AS text)::jsonb
             WHERE run_id = $4 AND status = 'running' AND finished_at IS NULL",
            &[
                &finished_at,
                &status,
                &summary.to_value().to_string(),
                &finish.run_id,
            ],
        )?;
        if affected != 1 {
            return Err(PostgresError::Store(
                StoreError::ObservabilityRunNotRunning(finish.run_id.clone()),
            ));
        }
        update_scheduler_job_clock_values_tx(
            &mut tx,
            &finish.job_clock.job_id,
            next_run_at,
            last_run_at,
        )?;
        let fence_token = checked_i64(claim.fence_token, "fence token")?;
        let cleared = tx.execute(
            "UPDATE ocfleet_native.scheduler_job_claims
             SET active_run_id = NULL, updated_at = clock_timestamp()
             WHERE job_id = $1 AND owner_id = $2 AND fence_token = $3
               AND owner_actor = $4 AND active_run_id = $5
               AND lease_expires_at > clock_timestamp()",
            &[
                &finish.job_clock.job_id,
                &claim.owner_id,
                &fence_token,
                &actor,
                &finish.run_id,
            ],
        )?;
        if cleared != 1 {
            return Err(scheduler_claim_lost(&claim.job_id));
        }
        let mut event = AuditEvent::new(actor, "scheduler.run.finish");
        event.ok = Some(status != "failed");
        event.detail_json = json!({
            "run_id": finish.run_id,
            "job_id": finish.job_clock.job_id,
            "kind": job.kind,
            "status": status,
            "observations": observation_count,
            "failed_observations": failed_observation_count,
            "result_class": "scheduler_summary",
        });
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn insert_probe_observation(
        &self,
        observation: &ProbeObservationInsert,
    ) -> Result<(), PostgresError> {
        validate_probe_observation(observation)?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        insert_probe_observation_tx(&mut tx, observation)?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_observability_runs(
        &self,
        limit: u64,
    ) -> Result<Vec<ObservabilityRunRecord>, PostgresError> {
        let limit = checked_query_limit(limit)?;
        let mut conn = self.connection()?;
        conn.query(
            "SELECT r.run_id, r.job_id, r.started_at, r.finished_at, r.status,
                    r.triggered_by, r.summary_json::text, COUNT(o.observation_id),
                    COUNT(o.observation_id) FILTER (WHERE o.ok = FALSE), j.kind
             FROM ocfleet_native.observability_runs r
             LEFT JOIN ocfleet_native.probe_observations o ON o.run_id = r.run_id
             LEFT JOIN ocfleet_native.observability_jobs j ON j.job_id = r.job_id
             GROUP BY r.run_id, j.kind ORDER BY r.started_at DESC, r.run_id DESC LIMIT $1",
            &[&limit],
        )?
        .iter()
        .map(observability_run_from_row)
        .collect()
    }

    pub fn get_observability_run(
        &self,
        run_id: &str,
    ) -> Result<Option<ObservabilityRunRecord>, PostgresError> {
        validate_native_id("scheduler run_id", run_id, 128)?;
        let mut conn = self.connection()?;
        conn.query_opt(
            "SELECT r.run_id, r.job_id, r.started_at, r.finished_at, r.status,
                    r.triggered_by, r.summary_json::text, COUNT(o.observation_id),
                    COUNT(o.observation_id) FILTER (WHERE o.ok = FALSE), j.kind
             FROM ocfleet_native.observability_runs r
             LEFT JOIN ocfleet_native.probe_observations o ON o.run_id = r.run_id
             LEFT JOIN ocfleet_native.observability_jobs j ON j.job_id = r.job_id
             WHERE r.run_id = $1 GROUP BY r.run_id, j.kind",
            &[&run_id],
        )?
        .as_ref()
        .map(observability_run_from_row)
        .transpose()
    }

    pub fn list_probe_observations_filtered(
        &self,
        node_filter: Option<&str>,
        method_filter: Option<&str>,
        since: Option<&str>,
        limit: u64,
    ) -> Result<Vec<ProbeObservationRecord>, PostgresError> {
        if let Some(node_id) = node_filter {
            validate_native_id("observation node_id", node_id, 128)?;
        }
        if let Some(method) = method_filter {
            validate_observation_method(method)?;
        }
        let since = since
            .map(|value| parse_postgres_timestamp(value, "observation since"))
            .transpose()?;
        let limit = checked_query_limit(limit)?;
        let mut conn = self.connection()?;
        conn.query(
            "SELECT observation_id, run_id, node_id, endpoint_id, method, ok, error_code,
                    duration_ms, observed_at, expires_at, result_class, summary_json::text
             FROM ocfleet_native.probe_observations
             WHERE ($1::text IS NULL OR node_id = $1)
               AND ($2::text IS NULL OR method = $2)
               AND ($3::timestamptz IS NULL OR observed_at >= $3)
             ORDER BY observed_at DESC, observation_id DESC LIMIT $4",
            &[&node_filter, &method_filter, &since, &limit],
        )?
        .iter()
        .map(probe_observation_from_row)
        .collect()
    }

    pub fn get_probe_observation(
        &self,
        observation_id: &str,
    ) -> Result<Option<ProbeObservationRecord>, PostgresError> {
        validate_native_id("observation_id", observation_id, 128)?;
        let mut conn = self.connection()?;
        conn.query_opt(
            "SELECT observation_id, run_id, node_id, endpoint_id, method, ok, error_code,
                    duration_ms, observed_at, expires_at, result_class, summary_json::text
             FROM ocfleet_native.probe_observations WHERE observation_id = $1",
            &[&observation_id],
        )?
        .as_ref()
        .map(probe_observation_from_row)
        .transpose()
    }

    pub fn get_retention_policy(
        &self,
        scope: &str,
    ) -> Result<Option<RetentionPolicyRecord>, PostgresError> {
        validate_retention_scope(scope)?;
        let mut conn = self.connection()?;
        conn.query_opt(
            "SELECT scope, max_age_days, max_rows, updated_at
             FROM ocfleet_native.retention_policies WHERE scope = $1",
            &[&scope],
        )?
        .as_ref()
        .map(retention_policy_from_row)
        .transpose()
    }

    pub fn set_retention_policy(
        &self,
        policy: &RetentionPolicyRecord,
        actor: &str,
    ) -> Result<RetentionPolicyRecord, PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        validate_retention_policy(policy)?;
        let updated_at = parse_postgres_timestamp(&policy.updated_at, "retention updated_at")?;
        let max_age_days = policy
            .max_age_days
            .map(|value| checked_i64(value, "retention max_age_days"))
            .transpose()?;
        let max_rows = policy
            .max_rows
            .map(|value| checked_i64(value, "retention max_rows"))
            .transpose()?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let before = get_retention_policy_tx(&mut tx, &policy.scope)?;
        if before.as_ref().is_some_and(|existing| {
            existing.max_age_days == policy.max_age_days && existing.max_rows == policy.max_rows
        }) {
            tx.commit()?;
            return Ok(before.expect("checked existing policy"));
        }
        tx.execute(
            "INSERT INTO ocfleet_native.retention_policies
             (scope, max_age_days, max_rows, updated_at) VALUES ($1, $2, $3, $4)
             ON CONFLICT (scope) DO UPDATE SET max_age_days = EXCLUDED.max_age_days,
               max_rows = EXCLUDED.max_rows, updated_at = EXCLUDED.updated_at",
            &[&policy.scope, &max_age_days, &max_rows, &updated_at],
        )?;
        let after = get_retention_policy_tx(&mut tx, &policy.scope)?.ok_or_else(|| {
            PostgresError::InvalidState("native retention policy disappeared".into())
        })?;
        let mut event = AuditEvent::new(actor, "retention.set");
        event.ok = Some(true);
        event.detail_json = json!({
            "actor_type": "user",
            "target_type": "retention_policy",
            "target_id": policy.scope,
            "before": before.as_ref().map(retention_policy_json),
            "after": retention_policy_json(&after),
            "reason": Value::Null,
        });
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(after)
    }

    pub fn retention_candidate_report(
        &self,
        scope: &str,
        cutoff: Option<&str>,
        max_rows: Option<u64>,
    ) -> Result<RetentionCandidateReport, PostgresError> {
        validate_retention_scope(scope)?;
        validate_retention_max_rows(max_rows)?;
        let cutoff = cutoff
            .map(|value| parse_postgres_timestamp(value, "retention cutoff"))
            .transpose()?;
        let max_rows = max_rows
            .map(|value| checked_i64(value, "retention max_rows"))
            .transpose()?;
        let mut conn = self.connection()?;
        retention_candidate_report_tx(&mut *conn, scope, cutoff, max_rows)
    }

    pub fn apply_retention(
        &self,
        input: &RetentionApplyInput,
        actor: &str,
    ) -> Result<RetentionApplyResult, PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        validate_retention_apply_input(input)?;
        let input_json = retention_input_json(input);
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        lock_retention_target_tx(&mut tx, &input.scope)?;
        if let Some(row) = tx.query_opt(
            "SELECT actor, input_json::text, result_json::text
             FROM ocfleet_native.retention_operations WHERE operation_id = $1 FOR UPDATE",
            &[&input.operation_id],
        )? {
            let existing_actor: String = row.try_get(0)?;
            let existing_input: String = row.try_get(1)?;
            let existing_input: Value = serde_json::from_str(&existing_input).map_err(|_| {
                PostgresError::InvalidState("native retention operation input is invalid".into())
            })?;
            if existing_actor != actor || existing_input != input_json {
                return Err(retention_operation_conflict(&input.operation_id));
            }
            let result_json: String = row.try_get(2)?;
            let result = retention_result_from_json(&result_json, &input.operation_id)?;
            tx.commit()?;
            return Ok(result);
        }
        let cutoff = match (&input.cutoff, input.max_age_days) {
            (Some(cutoff), _) => Some(parse_postgres_timestamp(cutoff, "retention cutoff")?),
            (None, Some(days)) => Some(
                OffsetDateTime::now_utc()
                    - time::Duration::days(checked_i64(days, "retention max_age_days")?),
            ),
            (None, None) => None,
        };
        let max_rows = input
            .max_rows
            .map(|value| checked_i64(value, "retention max_rows"))
            .transpose()?;
        let candidate_report =
            retention_candidate_report_tx(&mut tx, &input.scope, cutoff, max_rows)?;
        let planned_delete_count = input
            .limit
            .map(|limit| candidate_report.matched_count.min(limit))
            .unwrap_or(candidate_report.matched_count);
        let mut rows_deleted = 0_u64;
        let mut batch_count = 0_u64;
        while rows_deleted < planned_delete_count {
            let batch = (planned_delete_count - rows_deleted).min(input.batch_size);
            let deleted = prune_retention_batch_tx(
                &mut tx,
                &input.scope,
                cutoff,
                max_rows,
                checked_i64(batch, "retention batch")?,
            )?;
            if deleted == 0 {
                break;
            }
            rows_deleted = rows_deleted.checked_add(deleted).ok_or_else(|| {
                PostgresError::InvalidState("native retention deleted count overflow".into())
            })?;
            batch_count = batch_count.checked_add(1).ok_or_else(|| {
                PostgresError::InvalidState("native retention batch count overflow".into())
            })?;
        }
        let result = RetentionApplyResult {
            cutoff: cutoff
                .map(|value| format_postgres_timestamp(value, "retention cutoff"))
                .transpose()?,
            candidate_report,
            planned_delete_count,
            rows_deleted,
            batch_count,
        };
        let result_json = retention_result_json(&result);
        tx.execute(
            "INSERT INTO ocfleet_native.retention_operations
             (operation_id, actor, input_json, result_json)
             VALUES ($1, $2, CAST($3 AS text)::jsonb, CAST($4 AS text)::jsonb)",
            &[
                &input.operation_id,
                &actor,
                &input_json.to_string(),
                &result_json.to_string(),
            ],
        )?;
        let mut event = AuditEvent::new(actor, "retention.apply");
        event.ok = Some(true);
        event.request_id = Some(input.operation_id.clone());
        event.detail_json = json!({
            "actor_type": "user",
            "target_type": "retention_scope",
            "target_id": input.scope,
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
            "reason": Value::Null,
        });
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(result)
    }

    pub fn audit_count(&self, event: &str) -> Result<i64, PostgresError> {
        let mut conn = self.connection()?;
        Ok(conn
            .query_one(
                "SELECT COUNT(*) FROM ocfleet_native.controller_audit_log WHERE event = $1",
                &[&event],
            )?
            .get(0))
    }
}

impl PostgresNativeStore {
    pub fn get_health_policy(&self) -> Result<HealthPolicyRecord, PostgresError> {
        let mut conn = self.connection()?;
        conn.query_opt(
            "SELECT stale_window_seconds, unreachable_consecutive_failures,
                    cert_warning_days, cert_critical_days, updated_at
             FROM ocfleet_native.health_policy WHERE singleton_id = 1",
            &[],
        )?
        .as_ref()
        .map(health_policy_from_postgres_row)
        .transpose()?
        .ok_or_else(|| PostgresError::InvalidState("native health policy is missing".into()))
    }

    pub fn set_health_policy(
        &self,
        policy: &HealthPolicyRecord,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        map_store_validation(validate_health_policy(policy))?;
        validate_native_id("health policy updated_at", &policy.updated_at, 64)?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let before = tx.query_one(
            "SELECT stale_window_seconds, unreachable_consecutive_failures,
                    cert_warning_days, cert_critical_days, updated_at
             FROM ocfleet_native.health_policy WHERE singleton_id = 1 FOR UPDATE",
            &[],
        )?;
        let before = health_policy_from_postgres_row(&before)?;
        if before == *policy {
            tx.commit()?;
            return Ok(());
        }
        tx.execute(
            "UPDATE ocfleet_native.health_policy
             SET stale_window_seconds = $1, unreachable_consecutive_failures = $2,
                 cert_warning_days = $3, cert_critical_days = $4, updated_at = $5
             WHERE singleton_id = 1",
            &[
                &checked_i64(policy.stale_window_seconds, "stale_window_seconds")?,
                &checked_i64(
                    policy.unreachable_consecutive_failures,
                    "unreachable_consecutive_failures",
                )?,
                &checked_i64(policy.cert_warning_days, "cert_warning_days")?,
                &checked_i64(policy.cert_critical_days, "cert_critical_days")?,
                &policy.updated_at,
            ],
        )?;
        let mut event = AuditEvent::new(actor, "health.policy.set");
        event.ok = Some(true);
        event.detail_json = json!({
            "actor_type": "user",
            "target_type": "health_policy",
            "target_id": "global",
            "before": health_policy_audit_json_native(&before),
            "after": health_policy_audit_json_native(policy),
            "reason": Value::Null,
        });
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn write_health_snapshots(
        &self,
        write: &HealthSnapshotWrite,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        map_store_validation(validate_health_snapshot_write(write))?;
        let params_hash = health_snapshot_write_hash(write);
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        if native_audit_replay_tx(
            &mut tx,
            &write.evaluation_id,
            &write.event,
            actor,
            &params_hash,
        )? {
            tx.commit()?;
            return Ok(());
        }
        for snapshot in &write.snapshots {
            upsert_health_snapshot_postgres_tx(&mut tx, snapshot)?;
            insert_health_history_postgres_tx(&mut tx, &write.evaluation_id, snapshot)?;
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
        event.detail_json = json!({
            "actor_type": "user",
            "target_type": "health_snapshot_batch",
            "target_id": write.evaluation_id,
            "node_count": write.snapshots.len(),
            "status_counts": status_counts,
            "reason": Value::Null,
        });
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_health_snapshots(
        &self,
        limit: u64,
    ) -> Result<Vec<HealthSnapshotRecord>, PostgresError> {
        let limit = checked_query_limit(limit)?;
        let mut conn = self.connection()?;
        conn.query(
            "SELECT node_id, endpoint_id, computed_at, status, freshness_seconds,
                    last_success_at, last_failure_at, last_error_code,
                    degraded_methods_json::text, summary_json::text
             FROM ocfleet_native.health_snapshots
             ORDER BY computed_at DESC, node_id LIMIT $1",
            &[&limit],
        )?
        .iter()
        .map(health_snapshot_from_postgres_row)
        .collect()
    }

    pub fn list_health_history(
        &self,
        node_id: Option<&str>,
        from: &str,
        to: &str,
        limit: u64,
    ) -> Result<Vec<HealthHistoryRecord>, PostgresError> {
        if let Some(node_id) = node_id {
            validate_node_id(node_id)
                .map_err(|error| PostgresError::InvalidInput(error.to_string()))?;
        }
        let from = parse_postgres_timestamp(from, "health history from")?;
        let to = parse_postgres_timestamp(to, "health history to")?;
        if from >= to {
            return Err(PostgresError::InvalidInput(
                "health history from must precede to".into(),
            ));
        }
        let limit = checked_query_limit(limit)?;
        let mut conn = self.connection()?;
        conn.query(
            "SELECT evaluation_id, node_id, endpoint_id, computed_at, status,
                    freshness_seconds, last_success_at, last_failure_at, last_error_code,
                    degraded_methods_json::text, summary_json::text
             FROM ocfleet_native.health_history
             WHERE ($1::text IS NULL OR node_id = $1)
               AND computed_at >= $2 AND computed_at < $3
             ORDER BY computed_at DESC, node_id, evaluation_id LIMIT $4",
            &[&node_id, &from, &to, &limit],
        )?
        .iter()
        .map(health_history_from_postgres_row)
        .collect()
    }

    pub fn health_rollup_source(
        &self,
        node_id: &str,
        from: &str,
        to: &str,
    ) -> Result<HealthRollupSource, PostgresError> {
        validate_node_id(node_id)
            .map_err(|error| PostgresError::InvalidInput(error.to_string()))?;
        let from = parse_postgres_timestamp(from, "health rollup source from")?;
        let to = parse_postgres_timestamp(to, "health rollup source to")?;
        if from >= to {
            return Err(PostgresError::InvalidInput(
                "health rollup source from must precede to".into(),
            ));
        }
        const SOURCE_LIMIT: i64 = 100_001;
        let mut conn = self.connection()?;
        let history = conn
            .query(
                "SELECT evaluation_id, node_id, endpoint_id, computed_at, status,
                        freshness_seconds, last_success_at, last_failure_at, last_error_code,
                        degraded_methods_json::text, summary_json::text
                 FROM ocfleet_native.health_history
                 WHERE node_id = $1 AND computed_at >= $2 AND computed_at < $3
                 ORDER BY computed_at, evaluation_id LIMIT $4",
                &[&node_id, &from, &to, &SOURCE_LIMIT],
            )?
            .iter()
            .map(health_history_from_postgres_row)
            .collect::<Result<Vec<_>, _>>()?;
        let observations = conn
            .query(
                "SELECT observation_id, run_id, node_id, endpoint_id, method, ok,
                        error_code, duration_ms, observed_at, expires_at, result_class,
                        summary_json::text
                 FROM ocfleet_native.probe_observations
                 WHERE node_id = $1 AND observed_at >= $2 AND observed_at < $3
                 ORDER BY observed_at, observation_id LIMIT $4",
                &[&node_id, &from, &to, &SOURCE_LIMIT],
            )?
            .iter()
            .map(probe_observation_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        if history.len() >= SOURCE_LIMIT as usize || observations.len() >= SOURCE_LIMIT as usize {
            return Err(PostgresError::InvalidInput(
                "health rollup source exceeds 100000 rows in one bucket".into(),
            ));
        }
        Ok(HealthRollupSource {
            history,
            observations,
        })
    }

    pub fn health_rollup_node_ids(
        &self,
        from: &str,
        to: &str,
    ) -> Result<Vec<String>, PostgresError> {
        let from = parse_postgres_timestamp(from, "health rollup nodes from")?;
        let to = parse_postgres_timestamp(to, "health rollup nodes to")?;
        if from >= to {
            return Err(PostgresError::InvalidInput(
                "health rollup nodes from must precede to".into(),
            ));
        }
        let mut conn = self.connection()?;
        let rows = conn.query(
            "SELECT node_id FROM (
               SELECT node_id FROM ocfleet_native.health_history
               WHERE computed_at >= $1 AND computed_at < $2
               UNION
               SELECT node_id FROM ocfleet_native.probe_observations
               WHERE node_id IS NOT NULL AND observed_at >= $1 AND observed_at < $2
             ) source ORDER BY node_id LIMIT 1001",
            &[&from, &to],
        )?;
        if rows.len() > 1_000 {
            return Err(PostgresError::InvalidInput(
                "health rollup window exceeds 1000 nodes".into(),
            ));
        }
        rows.iter()
            .map(|row| row.try_get(0).map_err(Into::into))
            .collect()
    }

    pub fn write_health_rollups(
        &self,
        write: &HealthRollupWrite,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        map_store_validation(validate_health_rollup_write(write))?;
        let params_hash = health_rollup_write_hash(write);
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        if native_audit_replay_tx(
            &mut tx,
            &write.operation_id,
            "health.rollup.recompute",
            actor,
            &params_hash,
        )? {
            tx.commit()?;
            return Ok(());
        }
        for row in &write.rows {
            upsert_health_rollup_postgres_tx(&mut tx, row)?;
        }
        let mut event = AuditEvent::new(actor, "health.rollup.recompute");
        event.ok = Some(true);
        event.request_id = Some(write.operation_id.clone());
        event.params_hash = Some(params_hash);
        event.detail_json = json!({
            "actor_type": "system",
            "target_type": "health_rollup_batch",
            "target_id": write.operation_id,
            "batch_count": write.rows.len(),
            "reason": Value::Null,
        });
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_health_rollups(
        &self,
        node_id: Option<&str>,
        bucket_seconds: u64,
        from: &str,
        to: &str,
        limit: u64,
    ) -> Result<Vec<HealthRollupRecord>, PostgresError> {
        if let Some(node_id) = node_id {
            validate_node_id(node_id)
                .map_err(|error| PostgresError::InvalidInput(error.to_string()))?;
        }
        map_store_validation(validate_health_rollup_bucket(bucket_seconds))?;
        let bucket_seconds = checked_i64(bucket_seconds, "health rollup bucket")?;
        let from = parse_postgres_timestamp(from, "health rollup from")?;
        let to = parse_postgres_timestamp(to, "health rollup to")?;
        if from >= to {
            return Err(PostgresError::InvalidInput(
                "health rollup from must precede to".into(),
            ));
        }
        if limit == 0 || limit > 100_000 {
            return Err(PostgresError::InvalidInput(
                "health rollup limit must be between 1 and 100000".into(),
            ));
        }
        let limit = checked_i64(limit, "health rollup limit")?;
        let mut conn = self.connection()?;
        conn.query(
            "SELECT node_id, bucket_seconds, bucket_start, bucket_end, input_watermark,
                    health_samples, covered_slots, expected_slots, healthy_count,
                    degraded_count, unreachable_count, stale_count, disabled_count,
                    unknown_count, observation_count, observation_error_count,
                    duration_sample_count, duration_p50_ms, duration_p95_ms,
                    cert_warning_count, cert_critical_count, fingerprint_sample_count,
                    fingerprint_change_count, computed_at
             FROM ocfleet_native.health_rollups
             WHERE ($1::text IS NULL OR node_id = $1) AND bucket_seconds = $2
               AND bucket_start >= $3 AND bucket_start < $4
             ORDER BY bucket_start, node_id LIMIT $5",
            &[&node_id, &bucket_seconds, &from, &to, &limit],
        )?
        .iter()
        .map(health_rollup_from_postgres_row)
        .collect()
    }

    pub fn health_rollup_stored_node_ids(
        &self,
        bucket_seconds: u64,
        from: &str,
        to: &str,
    ) -> Result<Vec<String>, PostgresError> {
        map_store_validation(validate_health_rollup_bucket(bucket_seconds))?;
        let bucket_seconds = checked_i64(bucket_seconds, "health rollup bucket")?;
        let from = parse_postgres_timestamp(from, "health SLO from")?;
        let to = parse_postgres_timestamp(to, "health SLO to")?;
        if from >= to {
            return Err(PostgresError::InvalidInput(
                "health SLO from must precede to".into(),
            ));
        }
        let mut conn = self.connection()?;
        let rows = conn.query(
            "SELECT DISTINCT node_id FROM ocfleet_native.health_rollups
             WHERE bucket_seconds = $1 AND bucket_start >= $2 AND bucket_start < $3
             ORDER BY node_id LIMIT 1001",
            &[&bucket_seconds, &from, &to],
        )?;
        if rows.len() > 1_000 {
            return Err(PostgresError::InvalidInput(
                "health SLO window exceeds 1000 nodes".into(),
            ));
        }
        rows.iter()
            .map(|row| row.try_get(0).map_err(PostgresError::from))
            .collect()
    }

    pub fn get_health_evaluation_run(
        &self,
        evaluation_id: &str,
    ) -> Result<Option<HealthEvaluationRunRecord>, PostgresError> {
        validate_native_id("health evaluation_id", evaluation_id, 96)?;
        let mut conn = self.connection()?;
        conn.query_opt(
            "SELECT evaluation_id, input_watermark, policy_version, computation_version,
                    started_at, finished_at, status, snapshot_count, failure_code
             FROM ocfleet_native.health_evaluation_runs WHERE evaluation_id = $1",
            &[&evaluation_id],
        )?
        .as_ref()
        .map(health_evaluation_from_postgres_row)
        .transpose()
    }

    pub fn write_health_evaluation_start(
        &self,
        start: &HealthEvaluationStart,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        map_store_validation(validate_health_evaluation_start(start))?;
        let started_at = parse_postgres_timestamp(&start.started_at, "health started_at")?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        lock_native_operation_tx(&mut tx, &start.evaluation_id)?;
        let existing = tx.query_opt(
            "SELECT evaluation_id, input_watermark, policy_version, computation_version,
                    started_at, finished_at, status, snapshot_count, failure_code
             FROM ocfleet_native.health_evaluation_runs
             WHERE evaluation_id = $1 OR (
               input_watermark = $2 AND policy_version = $3 AND computation_version = $4
             ) FOR UPDATE",
            &[
                &start.evaluation_id,
                &start.input_watermark,
                &start.policy_version,
                &start.computation_version,
            ],
        )?;
        if let Some(existing) = existing {
            let existing = health_evaluation_from_postgres_row(&existing)?;
            if existing.evaluation_id == start.evaluation_id
                && existing.input_watermark == start.input_watermark
                && existing.policy_version == start.policy_version
                && existing.computation_version == start.computation_version
                && native_audit_actor_matches_tx(
                    &mut tx,
                    &start.evaluation_id,
                    "health.evaluation.start",
                    actor,
                )?
            {
                tx.commit()?;
                return Ok(());
            }
            return Err(health_evaluation_conflict(
                &start.evaluation_id,
                "evaluation identity, replay key, or audit provenance is already bound",
            ));
        }
        tx.execute(
            "INSERT INTO ocfleet_native.health_evaluation_runs
             (evaluation_id, input_watermark, policy_version, computation_version,
              started_at, status)
             VALUES ($1, $2, $3, $4, $5, 'running')",
            &[
                &start.evaluation_id,
                &start.input_watermark,
                &start.policy_version,
                &start.computation_version,
                &started_at,
            ],
        )?;
        insert_health_evaluation_audit_postgres_tx(
            &mut tx,
            actor,
            "health.evaluation.start",
            &start.evaluation_id,
            true,
            None,
            0,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn write_health_evaluation_finish(
        &self,
        finish: &HealthEvaluationFinish,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        map_store_validation(validate_health_evaluation_finish(finish))?;
        let finished_at = parse_postgres_timestamp(&finish.finished_at, "health finished_at")?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE ocfleet_native.health_evaluation_runs
             SET finished_at = $2, status = 'completed', snapshot_count = $3
             WHERE evaluation_id = $1 AND status = 'running' AND finished_at IS NULL
               AND started_at <= $2",
            &[
                &finish.evaluation_id,
                &finished_at,
                &checked_i64(finish.snapshots.len() as u64, "health snapshot count")?,
            ],
        )?;
        if changed != 1 {
            return Err(health_evaluation_conflict(
                &finish.evaluation_id,
                "evaluation is missing, not running, or has invalid finish order",
            ));
        }
        for snapshot in &finish.snapshots {
            upsert_health_snapshot_postgres_tx(&mut tx, snapshot)?;
            insert_health_history_postgres_tx(&mut tx, &finish.evaluation_id, snapshot)?;
        }
        insert_health_evaluation_audit_postgres_tx(
            &mut tx,
            actor,
            "health.evaluation.finish",
            &finish.evaluation_id,
            true,
            None,
            finish.snapshots.len(),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn write_health_evaluation_failure(
        &self,
        failure: &HealthEvaluationFailure,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        map_store_validation(validate_health_evaluation_failure(failure))?;
        let finished_at = parse_postgres_timestamp(&failure.finished_at, "health finished_at")?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE ocfleet_native.health_evaluation_runs
             SET finished_at = $2, status = 'failed', failure_code = $3
             WHERE evaluation_id = $1 AND status = 'running' AND finished_at IS NULL
               AND started_at <= $2",
            &[&failure.evaluation_id, &finished_at, &failure.failure_code],
        )?;
        if changed != 1 {
            return Err(health_evaluation_conflict(
                &failure.evaluation_id,
                "evaluation is missing, not running, or has invalid finish order",
            ));
        }
        insert_health_evaluation_audit_postgres_tx(
            &mut tx,
            actor,
            "health.evaluation.fail",
            &failure.evaluation_id,
            false,
            Some(&failure.failure_code),
            0,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn write_health_evaluation_recovery(
        &self,
        cutoff: &str,
        recovered_at: &str,
        actor: &str,
    ) -> Result<usize, PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        let cutoff = parse_postgres_timestamp(cutoff, "health recovery cutoff")?;
        let recovered_at = parse_postgres_timestamp(recovered_at, "health recovered_at")?;
        if recovered_at < cutoff {
            return Err(PostgresError::InvalidInput(
                "health evaluation recovered_at precedes cutoff".into(),
            ));
        }
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let candidates = tx.query(
            "SELECT evaluation_id FROM ocfleet_native.health_evaluation_runs
             WHERE status = 'running' AND started_at < $1
             ORDER BY started_at, evaluation_id LIMIT 100 FOR UPDATE SKIP LOCKED",
            &[&cutoff],
        )?;
        let evaluation_ids = candidates
            .iter()
            .map(|row| row.try_get::<_, String>(0))
            .collect::<Result<Vec<_>, _>>()?;
        for evaluation_id in &evaluation_ids {
            let changed = tx.execute(
                "UPDATE ocfleet_native.health_evaluation_runs
                 SET finished_at = $2, status = 'failed',
                     failure_code = 'HEALTH_EVALUATION_ABANDONED'
                 WHERE evaluation_id = $1 AND status = 'running'",
                &[evaluation_id, &recovered_at],
            )?;
            if changed != 1 {
                return Err(health_evaluation_conflict(
                    evaluation_id,
                    "evaluation changed during recovery",
                ));
            }
            insert_health_evaluation_audit_postgres_tx(
                &mut tx,
                actor,
                "health.evaluation.recover",
                evaluation_id,
                false,
                Some("HEALTH_EVALUATION_ABANDONED"),
                0,
            )?;
        }
        tx.commit()?;
        Ok(evaluation_ids.len())
    }
}

impl PostgresNativeStore {
    pub fn upsert_alert_event(&self, alert: &AlertEventRecord) -> Result<(), PostgresError> {
        map_store_validation(validate_alert_event_record(alert))?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        upsert_alert_event_postgres_tx(&mut tx, alert)?;
        tx.commit()?;
        Ok(())
    }

    pub fn write_alert_evaluation(
        &self,
        write: &AlertEvaluationWrite,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        map_store_validation(validate_alert_evaluation_write(write))?;
        let params_hash = alert_evaluation_write_hash(write);
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        if native_audit_replay_tx(
            &mut tx,
            &write.evaluation_id,
            "alert.evaluate",
            actor,
            &params_hash,
        )? {
            tx.commit()?;
            return Ok(());
        }
        for entry in &write.entries {
            let current = get_alert_event_postgres_tx(&mut tx, &entry.after.dedupe_key, true)?;
            if !optional_alerts_equivalent(current.as_ref(), entry.before.as_ref())? {
                return Err(alert_evaluation_conflict(
                    &write.evaluation_id,
                    "alert state changed after candidate evaluation",
                ));
            }
            upsert_alert_event_postgres_tx(&mut tx, &entry.after)?;
        }
        let open_alerts = write
            .entries
            .iter()
            .filter(|entry| entry.after.state == "open")
            .count();
        let mut event = AuditEvent::new(actor, "alert.evaluate");
        event.ok = Some(true);
        event.request_id = Some(write.evaluation_id.clone());
        event.params_hash = Some(params_hash);
        event.detail_json = json!({
            "actor_type": "user",
            "target_type": "alert_evaluation",
            "target_id": write.evaluation_id,
            "evaluated_candidates": write.entries.len(),
            "upserted_alerts": write.entries.len(),
            "open_alerts": open_alerts,
            "silenced_alerts": write.entries.len() - open_alerts,
            "created_or_updated_count": write.entries.len(),
            "reason": Value::Null,
        });
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn write_alert_state_transition(
        &self,
        write: &AlertStateTransition,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        map_store_validation(validate_alert_state_transition(write))?;
        let params_hash = alert_state_transition_hash(write);
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        if native_audit_replay_tx(
            &mut tx,
            &write.operation_id,
            &write.event,
            actor,
            &params_hash,
        )? {
            tx.commit()?;
            return Ok(());
        }
        let current = get_alert_event_postgres_tx(&mut tx, &write.before.dedupe_key, true)?;
        if !optional_alerts_equivalent(current.as_ref(), Some(&write.before))? {
            return Err(alert_mutation_conflict(
                &write.operation_id,
                "alert state changed before operator transition",
            ));
        }
        upsert_alert_event_postgres_tx(&mut tx, &write.after)?;
        let mut event = AuditEvent::new(actor, write.event.clone());
        event.ok = Some(true);
        event.request_id = Some(write.operation_id.clone());
        event.params_hash = Some(params_hash);
        event.detail_json = json!({
            "actor_type": "user",
            "target_type": "alert",
            "target_id": write.after.alert_id,
            "dedupe_key": write.after.dedupe_key,
            "before_state": write.before.state,
            "after_state": write.after.state,
            "reason": write.reason,
        });
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_alert_events(&self, limit: u64) -> Result<Vec<AlertEventRecord>, PostgresError> {
        self.list_alert_events_filtered(None, None, None, limit)
    }

    pub fn list_alert_events_filtered(
        &self,
        state: Option<&str>,
        severity: Option<&str>,
        node_id: Option<&str>,
        limit: u64,
    ) -> Result<Vec<AlertEventRecord>, PostgresError> {
        if state.is_some_and(|value| !matches!(value, "open" | "resolved" | "silenced")) {
            return Err(PostgresError::InvalidInput(
                "alert state filter is invalid".into(),
            ));
        }
        if severity.is_some_and(|value| !matches!(value, "warning" | "critical")) {
            return Err(PostgresError::InvalidInput(
                "alert severity filter is invalid".into(),
            ));
        }
        if let Some(node_id) = node_id {
            validate_node_id(node_id)
                .map_err(|error| PostgresError::InvalidInput(error.to_string()))?;
        }
        let limit = checked_query_limit(limit)?;
        let mut conn = self.connection()?;
        conn.query(
            "SELECT alert_id, dedupe_key, node_id, severity, state, reason_code,
                    first_seen_at, last_seen_at, last_sent_at, resolved_at,
                    detail_json::text
             FROM ocfleet_native.alert_events
             WHERE ($1::text IS NULL OR state = $1)
               AND ($2::text IS NULL OR severity = $2)
               AND ($3::text IS NULL OR node_id = $3)
             ORDER BY last_seen_at DESC, alert_id LIMIT $4",
            &[&state, &severity, &node_id, &limit],
        )?
        .iter()
        .map(alert_event_from_postgres_row)
        .collect()
    }

    pub fn write_alert_webhook_hook_create(
        &self,
        hook: &AlertWebhookHookRecord,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        map_store_validation(validate_alert_webhook_hook_record(hook))?;
        let created_at = parse_postgres_timestamp(&hook.created_at, "alert hook created_at")?;
        let updated_at = parse_postgres_timestamp(&hook.updated_at, "alert hook updated_at")?;
        let host_allow = AlertHostAllowPayloadV1::new(hook.host_allow.clone())
            .map_err(PostgresError::InvalidInput)?;
        let params_hash = alert_webhook_hook_hash(hook);
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        if native_audit_replay_tx(
            &mut tx,
            &hook.hook_id,
            "alert.hook.add_webhook",
            actor,
            &params_hash,
        )? {
            tx.commit()?;
            return Ok(());
        }
        tx.execute(
            "INSERT INTO ocfleet_native.alert_hooks
             (hook_id, name, hook_type, endpoint_url, endpoint_url_redacted,
              endpoint_host, host_allow_json, hmac_key_id, enabled, max_attempts,
              timeout_ms, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,CAST($7 AS text)::jsonb,$8,$9,$10,$11,$12,$13)",
            &[
                &hook.hook_id,
                &hook.name,
                &hook.hook_type,
                &hook.endpoint_url,
                &hook.endpoint_url_redacted,
                &hook.endpoint_host,
                &host_allow.to_value().to_string(),
                &hook.hmac_key_id,
                &hook.enabled,
                &checked_i64(hook.max_attempts, "alert max_attempts")?,
                &checked_i64(hook.timeout_ms, "alert timeout_ms")?,
                &created_at,
                &updated_at,
            ],
        )?;
        let mut event = AuditEvent::new(actor, "alert.hook.add_webhook");
        event.ok = Some(true);
        event.request_id = Some(hook.hook_id.clone());
        event.params_hash = Some(params_hash);
        event.detail_json = json!({
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
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_alert_webhook_hooks(&self) -> Result<Vec<AlertWebhookHookRecord>, PostgresError> {
        let mut conn = self.connection()?;
        conn.query(
            "SELECT hook_id, name, hook_type, endpoint_url, endpoint_url_redacted,
                    endpoint_host, host_allow_json::text, hmac_key_id, enabled,
                    max_attempts, timeout_ms, created_at, updated_at
             FROM ocfleet_native.alert_hooks WHERE hook_type = 'webhook'
             ORDER BY name, hook_id LIMIT 1001",
            &[],
        )?
        .iter()
        .map(alert_hook_from_postgres_row)
        .collect::<Result<Vec<_>, _>>()
        .and_then(|rows| {
            if rows.len() > 1_000 {
                Err(PostgresError::InvalidState(
                    "native alert hook list exceeds 1000 rows".into(),
                ))
            } else {
                Ok(rows)
            }
        })
    }

    pub fn get_alert_webhook_hook(
        &self,
        hook_id: &str,
    ) -> Result<Option<AlertWebhookHookRecord>, PostgresError> {
        validate_native_id("alert hook_id", hook_id, 128)?;
        let mut conn = self.connection()?;
        conn.query_opt(
            "SELECT hook_id, name, hook_type, endpoint_url, endpoint_url_redacted,
                    endpoint_host, host_allow_json::text, hmac_key_id, enabled,
                    max_attempts, timeout_ms, created_at, updated_at
             FROM ocfleet_native.alert_hooks
             WHERE hook_id = $1 AND hook_type = 'webhook'",
            &[&hook_id],
        )?
        .as_ref()
        .map(alert_hook_from_postgres_row)
        .transpose()
    }

    pub fn write_alert_webhook_hook_enabled(
        &self,
        hook_id: &str,
        enabled: bool,
        updated_at: &str,
        actor: &str,
    ) -> Result<bool, PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        validate_native_id("alert hook_id", hook_id, 128)?;
        let updated_at_value = parse_postgres_timestamp(updated_at, "alert hook updated_at")?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let current = tx.query_opt(
            "SELECT enabled FROM ocfleet_native.alert_hooks
             WHERE hook_id = $1 AND hook_type = 'webhook' FOR UPDATE",
            &[&hook_id],
        )?;
        let Some(current) = current else {
            return Err(PostgresError::InvalidInput(
                "alert webhook hook does not exist".into(),
            ));
        };
        let current: bool = current.try_get(0)?;
        if current == enabled {
            tx.commit()?;
            return Ok(false);
        }
        tx.execute(
            "UPDATE ocfleet_native.alert_hooks SET enabled = $2, updated_at = $3
             WHERE hook_id = $1 AND enabled = $4",
            &[&hook_id, &enabled, &updated_at_value, &current],
        )?;
        let event_name = if enabled {
            "alert.hook.enable"
        } else {
            "alert.hook.disable"
        };
        let mut event = AuditEvent::new(actor, event_name);
        event.ok = Some(true);
        event.request_id = Some(format!("{event_name}:{hook_id}:{updated_at}"));
        event.params_hash = Some(
            blake3::hash(format!("{hook_id}:{enabled}:{updated_at}").as_bytes())
                .to_hex()
                .to_string(),
        );
        event.detail_json = json!({
            "actor_type": "user",
            "target_type": "alert_webhook_hook",
            "target_id": hook_id,
            "enabled": enabled,
            "reason": Value::Null,
        });
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(true)
    }

    pub fn write_alert_delivery_attempt(
        &self,
        write: &AlertDeliveryAttemptWrite,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        map_store_validation(validate_alert_delivery_attempt_record(&write.attempt))?;
        let params_hash = alert_delivery_attempt_hash(&write.attempt);
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        if native_audit_replay_tx(
            &mut tx,
            &write.attempt.attempt_id,
            "alert.delivery.attempt",
            actor,
            &params_hash,
        )? {
            tx.commit()?;
            return Ok(());
        }
        insert_alert_delivery_attempt_postgres_tx(&mut tx, &write.attempt)?;
        insert_alert_attempt_audit_postgres_tx(&mut tx, &write.attempt, actor, &params_hash)?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_alert_delivery_attempts(
        &self,
        limit: u64,
    ) -> Result<Vec<AlertDeliveryAttemptRecord>, PostgresError> {
        let limit = checked_query_limit(limit)?;
        let mut conn = self.connection()?;
        conn.query(
            "SELECT attempt_id, alert_id, hook_id, attempt_no, attempted_at, status,
                    http_status_class, error_code, bytes_sent, detail_json::text
             FROM ocfleet_native.alert_delivery_attempts
             ORDER BY attempted_at DESC, attempt_id LIMIT $1",
            &[&limit],
        )?
        .iter()
        .map(alert_attempt_from_postgres_row)
        .collect()
    }

    pub fn write_alert_delivery_queue_enqueue(
        &self,
        enqueue: &AlertDeliveryQueueEnqueue,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        map_store_validation(validate_alert_delivery_queue_enqueue(enqueue))?;
        let enqueued_at = parse_postgres_timestamp(&enqueue.enqueued_at, "delivery enqueued_at")?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        lock_native_operation_tx(&mut tx, &enqueue.idempotency_key)?;
        let existing = tx.query_opt(
            "SELECT queue_id, alert_id, hook_id, idempotency_key, group_key
             FROM ocfleet_native.alert_delivery_queue
             WHERE queue_id = $1 OR idempotency_key = $2 FOR UPDATE",
            &[&enqueue.queue_id, &enqueue.idempotency_key],
        )?;
        if let Some(existing) = existing {
            let matches = existing.try_get::<_, String>(0)? == enqueue.queue_id
                && existing.try_get::<_, String>(1)? == enqueue.alert_id
                && existing.try_get::<_, String>(2)? == enqueue.hook_id
                && existing.try_get::<_, String>(3)? == enqueue.idempotency_key
                && existing.try_get::<_, String>(4)? == enqueue.group_key;
            if matches
                && native_audit_actor_matches_tx(
                    &mut tx,
                    &enqueue.queue_id,
                    "alert.delivery.queue.enqueue",
                    actor,
                )?
            {
                tx.commit()?;
                return Ok(());
            }
            return Err(alert_mutation_conflict(
                &enqueue.queue_id,
                "delivery queue identity, idempotency key, or audit provenance is already bound",
            ));
        }
        let hook_ok = tx
            .query_opt(
                "SELECT 1 FROM ocfleet_native.alert_hooks
             WHERE hook_id = $1 AND hook_type = 'webhook' AND enabled FOR SHARE",
                &[&enqueue.hook_id],
            )?
            .is_some();
        if !hook_ok {
            return Err(PostgresError::InvalidInput(
                "delivery queue hook is missing, disabled, or not a webhook".into(),
            ));
        }
        let alert_ok = tx
            .query_opt(
                "SELECT 1 FROM ocfleet_native.alert_events
             WHERE alert_id = $1 AND state = 'open' FOR SHARE",
                &[&enqueue.alert_id],
            )?
            .is_some();
        if !alert_ok {
            return Err(PostgresError::InvalidInput(
                "delivery queue alert is missing or is not open".into(),
            ));
        }
        tx.execute(
            "INSERT INTO ocfleet_native.alert_delivery_queue
             (queue_id, alert_id, hook_id, idempotency_key, group_key, status,
              next_attempt_at, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,'pending',$6,$6,$6)",
            &[
                &enqueue.queue_id,
                &enqueue.alert_id,
                &enqueue.hook_id,
                &enqueue.idempotency_key,
                &enqueue.group_key,
                &enqueued_at,
            ],
        )?;
        insert_alert_queue_audit_postgres_tx(
            &mut tx,
            actor,
            "alert.delivery.queue.enqueue",
            &enqueue.queue_id,
            true,
            None,
            json!({
                "queue_id": enqueue.queue_id,
                "hook_id": enqueue.hook_id,
                "alert_id": enqueue.alert_id,
                "group_key": enqueue.group_key,
                "state": "pending",
            }),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn alert_delivery_queue_health(
        &self,
        now: &str,
    ) -> Result<AlertDeliveryQueueHealth, PostgresError> {
        parse_postgres_timestamp(now, "delivery health timestamp")?;
        let mut conn = self.connection()?;
        let row = conn.query_one(
            "SELECT
               COUNT(*) FILTER (WHERE status = 'pending'),
               COUNT(*) FILTER (WHERE status = 'claimed'),
               COUNT(*) FILTER (WHERE status = 'retry'),
               COUNT(*) FILTER (WHERE status = 'dead_letter'),
               COUNT(*) FILTER (WHERE status = 'succeeded'),
               COUNT(*) FILTER (
                 WHERE status IN ('pending', 'retry') AND next_attempt_at <= clock_timestamp()
               ),
               COUNT(*) FILTER (
                 WHERE status = 'claimed' AND lease_expires_at <= clock_timestamp()
               ),
               MIN(next_attempt_at) FILTER (WHERE status IN ('pending', 'retry')),
               (SELECT MAX(attempted_at) FROM ocfleet_native.alert_delivery_attempts)
             FROM ocfleet_native.alert_delivery_queue",
            &[],
        )?;
        Ok(AlertDeliveryQueueHealth {
            pending: checked_u64(row.try_get(0)?, "delivery pending count")?,
            claimed: checked_u64(row.try_get(1)?, "delivery claimed count")?,
            retry: checked_u64(row.try_get(2)?, "delivery retry count")?,
            dead_letter: checked_u64(row.try_get(3)?, "delivery dead-letter count")?,
            succeeded: checked_u64(row.try_get(4)?, "delivery succeeded count")?,
            due: checked_u64(row.try_get(5)?, "delivery due count")?,
            expired_claims: checked_u64(row.try_get(6)?, "delivery expired count")?,
            oldest_due_at: row
                .try_get::<_, Option<OffsetDateTime>>(7)?
                .map(|value| format_postgres_timestamp(value, "delivery oldest due"))
                .transpose()?,
            last_attempt_at: row
                .try_get::<_, Option<OffsetDateTime>>(8)?
                .map(|value| format_postgres_timestamp(value, "delivery last attempt"))
                .transpose()?,
        })
    }

    pub fn write_alert_delivery_queue_claim_next(
        &self,
        owner_id: &str,
        now: &str,
        lease_seconds: u64,
        actor: &str,
    ) -> Result<Option<AlertDeliveryQueueClaim>, PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        map_store_validation(validate_alert_delivery_queue_claim_input(
            owner_id,
            now,
            lease_seconds,
        ))?;
        let lease_seconds = f64::from(
            u32::try_from(lease_seconds)
                .map_err(|_| PostgresError::InvalidInput("delivery lease exceeds u32".into()))?,
        );
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        recover_expired_alert_claims_postgres_tx(&mut tx, actor)?;
        let row = tx.query_opt(
            "SELECT queue_id FROM ocfleet_native.alert_delivery_queue
             WHERE status IN ('pending', 'retry') AND next_attempt_at <= clock_timestamp()
             ORDER BY next_attempt_at, queue_id LIMIT 1 FOR UPDATE SKIP LOCKED",
            &[],
        )?;
        let Some(row) = row else {
            tx.commit()?;
            return Ok(None);
        };
        let queue_id: String = row.try_get(0)?;
        let row = tx.query_one(
            "UPDATE ocfleet_native.alert_delivery_queue
             SET status = 'claimed', owner_id = $2, owner_actor = $3,
                 fence_token = fence_token + 1, claimed_at = clock_timestamp(),
                 lease_expires_at = clock_timestamp() + make_interval(secs => $4),
                 updated_at = clock_timestamp()
             WHERE queue_id = $1 AND status IN ('pending', 'retry')
             RETURNING queue_id, alert_id, hook_id, idempotency_key, group_key,
                       attempt_count, owner_id, fence_token, claimed_at, lease_expires_at",
            &[&queue_id, &owner_id, &actor, &lease_seconds],
        )?;
        let claim = alert_queue_claim_from_postgres_row(&row)?;
        insert_alert_queue_audit_postgres_tx(
            &mut tx,
            actor,
            "alert.delivery.queue.claim",
            &claim.queue_id,
            true,
            None,
            alert_queue_claim_audit_json_native(&claim, "claimed"),
        )?;
        tx.commit()?;
        Ok(Some(claim))
    }

    pub fn write_alert_delivery_queue_renew(
        &self,
        claim: &AlertDeliveryQueueClaim,
        now: &str,
        lease_seconds: u64,
        actor: &str,
    ) -> Result<AlertDeliveryQueueClaim, PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        map_store_validation(validate_alert_delivery_queue_claim(claim))?;
        map_store_validation(validate_alert_delivery_queue_claim_input(
            &claim.owner_id,
            now,
            lease_seconds,
        ))?;
        let lease_seconds = f64::from(
            u32::try_from(lease_seconds)
                .map_err(|_| PostgresError::InvalidInput("delivery lease exceeds u32".into()))?,
        );
        let fence_token = checked_i64(claim.fence_token, "delivery fence_token")?;
        let claimed_at = parse_postgres_timestamp(&claim.claimed_at, "delivery claimed_at")?;
        let expected_lease =
            parse_postgres_timestamp(&claim.lease_expires_at, "delivery lease_expires_at")?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let row = tx.query_opt(
            "UPDATE ocfleet_native.alert_delivery_queue
             SET lease_expires_at = clock_timestamp() + make_interval(secs => $5),
                 updated_at = clock_timestamp()
             WHERE queue_id = $1 AND status = 'claimed' AND owner_id = $2
               AND owner_actor = $3 AND fence_token = $4
               AND alert_id = $6 AND hook_id = $7 AND idempotency_key = $8
               AND group_key = $9 AND attempt_count = $10
               AND claimed_at = $11 AND lease_expires_at = $12
               AND lease_expires_at > clock_timestamp()
             RETURNING queue_id, alert_id, hook_id, idempotency_key, group_key,
                       attempt_count, owner_id, fence_token, claimed_at, lease_expires_at",
            &[
                &claim.queue_id,
                &claim.owner_id,
                &actor,
                &fence_token,
                &lease_seconds,
                &claim.alert_id,
                &claim.hook_id,
                &claim.idempotency_key,
                &claim.group_key,
                &checked_i64(claim.attempt_count, "delivery attempt_count")?,
                &claimed_at,
                &expected_lease,
            ],
        )?;
        let Some(row) = row else {
            return Err(alert_mutation_conflict(
                &claim.queue_id,
                "delivery queue lease, owner actor, or fence was lost",
            ));
        };
        let renewed = alert_queue_claim_from_postgres_row(&row)?;
        insert_alert_queue_audit_postgres_tx(
            &mut tx,
            actor,
            "alert.delivery.queue.renew",
            &claim.queue_id,
            true,
            None,
            alert_queue_claim_audit_json_native(&renewed, "renewed"),
        )?;
        tx.commit()?;
        Ok(renewed)
    }

    pub fn write_alert_delivery_queue_outcome(
        &self,
        outcome: &AlertDeliveryQueueOutcome,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        map_store_validation(validate_alert_delivery_queue_outcome(outcome))?;
        let completed_at =
            parse_postgres_timestamp(&outcome.completed_at, "delivery completed_at")?;
        let retry_at = parse_optional_postgres_timestamp(&outcome.retry_at, "delivery retry_at")?;
        let fence_token = checked_i64(outcome.claim.fence_token, "delivery fence_token")?;
        let claimed_at =
            parse_postgres_timestamp(&outcome.claim.claimed_at, "delivery claimed_at")?;
        let expected_lease =
            parse_postgres_timestamp(&outcome.claim.lease_expires_at, "delivery lease_expires_at")?;
        let next_attempt = outcome.claim.attempt_count + 1;
        let next_attempt_count = checked_i64(next_attempt, "delivery attempt_count")?;
        let succeeded = outcome.attempt.status == "succeeded";
        let should_retry = !succeeded && outcome.retryable && next_attempt < outcome.max_attempts;
        let status = if succeeded {
            "succeeded"
        } else if should_retry {
            "retry"
        } else {
            "dead_letter"
        };
        let next_attempt_at = retry_at.unwrap_or(completed_at);
        let delivered_at = succeeded.then_some(completed_at);
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        lock_live_alert_queue_claim_postgres_tx(&mut tx, &outcome.claim, actor)?;
        insert_alert_delivery_attempt_postgres_tx(&mut tx, &outcome.attempt)?;
        if succeeded
            && tx.execute(
                "UPDATE ocfleet_native.alert_events SET last_sent_at = $2 WHERE alert_id = $1",
                &[&outcome.claim.alert_id, &completed_at],
            )? != 1
        {
            return Err(alert_mutation_conflict(
                &outcome.claim.queue_id,
                "delivery alert disappeared before success finalization",
            ));
        }
        insert_alert_queue_audit_postgres_tx(
            &mut tx,
            actor,
            "alert.delivery.queue.outcome",
            &outcome.claim.queue_id,
            succeeded,
            outcome.attempt.error_code.as_deref(),
            json!({
                "queue_id": outcome.claim.queue_id,
                "hook_id": outcome.claim.hook_id,
                "alert_id": outcome.claim.alert_id,
                "attempt_no": next_attempt,
                "state": status,
                "next_attempt_at": if should_retry {
                    outcome.retry_at.as_deref()
                } else {
                    None
                },
            }),
        )?;
        let changed = tx.execute(
            "UPDATE ocfleet_native.alert_delivery_queue
             SET status = $6, attempt_count = $7, next_attempt_at = $8,
                 owner_id = NULL, owner_actor = NULL, claimed_at = NULL,
                 lease_expires_at = NULL, last_error_code = $9,
                 updated_at = $5, delivered_at = $10
             WHERE queue_id = $1 AND status = 'claimed' AND owner_id = $2
               AND owner_actor = $3 AND fence_token = $4
               AND alert_id = $11 AND hook_id = $12 AND idempotency_key = $13
               AND group_key = $14 AND attempt_count = $15
               AND claimed_at = $16 AND lease_expires_at = $17
               AND lease_expires_at > clock_timestamp()",
            &[
                &outcome.claim.queue_id,
                &outcome.claim.owner_id,
                &actor,
                &fence_token,
                &completed_at,
                &status,
                &next_attempt_count,
                &next_attempt_at,
                &outcome.attempt.error_code,
                &delivered_at,
                &outcome.claim.alert_id,
                &outcome.claim.hook_id,
                &outcome.claim.idempotency_key,
                &outcome.claim.group_key,
                &checked_i64(outcome.claim.attempt_count, "delivery attempt_count")?,
                &claimed_at,
                &expected_lease,
            ],
        )?;
        if changed != 1 {
            return Err(alert_mutation_conflict(
                &outcome.claim.queue_id,
                "delivery queue lease, owner actor, or fence was lost before outcome",
            ));
        }
        tx.commit()?;
        Ok(())
    }

    pub fn write_alert_delivery_queue_defer(
        &self,
        claim: &AlertDeliveryQueueClaim,
        deferred_at: &str,
        next_attempt_at: &str,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        map_store_validation(validate_alert_delivery_queue_claim(claim))?;
        let deferred_at = parse_postgres_timestamp(deferred_at, "delivery deferred_at")?;
        let next_attempt_at =
            parse_postgres_timestamp(next_attempt_at, "delivery next_attempt_at")?;
        if next_attempt_at <= deferred_at
            || next_attempt_at - deferred_at > time::Duration::hours(1)
        {
            return Err(PostgresError::InvalidInput(
                "delivery defer must be within one hour after deferral".into(),
            ));
        }
        let fence_token = checked_i64(claim.fence_token, "delivery fence_token")?;
        let claimed_at = parse_postgres_timestamp(&claim.claimed_at, "delivery claimed_at")?;
        let expected_lease =
            parse_postgres_timestamp(&claim.lease_expires_at, "delivery lease_expires_at")?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE ocfleet_native.alert_delivery_queue
             SET status = 'retry', owner_id = NULL, owner_actor = NULL,
                 claimed_at = NULL, lease_expires_at = NULL,
                 next_attempt_at = $5, updated_at = $4
             WHERE queue_id = $1 AND status = 'claimed' AND owner_id = $2
               AND owner_actor = $3 AND fence_token = $6
               AND alert_id = $7 AND hook_id = $8 AND idempotency_key = $9
               AND group_key = $10 AND attempt_count = $11
               AND claimed_at = $12 AND lease_expires_at = $13
               AND lease_expires_at > clock_timestamp()",
            &[
                &claim.queue_id,
                &claim.owner_id,
                &actor,
                &deferred_at,
                &next_attempt_at,
                &fence_token,
                &claim.alert_id,
                &claim.hook_id,
                &claim.idempotency_key,
                &claim.group_key,
                &checked_i64(claim.attempt_count, "delivery attempt_count")?,
                &claimed_at,
                &expected_lease,
            ],
        )?;
        if changed != 1 {
            return Err(alert_mutation_conflict(
                &claim.queue_id,
                "delivery queue lease, owner actor, or fence was lost before deferral",
            ));
        }
        insert_alert_queue_audit_postgres_tx(
            &mut tx,
            actor,
            "alert.delivery.queue.defer",
            &claim.queue_id,
            true,
            None,
            json!({
                "queue_id": claim.queue_id,
                "hook_id": claim.hook_id,
                "group_key": claim.group_key,
                "state": "retry",
                "next_attempt_at": format_postgres_timestamp(
                    next_attempt_at,
                    "delivery next_attempt_at",
                )?,
            }),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn write_alert_delivery_finalize(
        &self,
        write: &AlertDeliveryFinalizeWrite,
        actor: &str,
    ) -> Result<(), PostgresError> {
        validate_actor(actor).map_err(PostgresError::InvalidInput)?;
        map_store_validation(validate_alert_delivery_finalize(write))?;
        let params_hash = alert_delivery_finalize_hash(write);
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        if native_audit_replay_tx(
            &mut tx,
            &write.delivery_id,
            "alert.delivery",
            actor,
            &params_hash,
        )? {
            tx.commit()?;
            return Ok(());
        }
        for entry in &write.entries {
            let before = entry.before.as_ref().expect("validated delivery entry");
            let current = get_alert_event_postgres_tx(&mut tx, &before.dedupe_key, true)?;
            if !optional_alerts_equivalent(current.as_ref(), Some(before))? {
                return Err(alert_mutation_conflict(
                    &write.delivery_id,
                    "alert state changed before delivery finalization",
                ));
            }
            upsert_alert_event_postgres_tx(&mut tx, &entry.after)?;
        }
        let mut event = AuditEvent::new(actor, "alert.delivery");
        event.ok = Some(write.ok);
        event.request_id = Some(write.delivery_id.clone());
        event.params_hash = Some(params_hash);
        event.detail_json = json!({
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
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(())
    }
}

fn canonical_alert_detail_native(value: &Value) -> Result<AlertDetailPayloadV1, PostgresError> {
    AlertDetailPayloadV1::from_value(value)
        .or_else(|_| AlertDetailPayloadV1::from_legacy(value))
        .map_err(PostgresError::InvalidInput)
}

fn alert_event_from_postgres_row(row: &postgres::Row) -> Result<AlertEventRecord, PostgresError> {
    let detail: String = row.try_get(10)?;
    let detail: Value = serde_json::from_str(&detail)
        .map_err(|_| PostgresError::InvalidState("native alert detail JSON is invalid".into()))?;
    let detail = AlertDetailPayloadV1::from_value(&detail)
        .map_err(PostgresError::InvalidState)?
        .public_detail();
    Ok(AlertEventRecord {
        alert_id: row.try_get(0)?,
        dedupe_key: row.try_get(1)?,
        node_id: row.try_get(2)?,
        severity: row.try_get(3)?,
        state: row.try_get(4)?,
        reason_code: row.try_get(5)?,
        first_seen_at: format_postgres_timestamp(row.try_get(6)?, "alert first_seen_at")?,
        last_seen_at: format_postgres_timestamp(row.try_get(7)?, "alert last_seen_at")?,
        last_sent_at: row
            .try_get::<_, Option<OffsetDateTime>>(8)?
            .map(|value| format_postgres_timestamp(value, "alert last_sent_at"))
            .transpose()?,
        resolved_at: row
            .try_get::<_, Option<OffsetDateTime>>(9)?
            .map(|value| format_postgres_timestamp(value, "alert resolved_at"))
            .transpose()?,
        detail_json: detail,
    })
}

fn get_alert_event_postgres_tx(
    tx: &mut Transaction<'_>,
    dedupe_key: &str,
    lock: bool,
) -> Result<Option<AlertEventRecord>, PostgresError> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    let sql = format!(
        "SELECT alert_id, dedupe_key, node_id, severity, state, reason_code,
                first_seen_at, last_seen_at, last_sent_at, resolved_at, detail_json::text
         FROM ocfleet_native.alert_events WHERE dedupe_key = $1{suffix}"
    );
    tx.query_opt(&sql, &[&dedupe_key])?
        .as_ref()
        .map(alert_event_from_postgres_row)
        .transpose()
}

fn upsert_alert_event_postgres_tx(
    tx: &mut Transaction<'_>,
    alert: &AlertEventRecord,
) -> Result<(), PostgresError> {
    let detail = canonical_alert_detail_native(&alert.detail_json)?;
    let first_seen_at = parse_postgres_timestamp(&alert.first_seen_at, "alert first_seen_at")?;
    let last_seen_at = parse_postgres_timestamp(&alert.last_seen_at, "alert last_seen_at")?;
    let last_sent_at =
        parse_optional_postgres_timestamp(&alert.last_sent_at, "alert last_sent_at")?;
    let resolved_at = parse_optional_postgres_timestamp(&alert.resolved_at, "alert resolved_at")?;
    tx.execute(
        "INSERT INTO ocfleet_native.alert_events
         (alert_id, dedupe_key, node_id, severity, state, reason_code, first_seen_at,
          last_seen_at, last_sent_at, resolved_at, detail_json)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,CAST($11 AS text)::jsonb)
         ON CONFLICT (dedupe_key) DO UPDATE SET
           alert_id = EXCLUDED.alert_id, node_id = EXCLUDED.node_id,
           severity = EXCLUDED.severity, state = EXCLUDED.state,
           reason_code = EXCLUDED.reason_code, first_seen_at = EXCLUDED.first_seen_at,
           last_seen_at = EXCLUDED.last_seen_at, last_sent_at = EXCLUDED.last_sent_at,
           resolved_at = EXCLUDED.resolved_at, detail_json = EXCLUDED.detail_json",
        &[
            &alert.alert_id,
            &alert.dedupe_key,
            &alert.node_id,
            &alert.severity,
            &alert.state,
            &alert.reason_code,
            &first_seen_at,
            &last_seen_at,
            &last_sent_at,
            &resolved_at,
            &detail.to_value().to_string(),
        ],
    )?;
    Ok(())
}

fn optional_alerts_equivalent(
    left: Option<&AlertEventRecord>,
    right: Option<&AlertEventRecord>,
) -> Result<bool, PostgresError> {
    match (left, right) {
        (None, None) => Ok(true),
        (Some(left), Some(right)) => {
            let left_detail = canonical_alert_detail_native(&left.detail_json)?.public_detail();
            let right_detail = canonical_alert_detail_native(&right.detail_json)?.public_detail();
            Ok(left.alert_id == right.alert_id
                && left.dedupe_key == right.dedupe_key
                && left.node_id == right.node_id
                && left.severity == right.severity
                && left.state == right.state
                && left.reason_code == right.reason_code
                && postgres_timestamps_equal(&left.first_seen_at, &right.first_seen_at)
                && postgres_timestamps_equal(&left.last_seen_at, &right.last_seen_at)
                && optional_postgres_timestamps_equal(
                    left.last_sent_at.as_deref(),
                    right.last_sent_at.as_deref(),
                )
                && optional_postgres_timestamps_equal(
                    left.resolved_at.as_deref(),
                    right.resolved_at.as_deref(),
                )
                && left_detail == right_detail)
        }
        _ => Ok(false),
    }
}

fn optional_postgres_timestamps_equal(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => postgres_timestamps_equal(left, right),
        _ => false,
    }
}

fn alert_hook_from_postgres_row(
    row: &postgres::Row,
) -> Result<AlertWebhookHookRecord, PostgresError> {
    let host_allow: String = row.try_get(6)?;
    let host_allow: Value = serde_json::from_str(&host_allow).map_err(|_| {
        PostgresError::InvalidState("native alert hook allowlist JSON is invalid".into())
    })?;
    let host_allow =
        AlertHostAllowPayloadV1::from_value(&host_allow).map_err(PostgresError::InvalidState)?;
    let endpoint_host: String = row.try_get(5)?;
    host_allow
        .validate_relationship(&endpoint_host)
        .map_err(PostgresError::InvalidState)?;
    Ok(AlertWebhookHookRecord {
        hook_id: row.try_get(0)?,
        name: row.try_get(1)?,
        hook_type: row.try_get(2)?,
        endpoint_url: row.try_get(3)?,
        endpoint_url_redacted: row.try_get(4)?,
        endpoint_host,
        host_allow: host_allow.hosts,
        hmac_key_id: row.try_get(7)?,
        enabled: row.try_get(8)?,
        max_attempts: checked_u64(row.try_get(9)?, "alert max_attempts")?,
        timeout_ms: checked_u64(row.try_get(10)?, "alert timeout_ms")?,
        created_at: format_postgres_timestamp(row.try_get(11)?, "alert hook created_at")?,
        updated_at: format_postgres_timestamp(row.try_get(12)?, "alert hook updated_at")?,
    })
}

fn insert_alert_delivery_attempt_postgres_tx(
    tx: &mut Transaction<'_>,
    attempt: &AlertDeliveryAttemptRecord,
) -> Result<(), PostgresError> {
    let attempted_at = parse_postgres_timestamp(&attempt.attempted_at, "alert attempted_at")?;
    let detail = delivery_attempt_detail_payload(attempt).map_err(PostgresError::from)?;
    tx.execute(
        "INSERT INTO ocfleet_native.alert_delivery_attempts
         (attempt_id, alert_id, hook_id, attempt_no, attempted_at, status,
          http_status_class, error_code, bytes_sent, detail_json)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,CAST($10 AS text)::jsonb)",
        &[
            &attempt.attempt_id,
            &attempt.alert_id,
            &attempt.hook_id,
            &checked_i64(attempt.attempt_no, "delivery attempt_no")?,
            &attempted_at,
            &attempt.status,
            &attempt.http_status_class,
            &attempt.error_code,
            &checked_i64(attempt.bytes_sent, "delivery bytes_sent")?,
            &detail.to_value().to_string(),
        ],
    )?;
    Ok(())
}

fn alert_attempt_from_postgres_row(
    row: &postgres::Row,
) -> Result<AlertDeliveryAttemptRecord, PostgresError> {
    let record = AlertDeliveryAttemptRecord {
        attempt_id: row.try_get(0)?,
        alert_id: row.try_get(1)?,
        hook_id: row.try_get(2)?,
        attempt_no: checked_u64(row.try_get(3)?, "delivery attempt_no")?,
        attempted_at: format_postgres_timestamp(row.try_get(4)?, "delivery attempted_at")?,
        status: row.try_get(5)?,
        http_status_class: row.try_get(6)?,
        error_code: row.try_get(7)?,
        bytes_sent: checked_u64(row.try_get(8)?, "delivery bytes_sent")?,
    };
    let detail: String = row.try_get(9)?;
    let detail: Value = serde_json::from_str(&detail).map_err(|_| {
        PostgresError::InvalidState("native delivery attempt detail JSON is invalid".into())
    })?;
    let stored = crate::storage_payloads::DeliveryAttemptDetailPayloadV1::from_value(&detail)
        .map_err(PostgresError::InvalidState)?;
    let expected = delivery_attempt_detail_payload(&record).map_err(PostgresError::from)?;
    if stored != expected {
        return Err(PostgresError::InvalidState(
            "native delivery attempt detail is inconsistent with relational columns".into(),
        ));
    }
    Ok(record)
}

fn insert_alert_attempt_audit_postgres_tx(
    tx: &mut Transaction<'_>,
    attempt: &AlertDeliveryAttemptRecord,
    actor: &str,
    params_hash: &str,
) -> Result<(), PostgresError> {
    let mut event = AuditEvent::new(actor, "alert.delivery.attempt");
    event.ok = Some(attempt.status != "failed");
    event.request_id = Some(attempt.attempt_id.clone());
    event.params_hash = Some(params_hash.to_string());
    event.detail_json = json!({
        "actor_type": "user",
        "target_type": "alert_delivery_attempt",
        "target_id": attempt.attempt_id,
        "alert_id": attempt.alert_id,
        "hook_id": attempt.hook_id,
        "attempt_no": attempt.attempt_no,
        "status": attempt.status,
        "http_status_class": attempt.http_status_class,
        "error_code": attempt.error_code,
        "bytes_sent": attempt.bytes_sent,
        "reason": Value::Null,
    });
    insert_audit(tx, &event)
}

fn recover_expired_alert_claims_postgres_tx(
    tx: &mut Transaction<'_>,
    actor: &str,
) -> Result<(), PostgresError> {
    let rows = tx.query(
        "UPDATE ocfleet_native.alert_delivery_queue
         SET status = 'retry', owner_id = NULL, owner_actor = NULL,
             claimed_at = NULL, lease_expires_at = NULL,
             next_attempt_at = clock_timestamp(), updated_at = clock_timestamp(),
             last_error_code = 'DELIVERY_CLAIM_EXPIRED'
         WHERE queue_id IN (
           SELECT queue_id FROM ocfleet_native.alert_delivery_queue
           WHERE status = 'claimed' AND lease_expires_at <= clock_timestamp()
           ORDER BY lease_expires_at, queue_id LIMIT 100 FOR UPDATE SKIP LOCKED
         )
         RETURNING queue_id, alert_id, hook_id, group_key",
        &[],
    )?;
    for row in rows {
        let queue_id: String = row.try_get(0)?;
        insert_alert_queue_audit_postgres_tx(
            tx,
            actor,
            "alert.delivery.queue.recover",
            &queue_id,
            false,
            Some("DELIVERY_CLAIM_EXPIRED"),
            json!({
                "queue_id": queue_id,
                "alert_id": row.try_get::<_, String>(1)?,
                "hook_id": row.try_get::<_, String>(2)?,
                "group_key": row.try_get::<_, String>(3)?,
                "state": "retry",
            }),
        )?;
    }
    Ok(())
}

fn lock_live_alert_queue_claim_postgres_tx(
    tx: &mut Transaction<'_>,
    claim: &AlertDeliveryQueueClaim,
    actor: &str,
) -> Result<(), PostgresError> {
    let fence_token = checked_i64(claim.fence_token, "delivery fence_token")?;
    let attempt_count = checked_i64(claim.attempt_count, "delivery attempt_count")?;
    let claimed_at = parse_postgres_timestamp(&claim.claimed_at, "delivery claimed_at")?;
    let lease_expires_at =
        parse_postgres_timestamp(&claim.lease_expires_at, "delivery lease_expires_at")?;
    let row = tx.query_opt(
        "SELECT 1 FROM ocfleet_native.alert_delivery_queue
         WHERE queue_id = $1 AND status = 'claimed' AND owner_id = $2
           AND owner_actor = $3 AND fence_token = $4
           AND alert_id = $5 AND hook_id = $6 AND idempotency_key = $7
           AND group_key = $8 AND attempt_count = $9
           AND claimed_at = $10 AND lease_expires_at = $11
           AND lease_expires_at > clock_timestamp()
         FOR UPDATE",
        &[
            &claim.queue_id,
            &claim.owner_id,
            &actor,
            &fence_token,
            &claim.alert_id,
            &claim.hook_id,
            &claim.idempotency_key,
            &claim.group_key,
            &attempt_count,
            &claimed_at,
            &lease_expires_at,
        ],
    )?;
    if row.is_none() {
        return Err(alert_mutation_conflict(
            &claim.queue_id,
            "delivery queue lease, owner actor, fence, or claim projection was lost",
        ));
    }
    Ok(())
}

fn alert_queue_claim_from_postgres_row(
    row: &postgres::Row,
) -> Result<AlertDeliveryQueueClaim, PostgresError> {
    let claim = AlertDeliveryQueueClaim {
        queue_id: row.try_get(0)?,
        alert_id: row.try_get(1)?,
        hook_id: row.try_get(2)?,
        idempotency_key: row.try_get(3)?,
        group_key: row.try_get(4)?,
        attempt_count: checked_u64(row.try_get(5)?, "delivery attempt_count")?,
        owner_id: row.try_get(6)?,
        fence_token: checked_u64(row.try_get(7)?, "delivery fence_token")?,
        claimed_at: format_postgres_timestamp(row.try_get(8)?, "delivery claimed_at")?,
        lease_expires_at: format_postgres_timestamp(row.try_get(9)?, "delivery lease_expires_at")?,
    };
    map_store_validation(validate_alert_delivery_queue_claim(&claim))?;
    Ok(claim)
}

fn alert_queue_claim_audit_json_native(claim: &AlertDeliveryQueueClaim, state: &str) -> Value {
    json!({
        "queue_id": claim.queue_id,
        "hook_id": claim.hook_id,
        "alert_id": claim.alert_id,
        "group_key": claim.group_key,
        "owner_id": claim.owner_id,
        "generation": claim.fence_token,
        "attempt_no": claim.attempt_count + 1,
        "claimed_at": claim.claimed_at,
        "lease_expires_at": claim.lease_expires_at,
        "state": state,
    })
}

fn insert_alert_queue_audit_postgres_tx(
    tx: &mut Transaction<'_>,
    actor: &str,
    event_name: &str,
    queue_id: &str,
    ok: bool,
    error_code: Option<&str>,
    detail: Value,
) -> Result<(), PostgresError> {
    let mut event = AuditEvent::new(actor, event_name);
    event.ok = Some(ok);
    event.request_id = Some(queue_id.to_string());
    event.error_code = error_code.map(str::to_string);
    event.detail_json = detail;
    insert_audit(tx, &event)
}

fn alert_evaluation_conflict(evaluation_id: &str, detail: &'static str) -> PostgresError {
    PostgresError::Store(StoreError::AlertEvaluationConflict {
        evaluation_id: evaluation_id.to_string(),
        detail,
    })
}

fn alert_mutation_conflict(operation_id: &str, detail: &'static str) -> PostgresError {
    PostgresError::Store(StoreError::AlertMutationConflict {
        operation_id: operation_id.to_string(),
        detail,
    })
}

fn health_policy_from_postgres_row(
    row: &postgres::Row,
) -> Result<HealthPolicyRecord, PostgresError> {
    Ok(HealthPolicyRecord {
        stale_window_seconds: checked_u64(row.try_get(0)?, "health stale window")?,
        unreachable_consecutive_failures: checked_u64(
            row.try_get(1)?,
            "health unreachable failures",
        )?,
        cert_warning_days: checked_u64(row.try_get(2)?, "health warning days")?,
        cert_critical_days: checked_u64(row.try_get(3)?, "health critical days")?,
        updated_at: row.try_get(4)?,
    })
}

fn health_policy_audit_json_native(policy: &HealthPolicyRecord) -> Value {
    json!({
        "stale_window_seconds": policy.stale_window_seconds,
        "unreachable_consecutive_failures": policy.unreachable_consecutive_failures,
        "cert_warning_days": policy.cert_warning_days,
        "cert_critical_days": policy.cert_critical_days,
    })
}

fn native_audit_replay_tx(
    tx: &mut Transaction<'_>,
    request_id: &str,
    event: &str,
    actor: &str,
    params_hash: &str,
) -> Result<bool, PostgresError> {
    lock_native_operation_tx(tx, request_id)?;
    let rows = tx.query(
        "SELECT event, actor, params_hash
         FROM ocfleet_native.controller_audit_log
         WHERE request_id = $1 ORDER BY id LIMIT 2 FOR SHARE",
        &[&request_id],
    )?;
    if rows.is_empty() {
        return Ok(false);
    }
    if rows.len() == 1
        && rows[0].try_get::<_, String>(0)? == event
        && rows[0].try_get::<_, String>(1)? == actor
        && rows[0].try_get::<_, Option<String>>(2)?.as_deref() == Some(params_hash)
    {
        return Ok(true);
    }
    Err(PostgresError::InvalidState(format!(
        "native audit replay provenance for {request_id} is mismatched or ambiguous"
    )))
}

fn lock_native_operation_tx(
    tx: &mut Transaction<'_>,
    operation_id: &str,
) -> Result<(), PostgresError> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, $2))",
        &[&operation_id, &OPERATION_LOCK_SALT],
    )?;
    Ok(())
}

fn native_audit_actor_matches_tx(
    tx: &mut Transaction<'_>,
    request_id: &str,
    event: &str,
    actor: &str,
) -> Result<bool, PostgresError> {
    let rows = tx.query(
        "SELECT actor FROM ocfleet_native.controller_audit_log
         WHERE request_id = $1 AND event = $2 ORDER BY id LIMIT 2 FOR SHARE",
        &[&request_id, &event],
    )?;
    Ok(rows.len() == 1 && rows[0].try_get::<_, String>(0)? == actor)
}

fn canonical_health_payloads(
    snapshot: &HealthSnapshotRecord,
) -> Result<(Value, Value), PostgresError> {
    let degraded = HealthDegradedMethodsPayloadV1::from_value(&snapshot.degraded_methods_json)
        .map_err(PostgresError::InvalidInput)?;
    let summary = HealthSummaryPayloadV1::from_value(&snapshot.summary_json)
        .map_err(PostgresError::InvalidInput)?;
    validate_health_payload_relationship(&snapshot.status, &summary)
        .map_err(PostgresError::InvalidInput)?;
    Ok((degraded.to_value(), summary.to_value()))
}

fn upsert_health_snapshot_postgres_tx(
    tx: &mut Transaction<'_>,
    snapshot: &HealthSnapshotRecord,
) -> Result<(), PostgresError> {
    let computed_at = parse_postgres_timestamp(&snapshot.computed_at, "health computed_at")?;
    let last_success_at =
        parse_optional_postgres_timestamp(&snapshot.last_success_at, "health last_success_at")?;
    let last_failure_at =
        parse_optional_postgres_timestamp(&snapshot.last_failure_at, "health last_failure_at")?;
    let freshness_seconds = snapshot
        .freshness_seconds
        .map(|value| checked_i64(value, "health freshness_seconds"))
        .transpose()?;
    let (degraded, summary) = canonical_health_payloads(snapshot)?;
    tx.execute(
        "INSERT INTO ocfleet_native.health_snapshots
         (node_id, endpoint_id, computed_at, status, freshness_seconds,
          last_success_at, last_failure_at, last_error_code,
          degraded_methods_json, summary_json)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                 CAST($9 AS text)::jsonb, CAST($10 AS text)::jsonb)
         ON CONFLICT (node_id) DO UPDATE SET
           endpoint_id = EXCLUDED.endpoint_id,
           computed_at = EXCLUDED.computed_at,
           status = EXCLUDED.status,
           freshness_seconds = EXCLUDED.freshness_seconds,
           last_success_at = EXCLUDED.last_success_at,
           last_failure_at = EXCLUDED.last_failure_at,
           last_error_code = EXCLUDED.last_error_code,
           degraded_methods_json = EXCLUDED.degraded_methods_json,
           summary_json = EXCLUDED.summary_json",
        &[
            &snapshot.node_id,
            &snapshot.endpoint_id,
            &computed_at,
            &snapshot.status,
            &freshness_seconds,
            &last_success_at,
            &last_failure_at,
            &snapshot.last_error_code,
            &degraded.to_string(),
            &summary.to_string(),
        ],
    )?;
    Ok(())
}

fn insert_health_history_postgres_tx(
    tx: &mut Transaction<'_>,
    evaluation_id: &str,
    snapshot: &HealthSnapshotRecord,
) -> Result<(), PostgresError> {
    let computed_at = parse_postgres_timestamp(&snapshot.computed_at, "health computed_at")?;
    let last_success_at =
        parse_optional_postgres_timestamp(&snapshot.last_success_at, "health last_success_at")?;
    let last_failure_at =
        parse_optional_postgres_timestamp(&snapshot.last_failure_at, "health last_failure_at")?;
    let freshness_seconds = snapshot
        .freshness_seconds
        .map(|value| checked_i64(value, "health freshness_seconds"))
        .transpose()?;
    let (degraded, summary) = canonical_health_payloads(snapshot)?;
    tx.execute(
        "INSERT INTO ocfleet_native.health_history
         (evaluation_id, node_id, endpoint_id, computed_at, status, freshness_seconds,
          last_success_at, last_failure_at, last_error_code,
          degraded_methods_json, summary_json)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                 CAST($10 AS text)::jsonb, CAST($11 AS text)::jsonb)",
        &[
            &evaluation_id,
            &snapshot.node_id,
            &snapshot.endpoint_id,
            &computed_at,
            &snapshot.status,
            &freshness_seconds,
            &last_success_at,
            &last_failure_at,
            &snapshot.last_error_code,
            &degraded.to_string(),
            &summary.to_string(),
        ],
    )?;
    Ok(())
}

fn health_snapshot_from_postgres_row(
    row: &postgres::Row,
) -> Result<HealthSnapshotRecord, PostgresError> {
    let degraded: String = row.try_get(8)?;
    let degraded: Value = serde_json::from_str(&degraded).map_err(|_| {
        PostgresError::InvalidState("native health degraded payload is invalid".into())
    })?;
    HealthDegradedMethodsPayloadV1::from_value(&degraded).map_err(PostgresError::InvalidState)?;
    let summary: String = row.try_get(9)?;
    let summary: Value = serde_json::from_str(&summary).map_err(|_| {
        PostgresError::InvalidState("native health summary payload is invalid".into())
    })?;
    let summary_payload =
        HealthSummaryPayloadV1::from_value(&summary).map_err(PostgresError::InvalidState)?;
    let status: String = row.try_get(3)?;
    validate_health_payload_relationship(&status, &summary_payload)
        .map_err(PostgresError::InvalidState)?;
    Ok(HealthSnapshotRecord {
        node_id: row.try_get(0)?,
        endpoint_id: row.try_get(1)?,
        computed_at: format_postgres_timestamp(row.try_get(2)?, "health computed_at")?,
        status,
        freshness_seconds: row
            .try_get::<_, Option<i64>>(4)?
            .map(|value| checked_u64(value, "health freshness_seconds"))
            .transpose()?,
        last_success_at: row
            .try_get::<_, Option<OffsetDateTime>>(5)?
            .map(|value| format_postgres_timestamp(value, "health last_success_at"))
            .transpose()?,
        last_failure_at: row
            .try_get::<_, Option<OffsetDateTime>>(6)?
            .map(|value| format_postgres_timestamp(value, "health last_failure_at"))
            .transpose()?,
        last_error_code: row.try_get(7)?,
        degraded_methods_json: degraded,
        summary_json: summary,
    })
}

fn health_history_from_postgres_row(
    row: &postgres::Row,
) -> Result<HealthHistoryRecord, PostgresError> {
    let degraded: String = row.try_get(9)?;
    let degraded: Value = serde_json::from_str(&degraded).map_err(|_| {
        PostgresError::InvalidState("native health degraded payload is invalid".into())
    })?;
    HealthDegradedMethodsPayloadV1::from_value(&degraded).map_err(PostgresError::InvalidState)?;
    let summary: String = row.try_get(10)?;
    let summary: Value = serde_json::from_str(&summary).map_err(|_| {
        PostgresError::InvalidState("native health summary payload is invalid".into())
    })?;
    let summary_payload =
        HealthSummaryPayloadV1::from_value(&summary).map_err(PostgresError::InvalidState)?;
    let status: String = row.try_get(4)?;
    validate_health_payload_relationship(&status, &summary_payload)
        .map_err(PostgresError::InvalidState)?;
    Ok(HealthHistoryRecord {
        evaluation_id: row.try_get(0)?,
        snapshot: HealthSnapshotRecord {
            node_id: row.try_get(1)?,
            endpoint_id: row.try_get(2)?,
            computed_at: format_postgres_timestamp(row.try_get(3)?, "health computed_at")?,
            status,
            freshness_seconds: row
                .try_get::<_, Option<i64>>(5)?
                .map(|value| checked_u64(value, "health freshness_seconds"))
                .transpose()?,
            last_success_at: row
                .try_get::<_, Option<OffsetDateTime>>(6)?
                .map(|value| format_postgres_timestamp(value, "health last_success_at"))
                .transpose()?,
            last_failure_at: row
                .try_get::<_, Option<OffsetDateTime>>(7)?
                .map(|value| format_postgres_timestamp(value, "health last_failure_at"))
                .transpose()?,
            last_error_code: row.try_get(8)?,
            degraded_methods_json: degraded,
            summary_json: summary,
        },
    })
}

fn upsert_health_rollup_postgres_tx(
    tx: &mut Transaction<'_>,
    row: &HealthRollupRecord,
) -> Result<(), PostgresError> {
    let bucket_seconds = checked_i64(row.bucket_seconds, "health bucket_seconds")?;
    let bucket_start = parse_postgres_timestamp(&row.bucket_start, "health bucket_start")?;
    let bucket_end = parse_postgres_timestamp(&row.bucket_end, "health bucket_end")?;
    let computed_at = parse_postgres_timestamp(&row.computed_at, "health computed_at")?;
    let counts = [
        row.health_samples,
        row.covered_slots,
        row.expected_slots,
        row.healthy_count,
        row.degraded_count,
        row.unreachable_count,
        row.stale_count,
        row.disabled_count,
        row.unknown_count,
        row.observation_count,
        row.observation_error_count,
        row.duration_sample_count,
        row.cert_warning_count,
        row.cert_critical_count,
        row.fingerprint_sample_count,
        row.fingerprint_change_count,
    ]
    .into_iter()
    .map(|value| checked_i64(value, "health rollup counter"))
    .collect::<Result<Vec<_>, _>>()?;
    let p50 = row
        .duration_p50_ms
        .map(|value| checked_i64(value, "health duration p50"))
        .transpose()?;
    let p95 = row
        .duration_p95_ms
        .map(|value| checked_i64(value, "health duration p95"))
        .transpose()?;
    tx.execute(
        "INSERT INTO ocfleet_native.health_rollups
         (node_id, bucket_seconds, bucket_start, bucket_end, input_watermark,
          health_samples, covered_slots, expected_slots, healthy_count, degraded_count,
          unreachable_count, stale_count, disabled_count, unknown_count,
          observation_count, observation_error_count, duration_sample_count,
          duration_p50_ms, duration_p95_ms, cert_warning_count, cert_critical_count,
          fingerprint_sample_count, fingerprint_change_count, computed_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
                 $19,$20,$21,$22,$23,$24)
         ON CONFLICT (node_id, bucket_seconds, bucket_start) DO UPDATE SET
           bucket_end = EXCLUDED.bucket_end, input_watermark = EXCLUDED.input_watermark,
           health_samples = EXCLUDED.health_samples, covered_slots = EXCLUDED.covered_slots,
           expected_slots = EXCLUDED.expected_slots, healthy_count = EXCLUDED.healthy_count,
           degraded_count = EXCLUDED.degraded_count,
           unreachable_count = EXCLUDED.unreachable_count, stale_count = EXCLUDED.stale_count,
           disabled_count = EXCLUDED.disabled_count, unknown_count = EXCLUDED.unknown_count,
           observation_count = EXCLUDED.observation_count,
           observation_error_count = EXCLUDED.observation_error_count,
           duration_sample_count = EXCLUDED.duration_sample_count,
           duration_p50_ms = EXCLUDED.duration_p50_ms,
           duration_p95_ms = EXCLUDED.duration_p95_ms,
           cert_warning_count = EXCLUDED.cert_warning_count,
           cert_critical_count = EXCLUDED.cert_critical_count,
           fingerprint_sample_count = EXCLUDED.fingerprint_sample_count,
           fingerprint_change_count = EXCLUDED.fingerprint_change_count,
           computed_at = EXCLUDED.computed_at",
        &[
            &row.node_id,
            &bucket_seconds,
            &bucket_start,
            &bucket_end,
            &row.input_watermark,
            &counts[0],
            &counts[1],
            &counts[2],
            &counts[3],
            &counts[4],
            &counts[5],
            &counts[6],
            &counts[7],
            &counts[8],
            &counts[9],
            &counts[10],
            &counts[11],
            &p50,
            &p95,
            &counts[12],
            &counts[13],
            &counts[14],
            &counts[15],
            &computed_at,
        ],
    )?;
    Ok(())
}

fn health_rollup_from_postgres_row(
    row: &postgres::Row,
) -> Result<HealthRollupRecord, PostgresError> {
    let value = |index| -> Result<u64, PostgresError> {
        checked_u64(row.try_get(index)?, "health rollup counter")
    };
    let optional = |index| -> Result<Option<u64>, PostgresError> {
        row.try_get::<_, Option<i64>>(index)?
            .map(|value| checked_u64(value, "health rollup duration"))
            .transpose()
    };
    Ok(HealthRollupRecord {
        node_id: row.try_get(0)?,
        bucket_seconds: value(1)?,
        bucket_start: format_postgres_timestamp(row.try_get(2)?, "health bucket_start")?,
        bucket_end: format_postgres_timestamp(row.try_get(3)?, "health bucket_end")?,
        input_watermark: row.try_get(4)?,
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
        computed_at: format_postgres_timestamp(row.try_get(23)?, "health computed_at")?,
    })
}

fn health_evaluation_from_postgres_row(
    row: &postgres::Row,
) -> Result<HealthEvaluationRunRecord, PostgresError> {
    Ok(HealthEvaluationRunRecord {
        evaluation_id: row.try_get(0)?,
        input_watermark: row.try_get(1)?,
        policy_version: row.try_get(2)?,
        computation_version: row.try_get(3)?,
        started_at: format_postgres_timestamp(row.try_get(4)?, "health started_at")?,
        finished_at: row
            .try_get::<_, Option<OffsetDateTime>>(5)?
            .map(|value| format_postgres_timestamp(value, "health finished_at"))
            .transpose()?,
        status: row.try_get(6)?,
        snapshot_count: checked_u64(row.try_get(7)?, "health snapshot_count")?,
        failure_code: row.try_get(8)?,
    })
}

fn health_evaluation_conflict(evaluation_id: &str, detail: &'static str) -> PostgresError {
    PostgresError::Store(StoreError::HealthEvaluationConflict {
        evaluation_id: evaluation_id.to_string(),
        detail,
    })
}

fn insert_health_evaluation_audit_postgres_tx(
    tx: &mut Transaction<'_>,
    actor: &str,
    event_name: &str,
    evaluation_id: &str,
    ok: bool,
    failure_code: Option<&str>,
    snapshot_count: usize,
) -> Result<(), PostgresError> {
    let mut event = AuditEvent::new(actor, event_name);
    event.ok = Some(ok);
    event.request_id = Some(evaluation_id.to_string());
    event.error_code = failure_code.map(str::to_string);
    event.detail_json = json!({
        "actor_type": "system",
        "target_type": "health_evaluation",
        "target_id": evaluation_id,
        "batch_count": snapshot_count,
        "reason": Value::Null,
    });
    insert_audit(tx, &event)
}

fn validated_native_config(dsn: &str) -> Result<Config, PostgresError> {
    let config = Config::from_str(dsn)
        .map_err(|_| PostgresError::Configuration("Postgres DSN is invalid"))?;
    validate_transport(&config)?;
    Ok(config)
}

fn validate_native_schema(tx: &mut Transaction<'_>) -> Result<(), PostgresError> {
    for relation in [
        "ocfleet_native.migrations",
        "ocfleet_native.nodes",
        "ocfleet_native.endpoint_trust",
        "ocfleet_native.controller_audit_log",
        "ocfleet_native.node_metadata",
        "ocfleet_native.node_maintenance_windows",
        "ocfleet_native.node_capability_snapshots",
        "ocfleet_native.enrollment_tokens",
        "ocfleet_native.join_requests",
        "ocfleet_native.observability_jobs",
        "ocfleet_native.observability_runs",
        "ocfleet_native.probe_observations",
        "ocfleet_native.scheduler_job_claims",
        "ocfleet_native.scheduler_maintenance",
        "ocfleet_native.retention_policies",
        "ocfleet_native.retention_operations",
        "ocfleet_native.health_policy",
        "ocfleet_native.health_evaluation_runs",
        "ocfleet_native.health_snapshots",
        "ocfleet_native.health_history",
        "ocfleet_native.health_rollups",
        "ocfleet_native.alert_events",
        "ocfleet_native.alert_hooks",
        "ocfleet_native.alert_delivery_attempts",
        "ocfleet_native.alert_delivery_queue",
    ] {
        let is_table: bool = tx
            .query_one(
                "SELECT COALESCE((
                   SELECT relkind IN ('r', 'p')
                   FROM pg_class
                   WHERE oid = to_regclass($1)
                 ), FALSE)",
                &[&relation],
            )?
            .get(0);
        if !is_table {
            return Err(PostgresError::InvalidState(format!(
                "native Postgres relation {relation} is missing or incompatible"
            )));
        }
    }

    tx.query(
        "SELECT version, name, applied_at FROM ocfleet_native.migrations LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT node_id, endpoint_id, name, region, role, enabled, created_at, updated_at
         FROM ocfleet_native.nodes LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT endpoint_id, node_id, fingerprint, status, generation,
                previous_endpoint_id, rotated_to, trust_bundle_json, created_at, updated_at
         FROM ocfleet_native.endpoint_trust LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT id, ts, actor, event, node_id, endpoint_id, method, request_id,
                params_hash, ok, error_code, duration_ms, detail_json
         FROM ocfleet_native.controller_audit_log LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT node_id, environment, site, owner_team, service_tier, expected_agent_version,
                labels_json, updated_at FROM ocfleet_native.node_metadata LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT node_id, starts_at, ends_at, reason, updated_at
         FROM ocfleet_native.node_maintenance_windows LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT node_id, endpoint_id, observed_at, status, agent_version,
                protocol_min, protocol_max, ocserv_snapshot_min, ocserv_snapshot_max,
                controlled_writes_compiled, controlled_writes_locally_enabled
         FROM ocfleet_native.node_capability_snapshots LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT token_id, token_hash, created_at, created_by, expires_at, max_uses,
                used_count, status, description, labels_json, scope_json
         FROM ocfleet_native.enrollment_tokens LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT request_id, token_id, status, agent_public_key, fingerprint,
                requested_endpoint_id, assigned_endpoint_id, hostname, agent_version,
                requested_labels_json, approved_labels_json, created_at, approved_at,
                approved_by, rejection_reason, audit_correlation_id
         FROM ocfleet_native.join_requests LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT job_id, kind, selector_json, pair_selector_json, interval_seconds,
                jitter_seconds, timeout_ms, enabled, next_run_at, last_run_at,
                created_at, updated_at
         FROM ocfleet_native.observability_jobs LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT run_id, job_id, started_at, finished_at, status, triggered_by, summary_json
         FROM ocfleet_native.observability_runs LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT observation_id, run_id, node_id, endpoint_id, method, ok, error_code,
                duration_ms, observed_at, expires_at, result_class, summary_json
         FROM ocfleet_native.probe_observations LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT job_id, owner_id, owner_actor, fence_token, claimed_at, lease_expires_at,
                active_run_id, updated_at
         FROM ocfleet_native.scheduler_job_claims LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT singleton_id, starts_at, ends_at, reason, updated_at
         FROM ocfleet_native.scheduler_maintenance LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT scope, max_age_days, max_rows, updated_at
         FROM ocfleet_native.retention_policies LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT operation_id, actor, input_json, result_json, created_at
         FROM ocfleet_native.retention_operations LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT singleton_id, stale_window_seconds, unreachable_consecutive_failures,
                cert_warning_days, cert_critical_days, updated_at
         FROM ocfleet_native.health_policy LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT evaluation_id, input_watermark, policy_version, computation_version,
                started_at, finished_at, status, snapshot_count, failure_code
         FROM ocfleet_native.health_evaluation_runs LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT node_id, endpoint_id, computed_at, status, freshness_seconds,
                last_success_at, last_failure_at, last_error_code,
                degraded_methods_json, summary_json
         FROM ocfleet_native.health_snapshots LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT evaluation_id, node_id, endpoint_id, computed_at, status,
                freshness_seconds, last_success_at, last_failure_at, last_error_code,
                degraded_methods_json, summary_json
         FROM ocfleet_native.health_history LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT node_id, bucket_seconds, bucket_start, bucket_end, input_watermark,
                health_samples, covered_slots, expected_slots, healthy_count,
                degraded_count, unreachable_count, stale_count, disabled_count,
                unknown_count, observation_count, observation_error_count,
                duration_sample_count, duration_p50_ms, duration_p95_ms,
                cert_warning_count, cert_critical_count, fingerprint_sample_count,
                fingerprint_change_count, computed_at
         FROM ocfleet_native.health_rollups LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT alert_id, dedupe_key, node_id, severity, state, reason_code,
                first_seen_at, last_seen_at, last_sent_at, resolved_at, detail_json
         FROM ocfleet_native.alert_events LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT hook_id, name, hook_type, endpoint_url, endpoint_url_redacted,
                endpoint_host, host_allow_json, hmac_key_id, enabled, max_attempts,
                timeout_ms, created_at, updated_at
         FROM ocfleet_native.alert_hooks LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT attempt_id, alert_id, hook_id, attempt_no, attempted_at, status,
                http_status_class, error_code, bytes_sent, detail_json
         FROM ocfleet_native.alert_delivery_attempts LIMIT 0",
        &[],
    )?;
    tx.query(
        "SELECT queue_id, alert_id, hook_id, idempotency_key, group_key, status,
                attempt_count, next_attempt_at, owner_id, owner_actor, fence_token,
                claimed_at, lease_expires_at, last_error_code, created_at, updated_at,
                delivered_at
         FROM ocfleet_native.alert_delivery_queue LIMIT 0",
        &[],
    )?;
    Ok(())
}

fn map_store_validation(result: Result<(), StoreError>) -> Result<(), PostgresError> {
    result.map_err(|error| match error {
        StoreError::InvalidInput(message) => PostgresError::InvalidInput(message),
        other => PostgresError::InvalidInput(other.to_string()),
    })
}

fn checked_query_limit(limit: u64) -> Result<i64, PostgresError> {
    if limit == 0 || limit > MAX_STORE_READER_ROWS {
        return Err(PostgresError::InvalidInput(format!(
            "query limit must be between 1 and {MAX_STORE_READER_ROWS}"
        )));
    }
    i64::try_from(limit)
        .map_err(|_| PostgresError::InvalidInput("query limit exceeds i64".to_string()))
}

fn checked_i64(value: u64, field: &str) -> Result<i64, PostgresError> {
    i64::try_from(value).map_err(|_| PostgresError::InvalidInput(format!("{field} exceeds i64")))
}

fn checked_u64(value: i64, field: &str) -> Result<u64, PostgresError> {
    u64::try_from(value)
        .map_err(|_| PostgresError::InvalidState(format!("native {field} is negative")))
}

fn validate_native_id(field: &str, value: &str, max_len: usize) -> Result<(), PostgresError> {
    if value.is_empty()
        || value.len() > max_len
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(PostgresError::InvalidInput(format!(
            "{field} must be a bounded non-whitespace identifier"
        )));
    }
    Ok(())
}

fn parse_optional_postgres_timestamp(
    value: &Option<String>,
    field: &str,
) -> Result<Option<OffsetDateTime>, PostgresError> {
    value
        .as_deref()
        .map(|value| parse_postgres_timestamp(value, field))
        .transpose()
}

fn validate_scheduler_job_kind(kind: &str) -> Result<(), PostgresError> {
    if matches!(
        kind,
        "controller-ping" | "ocserv-status" | "ocserv-cert" | "ocserv-sessions" | "path-probe"
    ) {
        Ok(())
    } else {
        Err(PostgresError::InvalidInput(
            "scheduler job kind is invalid".to_string(),
        ))
    }
}

fn validate_observability_job(
    job: &ObservabilityJobRecord,
    actor: &str,
) -> Result<(), PostgresError> {
    validate_actor(actor).map_err(PostgresError::InvalidInput)?;
    validate_native_id("scheduler job_id", &job.job_id, 128)?;
    validate_scheduler_job_kind(&job.kind)?;
    let selector = SchedulerSelectorPayloadV1::from_value(&job.selector_json)
        .map_err(PostgresError::InvalidInput)?;
    let pair = job
        .pair_selector_json
        .as_ref()
        .map(SchedulerPairPayloadV1::from_value)
        .transpose()
        .map_err(PostgresError::InvalidInput)?;
    validate_scheduler_payload_relationship(&job.kind, &selector, pair.as_ref())
        .map_err(PostgresError::InvalidInput)?;
    if !(60..=86_400).contains(&job.interval_seconds) {
        return Err(PostgresError::InvalidInput(
            "interval_seconds must be between 60 and 86400".to_string(),
        ));
    }
    if job.jitter_seconds > 3_600 || job.jitter_seconds > job.interval_seconds {
        return Err(PostgresError::InvalidInput(
            "jitter_seconds must be at most 3600 and not exceed interval_seconds".to_string(),
        ));
    }
    if !(1_000..=30_000).contains(&job.timeout_ms) {
        return Err(PostgresError::InvalidInput(
            "timeout_ms must be between 1000 and 30000".to_string(),
        ));
    }
    parse_optional_postgres_timestamp(&job.next_run_at, "job next_run_at")?;
    parse_optional_postgres_timestamp(&job.last_run_at, "job last_run_at")?;
    parse_postgres_timestamp(&job.created_at, "job created_at")?;
    parse_postgres_timestamp(&job.updated_at, "job updated_at")?;
    Ok(())
}

fn observability_job_from_row(
    row: &postgres::Row,
) -> Result<ObservabilityJobRecord, PostgresError> {
    let selector_json: String = row.try_get(2)?;
    let selector_json: Value = serde_json::from_str(&selector_json)
        .map_err(|_| PostgresError::InvalidState("native job selector JSON is invalid".into()))?;
    let selector = SchedulerSelectorPayloadV1::from_value(&selector_json)
        .map_err(|error| PostgresError::InvalidState(format!("native job selector: {error}")))?;
    let pair_json: Option<String> = row.try_get(3)?;
    let pair_selector_json = pair_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|_| PostgresError::InvalidState("native job pair JSON is invalid".into()))?;
    let pair = pair_selector_json
        .as_ref()
        .map(SchedulerPairPayloadV1::from_value)
        .transpose()
        .map_err(|error| PostgresError::InvalidState(format!("native job pair: {error}")))?;
    let kind: String = row.try_get(1)?;
    validate_scheduler_job_kind(&kind)
        .map_err(|error| PostgresError::InvalidState(error.to_string()))?;
    validate_scheduler_payload_relationship(&kind, &selector, pair.as_ref())
        .map_err(|error| PostgresError::InvalidState(format!("native job payload: {error}")))?;
    let record = ObservabilityJobRecord {
        job_id: row.try_get(0)?,
        kind,
        selector_json,
        pair_selector_json,
        interval_seconds: checked_u64(row.try_get(4)?, "job interval_seconds")?,
        jitter_seconds: checked_u64(row.try_get(5)?, "job jitter_seconds")?,
        timeout_ms: checked_u64(row.try_get(6)?, "job timeout_ms")?,
        enabled: row.try_get(7)?,
        next_run_at: row
            .try_get::<_, Option<OffsetDateTime>>(8)?
            .map(|value| format_postgres_timestamp(value, "job next_run_at"))
            .transpose()?,
        last_run_at: row
            .try_get::<_, Option<OffsetDateTime>>(9)?
            .map(|value| format_postgres_timestamp(value, "job last_run_at"))
            .transpose()?,
        created_at: format_postgres_timestamp(row.try_get(10)?, "job created_at")?,
        updated_at: format_postgres_timestamp(row.try_get(11)?, "job updated_at")?,
    };
    if record.jitter_seconds > record.interval_seconds {
        return Err(PostgresError::InvalidState(
            "native job jitter exceeds interval".into(),
        ));
    }
    Ok(record)
}

fn get_observability_job_tx(
    tx: &mut Transaction<'_>,
    job_id: &str,
) -> Result<Option<ObservabilityJobRecord>, PostgresError> {
    tx.query_opt(
        "SELECT job_id, kind, selector_json::text, pair_selector_json::text,
                interval_seconds, jitter_seconds, timeout_ms, enabled,
                next_run_at, last_run_at, created_at, updated_at
         FROM ocfleet_native.observability_jobs WHERE job_id = $1 FOR UPDATE",
        &[&job_id],
    )?
    .as_ref()
    .map(observability_job_from_row)
    .transpose()
}

fn scheduler_job_audit_detail(job: &ObservabilityJobRecord, state: &str) -> Value {
    json!({
        "job_id": job.job_id,
        "kind": job.kind,
        "enabled": job.enabled,
        "state": state,
        "result_class": "scheduler_summary",
    })
}

fn validate_scheduler_maintenance(
    window: &SchedulerMaintenanceWindow,
) -> Result<(OffsetDateTime, OffsetDateTime, OffsetDateTime), PostgresError> {
    validate_reason(&window.reason).map_err(PostgresError::InvalidInput)?;
    let starts_at = parse_postgres_timestamp(&window.starts_at, "maintenance starts_at")?;
    let ends_at = parse_postgres_timestamp(&window.ends_at, "maintenance ends_at")?;
    let updated_at = parse_postgres_timestamp(&window.updated_at, "maintenance updated_at")?;
    if ends_at <= starts_at {
        return Err(PostgresError::InvalidInput(
            "scheduler maintenance ends_at must be later than starts_at".into(),
        ));
    }
    Ok((starts_at, ends_at, updated_at))
}

fn scheduler_maintenance_from_row(
    row: &postgres::Row,
) -> Result<SchedulerMaintenanceWindow, PostgresError> {
    let window = SchedulerMaintenanceWindow {
        starts_at: format_postgres_timestamp(row.try_get(0)?, "maintenance starts_at")?,
        ends_at: format_postgres_timestamp(row.try_get(1)?, "maintenance ends_at")?,
        reason: row.try_get(2)?,
        updated_at: format_postgres_timestamp(row.try_get(3)?, "maintenance updated_at")?,
    };
    validate_scheduler_maintenance(&window)
        .map_err(|error| PostgresError::InvalidState(error.to_string()))?;
    Ok(window)
}

fn validate_scheduler_claim_input(
    owner_id: &str,
    now: &str,
    lease_seconds: u64,
    actor: &str,
) -> Result<(), PostgresError> {
    validate_native_id("scheduler owner_id", owner_id, 128)?;
    validate_actor(actor).map_err(PostgresError::InvalidInput)?;
    if !(MIN_SCHEDULER_LEASE_SECONDS..=MAX_SCHEDULER_LEASE_SECONDS).contains(&lease_seconds) {
        return Err(PostgresError::InvalidInput(format!(
            "scheduler lease must be between {MIN_SCHEDULER_LEASE_SECONDS} and {MAX_SCHEDULER_LEASE_SECONDS} seconds"
        )));
    }
    parse_postgres_timestamp(now, "scheduler event timestamp")?;
    Ok(())
}

fn validate_scheduler_claim(claim: &SchedulerJobClaim) -> Result<(), PostgresError> {
    validate_native_id("scheduler job_id", &claim.job_id, 128)?;
    validate_native_id("scheduler owner_id", &claim.owner_id, 128)?;
    if claim.fence_token == 0 {
        return Err(PostgresError::InvalidInput(
            "scheduler fence token must be positive".into(),
        ));
    }
    let claimed_at = parse_postgres_timestamp(&claim.claimed_at, "claim claimed_at")?;
    let lease_expires_at =
        parse_postgres_timestamp(&claim.lease_expires_at, "claim lease_expires_at")?;
    if lease_expires_at <= claimed_at {
        return Err(PostgresError::InvalidInput(
            "scheduler lease must expire after claimed_at".into(),
        ));
    }
    if let Some(run_id) = &claim.active_run_id {
        validate_native_id("scheduler active_run_id", run_id, 128)?;
    }
    Ok(())
}

fn scheduler_claim_from_row(row: &postgres::Row) -> Result<SchedulerJobClaim, PostgresError> {
    let owner_id: Option<String> = row.try_get(1)?;
    let claimed_at: Option<OffsetDateTime> = row.try_get(3)?;
    let lease_expires_at: Option<OffsetDateTime> = row.try_get(4)?;
    let claim = SchedulerJobClaim {
        job_id: row.try_get(0)?,
        owner_id: owner_id.ok_or_else(|| {
            PostgresError::InvalidState("native scheduler claim owner is missing".into())
        })?,
        fence_token: checked_u64(row.try_get(2)?, "scheduler fence token")?,
        claimed_at: format_postgres_timestamp(
            claimed_at.ok_or_else(|| {
                PostgresError::InvalidState("native scheduler claimed_at is missing".into())
            })?,
            "scheduler claimed_at",
        )?,
        lease_expires_at: format_postgres_timestamp(
            lease_expires_at.ok_or_else(|| {
                PostgresError::InvalidState("native scheduler lease_expires_at is missing".into())
            })?,
            "scheduler lease_expires_at",
        )?,
        active_run_id: row.try_get(5)?,
    };
    validate_scheduler_claim(&claim)
        .map_err(|error| PostgresError::InvalidState(error.to_string()))?;
    Ok(claim)
}

fn scheduler_claim_lost(job_id: &str) -> PostgresError {
    PostgresError::Store(StoreError::SchedulerClaimLost(job_id.to_string()))
}

fn postgres_clock_timestamp(tx: &mut Transaction<'_>) -> Result<OffsetDateTime, PostgresError> {
    Ok(tx.query_one("SELECT clock_timestamp()", &[])?.try_get(0)?)
}

fn acquire_scheduler_claim_tx(
    tx: &mut Transaction<'_>,
    job_id: &str,
    owner_id: &str,
    lease_seconds: u64,
    actor: &str,
    require_due: bool,
) -> Result<Option<SchedulerJobClaim>, PostgresError> {
    let job = get_observability_job_tx(tx, job_id)?
        .ok_or_else(|| PostgresError::InvalidState(format!("native job not found: {job_id}")))?;
    if !job.enabled {
        return Ok(None);
    }
    let existing = tx.query_opt(
        "SELECT job_id, owner_id, fence_token, claimed_at, lease_expires_at, active_run_id
         FROM ocfleet_native.scheduler_job_claims WHERE job_id = $1 FOR UPDATE",
        &[&job_id],
    )?;
    let authoritative_now = postgres_clock_timestamp(tx)?;
    if require_due
        && job
            .next_run_at
            .as_deref()
            .map(|value| parse_postgres_timestamp(value, "stored job next_run_at"))
            .transpose()?
            .is_some_and(|next| next > authoritative_now)
    {
        return Ok(None);
    }
    if let Some(row) = &existing {
        let owner: Option<String> = row.try_get(1)?;
        let expires: Option<OffsetDateTime> = row.try_get(4)?;
        if owner.is_some() && expires.is_some_and(|expires| expires > authoritative_now) {
            return Ok(None);
        }
        let active_run_id: Option<String> = row.try_get(5)?;
        if let Some(run_id) = active_run_id {
            recover_expired_scheduler_run_tx(tx, job_id, &run_id, authoritative_now, actor)?;
        }
    }
    let previous_fence = existing
        .as_ref()
        .map(|row| row.try_get::<_, i64>(2))
        .transpose()?
        .unwrap_or(0);
    let fence_token = previous_fence.checked_add(1).ok_or_else(|| {
        PostgresError::InvalidState("native scheduler fence token overflow".into())
    })?;
    let lease_expires_at =
        authoritative_now + time::Duration::seconds(checked_i64(lease_seconds, "lease")?);
    tx.execute(
        "INSERT INTO ocfleet_native.scheduler_job_claims
         (job_id, owner_id, owner_actor, fence_token, claimed_at,
          lease_expires_at, active_run_id, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, NULL, $5)
         ON CONFLICT (job_id) DO UPDATE SET owner_id = EXCLUDED.owner_id,
           owner_actor = EXCLUDED.owner_actor, fence_token = EXCLUDED.fence_token,
           claimed_at = EXCLUDED.claimed_at,
           lease_expires_at = EXCLUDED.lease_expires_at, active_run_id = NULL,
           updated_at = EXCLUDED.updated_at",
        &[
            &job_id,
            &owner_id,
            &actor,
            &fence_token,
            &authoritative_now,
            &lease_expires_at,
        ],
    )?;
    let claim = SchedulerJobClaim {
        job_id: job_id.to_string(),
        owner_id: owner_id.to_string(),
        fence_token: checked_u64(fence_token, "scheduler fence token")?,
        claimed_at: format_postgres_timestamp(authoritative_now, "scheduler claimed_at")?,
        lease_expires_at: format_postgres_timestamp(
            lease_expires_at,
            "scheduler lease_expires_at",
        )?,
        active_run_id: None,
    };
    insert_scheduler_claim_audit(tx, "scheduler.claim.acquire", &claim, actor, "acquired")?;
    Ok(Some(claim))
}

fn recover_expired_scheduler_run_tx(
    tx: &mut Transaction<'_>,
    job_id: &str,
    run_id: &str,
    recovered_at: OffsetDateTime,
    actor: &str,
) -> Result<(), PostgresError> {
    let run = get_observability_run_state_tx(tx, run_id)?.ok_or_else(|| {
        PostgresError::Store(StoreError::ObservabilityRunNotFound(run_id.to_string()))
    })?;
    if run.job_id.as_deref() != Some(job_id) {
        return Err(PostgresError::InvalidInput(
            "expired scheduler claim references a run for another job".into(),
        ));
    }
    if run.status != "running" || run.finished_at.is_some() {
        return Ok(());
    }
    let finished_at = recovered_at.max(run.started_at);
    let kind: String = tx
        .query_one(
            "SELECT kind FROM ocfleet_native.observability_jobs WHERE job_id = $1",
            &[&job_id],
        )?
        .try_get(0)?;
    let summary = RunSummaryPayloadV1::new(
        Some(job_id.to_string()),
        Some(kind.clone()),
        "failed".to_string(),
        "scheduler.run.once".to_string(),
        Some(0),
        Some(0),
    )
    .map_err(PostgresError::InvalidState)?;
    let affected = tx.execute(
        "UPDATE ocfleet_native.observability_runs
         SET finished_at = $1, status = 'failed', summary_json = CAST($2 AS text)::jsonb
         WHERE run_id = $3 AND job_id = $4 AND status = 'running' AND finished_at IS NULL",
        &[
            &finished_at,
            &summary.to_value().to_string(),
            &run_id,
            &job_id,
        ],
    )?;
    if affected != 1 {
        return Err(PostgresError::Store(
            StoreError::ObservabilityRunNotRunning(run_id.to_string()),
        ));
    }
    let mut event = AuditEvent::new(actor, "scheduler.run.recover");
    event.ok = Some(false);
    event.error_code = Some("SCHEDULER_LEASE_EXPIRED".to_string());
    event.detail_json = json!({
        "run_id": run_id,
        "job_id": job_id,
        "kind": kind,
        "status": "failed",
        "reason_code": "SCHEDULER_LEASE_EXPIRED",
        "result_class": "scheduler_summary",
    });
    insert_audit(tx, &event)
}

fn insert_scheduler_claim_audit(
    tx: &mut Transaction<'_>,
    event_name: &str,
    claim: &SchedulerJobClaim,
    actor: &str,
    state: &str,
) -> Result<(), PostgresError> {
    let mut event = AuditEvent::new(actor, event_name);
    event.ok = Some(true);
    event.detail_json = json!({
        "job_id": claim.job_id,
        "correlation_id": claim.owner_id,
        "generation": claim.fence_token,
        "expires_at": claim.lease_expires_at,
        "state": state,
    });
    insert_audit(tx, &event)
}

#[derive(Debug)]
struct NativeRunState {
    job_id: Option<String>,
    started_at: OffsetDateTime,
    finished_at: Option<OffsetDateTime>,
    status: String,
}

fn validate_observability_run_insert(run: &ObservabilityRunInsert) -> Result<(), PostgresError> {
    validate_native_id("observability run_id", &run.run_id, 128)?;
    if let Some(job_id) = &run.job_id {
        validate_native_id("observability job_id", job_id, 128)?;
    }
    let started_at = parse_postgres_timestamp(&run.started_at, "run started_at")?;
    let finished_at = parse_optional_postgres_timestamp(&run.finished_at, "run finished_at")?;
    if !matches!(
        run.status.as_str(),
        "running" | "succeeded" | "failed" | "skipped"
    ) {
        return Err(PostgresError::InvalidInput("run status is invalid".into()));
    }
    if run.triggered_by != "manual" {
        return Err(PostgresError::InvalidInput(
            "native direct run insertion is reserved for manual runs".into(),
        ));
    }
    if (run.status == "running") != finished_at.is_none() {
        return Err(PostgresError::InvalidInput(
            "running run must be unfinished and completed run must be finished".into(),
        ));
    }
    if finished_at.is_some_and(|finished| finished < started_at) {
        return Err(PostgresError::InvalidInput(
            "run finished_at must not precede started_at".into(),
        ));
    }
    validate_low_sensitive_json(&run.summary_json, "observability run summary")?;
    Ok(())
}

fn insert_observability_run_tx(
    tx: &mut Transaction<'_>,
    run: &ObservabilityRunInsert,
) -> Result<(), PostgresError> {
    let kind: Option<String> = match run.job_id.as_deref() {
        Some(job_id) => tx
            .query_opt(
                "SELECT kind FROM ocfleet_native.observability_jobs WHERE job_id = $1",
                &[&job_id],
            )?
            .map(|row| row.try_get(0))
            .transpose()?,
        None => None,
    };
    if run.job_id.is_some() && kind.is_none() {
        return Err(PostgresError::InvalidState(
            "native run references an unknown job".into(),
        ));
    }
    let payload = RunSummaryPayloadV1::from_value(&run.summary_json)
        .or_else(|_| {
            RunSummaryPayloadV1::from_legacy(
                run.job_id.as_deref(),
                kind.as_deref(),
                &run.status,
                &run.triggered_by,
                &run.summary_json,
            )
        })
        .map_err(PostgresError::InvalidInput)?;
    payload
        .validate_relationship(
            run.job_id.as_deref(),
            kind.as_deref(),
            &run.status,
            &run.triggered_by,
        )
        .map_err(PostgresError::InvalidInput)?;
    let started_at = parse_postgres_timestamp(&run.started_at, "run started_at")?;
    let finished_at = parse_optional_postgres_timestamp(&run.finished_at, "run finished_at")?;
    tx.execute(
        "INSERT INTO ocfleet_native.observability_runs
         (run_id, job_id, started_at, finished_at, status, triggered_by, summary_json)
         VALUES ($1, $2, $3, $4, $5, $6, CAST($7 AS text)::jsonb)",
        &[
            &run.run_id,
            &run.job_id,
            &started_at,
            &finished_at,
            &run.status,
            &run.triggered_by,
            &payload.to_value().to_string(),
        ],
    )?;
    Ok(())
}

fn get_observability_run_state_tx(
    tx: &mut Transaction<'_>,
    run_id: &str,
) -> Result<Option<NativeRunState>, PostgresError> {
    tx.query_opt(
        "SELECT job_id, started_at, finished_at, status
         FROM ocfleet_native.observability_runs WHERE run_id = $1 FOR UPDATE",
        &[&run_id],
    )?
    .map(|row| {
        Ok(NativeRunState {
            job_id: row.try_get(0)?,
            started_at: row.try_get(1)?,
            finished_at: row.try_get(2)?,
            status: row.try_get(3)?,
        })
    })
    .transpose()
}

fn observability_run_from_row(
    row: &postgres::Row,
) -> Result<ObservabilityRunRecord, PostgresError> {
    let job_id: Option<String> = row.try_get(1)?;
    let status: String = row.try_get(4)?;
    let triggered_by: String = row.try_get(5)?;
    let kind: Option<String> = row.try_get(9)?;
    let summary: String = row.try_get(6)?;
    let summary: Value = serde_json::from_str(&summary)
        .map_err(|_| PostgresError::InvalidState("native run summary JSON is invalid".into()))?;
    let payload = RunSummaryPayloadV1::from_value(&summary)
        .map_err(|error| PostgresError::InvalidState(format!("native run summary: {error}")))?;
    payload
        .validate_relationship(job_id.as_deref(), kind.as_deref(), &status, &triggered_by)
        .map_err(|error| PostgresError::InvalidState(format!("native run summary: {error}")))?;
    Ok(ObservabilityRunRecord {
        run_id: row.try_get(0)?,
        job_id,
        started_at: format_postgres_timestamp(row.try_get(2)?, "run started_at")?,
        finished_at: row
            .try_get::<_, Option<OffsetDateTime>>(3)?
            .map(|value| format_postgres_timestamp(value, "run finished_at"))
            .transpose()?,
        status,
        triggered_by,
        summary_json: payload.public_summary(),
        observation_count: checked_u64(row.try_get(7)?, "run observation count")?,
        failed_observation_count: checked_u64(row.try_get(8)?, "run failed observation count")?,
    })
}

fn validate_observation_method(method: &str) -> Result<(), PostgresError> {
    if matches!(
        method,
        PROBE_CONTROLLER_PING
            | PROBE_PATH_ECHO
            | OCSERV_SERVICE_SUMMARY
            | OCSERV_VERSION
            | OCSERV_SESSIONS_SUMMARY
            | OCSERV_CERT_EXPIRY
            | OCSERV_CONFIG_FINGERPRINT
    ) {
        Ok(())
    } else {
        Err(PostgresError::InvalidInput(
            "scheduler observation method is invalid".into(),
        ))
    }
}

fn validate_scheduler_observation(
    observation: &ProbeObservationInsert,
) -> Result<(), PostgresError> {
    validate_probe_observation(observation)?;
    if observation.ok.is_none() || observation.duration_ms.is_none() {
        return Err(PostgresError::InvalidInput(
            "scheduler observation ok and duration_ms are required".into(),
        ));
    }
    Ok(())
}

fn validate_probe_observation(observation: &ProbeObservationInsert) -> Result<(), PostgresError> {
    validate_native_id("scheduler observation_id", &observation.observation_id, 128)?;
    if let Some(run_id) = &observation.run_id {
        validate_native_id("scheduler observation run_id", run_id, 128)?;
    }
    if let Some(node_id) = &observation.node_id {
        validate_native_id("scheduler observation node_id", node_id, 128)?;
    }
    if let Some(endpoint_id) = &observation.endpoint_id {
        validate_native_id("scheduler observation endpoint_id", endpoint_id, 128)?;
    }
    validate_observation_method(&observation.method)?;
    if let Some(error_code) = &observation.error_code {
        validate_native_id("scheduler observation error_code", error_code, 64)?;
    }
    if matches!(observation.ok, Some(true)) && observation.error_code.is_some()
        || matches!(observation.ok, Some(false)) && observation.error_code.is_none()
        || observation.ok.is_none() && observation.error_code.is_some()
    {
        return Err(PostgresError::InvalidInput(
            "scheduler observation result and error_code are inconsistent".into(),
        ));
    }
    parse_postgres_timestamp(&observation.observed_at, "scheduler observed_at")?;
    parse_optional_postgres_timestamp(&observation.expires_at, "scheduler expires_at")?;
    if !matches!(
        observation.result_class.as_str(),
        "controller_rpc_summary" | "low_sensitive_summary" | "scheduler_summary"
    ) {
        return Err(PostgresError::InvalidInput(
            "scheduler observation result_class is invalid".into(),
        ));
    }
    validate_low_sensitive_json(&observation.summary_json, "observation summary")?;
    canonical_observation_summary(observation)?;
    Ok(())
}

fn canonical_observation_summary(
    observation: &ProbeObservationInsert,
) -> Result<Value, PostgresError> {
    let payload = ObservationSummaryPayloadV1::from_value(&observation.summary_json)
        .or_else(|_| {
            ObservationSummaryPayloadV1::from_legacy(
                &observation.method,
                &observation.result_class,
                &observation.summary_json,
            )
        })
        .map_err(PostgresError::InvalidInput)?;
    if payload.method != observation.method || payload.result_class != observation.result_class {
        return Err(PostgresError::InvalidInput(
            "observation summary does not match relational method/result class".into(),
        ));
    }
    Ok(payload.to_value())
}

fn insert_probe_observation_tx(
    tx: &mut Transaction<'_>,
    observation: &ProbeObservationInsert,
) -> Result<(), PostgresError> {
    let summary = canonical_observation_summary(observation)?;
    let duration_ms = observation
        .duration_ms
        .map(|value| checked_i64(value, "observation duration_ms"))
        .transpose()?;
    let observed_at = parse_postgres_timestamp(&observation.observed_at, "observed_at")?;
    let expires_at = parse_optional_postgres_timestamp(&observation.expires_at, "expires_at")?;
    tx.execute(
        "INSERT INTO ocfleet_native.probe_observations
         (observation_id, run_id, node_id, endpoint_id, method, ok, error_code,
          duration_ms, observed_at, expires_at, result_class, summary_json)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                 CAST($12 AS text)::jsonb)",
        &[
            &observation.observation_id,
            &observation.run_id,
            &observation.node_id,
            &observation.endpoint_id,
            &observation.method,
            &observation.ok,
            &observation.error_code,
            &duration_ms,
            &observed_at,
            &expires_at,
            &observation.result_class,
            &summary.to_string(),
        ],
    )?;
    Ok(())
}

fn probe_observation_from_row(
    row: &postgres::Row,
) -> Result<ProbeObservationRecord, PostgresError> {
    let method: String = row.try_get(4)?;
    let result_class: String = row.try_get(10)?;
    let summary: String = row.try_get(11)?;
    let summary: Value = serde_json::from_str(&summary).map_err(|_| {
        PostgresError::InvalidState("native observation summary JSON is invalid".into())
    })?;
    let payload = ObservationSummaryPayloadV1::from_value(&summary).map_err(|error| {
        PostgresError::InvalidState(format!("native observation summary: {error}"))
    })?;
    if payload.method != method || payload.result_class != result_class {
        return Err(PostgresError::InvalidState(
            "native observation summary does not match relational fields".into(),
        ));
    }
    Ok(ProbeObservationRecord {
        observation_id: row.try_get(0)?,
        run_id: row.try_get(1)?,
        node_id: row.try_get(2)?,
        endpoint_id: row.try_get(3)?,
        method,
        ok: row.try_get(5)?,
        error_code: row.try_get(6)?,
        duration_ms: row
            .try_get::<_, Option<i64>>(7)?
            .map(|value| checked_u64(value, "observation duration_ms"))
            .transpose()?,
        observed_at: format_postgres_timestamp(row.try_get(8)?, "observation observed_at")?,
        expires_at: row
            .try_get::<_, Option<OffsetDateTime>>(9)?
            .map(|value| format_postgres_timestamp(value, "observation expires_at"))
            .transpose()?,
        result_class,
        summary_json: payload.public_summary(),
    })
}

fn validate_scheduler_outcome(
    outcome: &SchedulerOutcomeWrite,
    actor: &str,
) -> Result<(), PostgresError> {
    validate_actor(actor).map_err(PostgresError::InvalidInput)?;
    validate_native_id("scheduler job_id", &outcome.job_id, 128)?;
    if outcome.entries.is_empty() || outcome.entries.len() > MAX_SCHEDULER_OUTCOME_ENTRIES {
        return Err(PostgresError::InvalidInput(format!(
            "scheduler outcome must contain 1-{MAX_SCHEDULER_OUTCOME_ENTRIES} entries"
        )));
    }
    match outcome.run_id.as_deref() {
        Some(run_id) => {
            validate_native_id("scheduler run_id", run_id, 128)?;
            if outcome.job_clock.is_some() {
                return Err(PostgresError::InvalidInput(
                    "run-bound scheduler outcome cannot update job clocks".into(),
                ));
            }
            for entry in &outcome.entries {
                if entry.observation.run_id.as_deref() != Some(run_id) {
                    return Err(PostgresError::InvalidInput(
                        "scheduler outcome contains a mismatched run_id".into(),
                    ));
                }
                if !matches!(
                    entry.audit.event.as_str(),
                    "rpc.completed" | "scheduler.task.outcome"
                ) {
                    return Err(PostgresError::InvalidInput(
                        "run-bound scheduler outcome audit event is invalid".into(),
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
                return Err(PostgresError::InvalidInput(
                    "runless scheduler outcome must be one failed scheduler.job.invalid entry"
                        .into(),
                ));
            }
        }
    }
    if let Some(clock) = &outcome.job_clock {
        validate_scheduler_job_clock(clock)?;
        if clock.job_id != outcome.job_id {
            return Err(PostgresError::InvalidInput(
                "scheduler outcome clock job_id does not match outcome".into(),
            ));
        }
    }
    for entry in &outcome.entries {
        validate_scheduler_observation(&entry.observation)?;
        validate_scheduler_outcome_audit(&entry.audit, &entry.observation, actor)?;
    }
    Ok(())
}

fn validate_scheduler_outcome_claim(
    outcome: &SchedulerOutcomeWrite,
    claim: &SchedulerJobClaim,
) -> Result<(), PostgresError> {
    validate_scheduler_claim(claim)?;
    if claim.job_id != outcome.job_id {
        return Err(PostgresError::InvalidInput(
            "scheduler claim job_id does not match outcome".into(),
        ));
    }
    Ok(())
}

fn validate_scheduler_outcome_audit(
    audit: &AuditEvent,
    observation: &ProbeObservationInsert,
    actor: &str,
) -> Result<(), PostgresError> {
    if audit.actor != actor
        || audit.node_id != observation.node_id
        || audit.endpoint_id != observation.endpoint_id
        || audit.method.as_deref() != Some(observation.method.as_str())
        || audit.ok != observation.ok
        || audit.duration_ms != observation.duration_ms
    {
        return Err(PostgresError::InvalidInput(
            "scheduler outcome audit fields do not match observation".into(),
        ));
    }
    if matches!(audit.ok, Some(true)) && audit.error_code.is_some()
        || matches!(audit.ok, Some(false)) && audit.error_code.is_none()
    {
        return Err(PostgresError::InvalidInput(
            "scheduler outcome audit result and error_code are inconsistent".into(),
        ));
    }
    if audit.event != "rpc.completed" && audit.error_code != observation.error_code {
        return Err(PostgresError::InvalidInput(
            "scheduler outcome audit error_code does not match observation".into(),
        ));
    }
    Ok(())
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

fn validate_scheduler_job_clock(
    clock: &SchedulerJobClockUpdate,
) -> Result<(OffsetDateTime, OffsetDateTime), PostgresError> {
    validate_native_id("scheduler clock job_id", &clock.job_id, 128)?;
    let next_run_at = parse_postgres_timestamp(&clock.next_run_at, "scheduler next_run_at")?;
    let last_run_at = parse_postgres_timestamp(&clock.last_run_at, "scheduler last_run_at")?;
    if next_run_at <= last_run_at {
        return Err(PostgresError::InvalidInput(
            "scheduler next_run_at must be later than last_run_at".into(),
        ));
    }
    Ok((next_run_at, last_run_at))
}

fn update_scheduler_job_clock_tx(
    tx: &mut Transaction<'_>,
    clock: &SchedulerJobClockUpdate,
) -> Result<(), PostgresError> {
    let (next_run_at, last_run_at) = validate_scheduler_job_clock(clock)?;
    update_scheduler_job_clock_values_tx(tx, &clock.job_id, next_run_at, last_run_at)
}

fn update_scheduler_job_clock_values_tx(
    tx: &mut Transaction<'_>,
    job_id: &str,
    next_run_at: OffsetDateTime,
    last_run_at: OffsetDateTime,
) -> Result<(), PostgresError> {
    let affected = tx.execute(
        "UPDATE ocfleet_native.observability_jobs
         SET next_run_at = $1, last_run_at = $2, updated_at = clock_timestamp()
         WHERE job_id = $3 AND (last_run_at IS NULL OR last_run_at <= $2)",
        &[&next_run_at, &last_run_at, &job_id],
    )?;
    if affected != 1 {
        return Err(PostgresError::InvalidState(
            "native scheduler job clock update was rejected".into(),
        ));
    }
    Ok(())
}

fn ensure_scheduler_job_claim_tx(
    tx: &mut Transaction<'_>,
    expected: &SchedulerJobClaim,
    active_run_id: Option<&str>,
    actor: &str,
) -> Result<(), PostgresError> {
    let fence_token = checked_i64(expected.fence_token, "fence token")?;
    let matches = tx.query_opt(
        "SELECT 1
         FROM ocfleet_native.scheduler_job_claims
         WHERE job_id = $1 AND owner_id = $2 AND fence_token = $3
           AND owner_actor = $4 AND active_run_id IS NOT DISTINCT FROM $5
           AND lease_expires_at > clock_timestamp()
         FOR UPDATE",
        &[
            &expected.job_id,
            &expected.owner_id,
            &fence_token,
            &actor,
            &active_run_id,
        ],
    )?;
    if matches.is_none() {
        return Err(scheduler_claim_lost(&expected.job_id));
    }
    Ok(())
}

fn validate_retention_scope(scope: &str) -> Result<(), PostgresError> {
    if matches!(
        scope,
        "observations"
            | "observability-runs"
            | "health-snapshots"
            | "health-history"
            | "health-rollups"
            | "alert-events"
    ) {
        Ok(())
    } else {
        Err(PostgresError::InvalidInput(
            "native retention scope is not supported".into(),
        ))
    }
}

fn validate_retention_max_rows(max_rows: Option<u64>) -> Result<(), PostgresError> {
    if max_rows.is_some_and(|rows| rows == 0 || rows > MAX_RETENTION_POLICY_ROWS) {
        return Err(PostgresError::InvalidInput(format!(
            "retention max_rows must be 1-{MAX_RETENTION_POLICY_ROWS}"
        )));
    }
    Ok(())
}

fn validate_retention_policy(policy: &RetentionPolicyRecord) -> Result<(), PostgresError> {
    validate_retention_scope(&policy.scope)?;
    if policy
        .max_age_days
        .is_some_and(|days| days == 0 || days > MAX_RETENTION_POLICY_AGE_DAYS)
    {
        return Err(PostgresError::InvalidInput(format!(
            "retention max_age_days must be 1-{MAX_RETENTION_POLICY_AGE_DAYS}"
        )));
    }
    validate_retention_max_rows(policy.max_rows)?;
    parse_postgres_timestamp(&policy.updated_at, "retention updated_at")?;
    Ok(())
}

fn validate_retention_apply_input(input: &RetentionApplyInput) -> Result<(), PostgresError> {
    validate_native_id("retention operation_id", &input.operation_id, 96)?;
    let uuid = input
        .operation_id
        .strip_prefix("retention-")
        .ok_or_else(|| {
            PostgresError::InvalidInput(
                "retention operation_id must use retention-<uuid> format".into(),
            )
        })?;
    Uuid::parse_str(uuid).map_err(|_| {
        PostgresError::InvalidInput("retention operation_id must contain a UUID".into())
    })?;
    validate_retention_scope(&input.scope)?;
    if let Some(cutoff) = &input.cutoff {
        parse_postgres_timestamp(cutoff, "retention cutoff")?;
    }
    if input
        .max_age_days
        .is_some_and(|days| days == 0 || days > MAX_RETENTION_POLICY_AGE_DAYS)
    {
        return Err(PostgresError::InvalidInput(format!(
            "retention max_age_days must be 1-{MAX_RETENTION_POLICY_AGE_DAYS}"
        )));
    }
    validate_retention_max_rows(input.max_rows)?;
    if input
        .limit
        .is_some_and(|limit| limit == 0 || limit > MAX_RETENTION_APPLY_LIMIT)
    {
        return Err(PostgresError::InvalidInput(format!(
            "retention limit must be 1-{MAX_RETENTION_APPLY_LIMIT}"
        )));
    }
    if input.batch_size == 0 || input.batch_size > MAX_RETENTION_BATCH_SIZE {
        return Err(PostgresError::InvalidInput(format!(
            "retention batch_size must be 1-{MAX_RETENTION_BATCH_SIZE}"
        )));
    }
    Ok(())
}

fn retention_policy_from_row(row: &postgres::Row) -> Result<RetentionPolicyRecord, PostgresError> {
    let policy = RetentionPolicyRecord {
        scope: row.try_get(0)?,
        max_age_days: row
            .try_get::<_, Option<i64>>(1)?
            .map(|value| checked_u64(value, "retention max_age_days"))
            .transpose()?,
        max_rows: row
            .try_get::<_, Option<i64>>(2)?
            .map(|value| checked_u64(value, "retention max_rows"))
            .transpose()?,
        updated_at: format_postgres_timestamp(row.try_get(3)?, "retention updated_at")?,
    };
    validate_retention_policy(&policy)
        .map_err(|error| PostgresError::InvalidState(error.to_string()))?;
    Ok(policy)
}

fn get_retention_policy_tx(
    tx: &mut Transaction<'_>,
    scope: &str,
) -> Result<Option<RetentionPolicyRecord>, PostgresError> {
    tx.query_opt(
        "SELECT scope, max_age_days, max_rows, updated_at
         FROM ocfleet_native.retention_policies WHERE scope = $1 FOR UPDATE",
        &[&scope],
    )?
    .as_ref()
    .map(retention_policy_from_row)
    .transpose()
}

fn retention_policy_json(policy: &RetentionPolicyRecord) -> Value {
    json!({
        "scope": policy.scope,
        "max_age_days": policy.max_age_days,
        "max_rows": policy.max_rows,
        "updated_at": policy.updated_at,
    })
}

fn retention_candidate_report_tx<C: GenericClient>(
    conn: &mut C,
    scope: &str,
    cutoff: Option<OffsetDateTime>,
    max_rows: Option<i64>,
) -> Result<RetentionCandidateReport, PostgresError> {
    validate_retention_scope(scope)?;
    let sql = match scope {
        "observations" => {
            "WITH eligible AS (
               SELECT o.observation_id AS id, o.observed_at AS ts
               FROM ocfleet_native.probe_observations o
               WHERE o.run_id IS NULL OR (
                 EXISTS (
                   SELECT 1 FROM ocfleet_native.observability_runs r
                   WHERE r.run_id = o.run_id
                     AND r.status IN ('succeeded', 'failed', 'skipped')
                 )
                 AND NOT EXISTS (
                   SELECT 1 FROM ocfleet_native.scheduler_job_claims c
                   WHERE c.active_run_id = o.run_id
                 )
               )
             ), ranked AS (
               SELECT id, ts, row_number() OVER (ORDER BY ts DESC, id DESC) AS rn
               FROM eligible
             ), candidates AS (
               SELECT ts FROM ranked
               WHERE ($1::timestamptz IS NOT NULL AND ts < $1)
                  OR ($2::bigint IS NOT NULL AND rn > $2)
             )
             SELECT COUNT(*), MIN(ts), MAX(ts) FROM candidates"
        }
        "observability-runs" => {
            "WITH eligible AS (
               SELECT r.run_id AS id, r.started_at AS ts
               FROM ocfleet_native.observability_runs r
               WHERE r.status IN ('succeeded', 'failed', 'skipped')
                 AND NOT EXISTS (
                   SELECT 1 FROM ocfleet_native.scheduler_job_claims c
                   WHERE c.active_run_id = r.run_id
                 )
             ), ranked AS (
               SELECT id, ts, row_number() OVER (ORDER BY ts DESC, id DESC) AS rn
               FROM eligible
             ), candidates AS (
               SELECT ts FROM ranked
               WHERE ($1::timestamptz IS NOT NULL AND ts < $1)
                  OR ($2::bigint IS NOT NULL AND rn > $2)
             )
             SELECT COUNT(*), MIN(ts), MAX(ts) FROM candidates"
        }
        "health-snapshots" | "health-history" | "health-rollups" | "alert-events" => {
            simple_retention_report_sql(scope)
        }
        _ => unreachable!("validated retention scope"),
    };
    let row = conn.query_one(sql, &[&cutoff, &max_rows])?;
    Ok(RetentionCandidateReport {
        matched_count: checked_u64(row.try_get(0)?, "retention candidate count")?,
        oldest_timestamp: row
            .try_get::<_, Option<OffsetDateTime>>(1)?
            .map(|value| format_postgres_timestamp(value, "oldest retention candidate"))
            .transpose()?,
        newest_timestamp: row
            .try_get::<_, Option<OffsetDateTime>>(2)?
            .map(|value| format_postgres_timestamp(value, "newest retention candidate"))
            .transpose()?,
    })
}

fn simple_retention_report_sql(scope: &str) -> &'static str {
    match scope {
        "health-snapshots" => {
            "WITH ranked AS (
               SELECT node_id AS id, computed_at AS ts,
                      row_number() OVER (ORDER BY computed_at DESC, node_id DESC) AS rn
               FROM ocfleet_native.health_snapshots
             ), candidates AS (
               SELECT ts FROM ranked
               WHERE ($1::timestamptz IS NOT NULL AND ts < $1)
                  OR ($2::bigint IS NOT NULL AND rn > $2)
             ) SELECT COUNT(*), MIN(ts), MAX(ts) FROM candidates"
        }
        "health-history" => {
            "WITH ranked AS (
               SELECT evaluation_id || ':' || node_id AS id, computed_at AS ts,
                      row_number() OVER (
                        ORDER BY computed_at DESC, evaluation_id DESC, node_id DESC
                      ) AS rn
               FROM ocfleet_native.health_history
             ), candidates AS (
               SELECT ts FROM ranked
               WHERE ($1::timestamptz IS NOT NULL AND ts < $1)
                  OR ($2::bigint IS NOT NULL AND rn > $2)
             ) SELECT COUNT(*), MIN(ts), MAX(ts) FROM candidates"
        }
        "health-rollups" => {
            "WITH ranked AS (
               SELECT node_id, bucket_seconds, bucket_start AS ts,
                      row_number() OVER (
                        ORDER BY bucket_start DESC, node_id DESC, bucket_seconds DESC
                      ) AS rn
               FROM ocfleet_native.health_rollups
             ), candidates AS (
               SELECT ts FROM ranked
               WHERE ($1::timestamptz IS NOT NULL AND ts < $1)
                  OR ($2::bigint IS NOT NULL AND rn > $2)
             ) SELECT COUNT(*), MIN(ts), MAX(ts) FROM candidates"
        }
        "alert-events" => {
            "WITH ranked AS (
               SELECT a.alert_id AS id, a.last_seen_at AS ts,
                      row_number() OVER (
                        ORDER BY a.last_seen_at DESC, a.alert_id DESC
                      ) AS rn
               FROM ocfleet_native.alert_events a
               WHERE NOT EXISTS (
                 SELECT 1 FROM ocfleet_native.alert_delivery_queue q
                 WHERE q.alert_id = a.alert_id AND q.status = 'claimed'
               )
             ), candidates AS (
               SELECT ts FROM ranked
               WHERE ($1::timestamptz IS NOT NULL AND ts < $1)
                  OR ($2::bigint IS NOT NULL AND rn > $2)
             ) SELECT COUNT(*), MIN(ts), MAX(ts) FROM candidates"
        }
        _ => unreachable!("validated simple retention scope"),
    }
}

fn lock_retention_target_tx(tx: &mut Transaction<'_>, scope: &str) -> Result<(), PostgresError> {
    match scope {
        "observations" => tx.batch_execute(
            "LOCK TABLE ocfleet_native.probe_observations IN SHARE ROW EXCLUSIVE MODE",
        )?,
        "observability-runs" => tx.batch_execute(
            "LOCK TABLE ocfleet_native.observability_runs,
                        ocfleet_native.probe_observations,
                        ocfleet_native.scheduler_job_claims
             IN SHARE ROW EXCLUSIVE MODE",
        )?,
        "health-snapshots" => tx.batch_execute(
            "LOCK TABLE ocfleet_native.health_snapshots IN SHARE ROW EXCLUSIVE MODE",
        )?,
        "health-history" => tx.batch_execute(
            "LOCK TABLE ocfleet_native.health_history IN SHARE ROW EXCLUSIVE MODE",
        )?,
        "health-rollups" => tx.batch_execute(
            "LOCK TABLE ocfleet_native.health_rollups IN SHARE ROW EXCLUSIVE MODE",
        )?,
        "alert-events" => tx.batch_execute(
            "LOCK TABLE ocfleet_native.alert_events,
                        ocfleet_native.alert_delivery_queue,
                        ocfleet_native.alert_delivery_attempts
             IN SHARE ROW EXCLUSIVE MODE",
        )?,
        _ => {
            return Err(PostgresError::InvalidInput(
                "invalid retention scope".into(),
            ));
        }
    }
    Ok(())
}

fn prune_retention_batch_tx(
    tx: &mut Transaction<'_>,
    scope: &str,
    cutoff: Option<OffsetDateTime>,
    max_rows: Option<i64>,
    limit: i64,
) -> Result<u64, PostgresError> {
    let sql = match scope {
        "observations" => {
            "WITH eligible AS (
               SELECT o.observation_id AS id, o.observed_at AS ts
               FROM ocfleet_native.probe_observations o
               WHERE o.run_id IS NULL OR (
                 EXISTS (
                   SELECT 1 FROM ocfleet_native.observability_runs r
                   WHERE r.run_id = o.run_id
                     AND r.status IN ('succeeded', 'failed', 'skipped')
                 )
                 AND NOT EXISTS (
                   SELECT 1 FROM ocfleet_native.scheduler_job_claims c
                   WHERE c.active_run_id = o.run_id
                 )
               )
             ), ranked AS (
               SELECT id, ts, row_number() OVER (ORDER BY ts DESC, id DESC) AS rn
               FROM eligible
             ), doomed AS (
               SELECT id FROM ranked
               WHERE ($1::timestamptz IS NOT NULL AND ts < $1)
                  OR ($2::bigint IS NOT NULL AND rn > $2)
               ORDER BY ts, id LIMIT $3
             )
             DELETE FROM ocfleet_native.probe_observations target
             USING doomed WHERE target.observation_id = doomed.id
             RETURNING target.observation_id"
        }
        "observability-runs" => {
            "WITH eligible AS (
               SELECT r.run_id AS id, r.started_at AS ts
               FROM ocfleet_native.observability_runs r
               WHERE r.status IN ('succeeded', 'failed', 'skipped')
                 AND NOT EXISTS (
                   SELECT 1 FROM ocfleet_native.scheduler_job_claims c
                   WHERE c.active_run_id = r.run_id
                 )
             ), ranked AS (
               SELECT id, ts, row_number() OVER (ORDER BY ts DESC, id DESC) AS rn
               FROM eligible
             ), doomed AS (
               SELECT id FROM ranked
               WHERE ($1::timestamptz IS NOT NULL AND ts < $1)
                  OR ($2::bigint IS NOT NULL AND rn > $2)
               ORDER BY ts, id LIMIT $3
             )
             DELETE FROM ocfleet_native.observability_runs target
             USING doomed WHERE target.run_id = doomed.id
             RETURNING target.run_id"
        }
        "health-snapshots" => {
            "WITH ranked AS (
               SELECT node_id AS id, computed_at AS ts,
                      row_number() OVER (ORDER BY computed_at DESC, node_id DESC) AS rn
               FROM ocfleet_native.health_snapshots
             ), doomed AS (
               SELECT id FROM ranked
               WHERE ($1::timestamptz IS NOT NULL AND ts < $1)
                  OR ($2::bigint IS NOT NULL AND rn > $2)
               ORDER BY ts, id LIMIT $3
             )
             DELETE FROM ocfleet_native.health_snapshots target
             USING doomed WHERE target.node_id = doomed.id RETURNING target.node_id"
        }
        "health-history" => {
            "WITH ranked AS (
               SELECT evaluation_id, node_id, computed_at AS ts,
                      row_number() OVER (
                        ORDER BY computed_at DESC, evaluation_id DESC, node_id DESC
                      ) AS rn
               FROM ocfleet_native.health_history
             ), doomed AS (
               SELECT evaluation_id, node_id FROM ranked
               WHERE ($1::timestamptz IS NOT NULL AND ts < $1)
                  OR ($2::bigint IS NOT NULL AND rn > $2)
               ORDER BY ts, evaluation_id, node_id LIMIT $3
             )
             DELETE FROM ocfleet_native.health_history target USING doomed
             WHERE target.evaluation_id = doomed.evaluation_id
               AND target.node_id = doomed.node_id
             RETURNING target.evaluation_id"
        }
        "health-rollups" => {
            "WITH ranked AS (
               SELECT node_id, bucket_seconds, bucket_start AS ts,
                      row_number() OVER (
                        ORDER BY bucket_start DESC, node_id DESC, bucket_seconds DESC
                      ) AS rn
               FROM ocfleet_native.health_rollups
             ), doomed AS (
               SELECT node_id, bucket_seconds, ts FROM ranked
               WHERE ($1::timestamptz IS NOT NULL AND ts < $1)
                  OR ($2::bigint IS NOT NULL AND rn > $2)
               ORDER BY ts, node_id, bucket_seconds LIMIT $3
             )
             DELETE FROM ocfleet_native.health_rollups target USING doomed
             WHERE target.node_id = doomed.node_id
               AND target.bucket_seconds = doomed.bucket_seconds
               AND target.bucket_start = doomed.ts
             RETURNING target.node_id"
        }
        "alert-events" => {
            "WITH ranked AS (
               SELECT a.alert_id AS id, a.last_seen_at AS ts,
                      row_number() OVER (
                        ORDER BY a.last_seen_at DESC, a.alert_id DESC
                      ) AS rn
               FROM ocfleet_native.alert_events a
               WHERE NOT EXISTS (
                 SELECT 1 FROM ocfleet_native.alert_delivery_queue q
                 WHERE q.alert_id = a.alert_id AND q.status = 'claimed'
               )
             ), doomed AS (
               SELECT id FROM ranked
               WHERE ($1::timestamptz IS NOT NULL AND ts < $1)
                  OR ($2::bigint IS NOT NULL AND rn > $2)
               ORDER BY ts, id LIMIT $3
             )
             DELETE FROM ocfleet_native.alert_events target
             USING doomed WHERE target.alert_id = doomed.id RETURNING target.alert_id"
        }
        _ => {
            return Err(PostgresError::InvalidInput(
                "invalid retention scope".into(),
            ));
        }
    };
    let rows = tx.query(sql, &[&cutoff, &max_rows, &limit])?;
    u64::try_from(rows.len())
        .map_err(|_| PostgresError::InvalidState("retention batch count overflow".into()))
}

fn retention_input_json(input: &RetentionApplyInput) -> Value {
    json!({
        "scope": input.scope,
        "cutoff": input.cutoff,
        "max_age_days": input.max_age_days,
        "max_rows": input.max_rows,
        "limit": input.limit,
        "batch_size": input.batch_size,
    })
}

fn retention_result_json(result: &RetentionApplyResult) -> Value {
    json!({
        "cutoff": result.cutoff,
        "matched_count": result.candidate_report.matched_count,
        "oldest_timestamp": result.candidate_report.oldest_timestamp,
        "newest_timestamp": result.candidate_report.newest_timestamp,
        "planned_delete_count": result.planned_delete_count,
        "rows_deleted": result.rows_deleted,
        "batch_count": result.batch_count,
    })
}

fn retention_operation_conflict(operation_id: &str) -> PostgresError {
    PostgresError::Store(StoreError::RetentionOperationConflict {
        operation_id: operation_id.to_string(),
        detail: "operation provenance does not match the original request",
    })
}

fn retention_result_from_json(
    encoded: &str,
    operation_id: &str,
) -> Result<RetentionApplyResult, PostgresError> {
    let value: Value =
        serde_json::from_str(encoded).map_err(|_| retention_operation_conflict(operation_id))?;
    let read_u64 = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_u64)
            .ok_or_else(|| retention_operation_conflict(operation_id))
    };
    let read_optional = |key: &str| -> Result<Option<String>, PostgresError> {
        match value.get(key) {
            Some(Value::Null) => Ok(None),
            Some(Value::String(value)) => Ok(Some(value.clone())),
            _ => Err(retention_operation_conflict(operation_id)),
        }
    };
    Ok(RetentionApplyResult {
        cutoff: read_optional("cutoff")?,
        candidate_report: RetentionCandidateReport {
            matched_count: read_u64("matched_count")?,
            oldest_timestamp: read_optional("oldest_timestamp")?,
            newest_timestamp: read_optional("newest_timestamp")?,
        },
        planned_delete_count: read_u64("planned_delete_count")?,
        rows_deleted: read_u64("rows_deleted")?,
        batch_count: read_u64("batch_count")?,
    })
}

fn parse_postgres_timestamp(value: &str, field: &str) -> Result<OffsetDateTime, PostgresError> {
    if value.is_empty() || value.len() > 64 {
        return Err(PostgresError::InvalidInput(format!(
            "{field} must be bounded RFC3339"
        )));
    }
    let parsed = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| PostgresError::InvalidInput(format!("{field} must be bounded RFC3339")))?;
    parsed
        .replace_nanosecond((parsed.nanosecond() / 1_000) * 1_000)
        .map_err(|_| {
            PostgresError::InvalidInput(format!(
                "{field} cannot be represented at Postgres microsecond precision"
            ))
        })
}

fn format_postgres_timestamp(value: OffsetDateTime, field: &str) -> Result<String, PostgresError> {
    let value = value
        .replace_nanosecond((value.nanosecond() / 1_000) * 1_000)
        .map_err(|_| PostgresError::InvalidState(format!("native {field} is invalid")))?;
    value
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|_| PostgresError::InvalidState(format!("native {field} is invalid")))
}

fn postgres_timestamps_equal(left: &str, right: &str) -> bool {
    matches!(
        (
            parse_postgres_timestamp(left, "timestamp"),
            parse_postgres_timestamp(right, "timestamp"),
        ),
        (Ok(left), Ok(right)) if left == right
    )
}

fn get_node_tx(
    tx: &mut Transaction<'_>,
    node_id: &str,
) -> Result<Option<NodeRecord>, PostgresError> {
    tx.query_opt(
        "SELECT node_id, endpoint_id, name, region, role, enabled
         FROM ocfleet_native.nodes WHERE node_id = $1 FOR UPDATE",
        &[&node_id],
    )?
    .map(|row| node_from_row(&row))
    .transpose()
}

fn get_node_metadata_conn<C: GenericClient>(
    conn: &mut C,
    node_id: &str,
) -> Result<Option<NodeMetadataRecord>, PostgresError> {
    conn.query_opt(
        "SELECT node_id, environment, site, owner_team, service_tier,
                labels_json::text, expected_agent_version, updated_at
         FROM ocfleet_native.node_metadata WHERE node_id = $1",
        &[&node_id],
    )?
    .map(|row| node_metadata_from_row(&row))
    .transpose()
}

fn get_node_metadata_tx(
    tx: &mut Transaction<'_>,
    node_id: &str,
) -> Result<Option<NodeMetadataRecord>, PostgresError> {
    get_node_metadata_conn(tx, node_id)
}

fn node_metadata_from_row(row: &postgres::Row) -> Result<NodeMetadataRecord, PostgresError> {
    let labels: String = row.try_get(5)?;
    let labels_json = serde_json::from_str(&labels)
        .map_err(|_| PostgresError::InvalidState("native node metadata JSON is invalid".into()))?;
    validate_low_sensitive_json(&labels_json, "native node metadata labels")?;
    Ok(NodeMetadataRecord {
        node_id: row.try_get(0)?,
        environment: row.try_get(1)?,
        site: row.try_get(2)?,
        owner_team: row.try_get(3)?,
        service_tier: row.try_get(4)?,
        labels_json,
        expected_agent_version: row.try_get(6)?,
        updated_at: format_postgres_timestamp(row.try_get(7)?, "node metadata updated_at")?,
    })
}

fn node_maintenance_from_row(row: &postgres::Row) -> Result<NodeMaintenanceWindow, PostgresError> {
    Ok(NodeMaintenanceWindow {
        node_id: row.try_get(0)?,
        starts_at: format_postgres_timestamp(row.try_get(1)?, "node maintenance starts_at")?,
        ends_at: format_postgres_timestamp(row.try_get(2)?, "node maintenance ends_at")?,
        reason: row.try_get(3)?,
        updated_at: format_postgres_timestamp(row.try_get(4)?, "node maintenance updated_at")?,
    })
}

fn capability_from_row(row: &postgres::Row) -> Result<CapabilitySnapshot, PostgresError> {
    capability_from_offset_row(row, 0)
}

fn capability_from_offset_row(
    row: &postgres::Row,
    offset: usize,
) -> Result<CapabilitySnapshot, PostgresError> {
    let status: String = row.try_get(offset + 3)?;
    let status = match status.as_str() {
        "compatible" => CapabilityNegotiationStatus::Compatible,
        "incompatible_protocol" => CapabilityNegotiationStatus::IncompatibleProtocol,
        "unsupported_capability" => CapabilityNegotiationStatus::UnsupportedCapability,
        "legacy_unsupported" => CapabilityNegotiationStatus::LegacyUnsupported,
        "invalid_response" => CapabilityNegotiationStatus::InvalidResponse,
        _ => {
            return Err(PostgresError::InvalidState(
                "native capability status is invalid".to_string(),
            ));
        }
    };
    let snapshot = CapabilitySnapshot {
        node_id: row.try_get(offset)?,
        endpoint_id: row.try_get(offset + 1)?,
        observed_at: format_postgres_timestamp(row.try_get(offset + 2)?, "capability observed_at")?,
        status,
        agent_version: row.try_get(offset + 4)?,
        protocol_min: optional_i32_to_u32(row.try_get(offset + 5)?)?,
        protocol_max: optional_i32_to_u32(row.try_get(offset + 6)?)?,
        ocserv_snapshot_min: optional_i32_to_u32(row.try_get(offset + 7)?)?,
        ocserv_snapshot_max: optional_i32_to_u32(row.try_get(offset + 8)?)?,
        controlled_writes_compiled: row.try_get(offset + 9)?,
        controlled_writes_locally_enabled: row.try_get(offset + 10)?,
    };
    snapshot
        .validate()
        .map_err(|error| PostgresError::InvalidState(format!("native {error}")))?;
    Ok(snapshot)
}

fn optional_u32_to_i32(value: Option<u32>) -> Result<Option<i32>, PostgresError> {
    value
        .map(i32::try_from)
        .transpose()
        .map_err(|_| PostgresError::InvalidInput("capability version exceeds i32".to_string()))
}

fn optional_i32_to_u32(value: Option<i32>) -> Result<Option<u32>, PostgresError> {
    value
        .map(u32::try_from)
        .transpose()
        .map_err(|_| PostgresError::InvalidState("native capability version is invalid".into()))
}

fn json_detail(
    target_type: &str,
    target_id: &str,
    before: Option<Value>,
    after: Option<Value>,
    reason: Option<&str>,
) -> Value {
    json!({
        "actor_type": "user",
        "target_type": target_type,
        "target_id": target_id,
        "before": before,
        "after": after,
        "reason": reason,
    })
}

fn node_metadata_audit_json(metadata: &NodeMetadataRecord) -> Value {
    json!({
        "environment": metadata.environment,
        "site": metadata.site,
        "owner_team": metadata.owner_team,
        "service_tier": metadata.service_tier,
        "labels": metadata.labels_json,
        "expected_agent_version": metadata.expected_agent_version,
    })
}

fn get_endpoint_trust_conn<C: GenericClient>(
    conn: &mut C,
    endpoint_id: &str,
    for_update: bool,
) -> Result<Option<EndpointTrustRecord>, PostgresError> {
    let sql = if for_update {
        "SELECT endpoint_id, node_id, fingerprint, status, generation,
                previous_endpoint_id, rotated_to, trust_bundle_json::text,
                created_at, updated_at
         FROM ocfleet_native.endpoint_trust WHERE endpoint_id = $1 FOR UPDATE"
    } else {
        "SELECT endpoint_id, node_id, fingerprint, status, generation,
                previous_endpoint_id, rotated_to, trust_bundle_json::text,
                created_at, updated_at
         FROM ocfleet_native.endpoint_trust WHERE endpoint_id = $1"
    };
    conn.query_opt(sql, &[&endpoint_id])?
        .map(|row| endpoint_trust_from_row(&row))
        .transpose()
}

fn get_endpoint_trust_tx(
    tx: &mut Transaction<'_>,
    endpoint_id: &str,
) -> Result<Option<EndpointTrustRecord>, PostgresError> {
    get_endpoint_trust_conn(tx, endpoint_id, true)
}

fn endpoint_trust_from_row(row: &postgres::Row) -> Result<EndpointTrustRecord, PostgresError> {
    let endpoint_id: String = row.try_get(0)?;
    let status_text: String = row.try_get(3)?;
    let status = EndpointStatus::from_str(&status_text)
        .map_err(|_| PostgresError::InvalidState("native endpoint status is invalid".into()))?;
    let generation_i64: i64 = row.try_get(4)?;
    let generation = u64::try_from(generation_i64).map_err(|_| {
        PostgresError::InvalidState("native endpoint generation is invalid".to_string())
    })?;
    let payload_text: String = row.try_get(7)?;
    let payload_value: Value = serde_json::from_str(&payload_text)
        .map_err(|_| PostgresError::InvalidState("native trust payload JSON is invalid".into()))?;
    let payload = TrustBundlePayloadV1::from_value(&payload_value)
        .map_err(|error| PostgresError::InvalidState(format!("native trust payload: {error}")))?;
    payload
        .validate_relationship(&endpoint_id, generation, status.as_str())
        .map_err(|error| PostgresError::InvalidState(format!("native trust payload: {error}")))?;
    Ok(EndpointTrustRecord {
        endpoint_id,
        node_id: row.try_get(1)?,
        fingerprint: row.try_get(2)?,
        status,
        generation,
        previous_endpoint_id: row.try_get(5)?,
        rotated_to: row.try_get(6)?,
        trust_bundle_json: payload.public_bundle(),
        created_at: format_postgres_timestamp(row.try_get(8)?, "endpoint created_at")?,
        updated_at: format_postgres_timestamp(row.try_get(9)?, "endpoint updated_at")?,
    })
}

fn trust_payload(
    endpoint_id: &str,
    generation: u64,
    status: EndpointStatus,
) -> Result<Value, PostgresError> {
    Ok(TrustBundlePayloadV1::new(
        endpoint_id.to_string(),
        generation,
        status.as_str().to_string(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .map_err(PostgresError::InvalidInput)?
    .to_value())
}

fn transition_endpoint_status_tx(
    tx: &mut Transaction<'_>,
    before: &EndpointTrustRecord,
    status: EndpointStatus,
) -> Result<EndpointTrustRecord, PostgresError> {
    let generation = before.generation.checked_add(1).ok_or_else(|| {
        PostgresError::InvalidState("native endpoint generation exhausted".to_string())
    })?;
    let generation_i64 = i64::try_from(generation).map_err(|_| {
        PostgresError::InvalidState("native endpoint generation exceeds i64".to_string())
    })?;
    let payload = trust_payload(&before.endpoint_id, generation, status)?;
    tx.execute(
        "UPDATE ocfleet_native.endpoint_trust
         SET status = $1, generation = $2, trust_bundle_json = CAST($3 AS text)::jsonb,
             updated_at = clock_timestamp()
         WHERE endpoint_id = $4",
        &[
            &status.as_str(),
            &generation_i64,
            &payload.to_string(),
            &before.endpoint_id,
        ],
    )?;
    get_endpoint_trust_tx(tx, &before.endpoint_id)?.ok_or_else(|| {
        PostgresError::InvalidState("native endpoint disappeared during transition".to_string())
    })
}

fn endpoint_audit_json(endpoint: &EndpointTrustRecord) -> Value {
    json!({
        "endpoint_id": endpoint.endpoint_id,
        "node_id": endpoint.node_id,
        "fingerprint_present": endpoint.fingerprint.is_some(),
        "status": endpoint.status.as_str(),
        "generation": endpoint.generation,
        "previous_endpoint_id": endpoint.previous_endpoint_id,
        "rotated_to": endpoint.rotated_to,
    })
}

fn enrollment_metadata_payload(
    kind: EnrollmentMetadataKindV1,
    value: &Value,
) -> Result<Value, PostgresError> {
    EnrollmentMetadataPayloadV1::new(kind, value)
        .map(|payload| payload.to_value())
        .map_err(PostgresError::InvalidInput)
}

fn validate_enrollment_token_id(token_id: &str) -> Result<(), PostgresError> {
    if token_id.len() < 5
        || token_id.len() > 128
        || !token_id.starts_with("tok-")
        || !token_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(PostgresError::InvalidInput(
            "enrollment token id must be a bounded tok- identifier".to_string(),
        ));
    }
    Ok(())
}

fn validate_enrollment_request_id(request_id: &str) -> Result<(), PostgresError> {
    let Some(uuid) = request_id.strip_prefix("join-") else {
        return Err(PostgresError::InvalidInput(
            "join request id must use join-<uuid>".to_string(),
        ));
    };
    Uuid::parse_str(uuid)
        .map(|_| ())
        .map_err(|_| PostgresError::InvalidInput("join request id must contain a UUID".into()))
}

fn validate_enrollment_token_input(token: &EnrollmentTokenInsert) -> Result<(), PostgresError> {
    validate_enrollment_token_id(&token.token_id)?;
    if token.token_hash.len() != 64
        || !token
            .token_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PostgresError::InvalidInput(
            "enrollment token hash must be lowercase BLAKE3 hex".to_string(),
        ));
    }
    parse_postgres_timestamp(&token.expires_at, "enrollment token expires_at")?;
    if token.max_uses == 0 || token.max_uses > MAX_ENROLLMENT_TOKEN_USES {
        return Err(PostgresError::InvalidInput(format!(
            "enrollment token max uses must be 1-{MAX_ENROLLMENT_TOKEN_USES}"
        )));
    }
    Ok(())
}

fn validate_enrollment_token_plaintext(token: &str) -> Result<(), PostgresError> {
    if token.is_empty() || token.len() > 512 || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(PostgresError::InvalidInput(
            "enrollment token must be bounded ASCII without whitespace".to_string(),
        ));
    }
    Ok(())
}

fn get_enrollment_token_conn<C: GenericClient>(
    conn: &mut C,
    token_id: &str,
    for_update: bool,
) -> Result<Option<EnrollmentTokenRecord>, PostgresError> {
    let sql = if for_update {
        "SELECT token_id, token_hash, created_at, created_by, expires_at,
                max_uses, used_count, status, description, labels_json::text, scope_json::text
         FROM ocfleet_native.enrollment_tokens WHERE token_id = $1 FOR UPDATE"
    } else {
        "SELECT token_id, token_hash, created_at, created_by, expires_at,
                max_uses, used_count, status, description, labels_json::text, scope_json::text
         FROM ocfleet_native.enrollment_tokens WHERE token_id = $1"
    };
    conn.query_opt(sql, &[&token_id])?
        .map(|row| enrollment_token_from_row(&row))
        .transpose()
}

fn get_enrollment_token_tx(
    tx: &mut Transaction<'_>,
    token_id: &str,
) -> Result<Option<EnrollmentTokenRecord>, PostgresError> {
    get_enrollment_token_conn(tx, token_id, true)
}

fn get_enrollment_token_by_hash_tx(
    tx: &mut Transaction<'_>,
    token_hash: &str,
) -> Result<Option<EnrollmentTokenRecord>, PostgresError> {
    tx.query_opt(
        "SELECT token_id, token_hash, created_at, created_by, expires_at,
                max_uses, used_count, status, description, labels_json::text, scope_json::text
         FROM ocfleet_native.enrollment_tokens WHERE token_hash = $1 FOR UPDATE",
        &[&token_hash],
    )?
    .map(|row| enrollment_token_from_row(&row))
    .transpose()
}

fn enrollment_token_from_row(row: &postgres::Row) -> Result<EnrollmentTokenRecord, PostgresError> {
    let status_text: String = row.try_get(7)?;
    let status = EnrollmentTokenStatus::from_str(&status_text).map_err(|_| {
        PostgresError::InvalidState("native enrollment token status is invalid".to_string())
    })?;
    let labels = enrollment_metadata_from_text(
        &row.try_get::<_, String>(9)?,
        EnrollmentMetadataKindV1::TokenLabels,
    )?;
    let scope = enrollment_metadata_from_text(
        &row.try_get::<_, String>(10)?,
        EnrollmentMetadataKindV1::TokenScope,
    )?;
    Ok(EnrollmentTokenRecord {
        token_id: row.try_get(0)?,
        token_hash: row.try_get(1)?,
        created_at: format_postgres_timestamp(row.try_get(2)?, "enrollment token created_at")?,
        created_by: row.try_get(3)?,
        expires_at: format_postgres_timestamp(row.try_get(4)?, "enrollment token expires_at")?,
        max_uses: u32::try_from(row.try_get::<_, i32>(5)?).map_err(|_| {
            PostgresError::InvalidState("native enrollment max uses is invalid".into())
        })?,
        used_count: u32::try_from(row.try_get::<_, i32>(6)?).map_err(|_| {
            PostgresError::InvalidState("native enrollment used count is invalid".into())
        })?,
        status,
        description: row.try_get(8)?,
        labels_json: labels,
        scope_json: scope,
    })
}

fn enrollment_metadata_from_text(
    text: &str,
    kind: EnrollmentMetadataKindV1,
) -> Result<Value, PostgresError> {
    let value = serde_json::from_str(text)
        .map_err(|_| PostgresError::InvalidState("native enrollment JSON is invalid".into()))?;
    EnrollmentMetadataPayloadV1::from_value(kind, &value)
        .map(|payload| payload.public_value())
        .map_err(|error| PostgresError::InvalidState(format!("native enrollment JSON: {error}")))
}

fn get_join_request_conn<C: GenericClient>(
    conn: &mut C,
    request_id: &str,
    for_update: bool,
) -> Result<Option<JoinRequestRecord>, PostgresError> {
    let sql = if for_update {
        "SELECT request_id, token_id, status, agent_public_key, fingerprint,
                requested_endpoint_id, assigned_endpoint_id, hostname, agent_version,
                requested_labels_json::text, approved_labels_json::text, created_at, approved_at,
                approved_by, rejection_reason, audit_correlation_id
         FROM ocfleet_native.join_requests WHERE request_id = $1 FOR UPDATE"
    } else {
        "SELECT request_id, token_id, status, agent_public_key, fingerprint,
                requested_endpoint_id, assigned_endpoint_id, hostname, agent_version,
                requested_labels_json::text, approved_labels_json::text, created_at, approved_at,
                approved_by, rejection_reason, audit_correlation_id
         FROM ocfleet_native.join_requests WHERE request_id = $1"
    };
    conn.query_opt(sql, &[&request_id])?
        .map(|row| join_request_from_row(&row))
        .transpose()
}

fn get_join_request_tx(
    tx: &mut Transaction<'_>,
    request_id: &str,
) -> Result<Option<JoinRequestRecord>, PostgresError> {
    get_join_request_conn(tx, request_id, true)
}

fn join_request_from_row(row: &postgres::Row) -> Result<JoinRequestRecord, PostgresError> {
    let status_text: String = row.try_get(2)?;
    let status = JoinRequestStatus::from_str(&status_text).map_err(|_| {
        PostgresError::InvalidState("native join request status is invalid".to_string())
    })?;
    let requested_labels = enrollment_metadata_from_text(
        &row.try_get::<_, String>(9)?,
        EnrollmentMetadataKindV1::RequestedLabels,
    )?;
    let approved_labels = enrollment_metadata_from_text(
        &row.try_get::<_, String>(10)?,
        EnrollmentMetadataKindV1::ApprovedLabels,
    )?;
    if status != JoinRequestStatus::Approved
        && approved_labels
            .as_object()
            .is_some_and(|labels| !labels.is_empty())
    {
        return Err(PostgresError::InvalidState(
            "native unapproved join request contains approved labels".to_string(),
        ));
    }
    Ok(JoinRequestRecord {
        request_id: row.try_get(0)?,
        token_id: row.try_get(1)?,
        status,
        agent_public_key: row.try_get(3)?,
        fingerprint: row.try_get(4)?,
        requested_endpoint_id: row.try_get(5)?,
        assigned_endpoint_id: row.try_get(6)?,
        hostname: row.try_get(7)?,
        agent_version: row.try_get(8)?,
        requested_labels_json: requested_labels,
        approved_labels_json: approved_labels,
        created_at: format_postgres_timestamp(row.try_get(11)?, "join request created_at")?,
        approved_at: row
            .try_get::<_, Option<OffsetDateTime>>(12)?
            .map(|value| format_postgres_timestamp(value, "join request approved_at"))
            .transpose()?,
        approved_by: row.try_get(13)?,
        rejection_reason: row.try_get(14)?,
        audit_correlation_id: row.try_get(15)?,
    })
}

fn enrollment_token_matches(
    existing: &EnrollmentTokenRecord,
    requested: &EnrollmentTokenInsert,
    actor: &str,
) -> bool {
    existing.token_id == requested.token_id
        && existing.token_hash == requested.token_hash
        && existing.created_by == actor
        && postgres_timestamps_equal(&existing.expires_at, &requested.expires_at)
        && existing.max_uses == requested.max_uses
        && existing.description == requested.description
        && existing.labels_json == requested.labels_json
        && existing.scope_json == requested.scope_json
}

fn join_request_matches(
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

fn token_is_expired(expires_at: &str) -> bool {
    parse_postgres_timestamp(expires_at, "enrollment token expires_at")
        .map(|expires| expires <= OffsetDateTime::now_utc())
        .unwrap_or(true)
}

fn invalid_enrollment_binding(request_id: &str, detail: &str) -> PostgresError {
    PostgresError::InvalidState(format!(
        "native enrollment binding {request_id} is invalid: {detail}"
    ))
}

fn get_node_by_endpoint_tx(
    tx: &mut Transaction<'_>,
    endpoint_id: &str,
) -> Result<Option<NodeRecord>, PostgresError> {
    tx.query_opt(
        "SELECT node_id, endpoint_id, name, region, role, enabled
         FROM ocfleet_native.nodes WHERE endpoint_id = $1 FOR UPDATE",
        &[&endpoint_id],
    )?
    .map(|row| node_from_row(&row))
    .transpose()
}

fn get_active_endpoint_trust_for_node_tx(
    tx: &mut Transaction<'_>,
    node_id: &str,
) -> Result<Vec<EndpointTrustRecord>, PostgresError> {
    tx.query(
        "SELECT endpoint_id, node_id, fingerprint, status, generation,
                previous_endpoint_id, rotated_to, trust_bundle_json::text,
                created_at, updated_at
         FROM ocfleet_native.endpoint_trust
         WHERE node_id = $1 AND status = 'active'
         ORDER BY endpoint_id LIMIT 2 FOR UPDATE",
        &[&node_id],
    )?
    .iter()
    .map(endpoint_trust_from_row)
    .collect()
}

fn endpoint_trust_count_for_node_tx(
    tx: &mut Transaction<'_>,
    node_id: &str,
) -> Result<i64, PostgresError> {
    Ok(tx
        .query_one(
            "SELECT COUNT(*) FROM ocfleet_native.endpoint_trust WHERE node_id = $1",
            &[&node_id],
        )?
        .try_get(0)?)
}

fn approved_join_assignment_count_tx(
    tx: &mut Transaction<'_>,
    endpoint_id: &str,
) -> Result<i64, PostgresError> {
    Ok(tx
        .query_one(
            "SELECT COUNT(*) FROM ocfleet_native.join_requests
             WHERE status = 'approved' AND assigned_endpoint_id = $1",
            &[&endpoint_id],
        )?
        .try_get(0)?)
}

fn validate_enrollment_token_audit_provenance_tx(
    tx: &mut Transaction<'_>,
    event: &str,
    token_id: &str,
    actor: &str,
    reason: Option<&str>,
) -> Result<(), PostgresError> {
    let count: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM ocfleet_native.controller_audit_log
             WHERE event = $1 AND ok = TRUE
               AND detail_json->>'target_id' = $2
               AND actor = $3
               AND ($4::text IS NULL OR detail_json->>'reason' = $4)",
            &[&event, &token_id, &actor, &reason],
        )?
        .try_get(0)?;
    if count != 1 {
        return Err(PostgresError::InvalidState(
            "native enrollment token audit provenance is missing or ambiguous".to_string(),
        ));
    }
    Ok(())
}

fn validate_join_submission_audit_provenance_tx(
    tx: &mut Transaction<'_>,
    join: &JoinRequestRecord,
    actor: &str,
) -> Result<(), PostgresError> {
    let count: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM ocfleet_native.controller_audit_log
             WHERE event = 'enrollment.token.use'
               AND request_id = $1 AND ok = TRUE
               AND detail_json->>'target_id' = $1
               AND actor = $2",
            &[&join.request_id, &actor],
        )?
        .try_get(0)?;
    if count != 1 {
        return Err(PostgresError::InvalidState(format!(
            "native enrollment request {} submission audit provenance is missing or ambiguous",
            join.request_id
        )));
    }
    Ok(())
}

fn validate_join_rejection_audit_provenance_tx(
    tx: &mut Transaction<'_>,
    request_id: &str,
    actor: &str,
    reason: &str,
) -> Result<(), PostgresError> {
    let count: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM ocfleet_native.controller_audit_log
             WHERE event = 'enrollment.reject'
               AND request_id = $1 AND ok = TRUE
               AND detail_json->>'target_id' = $1
               AND actor = $2 AND detail_json->>'reason' = $3",
            &[&request_id, &actor, &reason],
        )?
        .try_get(0)?;
    if count != 1 {
        return Err(PostgresError::InvalidState(format!(
            "native enrollment request {request_id} rejection audit provenance is missing or ambiguous"
        )));
    }
    Ok(())
}

fn validate_approved_join_audit_provenance_tx(
    tx: &mut Transaction<'_>,
    join: &JoinRequestRecord,
    endpoint_id: &str,
    node_id: Option<&str>,
) -> Result<(), PostgresError> {
    let count: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM ocfleet_native.controller_audit_log
             WHERE event = 'enrollment.approve'
               AND request_id = $1 AND endpoint_id = $2
               AND actor = $3 AND ok = TRUE
               AND node_id IS NOT DISTINCT FROM $4
               AND detail_json->>'target_id' = $1",
            &[&join.request_id, &endpoint_id, &join.approved_by, &node_id],
        )?
        .try_get(0)?;
    if count != 1 {
        return Err(invalid_enrollment_binding(
            &join.request_id,
            "approval audit provenance is missing or ambiguous",
        ));
    }
    Ok(())
}

fn validate_enrollment_claim_audit_provenance_tx(
    tx: &mut Transaction<'_>,
    join: &JoinRequestRecord,
    endpoint_id: &str,
    node_id: &str,
    actor: &str,
    reason: &str,
) -> Result<(), PostgresError> {
    let count: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM ocfleet_native.controller_audit_log
             WHERE event = 'enrollment.claim'
               AND request_id = $1 AND endpoint_id = $2 AND node_id = $3
               AND actor = $4 AND ok = TRUE
               AND detail_json->>'target_id' = $1
               AND detail_json->>'reason' = $5",
            &[&join.request_id, &endpoint_id, &node_id, &actor, &reason],
        )?
        .try_get(0)?;
    if count != 1 {
        return Err(invalid_enrollment_binding(
            &join.request_id,
            "claim retry audit provenance is missing or ambiguous",
        ));
    }
    Ok(())
}

fn validate_pending_join_for_approval(join: &JoinRequestRecord) -> Result<(), PostgresError> {
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
        return Err(invalid_enrollment_binding(
            &join.request_id,
            "pending join request has decision metadata",
        ));
    }
    validate_agent_public_key(&join.agent_public_key).map_err(|_| {
        invalid_enrollment_binding(&join.request_id, "stored public key is invalid")
    })?;
    validate_agent_fingerprint(&join.fingerprint).map_err(|_| {
        invalid_enrollment_binding(&join.request_id, "stored fingerprint is invalid")
    })?;
    validate_hostname(&join.hostname)
        .map_err(|_| invalid_enrollment_binding(&join.request_id, "stored hostname is invalid"))?;
    validate_agent_version(&join.agent_version).map_err(|_| {
        invalid_enrollment_binding(&join.request_id, "stored agent version is invalid")
    })?;
    validate_label_json(&join.requested_labels_json, "requested_labels").map_err(|_| {
        invalid_enrollment_binding(&join.request_id, "stored requested labels are invalid")
    })?;
    Ok(())
}

fn validate_approved_join_provenance_tx(
    tx: &mut Transaction<'_>,
    join: &JoinRequestRecord,
    endpoint_id: &str,
) -> Result<(), PostgresError> {
    if join.status != JoinRequestStatus::Approved
        || join.assigned_endpoint_id.as_deref() != Some(endpoint_id)
        || join
            .requested_endpoint_id
            .as_deref()
            .is_some_and(|requested| requested != endpoint_id)
    {
        return Err(invalid_enrollment_binding(
            &join.request_id,
            "approved endpoint provenance does not match",
        ));
    }
    let approved_by = join.approved_by.as_deref().ok_or_else(|| {
        invalid_enrollment_binding(&join.request_id, "approval metadata is incomplete")
    })?;
    if validate_actor(approved_by).is_err()
        || join
            .approved_at
            .as_deref()
            .is_none_or(|value| parse_postgres_timestamp(value, "approved_at").is_err())
        || join.rejection_reason.is_some()
    {
        return Err(invalid_enrollment_binding(
            &join.request_id,
            "approval metadata is invalid",
        ));
    }
    validate_agent_fingerprint(&join.fingerprint).map_err(|_| {
        invalid_enrollment_binding(&join.request_id, "stored fingerprint is invalid")
    })?;
    validate_label_json(&join.approved_labels_json, "approved_labels")
        .map_err(|_| invalid_enrollment_binding(&join.request_id, "approved labels are invalid"))?;
    if approved_join_assignment_count_tx(tx, endpoint_id)? != 1 {
        return Err(invalid_enrollment_binding(
            &join.request_id,
            "approved endpoint assignment is ambiguous",
        ));
    }
    Ok(())
}

fn empty_trust_bundle(
    endpoint_id: &str,
    generation: u64,
    status: EndpointStatus,
) -> Result<Value, PostgresError> {
    Ok(TrustBundlePayloadV1::new(
        endpoint_id.to_string(),
        generation,
        status.as_str().to_string(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .map_err(PostgresError::InvalidInput)?
    .public_bundle())
}

fn validate_endpoint_bundle_projection(
    endpoint: &EndpointTrustRecord,
) -> Result<(), PostgresError> {
    let bundle: TrustBundle =
        serde_json::from_value(endpoint.trust_bundle_json.clone()).map_err(|_| {
            PostgresError::InvalidState("native endpoint trust bundle is invalid".into())
        })?;
    if bundle.endpoint_id != endpoint.endpoint_id
        || bundle.generation != endpoint.generation
        || bundle.status != endpoint.status
    {
        return Err(PostgresError::InvalidState(
            "native endpoint trust bundle projection is inconsistent".to_string(),
        ));
    }
    Ok(())
}

fn validate_enrollment_endpoint_origin(
    join: &JoinRequestRecord,
    endpoint: &EndpointTrustRecord,
    request_id: &str,
) -> Result<(), PostgresError> {
    if endpoint.endpoint_id != join.assigned_endpoint_id.as_deref().unwrap_or_default()
        || endpoint.status != EndpointStatus::Active
        || endpoint.generation != 1
        || endpoint.previous_endpoint_id.is_some()
        || endpoint.rotated_to.is_some()
        || endpoint.fingerprint.as_deref() != Some(join.fingerprint.as_str())
    {
        return Err(invalid_enrollment_binding(
            request_id,
            "endpoint trust is not an original active enrollment",
        ));
    }
    validate_endpoint_bundle_projection(endpoint).map_err(|_| {
        invalid_enrollment_binding(request_id, "endpoint trust bundle is inconsistent")
    })?;
    if endpoint.trust_bundle_json
        != empty_trust_bundle(&endpoint.endpoint_id, 1, EndpointStatus::Active)?
    {
        return Err(invalid_enrollment_binding(
            request_id,
            "endpoint trust bundle is not the empty enrollment bundle",
        ));
    }
    Ok(())
}

fn validate_exact_enrollment_binding_tx(
    tx: &mut Transaction<'_>,
    join: &JoinRequestRecord,
    endpoint: &EndpointTrustRecord,
    expected_node: &NodeInsert,
    expected_approved_labels: Option<&Value>,
    failure_detail: &str,
) -> Result<(), PostgresError> {
    validate_approved_join_provenance_tx(tx, join, &expected_node.endpoint_id)?;
    validate_enrollment_endpoint_origin(join, endpoint, &join.request_id)?;
    if expected_approved_labels.is_some_and(|expected| expected != &join.approved_labels_json)
        || endpoint.node_id.as_deref() != Some(expected_node.node_id.as_str())
    {
        return Err(invalid_enrollment_binding(&join.request_id, failure_detail));
    }
    let node = get_node_tx(tx, &expected_node.node_id)?
        .ok_or_else(|| invalid_enrollment_binding(&join.request_id, failure_detail))?;
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

fn validate_unrotated_lineage(
    tx: &mut Transaction<'_>,
    endpoint: &EndpointTrustRecord,
) -> Result<(), PostgresError> {
    validate_endpoint_bundle_projection(endpoint)?;
    if endpoint.rotated_to.is_some() {
        return Err(PostgresError::InvalidState(
            "native endpoint lineage is inconsistent".to_string(),
        ));
    }
    let Some(previous_endpoint_id) = endpoint.previous_endpoint_id.as_deref() else {
        return Ok(());
    };
    let previous = get_endpoint_trust_tx(tx, previous_endpoint_id)?.ok_or_else(|| {
        PostgresError::InvalidState("native endpoint rotation predecessor is missing".to_string())
    })?;
    validate_endpoint_bundle_projection(&previous)?;
    if previous.status != EndpointStatus::Rotated
        || previous.rotated_to.as_deref() != Some(endpoint.endpoint_id.as_str())
        || previous.node_id != endpoint.node_id
        || previous.fingerprint != endpoint.fingerprint
        || previous.generation > endpoint.generation
    {
        return Err(PostgresError::InvalidState(
            "native endpoint rotation lineage is inconsistent".to_string(),
        ));
    }
    Ok(())
}

fn validate_rotation_edge(
    tx: &mut Transaction<'_>,
    old: &EndpointTrustRecord,
    new: &EndpointTrustRecord,
) -> Result<(), PostgresError> {
    validate_endpoint_bundle_projection(old)?;
    validate_endpoint_bundle_projection(new)?;
    if old.status != EndpointStatus::Rotated
        || old.rotated_to.as_deref() != Some(new.endpoint_id.as_str())
        || new.previous_endpoint_id.as_deref() != Some(old.endpoint_id.as_str())
        || old.node_id != new.node_id
        || old.fingerprint != new.fingerprint
        || old.generation > new.generation
    {
        return Err(PostgresError::InvalidState(
            "native endpoint rotation lineage is inconsistent".to_string(),
        ));
    }
    if new.status != EndpointStatus::Rotated {
        validate_unrotated_lineage(tx, new)?;
    }
    if let Some(previous_endpoint_id) = old.previous_endpoint_id.as_deref() {
        let previous = get_endpoint_trust_tx(tx, previous_endpoint_id)?.ok_or_else(|| {
            PostgresError::InvalidState(
                "native endpoint rotation predecessor is missing".to_string(),
            )
        })?;
        if previous.status != EndpointStatus::Rotated
            || previous.rotated_to.as_deref() != Some(old.endpoint_id.as_str())
        {
            return Err(PostgresError::InvalidState(
                "native endpoint rotation lineage is inconsistent".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_rotation_binding_tx(
    tx: &mut Transaction<'_>,
    endpoint: &EndpointTrustRecord,
) -> Result<NodeRecord, PostgresError> {
    let node_id = endpoint.node_id.as_deref().ok_or_else(|| {
        PostgresError::InvalidState("native unbound endpoint cannot be rotated".to_string())
    })?;
    let node = get_node_tx(tx, node_id)?.ok_or_else(|| {
        PostgresError::InvalidState("native endpoint bound node is missing".to_string())
    })?;
    if node.endpoint_id != endpoint.endpoint_id {
        return Err(PostgresError::InvalidState(
            "native bound node does not point to the endpoint".to_string(),
        ));
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
        return Err(PostgresError::InvalidState(
            "native node has an inconsistent active endpoint binding".to_string(),
        ));
    }
    Ok(node)
}

fn enrollment_token_audit_json(token: &EnrollmentTokenRecord) -> Value {
    json!({
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

fn enrollment_join_audit_json(join: &JoinRequestRecord) -> Value {
    json!({
        "request_id": join.request_id,
        "status": join.status.as_str(),
        "requested_endpoint_id_present": join.requested_endpoint_id.is_some(),
        "assigned_endpoint_id": join.assigned_endpoint_id,
    })
}

fn enrollment_token_transition_audit_json(
    token_id: &str,
    before: Option<&EnrollmentTokenRecord>,
    after: Option<&EnrollmentTokenRecord>,
    reason: Option<&str>,
) -> Value {
    json!({
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
    json!({
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
    json!({
        "actor_type": "user",
        "target_type": "join_request",
        "target_id": request_id,
        "before": enrollment_join_audit_json(before),
        "after": enrollment_join_audit_json(after),
        "reason": reason,
    })
}

#[allow(clippy::too_many_arguments)]
fn enrollment_binding_audit_json(
    request_id: &str,
    join_before: &JoinRequestRecord,
    join_after: &JoinRequestRecord,
    node_before: Option<&NodeRecord>,
    node_after: Option<&NodeRecord>,
    endpoint_before: Option<&EndpointTrustRecord>,
    endpoint_after: Option<&EndpointTrustRecord>,
    reason: &str,
) -> Value {
    json!({
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
    })
}

fn insert_enrollment_rejection_audit(
    tx: &mut Transaction<'_>,
    actor: &str,
    request_id: &str,
    token_id: Option<&str>,
    reason: &str,
) -> Result<(), PostgresError> {
    let mut event = AuditEvent::new(actor, "enrollment.token.reject");
    event.ok = Some(false);
    event.request_id = Some(request_id.to_string());
    event.error_code = Some("ENROLLMENT_REJECTED".to_string());
    event.detail_json = json!({
        "actor_type": "user",
        "action": "enrollment.token.reject",
        "target_type": "enrollment_token",
        "target_id": token_id,
        "reason": reason,
    });
    insert_audit(tx, &event)
}

fn validate_node(node: &NodeInsert, actor: &str) -> Result<(), PostgresError> {
    validate_actor(actor).map_err(PostgresError::InvalidInput)?;
    validate_node_id(&node.node_id)
        .map_err(|error| PostgresError::InvalidInput(error.to_string()))?;
    validate_endpoint_id(&node.endpoint_id).map_err(PostgresError::InvalidInput)?;
    validate_region(&node.region)
        .map_err(|error| PostgresError::InvalidInput(error.to_string()))?;
    validate_role(&node.role).map_err(|error| PostgresError::InvalidInput(error.to_string()))?;
    if node.name.is_empty()
        || node.name.len() > 128
        || node.name.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(PostgresError::InvalidInput(
            "node name must be a bounded display value".to_string(),
        ));
    }
    Ok(())
}

fn node_from_row(row: &postgres::Row) -> Result<NodeRecord, PostgresError> {
    Ok(NodeRecord {
        node_id: row.try_get(0)?,
        endpoint_id: row.try_get(1)?,
        name: row.try_get(2)?,
        region: row.try_get(3)?,
        role: row.try_get(4)?,
        enabled: row.try_get(5)?,
    })
}

fn node_audit_json(node: &NodeRecord) -> Value {
    json!({
        "node_id": node.node_id,
        "endpoint_id": node.endpoint_id,
        "region": node.region,
        "role": node.role,
        "enabled": node.enabled,
    })
}

fn insert_audit(tx: &mut Transaction<'_>, event: &AuditEvent) -> Result<(), PostgresError> {
    validate_actor(&event.actor).map_err(PostgresError::InvalidInput)?;
    let audit_ts = parse_postgres_timestamp(&event.ts, "audit timestamp")?;
    let canonical_audit_ts = format_postgres_timestamp(audit_ts, "audit timestamp")?;
    validate_low_sensitive_json(&event.detail_json, "audit detail")?;
    let detail = AuditDetailPayloadV1::new(
        canonical_audit_ts,
        event.actor.clone(),
        event.event.clone(),
        event.node_id.clone(),
        event.endpoint_id.clone(),
        event.method.clone(),
        event.request_id.clone(),
        event.params_hash.clone(),
        event.ok,
        event.error_code.clone(),
        event.duration_ms,
        &event.detail_json,
    )
    .map_err(PostgresError::InvalidInput)?;
    let duration_ms = event
        .duration_ms
        .map(i64::try_from)
        .transpose()
        .map_err(|_| PostgresError::InvalidInput("audit duration exceeds i64".to_string()))?;
    tx.execute(
        "INSERT INTO ocfleet_native.controller_audit_log
         (ts, actor, event, node_id, endpoint_id, method, request_id, params_hash,
          ok, error_code, duration_ms, detail_json)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                 CAST($12 AS text)::jsonb)",
        &[
            &audit_ts,
            &event.actor,
            &event.event,
            &event.node_id,
            &event.endpoint_id,
            &event.method,
            &event.request_id,
            &event.params_hash,
            &event.ok,
            &event.error_code,
            &duration_ms,
            &detail.to_value().to_string(),
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validated_native_config;

    #[test]
    fn native_no_tls_rejects_remote_hosts() {
        for dsn in [
            "postgresql://db.example.test/ocfleet",
            "postgresql://203.0.113.10/ocfleet",
            "postgresql://[2001:db8::10]/ocfleet",
        ] {
            assert!(validated_native_config(dsn).is_err(), "accepted {dsn}");
        }
        for dsn in [
            "postgresql://localhost/ocfleet",
            "postgresql://127.0.0.1/ocfleet",
            "postgresql://[::1]/ocfleet",
        ] {
            assert!(validated_native_config(dsn).is_ok(), "rejected {dsn}");
        }
        #[cfg(unix)]
        assert!(
            validated_native_config("postgresql:///ocfleet?host=%2Fvar%2Frun%2Fpostgresql").is_ok()
        );
    }

    #[test]
    fn native_backend_is_not_runtime_selectable_before_contract_parity() {
        for (name, source) in [
            ("args.rs", include_str!("args.rs")),
            ("main.rs", include_str!("main.rs")),
            ("postgres_commands.rs", include_str!("postgres_commands.rs")),
        ] {
            assert!(
                !source.contains("connect_native"),
                "{name} must not expose native Postgres before parity"
            );
        }
    }
}
