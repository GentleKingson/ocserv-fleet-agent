//! Native relational Postgres backend under construction for C1.
//!
//! This module is deliberately not wired into the CLI/runtime until every
//! `StoreReader` and `StoreWriter` contract has native parity. The first slice
//! establishes fail-closed migrations and the atomic node/audit boundary.

use std::fmt;
use std::str::FromStr;

use ocfleet_config::validation::{validate_node_id, validate_region, validate_role};
use ocfleet_protocol::enrollment::{EndpointStatus, EnrollmentTokenStatus, JoinRequestStatus};
use postgres::{Config, GenericClient, NoTls, Transaction};
use r2d2::{Pool, PooledConnection};
use r2d2_postgres::PostgresConnectionManager;
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
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
    AuditDetailPayloadV1, EnrollmentMetadataKindV1, EnrollmentMetadataPayloadV1,
    TrustBundlePayloadV1,
};
use crate::store::{
    ApprovalInput, EndpointTrustRecord, EnrollmentTokenInsert, EnrollmentTokenRecord,
    JoinRequestInsert, JoinRequestRecord, LegacyEnrollmentClaimInput, MAX_ENROLLMENT_TOKEN_USES,
    NodeInsert, NodeMaintenanceWindow, NodeMetadataRecord, NodeRecord, Store, StoreError,
    TrustSnapshot, validate_low_sensitive_json, validate_node_maintenance_record,
    validate_node_metadata_record,
};
use crate::version_governance::{
    CapabilityNegotiationStatus, CapabilitySnapshot, MAX_VERSION_GOVERNANCE_NODES,
    VersionGovernanceInput,
};

type Manager = PostgresConnectionManager<NoTls>;
type Connection = PooledConnection<Manager>;

const MIGRATION_LOCK_ID: i64 = 0x4f43464c4e4154;
const NATIVE_MIGRATION_1_NAME: &str = "0001_native_core";
const NATIVE_MIGRATION_2_NAME: &str = "0002_registry_trust";
pub const NATIVE_BACKEND_SCHEMA_VERSION: i32 = 2;

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
             VALUES ($1, $2, $3, $4, $5, $6, CAST($7 AS text)::jsonb,
                     CAST($8 AS text)::timestamptz)
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
                &metadata.updated_at,
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
             VALUES ($1, CAST($2 AS text)::timestamptz, CAST($3 AS text)::timestamptz,
                     $4, CAST($5 AS text)::timestamptz)
             ON CONFLICT (node_id) DO UPDATE SET
               starts_at = EXCLUDED.starts_at,
               ends_at = EXCLUDED.ends_at,
               reason = EXCLUDED.reason,
               updated_at = EXCLUDED.updated_at",
            &[
                &window.node_id,
                &window.starts_at,
                &window.ends_at,
                &window.reason,
                &window.updated_at,
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
            "SELECT node_id,
                    to_char(starts_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                    to_char(ends_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                    reason,
                    to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
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
        validate_rfc3339(now, "node maintenance check timestamp")?;
        let mut conn = self.connection()?;
        Ok(conn
            .query_one(
                "SELECT EXISTS (
                   SELECT 1 FROM ocfleet_native.node_maintenance_windows
                   WHERE node_id = $1
                     AND starts_at <= CAST($2 AS text)::timestamptz
                     AND CAST($2 AS text)::timestamptz < ends_at
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
        validate_rfc3339(&snapshot.observed_at, "capability observed_at")?;
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
             VALUES ($1, $2, CAST($3 AS text)::timestamptz, $4, $5, $6, $7, $8, $9, $10, $11)
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
                &snapshot.observed_at,
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
            "SELECT node_id, endpoint_id,
                    to_char(observed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                    status, agent_version, protocol_min, protocol_max,
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
                    c.node_id, c.endpoint_id,
                    CASE WHEN c.observed_at IS NULL THEN NULL ELSE
                      to_char(c.observed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') END,
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
        let rows = conn.query(
            "SELECT endpoint_id, node_id, fingerprint, status, generation,
                    previous_endpoint_id, rotated_to, trust_bundle_json::text,
                    to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                    to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
             FROM ocfleet_native.endpoint_trust ORDER BY endpoint_id
             LIMIT $1",
            &[&(MAX_STORE_READER_ROWS as i64)],
        )?;
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
            return get_endpoint_trust_tx(&mut tx, &new_endpoint_id)?.ok_or_else(|| {
                PostgresError::InvalidState(
                    "native endpoint rotation lineage is broken".to_string(),
                )
            });
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
        if old_before.previous_endpoint_id.is_some() && old_before.rotated_to.is_some() {
            return Err(PostgresError::InvalidState(
                "native endpoint lineage is inconsistent".to_string(),
            ));
        }
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
        let node_before = if let Some(node_id) = old_before.node_id.as_deref() {
            get_node_tx(&mut tx, node_id)?
        } else {
            None
        };
        let node_after = if let Some(node) = node_before.as_ref() {
            if node.endpoint_id != old_endpoint_id {
                return Err(PostgresError::InvalidState(
                    "native node endpoint binding is inconsistent".to_string(),
                ));
            }
            let enabled = node.enabled && old_before.status != EndpointStatus::Quarantined;
            tx.execute(
                "UPDATE ocfleet_native.nodes
                 SET endpoint_id = $1, enabled = $2, updated_at = clock_timestamp()
                 WHERE node_id = $3 AND endpoint_id = $4",
                &[&new_endpoint_id, &enabled, &node.node_id, &old_endpoint_id],
            )?;
            get_node_tx(&mut tx, &node.node_id)?
        } else {
            None
        };
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
            "before": {"node": node_before.as_ref().map(node_audit_json), "old_endpoint": endpoint_audit_json(&old_before)},
            "after": {"node": node_after.as_ref().map(node_audit_json), "old_endpoint": endpoint_audit_json(&old_after), "new_endpoint": endpoint_audit_json(&new_after)},
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
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        if let Some(existing) = get_enrollment_token_tx(&mut tx, &token.token_id)? {
            if enrollment_token_matches(&existing, token, actor) {
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
             VALUES ($1, $2, $3, CAST($4 AS text)::timestamptz, $5, 'active', $6,
                     CAST($7 AS text)::jsonb, CAST($8 AS text)::jsonb)",
            &[
                &token.token_id,
                &token.token_hash,
                &actor,
                &token.expires_at,
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
        event.detail_json = json_detail(
            "enrollment_token",
            &token.token_id,
            None,
            Some(enrollment_token_audit_json(&after)),
            None,
        );
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
        event.detail_json = json_detail(
            "enrollment_token",
            token_id,
            Some(enrollment_token_audit_json(&before)),
            Some(enrollment_token_audit_json(&after)),
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
            tx.execute(
                "UPDATE ocfleet_native.enrollment_tokens
                 SET status = 'expired' WHERE token_id = $1 AND status = 'active'",
                &[&token.token_id],
            )?;
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
        let mut event = AuditEvent::new(actor, "enrollment.token.use");
        event.ok = Some(true);
        event.request_id = Some(request.request_id.clone());
        event.detail_json = json_detail(
            "enrollment_token_use",
            &token.token_id,
            Some(json!({"used_count": token.used_count})),
            Some(json!({
                "used_count": token.used_count + 1,
                "request_id": request.request_id,
            })),
            None,
        );
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
        event.detail_json = json_detail(
            "join_request",
            request_id,
            Some(join_request_audit_json(&before)),
            Some(join_request_audit_json(&after)),
            Some(reason),
        );
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
            if before.assigned_endpoint_id.as_deref() == Some(node.endpoint_id.as_str())
                && get_node_tx(&mut tx, &node.node_id)?.is_some()
            {
                return Ok(before);
            }
            return Err(PostgresError::InvalidState(
                "native approved enrollment binding is inconsistent".to_string(),
            ));
        }
        if before.status != JoinRequestStatus::Pending {
            return Err(PostgresError::InvalidState(
                "native join request is not pending".to_string(),
            ));
        }
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
            || get_endpoint_trust_tx(&mut tx, &node.endpoint_id)?.is_some()
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
        let mut event = AuditEvent::new(actor, "enrollment.approve");
        event.ok = Some(true);
        event.request_id = Some(approval.request_id.clone());
        event.node_id = Some(node.node_id.clone());
        event.endpoint_id = Some(node.endpoint_id.clone());
        event.detail_json = json!({
            "actor_type": "user",
            "target_type": "enrollment_binding",
            "target_id": approval.request_id,
            "before": {"join_request": join_request_audit_json(&before), "node": Value::Null, "endpoint": Value::Null},
            "after": {"join_request": join_request_audit_json(&after), "node": node_audit_json(&node_after), "endpoint": endpoint_audit_json(&endpoint_after)},
            "reason": approval.reason,
        });
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
        if join.status != JoinRequestStatus::Approved
            || join.assigned_endpoint_id.as_deref() != Some(node.endpoint_id.as_str())
        {
            return Err(PostgresError::InvalidState(
                "native legacy enrollment is not an approved endpoint binding".to_string(),
            ));
        }
        let endpoint_before =
            get_endpoint_trust_tx(&mut tx, &node.endpoint_id)?.ok_or_else(|| {
                PostgresError::InvalidState("native approved endpoint is missing".to_string())
            })?;
        if endpoint_before.status != EndpointStatus::Active
            || endpoint_before.generation != 1
            || endpoint_before.previous_endpoint_id.is_some()
            || endpoint_before.rotated_to.is_some()
            || endpoint_before.fingerprint.as_deref() != Some(join.fingerprint.as_str())
        {
            return Err(PostgresError::InvalidState(
                "native legacy endpoint origin or lineage is invalid".to_string(),
            ));
        }
        if let Some(bound_node_id) = endpoint_before.node_id.as_deref() {
            if bound_node_id == node.node_id
                && get_node_tx(&mut tx, &node.node_id)?.is_some_and(|existing| {
                    existing.endpoint_id == node.endpoint_id
                        && existing.region == node.region
                        && existing.role == node.role
                })
            {
                return Ok(join);
            }
            return Err(PostgresError::InvalidState(
                "native legacy endpoint is already bound".to_string(),
            ));
        }
        if get_node_tx(&mut tx, &node.node_id)?.is_some() {
            return Err(PostgresError::InvalidState(
                "native legacy node already exists".to_string(),
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
        let mut event = AuditEvent::new(actor, "enrollment.claim");
        event.ok = Some(true);
        event.request_id = Some(claim.request_id.clone());
        event.node_id = Some(node.node_id.clone());
        event.endpoint_id = Some(node.endpoint_id.clone());
        event.detail_json = json!({
            "actor_type": "user",
            "target_type": "enrollment_binding",
            "target_id": claim.request_id,
            "before": {"join_request": join_request_audit_json(&join), "node": Value::Null, "endpoint": endpoint_audit_json(&endpoint_before)},
            "after": {"join_request": join_request_audit_json(&join), "node": node_audit_json(&node_after), "endpoint": endpoint_audit_json(&endpoint_after)},
            "reason": claim.reason,
        });
        insert_audit(&mut tx, &event)?;
        tx.commit()?;
        Ok(join)
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

fn validate_rfc3339(value: &str, field: &str) -> Result<(), PostgresError> {
    if value.is_empty() || value.len() > 64 || OffsetDateTime::parse(value, &Rfc3339).is_err() {
        return Err(PostgresError::InvalidInput(format!(
            "{field} must be bounded RFC3339"
        )));
    }
    Ok(())
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
                labels_json::text, expected_agent_version,
                to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
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
        updated_at: row.try_get(7)?,
    })
}

fn node_maintenance_from_row(row: &postgres::Row) -> Result<NodeMaintenanceWindow, PostgresError> {
    Ok(NodeMaintenanceWindow {
        node_id: row.try_get(0)?,
        starts_at: row.try_get(1)?,
        ends_at: row.try_get(2)?,
        reason: row.try_get(3)?,
        updated_at: row.try_get(4)?,
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
        observed_at: row.try_get(offset + 2)?,
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
                to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
         FROM ocfleet_native.endpoint_trust WHERE endpoint_id = $1 FOR UPDATE"
    } else {
        "SELECT endpoint_id, node_id, fingerprint, status, generation,
                previous_endpoint_id, rotated_to, trust_bundle_json::text,
                to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
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
        created_at: row.try_get(8)?,
        updated_at: row.try_get(9)?,
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
    validate_rfc3339(&token.expires_at, "enrollment token expires_at")?;
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
        "SELECT token_id, token_hash,
                to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                created_by,
                to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                max_uses, used_count, status, description, labels_json::text, scope_json::text
         FROM ocfleet_native.enrollment_tokens WHERE token_id = $1 FOR UPDATE"
    } else {
        "SELECT token_id, token_hash,
                to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                created_by,
                to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
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
        "SELECT token_id, token_hash,
                to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                created_by,
                to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
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
        created_at: row.try_get(2)?,
        created_by: row.try_get(3)?,
        expires_at: row.try_get(4)?,
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
                requested_labels_json::text, approved_labels_json::text,
                to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                CASE WHEN approved_at IS NULL THEN NULL ELSE
                  to_char(approved_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') END,
                approved_by, rejection_reason, audit_correlation_id
         FROM ocfleet_native.join_requests WHERE request_id = $1 FOR UPDATE"
    } else {
        "SELECT request_id, token_id, status, agent_public_key, fingerprint,
                requested_endpoint_id, assigned_endpoint_id, hostname, agent_version,
                requested_labels_json::text, approved_labels_json::text,
                to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                CASE WHEN approved_at IS NULL THEN NULL ELSE
                  to_char(approved_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') END,
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
        created_at: row.try_get(11)?,
        approved_at: row.try_get(12)?,
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
        && existing.expires_at == requested.expires_at
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
    OffsetDateTime::parse(expires_at, &Rfc3339)
        .map(|expires| expires <= OffsetDateTime::now_utc())
        .unwrap_or(true)
}

fn enrollment_token_audit_json(token: &EnrollmentTokenRecord) -> Value {
    json!({
        "token_id": token.token_id,
        "created_by": token.created_by,
        "expires_at": token.expires_at,
        "max_uses": token.max_uses,
        "used_count": token.used_count,
        "status": token.status.as_str(),
        "description_present": token.description.is_some(),
        "labels": token.labels_json,
        "scope": token.scope_json,
    })
}

fn join_request_audit_json(join: &JoinRequestRecord) -> Value {
    json!({
        "request_id": join.request_id,
        "token_id": join.token_id,
        "status": join.status.as_str(),
        "requested_endpoint_id": join.requested_endpoint_id,
        "assigned_endpoint_id": join.assigned_endpoint_id,
        "agent_version": join.agent_version,
        "requested_labels": join.requested_labels_json,
        "approved_labels": join.approved_labels_json,
        "approved_at": join.approved_at,
        "approved_by": join.approved_by,
        "rejection_reason": join.rejection_reason,
        "audit_correlation_id": join.audit_correlation_id,
        "agent_public_key_present": true,
        "fingerprint_present": true,
        "hostname_present": true,
    })
}

fn insert_enrollment_rejection_audit(
    tx: &mut Transaction<'_>,
    actor: &str,
    request_id: &str,
    token_id: Option<&str>,
    reason: &str,
) -> Result<(), PostgresError> {
    let mut event = AuditEvent::new(actor, "enrollment.request.reject");
    event.ok = Some(false);
    event.request_id = Some(request_id.to_string());
    event.error_code = Some(reason.to_string());
    event.detail_json = json_detail(
        "join_request",
        request_id,
        None,
        Some(json!({"state": "rejected", "token_id": token_id})),
        Some(reason),
    );
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
    if event.ts.len() > 64 || OffsetDateTime::parse(&event.ts, &Rfc3339).is_err() {
        return Err(PostgresError::InvalidInput(
            "audit timestamp must be bounded RFC3339".to_string(),
        ));
    }
    validate_low_sensitive_json(&event.detail_json, "audit detail")?;
    let detail = AuditDetailPayloadV1::new(
        event.ts.clone(),
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
         VALUES (CAST($1 AS text)::timestamptz, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                 CAST($12 AS text)::jsonb)",
        &[
            &event.ts,
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
