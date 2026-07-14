//! Native relational Postgres backend under construction for C1.
//!
//! This module is deliberately not wired into the CLI/runtime until every
//! `StoreReader` and `StoreWriter` contract has native parity. The first slice
//! establishes fail-closed migrations and the atomic node/audit boundary.

use std::fmt;
use std::str::FromStr;

use ocfleet_config::validation::{validate_node_id, validate_region, validate_role};
use ocfleet_protocol::enrollment::EndpointStatus;
use postgres::{Config, NoTls, Transaction};
use r2d2::{Pool, PooledConnection};
use r2d2_postgres::PostgresConnectionManager;
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::audit::AuditEvent;
use crate::backend::MAX_STORE_READER_ROWS;
use crate::input_validation::{validate_actor, validate_endpoint_id};
use crate::postgres_backend::{PostgresConnectionSource, PostgresError};
use crate::storage_payloads::{AuditDetailPayloadV1, TrustBundlePayloadV1};
use crate::store::{NodeInsert, NodeRecord, validate_low_sensitive_json};

type Manager = PostgresConnectionManager<NoTls>;
type Connection = PooledConnection<Manager>;

const MIGRATION_LOCK_ID: i64 = 0x4f43464c4e4154;
pub const NATIVE_BACKEND_SCHEMA_VERSION: i32 = 1;

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
    let config = Config::from_str(&private.dsn)
        .map_err(|_| PostgresError::Configuration("Postgres DSN is invalid"))?;
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

        let table_exists: bool = tx
            .query_one(
                "SELECT to_regclass('ocfleet_native_migrations') IS NOT NULL",
                &[],
            )?
            .get(0);
        if table_exists {
            let existing: i32 = tx
                .query_one(
                    "SELECT COALESCE(MAX(version), 0) FROM ocfleet_native_migrations",
                    &[],
                )?
                .get(0);
            if existing > NATIVE_BACKEND_SCHEMA_VERSION {
                return Err(PostgresError::UnsupportedBackendSchema(existing));
            }
        }

        tx.batch_execute(
            r#"
CREATE TABLE IF NOT EXISTS ocfleet_native_migrations (
  version INTEGER PRIMARY KEY CHECK (version > 0),
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS nodes (
  node_id TEXT PRIMARY KEY CHECK (length(node_id) BETWEEN 1 AND 128),
  endpoint_id TEXT NOT NULL UNIQUE CHECK (length(endpoint_id) BETWEEN 1 AND 128),
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  region TEXT NOT NULL CHECK (length(region) BETWEEN 1 AND 64),
  role TEXT NOT NULL CHECK (length(role) BETWEEN 1 AND 64),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS endpoint_trust (
  endpoint_id TEXT PRIMARY KEY REFERENCES nodes(endpoint_id) ON DELETE CASCADE,
  node_id TEXT NOT NULL UNIQUE REFERENCES nodes(node_id) ON DELETE CASCADE,
  fingerprint TEXT,
  status TEXT NOT NULL CHECK (status IN ('active', 'rotated', 'revoked', 'quarantined')),
  generation BIGINT NOT NULL CHECK (generation > 0),
  previous_endpoint_id TEXT,
  rotated_to TEXT,
  trust_bundle_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS controller_audit_log (
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

CREATE INDEX IF NOT EXISTS idx_native_audit_ts_id
  ON controller_audit_log(ts, id);
"#,
        )?;
        tx.execute(
            "INSERT INTO ocfleet_native_migrations (version, name)
             VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
            &[&1_i32, &"0001_native_core"],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn schema_version(&self) -> Result<i32, PostgresError> {
        let mut conn = self.connection()?;
        Ok(conn
            .query_one(
                "SELECT COALESCE(MAX(version), 0) FROM ocfleet_native_migrations",
                &[],
            )?
            .get(0))
    }

    pub fn add_node(&self, node: &NodeInsert, actor: &str) -> Result<(), PostgresError> {
        validate_node(node, actor)?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO nodes (node_id, endpoint_id, name, region, role)
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
            "INSERT INTO endpoint_trust
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
             FROM nodes WHERE node_id = $1",
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
             FROM nodes ORDER BY node_id LIMIT $1",
            &[&limit],
        )?
        .iter()
        .map(node_from_row)
        .collect()
    }

    pub fn audit_count(&self, event: &str) -> Result<i64, PostgresError> {
        let mut conn = self.connection()?;
        Ok(conn
            .query_one(
                "SELECT COUNT(*) FROM controller_audit_log WHERE event = $1",
                &[&event],
            )?
            .get(0))
    }
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
        node_id: row.get(0),
        endpoint_id: row.get(1),
        name: row.get(2),
        region: row.get(3),
        role: row.get(4),
        enabled: row.get(5),
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
        "INSERT INTO controller_audit_log
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
