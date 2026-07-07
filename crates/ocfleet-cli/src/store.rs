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
use crate::private_file::{self, PrivateFileError};

pub const CURRENT_SCHEMA_VERSION: i64 = 2;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("controller state file permissions are unsafe")]
    UnsafePermissions,
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
        let _created_database = create_database_file_if_missing(path)?;
        Self::open_existing_or_create(path)
    }

    pub fn open_with_status(path: &Path) -> Result<StoreOpenResult, StoreError> {
        let created_database = create_database_file_if_missing(path)?;
        let store = Self::open_existing_or_create(path)?;
        Ok(StoreOpenResult {
            store,
            created_database,
        })
    }

    fn open_existing_or_create(path: &Path) -> Result<Self, StoreError> {
        validate_database_files(path)?;
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", 5_000)?;

        let store = Self { conn };
        store.migrate()?;
        validate_database_files(path)?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
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
              enabled INTEGER NOT NULL DEFAULT 1,
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
        tx.execute(
            "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?1, strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
            [CURRENT_SCHEMA_VERSION],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn current_schema_version(&self) -> Result<i64, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT max(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })?)
    }

    pub fn add_node(&self, node: &NodeInsert) -> Result<(), StoreError> {
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

    pub fn list_probe_history(
        &self,
        node_filter: Option<&str>,
    ) -> Result<Vec<ProbeHistoryRecord>, StoreError> {
        if let Some(node_id) = node_filter {
            let mut stmt = self.conn.prepare(
                "SELECT ts, node_id, endpoint_id, method, request_id, ok, error_code, duration_ms, detail_json
                 FROM controller_audit_log
                 WHERE method IN (?1, ?2) AND node_id = ?3
                 ORDER BY id DESC
                 LIMIT 50",
            )?;
            let rows = stmt.query_map(
                params![PROBE_CONTROLLER_PING, PROBE_PATH_ECHO, node_id],
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
                 LIMIT 50",
            )?;
            let rows = stmt.query_map(
                params![PROBE_CONTROLLER_PING, PROBE_PATH_ECHO],
                probe_history_from_row,
            )?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(StoreError::from)
        }
    }

    pub fn disable_node(&self, node_id: &str) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let affected = tx.execute(
            "UPDATE nodes SET enabled = 0, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE node_id = ?1",
            [node_id],
        )?;
        if affected == 0 {
            return Err(StoreError::NodeNotFound(node_id.to_string()));
        }
        tx.commit()?;
        Ok(())
    }

    pub fn enable_node(&self, node_id: &str) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let affected = tx.execute(
            "UPDATE nodes SET enabled = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE node_id = ?1",
            [node_id],
        )?;
        if affected == 0 {
            return Err(StoreError::NodeNotFound(node_id.to_string()));
        }
        tx.commit()?;
        Ok(())
    }

    pub fn remove_node(&self, node_id: &str) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let affected = tx.execute("DELETE FROM nodes WHERE node_id = ?1", [node_id])?;
        if affected == 0 {
            return Err(StoreError::NodeNotFound(node_id.to_string()));
        }
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

    pub fn hash_enrollment_token(token: &str) -> String {
        blake3::hash(token.as_bytes()).to_hex().to_string()
    }

    pub fn create_enrollment_token(
        &self,
        token: &EnrollmentTokenInsert,
        actor: &str,
    ) -> Result<(), StoreError> {
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
                request.requested_endpoint_id.as_deref(),
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
                "requested_endpoint_id": request.requested_endpoint_id.clone(),
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
        let tx = self.conn.unchecked_transaction()?;
        let before = get_join_request_tx(&tx, &approval.request_id)?
            .ok_or_else(|| StoreError::JoinRequestNotFound(approval.request_id.clone()))?;
        if before.status != JoinRequestStatus::Pending {
            return Err(StoreError::InvalidJoinRequestStatus {
                request_id: approval.request_id.clone(),
                status: before.status.as_str().to_string(),
            });
        }
        if get_endpoint_trust_tx(&tx, &approval.endpoint_id)?.is_some() {
            return Err(StoreError::EndpointAlreadyExists(
                approval.endpoint_id.clone(),
            ));
        }

        let bundle = trust_bundle_json(&approval.endpoint_id, 1, EndpointStatus::Active);
        insert_endpoint_trust_tx(
            &tx,
            &EndpointTrustRecord {
                endpoint_id: approval.endpoint_id.clone(),
                node_id: Some(before.hostname.clone()),
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
                approval.endpoint_id.as_str(),
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
        event.endpoint_id = Some(approval.endpoint_id.clone());
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
        let tx = self.conn.unchecked_transaction()?;
        let old_before = get_endpoint_trust_tx(&tx, old_endpoint_id)?
            .ok_or_else(|| StoreError::EndpointNotFound(old_endpoint_id.to_string()))?;
        if get_endpoint_trust_tx(&tx, new_endpoint_id)?.is_some() {
            return Err(StoreError::EndpointAlreadyExists(
                new_endpoint_id.to_string(),
            ));
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
                new_endpoint_id,
                trust_bundle_json(old_endpoint_id, new_generation, EndpointStatus::Rotated)
                    .to_string(),
                old_endpoint_id,
            ],
        )?;
        insert_endpoint_trust_tx(
            &tx,
            &EndpointTrustRecord {
                endpoint_id: new_endpoint_id.to_string(),
                node_id: old_before.node_id.clone(),
                fingerprint: old_before.fingerprint.clone(),
                status: EndpointStatus::Active,
                generation: new_generation,
                previous_endpoint_id: Some(old_endpoint_id.to_string()),
                rotated_to: None,
                trust_bundle_json: trust_bundle_json(
                    new_endpoint_id,
                    new_generation,
                    EndpointStatus::Active,
                ),
                created_at: String::new(),
                updated_at: String::new(),
            },
        )?;
        let old_after = get_endpoint_trust_tx(&tx, old_endpoint_id)?.expect("old endpoint exists");
        let new_after = get_endpoint_trust_tx(&tx, new_endpoint_id)?.expect("new endpoint exists");
        audit_endpoint_lifecycle_tx(
            &tx,
            actor,
            "endpoint.rotate",
            new_endpoint_id,
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
        let tx = self.conn.unchecked_transaction()?;
        let before = get_endpoint_trust_tx(&tx, endpoint_id)?
            .ok_or_else(|| StoreError::EndpointNotFound(endpoint_id.to_string()))?;
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
                trust_bundle_json(endpoint_id, generation, status).to_string(),
                endpoint_id,
            ],
        )?;
        let after = get_endpoint_trust_tx(&tx, endpoint_id)?.expect("endpoint exists");
        audit_endpoint_lifecycle_tx(
            &tx,
            actor,
            action,
            endpoint_id,
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
    let ok = event.ok.map(|v| if v { 1_i64 } else { 0_i64 });
    let duration_ms = event.duration_ms.map(|v| v as i64);
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
        | PrivateFileError::UnsafeFile => StoreError::UnsafePermissions,
    }
}

fn node_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<NodeRecord> {
    Ok(NodeRecord {
        node_id: row.get(0)?,
        endpoint_id: row.get(1)?,
        name: row.get(2)?,
        region: row.get(3)?,
        role: row.get(4)?,
        enabled: row.get::<_, i64>(5)? == 1,
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
        ok: ok.map(|value| value != 0),
        error_code: row.get(6)?,
        duration_ms: duration_ms.and_then(|value| u64::try_from(value).ok()),
        detail_json: serde_json::from_str(&detail_json).unwrap_or(Value::Null),
    })
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
