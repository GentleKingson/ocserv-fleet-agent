//! Controller-side controlled-write approval state. This module deliberately
//! contains no agent RPC or local service adapter; D0 can only record dry-runs.

use base64::Engine as _;
use ocfleet_protocol::controlled_write::{
    ControlledWriteOperationKind, SignedControlledWriteIntent,
};
use ring::signature::{ED25519, UnparsedPublicKey};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::path::Path;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::input_validation::{validate_actor, validate_endpoint_id, validate_reason};
use crate::store::{Store, StoreError, validate_low_sensitive_json};

const MAX_ROWS: u64 = 1_000;
const MAX_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;
const MIN_NONCE_BYTES: usize = 16;
const MAX_NONCE_BYTES: usize = 128;
const MAX_KEYRING_BYTES: usize = 64 * 1024;
const MAX_TRUSTED_KEYS: usize = 64;
const MAX_INTENT_BYTES: usize = 64 * 1024;
const MAX_SIGNATURE_FILE_BYTES: usize = 4 * 1024;
const MAX_POLICY_BYTES: usize = 16 * 1024;

#[derive(Clone)]
pub struct TrustedIntentKeyring {
    keys: BTreeMap<String, TrustedIntentKey>,
}

#[derive(Clone)]
struct TrustedIntentKey {
    public_key: [u8; 32],
    public_key_fingerprint: String,
    allowed_actors: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringFile {
    keys: Vec<KeyringEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringEntry {
    key_id: String,
    public_key_base64: String,
    allowed_actors: Vec<String>,
}

impl fmt::Debug for TrustedIntentKeyring {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedIntentKeyring")
            .field("key_count", &self.keys.len())
            .field("key_material", &"<redacted>")
            .finish()
    }
}

impl TrustedIntentKeyring {
    pub fn from_private_file(path: &Path) -> Result<Self, StoreError> {
        let file = crate::private_file::open_existing_private_read(path)
            .map_err(|_| invalid("trusted intent keyring could not be read"))?;
        let mut text = String::new();
        file.take((MAX_KEYRING_BYTES + 1) as u64)
            .read_to_string(&mut text)
            .map_err(|_| invalid("trusted intent keyring could not be read"))?;
        if text.len() > MAX_KEYRING_BYTES {
            return Err(invalid("trusted intent keyring is too large"));
        }
        let parsed: KeyringFile =
            toml::from_str(&text).map_err(|_| invalid("trusted intent keyring is invalid"))?;
        Self::from_entries(parsed.keys)
    }

    fn from_entries(entries: Vec<KeyringEntry>) -> Result<Self, StoreError> {
        if entries.is_empty() || entries.len() > MAX_TRUSTED_KEYS {
            return Err(invalid("trusted intent keyring must contain 1-64 keys"));
        }
        let mut keys = BTreeMap::new();
        for entry in entries {
            validate_id(&entry.key_id, "trusted key_id")?;
            if entry.allowed_actors.is_empty() || entry.allowed_actors.len() > 64 {
                return Err(invalid("trusted intent key must bind at least one actor"));
            }
            let mut allowed_actors = BTreeSet::new();
            for actor in entry.allowed_actors {
                validate_actor(&actor).map_err(StoreError::InvalidInput)?;
                if !allowed_actors.insert(actor) {
                    return Err(invalid("trusted intent key contains a duplicate actor"));
                }
            }
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&entry.public_key_base64)
                .map_err(|_| invalid("trusted Ed25519 public key is invalid"))?;
            let public_key: [u8; 32] = decoded
                .try_into()
                .map_err(|_| invalid("trusted Ed25519 public key must be 32 bytes"))?;
            let fingerprint = format!("{:x}", Sha256::digest(public_key));
            let trusted = TrustedIntentKey {
                public_key,
                public_key_fingerprint: fingerprint,
                allowed_actors,
            };
            if keys.insert(entry.key_id, trusted).is_some() {
                return Err(invalid("trusted intent key_id is duplicated"));
            }
        }
        Ok(Self { keys })
    }

    fn resolve(&self, key_id: &str, actor: &str) -> Result<&TrustedIntentKey, StoreError> {
        let key = self
            .keys
            .get(key_id)
            .ok_or_else(|| invalid("signed intent key_id is not trusted"))?;
        if !key.allowed_actors.contains(actor) {
            return Err(invalid("signed intent key is not authorized for actor"));
        }
        Ok(key)
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedChangeIntent {
    pub request_id: String,
    pub operation_id: String,
    pub operation_kind: ControlledWriteOperationKind,
    pub endpoint_id: String,
    pub reason: String,
    pub change_ticket: String,
    pub nonce: String,
    pub expires_at: String,
    pub params_summary: Value,
}

impl fmt::Debug for UnsignedChangeIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnsignedChangeIntent")
            .field("request_id", &self.request_id)
            .field("operation_id", &self.operation_id)
            .field("operation_kind", &self.operation_kind)
            .field("endpoint_id", &self.endpoint_id)
            .field("reason", &"<redacted>")
            .field("change_ticket", &self.change_ticket)
            .field("nonce", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("params_summary", &"<typed-summary-only>")
            .finish()
    }
}

impl UnsignedChangeIntent {
    pub fn from_private_file(path: &Path) -> Result<Self, StoreError> {
        let text = read_private_text(path, MAX_INTENT_BYTES, "change intent")?;
        serde_json::from_str(&text).map_err(|_| invalid("change intent JSON is invalid"))
    }

    pub fn build_request(
        &self,
        actor: &str,
        key_id: &str,
        signature: String,
    ) -> Result<CreateChangeRequest, StoreError> {
        let mut request = CreateChangeRequest {
            request_id: self.request_id.clone(),
            operation_id: self.operation_id.clone(),
            operation_kind: self.operation_kind,
            endpoint_id: self.endpoint_id.clone(),
            actor: actor.to_string(),
            reason: self.reason.clone(),
            change_ticket: self.change_ticket.clone(),
            nonce: self.nonce.clone(),
            expires_at: self.expires_at.clone(),
            params_summary: self.params_summary.clone(),
            signed_intent: SignedControlledWriteIntent {
                key_id: key_id.to_string(),
                algorithm: "Ed25519".into(),
                payload_sha256: String::new(),
                signature,
            },
        };
        request.signed_intent.payload_sha256 = operation_digest(&request)?;
        Ok(request)
    }

    pub fn digest(&self, actor: &str, now: &str) -> Result<String, StoreError> {
        let request = self.build_request(actor, "digest-preview", "AA==".into())?;
        validate_create(&request, now)?;
        operation_digest(&request)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ControlledWritePolicy {
    pub enabled: bool,
    pub allowed_operations: BTreeSet<String>,
}

impl ControlledWritePolicy {
    pub fn from_private_file(path: &Path) -> Result<Self, StoreError> {
        let text = read_private_text(path, MAX_POLICY_BYTES, "controlled-write policy")?;
        let policy: Self =
            toml::from_str(&text).map_err(|_| invalid("controlled-write policy is invalid"))?;
        for operation in &policy.allowed_operations {
            if !matches!(
                operation.as_str(),
                "ocserv_reload"
                    | "ocserv_restart"
                    | "ocserv_config_apply"
                    | "ocserv_config_rollback"
            ) {
                return Err(invalid(
                    "controlled-write policy contains an unsupported operation",
                ));
            }
        }
        Ok(policy)
    }

    pub fn allows(&self, operation: &str) -> bool {
        self.enabled && self.allowed_operations.contains(operation)
    }
}

pub fn read_private_signature(path: &Path) -> Result<String, StoreError> {
    let text = read_private_text(path, MAX_SIGNATURE_FILE_BYTES, "signature")?;
    let signature = text.trim_end_matches(['\r', '\n']);
    decode_signature(signature)?;
    Ok(signature.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeState {
    Draft,
    DryRunPending,
    DryRunSucceeded,
    DryRunFailed,
    ApprovalPending,
    Approved,
    Rejected,
    Dispatching,
    Succeeded,
    Failed,
    RollbackPending,
    RolledBack,
    Cancelled,
    Expired,
}

impl ChangeState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::DryRunPending => "dry_run_pending",
            Self::DryRunSucceeded => "dry_run_succeeded",
            Self::DryRunFailed => "dry_run_failed",
            Self::ApprovalPending => "approval_pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Dispatching => "dispatching",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::RollbackPending => "rollback_pending",
            Self::RolledBack => "rolled_back",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "draft" => Ok(Self::Draft),
            "dry_run_pending" => Ok(Self::DryRunPending),
            "dry_run_succeeded" => Ok(Self::DryRunSucceeded),
            "dry_run_failed" => Ok(Self::DryRunFailed),
            "approval_pending" => Ok(Self::ApprovalPending),
            "approved" => Ok(Self::Approved),
            "rejected" => Ok(Self::Rejected),
            "dispatching" => Ok(Self::Dispatching),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "rollback_pending" => Ok(Self::RollbackPending),
            "rolled_back" => Ok(Self::RolledBack),
            "cancelled" => Ok(Self::Cancelled),
            "expired" => Ok(Self::Expired),
            _ => Err(StoreError::InvalidInput(
                "stored change state is invalid".into(),
            )),
        }
    }
}

#[derive(Clone)]
pub struct CreateChangeRequest {
    pub request_id: String,
    pub operation_id: String,
    pub operation_kind: ControlledWriteOperationKind,
    pub endpoint_id: String,
    pub actor: String,
    pub reason: String,
    pub change_ticket: String,
    pub nonce: String,
    pub expires_at: String,
    pub params_summary: Value,
    pub signed_intent: SignedControlledWriteIntent,
}

impl fmt::Debug for CreateChangeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateChangeRequest")
            .field("request_id", &self.request_id)
            .field("operation_id", &self.operation_id)
            .field("operation_kind", &self.operation_kind)
            .field("endpoint_id", &self.endpoint_id)
            .field("actor", &"<redacted>")
            .field("reason", &"<redacted>")
            .field("change_ticket", &self.change_ticket)
            .field("nonce", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("params_summary", &"<typed-summary-only>")
            .field("signed_intent", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangeRequestRecord {
    pub request_id: String,
    pub operation_id: String,
    pub operation_kind: String,
    pub endpoint_id: String,
    pub actor: String,
    pub change_ticket: String,
    pub operation_digest: String,
    pub state: ChangeState,
    pub expires_at: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct ApprovalDecision {
    pub approval_id: String,
    pub approver: String,
    pub role: String,
    pub reason: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangeAuditRecord {
    pub id: i64,
    pub timestamp: String,
    pub request_id: String,
    pub operation_id: String,
    pub operation_kind: String,
    pub actor: String,
    pub approval_id: Option<String>,
    pub state_from: Option<String>,
    pub state_to: String,
    pub ok: Option<bool>,
    pub error_code: Option<String>,
}

impl Store {
    pub fn create_change_request(
        &self,
        input: &CreateChangeRequest,
        keyring: &TrustedIntentKeyring,
        now: &str,
    ) -> Result<ChangeRequestRecord, StoreError> {
        validate_create(input, now)?;
        let digest = operation_digest(input)?;
        if digest != input.signed_intent.payload_sha256 {
            return Err(invalid("signed intent digest does not match the operation"));
        }
        let signature = decode_signature(&input.signed_intent.signature)?;
        let trusted_key = keyring.resolve(&input.signed_intent.key_id, &input.actor)?;
        UnparsedPublicKey::new(&ED25519, trusted_key.public_key)
            .verify(digest.as_bytes(), &signature)
            .map_err(|_| invalid("signed intent signature is invalid"))?;

        let tx = self.conn.unchecked_transaction()?;
        let signed_intent = json!({
            "schema": "ocfleet.signed_intent.v1",
            "key_id": input.signed_intent.key_id,
            "algorithm": input.signed_intent.algorithm,
            "payload_sha256": input.signed_intent.payload_sha256,
            "signature": input.signed_intent.signature,
            "public_key_fingerprint": trusted_key.public_key_fingerprint,
        });
        tx.execute(
            "INSERT INTO change_requests
             (request_id, operation_id, operation_kind, endpoint_id, actor, reason,
              change_ticket, operation_digest, nonce, signer_key_id, signed_intent_json,
              params_summary_json, state, expires_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     'draft', ?13, ?14, ?14)",
            params![
                input.request_id,
                input.operation_id,
                operation_kind(input.operation_kind),
                input.endpoint_id,
                input.actor,
                input.reason,
                input.change_ticket,
                digest,
                input.nonce,
                input.signed_intent.key_id,
                serde_json::to_string(&signed_intent).map_err(json_error)?,
                serde_json::to_string(&input.params_summary).map_err(json_error)?,
                input.expires_at,
                now,
            ],
        )?;
        insert_transition_audit(
            &tx,
            input,
            TransitionAudit {
                from: None,
                to: ChangeState::Draft,
                actor: &input.actor,
                approval_id: None,
                ok: true,
                error: None,
                now,
            },
        )?;
        let record = get_change_tx(&tx, &input.request_id)?
            .ok_or_else(|| invalid("created change request is missing"))?;
        tx.commit()?;
        Ok(record)
    }

    /// Records a policy-only dry-run. No RPC, service adapter, or filesystem
    /// operation is reachable from this method.
    pub fn record_change_dry_run(
        &self,
        request_id: &str,
        actor: &str,
        feature_enabled: bool,
        local_policy_enabled: bool,
        now: &str,
    ) -> Result<ChangeRequestRecord, StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        parse_time(now, "now")?;
        self.persist_expiry_if_needed(request_id, now)?;
        let tx = self.conn.unchecked_transaction()?;
        let current = require_active_change(&tx, request_id, now)?;
        if current.actor != actor {
            return Err(invalid("dry-run actor must be the change request actor"));
        }
        if !matches!(
            current.state,
            ChangeState::Draft | ChangeState::DryRunFailed
        ) {
            return Err(invalid("invalid transition to dry_run_pending"));
        }
        transition(
            &tx,
            request_id,
            current.state,
            ChangeState::DryRunPending,
            now,
        )?;
        let allowed = feature_enabled && local_policy_enabled;
        let target = if allowed {
            ChangeState::DryRunSucceeded
        } else {
            ChangeState::DryRunFailed
        };
        let attempt_id = format!("dry-run:{}", Uuid::new_v4());
        tx.execute(
            "INSERT INTO write_operation_attempts
             (attempt_id, request_id, attempt_kind, status, validation_code, created_at, completed_at)
             VALUES (?1, ?2, 'dry_run', ?3, ?4, ?5, ?5)",
            params![attempt_id, request_id, if allowed { "succeeded" } else { "failed" }, if allowed { "POLICY_ALLOWED" } else { "POLICY_DISABLED" }, now],
        )?;
        transition(&tx, request_id, ChangeState::DryRunPending, target, now)?;
        insert_record_audit(
            &tx,
            &current,
            TransitionAudit {
                from: Some(current.state),
                to: target,
                actor,
                approval_id: None,
                ok: allowed,
                error: (!allowed).then_some("POLICY_DISABLED"),
                now,
            },
        )?;
        let record =
            get_change_tx(&tx, request_id)?.ok_or_else(|| invalid("change request is missing"))?;
        tx.commit()?;
        Ok(record)
    }

    pub fn approve_change(
        &self,
        request_id: &str,
        approval: &ApprovalDecision,
        now: &str,
    ) -> Result<ChangeRequestRecord, StoreError> {
        validate_approval(approval, now)?;
        self.persist_expiry_if_needed(request_id, now)?;
        let tx = self.conn.unchecked_transaction()?;
        let current = require_active_change(&tx, request_id, now)?;
        if current.actor == approval.approver {
            return Err(invalid(
                "change actor and approver must be different principals",
            ));
        }
        if current.state != ChangeState::DryRunSucceeded
            && current.state != ChangeState::ApprovalPending
        {
            return Err(invalid("approval requires a successful dry-run"));
        }
        tx.execute(
            "INSERT INTO change_approvals
             (approval_id, request_id, approver_actor, approver_role, decision, reason, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, 'approved', ?5, ?6, ?7)",
            params![approval.approval_id, request_id, approval.approver, approval.role, approval.reason, approval.expires_at, now],
        )?;
        transition(&tx, request_id, current.state, ChangeState::Approved, now)?;
        insert_record_audit(
            &tx,
            &current,
            TransitionAudit {
                from: Some(current.state),
                to: ChangeState::Approved,
                actor: &approval.approver,
                approval_id: Some(&approval.approval_id),
                ok: true,
                error: None,
                now,
            },
        )?;
        let record =
            get_change_tx(&tx, request_id)?.ok_or_else(|| invalid("change request is missing"))?;
        tx.commit()?;
        Ok(record)
    }

    pub fn reject_change(
        &self,
        request_id: &str,
        decision: &ApprovalDecision,
        now: &str,
    ) -> Result<ChangeRequestRecord, StoreError> {
        validate_approval(decision, now)?;
        self.persist_expiry_if_needed(request_id, now)?;
        let tx = self.conn.unchecked_transaction()?;
        let current = require_active_change(&tx, request_id, now)?;
        if current.actor == decision.approver {
            return Err(invalid(
                "change actor and approver must be different principals",
            ));
        }
        if !matches!(
            current.state,
            ChangeState::DryRunSucceeded | ChangeState::ApprovalPending
        ) {
            return Err(invalid("change request is not awaiting approval"));
        }
        tx.execute(
            "INSERT INTO change_approvals
             (approval_id, request_id, approver_actor, approver_role, decision, reason, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, 'rejected', ?5, ?6, ?7)",
            params![decision.approval_id, request_id, decision.approver, decision.role, decision.reason, decision.expires_at, now],
        )?;
        transition(&tx, request_id, current.state, ChangeState::Rejected, now)?;
        insert_record_audit(
            &tx,
            &current,
            TransitionAudit {
                from: Some(current.state),
                to: ChangeState::Rejected,
                actor: &decision.approver,
                approval_id: Some(&decision.approval_id),
                ok: true,
                error: None,
                now,
            },
        )?;
        let record =
            get_change_tx(&tx, request_id)?.ok_or_else(|| invalid("change request is missing"))?;
        tx.commit()?;
        Ok(record)
    }

    pub fn cancel_change(
        &self,
        request_id: &str,
        actor: &str,
        now: &str,
    ) -> Result<ChangeRequestRecord, StoreError> {
        validate_actor(actor).map_err(StoreError::InvalidInput)?;
        self.persist_expiry_if_needed(request_id, now)?;
        let tx = self.conn.unchecked_transaction()?;
        let current = require_active_change(&tx, request_id, now)?;
        if current.actor != actor {
            return Err(invalid("only the requesting actor may cancel a change"));
        }
        if !matches!(
            current.state,
            ChangeState::Draft
                | ChangeState::DryRunPending
                | ChangeState::DryRunSucceeded
                | ChangeState::DryRunFailed
                | ChangeState::ApprovalPending
                | ChangeState::Approved
        ) {
            return Err(invalid("change can no longer be cancelled"));
        }
        transition(&tx, request_id, current.state, ChangeState::Cancelled, now)?;
        insert_record_audit(
            &tx,
            &current,
            TransitionAudit {
                from: Some(current.state),
                to: ChangeState::Cancelled,
                actor,
                approval_id: None,
                ok: true,
                error: None,
                now,
            },
        )?;
        let record =
            get_change_tx(&tx, request_id)?.ok_or_else(|| invalid("change request is missing"))?;
        tx.commit()?;
        Ok(record)
    }

    pub fn get_change_request(
        &self,
        request_id: &str,
    ) -> Result<Option<ChangeRequestRecord>, StoreError> {
        get_change_conn(&self.conn, request_id)
    }

    pub fn list_change_requests(&self, limit: u64) -> Result<Vec<ChangeRequestRecord>, StoreError> {
        if limit == 0 || limit > MAX_ROWS {
            return Err(invalid("change request limit must be between 1 and 1000"));
        }
        let limit = i64::try_from(limit).map_err(|_| invalid("change request limit is invalid"))?;
        let mut statement = self.conn.prepare(
            "SELECT request_id, operation_id, operation_kind, endpoint_id, actor, change_ticket,
                    operation_digest, state, expires_at, created_at, updated_at
             FROM change_requests ORDER BY created_at DESC, request_id LIMIT ?1",
        )?;
        let rows = statement.query_map([limit], change_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn list_change_audit(
        &self,
        request_id: &str,
        limit: u64,
    ) -> Result<Vec<ChangeAuditRecord>, StoreError> {
        validate_id(request_id, "request_id")?;
        if limit == 0 || limit > MAX_ROWS {
            return Err(invalid("change audit limit must be between 1 and 1000"));
        }
        let limit = i64::try_from(limit).map_err(|_| invalid("change audit limit is invalid"))?;
        let mut statement = self.conn.prepare(
            "SELECT id, ts, request_id, operation_id, operation_kind, actor, approval_id,
                    state_from, state_to, ok, error_code
             FROM write_operation_audit WHERE request_id = ?1 ORDER BY id LIMIT ?2",
        )?;
        let rows = statement.query_map(params![request_id, limit], |row| {
            Ok(ChangeAuditRecord {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                request_id: row.get(2)?,
                operation_id: row.get(3)?,
                operation_kind: row.get(4)?,
                actor: row.get(5)?,
                approval_id: row.get(6)?,
                state_from: row.get(7)?,
                state_to: row.get(8)?,
                ok: row.get(9)?,
                error_code: row.get(10)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    fn persist_expiry_if_needed(&self, request_id: &str, now: &str) -> Result<(), StoreError> {
        validate_id(request_id, "request_id")?;
        let now_time = parse_time(now, "now")?;
        let tx = self.conn.unchecked_transaction()?;
        let current =
            get_change_tx(&tx, request_id)?.ok_or_else(|| invalid("change request not found"))?;
        let expires = parse_time(&current.expires_at, "stored expires_at")?;
        if expires > now_time {
            tx.commit()?;
            return Ok(());
        }
        if matches!(
            current.state,
            ChangeState::Succeeded
                | ChangeState::Failed
                | ChangeState::Rejected
                | ChangeState::Cancelled
                | ChangeState::Expired
                | ChangeState::RolledBack
        ) {
            tx.commit()?;
            return Err(invalid("change request has expired"));
        }
        transition(&tx, request_id, current.state, ChangeState::Expired, now)?;
        insert_record_audit(
            &tx,
            &current,
            TransitionAudit {
                from: Some(current.state),
                to: ChangeState::Expired,
                actor: "system:expiry",
                approval_id: None,
                ok: true,
                error: None,
                now,
            },
        )?;
        tx.commit()?;
        Err(invalid("change request has expired"))
    }
}

fn validate_create(input: &CreateChangeRequest, now: &str) -> Result<(), StoreError> {
    validate_id(&input.request_id, "request_id")?;
    Uuid::parse_str(&input.request_id).map_err(|_| invalid("request_id must be a UUID"))?;
    validate_id(&input.operation_id, "operation_id")?;
    validate_endpoint_id(&input.endpoint_id).map_err(StoreError::InvalidInput)?;
    validate_actor(&input.actor).map_err(StoreError::InvalidInput)?;
    validate_reason(&input.reason).map_err(StoreError::InvalidInput)?;
    validate_id(&input.change_ticket, "change_ticket")?;
    validate_id(&input.signed_intent.key_id, "signer key id")?;
    if input.signed_intent.algorithm != "Ed25519" {
        return Err(invalid("signed intent algorithm must be Ed25519"));
    }
    if input.nonce.len() < MIN_NONCE_BYTES
        || input.nonce.len() > MAX_NONCE_BYTES
        || !input.nonce.bytes().all(safe_id_byte)
    {
        return Err(invalid("nonce must be a bounded opaque identifier"));
    }
    validate_low_sensitive_json(&input.params_summary, "controlled write params summary")?;
    let now = parse_time(now, "now")?;
    let expires = parse_time(&input.expires_at, "expires_at")?;
    if expires <= now || expires - now > time::Duration::seconds(MAX_LIFETIME_SECONDS) {
        return Err(invalid(
            "change request expiry must be in the future and within 30 days",
        ));
    }
    if input.operation_kind == ControlledWriteOperationKind::OcservSessionDisconnect {
        return Err(invalid("session disconnect is not supported by D0"));
    }
    Ok(())
}

fn validate_approval(input: &ApprovalDecision, now: &str) -> Result<(), StoreError> {
    validate_id(&input.approval_id, "approval_id")?;
    validate_actor(&input.approver).map_err(StoreError::InvalidInput)?;
    validate_reason(&input.reason).map_err(StoreError::InvalidInput)?;
    if input.role != "change-approver" && input.role != "security-admin" {
        return Err(invalid("approver role is not permitted"));
    }
    let now = parse_time(now, "now")?;
    let expires = parse_time(&input.expires_at, "approval expires_at")?;
    if expires <= now || expires - now > time::Duration::seconds(MAX_LIFETIME_SECONDS) {
        return Err(invalid(
            "approval expiry must be in the future and within 30 days",
        ));
    }
    Ok(())
}

fn operation_digest(input: &CreateChangeRequest) -> Result<String, StoreError> {
    let canonical = serde_json::to_vec(&json!({
        "schema": "ocfleet.controlled_write_intent.v1",
        "request_id": input.request_id,
        "operation_id": input.operation_id,
        "operation_kind": operation_kind(input.operation_kind),
        "endpoint_id": input.endpoint_id,
        "actor": input.actor,
        "reason": input.reason,
        "change_ticket": input.change_ticket,
        "nonce": input.nonce,
        "expires_at": input.expires_at,
        "params_summary": input.params_summary,
    }))
    .map_err(json_error)?;
    Ok(format!("{:x}", Sha256::digest(canonical)))
}

fn require_active_change(
    tx: &Transaction<'_>,
    request_id: &str,
    now: &str,
) -> Result<ChangeRequestRecord, StoreError> {
    validate_id(request_id, "request_id")?;
    let now_time = parse_time(now, "now")?;
    let current =
        get_change_tx(tx, request_id)?.ok_or_else(|| invalid("change request not found"))?;
    let expires = parse_time(&current.expires_at, "stored expires_at")?;
    if expires <= now_time {
        return Err(invalid("change request has expired"));
    }
    Ok(current)
}

fn transition(
    tx: &Transaction<'_>,
    request_id: &str,
    from: ChangeState,
    to: ChangeState,
    now: &str,
) -> Result<(), StoreError> {
    let changed = tx.execute(
        "UPDATE change_requests SET state = ?1, updated_at = ?2 WHERE request_id = ?3 AND state = ?4",
        params![to.as_str(), now, request_id, from.as_str()],
    )?;
    if changed != 1 {
        return Err(invalid(
            "change request transition lost a concurrent update",
        ));
    }
    Ok(())
}

struct TransitionAudit<'a> {
    from: Option<ChangeState>,
    to: ChangeState,
    actor: &'a str,
    approval_id: Option<&'a str>,
    ok: bool,
    error: Option<&'a str>,
    now: &'a str,
}

fn insert_transition_audit(
    tx: &Transaction<'_>,
    input: &CreateChangeRequest,
    audit: TransitionAudit<'_>,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO write_operation_audit
         (ts, request_id, operation_id, operation_kind, actor, approval_id, state_from, state_to, ok, error_code, detail_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![audit.now, input.request_id, input.operation_id, operation_kind(input.operation_kind), audit.actor, audit.approval_id, audit.from.map(ChangeState::as_str), audit.to.as_str(), audit.ok, audit.error, "{\"schema\":\"ocfleet.write_audit.v1\"}"],
    )?;
    Ok(())
}

fn insert_record_audit(
    tx: &Transaction<'_>,
    record: &ChangeRequestRecord,
    audit: TransitionAudit<'_>,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO write_operation_audit
         (ts, request_id, operation_id, operation_kind, actor, approval_id, state_from, state_to, ok, error_code, detail_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![audit.now, record.request_id, record.operation_id, record.operation_kind, audit.actor, audit.approval_id, audit.from.map(ChangeState::as_str), audit.to.as_str(), audit.ok, audit.error, "{\"schema\":\"ocfleet.write_audit.v1\"}"],
    )?;
    Ok(())
}

fn get_change_conn(
    conn: &rusqlite::Connection,
    request_id: &str,
) -> Result<Option<ChangeRequestRecord>, StoreError> {
    conn.query_row(
        "SELECT request_id, operation_id, operation_kind, endpoint_id, actor, change_ticket,
                operation_digest, state, expires_at, created_at, updated_at
         FROM change_requests WHERE request_id = ?1",
        [request_id],
        change_from_row,
    )
    .optional()
    .map_err(StoreError::from)
}

fn get_change_tx(
    tx: &Transaction<'_>,
    request_id: &str,
) -> Result<Option<ChangeRequestRecord>, StoreError> {
    tx.query_row(
        "SELECT request_id, operation_id, operation_kind, endpoint_id, actor, change_ticket,
                operation_digest, state, expires_at, created_at, updated_at
         FROM change_requests WHERE request_id = ?1",
        [request_id],
        change_from_row,
    )
    .optional()
    .map_err(StoreError::from)
}

fn change_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChangeRequestRecord> {
    let state: String = row.get(7)?;
    let state = ChangeState::parse(&state).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(ChangeRequestRecord {
        request_id: row.get(0)?,
        operation_id: row.get(1)?,
        operation_kind: row.get(2)?,
        endpoint_id: row.get(3)?,
        actor: row.get(4)?,
        change_ticket: row.get(5)?,
        operation_digest: row.get(6)?,
        state,
        expires_at: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

fn operation_kind(kind: ControlledWriteOperationKind) -> &'static str {
    match kind {
        ControlledWriteOperationKind::OcservReload => "ocserv_reload",
        ControlledWriteOperationKind::OcservRestart => "ocserv_restart",
        ControlledWriteOperationKind::OcservConfigApply => "ocserv_config_apply",
        ControlledWriteOperationKind::OcservConfigRollback => "ocserv_config_rollback",
        ControlledWriteOperationKind::OcservSessionDisconnect => "ocserv_session_disconnect",
    }
}

fn decode_signature(value: &str) -> Result<Vec<u8>, StoreError> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value))
        .map_err(|_| invalid("signed intent signature is not valid base64"))
}

fn validate_id(value: &str, field: &str) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > 128 || !value.bytes().all(safe_id_byte) {
        return Err(invalid(format!("{field} is invalid")));
    }
    Ok(())
}

fn safe_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':')
}
fn parse_time(value: &str, field: &str) -> Result<OffsetDateTime, StoreError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| invalid(format!("{field} must be RFC3339")))
}
fn invalid(message: impl Into<String>) -> StoreError {
    StoreError::InvalidInput(message.into())
}
fn json_error(error: serde_json::Error) -> StoreError {
    invalid(format!("controlled write JSON is invalid: {error}"))
}

fn read_private_text(path: &Path, max_bytes: usize, label: &str) -> Result<String, StoreError> {
    let file = crate::private_file::open_existing_private_read(path)
        .map_err(|_| invalid(format!("{label} file could not be read")))?;
    let mut text = String::new();
    file.take((max_bytes + 1) as u64)
        .read_to_string(&mut text)
        .map_err(|_| invalid(format!("{label} file could not be read")))?;
    if text.len() > max_bytes {
        return Err(invalid(format!("{label} file is too large")));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn fixture() -> (
        tempfile::TempDir,
        Store,
        CreateChangeRequest,
        TrustedIntentKeyring,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&dir.path().join("controller.sqlite")).expect("store");
        let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate key");
        let key = Ed25519KeyPair::from_pkcs8(key.as_ref()).expect("parse key");
        let mut request = CreateChangeRequest {
            request_id: Uuid::new_v4().to_string(),
            operation_id: format!("op:{}", Uuid::new_v4()),
            operation_kind: ControlledWriteOperationKind::OcservReload,
            endpoint_id: iroh::SecretKey::generate().public().to_string(),
            actor: "operator-a".into(),
            reason: "Reviewed reload dry run".into(),
            change_ticket: "CHG-1234".into(),
            nonce: format!("nonce:{}", Uuid::new_v4()),
            expires_at: "2026-07-14T00:00:00Z".into(),
            params_summary: json!({"schema":"ocfleet.reload.v1"}),
            signed_intent: SignedControlledWriteIntent {
                key_id: "test-key".into(),
                algorithm: "Ed25519".into(),
                payload_sha256: "0".repeat(64),
                signature: "pending".into(),
            },
        };
        let digest = operation_digest(&request).expect("digest");
        request.signed_intent.payload_sha256 = digest.clone();
        request.signed_intent.signature =
            base64::engine::general_purpose::STANDARD.encode(key.sign(digest.as_bytes()).as_ref());
        let keyring = TrustedIntentKeyring::from_entries(vec![KeyringEntry {
            key_id: "test-key".into(),
            public_key_base64: base64::engine::general_purpose::STANDARD
                .encode(key.public_key().as_ref()),
            allowed_actors: vec!["operator-a".into()],
        }])
        .expect("keyring");
        (dir, store, request, keyring)
    }

    #[test]
    fn dry_run_and_two_person_approval_never_dispatch() {
        let (_dir, store, request, keyring) = fixture();
        let created = store
            .create_change_request(&request, &keyring, "2026-07-13T00:00:00Z")
            .expect("create");
        assert_eq!(created.state, ChangeState::Draft);
        let dry_run = store
            .record_change_dry_run(
                &request.request_id,
                &request.actor,
                true,
                true,
                "2026-07-13T00:01:00Z",
            )
            .expect("dry run");
        assert_eq!(dry_run.state, ChangeState::DryRunSucceeded);
        let approval = ApprovalDecision {
            approval_id: "approval:test".into(),
            approver: "approver-b".into(),
            role: "change-approver".into(),
            reason: "Reviewed exact endpoint".into(),
            expires_at: "2026-07-13T12:00:00Z".into(),
        };
        let approved = store
            .approve_change(&request.request_id, &approval, "2026-07-13T00:02:00Z")
            .expect("approve");
        assert_eq!(approved.state, ChangeState::Approved);
    }

    #[test]
    fn policy_disabled_same_actor_and_replay_fail_closed() {
        let (_dir, store, request, keyring) = fixture();
        store
            .create_change_request(&request, &keyring, "2026-07-13T00:00:00Z")
            .expect("create");
        assert!(
            store
                .create_change_request(&request, &keyring, "2026-07-13T00:00:00Z")
                .is_err(),
            "operation id and nonce are idempotent/replay protected"
        );
        let failed = store
            .record_change_dry_run(
                &request.request_id,
                &request.actor,
                false,
                true,
                "2026-07-13T00:01:00Z",
            )
            .expect("record denial");
        assert_eq!(failed.state, ChangeState::DryRunFailed);
    }

    #[test]
    fn debug_redacts_signed_and_sensitive_material() {
        let (_dir, _store, request, keyring) = fixture();
        let debug = format!("{request:?}");
        assert!(!debug.contains(&request.reason));
        assert!(!debug.contains(&request.nonce));
        assert!(!debug.contains(&request.signed_intent.signature));
        assert!(format!("{keyring:?}").contains("<redacted>"));
    }

    #[test]
    fn trusted_key_binding_and_signed_actor_reason_fail_closed() {
        let (_dir, store, request, keyring) = fixture();
        let mut actor_tamper = request.clone();
        actor_tamper.actor = "operator-b".into();
        assert!(
            store
                .create_change_request(&actor_tamper, &keyring, "2026-07-13T00:00:00Z")
                .is_err()
        );
        let mut reason_tamper = request.clone();
        reason_tamper.reason = "Different reviewed reason".into();
        assert!(
            store
                .create_change_request(&reason_tamper, &keyring, "2026-07-13T00:00:00Z")
                .is_err()
        );
    }

    #[test]
    fn expiry_transition_is_committed_and_terminal_cancel_is_rejected() {
        let (_dir, store, request, keyring) = fixture();
        store
            .create_change_request(&request, &keyring, "2026-07-13T00:00:00Z")
            .expect("create");
        assert!(
            store
                .record_change_dry_run(
                    &request.request_id,
                    &request.actor,
                    true,
                    true,
                    "2026-07-14T00:00:00Z",
                )
                .is_err()
        );
        assert_eq!(
            store
                .get_change_request(&request.request_id)
                .expect("read")
                .expect("request")
                .state,
            ChangeState::Expired
        );
        assert!(
            store
                .cancel_change(&request.request_id, &request.actor, "2026-07-14T00:01:00Z")
                .is_err()
        );
    }

    #[test]
    fn unsupported_operation_is_rejected_before_sql() {
        let (_dir, store, mut request, keyring) = fixture();
        request.operation_kind = ControlledWriteOperationKind::OcservSessionDisconnect;
        assert!(
            store
                .create_change_request(&request, &keyring, "2026-07-13T00:00:00Z")
                .is_err()
        );
    }

    #[test]
    fn rust_operation_catalog_matches_schema_allowlist() {
        let (_dir, store, _request, _keyring) = fixture();
        for (index, kind) in [
            ControlledWriteOperationKind::OcservReload,
            ControlledWriteOperationKind::OcservRestart,
            ControlledWriteOperationKind::OcservConfigApply,
            ControlledWriteOperationKind::OcservConfigRollback,
        ]
        .into_iter()
        .enumerate()
        {
            store
                .conn
                .execute(
                    "INSERT INTO change_requests
                     (request_id, operation_id, operation_kind, endpoint_id, actor, reason,
                      change_ticket, operation_digest, nonce, signer_key_id, signed_intent_json,
                      params_summary_json, state, expires_at, created_at, updated_at)
                     VALUES (?1, ?2, ?3, 'endpoint', 'actor', 'reason', 'CHG-1', ?4, ?5,
                             'key', '{}', '{}', 'draft', ?6, ?7, ?7)",
                    params![
                        format!("request-{index}"),
                        format!("operation-{index}"),
                        operation_kind(kind),
                        "0".repeat(64),
                        format!("nonce-{index:016}"),
                        "2026-07-14T00:00:00Z",
                        "2026-07-13T00:00:00Z",
                    ],
                )
                .expect("supported Rust kind must satisfy schema");
        }
        assert_eq!(
            operation_kind(ControlledWriteOperationKind::OcservSessionDisconnect),
            "ocserv_session_disconnect"
        );
    }

    #[test]
    fn transition_audit_failure_rolls_back_change_creation() {
        let (_dir, store, request, keyring) = fixture();
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER reject_write_audit BEFORE INSERT ON write_operation_audit
                 BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;",
            )
            .expect("install trigger");
        assert!(
            store
                .create_change_request(&request, &keyring, "2026-07-13T00:00:00Z")
                .is_err()
        );
        assert!(
            store
                .get_change_request(&request.request_id)
                .expect("read")
                .is_none()
        );
    }

    #[test]
    fn change_audit_projection_is_bounded_and_excludes_signed_material() {
        let (_dir, store, request, keyring) = fixture();
        store
            .create_change_request(&request, &keyring, "2026-07-13T00:00:00Z")
            .expect("create");
        let audit = store
            .list_change_audit(&request.request_id, 10)
            .expect("audit");
        assert_eq!(audit.len(), 1);
        let output = serde_json::to_string(&audit).expect("serialize");
        assert!(!output.contains(&request.signed_intent.signature));
        assert!(!output.contains(&request.nonce));
        assert!(store.list_change_audit(&request.request_id, 0).is_err());
        assert!(store.list_change_audit(&request.request_id, 1_001).is_err());
    }
}
