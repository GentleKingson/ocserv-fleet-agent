use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_ID_BYTES: usize = 128;
const MAX_ACTOR_BYTES: usize = 128;
const MAX_REASON_BYTES: usize = 256;
const MAX_SIGNATURE_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlledWriteOperationKind {
    OcservReload,
    OcservRestart,
    OcservConfigApply,
    OcservConfigRollback,
    OcservSessionDisconnect,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledWriteRequest {
    pub operation_id: String,
    pub operation_kind: ControlledWriteOperationKind,
    pub actor: String,
    pub reason: String,
    pub change_ticket: String,
    pub approval_id: String,
    pub request_id: String,
    pub dry_run: bool,
    pub signed_intent: SignedControlledWriteIntent,
    pub params: ControlledWriteParams,
}

impl fmt::Debug for ControlledWriteRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlledWriteRequest")
            .field("operation_id", &self.operation_id)
            .field("operation_kind", &self.operation_kind)
            .field("actor", &"<redacted>")
            .field("reason", &"<redacted>")
            .field("change_ticket", &self.change_ticket)
            .field("approval_id", &self.approval_id)
            .field("request_id", &self.request_id)
            .field("dry_run", &self.dry_run)
            .field("signed_intent", &"<redacted>")
            .field("params", &"<typed-summary-only>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedControlledWriteIntent {
    pub key_id: String,
    pub algorithm: String,
    pub payload_sha256: String,
    pub signature: String,
}

impl fmt::Debug for SignedControlledWriteIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedControlledWriteIntent")
            .field("key_id", &self.key_id)
            .field("algorithm", &self.algorithm)
            .field("payload_sha256", &self.payload_sha256)
            .field("signature", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlledWriteParams {
    OcservReload {},
    OcservRestart {
        acknowledge_outage: bool,
    },
    OcservConfigApply {
        bundle_id: String,
        bundle_sha256: String,
        expected_previous_bundle_id: Option<String>,
    },
    OcservConfigRollback {
        target_bundle_id: String,
        target_bundle_sha256: String,
    },
    /// Deliberately carries no selector. A safe opaque selection protocol has
    /// not been designed, so this draft operation always fails validation.
    OcservSessionDisconnect {},
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlledWriteStatus {
    AcceptedDryRun,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlledWritePolicyDecision {
    WouldAllow,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledWriteSummary {
    pub operation_kind: ControlledWriteOperationKind,
    pub policy_decision: ControlledWritePolicyDecision,
    pub validation_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IrreversibilityReason {
    ReloadHasNoRollback,
    RestartOutageCannotBeUndone,
    SessionDisconnectCannotBeUndone,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledWriteResponse {
    pub operation_id: String,
    pub request_id: String,
    pub status: ControlledWriteStatus,
    pub dry_run: bool,
    pub summary: ControlledWriteSummary,
    pub rollback_available: bool,
    pub rollback_plan_id: Option<String>,
    pub irreversible_reason: Option<IrreversibilityReason>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ControlledWriteValidationError {
    #[error("controlled write scaffold only accepts dry-run requests")]
    NonDryRun,
    #[error("invalid controlled write field: {0}")]
    InvalidField(&'static str),
    #[error("controlled write operation kind does not match params")]
    OperationKindMismatch,
    #[error("session disconnect has no safe selector in the current scaffold")]
    SessionDisconnectUnavailable,
}

impl ControlledWriteRequest {
    pub fn validate_dry_run(&self) -> Result<(), ControlledWriteValidationError> {
        if !self.dry_run {
            return Err(ControlledWriteValidationError::NonDryRun);
        }
        validate_id(&self.operation_id, "operation_id")?;
        validate_actor(&self.actor)?;
        validate_reason(&self.reason)?;
        validate_id(&self.change_ticket, "change_ticket")?;
        validate_id(&self.approval_id, "approval_id")?;
        uuid::Uuid::parse_str(&self.request_id)
            .map_err(|_| ControlledWriteValidationError::InvalidField("request_id"))?;
        self.signed_intent.validate()?;
        self.params.validate_for(self.operation_kind)
    }
}

impl SignedControlledWriteIntent {
    fn validate(&self) -> Result<(), ControlledWriteValidationError> {
        validate_id(&self.key_id, "signed_intent.key_id")?;
        if self.algorithm != "Ed25519" {
            return Err(ControlledWriteValidationError::InvalidField(
                "signed_intent.algorithm",
            ));
        }
        validate_sha256(&self.payload_sha256, "signed_intent.payload_sha256")?;
        if self.signature.len() < 64
            || self.signature.len() > MAX_SIGNATURE_BYTES
            || !self.signature.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'_' | b'-')
            })
        {
            return Err(ControlledWriteValidationError::InvalidField(
                "signed_intent.signature",
            ));
        }
        Ok(())
    }
}

impl ControlledWriteParams {
    fn validate_for(
        &self,
        operation_kind: ControlledWriteOperationKind,
    ) -> Result<(), ControlledWriteValidationError> {
        match (operation_kind, self) {
            (ControlledWriteOperationKind::OcservReload, Self::OcservReload {}) => Ok(()),
            (
                ControlledWriteOperationKind::OcservRestart,
                Self::OcservRestart {
                    acknowledge_outage: true,
                },
            ) => Ok(()),
            (
                ControlledWriteOperationKind::OcservRestart,
                Self::OcservRestart {
                    acknowledge_outage: false,
                },
            ) => Err(ControlledWriteValidationError::InvalidField(
                "params.acknowledge_outage",
            )),
            (
                ControlledWriteOperationKind::OcservConfigApply,
                Self::OcservConfigApply {
                    bundle_id,
                    bundle_sha256,
                    expected_previous_bundle_id,
                },
            ) => {
                validate_id(bundle_id, "params.bundle_id")?;
                validate_sha256(bundle_sha256, "params.bundle_sha256")?;
                if let Some(bundle_id) = expected_previous_bundle_id {
                    validate_id(bundle_id, "params.expected_previous_bundle_id")?;
                }
                Ok(())
            }
            (
                ControlledWriteOperationKind::OcservConfigRollback,
                Self::OcservConfigRollback {
                    target_bundle_id,
                    target_bundle_sha256,
                },
            ) => {
                validate_id(target_bundle_id, "params.target_bundle_id")?;
                validate_sha256(target_bundle_sha256, "params.target_bundle_sha256")
            }
            (
                ControlledWriteOperationKind::OcservSessionDisconnect,
                Self::OcservSessionDisconnect {},
            ) => Err(ControlledWriteValidationError::SessionDisconnectUnavailable),
            _ => Err(ControlledWriteValidationError::OperationKindMismatch),
        }
    }
}

impl ControlledWriteResponse {
    pub fn validate(&self) -> Result<(), ControlledWriteValidationError> {
        if !self.dry_run {
            return Err(ControlledWriteValidationError::NonDryRun);
        }
        validate_id(&self.operation_id, "operation_id")?;
        uuid::Uuid::parse_str(&self.request_id)
            .map_err(|_| ControlledWriteValidationError::InvalidField("request_id"))?;
        if let Some(id) = &self.rollback_plan_id {
            validate_id(id, "rollback_plan_id")?;
        }
        if let Some(code) = &self.summary.validation_code {
            validate_id(code, "summary.validation_code")?;
        }
        match (self.status, self.summary.policy_decision) {
            (ControlledWriteStatus::AcceptedDryRun, ControlledWritePolicyDecision::WouldAllow) => {}
            (ControlledWriteStatus::Rejected, ControlledWritePolicyDecision::Denied)
                if self.summary.validation_code.is_some() => {}
            _ => {
                return Err(ControlledWriteValidationError::InvalidField(
                    "summary.policy_decision",
                ));
            }
        }
        if self.rollback_available != self.rollback_plan_id.is_some()
            || (self.rollback_available && self.irreversible_reason.is_some())
        {
            return Err(ControlledWriteValidationError::InvalidField(
                "rollback_contract",
            ));
        }
        if self.status == ControlledWriteStatus::Rejected
            && (self.rollback_available || self.irreversible_reason.is_some())
        {
            return Err(ControlledWriteValidationError::InvalidField(
                "rejected_response_contract",
            ));
        }
        if self.status == ControlledWriteStatus::AcceptedDryRun {
            match self.summary.operation_kind {
                ControlledWriteOperationKind::OcservReload
                    if !self.rollback_available
                        && self.irreversible_reason
                            == Some(IrreversibilityReason::ReloadHasNoRollback) => {}
                ControlledWriteOperationKind::OcservRestart
                    if !self.rollback_available
                        && self.irreversible_reason
                            == Some(IrreversibilityReason::RestartOutageCannotBeUndone) => {}
                ControlledWriteOperationKind::OcservConfigApply if self.rollback_available => {}
                ControlledWriteOperationKind::OcservConfigRollback if self.rollback_available => {}
                ControlledWriteOperationKind::OcservSessionDisconnect => {
                    return Err(ControlledWriteValidationError::SessionDisconnectUnavailable);
                }
                _ => {
                    return Err(ControlledWriteValidationError::InvalidField(
                        "rollback_contract",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn validate_id(value: &str, field: &'static str) -> Result<(), ControlledWriteValidationError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(ControlledWriteValidationError::InvalidField(field));
    }
    Ok(())
}

fn validate_actor(value: &str) -> Result<(), ControlledWriteValidationError> {
    if value.trim().is_empty()
        || value.len() > MAX_ACTOR_BYTES
        || value
            .bytes()
            .any(|byte| !byte.is_ascii() || byte.is_ascii_control())
    {
        return Err(ControlledWriteValidationError::InvalidField("actor"));
    }
    Ok(())
}

fn validate_reason(value: &str) -> Result<(), ControlledWriteValidationError> {
    let lower = value.to_ascii_lowercase();
    if value.trim().is_empty()
        || value.len() > MAX_REASON_BYTES
        || value
            .bytes()
            .any(|byte| !byte.is_ascii() || byte.is_ascii_control())
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b' ' | b'.' | b',' | b':' | b'_' | b'-' | b'(' | b')')
        })
        || [
            "/etc/",
            "/var/",
            "/home/",
            "/users/",
            "systemctl",
            "journalctl",
            "occtl",
            "shell",
            "command",
            "script",
            "username",
            "client_ip",
            "session_id",
            "password",
            "secret",
            "token",
            "credential",
            "private key",
        ]
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return Err(ControlledWriteValidationError::InvalidField("reason"));
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), ControlledWriteValidationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ControlledWriteValidationError::InvalidField(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_request() -> ControlledWriteRequest {
        ControlledWriteRequest {
            operation_id: "op_123".to_string(),
            operation_kind: ControlledWriteOperationKind::OcservConfigApply,
            actor: "alice@example.com".to_string(),
            reason: "approved maintenance".to_string(),
            change_ticket: "CHG-123".to_string(),
            approval_id: "approval_123".to_string(),
            request_id: "018f2f5e-4c44-7b55-9000-000000000001".to_string(),
            dry_run: true,
            signed_intent: SignedControlledWriteIntent {
                key_id: "key-1".to_string(),
                algorithm: "Ed25519".to_string(),
                payload_sha256: "a".repeat(64),
                signature: "s".repeat(88),
            },
            params: ControlledWriteParams::OcservConfigApply {
                bundle_id: "bundle-1".to_string(),
                bundle_sha256: "b".repeat(64),
                expected_previous_bundle_id: Some("bundle-0".to_string()),
            },
        }
    }

    #[test]
    fn draft_request_is_bounded_dry_run_only_and_closed() {
        let request = valid_request();
        request.validate_dry_run().expect("valid dry-run scaffold");
        let value = serde_json::to_value(&request).expect("serialize request");
        let decoded: ControlledWriteRequest =
            serde_json::from_value(value).expect("decode request");
        assert!(decoded.dry_run);

        let mut unsafe_request = request.clone();
        unsafe_request.dry_run = false;
        assert_eq!(
            unsafe_request.validate_dry_run(),
            Err(ControlledWriteValidationError::NonDryRun)
        );
        unsafe_request = request;
        unsafe_request.reason = "run systemctl restart ocserv".to_string();
        assert!(unsafe_request.validate_dry_run().is_err());
    }

    #[test]
    fn restart_requires_explicit_outage_acknowledgement() {
        let mut request = valid_request();
        request.operation_kind = ControlledWriteOperationKind::OcservRestart;
        request.params = ControlledWriteParams::OcservRestart {
            acknowledge_outage: false,
        };
        assert_eq!(
            request.validate_dry_run(),
            Err(ControlledWriteValidationError::InvalidField(
                "params.acknowledge_outage"
            ))
        );
        request.params = ControlledWriteParams::OcservRestart {
            acknowledge_outage: true,
        };
        request
            .validate_dry_run()
            .expect("acknowledged restart preflight");
    }

    #[test]
    fn debug_redacts_signed_intent_and_session_params_have_no_identifier() {
        let mut request = valid_request();
        request.actor = "sensitive-actor".to_string();
        request.reason = "sensitive maintenance reason".to_string();
        let debug = format!("{request:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&"s".repeat(88)));
        assert!(!debug.contains("sensitive-actor"));
        assert!(!debug.contains("sensitive maintenance reason"));

        let session = serde_json::to_string(&ControlledWriteParams::OcservSessionDisconnect {})
            .expect("serialize session scaffold");
        for forbidden in ["token", "username", "client_ip", "session_id"] {
            assert!(!session.contains(forbidden));
        }
    }

    #[test]
    fn reason_rejects_secret_assignments_and_local_paths() {
        for reason in [
            "password=hunter2",
            "token abc123",
            "see /home/alice/secret.conf",
            "credential rotation",
        ] {
            let mut request = valid_request();
            request.reason = reason.to_string();
            assert_eq!(
                request.validate_dry_run(),
                Err(ControlledWriteValidationError::InvalidField("reason"))
            );
        }
    }

    #[test]
    fn response_uses_typed_low_sensitive_summary() {
        let response = ControlledWriteResponse {
            operation_id: "op_123".to_string(),
            request_id: "018f2f5e-4c44-7b55-9000-000000000002".to_string(),
            status: ControlledWriteStatus::AcceptedDryRun,
            dry_run: true,
            summary: ControlledWriteSummary {
                operation_kind: ControlledWriteOperationKind::OcservReload,
                policy_decision: ControlledWritePolicyDecision::WouldAllow,
                validation_code: Some("POLICY_ALLOWED".to_string()),
            },
            rollback_available: false,
            rollback_plan_id: None,
            irreversible_reason: Some(IrreversibilityReason::ReloadHasNoRollback),
        };
        response.validate().expect("valid response");
        let text = serde_json::to_string(&response).expect("serialize response");
        for forbidden in ["stdout", "stderr", "username", "client_ip", "session_id"] {
            assert!(!text.contains(forbidden));
        }
    }

    #[test]
    fn response_rejects_inconsistent_policy_and_rollback_claims() {
        let base = ControlledWriteResponse {
            operation_id: "op_123".to_string(),
            request_id: "018f2f5e-4c44-7b55-9000-000000000003".to_string(),
            status: ControlledWriteStatus::AcceptedDryRun,
            dry_run: true,
            summary: ControlledWriteSummary {
                operation_kind: ControlledWriteOperationKind::OcservConfigApply,
                policy_decision: ControlledWritePolicyDecision::WouldAllow,
                validation_code: None,
            },
            rollback_available: true,
            rollback_plan_id: Some("rollback_123".to_string()),
            irreversible_reason: None,
        };
        base.validate().expect("consistent dry-run response");

        let mut invalid = base.clone();
        invalid.rollback_plan_id = None;
        assert!(invalid.validate().is_err());

        invalid = base.clone();
        invalid.summary.policy_decision = ControlledWritePolicyDecision::Denied;
        assert!(invalid.validate().is_err());

        invalid = base;
        invalid.summary.operation_kind = ControlledWriteOperationKind::OcservRestart;
        invalid.rollback_available = false;
        invalid.rollback_plan_id = None;
        assert!(invalid.validate().is_err());

        let mut rollback_without_plan = ControlledWriteResponse {
            operation_id: "op_456".to_string(),
            request_id: "018f2f5e-4c44-7b55-9000-000000000004".to_string(),
            status: ControlledWriteStatus::AcceptedDryRun,
            dry_run: true,
            summary: ControlledWriteSummary {
                operation_kind: ControlledWriteOperationKind::OcservConfigRollback,
                policy_decision: ControlledWritePolicyDecision::WouldAllow,
                validation_code: None,
            },
            rollback_available: false,
            rollback_plan_id: None,
            irreversible_reason: None,
        };
        assert!(rollback_without_plan.validate().is_err());
        rollback_without_plan.rollback_available = true;
        rollback_without_plan.rollback_plan_id = Some("rollback_456".to_string());
        rollback_without_plan
            .validate()
            .expect("rollback preflight includes a recovery plan");
    }
}
