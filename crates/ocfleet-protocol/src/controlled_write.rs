use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlledWriteOperationKind {
    OcservReload,
    OcservRestart,
    OcservConfigApply,
    OcservConfigRollback,
    OcservSessionDisconnect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedControlledWriteIntent {
    pub key_id: String,
    pub algorithm: String,
    pub payload_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlledWriteParams {
    OcservReload {},
    OcservRestart {
        emergency: bool,
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
    OcservSessionDisconnect {
        session_token: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlledWriteStatus {
    AcceptedDryRun,
    Rejected,
    PendingApproval,
    Completed,
    RollbackRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledWriteResponse {
    pub operation_id: String,
    pub request_id: String,
    pub status: ControlledWriteStatus,
    pub dry_run: bool,
    pub summary: Value,
    pub rollback_available: bool,
    pub rollback_plan_id: Option<String>,
    pub irreversible_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn draft_request_round_trips_without_raw_command_fields() {
        let request = ControlledWriteRequest {
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
                signature: "base64-signature".to_string(),
            },
            params: ControlledWriteParams::OcservConfigApply {
                bundle_id: "bundle-1".to_string(),
                bundle_sha256: "b".repeat(64),
                expected_previous_bundle_id: Some("bundle-0".to_string()),
            },
        };

        let value = serde_json::to_value(&request).expect("serialize draft request");
        let text = value.to_string();
        for forbidden in [
            "command",
            "shell",
            "script",
            "unit",
            "journal",
            "username",
            "client_ip",
            "session_id",
            "raw_config",
        ] {
            assert!(
                !text.contains(forbidden),
                "draft DTO must not contain forbidden key marker: {forbidden}"
            );
        }
        let decoded: ControlledWriteRequest =
            serde_json::from_value(value).expect("decode draft request");
        assert!(decoded.dry_run);
    }

    #[test]
    fn draft_response_is_low_sensitive_summary_shape() {
        let response = ControlledWriteResponse {
            operation_id: "op_123".to_string(),
            request_id: "018f2f5e-4c44-7b55-9000-000000000002".to_string(),
            status: ControlledWriteStatus::AcceptedDryRun,
            dry_run: true,
            summary: json!({
                "operation_kind": "ocserv_reload",
                "policy": "allowed_by_local_policy"
            }),
            rollback_available: false,
            rollback_plan_id: None,
            irreversible_reason: Some("reload has no direct rollback".to_string()),
        };

        let text = serde_json::to_string(&response).expect("serialize response");
        for forbidden in [
            "stdout",
            "stderr",
            "raw",
            "username",
            "client_ip",
            "session_id",
        ] {
            assert!(
                !text.contains(forbidden),
                "draft response must not contain forbidden marker: {forbidden}"
            );
        }
    }
}
