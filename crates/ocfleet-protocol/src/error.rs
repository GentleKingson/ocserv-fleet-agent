use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    FrameTooLarge,
    FrameReadFailed,
    InvalidJson,
    InvalidVersion,
    InvalidRequestId,
    InvalidTimestamp,
    RequestExpired,
    ClockSkewExceeded,
    InvalidNonce,
    ReplayedNonce,
    InvalidDeadline,
    ParamsInvalid,
    UnsupportedAuthScheme,
    ResponseTooLarge,
    InvalidResponse,
    EndpointNotAllowed,
    EndpointMismatch,
    NodeNotFound,
    NodeDisabled,
    MethodNotFound,
    MethodNotAllowed,
    ConnectFailed,
    RpcTimeout,
    AuditWriteFailed,
    ResourceExhausted,
    SqliteError,
    SqliteBusyTimeout,
    SchemaMigrationFailed,
    SchemaVersionUnsupported,
    ConfigLoadFailed,
    SecretKeyLoadFailed,
    SecretKeyPermissionInvalid,
    OcservReadonlyDisabled,
    OcservProviderUnavailable,
    OcservProviderInvalidData,
    OcservProviderUnsafeSource,
    OcservOutputBoundExceeded,
    OcservUnsupportedField,
    InternalError,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default)]
    pub details: serde_json::Value,
}

impl RpcError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: serde_json::json!({}),
        }
    }
}
