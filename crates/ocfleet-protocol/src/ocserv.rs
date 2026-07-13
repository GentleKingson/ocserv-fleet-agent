use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

pub const OCSERV_RESPONSE_MAX_JSON_BYTES: usize = 8 * 1024;
pub const OCSERV_VERSION_MAX_BYTES: usize = 64;
pub const OCSERV_NAME_MAX_BYTES: usize = 64;
pub const OCSERV_COLLECTED_AT_MAX_BYTES: usize = 64;
pub const OCSERV_CERT_MAX_ENTRIES: usize = 8;
pub const OCSERV_ERROR_MESSAGE_MAX_BYTES: usize = 128;
pub const OCSERV_CONFIG_FINGERPRINT_SHORT_MIN_BYTES: usize = 6;
pub const OCSERV_CONFIG_FINGERPRINT_SHORT_MAX_BYTES: usize = 16;
pub const OCSERV_ROLLING_COUNT_MAX: u64 = 1_000_000;
pub const OCSERV_CERT_DAYS_REMAINING_MIN: i64 = -3650;
pub const OCSERV_CERT_DAYS_REMAINING_MAX: i64 = 36500;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OcservProtocolValidationError {
    #[error("ocserv response exceeds {max} bytes")]
    ResponseTooLarge { max: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub struct OcservReadonlyMeta {
    pub source: OcservReadonlySource,
    pub collected_at: String,
    pub freshness: OcservFreshness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcservReadonlySource {
    Provider,
    Snapshot,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcservFreshness {
    Live,
    Cached,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcservFieldStatus {
    Available,
    Unavailable,
    Unknown,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcservServiceSummaryRequest {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcservServiceSummaryResponse {
    pub service: OcservServiceSummary,
    pub meta: OcservReadonlyMeta,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live: Option<OcservLiveReadonlyMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcservServiceSummary {
    pub state: OcservServiceState,
    pub enabled: OcservServiceEnabledState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcservServiceState {
    Running,
    Stopped,
    Failed,
    Starting,
    Stopping,
    Unknown,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcservServiceEnabledState {
    Enabled,
    Disabled,
    Static,
    Unknown,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcservVersionRequest {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcservVersionResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub status: OcservFieldStatus,
    pub meta: OcservReadonlyMeta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcservSessionsSummaryRequest {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcservSessionsSummaryResponse {
    pub sessions: OcservSessionsSummary,
    pub meta: OcservReadonlyMeta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcservSessionsSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u32>,
    pub status: OcservFieldStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcservLiveReadonlyMetadata {
    pub collector_status: OcservCollectorStatus,
    pub last_snapshot_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_failure_count_rolling: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_failure_count_rolling: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_min_days_remaining: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_fingerprint_short: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcservCollectorStatus {
    Ok,
    Partial,
    Stale,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcservCertExpiryRequest {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcservCertExpiryResponse {
    pub certs: Vec<OcservCertExpiry>,
    pub meta: OcservReadonlyMeta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcservCertExpiry {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days_remaining: Option<i64>,
    pub status: OcservCertStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcservCertStatus {
    Valid,
    ExpiringSoon,
    Expired,
    Unreadable,
    Invalid,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcservConfigFingerprintRequest {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcservConfigFingerprintResponse {
    pub fingerprint: OcservConfigFingerprint,
    pub meta: OcservReadonlyMeta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcservConfigFingerprint {
    pub algorithm: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<OcservConfigFingerprintDigest>,
    pub status: OcservFieldStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcservConfigFingerprintDigest {
    pub algorithm: String,
    pub key_id: String,
    pub hash: String,
}

impl std::fmt::Display for OcservServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Starting => "starting",
            Self::Stopping => "stopping",
            Self::Unknown => "unknown",
            Self::Unavailable => "unavailable",
        })
    }
}

impl std::fmt::Display for OcservServiceEnabledState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::Static => "static",
            Self::Unknown => "unknown",
            Self::Unavailable => "unavailable",
        })
    }
}

impl std::fmt::Display for OcservCertStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Valid => "valid",
            Self::ExpiringSoon => "expiring_soon",
            Self::Expired => "expired",
            Self::Unreadable => "unreadable",
            Self::Invalid => "invalid",
            Self::Unknown => "unknown",
        })
    }
}

impl std::fmt::Display for OcservFieldStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Available => "available",
            Self::Unavailable => "unavailable",
            Self::Unknown => "unknown",
            Self::Invalid => "invalid",
        })
    }
}

impl std::fmt::Display for OcservCollectorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ok => "ok",
            Self::Partial => "partial",
            Self::Stale => "stale",
            Self::Unavailable => "unavailable",
            Self::Unknown => "unknown",
        })
    }
}

pub fn is_valid_ocserv_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= OCSERV_VERSION_MAX_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b' ' | b'.' | b'_' | b'-' | b'+' | b'~' | b':')
        })
}

pub fn is_valid_ocserv_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= OCSERV_NAME_MAX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn is_valid_sha256_short_hex(value: &str) -> bool {
    (OCSERV_CONFIG_FINGERPRINT_SHORT_MIN_BYTES..=OCSERV_CONFIG_FINGERPRINT_SHORT_MAX_BYTES)
        .contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn is_valid_ocserv_collected_at(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= OCSERV_COLLECTED_AT_MAX_BYTES
        && value.bytes().all(|byte| byte >= 0x20 && byte != 0x7f)
        && !contains_low_sensitive_forbidden_marker(value)
        && OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).is_ok()
}

fn contains_low_sensitive_forbidden_marker(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    [
        "/etc/",
        "/var/log",
        "ocserv.conf",
        "server-cert",
        "begin certificate",
        "private key",
        "systemctl",
        "journalctl",
        "occtl",
        "execstart",
        "stdout",
        "stderr",
        "username",
        "session_id",
        "client_ip",
        "vpn_ip",
        "assigned_ip",
        "cn=",
        "san",
        "dns:",
        "issuer",
        "serial",
        "subject",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
}

pub fn validate_ocserv_response_json_size<T: Serialize>(
    response: &T,
) -> Result<(), OcservProtocolValidationError> {
    let payload = serde_json::to_vec(response).map_err(|_| {
        OcservProtocolValidationError::ResponseTooLarge {
            max: OCSERV_RESPONSE_MAX_JSON_BYTES,
        }
    })?;
    if payload.len() > OCSERV_RESPONSE_MAX_JSON_BYTES {
        return Err(OcservProtocolValidationError::ResponseTooLarge {
            max: OCSERV_RESPONSE_MAX_JSON_BYTES,
        });
    }
    Ok(())
}
