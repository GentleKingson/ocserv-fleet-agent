use ocfleet_protocol::ocserv::{
    OCSERV_CERT_DAYS_REMAINING_MAX, OCSERV_CERT_DAYS_REMAINING_MIN, OCSERV_ROLLING_COUNT_MAX,
    OcservCollectorStatus, OcservServiceEnabledState, OcservServiceState,
    is_valid_ocserv_collected_at, is_valid_ocserv_version, is_valid_sha256_short_hex,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub mod producer;

pub const SCHEMA_VERSION_V2: &str = "ocfleet.ocserv.snapshot.v2";
pub const SCHEMA_MAJOR_VERSION_V2: u32 = 2;
pub const MAX_SNAPSHOT_BYTES: usize = 16 * 1024;
pub const MACHINE_SCHEMA: &str = include_str!("../schema/ocfleet.ocserv.snapshot.v2.schema.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotDocument {
    pub schema_version: String,
    pub collected_at: String,
    pub collector_status: OcservCollectorStatus,
    pub service_state: OcservServiceState,
    pub enabled_state: OcservServiceEnabledState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_total: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_failure_count_rolling: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_failure_count_rolling: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_min_days_remaining: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_fingerprint_short: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes")]
    TooLarge,
    #[error("snapshot is not closed valid JSON")]
    InvalidJson,
    #[error("snapshot schema version is unsupported")]
    UnsupportedVersion,
    #[error("snapshot field is invalid: {0}")]
    InvalidField(&'static str),
    #[error("failed to read snapshot")]
    Io(#[from] std::io::Error),
}

pub fn validate_bytes(bytes: &[u8]) -> Result<SnapshotDocument, ValidationError> {
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(ValidationError::TooLarge);
    }
    let document: SnapshotDocument =
        serde_json::from_slice(bytes).map_err(|_| ValidationError::InvalidJson)?;
    validate(&document)?;
    Ok(document)
}

pub fn validate_file(path: &Path) -> Result<SnapshotDocument, ValidationError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_SNAPSHOT_BYTES as u64
    {
        return Err(ValidationError::InvalidField("input_path"));
    }
    validate_bytes(&fs::read(path)?)
}

pub fn validate(document: &SnapshotDocument) -> Result<(), ValidationError> {
    if document.schema_version != SCHEMA_VERSION_V2 {
        return Err(ValidationError::UnsupportedVersion);
    }
    if !is_valid_ocserv_collected_at(&document.collected_at) {
        return Err(ValidationError::InvalidField("collected_at"));
    }
    if document
        .version
        .as_deref()
        .is_some_and(|v| !is_valid_ocserv_version(v))
    {
        return Err(ValidationError::InvalidField("version"));
    }
    for count in [
        document.auth_failure_count_rolling,
        document.connection_failure_count_rolling,
    ]
    .into_iter()
    .flatten()
    {
        if count > OCSERV_ROLLING_COUNT_MAX {
            return Err(ValidationError::InvalidField("rolling_count"));
        }
    }
    if document.cert_min_days_remaining.is_some_and(|v| {
        !(OCSERV_CERT_DAYS_REMAINING_MIN..=OCSERV_CERT_DAYS_REMAINING_MAX).contains(&v)
    }) {
        return Err(ValidationError::InvalidField("cert_min_days_remaining"));
    }
    if document
        .config_fingerprint_short
        .as_deref()
        .is_some_and(|v| !is_valid_sha256_short_hex(v))
    {
        return Err(ValidationError::InvalidField("config_fingerprint_short"));
    }
    Ok(())
}

pub fn supports_version(version: &str) -> bool {
    version == SCHEMA_VERSION_V2
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid() -> serde_json::Value {
        json!({"schema_version":SCHEMA_VERSION_V2,"collected_at":"2026-07-12T00:00:00Z","collector_status":"ok","service_state":"running","enabled_state":"enabled","session_total":3})
    }

    #[test]
    fn roundtrip_and_unknown_fields_are_closed() {
        let value = valid();
        let doc = validate_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(serde_json::to_value(doc).unwrap(), value);
        let mut bad = value;
        bad["username"] = json!("alice");
        assert!(matches!(
            validate_bytes(&serde_json::to_vec(&bad).unwrap()),
            Err(ValidationError::InvalidJson)
        ));
    }
    #[test]
    fn bounds_and_versions_fail_closed() {
        let mut value = valid();
        value["schema_version"] = json!("ocfleet.ocserv.snapshot.v3");
        assert!(matches!(
            validate_bytes(&serde_json::to_vec(&value).unwrap()),
            Err(ValidationError::UnsupportedVersion)
        ));
        assert!(matches!(
            validate_bytes(&vec![b' '; MAX_SNAPSHOT_BYTES + 1]),
            Err(ValidationError::TooLarge)
        ));
        assert!(!supports_version("v1"));
    }
    #[test]
    fn forbidden_raw_fields_are_rejected() {
        for key in [
            "raw_logs",
            "username",
            "ip",
            "session",
            "cookie",
            "certificate_identity",
            "raw_config",
            "command_output",
        ] {
            let mut value = valid();
            value[key] = json!("forbidden");
            assert!(
                validate_bytes(&serde_json::to_vec(&value).unwrap()).is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn machine_schema_is_closed_and_version_aligned() {
        let schema: serde_json::Value = serde_json::from_str(MACHINE_SCHEMA).unwrap();
        assert_eq!(
            schema["properties"]["schema_version"]["const"],
            SCHEMA_VERSION_V2
        );
        assert_eq!(schema["additionalProperties"], false);
    }
}
