use std::path::{Path, PathBuf};

use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::ocserv::{
    OcservCollectorStatus, OcservFieldStatus, OcservFreshness, OcservLiveReadonlyMetadata,
    OcservReadonlyMeta, OcservReadonlySource, OcservServiceEnabledState, OcservServiceState,
    OcservServiceSummary, OcservServiceSummaryResponse, OcservSessionsSummary,
    OcservSessionsSummaryResponse, OcservVersionResponse, is_valid_ocserv_collected_at,
    is_valid_ocserv_version,
};
use serde::Deserialize;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use crate::ocserv::{
    OcservReadonlyError, OcservReadonlyProvider, sanitize,
    trusted_file::{PermissionPolicy, read_bounded_trusted_file},
};

const COLLECTOR_SNAPSHOT_SCHEMA_VERSION: &str = "ocfleet.ocserv.snapshot.v2";
const SNAPSHOT_MAX_BYTES: u64 = 16 * 1024;
const MAX_SNAPSHOT_AGE_SECONDS: i64 = 60 * 60;
const MAX_FUTURE_SKEW_SECONDS: i64 = 5 * 60;

#[derive(Debug, Clone)]
pub struct CollectorSnapshotOcservReadonlyProvider {
    path: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectorSnapshotDocument {
    schema_version: String,
    collected_at: String,
    collector_status: OcservCollectorStatus,
    service_state: OcservServiceState,
    enabled_state: OcservServiceEnabledState,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    session_total: Option<u32>,
    #[serde(default)]
    auth_failure_count_rolling: Option<u64>,
    #[serde(default)]
    connection_failure_count_rolling: Option<u64>,
    #[serde(default)]
    cert_min_days_remaining: Option<i64>,
    #[serde(default)]
    config_fingerprint_short: Option<String>,
}

impl CollectorSnapshotOcservReadonlyProvider {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn read(&self) -> Result<CollectorSnapshotDocument, OcservReadonlyError> {
        let bytes = read_private_snapshot(&self.path)?;
        let snapshot: CollectorSnapshotDocument = serde_json::from_slice(&bytes).map_err(|_| {
            OcservReadonlyError::new(
                ErrorCode::OcservProviderInvalidData,
                "ocserv live snapshot is invalid",
            )
        })?;
        validate_snapshot(&snapshot)?;
        Ok(snapshot)
    }
}

impl OcservReadonlyProvider for CollectorSnapshotOcservReadonlyProvider {
    fn service_summary(&self) -> Result<OcservServiceSummaryResponse, OcservReadonlyError> {
        let snapshot = self.read()?;
        sanitize::service_summary(OcservServiceSummaryResponse {
            service: OcservServiceSummary {
                state: snapshot.service_state,
                enabled: snapshot.enabled_state,
                since: None,
            },
            meta: snapshot_meta(&snapshot.collected_at),
            live: Some(live_metadata(&snapshot)),
        })
    }

    fn version(&self) -> Result<OcservVersionResponse, OcservReadonlyError> {
        let snapshot = self.read()?;
        let status = if snapshot.version.is_some() {
            OcservFieldStatus::Available
        } else {
            OcservFieldStatus::Unavailable
        };
        let meta = snapshot_meta(&snapshot.collected_at);
        sanitize::version(OcservVersionResponse {
            version: snapshot.version,
            status,
            meta,
        })
    }

    fn sessions_summary(&self) -> Result<OcservSessionsSummaryResponse, OcservReadonlyError> {
        let snapshot = self.read()?;
        let status = if snapshot.session_total.is_some() {
            OcservFieldStatus::Available
        } else {
            OcservFieldStatus::Unavailable
        };
        sanitize::sessions_summary(OcservSessionsSummaryResponse {
            sessions: OcservSessionsSummary {
                total: snapshot.session_total,
                status,
            },
            meta: snapshot_meta(&snapshot.collected_at),
        })
    }

    fn cert_expiry(
        &self,
    ) -> Result<ocfleet_protocol::ocserv::OcservCertExpiryResponse, OcservReadonlyError> {
        Err(OcservReadonlyError::new(
            ErrorCode::OcservProviderUnavailable,
            "ocserv certificate provider is unavailable",
        ))
    }

    fn config_fingerprint(
        &self,
    ) -> Result<ocfleet_protocol::ocserv::OcservConfigFingerprintResponse, OcservReadonlyError>
    {
        Err(OcservReadonlyError::new(
            ErrorCode::OcservProviderUnavailable,
            "ocserv config fingerprint provider is unavailable",
        ))
    }
}

fn validate_snapshot(snapshot: &CollectorSnapshotDocument) -> Result<(), OcservReadonlyError> {
    if snapshot.schema_version != COLLECTOR_SNAPSHOT_SCHEMA_VERSION {
        return invalid_data("ocserv live snapshot schema is unsupported");
    }
    if !is_valid_ocserv_collected_at(&snapshot.collected_at) {
        return invalid_data("ocserv live snapshot timestamp is invalid");
    }
    validate_fresh_timestamp(&snapshot.collected_at)?;
    if let Some(version) = snapshot.version.as_deref()
        && !is_valid_ocserv_version(version)
    {
        return invalid_data("ocserv live version is invalid");
    }
    sanitize::validate_live_metadata(&live_metadata(snapshot))?;
    Ok(())
}

fn validate_fresh_timestamp(value: &str) -> Result<(), OcservReadonlyError> {
    let collected_at = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| invalid_data_error("ocserv live snapshot timestamp is invalid"))?;
    let now = OffsetDateTime::now_utc();
    if collected_at > now + Duration::seconds(MAX_FUTURE_SKEW_SECONDS) {
        return invalid_data("ocserv live snapshot timestamp is invalid");
    }
    if now - collected_at > Duration::seconds(MAX_SNAPSHOT_AGE_SECONDS) {
        return Err(OcservReadonlyError::new(
            ErrorCode::OcservProviderUnavailable,
            "ocserv live snapshot is stale",
        ));
    }
    Ok(())
}

fn live_metadata(snapshot: &CollectorSnapshotDocument) -> OcservLiveReadonlyMetadata {
    OcservLiveReadonlyMetadata {
        collector_status: snapshot.collector_status,
        last_snapshot_at: snapshot.collected_at.clone(),
        auth_failure_count_rolling: snapshot.auth_failure_count_rolling,
        connection_failure_count_rolling: snapshot.connection_failure_count_rolling,
        cert_min_days_remaining: snapshot.cert_min_days_remaining,
        config_fingerprint_short: snapshot.config_fingerprint_short.clone(),
    }
}

fn snapshot_meta(collected_at: &str) -> OcservReadonlyMeta {
    OcservReadonlyMeta {
        source: OcservReadonlySource::Snapshot,
        collected_at: collected_at.to_string(),
        freshness: OcservFreshness::Cached,
    }
}

fn read_private_snapshot(path: &Path) -> Result<Vec<u8>, OcservReadonlyError> {
    read_bounded_trusted_file(
        path,
        SNAPSHOT_MAX_BYTES,
        PermissionPolicy::Private,
        "ocserv live snapshot is unavailable",
        "ocserv live snapshot source is unsafe",
        "ocserv live snapshot is too large",
    )
}

fn invalid_data<T>(message: &'static str) -> Result<T, OcservReadonlyError> {
    Err(invalid_data_error(message))
}

fn invalid_data_error(message: &'static str) -> OcservReadonlyError {
    OcservReadonlyError::new(ErrorCode::OcservProviderInvalidData, message)
}
