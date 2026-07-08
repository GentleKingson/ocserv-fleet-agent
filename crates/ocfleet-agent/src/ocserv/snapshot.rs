use std::fs;
use std::path::{Path, PathBuf};

use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::ocserv::{
    OcservFieldStatus, OcservFreshness, OcservReadonlyMeta, OcservReadonlySource,
    OcservServiceEnabledState, OcservServiceState, OcservServiceSummary,
    OcservServiceSummaryResponse, OcservSessionsSummary, OcservSessionsSummaryResponse,
    OcservVersionResponse,
};
use serde::Deserialize;
use time::OffsetDateTime;

use crate::ocserv::{OcservReadonlyError, OcservReadonlyProvider, sanitize};

const SNAPSHOT_MAX_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone)]
pub struct SnapshotOcservReadonlyProvider {
    path: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotDocument {
    #[serde(default)]
    service: Option<OcservServiceSummary>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    sessions: Option<SnapshotSessions>,
    #[serde(default)]
    collected_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotSessions {
    total: u32,
}

impl SnapshotOcservReadonlyProvider {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn read(&self) -> Result<SnapshotDocument, OcservReadonlyError> {
        let bytes = read_private_snapshot(&self.path)?;
        serde_json::from_slice(&bytes).map_err(|_| {
            OcservReadonlyError::new(
                ErrorCode::OcservProviderInvalidData,
                "ocserv readonly snapshot is invalid",
            )
        })
    }
}

impl OcservReadonlyProvider for SnapshotOcservReadonlyProvider {
    fn service_summary(&self) -> Result<OcservServiceSummaryResponse, OcservReadonlyError> {
        let snapshot = self.read()?;
        let service = snapshot.service.unwrap_or(OcservServiceSummary {
            state: OcservServiceState::Unavailable,
            enabled: OcservServiceEnabledState::Unavailable,
            since: None,
        });
        sanitize::service_summary(OcservServiceSummaryResponse {
            service,
            meta: snapshot_meta(snapshot.collected_at),
        })
    }

    fn version(&self) -> Result<OcservVersionResponse, OcservReadonlyError> {
        let snapshot = self.read()?;
        let status = if snapshot.version.is_some() {
            OcservFieldStatus::Available
        } else {
            OcservFieldStatus::Unavailable
        };
        sanitize::version(OcservVersionResponse {
            version: snapshot.version,
            status,
            meta: snapshot_meta(snapshot.collected_at),
        })
    }

    fn sessions_summary(&self) -> Result<OcservSessionsSummaryResponse, OcservReadonlyError> {
        let snapshot = self.read()?;
        let total = snapshot.sessions.map(|sessions| sessions.total);
        let status = if total.is_some() {
            OcservFieldStatus::Available
        } else {
            OcservFieldStatus::Unavailable
        };
        sanitize::sessions_summary(OcservSessionsSummaryResponse {
            sessions: OcservSessionsSummary { total, status },
            meta: snapshot_meta(snapshot.collected_at),
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

fn snapshot_meta(collected_at: Option<String>) -> OcservReadonlyMeta {
    OcservReadonlyMeta {
        source: OcservReadonlySource::Snapshot,
        collected_at: collected_at.unwrap_or_else(now_rfc3339),
        freshness: OcservFreshness::Cached,
    }
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("RFC3339 formatting succeeds")
}

fn read_private_snapshot(path: &Path) -> Result<Vec<u8>, OcservReadonlyError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        OcservReadonlyError::new(
            ErrorCode::OcservProviderUnavailable,
            "ocserv readonly snapshot is unavailable",
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(OcservReadonlyError::new(
            ErrorCode::OcservProviderUnsafeSource,
            "ocserv readonly snapshot source is unsafe",
        ));
    }
    if metadata.len() > SNAPSHOT_MAX_BYTES {
        return Err(OcservReadonlyError::new(
            ErrorCode::OcservOutputBoundExceeded,
            "ocserv readonly snapshot is too large",
        ));
    }
    require_private_permissions(&metadata)?;
    fs::read(path).map_err(|_| {
        OcservReadonlyError::new(
            ErrorCode::OcservProviderUnavailable,
            "ocserv readonly snapshot is unavailable",
        )
    })
}

#[cfg(unix)]
fn require_private_permissions(metadata: &fs::Metadata) -> Result<(), OcservReadonlyError> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(OcservReadonlyError::new(
            ErrorCode::OcservProviderUnsafeSource,
            "ocserv readonly snapshot source is unsafe",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_private_permissions(_metadata: &fs::Metadata) -> Result<(), OcservReadonlyError> {
    Ok(())
}
