use std::path::Path;

use ocfleet_config::agent::OcservConfigFingerprintConfig;
use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::ocserv::{
    OcservConfigFingerprint, OcservConfigFingerprintResponse, OcservFieldStatus, OcservFreshness,
    OcservReadonlyMeta, OcservReadonlySource,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::ocserv::{
    OcservReadonlyError, OcservReadonlyProvider, sanitize,
    trusted_file::{PermissionPolicy, read_bounded_trusted_file},
};

const CONFIG_MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ConfigFingerprintProvider {
    config: Option<OcservConfigFingerprintConfig>,
}

impl ConfigFingerprintProvider {
    pub fn new(config: Option<OcservConfigFingerprintConfig>) -> Self {
        Self { config }
    }
}

impl OcservReadonlyProvider for ConfigFingerprintProvider {
    fn service_summary(
        &self,
    ) -> Result<ocfleet_protocol::ocserv::OcservServiceSummaryResponse, OcservReadonlyError> {
        Err(OcservReadonlyError::new(
            ErrorCode::OcservProviderUnavailable,
            "ocserv service provider is unavailable",
        ))
    }

    fn version(
        &self,
    ) -> Result<ocfleet_protocol::ocserv::OcservVersionResponse, OcservReadonlyError> {
        Err(OcservReadonlyError::new(
            ErrorCode::OcservProviderUnavailable,
            "ocserv version provider is unavailable",
        ))
    }

    fn sessions_summary(
        &self,
    ) -> Result<ocfleet_protocol::ocserv::OcservSessionsSummaryResponse, OcservReadonlyError> {
        Err(OcservReadonlyError::new(
            ErrorCode::OcservProviderUnavailable,
            "ocserv sessions provider is unavailable",
        ))
    }

    fn cert_expiry(
        &self,
    ) -> Result<ocfleet_protocol::ocserv::OcservCertExpiryResponse, OcservReadonlyError> {
        Err(OcservReadonlyError::new(
            ErrorCode::OcservProviderUnavailable,
            "ocserv certificate provider is unavailable",
        ))
    }

    fn config_fingerprint(&self) -> Result<OcservConfigFingerprintResponse, OcservReadonlyError> {
        let Some(config) = &self.config else {
            return sanitize::config_fingerprint(OcservConfigFingerprintResponse {
                fingerprint: OcservConfigFingerprint {
                    algorithm: "sha256".to_string(),
                    hash: None,
                    status: OcservFieldStatus::Unavailable,
                },
                meta: meta(),
            });
        };
        let bytes = read_bounded_regular_file(&config.config_path, CONFIG_MAX_BYTES)?;
        let digest = Sha256::digest(&bytes);
        sanitize::config_fingerprint(OcservConfigFingerprintResponse {
            fingerprint: OcservConfigFingerprint {
                algorithm: "sha256".to_string(),
                hash: Some(format!("{digest:x}")),
                status: OcservFieldStatus::Available,
            },
            meta: meta(),
        })
    }
}

fn read_bounded_regular_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, OcservReadonlyError> {
    read_bounded_trusted_file(
        path,
        max_bytes,
        PermissionPolicy::TrustedReadable,
        "ocserv config fingerprint unavailable",
        "ocserv config fingerprint source is unsafe",
        "ocserv config fingerprint source is too large",
    )
}

fn meta() -> OcservReadonlyMeta {
    OcservReadonlyMeta {
        source: OcservReadonlySource::Provider,
        collected_at: OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .expect("RFC3339 formatting succeeds"),
        freshness: OcservFreshness::Live,
    }
}
