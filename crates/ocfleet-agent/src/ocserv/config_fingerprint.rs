use std::path::Path;

use ocfleet_config::agent::{ConfigFingerprintMode, OcservConfigFingerprintConfig};
use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::ocserv::{
    OcservConfigFingerprint, OcservConfigFingerprintDigest, OcservConfigFingerprintResponse,
    OcservFieldStatus, OcservFreshness, OcservReadonlyMeta, OcservReadonlySource,
};
use ring::hmac;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::ocserv::{
    OcservReadonlyError, OcservReadonlyProvider, sanitize,
    trusted_file::{PermissionPolicy, read_bounded_trusted_file},
};

const CONFIG_MAX_BYTES: u64 = 1024 * 1024;
const KEY_MAX_BYTES: u64 = 1024;
const KEY_MIN_BYTES: usize = 32;

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
                    key_id: None,
                    hash: None,
                    previous: None,
                    status: OcservFieldStatus::Unavailable,
                },
                meta: meta(),
            });
        };
        let bytes = read_bounded_regular_file(&config.config_path, CONFIG_MAX_BYTES)?;
        let (algorithm, key_id, hash, previous) = match config.mode {
            ConfigFingerprintMode::LegacySha256 => (
                "sha256".to_string(),
                None,
                format!("{:x}", Sha256::digest(&bytes)),
                None,
            ),
            ConfigFingerprintMode::HmacSha256 => {
                let key_id = config.key_id.clone().ok_or_else(invalid_key)?;
                let key = read_key(config.key_path.as_deref().ok_or_else(invalid_key)?)?;
                let hash =
                    hex(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key), &bytes).as_ref());
                let previous = match (
                    config.previous_key_id.as_ref(),
                    config.previous_key_path.as_deref(),
                ) {
                    (Some(id), Some(path)) => {
                        let key = read_key(path)?;
                        Some(OcservConfigFingerprintDigest {
                            algorithm: "hmac-sha256".into(),
                            key_id: id.clone(),
                            hash: hex(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key), &bytes)
                                .as_ref()),
                        })
                    }
                    (None, None) => None,
                    _ => return Err(invalid_key()),
                };
                ("hmac-sha256".to_string(), Some(key_id), hash, previous)
            }
        };
        sanitize::config_fingerprint(OcservConfigFingerprintResponse {
            fingerprint: OcservConfigFingerprint {
                algorithm,
                key_id,
                hash: Some(hash),
                previous,
                status: OcservFieldStatus::Available,
            },
            meta: meta(),
        })
    }
}

fn read_key(path: &Path) -> Result<Vec<u8>, OcservReadonlyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(path).map_err(|_| invalid_key())?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err(invalid_key());
        }
    }
    let key = read_bounded_trusted_file(
        path,
        KEY_MAX_BYTES,
        PermissionPolicy::Private,
        "ocserv config fingerprint key unavailable",
        "ocserv config fingerprint key is unsafe",
        "ocserv config fingerprint key is too large",
    )?;
    if key.len() < KEY_MIN_BYTES {
        return Err(invalid_key());
    }
    Ok(key)
}
fn invalid_key() -> OcservReadonlyError {
    OcservReadonlyError::new(
        ErrorCode::OcservProviderUnsafeSource,
        "ocserv config fingerprint key is invalid",
    )
}
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("string write");
    }
    out
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
