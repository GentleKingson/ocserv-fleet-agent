use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::ocserv::{
    OCSERV_ERROR_MESSAGE_MAX_BYTES, OcservCertExpiryResponse, OcservConfigFingerprintResponse,
    OcservServiceSummaryResponse, OcservSessionsSummaryResponse, OcservVersionResponse,
};

use crate::ocserv::{
    CertificateExpiryProvider, ConfigFingerprintProvider, SnapshotOcservReadonlyProvider,
};

pub trait OcservReadonlyProvider: Send + Sync {
    fn service_summary(&self) -> Result<OcservServiceSummaryResponse, OcservReadonlyError>;
    fn version(&self) -> Result<OcservVersionResponse, OcservReadonlyError>;
    fn sessions_summary(&self) -> Result<OcservSessionsSummaryResponse, OcservReadonlyError>;
    fn cert_expiry(&self) -> Result<OcservCertExpiryResponse, OcservReadonlyError>;
    fn config_fingerprint(&self) -> Result<OcservConfigFingerprintResponse, OcservReadonlyError>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct OcservReadonlyError {
    code: ErrorCode,
    message: String,
}

impl OcservReadonlyError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        let mut message = message.into();
        if message.len() > OCSERV_ERROR_MESSAGE_MAX_BYTES {
            message.truncate(OCSERV_ERROR_MESSAGE_MAX_BYTES);
        }
        Self { code, message }
    }

    pub fn code(&self) -> ErrorCode {
        self.code.clone()
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

pub struct CompositeOcservReadonlyProvider {
    snapshot: SnapshotOcservReadonlyProvider,
    certs: CertificateExpiryProvider,
    config: ConfigFingerprintProvider,
}

impl CompositeOcservReadonlyProvider {
    pub fn new(
        snapshot: SnapshotOcservReadonlyProvider,
        certs: CertificateExpiryProvider,
        config: ConfigFingerprintProvider,
    ) -> Self {
        Self {
            snapshot,
            certs,
            config,
        }
    }
}

impl OcservReadonlyProvider for CompositeOcservReadonlyProvider {
    fn service_summary(&self) -> Result<OcservServiceSummaryResponse, OcservReadonlyError> {
        self.snapshot.service_summary()
    }

    fn version(&self) -> Result<OcservVersionResponse, OcservReadonlyError> {
        self.snapshot.version()
    }

    fn sessions_summary(&self) -> Result<OcservSessionsSummaryResponse, OcservReadonlyError> {
        self.snapshot.sessions_summary()
    }

    fn cert_expiry(&self) -> Result<OcservCertExpiryResponse, OcservReadonlyError> {
        self.certs.cert_expiry()
    }

    fn config_fingerprint(&self) -> Result<OcservConfigFingerprintResponse, OcservReadonlyError> {
        self.config.config_fingerprint()
    }
}
