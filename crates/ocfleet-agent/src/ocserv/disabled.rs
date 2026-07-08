use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::ocserv::{
    OcservCertExpiryResponse, OcservConfigFingerprintResponse, OcservServiceSummaryResponse,
    OcservSessionsSummaryResponse, OcservVersionResponse,
};

use crate::ocserv::{OcservReadonlyError, OcservReadonlyProvider};

#[derive(Debug, Clone, Copy)]
pub struct DisabledOcservReadonlyProvider;

impl DisabledOcservReadonlyProvider {
    fn disabled<T>(&self) -> Result<T, OcservReadonlyError> {
        Err(OcservReadonlyError::new(
            ErrorCode::OcservReadonlyDisabled,
            "ocserv readonly provider is disabled",
        ))
    }
}

impl OcservReadonlyProvider for DisabledOcservReadonlyProvider {
    fn service_summary(&self) -> Result<OcservServiceSummaryResponse, OcservReadonlyError> {
        self.disabled()
    }

    fn version(&self) -> Result<OcservVersionResponse, OcservReadonlyError> {
        self.disabled()
    }

    fn sessions_summary(&self) -> Result<OcservSessionsSummaryResponse, OcservReadonlyError> {
        self.disabled()
    }

    fn cert_expiry(&self) -> Result<OcservCertExpiryResponse, OcservReadonlyError> {
        self.disabled()
    }

    fn config_fingerprint(&self) -> Result<OcservConfigFingerprintResponse, OcservReadonlyError> {
        self.disabled()
    }
}
