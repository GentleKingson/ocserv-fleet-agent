use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::ocserv::{
    OCSERV_ERROR_MESSAGE_MAX_BYTES, OcservCertExpiryResponse, OcservConfigFingerprintResponse,
    OcservServiceSummaryResponse, OcservSessionsSummaryResponse, OcservVersionResponse,
};

use crate::ocserv::{CertificateExpiryProvider, ConfigFingerprintProvider};

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
        let mut message = sanitize_provider_error_message(&message.into());
        if message.len() > OCSERV_ERROR_MESSAGE_MAX_BYTES {
            truncate_to_boundary(&mut message, OCSERV_ERROR_MESSAGE_MAX_BYTES);
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

fn sanitize_provider_error_message(message: &str) -> String {
    let sanitized = message
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>();
    if contains_forbidden_provider_marker(&sanitized) {
        "ocserv readonly provider error".to_string()
    } else {
        sanitized
    }
}

fn contains_forbidden_provider_marker(message: &str) -> bool {
    let lowered = message.to_ascii_lowercase();
    [
        "/etc/",
        "/var/log",
        "ocserv.conf",
        "server-cert",
        "begin certificate",
        "private key",
        concat!("system", "ctl"),
        concat!("journal", "ctl"),
        concat!("occ", "tl"),
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

fn truncate_to_boundary(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
}

pub struct CompositeOcservReadonlyProvider {
    snapshot: Box<dyn OcservReadonlyProvider>,
    certs: CertificateExpiryProvider,
    config: ConfigFingerprintProvider,
}

impl CompositeOcservReadonlyProvider {
    pub fn new(
        snapshot: Box<dyn OcservReadonlyProvider>,
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
