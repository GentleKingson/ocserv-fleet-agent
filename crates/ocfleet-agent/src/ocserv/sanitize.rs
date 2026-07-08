use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::ocserv::{
    OCSERV_CERT_MAX_ENTRIES, OcservCertExpiryResponse, OcservConfigFingerprintResponse,
    OcservServiceSummaryResponse, OcservSessionsSummaryResponse, OcservVersionResponse,
    is_valid_ocserv_name, is_valid_ocserv_version, is_valid_sha256_hex,
    validate_ocserv_response_json_size,
};

use crate::ocserv::OcservReadonlyError;

pub fn service_summary(
    response: OcservServiceSummaryResponse,
) -> Result<OcservServiceSummaryResponse, OcservReadonlyError> {
    if response
        .service
        .since
        .as_deref()
        .is_some_and(has_scalar_control_or_too_long)
    {
        return invalid_data("ocserv service summary contains invalid timestamp");
    }
    bounded(response)
}

pub fn version(
    response: OcservVersionResponse,
) -> Result<OcservVersionResponse, OcservReadonlyError> {
    if let Some(version) = response.version.as_deref()
        && !is_valid_ocserv_version(version)
    {
        return invalid_data("ocserv version is invalid");
    }
    bounded(response)
}

pub fn sessions_summary(
    response: OcservSessionsSummaryResponse,
) -> Result<OcservSessionsSummaryResponse, OcservReadonlyError> {
    bounded(response)
}

pub fn cert_expiry(
    response: OcservCertExpiryResponse,
) -> Result<OcservCertExpiryResponse, OcservReadonlyError> {
    if response.certs.len() > OCSERV_CERT_MAX_ENTRIES {
        return Err(OcservReadonlyError::new(
            ErrorCode::OcservOutputBoundExceeded,
            "ocserv certificate response is too large",
        ));
    }
    for cert in &response.certs {
        if !is_valid_ocserv_name(&cert.name) {
            return invalid_data("ocserv certificate name is invalid");
        }
        for value in [cert.not_before.as_deref(), cert.not_after.as_deref()]
            .into_iter()
            .flatten()
        {
            if has_scalar_control_or_too_long(value) {
                return invalid_data("ocserv certificate timestamp is invalid");
            }
        }
        if cert
            .fingerprint_sha256
            .as_deref()
            .is_some_and(|hash| !is_valid_sha256_hex(hash))
        {
            return invalid_data("ocserv certificate fingerprint is invalid");
        }
    }
    bounded(response)
}

pub fn config_fingerprint(
    response: OcservConfigFingerprintResponse,
) -> Result<OcservConfigFingerprintResponse, OcservReadonlyError> {
    if response.fingerprint.algorithm != "sha256" {
        return invalid_data("ocserv config fingerprint algorithm is invalid");
    }
    if response
        .fingerprint
        .hash
        .as_deref()
        .is_some_and(|hash| !is_valid_sha256_hex(hash))
    {
        return invalid_data("ocserv config fingerprint hash is invalid");
    }
    bounded(response)
}

fn bounded<T>(response: T) -> Result<T, OcservReadonlyError>
where
    T: serde::Serialize,
{
    validate_ocserv_response_json_size(&response).map_err(|_| {
        OcservReadonlyError::new(
            ErrorCode::OcservOutputBoundExceeded,
            "ocserv response is too large",
        )
    })?;
    Ok(response)
}

fn invalid_data<T>(message: &'static str) -> Result<T, OcservReadonlyError> {
    Err(OcservReadonlyError::new(
        ErrorCode::OcservProviderInvalidData,
        message,
    ))
}

fn has_scalar_control_or_too_long(value: &str) -> bool {
    value.len() > 64 || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
}
