use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::ocserv::{
    OCSERV_CERT_DAYS_REMAINING_MAX, OCSERV_CERT_DAYS_REMAINING_MIN, OCSERV_CERT_MAX_ENTRIES,
    OCSERV_ROLLING_COUNT_MAX, OcservCertExpiryResponse, OcservConfigFingerprintResponse,
    OcservLiveReadonlyMetadata, OcservReadonlyMeta, OcservServiceSummaryResponse,
    OcservSessionsSummaryResponse, OcservVersionResponse, is_valid_ocserv_collected_at,
    is_valid_ocserv_name, is_valid_ocserv_version, is_valid_sha256_hex, is_valid_sha256_short_hex,
    validate_ocserv_response_json_size,
};

use crate::ocserv::OcservReadonlyError;

pub fn service_summary(
    response: OcservServiceSummaryResponse,
) -> Result<OcservServiceSummaryResponse, OcservReadonlyError> {
    validate_meta(&response.meta)?;
    if response
        .service
        .since
        .as_deref()
        .is_some_and(has_scalar_control_or_too_long)
    {
        return invalid_data("ocserv service summary contains invalid timestamp");
    }
    if let Some(live) = &response.live {
        validate_live_metadata(live)?;
    }
    bounded(response)
}

pub fn version(
    response: OcservVersionResponse,
) -> Result<OcservVersionResponse, OcservReadonlyError> {
    validate_meta(&response.meta)?;
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
    validate_meta(&response.meta)?;
    bounded(response)
}

pub fn cert_expiry(
    response: OcservCertExpiryResponse,
) -> Result<OcservCertExpiryResponse, OcservReadonlyError> {
    validate_meta(&response.meta)?;
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
    validate_meta(&response.meta)?;
    if !matches!(
        response.fingerprint.algorithm.as_str(),
        "sha256" | "hmac-sha256"
    ) {
        return invalid_data("ocserv config fingerprint algorithm is invalid");
    }
    if response.fingerprint.algorithm == "hmac-sha256" {
        if response
            .fingerprint
            .key_id
            .as_deref()
            .is_none_or(|id| !is_valid_ocserv_name(id))
        {
            return invalid_data("ocserv config fingerprint key ID is invalid");
        }
    } else if response.fingerprint.key_id.is_some() || response.fingerprint.previous.is_some() {
        return invalid_data("legacy config fingerprint cannot contain key data");
    }
    if response
        .fingerprint
        .hash
        .as_deref()
        .is_some_and(|hash| !is_valid_sha256_hex(hash))
    {
        return invalid_data("ocserv config fingerprint hash is invalid");
    }
    if let Some(previous) = &response.fingerprint.previous
        && (previous.algorithm != "hmac-sha256"
            || !is_valid_ocserv_name(&previous.key_id)
            || !is_valid_sha256_hex(&previous.hash)
            || Some(previous.key_id.as_str()) == response.fingerprint.key_id.as_deref())
    {
        return invalid_data("ocserv previous config fingerprint is invalid");
    }
    bounded(response)
}

pub fn validate_meta(meta: &OcservReadonlyMeta) -> Result<(), OcservReadonlyError> {
    if is_valid_ocserv_collected_at(&meta.collected_at) {
        Ok(())
    } else {
        invalid_data("ocserv readonly meta collected_at is invalid")
    }
}

pub fn validate_live_metadata(
    live: &OcservLiveReadonlyMetadata,
) -> Result<(), OcservReadonlyError> {
    if !is_valid_ocserv_collected_at(&live.last_snapshot_at) {
        return invalid_data("ocserv live snapshot timestamp is invalid");
    }
    for count in [
        live.auth_failure_count_rolling,
        live.connection_failure_count_rolling,
    ]
    .into_iter()
    .flatten()
    {
        if count > OCSERV_ROLLING_COUNT_MAX {
            return invalid_data("ocserv live rolling count is invalid");
        }
    }
    if let Some(days_remaining) = live.cert_min_days_remaining
        && !(OCSERV_CERT_DAYS_REMAINING_MIN..=OCSERV_CERT_DAYS_REMAINING_MAX)
            .contains(&days_remaining)
    {
        return invalid_data("ocserv live certificate days remaining is invalid");
    }
    if live
        .config_fingerprint_short
        .as_deref()
        .is_some_and(|value| !is_valid_sha256_short_hex(value))
    {
        return invalid_data("ocserv live config fingerprint prefix is invalid");
    }
    Ok(())
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
