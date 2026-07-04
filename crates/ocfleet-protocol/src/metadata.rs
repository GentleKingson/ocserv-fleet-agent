use base64::Engine;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::error::{ErrorCode, RpcError};

pub fn validate_request_id(value: &str) -> Result<(), RpcError> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| RpcError::new(ErrorCode::InvalidRequestId, "request_id must be a UUID"))
}

pub fn validate_deadline_ms(deadline_ms: u64, max_deadline_ms: u64) -> Result<(), RpcError> {
    if deadline_ms == 0 || deadline_ms > max_deadline_ms {
        return Err(RpcError::new(
            ErrorCode::InvalidDeadline,
            "deadline_ms must be greater than zero and no larger than max_deadline_ms",
        ));
    }
    Ok(())
}

pub fn execution_timeout_ms(deadline_ms: u64, max_rpc_timeout_ms: u64) -> u64 {
    deadline_ms.min(max_rpc_timeout_ms)
}

pub fn validate_nonce(value: &str) -> Result<(), RpcError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| {
            RpcError::new(
                ErrorCode::InvalidNonce,
                "nonce must be base64url without padding",
            )
        })?;
    if bytes.len() != 16 {
        return Err(RpcError::new(
            ErrorCode::InvalidNonce,
            "nonce must decode to 16 bytes",
        ));
    }
    Ok(())
}

pub fn nonce_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("sha256:{digest:x}")
}

pub fn validate_issued_at(
    issued_at: &str,
    now: OffsetDateTime,
    allowed_clock_skew_seconds: i64,
    deadline_ms: u64,
) -> Result<(), RpcError> {
    let parsed = OffsetDateTime::parse(issued_at, &time::format_description::well_known::Rfc3339)
        .map_err(|_| {
        RpcError::new(ErrorCode::InvalidTimestamp, "issued_at must be RFC3339 UTC")
    })?;

    let skew = if parsed > now {
        parsed - now
    } else {
        now - parsed
    };
    if skew > Duration::seconds(allowed_clock_skew_seconds) {
        return Err(RpcError::new(
            ErrorCode::ClockSkewExceeded,
            "issued_at is outside the allowed clock skew window",
        ));
    }

    let deadline = parsed + Duration::milliseconds(deadline_ms as i64);
    if now > deadline {
        return Err(RpcError::new(
            ErrorCode::RequestExpired,
            "request deadline has expired",
        ));
    }

    Ok(())
}
