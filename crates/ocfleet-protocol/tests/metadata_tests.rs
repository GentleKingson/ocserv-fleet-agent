use base64::Engine;
use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::metadata::{
    nonce_hash, validate_deadline_ms, validate_nonce, validate_request_id,
};

#[test]
fn request_id_must_be_uuid() {
    assert!(validate_request_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
    let err = validate_request_id("not-a-uuid").expect_err("invalid id rejected");
    assert_eq!(err.code, ErrorCode::InvalidRequestId);
}

#[test]
fn deadline_must_be_positive_and_within_max() {
    assert!(validate_deadline_ms(5_000, 10_000).is_ok());
    assert_eq!(
        validate_deadline_ms(0, 10_000)
            .expect_err("zero rejected")
            .code,
        ErrorCode::InvalidDeadline
    );
    assert_eq!(
        validate_deadline_ms(10_001, 10_000)
            .expect_err("too large rejected")
            .code,
        ErrorCode::InvalidDeadline
    );
}

#[test]
fn nonce_must_be_base64url_16_bytes() {
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 16]);
    assert!(validate_nonce(&nonce).is_ok());
    assert_eq!(
        validate_nonce("bad nonce with spaces")
            .expect_err("bad nonce rejected")
            .code,
        ErrorCode::InvalidNonce
    );
}

#[test]
fn nonce_hash_uses_real_sha256_prefix() {
    assert_eq!(
        nonce_hash("abc"),
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
