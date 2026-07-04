use ocfleet_cli::rpc_client::{
    RpcClientError, read_response_frame, read_response_frame_with_timeout, validate_rpc_response,
};
use ocfleet_protocol::constants::PROTOCOL_VERSION;
use ocfleet_protocol::error::{ErrorCode, RpcError};
use ocfleet_protocol::rpc::RpcResponse;
use serde_json::json;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn read_response_frame_rejects_oversized_declared_length_without_reading_payload() {
    let (mut writer, mut reader) = tokio::io::duplex(64);
    writer
        .write_all(&8_u32.to_be_bytes())
        .await
        .expect("write frame length");

    let err = tokio::time::timeout(Duration::from_millis(100), read_response_frame(&mut reader, 4))
        .await
        .expect("read_response_frame returns after reading only the header")
        .expect_err("oversized frame rejected");

    assert_eq!(err.code(), ErrorCode::FrameTooLarge);
}

#[tokio::test]
async fn timed_response_read_rejects_incomplete_header() {
    let (mut writer, mut reader) = tokio::io::duplex(64);
    writer.write_all(&[0, 0]).await.expect("partial header");

    let err = read_response_frame_with_timeout(&mut reader, 64, Duration::from_millis(10))
        .await
        .expect_err("partial response times out");

    assert_eq!(err.code(), ErrorCode::RpcTimeout);
}

#[test]
fn validate_node_info_response_rejects_endpoint_mismatch() {
    let response = RpcResponse {
        version: PROTOCOL_VERSION,
        request_id: Some("request-1".to_string()),
        ok: true,
        result: Some(json!({"agent_endpoint_id": "actual-endpoint"})),
        error: None,
        started_at: "2026-01-01T00:00:00Z".to_string(),
        finished_at: "2026-01-01T00:00:00Z".to_string(),
        duration_ms: 0,
    };

    let err = validate_rpc_response(&response, "request-1", Some("expected-endpoint"))
        .expect_err("endpoint mismatch rejected");

    assert_eq!(err.code(), ErrorCode::InvalidResponse);
}

#[test]
fn validate_error_response_rejects_result_payload() {
    let response = RpcResponse {
        version: PROTOCOL_VERSION,
        request_id: Some("request-1".to_string()),
        ok: false,
        result: Some(json!({"unexpected": true})),
        error: Some(RpcError {
            code: ErrorCode::MethodNotFound,
            message: "method not found".to_string(),
            details: json!({"method": "shell.exec"}),
        }),
        started_at: "2026-01-01T00:00:00Z".to_string(),
        finished_at: "2026-01-01T00:00:00Z".to_string(),
        duration_ms: 0,
    };

    let err = validate_rpc_response(&response, "request-1", None)
        .expect_err("malformed error response rejected");

    assert_eq!(err.code(), ErrorCode::InvalidResponse);
}

#[test]
fn validate_error_response_preserves_agent_details() {
    let response = RpcResponse {
        version: PROTOCOL_VERSION,
        request_id: Some("request-1".to_string()),
        ok: false,
        result: None,
        error: Some(RpcError {
            code: ErrorCode::MethodNotAllowed,
            message: "method not allowed".to_string(),
            details: json!({"method": "ocserv.status", "phase": 1}),
        }),
        started_at: "2026-01-01T00:00:00Z".to_string(),
        finished_at: "2026-01-01T00:00:00Z".to_string(),
        duration_ms: 0,
    };

    let err = validate_rpc_response(&response, "request-1", None)
        .expect_err("agent error is returned");

    assert_eq!(err.code(), ErrorCode::MethodNotAllowed);
    assert_eq!(err.details()["method"], "ocserv.status");
    assert_eq!(err.details()["phase"], 1);
}

#[test]
fn endpoint_mismatch_error_exposes_structured_details() {
    let expected = iroh::SecretKey::generate().public();
    let actual = iroh::SecretKey::generate().public();

    let err = RpcClientError::endpoint_mismatch(expected, actual);

    assert_eq!(err.code(), ErrorCode::EndpointMismatch);
    assert!(
        err.to_string()
            .contains(&format!("ENDPOINT_MISMATCH expected={expected} actual={actual}"))
    );
    assert_eq!(
        err.details()["expected_endpoint_id"],
        expected.to_string()
    );
    assert_eq!(
        err.details()["actual_remote_endpoint_id"],
        actual.to_string()
    );
}
