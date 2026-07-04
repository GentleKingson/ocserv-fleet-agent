use ocfleet_cli::rpc_client::{
    read_response_frame, read_response_frame_with_timeout, validate_rpc_response,
};
use ocfleet_protocol::constants::PROTOCOL_VERSION;
use ocfleet_protocol::error::ErrorCode;
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
