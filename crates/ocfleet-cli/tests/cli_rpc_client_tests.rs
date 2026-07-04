use ocfleet_cli::rpc_client::read_response_frame;
use ocfleet_protocol::error::ErrorCode;
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
