use ocfleet_protocol::frame::{decode_frame, encode_frame, FrameError};

#[test]
fn frame_round_trips_json_bytes() {
    let payload = br#"{"version":1,"method":"node.ping"}"#;
    let encoded = encode_frame(payload, 1024).expect("frame encodes");
    assert_eq!(&encoded[0..4], &(payload.len() as u32).to_be_bytes());
    let decoded = decode_frame(&encoded, 1024).expect("frame decodes");
    assert_eq!(decoded, payload);
}

#[test]
fn encode_rejects_payload_larger_than_limit() {
    let err = encode_frame(b"abcdef", 5).expect_err("payload rejected");
    assert_eq!(err, FrameError::FrameTooLarge { length: 6, max: 5 });
}

#[test]
fn decode_rejects_length_before_reading_payload() {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&6u32.to_be_bytes());
    encoded.extend_from_slice(b"abcdef");
    let err = decode_frame(&encoded, 5).expect_err("frame rejected");
    assert_eq!(err, FrameError::FrameTooLarge { length: 6, max: 5 });
}
