#![no_main]

use libfuzzer_sys::fuzz_target;
use ocfleet_protocol::frame::{decode_frame, encode_frame};
use ocfleet_protocol::{RpcRequest, RpcResponse};

const MAX_PAYLOAD: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<RpcRequest>(data);
    let _ = serde_json::from_slice::<RpcResponse>(data);
    let _ = decode_frame(data, MAX_PAYLOAD);

    if data.len() <= MAX_PAYLOAD {
        let encoded = encode_frame(data, MAX_PAYLOAD).expect("bounded payload encodes");
        assert_eq!(decode_frame(&encoded, MAX_PAYLOAD), Ok(data));
    }
});
