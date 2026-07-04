use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame too large: {length} > {max}")]
    FrameTooLarge { length: usize, max: usize },
    #[error("frame too short")]
    FrameTooShort,
    #[error("frame payload length mismatch: declared {declared}, actual {actual}")]
    FrameLengthMismatch { declared: usize, actual: usize },
}

pub fn encode_frame(payload: &[u8], max_payload_bytes: usize) -> Result<Vec<u8>, FrameError> {
    if payload.len() > max_payload_bytes {
        return Err(FrameError::FrameTooLarge {
            length: payload.len(),
            max: max_payload_bytes,
        });
    }

    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn decode_frame(frame: &[u8], max_payload_bytes: usize) -> Result<&[u8], FrameError> {
    if frame.len() < 4 {
        return Err(FrameError::FrameTooShort);
    }

    let declared = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if declared > max_payload_bytes {
        return Err(FrameError::FrameTooLarge {
            length: declared,
            max: max_payload_bytes,
        });
    }

    let actual = frame.len() - 4;
    if declared != actual {
        return Err(FrameError::FrameLengthMismatch { declared, actual });
    }

    Ok(&frame[4..])
}
