use std::io::Read;
use std::path::Path;

use anyhow::bail;
use axum::http::HeaderMap;
use ocfleet_cli::private_file;
use sha2::{Digest, Sha256};

const MAX_TOKEN_BYTES: usize = 4_096;
const MIN_TOKEN_BYTES: usize = 32;

#[derive(Clone, Debug)]
pub struct AuthToken {
    digest: [u8; 32],
}

impl AuthToken {
    pub fn from_private_file(path: &Path) -> anyhow::Result<Self> {
        let file = private_file::open_existing_private_read(path)?;
        let mut limited = file.take((MAX_TOKEN_BYTES + 1) as u64);
        let mut raw = String::new();
        limited.read_to_string(&mut raw)?;
        if raw.len() > MAX_TOKEN_BYTES {
            bail!("auth token file is too large");
        }
        Self::from_token_text(&raw)
    }

    pub fn from_token_text(raw: &str) -> anyhow::Result<Self> {
        let token = raw.trim_end_matches(['\r', '\n']);
        validate_token(token)?;
        Ok(Self {
            digest: digest(token.as_bytes()),
        })
    }

    pub fn verify_headers(&self, headers: &HeaderMap) -> bool {
        let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
            return false;
        };
        let Ok(value) = value.to_str() else {
            return false;
        };
        let Some(token) = value.strip_prefix("Bearer ") else {
            return false;
        };
        constant_time_eq(&self.digest, &digest(token.as_bytes()))
    }
}

fn validate_token(token: &str) -> anyhow::Result<()> {
    let len = token.len();
    if !(MIN_TOKEN_BYTES..=MAX_TOKEN_BYTES).contains(&len) {
        bail!("auth token must be between {MIN_TOKEN_BYTES} and {MAX_TOKEN_BYTES} bytes");
    }
    if token
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        bail!("auth token must not contain whitespace or control characters");
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_tokens() {
        assert!(AuthToken::from_token_text("short").is_err());
    }

    #[test]
    fn accepts_trailing_newline() {
        let token =
            AuthToken::from_token_text("abcdefghijklmnopqrstuvwxyz123456\n").expect("valid token");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer abcdefghijklmnopqrstuvwxyz123456"
                .parse()
                .expect("header"),
        );
        assert!(token.verify_headers(&headers));
    }
}
