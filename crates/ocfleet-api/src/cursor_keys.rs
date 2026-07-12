use std::fmt;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, bail};
use base64::Engine as _;
use ocfleet_cli::private_file;
use serde::Deserialize;

const CURSOR_KEY_FILE_SCHEMA: &str = "ocfleet.cursor-keys.v1";
const MAX_CURSOR_KEY_FILE_BYTES: usize = 4_096;
const MAX_CURSOR_KEY_ID_BYTES: usize = 32;

#[derive(Clone)]
pub(crate) struct CursorKey {
    key_id: String,
    key: [u8; 32],
}

impl CursorKey {
    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn key(&self) -> &[u8; 32] {
        &self.key
    }
}

impl fmt::Debug for CursorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CursorKey")
            .field("key_id", &self.key_id)
            .field("key_configured", &true)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct CursorKeyring {
    current: CursorKey,
    previous: Option<CursorKey>,
}

impl CursorKeyring {
    pub fn from_private_file(path: &Path) -> anyhow::Result<Self> {
        let file = private_file::open_existing_private_read(path)?;
        let mut limited = file.take((MAX_CURSOR_KEY_FILE_BYTES + 1) as u64);
        let mut raw = Vec::new();
        limited.read_to_end(&mut raw)?;
        if raw.len() > MAX_CURSOR_KEY_FILE_BYTES {
            bail!("cursor key file is too large");
        }
        let key_file: CursorKeyFile =
            serde_json::from_slice(&raw).context("cursor key file must be closed JSON")?;
        if key_file.schema != CURSOR_KEY_FILE_SCHEMA {
            bail!("cursor key file schema is unsupported");
        }
        let current = decode_entry(key_file.current)?;
        let previous = key_file.previous.map(decode_entry).transpose()?;
        if previous
            .as_ref()
            .is_some_and(|previous| previous.key_id == current.key_id)
        {
            bail!("cursor current and previous key IDs must differ");
        }
        Ok(Self { current, previous })
    }

    pub(crate) fn current(&self) -> &CursorKey {
        &self.current
    }

    pub(crate) fn find(&self, key_id: &str) -> Option<&CursorKey> {
        if self.current.key_id == key_id {
            return Some(&self.current);
        }
        self.previous
            .as_ref()
            .filter(|previous| previous.key_id == key_id)
    }

    #[cfg(test)]
    pub(crate) fn for_test(key_id: &str, key: [u8; 32]) -> Self {
        Self {
            current: CursorKey {
                key_id: key_id.to_string(),
                key,
            },
            previous: None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorKeyFile {
    schema: String,
    current: CursorKeyEntry,
    #[serde(default)]
    previous: Option<CursorKeyEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorKeyEntry {
    key_id: String,
    key_base64: String,
}

fn decode_entry(entry: CursorKeyEntry) -> anyhow::Result<CursorKey> {
    validate_key_id(&entry.key_id)?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(entry.key_base64)
        .context("cursor key must be base64")?;
    let key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("cursor key must decode to exactly 32 bytes"))?;
    Ok(CursorKey {
        key_id: entry.key_id,
        key,
    })
}

fn validate_key_id(key_id: &str) -> anyhow::Result<()> {
    if key_id.is_empty()
        || key_id.len() > MAX_CURSOR_KEY_ID_BYTES
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!(
            "cursor key_id must be 1-{MAX_CURSOR_KEY_ID_BYTES} ASCII letters, digits, '.', '_', or '-'"
        );
    }
    Ok(())
}
