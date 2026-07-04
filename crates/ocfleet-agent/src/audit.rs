use serde::Serialize;
use std::io::{self, Write};
use std::path::PathBuf;
use time::OffsetDateTime;

use crate::private_file;

#[derive(Debug, Clone, Serialize)]
pub struct AgentAuditEvent {
    pub ts: String,
    pub event: String,
    pub request_id: Option<String>,
    pub remote_endpoint_id: Option<String>,
    pub method: Option<String>,
    pub params_hash: Option<String>,
    pub nonce_hash: Option<String>,
    pub allowed: Option<bool>,
    pub ok: Option<bool>,
    pub error_code: Option<String>,
    pub duration_ms: Option<u64>,
    pub response_bytes: Option<usize>,
    pub stage: Option<String>,
    pub reason: Option<String>,
    pub suppressed_count: Option<u64>,
    pub limit_key: Option<String>,
    pub resource: Option<String>,
}

impl AgentAuditEvent {
    pub fn new(event: impl Into<String>) -> Self {
        Self {
            ts: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .expect("RFC3339 formatting succeeds"),
            event: event.into(),
            request_id: None,
            remote_endpoint_id: None,
            method: None,
            params_hash: None,
            nonce_hash: None,
            allowed: None,
            ok: None,
            error_code: None,
            duration_ms: None,
            response_bytes: None,
            stage: None,
            reason: None,
            suppressed_count: None,
            limit_key: None,
            resource: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct JsonlAuditWriter {
    path: PathBuf,
}

impl JsonlAuditWriter {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn write(&self, event: &AgentAuditEvent) -> io::Result<()> {
        let mut file = private_file::open_private_append(&self.path)?;
        serde_json::to_writer(&mut file, event).map_err(io::Error::other)?;
        file.write_all(b"\n")?;
        Ok(())
    }
}
