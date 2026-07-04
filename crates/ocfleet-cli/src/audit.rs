use serde_json::Value;
use time::OffsetDateTime;

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub ts: String,
    pub actor: String,
    pub event: String,
    pub node_id: Option<String>,
    pub endpoint_id: Option<String>,
    pub method: Option<String>,
    pub request_id: Option<String>,
    pub params_hash: Option<String>,
    pub ok: Option<bool>,
    pub error_code: Option<String>,
    pub duration_ms: Option<u64>,
    pub detail_json: Value,
}

impl AuditEvent {
    pub fn new(actor: impl Into<String>, event: impl Into<String>) -> Self {
        Self {
            ts: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .expect("RFC3339 formatting succeeds"),
            actor: actor.into(),
            event: event.into(),
            node_id: None,
            endpoint_id: None,
            method: None,
            request_id: None,
            params_hash: None,
            ok: None,
            error_code: None,
            duration_ms: None,
            detail_json: serde_json::json!({}),
        }
    }
}
