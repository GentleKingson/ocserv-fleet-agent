use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::RpcError;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcRequest {
    pub version: u32,
    pub request_id: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
    pub issued_at: String,
    pub nonce: String,
    pub deadline_ms: u64,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub auth: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcResponse {
    pub version: u32,
    #[serde(default)]
    pub request_id: Option<String>,
    pub ok: bool,
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub error: Option<RpcError>,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u64,
}
