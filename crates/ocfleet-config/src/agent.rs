use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::validation::{
    canonicalize_controller_endpoint_id, canonicalize_peer_endpoint_id,
    validate_controller_endpoint_id, validate_controller_role, validate_node_id,
    validate_non_empty_path, validate_peer_endpoint_id, validate_positive_i64,
    validate_positive_u64, validate_positive_usize, validate_region, validate_role,
};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config: {0}")]
    Read(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    pub node: NodeConfig,
    pub iroh: IrohConfig,
    pub security: SecurityConfig,
    pub audit: AuditConfig,
    #[serde(default)]
    pub ocserv: Option<toml::Value>,
    #[serde(default)]
    pub logs: Option<toml::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    pub id: String,
    pub region: String,
    pub role: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IrohConfig {
    pub secret_key_path: PathBuf,
    #[serde(default = "default_alpn")]
    pub alpn: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    #[serde(default = "default_clock_skew")]
    pub allowed_clock_skew_seconds: i64,
    #[serde(default = "default_deadline_ms")]
    pub default_deadline_ms: u64,
    #[serde(default = "default_max_deadline_ms")]
    pub max_deadline_ms: u64,
    #[serde(default = "default_max_rpc_timeout_ms")]
    pub max_rpc_timeout_ms: u64,
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
    #[serde(default = "default_max_handshake_tasks_global")]
    pub max_handshake_tasks_global: usize,
    #[serde(default = "default_max_connections_global")]
    pub max_connections_global: usize,
    #[serde(default = "default_max_connections_per_controller")]
    pub max_connections_per_controller: usize,
    #[serde(default = "default_max_streams_global")]
    pub max_streams_global: usize,
    #[serde(default = "default_max_streams_per_controller")]
    pub max_streams_per_controller: usize,
    #[serde(default = "default_max_live_nonces_global")]
    pub max_live_nonces_global: usize,
    #[serde(default = "default_max_live_nonces_per_controller")]
    pub max_live_nonces_per_controller: usize,
    #[serde(default)]
    pub controllers: Vec<ControllerConfig>,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ControllerConfig {
    pub endpoint_id: String,
    #[serde(default = "default_controller_role")]
    pub role: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub endpoint_id: String,
    #[serde(default = "default_peer_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditConfig {
    pub path: PathBuf,
    #[serde(default = "default_audit_queue_capacity")]
    pub audit_queue_capacity: usize,
    #[serde(default = "default_rejected_peer_log_burst")]
    pub rejected_peer_log_burst: usize,
    #[serde(default = "default_rejected_peer_log_refill_per_sec")]
    pub rejected_peer_log_refill_per_sec: usize,
    #[serde(default = "default_rejected_peer_log_max_buckets")]
    pub rejected_peer_log_max_buckets: usize,
    #[serde(default = "default_rejected_peer_log_bucket_ttl_seconds")]
    pub rejected_peer_log_bucket_ttl_seconds: u64,
    #[serde(default = "default_rejected_peer_log_aggregate_interval_seconds")]
    pub rejected_peer_log_aggregate_interval_seconds: u64,
}

pub fn load_agent_config(path: &Path) -> Result<AgentConfig, ConfigError> {
    let text = fs::read_to_string(path)?;
    let config: AgentConfig = toml::from_str(&text)?;
    validate_agent_config(&config)?;
    Ok(config)
}

pub fn validate_agent_config(config: &AgentConfig) -> Result<(), ConfigError> {
    validate_node_id(&config.node.id).map_err(|e| ConfigError::Invalid(e.to_string()))?;
    validate_region(&config.node.region).map_err(|e| ConfigError::Invalid(e.to_string()))?;
    validate_role(&config.node.role).map_err(|e| ConfigError::Invalid(e.to_string()))?;
    validate_non_empty_path(&config.iroh.secret_key_path, "iroh.secret_key_path")
        .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    validate_non_empty_path(&config.audit.path, "audit.path")
        .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    if config.ocserv.is_some() {
        return Err(ConfigError::Invalid(
            "[ocserv] is not part of the Phase 1 read-only MVP".to_string(),
        ));
    }
    if config.logs.is_some() {
        return Err(ConfigError::Invalid(
            "[logs] is not part of the Phase 1 read-only MVP".to_string(),
        ));
    }
    let mut controller_endpoint_ids = HashSet::new();
    for controller in &config.security.controllers {
        validate_controller_endpoint_id(&controller.endpoint_id)
            .map_err(|e| ConfigError::Invalid(e.to_string()))?;
        validate_controller_role(&controller.role)
            .map_err(|e| ConfigError::Invalid(e.to_string()))?;
        controller_endpoint_ids.insert(
            canonicalize_controller_endpoint_id(&controller.endpoint_id)
                .map_err(|e| ConfigError::Invalid(e.to_string()))?,
        );
    }
    let mut peer_endpoint_ids = HashSet::new();
    for peer in &config.security.peers {
        validate_peer_endpoint_id(&peer.endpoint_id)
            .map_err(|e| ConfigError::Invalid(e.to_string()))?;
        let endpoint_id = canonicalize_peer_endpoint_id(&peer.endpoint_id)
            .map_err(|e| ConfigError::Invalid(e.to_string()))?;
        if !peer_endpoint_ids.insert(endpoint_id.clone()) {
            return Err(ConfigError::Invalid(format!(
                "duplicate peer endpoint_id: {endpoint_id}"
            )));
        }
        if controller_endpoint_ids.contains(&endpoint_id) {
            return Err(ConfigError::Invalid(format!(
                "endpoint_id cannot be both controller and peer: {endpoint_id}"
            )));
        }
    }
    validate_positive_i64(
        config.security.allowed_clock_skew_seconds,
        "allowed_clock_skew_seconds",
    )
    .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    validate_positive_u64(config.security.default_deadline_ms, "default_deadline_ms")
        .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    validate_positive_u64(config.security.max_rpc_timeout_ms, "max_rpc_timeout_ms")
        .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    if config.security.max_deadline_ms < config.security.default_deadline_ms {
        return Err(ConfigError::Invalid(
            "max_deadline_ms must be >= default_deadline_ms".into(),
        ));
    }
    validate_positive_usize(config.security.max_request_bytes, "max_request_bytes")
        .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    validate_positive_usize(config.security.max_response_bytes, "max_response_bytes")
        .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    if config.security.max_response_bytes < 512 {
        return Err(ConfigError::Invalid(
            "max_response_bytes must be >= 512".to_string(),
        ));
    }
    validate_positive_usize(
        config.security.max_handshake_tasks_global,
        "max_handshake_tasks_global",
    )
    .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    validate_positive_usize(
        config.security.max_connections_global,
        "max_connections_global",
    )
    .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    validate_positive_usize(
        config.security.max_connections_per_controller,
        "max_connections_per_controller",
    )
    .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    if config.security.max_connections_per_controller > config.security.max_connections_global {
        return Err(ConfigError::Invalid(
            "max_connections_per_controller must be <= max_connections_global".to_string(),
        ));
    }
    validate_positive_usize(config.security.max_streams_global, "max_streams_global")
        .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    validate_positive_usize(
        config.security.max_streams_per_controller,
        "max_streams_per_controller",
    )
    .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    if config.security.max_streams_per_controller > config.security.max_streams_global {
        return Err(ConfigError::Invalid(
            "max_streams_per_controller must be <= max_streams_global".to_string(),
        ));
    }
    validate_positive_usize(
        config.security.max_live_nonces_global,
        "max_live_nonces_global",
    )
    .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    validate_positive_usize(
        config.security.max_live_nonces_per_controller,
        "max_live_nonces_per_controller",
    )
    .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    if config.security.max_live_nonces_per_controller > config.security.max_live_nonces_global {
        return Err(ConfigError::Invalid(
            "max_live_nonces_per_controller must be <= max_live_nonces_global".to_string(),
        ));
    }
    validate_positive_usize(config.audit.audit_queue_capacity, "audit_queue_capacity")
        .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    validate_positive_usize(
        config.audit.rejected_peer_log_burst,
        "rejected_peer_log_burst",
    )
    .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    validate_positive_usize(
        config.audit.rejected_peer_log_refill_per_sec,
        "rejected_peer_log_refill_per_sec",
    )
    .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    validate_positive_usize(
        config.audit.rejected_peer_log_max_buckets,
        "rejected_peer_log_max_buckets",
    )
    .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    validate_positive_u64(
        config.audit.rejected_peer_log_bucket_ttl_seconds,
        "rejected_peer_log_bucket_ttl_seconds",
    )
    .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    validate_positive_u64(
        config.audit.rejected_peer_log_aggregate_interval_seconds,
        "rejected_peer_log_aggregate_interval_seconds",
    )
    .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    if config.audit.rejected_peer_log_bucket_ttl_seconds
        < config.audit.rejected_peer_log_aggregate_interval_seconds
    {
        return Err(ConfigError::Invalid(
            "rejected_peer_log_bucket_ttl_seconds must be >= rejected_peer_log_aggregate_interval_seconds".to_string(),
        ));
    }
    Ok(())
}

fn default_alpn() -> String {
    "/com.github.gentlekingson.ocfleet.mgmt/1".to_string()
}

fn default_clock_skew() -> i64 {
    60
}

fn default_deadline_ms() -> u64 {
    5_000
}

fn default_max_deadline_ms() -> u64 {
    10_000
}

fn default_max_rpc_timeout_ms() -> u64 {
    5_000
}

fn default_max_request_bytes() -> usize {
    65_536
}

fn default_max_response_bytes() -> usize {
    2_097_152
}

fn default_max_handshake_tasks_global() -> usize {
    256
}

fn default_max_connections_global() -> usize {
    256
}

fn default_max_connections_per_controller() -> usize {
    32
}

fn default_max_streams_global() -> usize {
    1024
}

fn default_max_streams_per_controller() -> usize {
    128
}

fn default_max_live_nonces_global() -> usize {
    100_000
}

fn default_max_live_nonces_per_controller() -> usize {
    10_000
}

fn default_audit_queue_capacity() -> usize {
    1024
}

fn default_rejected_peer_log_burst() -> usize {
    10
}

fn default_rejected_peer_log_refill_per_sec() -> usize {
    1
}

fn default_rejected_peer_log_max_buckets() -> usize {
    4096
}

fn default_rejected_peer_log_bucket_ttl_seconds() -> u64 {
    3600
}

fn default_rejected_peer_log_aggregate_interval_seconds() -> u64 {
    60
}

fn default_controller_role() -> String {
    "viewer".to_string()
}

fn default_peer_enabled() -> bool {
    true
}
