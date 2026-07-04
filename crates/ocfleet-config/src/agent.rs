use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::validation::{validate_node_id, validate_region, validate_role, validate_service_name};

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
    pub ocserv: Option<OcservConfig>,
    #[serde(default)]
    pub logs: Option<LogsConfig>,
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
    #[serde(default)]
    pub controllers: Vec<ControllerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ControllerConfig {
    pub endpoint_id: String,
    #[serde(default = "default_controller_role")]
    pub role: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditConfig {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OcservConfig {
    pub service_name: Option<String>,
    pub occtl_path: Option<PathBuf>,
    pub socket_file: Option<PathBuf>,
    pub config_file: Option<PathBuf>,
    pub server_cert: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogsConfig {
    pub journal_unit: Option<String>,
    pub default_lines: Option<u32>,
    pub max_lines: Option<u32>,
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
    if let Some(service_name) = config
        .ocserv
        .as_ref()
        .and_then(|ocserv| ocserv.service_name.as_deref())
    {
        validate_service_name(service_name).map_err(|e| ConfigError::Invalid(e.to_string()))?;
    }
    if config.security.default_deadline_ms == 0 {
        return Err(ConfigError::Invalid(
            "default_deadline_ms must be greater than zero".into(),
        ));
    }
    if config.security.max_rpc_timeout_ms == 0 {
        return Err(ConfigError::Invalid(
            "max_rpc_timeout_ms must be greater than zero".into(),
        ));
    }
    if config.security.max_deadline_ms < config.security.default_deadline_ms {
        return Err(ConfigError::Invalid(
            "max_deadline_ms must be >= default_deadline_ms".into(),
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

fn default_controller_role() -> String {
    "viewer".to_string()
}
