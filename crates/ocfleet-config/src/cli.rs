use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::validation::{validate_non_empty_path, validate_positive_u64};

#[derive(Debug, Error)]
pub enum CliConfigError {
    #[error("failed to read config: {0}")]
    Read(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Deserialize)]
pub struct CliConfig {
    pub controller: ControllerConfig,
    pub iroh: IrohConfig,
    #[serde(default)]
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ControllerConfig {
    pub database_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IrohConfig {
    pub secret_key_path: PathBuf,
    #[serde(default = "default_alpn")]
    pub alpn: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            request_timeout_ms: default_request_timeout_ms(),
        }
    }
}

pub fn load_cli_config(path: &Path) -> Result<CliConfig, CliConfigError> {
    let text = fs::read_to_string(path)?;
    let config: CliConfig = toml::from_str(&text)?;
    validate_cli_config(&config)?;
    Ok(config)
}

pub fn validate_cli_config(config: &CliConfig) -> Result<(), CliConfigError> {
    validate_non_empty_path(&config.controller.database_path, "controller.database_path")
        .map_err(|e| CliConfigError::Invalid(e.to_string()))?;
    validate_non_empty_path(&config.iroh.secret_key_path, "iroh.secret_key_path")
        .map_err(|e| CliConfigError::Invalid(e.to_string()))?;
    validate_positive_u64(config.security.request_timeout_ms, "request_timeout_ms")
        .map_err(|e| CliConfigError::Invalid(e.to_string()))?;
    Ok(())
}

fn default_alpn() -> String {
    "/com.github.gentlekingson.ocfleet.mgmt/1".to_string()
}

fn default_request_timeout_ms() -> u64 {
    5_000
}
