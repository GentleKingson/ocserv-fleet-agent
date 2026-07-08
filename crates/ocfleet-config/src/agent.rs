use serde::{Deserialize, Deserializer};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::validation::{
    canonicalize_controller_endpoint_id, canonicalize_path_probe_endpoint_id,
    canonicalize_peer_endpoint_id, validate_controller_endpoint_id, validate_controller_role,
    validate_node_id, validate_non_empty_path, validate_path_probe_endpoint_id,
    validate_peer_endpoint_id, validate_positive_i64, validate_positive_u64,
    validate_positive_usize, validate_region, validate_role,
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
    pub ocserv_readonly: OcservReadonlyConfig,
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
    #[serde(default = "default_max_handshake_duration_ms")]
    pub max_handshake_duration_ms: u64,
    #[serde(default = "default_max_connection_idle_ms")]
    pub max_connection_idle_ms: u64,
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
    #[serde(default)]
    pub path_probes: Vec<PathProbeConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct PathProbeConfig {
    pub controller_endpoint_id: String,
    pub target_endpoint_id: String,
    #[serde(default = "default_path_probe_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditConfig {
    pub path: PathBuf,
    #[serde(default = "default_audit_queue_capacity")]
    pub audit_queue_capacity: usize,
    #[serde(default)]
    pub spool_path: Option<PathBuf>,
    #[serde(default)]
    pub metrics_path: Option<PathBuf>,
    #[serde(default = "default_audit_spool_max_events")]
    pub spool_max_events: usize,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcservReadonlyConfig {
    pub enabled: bool,
    pub provider: OcservReadonlyProviderKind,
    pub snapshot_path: Option<PathBuf>,
    pub config_fingerprint: Option<OcservConfigFingerprintConfig>,
    pub certificates: Vec<OcservCertificateConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcservReadonlyProviderKind {
    Disabled,
    Snapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcservCertificateConfig {
    pub name: String,
    pub cert_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcservConfigFingerprintConfig {
    pub name: String,
    pub config_path: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OcservReadonlyConfigFields {
    #[serde(default)]
    enabled: bool,
    provider: Option<OcservReadonlyProviderKind>,
    #[serde(default)]
    snapshot_path: Option<PathBuf>,
    #[serde(default)]
    config_fingerprint: Option<OcservConfigFingerprintConfig>,
    #[serde(default)]
    certificates: Vec<OcservCertificateConfig>,
}

impl Default for OcservReadonlyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: OcservReadonlyProviderKind::Disabled,
            snapshot_path: None,
            config_fingerprint: None,
            certificates: Vec::new(),
        }
    }
}

impl<'de> Deserialize<'de> for OcservReadonlyConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = OcservReadonlyConfigFields::deserialize(deserializer)?;
        if fields.enabled && fields.provider.is_none() {
            return Err(serde::de::Error::missing_field("provider"));
        }
        Ok(Self {
            enabled: fields.enabled,
            provider: fields
                .provider
                .unwrap_or(OcservReadonlyProviderKind::Disabled),
            snapshot_path: fields.snapshot_path,
            config_fingerprint: fields.config_fingerprint,
            certificates: fields.certificates,
        })
    }
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
    validate_ocserv_readonly_config(&config.ocserv_readonly)?;
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
    let mut path_probe_pairs = HashSet::new();
    for path_probe in &config.security.path_probes {
        validate_path_probe_endpoint_id(&path_probe.controller_endpoint_id)
            .map_err(|e| ConfigError::Invalid(e.to_string()))?;
        validate_path_probe_endpoint_id(&path_probe.target_endpoint_id)
            .map_err(|e| ConfigError::Invalid(e.to_string()))?;
        let controller_endpoint_id =
            canonicalize_path_probe_endpoint_id(&path_probe.controller_endpoint_id)
                .map_err(|e| ConfigError::Invalid(e.to_string()))?;
        let target_endpoint_id =
            canonicalize_path_probe_endpoint_id(&path_probe.target_endpoint_id)
                .map_err(|e| ConfigError::Invalid(e.to_string()))?;
        if !controller_endpoint_ids.contains(&controller_endpoint_id) {
            return Err(ConfigError::Invalid(format!(
                "path probe controller_endpoint_id must exist in security.controllers: {controller_endpoint_id}"
            )));
        }
        if controller_endpoint_ids.contains(&target_endpoint_id) {
            return Err(ConfigError::Invalid(format!(
                "path probe target_endpoint_id must not exist in security.controllers: {target_endpoint_id}"
            )));
        }
        let pair = (controller_endpoint_id, target_endpoint_id);
        if !path_probe_pairs.insert(pair.clone()) {
            return Err(ConfigError::Invalid(format!(
                "duplicate path probe authorization entry: controller_endpoint_id={} target_endpoint_id={}",
                pair.0, pair.1
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
    validate_positive_u64(
        config.security.max_handshake_duration_ms,
        "max_handshake_duration_ms",
    )
    .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    validate_positive_u64(
        config.security.max_connection_idle_ms,
        "max_connection_idle_ms",
    )
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
    if let Some(path) = &config.audit.spool_path {
        validate_non_empty_path(path, "audit.spool_path")
            .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    }
    if let Some(path) = &config.audit.metrics_path {
        validate_non_empty_path(path, "audit.metrics_path")
            .map_err(|e| ConfigError::Invalid(e.to_string()))?;
    }
    validate_positive_usize(config.audit.spool_max_events, "audit.spool_max_events")
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

fn validate_ocserv_readonly_config(config: &OcservReadonlyConfig) -> Result<(), ConfigError> {
    if config.enabled && config.provider == OcservReadonlyProviderKind::Disabled {
        return Err(ConfigError::Invalid(
            "ocserv_readonly.provider must not be disabled when enabled=true".to_string(),
        ));
    }
    if config.enabled && config.provider == OcservReadonlyProviderKind::Snapshot {
        let Some(snapshot_path) = &config.snapshot_path else {
            return Err(ConfigError::Invalid(
                "ocserv_readonly.snapshot_path is required for snapshot provider".to_string(),
            ));
        };
        validate_absolute_path(snapshot_path, "ocserv_readonly.snapshot_path")?;
    }
    if let Some(snapshot_path) = &config.snapshot_path {
        validate_absolute_path(snapshot_path, "ocserv_readonly.snapshot_path")?;
    }
    if config.certificates.len() > 8 {
        return Err(ConfigError::Invalid(
            "ocserv_readonly.certificates must contain at most 8 entries".to_string(),
        ));
    }
    for certificate in &config.certificates {
        validate_ocserv_logical_name(&certificate.name, "ocserv_readonly.certificates.name")?;
        validate_absolute_path(
            &certificate.cert_path,
            "ocserv_readonly.certificates.cert_path",
        )?;
    }
    if let Some(fingerprint) = &config.config_fingerprint {
        validate_ocserv_logical_name(&fingerprint.name, "ocserv_readonly.config_fingerprint.name")?;
        validate_absolute_path(
            &fingerprint.config_path,
            "ocserv_readonly.config_fingerprint.config_path",
        )?;
    }
    Ok(())
}

fn validate_absolute_path(path: &Path, field: &'static str) -> Result<(), ConfigError> {
    validate_non_empty_path(path, field).map_err(|e| ConfigError::Invalid(e.to_string()))?;
    if !path.is_absolute() {
        return Err(ConfigError::Invalid(format!(
            "{field} must be an absolute path"
        )));
    }
    Ok(())
}

fn validate_ocserv_logical_name(value: &str, field: &'static str) -> Result<(), ConfigError> {
    let ok_len = !value.is_empty() && value.len() <= 64;
    let ok_chars = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if ok_len && ok_chars {
        Ok(())
    } else {
        Err(ConfigError::Invalid(format!(
            "{field} must be 1-64 characters and contain only [a-zA-Z0-9._-]"
        )))
    }
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

fn default_max_handshake_duration_ms() -> u64 {
    5_000
}

fn default_max_connection_idle_ms() -> u64 {
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

fn default_audit_spool_max_events() -> usize {
    10_000
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

fn default_path_probe_enabled() -> bool {
    true
}
