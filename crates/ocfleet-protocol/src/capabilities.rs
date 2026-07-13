use serde::{Deserialize, Serialize};

pub const MAX_CAPABILITY_METHODS: usize = 32;
pub const MAX_CAPABILITY_PROVIDER_SCHEMAS: usize = 8;
pub const MAX_CAPABILITY_FEATURE_FLAGS: usize = 16;
pub const MAX_CAPABILITY_AGENT_VERSION_BYTES: usize = 64;
pub const MAX_CAPABILITIES_RESPONSE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FixedRpcMethod {
    #[serde(rename = "node.ping")]
    NodePing,
    #[serde(rename = "node.info")]
    NodeInfo,
    #[serde(rename = "node.capabilities")]
    NodeCapabilities,
    #[serde(rename = "probe.controller.ping")]
    ProbeControllerPing,
    #[serde(rename = "probe.peer.echo")]
    ProbePeerEcho,
    #[serde(rename = "probe.path.echo")]
    ProbePathEcho,
    #[serde(rename = "ocserv.service.summary")]
    OcservServiceSummary,
    #[serde(rename = "ocserv.version")]
    OcservVersion,
    #[serde(rename = "ocserv.sessions.summary")]
    OcservSessionsSummary,
    #[serde(rename = "ocserv.cert.expiry")]
    OcservCertExpiry,
    #[serde(rename = "ocserv.config.fingerprint")]
    OcservConfigFingerprint,
}

impl FixedRpcMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NodePing => "node.ping",
            Self::NodeInfo => "node.info",
            Self::NodeCapabilities => "node.capabilities",
            Self::ProbeControllerPing => "probe.controller.ping",
            Self::ProbePeerEcho => "probe.peer.echo",
            Self::ProbePathEcho => "probe.path.echo",
            Self::OcservServiceSummary => "ocserv.service.summary",
            Self::OcservVersion => "ocserv.version",
            Self::OcservSessionsSummary => "ocserv.sessions.summary",
            Self::OcservCertExpiry => "ocserv.cert.expiry",
            Self::OcservConfigFingerprint => "ocserv.config.fingerprint",
        }
    }
}

pub const READONLY_FIXED_METHOD_CATALOG: &[FixedRpcMethod] = &[
    FixedRpcMethod::NodePing,
    FixedRpcMethod::NodeInfo,
    FixedRpcMethod::NodeCapabilities,
    FixedRpcMethod::ProbeControllerPing,
    FixedRpcMethod::ProbePeerEcho,
    FixedRpcMethod::ProbePathEcho,
    FixedRpcMethod::OcservServiceSummary,
    FixedRpcMethod::OcservVersion,
    FixedRpcMethod::OcservSessionsSummary,
    FixedRpcMethod::OcservCertExpiry,
    FixedRpcMethod::OcservConfigFingerprint,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSchemaId {
    OcservSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSchemaCapability {
    pub provider: ProviderSchemaId,
    pub min_version: u32,
    pub max_version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentFeatureFlag {
    CapabilityNegotiation,
    HmacConfigFingerprint,
    LocalSnapshotV2,
    OcservReadonly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledWritesCapability {
    pub compiled: bool,
    pub locally_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCapabilitiesRequest {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCapabilitiesResponse {
    pub protocol_min: u32,
    pub protocol_max: u32,
    pub agent_version: String,
    pub supported_methods: Vec<FixedRpcMethod>,
    pub provider_schemas: Vec<ProviderSchemaCapability>,
    pub feature_flags: Vec<AgentFeatureFlag>,
    pub controlled_writes: ControlledWritesCapability,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapabilitiesValidationError {
    #[error("capabilities field is invalid: {0}")]
    InvalidField(&'static str),
    #[error(
        "controller protocol {controller} is outside agent range {protocol_min}..={protocol_max}"
    )]
    IncompatibleProtocol {
        controller: u32,
        protocol_min: u32,
        protocol_max: u32,
    },
    #[error("agent does not report node.capabilities in its fixed method catalog")]
    CapabilityMethodMissing,
}

impl NodeCapabilitiesResponse {
    pub fn validate(&self) -> Result<(), CapabilitiesValidationError> {
        if self.protocol_min == 0
            || self.protocol_min > self.protocol_max
            || self.protocol_max > u16::MAX.into()
        {
            return Err(CapabilitiesValidationError::InvalidField("protocol_range"));
        }
        if !valid_agent_version(&self.agent_version) {
            return Err(CapabilitiesValidationError::InvalidField("agent_version"));
        }
        validate_sorted_unique(
            &self.supported_methods,
            1,
            MAX_CAPABILITY_METHODS,
            "supported_methods",
        )?;
        validate_sorted_unique(
            &self.feature_flags,
            1,
            MAX_CAPABILITY_FEATURE_FLAGS,
            "feature_flags",
        )?;
        if self.provider_schemas.is_empty()
            || self.provider_schemas.len() > MAX_CAPABILITY_PROVIDER_SCHEMAS
        {
            return Err(CapabilitiesValidationError::InvalidField(
                "provider_schemas",
            ));
        }
        let mut previous = None;
        for schema in &self.provider_schemas {
            if schema.min_version == 0
                || schema.min_version > schema.max_version
                || schema.max_version > u16::MAX.into()
                || previous.is_some_and(|value| value >= schema.provider)
            {
                return Err(CapabilitiesValidationError::InvalidField(
                    "provider_schemas",
                ));
            }
            previous = Some(schema.provider);
        }
        if self.controlled_writes.locally_enabled && !self.controlled_writes.compiled {
            return Err(CapabilitiesValidationError::InvalidField(
                "controlled_writes",
            ));
        }
        let size = serde_json::to_vec(self)
            .map_err(|_| CapabilitiesValidationError::InvalidField("response"))?
            .len();
        if size > MAX_CAPABILITIES_RESPONSE_BYTES {
            return Err(CapabilitiesValidationError::InvalidField("response_size"));
        }
        Ok(())
    }

    pub fn ensure_controller_compatible(
        &self,
        controller_protocol: u32,
    ) -> Result<(), CapabilitiesValidationError> {
        self.validate()?;
        if controller_protocol < self.protocol_min || controller_protocol > self.protocol_max {
            return Err(CapabilitiesValidationError::IncompatibleProtocol {
                controller: controller_protocol,
                protocol_min: self.protocol_min,
                protocol_max: self.protocol_max,
            });
        }
        if !self
            .supported_methods
            .contains(&FixedRpcMethod::NodeCapabilities)
        {
            return Err(CapabilitiesValidationError::CapabilityMethodMissing);
        }
        Ok(())
    }
}

fn validate_sorted_unique<T: Ord>(
    values: &[T],
    min: usize,
    max: usize,
    field: &'static str,
) -> Result<(), CapabilitiesValidationError> {
    if values.len() < min || values.len() > max {
        return Err(CapabilitiesValidationError::InvalidField(field));
    }
    if values.windows(2).any(|window| window[0] >= window[1]) {
        return Err(CapabilitiesValidationError::InvalidField(field));
    }
    Ok(())
}

fn valid_agent_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CAPABILITY_AGENT_VERSION_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_'))
}
