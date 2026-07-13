use std::collections::BTreeMap;

use ocfleet_protocol::constants::PROTOCOL_VERSION;
use semver::Version;
use serde::{Deserialize, Serialize};

pub const MAX_VERSION_GOVERNANCE_NODES: usize = 1_000;
pub const REQUIRED_OCSERV_SNAPSHOT_SCHEMA: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityNegotiationStatus {
    Compatible,
    IncompatibleProtocol,
    UnsupportedCapability,
    LegacyUnsupported,
    InvalidResponse,
}

impl CapabilityNegotiationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compatible => "compatible",
            Self::IncompatibleProtocol => "incompatible_protocol",
            Self::UnsupportedCapability => "unsupported_capability",
            Self::LegacyUnsupported => "legacy_unsupported",
            Self::InvalidResponse => "invalid_response",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySnapshot {
    pub node_id: String,
    pub endpoint_id: String,
    pub observed_at: String,
    pub status: CapabilityNegotiationStatus,
    pub agent_version: Option<String>,
    pub protocol_min: Option<u32>,
    pub protocol_max: Option<u32>,
    pub ocserv_snapshot_min: Option<u32>,
    pub ocserv_snapshot_max: Option<u32>,
    pub controlled_writes_compiled: Option<bool>,
    pub controlled_writes_locally_enabled: Option<bool>,
}

impl CapabilitySnapshot {
    pub fn validate(&self) -> Result<(), String> {
        if self.node_id.is_empty()
            || self.node_id.len() > 128
            || self.endpoint_id.is_empty()
            || self.endpoint_id.len() > 128
            || self.observed_at.is_empty()
            || self.observed_at.len() > 64
            || self
                .agent_version
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 64)
        {
            return Err("capability snapshot identity or text bound is invalid".to_string());
        }
        for (min, max) in [
            (self.protocol_min, self.protocol_max),
            (self.ocserv_snapshot_min, self.ocserv_snapshot_max),
        ] {
            if min.is_some() != max.is_some()
                || min.is_some_and(|value| value == 0 || value > u16::MAX.into())
                || max.is_some_and(|value| value == 0 || value > u16::MAX.into())
                || min.zip(max).is_some_and(|(min, max)| min > max)
            {
                return Err("capability snapshot version range is invalid".to_string());
            }
        }
        if self.controlled_writes_compiled.is_some()
            != self.controlled_writes_locally_enabled.is_some()
            || self.controlled_writes_locally_enabled == Some(true)
                && self.controlled_writes_compiled != Some(true)
        {
            return Err("capability snapshot controlled-write state is invalid".to_string());
        }
        let complete = self.agent_version.is_some()
            && self.protocol_min.is_some()
            && self.ocserv_snapshot_min.is_some()
            && self.controlled_writes_compiled.is_some();
        match self.status {
            CapabilityNegotiationStatus::Compatible
            | CapabilityNegotiationStatus::IncompatibleProtocol
            | CapabilityNegotiationStatus::UnsupportedCapability
                if !complete =>
            {
                Err("trusted capability status requires complete fields".to_string())
            }
            CapabilityNegotiationStatus::LegacyUnsupported
            | CapabilityNegotiationStatus::InvalidResponse
                if self.agent_version.is_some()
                    || self.protocol_min.is_some()
                    || self.ocserv_snapshot_min.is_some()
                    || self.controlled_writes_compiled.is_some() =>
            {
                Err("untrusted capability status cannot carry response fields".to_string())
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionGovernanceInput {
    pub node_id: String,
    pub enabled: bool,
    pub expected_agent_version: Option<String>,
    pub capability: Option<CapabilitySnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionStatus {
    Current,
    Ahead,
    Outdated,
    PolicyMissing,
    UnknownVersion,
    InvalidExpectedVersion,
    InvalidObservedVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    Compatible,
    Incompatible,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessStatus {
    Ready,
    Blocked,
    Unknown,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NodeVersionReadiness {
    pub node_id: String,
    pub enabled: bool,
    pub expected_agent_version: Option<String>,
    pub observed_agent_version: Option<String>,
    pub observed_at: Option<String>,
    pub negotiation_status: Option<CapabilityNegotiationStatus>,
    pub version_status: VersionStatus,
    pub protocol_status: CompatibilityStatus,
    pub provider_schema_status: CompatibilityStatus,
    pub readiness: ReadinessStatus,
    pub actions_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VersionDistributionEntry {
    pub version: String,
    pub node_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FleetVersionReport {
    pub schema: &'static str,
    pub required_protocol: u32,
    pub required_ocserv_snapshot_schema: u32,
    pub node_count: usize,
    pub ready_count: usize,
    pub blocked_count: usize,
    pub unknown_count: usize,
    pub disabled_count: usize,
    pub outdated_count: usize,
    pub protocol_incompatible_count: usize,
    pub provider_incompatible_count: usize,
    pub alert_count: usize,
    pub distribution: Vec<VersionDistributionEntry>,
    pub nodes: Vec<NodeVersionReadiness>,
    pub alerts: Vec<VersionDriftAlert>,
    pub actions_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VersionDriftAlert {
    pub node_id: String,
    pub severity: &'static str,
    pub reason_code: &'static str,
    pub version_status: VersionStatus,
    pub protocol_status: CompatibilityStatus,
    pub provider_schema_status: CompatibilityStatus,
    pub observed_agent_version: Option<String>,
    pub expected_agent_version: Option<String>,
}

pub fn build_fleet_version_report(
    mut inputs: Vec<VersionGovernanceInput>,
) -> Result<FleetVersionReport, String> {
    if inputs.len() > MAX_VERSION_GOVERNANCE_NODES {
        return Err(format!(
            "version governance node count exceeds {MAX_VERSION_GOVERNANCE_NODES}"
        ));
    }
    inputs.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    if inputs
        .windows(2)
        .any(|pair| pair[0].node_id == pair[1].node_id)
    {
        return Err("version governance contains duplicate node IDs".to_string());
    }

    let mut distribution = BTreeMap::<String, usize>::new();
    let mut nodes = Vec::with_capacity(inputs.len());
    for input in inputs {
        if let Some(version) = input
            .capability
            .as_ref()
            .and_then(|capability| capability.agent_version.as_ref())
        {
            *distribution.entry(version.clone()).or_default() += 1;
        }
        nodes.push(project_node(input));
    }

    let distribution = distribution
        .into_iter()
        .map(|(version, node_count)| VersionDistributionEntry {
            version,
            node_count,
        })
        .collect();
    let mut report = FleetVersionReport {
        schema: "ocfleet.version-readiness.v1",
        required_protocol: PROTOCOL_VERSION,
        required_ocserv_snapshot_schema: REQUIRED_OCSERV_SNAPSHOT_SCHEMA,
        node_count: nodes.len(),
        ready_count: count_readiness(&nodes, ReadinessStatus::Ready),
        blocked_count: count_readiness(&nodes, ReadinessStatus::Blocked),
        unknown_count: count_readiness(&nodes, ReadinessStatus::Unknown),
        disabled_count: count_readiness(&nodes, ReadinessStatus::Disabled),
        outdated_count: nodes
            .iter()
            .filter(|node| node.version_status == VersionStatus::Outdated)
            .count(),
        protocol_incompatible_count: nodes
            .iter()
            .filter(|node| node.protocol_status == CompatibilityStatus::Incompatible)
            .count(),
        provider_incompatible_count: nodes
            .iter()
            .filter(|node| node.provider_schema_status == CompatibilityStatus::Incompatible)
            .count(),
        alert_count: 0,
        distribution,
        nodes,
        alerts: Vec::new(),
        actions_enabled: false,
    };
    report.alerts = version_drift_alerts(&report);
    report.alert_count = report.alerts.len();
    Ok(report)
}

pub fn version_drift_alerts(report: &FleetVersionReport) -> Vec<VersionDriftAlert> {
    let mut alerts = Vec::new();
    for node in report.nodes.iter().filter(|node| node.enabled) {
        let common = || VersionDriftAlert {
            node_id: node.node_id.clone(),
            severity: "warning",
            reason_code: "AGENT_VERSION_OUTDATED",
            version_status: node.version_status,
            protocol_status: node.protocol_status,
            provider_schema_status: node.provider_schema_status,
            observed_agent_version: node.observed_agent_version.clone(),
            expected_agent_version: node.expected_agent_version.clone(),
        };
        if node.version_status == VersionStatus::Outdated {
            alerts.push(common());
        }
        if node.protocol_status == CompatibilityStatus::Incompatible {
            alerts.push(VersionDriftAlert {
                severity: "critical",
                reason_code: "PROTOCOL_INCOMPATIBLE",
                ..common()
            });
        }
        if node.provider_schema_status == CompatibilityStatus::Incompatible {
            alerts.push(VersionDriftAlert {
                severity: "critical",
                reason_code: "PROVIDER_SCHEMA_INCOMPATIBLE",
                ..common()
            });
        }
    }
    alerts
}

fn project_node(input: VersionGovernanceInput) -> NodeVersionReadiness {
    let capability = input.capability.as_ref();
    let observed_agent_version = capability.and_then(|value| value.agent_version.clone());
    let version_status = compare_versions(
        input.expected_agent_version.as_deref(),
        observed_agent_version.as_deref(),
    );
    let protocol_status = capability.map_or(CompatibilityStatus::Unknown, protocol_status);
    let provider_schema_status = capability.map_or(CompatibilityStatus::Unknown, provider_status);
    let readiness = if !input.enabled {
        ReadinessStatus::Disabled
    } else if version_status == VersionStatus::Outdated
        || protocol_status == CompatibilityStatus::Incompatible
        || provider_schema_status == CompatibilityStatus::Incompatible
    {
        ReadinessStatus::Blocked
    } else if matches!(
        version_status,
        VersionStatus::Current | VersionStatus::Ahead
    ) && protocol_status == CompatibilityStatus::Compatible
        && provider_schema_status == CompatibilityStatus::Compatible
    {
        ReadinessStatus::Ready
    } else {
        ReadinessStatus::Unknown
    };
    NodeVersionReadiness {
        node_id: input.node_id,
        enabled: input.enabled,
        expected_agent_version: input.expected_agent_version,
        observed_agent_version,
        observed_at: capability.map(|value| value.observed_at.clone()),
        negotiation_status: capability.map(|value| value.status),
        version_status,
        protocol_status,
        provider_schema_status,
        readiness,
        actions_enabled: false,
    }
}

fn compare_versions(expected: Option<&str>, observed: Option<&str>) -> VersionStatus {
    let Some(expected) = expected else {
        return VersionStatus::PolicyMissing;
    };
    let Ok(expected) = Version::parse(expected) else {
        return VersionStatus::InvalidExpectedVersion;
    };
    let Some(observed) = observed else {
        return VersionStatus::UnknownVersion;
    };
    let Ok(observed) = Version::parse(observed) else {
        return VersionStatus::InvalidObservedVersion;
    };
    match observed.cmp(&expected) {
        std::cmp::Ordering::Less => VersionStatus::Outdated,
        std::cmp::Ordering::Equal => VersionStatus::Current,
        std::cmp::Ordering::Greater => VersionStatus::Ahead,
    }
}

fn protocol_status(capability: &CapabilitySnapshot) -> CompatibilityStatus {
    match capability.status {
        CapabilityNegotiationStatus::IncompatibleProtocol
        | CapabilityNegotiationStatus::UnsupportedCapability => CompatibilityStatus::Incompatible,
        CapabilityNegotiationStatus::LegacyUnsupported
        | CapabilityNegotiationStatus::InvalidResponse => CompatibilityStatus::Unknown,
        CapabilityNegotiationStatus::Compatible => {
            match (capability.protocol_min, capability.protocol_max) {
                (Some(min), Some(max)) if min <= PROTOCOL_VERSION && PROTOCOL_VERSION <= max => {
                    CompatibilityStatus::Compatible
                }
                (Some(_), Some(_)) => CompatibilityStatus::Incompatible,
                _ => CompatibilityStatus::Unknown,
            }
        }
    }
}

fn provider_status(capability: &CapabilitySnapshot) -> CompatibilityStatus {
    if protocol_status(capability) != CompatibilityStatus::Compatible {
        return CompatibilityStatus::Unknown;
    }
    match (
        capability.ocserv_snapshot_min,
        capability.ocserv_snapshot_max,
    ) {
        (Some(min), Some(max))
            if min <= REQUIRED_OCSERV_SNAPSHOT_SCHEMA && REQUIRED_OCSERV_SNAPSHOT_SCHEMA <= max =>
        {
            CompatibilityStatus::Compatible
        }
        (Some(_), Some(_)) => CompatibilityStatus::Incompatible,
        _ => CompatibilityStatus::Unknown,
    }
}

fn count_readiness(nodes: &[NodeVersionReadiness], status: ReadinessStatus) -> usize {
    nodes.iter().filter(|node| node.readiness == status).count()
}
