use ocfleet_config::agent::AgentConfig;
use ocfleet_protocol::capabilities::{
    AgentFeatureFlag, ControlledWritesCapability, NodeCapabilitiesResponse,
    ProviderSchemaCapability, ProviderSchemaId, READONLY_FIXED_METHOD_CATALOG,
};
use ocfleet_protocol::constants::PROTOCOL_VERSION;
use ocfleet_snapshot_schema::SCHEMA_MAJOR_VERSION_V2;

use crate::AGENT_VERSION;

pub fn collect_node_capabilities(config: &AgentConfig) -> NodeCapabilitiesResponse {
    let controlled_writes_compiled = cfg!(feature = "controlled-writes");
    let response = NodeCapabilitiesResponse {
        protocol_min: PROTOCOL_VERSION,
        protocol_max: PROTOCOL_VERSION,
        agent_version: AGENT_VERSION.to_string(),
        supported_methods: READONLY_FIXED_METHOD_CATALOG.to_vec(),
        provider_schemas: vec![ProviderSchemaCapability {
            provider: ProviderSchemaId::OcservSnapshot,
            min_version: SCHEMA_MAJOR_VERSION_V2,
            max_version: SCHEMA_MAJOR_VERSION_V2,
        }],
        feature_flags: vec![
            AgentFeatureFlag::CapabilityNegotiation,
            AgentFeatureFlag::HmacConfigFingerprint,
            AgentFeatureFlag::LocalSnapshotV2,
            AgentFeatureFlag::OcservReadonly,
        ],
        controlled_writes: ControlledWritesCapability {
            compiled: controlled_writes_compiled,
            locally_enabled: controlled_writes_compiled && config.controlled_writes.enabled,
        },
    };
    response
        .validate()
        .expect("static agent capability catalog must remain valid");
    response
}
