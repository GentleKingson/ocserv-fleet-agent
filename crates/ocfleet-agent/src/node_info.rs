use serde::Serialize;
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub region: String,
    pub role: String,
    pub agent_version: String,
    pub current_time_utc: String,
    pub agent_endpoint_id: String,
}

pub fn collect_node_info(
    node_id: String,
    region: String,
    role: String,
    agent_version: String,
    agent_endpoint_id: String,
) -> NodeInfo {
    NodeInfo {
        node_id,
        region,
        role,
        agent_version,
        current_time_utc: OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .expect("RFC3339 formatting succeeds"),
        agent_endpoint_id,
    }
}
