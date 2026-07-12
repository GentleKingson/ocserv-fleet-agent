use std::collections::HashSet;

use anyhow::{Context, Result};
use iroh::EndpointId;
use ocfleet_config::agent::SecurityConfig;
use ocfleet_protocol::method::{
    NODE_CAPABILITIES, NODE_INFO, NODE_PING, OCSERV_CERT_EXPIRY, OCSERV_CONFIG_FINGERPRINT,
    OCSERV_SERVICE_SUMMARY, OCSERV_SESSIONS_SUMMARY, OCSERV_VERSION, PROBE_CONTROLLER_PING,
    PROBE_PATH_ECHO, PROBE_PEER_ECHO,
};

use crate::server::parse_endpoint_id;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerClass {
    Controller,
    Peer,
    DisabledPeer,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathProbeDecision {
    Allowed,
    Disabled,
    Missing,
    TargetIsController,
    SelfTarget,
}

#[derive(Debug, Clone)]
pub struct AgentAuthorization {
    controllers: HashSet<EndpointId>,
    enabled_peers: HashSet<EndpointId>,
    disabled_peers: HashSet<EndpointId>,
    enabled_path_probes: HashSet<(EndpointId, EndpointId)>,
    disabled_path_probes: HashSet<(EndpointId, EndpointId)>,
}

impl AgentAuthorization {
    pub fn from_security_config(config: &SecurityConfig) -> Result<Self> {
        let controllers = config
            .controllers
            .iter()
            .map(|controller| {
                parse_endpoint_id(&controller.endpoint_id).with_context(|| {
                    format!(
                        "invalid allowed controller endpoint id: {}",
                        controller.endpoint_id
                    )
                })
            })
            .collect::<Result<HashSet<_>>>()?;

        let mut enabled_peers = HashSet::new();
        let mut disabled_peers = HashSet::new();
        for peer in &config.peers {
            let endpoint_id = parse_endpoint_id(&peer.endpoint_id).with_context(|| {
                format!("invalid allowed peer endpoint id: {}", peer.endpoint_id)
            })?;
            if peer.enabled {
                enabled_peers.insert(endpoint_id);
            } else {
                disabled_peers.insert(endpoint_id);
            }
        }

        let mut enabled_path_probes = HashSet::new();
        let mut disabled_path_probes = HashSet::new();
        for path_probe in &config.path_probes {
            let controller_endpoint_id = parse_endpoint_id(&path_probe.controller_endpoint_id)
                .with_context(|| {
                    format!(
                        "invalid path probe controller endpoint id: {}",
                        path_probe.controller_endpoint_id
                    )
                })?;
            let target_endpoint_id = parse_endpoint_id(&path_probe.target_endpoint_id)
                .with_context(|| {
                    format!(
                        "invalid path probe target endpoint id: {}",
                        path_probe.target_endpoint_id
                    )
                })?;
            let pair = (controller_endpoint_id, target_endpoint_id);
            if path_probe.enabled {
                enabled_path_probes.insert(pair);
            } else {
                disabled_path_probes.insert(pair);
            }
        }

        Ok(Self {
            controllers,
            enabled_peers,
            disabled_peers,
            enabled_path_probes,
            disabled_path_probes,
        })
    }

    pub fn classify(&self, endpoint_id: &EndpointId) -> CallerClass {
        if self.controllers.contains(endpoint_id) {
            CallerClass::Controller
        } else if self.enabled_peers.contains(endpoint_id) {
            CallerClass::Peer
        } else if self.disabled_peers.contains(endpoint_id) {
            CallerClass::DisabledPeer
        } else {
            CallerClass::Unknown
        }
    }

    pub fn is_connection_admitted(&self, endpoint_id: &EndpointId) -> bool {
        matches!(
            self.classify(endpoint_id),
            CallerClass::Controller | CallerClass::Peer
        )
    }

    pub fn method_allowed(caller: CallerClass, method: &str) -> bool {
        match caller {
            CallerClass::Controller => {
                matches!(
                    method,
                    NODE_PING
                        | NODE_INFO
                        | NODE_CAPABILITIES
                        | PROBE_CONTROLLER_PING
                        | PROBE_PATH_ECHO
                        | OCSERV_SERVICE_SUMMARY
                        | OCSERV_VERSION
                        | OCSERV_SESSIONS_SUMMARY
                        | OCSERV_CERT_EXPIRY
                        | OCSERV_CONFIG_FINGERPRINT
                )
            }
            CallerClass::Peer => method == PROBE_PEER_ECHO,
            CallerClass::DisabledPeer | CallerClass::Unknown => false,
        }
    }

    pub fn path_probe_decision(
        &self,
        controller_endpoint_id: &EndpointId,
        target_endpoint_id: &EndpointId,
        source_endpoint_id: &EndpointId,
    ) -> PathProbeDecision {
        if target_endpoint_id == source_endpoint_id {
            return PathProbeDecision::SelfTarget;
        }
        if self.controllers.contains(target_endpoint_id) {
            return PathProbeDecision::TargetIsController;
        }
        if !self.enabled_peers.contains(target_endpoint_id) {
            return PathProbeDecision::Missing;
        }
        let pair = (*controller_endpoint_id, *target_endpoint_id);
        if self.enabled_path_probes.contains(&pair) {
            PathProbeDecision::Allowed
        } else if self.disabled_path_probes.contains(&pair) {
            PathProbeDecision::Disabled
        } else {
            PathProbeDecision::Missing
        }
    }
}
