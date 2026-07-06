use std::collections::HashSet;

use anyhow::{Context, Result};
use iroh::EndpointId;
use ocfleet_config::agent::SecurityConfig;
use ocfleet_protocol::method::{NODE_INFO, NODE_PING, PROBE_CONTROLLER_PING, PROBE_PEER_ECHO};

use crate::server::parse_endpoint_id;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerClass {
    Controller,
    Peer,
    DisabledPeer,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct AgentAuthorization {
    controllers: HashSet<EndpointId>,
    enabled_peers: HashSet<EndpointId>,
    disabled_peers: HashSet<EndpointId>,
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

        Ok(Self {
            controllers,
            enabled_peers,
            disabled_peers,
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
                matches!(method, NODE_PING | NODE_INFO | PROBE_CONTROLLER_PING)
            }
            CallerClass::Peer => method == PROBE_PEER_ECHO,
            CallerClass::DisabledPeer | CallerClass::Unknown => false,
        }
    }
}
