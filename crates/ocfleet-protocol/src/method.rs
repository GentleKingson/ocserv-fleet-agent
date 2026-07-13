use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MethodStatus {
    Allowed,
    KnownButNotAllowed,
    Unknown,
}

pub const NODE_PING: &str = "node.ping";
pub const NODE_INFO: &str = "node.info";
pub const NODE_CAPABILITIES: &str = "node.capabilities";
pub const PROBE_CONTROLLER_PING: &str = "probe.controller.ping";
pub const PROBE_PEER_ECHO: &str = "probe.peer.echo";
pub const PROBE_PATH_ECHO: &str = "probe.path.echo";
pub const OCSERV_SERVICE_SUMMARY: &str = "ocserv.service.summary";
pub const OCSERV_VERSION: &str = "ocserv.version";
pub const OCSERV_SESSIONS_SUMMARY: &str = "ocserv.sessions.summary";
pub const OCSERV_CERT_EXPIRY: &str = "ocserv.cert.expiry";
pub const OCSERV_CONFIG_FINGERPRINT: &str = "ocserv.config.fingerprint";
pub const OCSERV_RELOAD: &str = "ocserv.reload";
pub const OCSERV_RESTART: &str = "ocserv.restart";
pub const OCSERV_CONFIG_APPLY: &str = "ocserv.config.apply";
pub const OCSERV_CONFIG_ROLLBACK: &str = "ocserv.config.rollback";
pub const OCSERV_SESSION_DISCONNECT: &str = "ocserv.session.disconnect";

pub fn classify_phase_one_method(method: &str) -> MethodStatus {
    match method {
        NODE_PING
        | NODE_INFO
        | NODE_CAPABILITIES
        | PROBE_CONTROLLER_PING
        | OCSERV_SERVICE_SUMMARY
        | OCSERV_VERSION
        | OCSERV_SESSIONS_SUMMARY
        | OCSERV_CERT_EXPIRY
        | OCSERV_CONFIG_FINGERPRINT => MethodStatus::Allowed,
        "ocserv.service.status"
        | "ocserv.status"
        | OCSERV_RELOAD
        | OCSERV_RESTART
        | OCSERV_CONFIG_APPLY
        | OCSERV_CONFIG_ROLLBACK
        | OCSERV_SESSION_DISCONNECT
        | "ocserv.users.list"
        | "ocserv.users.get"
        | "ocserv.logs.recent"
        | "ocserv.cert.status"
        | "ocserv.config.summary" => MethodStatus::KnownButNotAllowed,
        _ => MethodStatus::Unknown,
    }
}
