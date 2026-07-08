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
pub const PROBE_CONTROLLER_PING: &str = "probe.controller.ping";
pub const PROBE_PEER_ECHO: &str = "probe.peer.echo";
pub const PROBE_PATH_ECHO: &str = "probe.path.echo";
pub const OCSERV_SERVICE_SUMMARY: &str = "ocserv.service.summary";
pub const OCSERV_VERSION: &str = "ocserv.version";
pub const OCSERV_SESSIONS_SUMMARY: &str = "ocserv.sessions.summary";
pub const OCSERV_CERT_EXPIRY: &str = "ocserv.cert.expiry";
pub const OCSERV_CONFIG_FINGERPRINT: &str = "ocserv.config.fingerprint";

pub fn classify_phase_one_method(method: &str) -> MethodStatus {
    match method {
        NODE_PING
        | NODE_INFO
        | PROBE_CONTROLLER_PING
        | OCSERV_SERVICE_SUMMARY
        | OCSERV_VERSION
        | OCSERV_SESSIONS_SUMMARY
        | OCSERV_CERT_EXPIRY
        | OCSERV_CONFIG_FINGERPRINT => MethodStatus::Allowed,
        "ocserv.service.status"
        | "ocserv.status"
        | "ocserv.users.list"
        | "ocserv.users.get"
        | "ocserv.logs.recent"
        | "ocserv.cert.status"
        | "ocserv.config.summary" => MethodStatus::KnownButNotAllowed,
        _ => MethodStatus::Unknown,
    }
}
