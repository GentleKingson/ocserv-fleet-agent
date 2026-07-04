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

pub fn classify_phase_one_method(method: &str) -> MethodStatus {
    match method {
        NODE_PING | NODE_INFO => MethodStatus::Allowed,
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
