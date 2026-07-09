use ocfleet_protocol::method::{
    MethodStatus, NODE_INFO, NODE_PING, OCSERV_CONFIG_APPLY, OCSERV_CONFIG_ROLLBACK, OCSERV_RELOAD,
    OCSERV_RESTART, OCSERV_SESSION_DISCONNECT, PROBE_CONTROLLER_PING, PROBE_PATH_ECHO,
    PROBE_PEER_ECHO, classify_phase_one_method,
};

#[test]
fn phase_one_methods_include_controller_probe_ping() {
    for method in [NODE_PING, NODE_INFO, PROBE_CONTROLLER_PING] {
        assert_eq!(classify_phase_one_method(method), MethodStatus::Allowed);
    }
}

#[test]
fn future_and_dangerous_methods_are_not_allowed() {
    for method in [
        "relay.forward",
        "relay.raw",
        "mesh.status",
        PROBE_PEER_ECHO,
        PROBE_PATH_ECHO,
        "probe.path.report",
        "proxy.open",
        "tunnel.open",
        "shell.exec",
        "command.run",
        "file.read",
        "systemctl.restart",
        OCSERV_RELOAD,
        OCSERV_RESTART,
        OCSERV_CONFIG_APPLY,
        OCSERV_CONFIG_ROLLBACK,
        OCSERV_SESSION_DISCONNECT,
    ] {
        assert_ne!(
            classify_phase_one_method(method),
            MethodStatus::Allowed,
            "{method} must not be allowed in direction-two phase 1"
        );
    }
}

#[test]
fn future_controlled_write_methods_are_known_but_not_allowed() {
    for method in [
        OCSERV_RELOAD,
        OCSERV_RESTART,
        OCSERV_CONFIG_APPLY,
        OCSERV_CONFIG_ROLLBACK,
        OCSERV_SESSION_DISCONNECT,
    ] {
        assert_eq!(
            classify_phase_one_method(method),
            MethodStatus::KnownButNotAllowed,
            "{method} must stay a draft write method until controlled-writes is fully wired"
        );
    }
}
