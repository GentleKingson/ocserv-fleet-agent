use ocfleet_protocol::method::{
    MethodStatus, NODE_INFO, NODE_PING, PROBE_CONTROLLER_PING, PROBE_PATH_ECHO, PROBE_PEER_ECHO,
    classify_phase_one_method,
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
    ] {
        assert_ne!(
            classify_phase_one_method(method),
            MethodStatus::Allowed,
            "{method} must not be allowed in direction-two phase 1"
        );
    }
}
