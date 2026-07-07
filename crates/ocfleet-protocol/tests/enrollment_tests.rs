use ocfleet_protocol::enrollment::{
    AgentEnrollmentState, EndpointStatus, EnrollmentTokenStatus, JoinRequestStatus, TrustBundle,
};

#[test]
fn enrollment_statuses_serialize_as_stable_snake_case() {
    assert_eq!(
        serde_json::to_value(EnrollmentTokenStatus::Active).expect("serialize token status"),
        serde_json::json!("active")
    );
    assert_eq!(
        serde_json::to_value(JoinRequestStatus::Pending).expect("serialize request status"),
        serde_json::json!("pending")
    );
    assert_eq!(
        serde_json::to_value(EndpointStatus::Quarantined).expect("serialize endpoint status"),
        serde_json::json!("quarantined")
    );
}

#[test]
fn trust_bundle_round_trips_controller_peer_and_path_probe_views() {
    let bundle = TrustBundle {
        endpoint_id: "endpoint-active".to_string(),
        generation: 7,
        status: EndpointStatus::Active,
        trusted_controllers: vec!["controller-one".to_string()],
        trusted_peers: vec!["peer-one".to_string()],
        authorized_path_probes: vec![("controller-one".to_string(), "peer-one".to_string())],
    };

    let encoded = serde_json::to_string(&bundle).expect("serialize trust bundle");
    let decoded: TrustBundle = serde_json::from_str(&encoded).expect("deserialize trust bundle");

    assert_eq!(decoded, bundle);
}

#[test]
fn pending_agent_state_contains_no_trust_bundle() {
    let state = AgentEnrollmentState::Pending {
        request_id: "join-123".to_string(),
        token_id: "tok-123".to_string(),
    };

    let value = serde_json::to_value(&state).expect("serialize pending state");

    assert_eq!(value["status"], "pending");
    assert!(value.get("trust_bundle").is_none());
}
