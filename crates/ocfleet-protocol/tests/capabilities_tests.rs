use ocfleet_protocol::capabilities::{
    AgentFeatureFlag, CapabilitiesValidationError, ControlledWritesCapability, FixedRpcMethod,
    NodeCapabilitiesRequest, NodeCapabilitiesResponse, ProviderSchemaCapability, ProviderSchemaId,
    READONLY_FIXED_METHOD_CATALOG,
};
use ocfleet_protocol::constants::PROTOCOL_VERSION;
use serde_json::json;

fn valid_response() -> NodeCapabilitiesResponse {
    NodeCapabilitiesResponse {
        protocol_min: PROTOCOL_VERSION,
        protocol_max: PROTOCOL_VERSION,
        agent_version: "0.4.0-rc.1".to_string(),
        supported_methods: READONLY_FIXED_METHOD_CATALOG.to_vec(),
        provider_schemas: vec![ProviderSchemaCapability {
            provider: ProviderSchemaId::OcservSnapshot,
            min_version: 2,
            max_version: 2,
        }],
        feature_flags: vec![
            AgentFeatureFlag::CapabilityNegotiation,
            AgentFeatureFlag::HmacConfigFingerprint,
            AgentFeatureFlag::LocalSnapshotV2,
            AgentFeatureFlag::OcservReadonly,
        ],
        controlled_writes: ControlledWritesCapability {
            compiled: false,
            locally_enabled: false,
        },
    }
}

#[test]
fn capabilities_dto_round_trips_as_closed_bounded_shape() {
    let response = valid_response();
    response.validate().expect("valid capabilities");
    response
        .ensure_controller_compatible(PROTOCOL_VERSION)
        .expect("controller compatible");
    let value = serde_json::to_value(&response).expect("serialize response");
    let decoded: NodeCapabilitiesResponse =
        serde_json::from_value(value.clone()).expect("decode response");
    assert_eq!(decoded, response);
    assert_eq!(value["supported_methods"][2], "node.capabilities");
    assert_eq!(value["provider_schemas"][0]["provider"], "ocserv_snapshot");

    let request = serde_json::to_value(NodeCapabilitiesRequest {}).expect("serialize request");
    assert_eq!(request, json!({}));
    serde_json::from_value::<NodeCapabilitiesRequest>(json!({"path":"/etc/ocserv"}))
        .expect_err("request is closed");

    let encoded = value.to_string();
    for forbidden_key in [
        "\"path\":",
        "\"command\":",
        "\"unit\":",
        "\"local_policy\":",
    ] {
        assert!(!encoded.contains(forbidden_key));
    }
    for forbidden_value in [
        "/etc/",
        "systemctl",
        "secret",
        "token",
        "/etc/ocserv/ocserv.conf",
    ] {
        assert!(!encoded.contains(forbidden_value));
    }
}

#[test]
fn capabilities_reject_unknown_fields_duplicates_and_bounds() {
    let mut unknown = serde_json::to_value(valid_response()).unwrap();
    unknown["command"] = json!("systemctl restart ocserv");
    serde_json::from_value::<NodeCapabilitiesResponse>(unknown)
        .expect_err("unknown response field rejected");

    let mut duplicate = valid_response();
    duplicate
        .supported_methods
        .insert(1, FixedRpcMethod::NodePing);
    assert_eq!(
        duplicate.validate(),
        Err(CapabilitiesValidationError::InvalidField(
            "supported_methods"
        ))
    );

    let mut unsorted = valid_response();
    unsorted.feature_flags.swap(0, 1);
    assert_eq!(
        unsorted.validate(),
        Err(CapabilitiesValidationError::InvalidField("feature_flags"))
    );

    let mut oversized = valid_response();
    oversized.agent_version = "x".repeat(65);
    assert_eq!(
        oversized.validate(),
        Err(CapabilitiesValidationError::InvalidField("agent_version"))
    );

    let mut too_many_methods = valid_response();
    too_many_methods.supported_methods = vec![FixedRpcMethod::NodePing; 33];
    assert_eq!(
        too_many_methods.validate(),
        Err(CapabilitiesValidationError::InvalidField(
            "supported_methods"
        ))
    );

    let mut invalid_controlled = valid_response();
    invalid_controlled.controlled_writes.locally_enabled = true;
    assert_eq!(
        invalid_controlled.validate(),
        Err(CapabilitiesValidationError::InvalidField(
            "controlled_writes"
        ))
    );
}

#[test]
fn capabilities_fail_closed_for_protocol_and_method_incompatibility() {
    let mut future = valid_response();
    future.protocol_min = PROTOCOL_VERSION + 1;
    future.protocol_max = PROTOCOL_VERSION + 1;
    assert!(matches!(
        future.ensure_controller_compatible(PROTOCOL_VERSION),
        Err(CapabilitiesValidationError::IncompatibleProtocol { .. })
    ));

    let mut missing = valid_response();
    missing
        .supported_methods
        .retain(|method| *method != FixedRpcMethod::NodeCapabilities);
    assert_eq!(
        missing.ensure_controller_compatible(PROTOCOL_VERSION),
        Err(CapabilitiesValidationError::CapabilityMethodMissing)
    );
}

#[test]
fn fixed_method_catalog_contains_no_controlled_or_generic_method() {
    let methods = READONLY_FIXED_METHOD_CATALOG
        .iter()
        .map(|method| method.as_str())
        .collect::<Vec<_>>();
    assert_eq!(methods.len(), 11);
    for forbidden in [
        "ocserv.reload",
        "ocserv.restart",
        "ocserv.config.apply",
        "shell.exec",
        "command.run",
        "file.read",
    ] {
        assert!(!methods.contains(&forbidden));
    }
}
