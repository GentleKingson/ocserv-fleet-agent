use ocfleet_cli::controller_rpc::{
    CONTROLLER_RPC_RESULT_CLASS, ControllerRpcRunner, FixedControllerRpc,
    low_sensitive_fixed_rpc_summary,
};
use ocfleet_cli::store::Store;
use ocfleet_protocol::method::{PROBE_CONTROLLER_PING, PROBE_PATH_ECHO};
use serde_json::json;

#[tokio::test]
async fn controller_rpc_missing_node_returns_node_not_found_outcome() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("controller.secret");
    let store = Store::open(&db).expect("store opens");
    let runner = ControllerRpcRunner::new(&store, &secret_key);

    let outcome = runner
        .run_fixed_node_rpc("missing-node", PROBE_CONTROLLER_PING)
        .await;

    assert_eq!(outcome.node_id, "missing-node");
    assert_eq!(outcome.endpoint_id, None);
    assert_eq!(outcome.method, PROBE_CONTROLLER_PING);
    assert_eq!(outcome.request_id, None);
    assert!(!outcome.ok);
    assert_eq!(outcome.error_code.as_deref(), Some("NODE_NOT_FOUND"));
    assert_eq!(outcome.result_class, "controller_rpc_summary");
    assert_eq!(
        outcome.summary_json["message"],
        "node not found: missing-node"
    );
}

#[test]
fn controller_rpc_ping_summary_drops_unexpected_raw_fields() {
    let summary = low_sensitive_fixed_rpc_summary(
        PROBE_CONTROLLER_PING,
        &json!({
            "message": "pong",
            "probe": "controller.ping",
            "node_id": "hk-ocserv-01",
            "agent_version": "0.1.0",
            "agent_endpoint_id": "agent-endpoint-1",
            "time_utc": "2026-07-08T00:00:00Z",
            "username": "alice",
            "client_ip": "10.0.0.2"
        }),
    )
    .expect("summary");

    assert_eq!(summary["result_class"], CONTROLLER_RPC_RESULT_CLASS);
    assert_eq!(summary["message"], "pong");
    assert_eq!(summary["probe"], "controller.ping");
    assert_eq!(summary["agent_endpoint_id"], "agent-endpoint-1");
    assert!(summary.get("username").is_none());
    assert!(summary.get("client_ip").is_none());
}

#[test]
fn controller_rpc_path_summary_drops_nested_target_result() {
    let summary = low_sensitive_fixed_rpc_summary(
        PROBE_PATH_ECHO,
        &json!({
            "probe": "path.echo",
            "ok": false,
            "source_agent_endpoint_id": "source-endpoint",
            "target_agent_endpoint_id": "target-endpoint",
            "root_request_id": "root-request",
            "peer_request_id": "peer-request",
            "time_utc": "2026-07-08T00:00:00Z",
            "target_result": {
                "error_code": "CONNECT_FAILED",
                "username": "alice",
                "client_ip": "10.0.0.2",
                "raw": {"stdout": "secret"}
            }
        }),
    )
    .expect("summary");

    assert_eq!(summary["result_class"], CONTROLLER_RPC_RESULT_CLASS);
    assert_eq!(summary["probe"], "path.echo");
    assert_eq!(summary["ok"], false);
    assert_eq!(summary["source_agent_endpoint_id"], "source-endpoint");
    assert_eq!(summary["target_agent_endpoint_id"], "target-endpoint");
    assert_eq!(summary["root_request_id"], "root-request");
    assert_eq!(summary["peer_request_id"], "peer-request");
    assert_eq!(summary["target_error_code"], "CONNECT_FAILED");
    assert!(summary.get("target_result").is_none());
    assert!(!summary.to_string().contains("alice"));
    assert!(!summary.to_string().contains("10.0.0.2"));
    assert!(!summary.to_string().contains("stdout"));
}

#[test]
fn controller_rpc_fixed_rpc_variants_define_method_and_params() {
    assert_eq!(
        FixedControllerRpc::ProbeControllerPing.method(),
        PROBE_CONTROLLER_PING
    );
    assert_eq!(FixedControllerRpc::ProbeControllerPing.params(), json!({}));

    let path = FixedControllerRpc::ProbePathEcho {
        target_agent_endpoint_id: "target-endpoint".to_string(),
    };
    assert_eq!(path.method(), PROBE_PATH_ECHO);
    assert_eq!(
        path.params(),
        json!({"target_agent_endpoint_id": "target-endpoint"})
    );

    let allowlist = FixedControllerRpc::allowlisted_methods();
    assert!(allowlist.contains(&PROBE_CONTROLLER_PING));
    assert!(allowlist.contains(&PROBE_PATH_ECHO));
    assert!(!allowlist.contains(&"shell.exec"));
}
