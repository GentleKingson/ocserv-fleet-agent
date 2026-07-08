use ocfleet_cli::controller_rpc::ControllerRpcRunner;
use ocfleet_cli::store::Store;
use ocfleet_protocol::method::PROBE_CONTROLLER_PING;

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
