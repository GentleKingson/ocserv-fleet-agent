use ocfleet_cli::controller_rpc::{
    CONTROLLER_RPC_RESULT_CLASS, ControllerRpcRunner, FixedControllerRpc,
    low_sensitive_fixed_rpc_summary, low_sensitive_ocserv_observation_summary,
};
use ocfleet_cli::store::Store;
use ocfleet_protocol::method::{
    OCSERV_CERT_EXPIRY, OCSERV_CONFIG_FINGERPRINT, OCSERV_SERVICE_SUMMARY, OCSERV_SESSIONS_SUMMARY,
    OCSERV_VERSION, PROBE_CONTROLLER_PING, PROBE_PATH_ECHO,
};
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

#[test]
fn controller_rpc_ocserv_observation_summary_drops_raw_dto_fields() {
    let service = low_sensitive_ocserv_observation_summary(
        OCSERV_SERVICE_SUMMARY,
        &json!({
            "service": {"state": "running", "enabled": "enabled", "since": "2026-07-08T00:00:00Z"},
            "live": {
                "collector_status": "ok",
                "last_snapshot_at": "2026-07-08T00:00:00Z",
                "auth_failure_count_rolling": 2,
                "connection_failure_count_rolling": 1,
                "cert_min_days_remaining": 42,
                "config_fingerprint_short": "abcdef123456"
            },
            "meta": {"source": "provider", "collected_at": "2026-07-08T00:00:00Z", "freshness": "live"},
            "username": "alice",
            "client_ip": "10.0.0.2",
            "config_path": "/etc/ocserv/ocserv.conf"
        }),
    )
    .expect("service summary");
    assert_eq!(service["result_class"], "low_sensitive_summary");
    assert_eq!(service["service_state"], "running");
    assert_eq!(service["service_enabled"], "enabled");
    assert_eq!(service["collector_status"], "ok");
    assert_eq!(service["auth_failure_count_rolling"], 2);
    assert_eq!(service["connection_failure_count_rolling"], 1);
    assert_eq!(service["cert_min_days_remaining"], 42);
    assert_eq!(service["config_fingerprint_short"], "abcdef123456");
    assert!(service.get("service").is_none());
    assert!(service.get("meta").is_none());

    let version = low_sensitive_ocserv_observation_summary(
        OCSERV_VERSION,
        &json!({
            "version": "1.2.3",
            "status": "available",
            "meta": {"source": "provider", "collected_at": "2026-07-08T00:00:00Z", "freshness": "live"},
            "stdout": "secret"
        }),
    )
    .expect("version summary");
    assert_eq!(version["version"], "1.2.3");
    assert_eq!(version["status"], "available");
    assert!(version.get("meta").is_none());

    let sessions = low_sensitive_ocserv_observation_summary(
        OCSERV_SESSIONS_SUMMARY,
        &json!({
            "sessions": {"total": 12, "status": "available", "users": ["alice"]},
            "meta": {"source": "provider", "collected_at": "2026-07-08T00:00:00Z", "freshness": "live"}
        }),
    )
    .expect("sessions summary");
    assert_eq!(sessions["sessions_total"], 12);
    assert_eq!(sessions["sessions_status"], "available");
    assert!(sessions.get("users").is_none());

    let fingerprint = low_sensitive_ocserv_observation_summary(
        OCSERV_CONFIG_FINGERPRINT,
        &json!({
            "fingerprint": {
                "algorithm": "sha256",
                "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "status": "available",
                "path": "/etc/ocserv/ocserv.conf"
            },
            "meta": {"source": "provider", "collected_at": "2026-07-08T00:00:00Z", "freshness": "live"}
        }),
    )
    .expect("fingerprint summary");
    assert_eq!(fingerprint["config_fingerprint_algorithm"], "sha256");
    assert_eq!(fingerprint["config_fingerprint_prefix"], "aaaaaaaaaaaa");
    assert_eq!(fingerprint["config_fingerprint_status"], "available");
    assert!(fingerprint.get("hash").is_none());

    let combined = json!([service, version, sessions, fingerprint]).to_string();
    for marker in [
        "alice",
        "10.0.0.2",
        "/etc/ocserv",
        "stdout",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        assert!(!combined.contains(marker), "raw marker leaked: {marker}");
    }
}

#[test]
fn controller_rpc_cert_summary_uses_alert_and_health_consumable_fields() {
    let summary = low_sensitive_ocserv_observation_summary(
        OCSERV_CERT_EXPIRY,
        &json!({
            "certs": [
                {
                    "name": "server",
                    "status": "valid",
                    "days_remaining": 40,
                    "fingerprint_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "subject": "CN=vpn.example"
                },
                {
                    "name": "intermediate",
                    "status": "expiring_soon",
                    "days_remaining": 3,
                    "issuer": "CN=ca"
                }
            ],
            "meta": {"source": "provider", "collected_at": "2026-07-08T00:00:00Z", "freshness": "live"}
        }),
    )
    .expect("cert summary");

    assert_eq!(summary["result_class"], "low_sensitive_summary");
    assert_eq!(summary["cert_count"], 2);
    assert_eq!(summary["days_remaining"], 3);
    assert_eq!(summary["status"], "expiring_soon");
    assert!(summary.get("min_days_remaining").is_none());
    assert!(summary.get("cert_status").is_none());
    assert!(!summary.to_string().contains("bbbbbbbbbbbbbbbb"));
    assert!(!summary.to_string().contains("subject"));
    assert!(!summary.to_string().contains("issuer"));
}
