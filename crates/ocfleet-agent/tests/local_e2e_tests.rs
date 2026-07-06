use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use ocfleet_agent::audit::JsonlAuditWriter;
use ocfleet_agent::audit_limiter::RejectedAuditLimiter;
use ocfleet_agent::nonce::NonceCache;
use ocfleet_agent::server::{
    AgentServerState, ServerLimiters, bind_agent_endpoint_local_only, serve_endpoint,
};
use ocfleet_cli::rpc_client::{
    bind_controller_endpoint_local_only, build_request, call_endpoint_addr,
};
use ocfleet_config::agent::{
    AgentConfig, AuditConfig, ControllerConfig, IrohConfig, NodeConfig, SecurityConfig,
};
use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::method::{NODE_INFO, NODE_PING, PROBE_CONTROLLER_PING};
use ocfleet_protocol::rpc::RpcResponse;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::task::JoinHandle;

struct LocalAgentHarness {
    controller: Endpoint,
    agent: Endpoint,
    agent_addr: EndpointAddr,
    agent_id: EndpointId,
    config: AgentConfig,
    audit_path: PathBuf,
    server_task: JoinHandle<anyhow::Result<()>>,
}

impl LocalAgentHarness {
    async fn shutdown(self) {
        self.agent.close().await;
        self.controller.close().await;
        self.server_task.abort();
        let _ = self.server_task.await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_controller_can_ping_and_get_node_info() {
    let dir = tempfile::tempdir().expect("temp dir");
    let controller_key = SecretKey::generate();
    let agent_key = SecretKey::generate();
    let harness = spawn_local_agent(controller_key, agent_key, &dir).await;

    let ping_request = build_request(NODE_PING, json!({}), Some("local-cli".into()), 5_000);
    let ping_response = call_endpoint_addr(
        &harness.controller,
        harness.agent_addr.clone(),
        harness.agent_id,
        harness.config.iroh.alpn.as_bytes(),
        ping_request,
    )
    .await
    .expect("node.ping rpc");

    assert!(ping_response.ok);
    assert_eq!(
        ping_response.result.as_ref().expect("ping result")["message"],
        "pong"
    );

    let info_request = build_request(NODE_INFO, json!({}), Some("local-cli".into()), 5_000);
    let info_response = call_endpoint_addr(
        &harness.controller,
        harness.agent_addr.clone(),
        harness.agent_id,
        harness.config.iroh.alpn.as_bytes(),
        info_request,
    )
    .await
    .expect("node.info rpc");

    assert!(info_response.ok);
    let info = info_response.result.as_ref().expect("node.info result");
    assert_eq!(info["node_id"], "hk-ocserv-01");
    assert_eq!(info["agent_endpoint_id"], harness.agent_id.to_string());

    wait_for_audit_event(&harness.audit_path, |event| {
        audit_is_successful_method(event, NODE_PING)
    })
    .await;
    wait_for_audit_event(&harness.audit_path, |event| {
        audit_is_successful_method(event, NODE_INFO)
    })
    .await;

    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_controller_can_run_controller_probe_ping() {
    let dir = tempfile::tempdir().expect("temp dir");
    let controller_key = SecretKey::generate();
    let agent_key = SecretKey::generate();
    let harness = spawn_local_agent(controller_key, agent_key, &dir).await;

    let request = build_request(
        PROBE_CONTROLLER_PING,
        json!({}),
        Some("local-cli".into()),
        5_000,
    );
    let response = call_endpoint_addr(
        &harness.controller,
        harness.agent_addr.clone(),
        harness.agent_id,
        harness.config.iroh.alpn.as_bytes(),
        request,
    )
    .await
    .expect("probe.controller.ping rpc");

    assert!(response.ok);
    let result = response.result.as_ref().expect("probe result");
    assert_eq!(result["message"], "pong");
    assert_eq!(result["probe"], "controller.ping");
    assert_eq!(result["node_id"], "hk-ocserv-01");
    assert_eq!(result["agent_endpoint_id"], harness.agent_id.to_string());
    assert!(result["agent_version"].as_str().is_some());
    assert!(
        time::OffsetDateTime::parse(
            result["time_utc"].as_str().expect("probe time string"),
            &time::format_description::well_known::Rfc3339,
        )
        .is_ok()
    );
    let mut fields = result
        .as_object()
        .expect("probe result object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    fields.sort_unstable();
    assert_eq!(
        fields,
        vec![
            "agent_endpoint_id",
            "agent_version",
            "message",
            "node_id",
            "probe",
            "time_utc"
        ]
    );

    wait_for_audit_event(&harness.audit_path, |event| {
        audit_is_successful_method(event, PROBE_CONTROLLER_PING)
    })
    .await;

    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_agent_rejects_known_and_unknown_disallowed_methods() {
    let dir = tempfile::tempdir().expect("temp dir");
    let harness = spawn_local_agent(SecretKey::generate(), SecretKey::generate(), &dir).await;

    let known = call_agent(&harness, "ocserv.status").await;
    assert_eq!(
        known.error.as_ref().expect("known method error").code,
        ErrorCode::MethodNotAllowed
    );

    let unknown = call_agent(&harness, "shell.exec").await;
    assert_eq!(
        unknown.error.as_ref().expect("unknown method error").code,
        ErrorCode::MethodNotFound
    );

    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_agent_rejects_replayed_nonce() {
    let dir = tempfile::tempdir().expect("temp dir");
    let harness = spawn_local_agent(SecretKey::generate(), SecretKey::generate(), &dir).await;
    let request = build_request(NODE_PING, json!({}), Some("local-cli".into()), 5_000);

    let first = call_endpoint_addr(
        &harness.controller,
        harness.agent_addr.clone(),
        harness.agent_id,
        harness.config.iroh.alpn.as_bytes(),
        request.clone(),
    )
    .await
    .expect("first node.ping rpc");
    assert!(first.ok);

    let replay = call_endpoint_addr(
        &harness.controller,
        harness.agent_addr.clone(),
        harness.agent_id,
        harness.config.iroh.alpn.as_bytes(),
        request,
    )
    .await
    .expect("replayed node.ping rpc response");
    assert_eq!(
        replay.error.as_ref().expect("replay error").code,
        ErrorCode::ReplayedNonce
    );

    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_agent_rejects_unauthorized_controller() {
    let dir = tempfile::tempdir().expect("temp dir");
    let authorized_controller_key = SecretKey::generate();
    let harness = spawn_local_agent(authorized_controller_key, SecretKey::generate(), &dir).await;
    let unauthorized_controller = bind_controller_endpoint_local_only(SecretKey::generate())
        .await
        .expect("unauthorized controller endpoint");
    let request = build_request(NODE_PING, json!({}), Some("local-cli".into()), 5_000);

    let result = call_endpoint_addr(
        &unauthorized_controller,
        harness.agent_addr.clone(),
        harness.agent_id,
        harness.config.iroh.alpn.as_bytes(),
        request,
    )
    .await;

    assert!(
        result.as_ref().map(|response| !response.ok).unwrap_or(true),
        "unauthorized controller must not receive a successful response: {result:?}"
    );
    wait_for_audit_event(&harness.audit_path, |event| {
        event["error_code"] == "ENDPOINT_NOT_ALLOWED"
            || (event["event"] == "rpc_rejected" && event["allowed"] == false)
    })
    .await;

    unauthorized_controller.close().await;
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_client_detects_endpoint_mismatch_before_sending_rpc() {
    let dir = tempfile::tempdir().expect("temp dir");
    let harness = spawn_local_agent(SecretKey::generate(), SecretKey::generate(), &dir).await;
    let wrong_endpoint_id = SecretKey::generate().public();
    let request = build_request(NODE_PING, json!({}), Some("local-cli".into()), 5_000);

    let err = call_endpoint_addr(
        &harness.controller,
        harness.agent_addr.clone(),
        wrong_endpoint_id,
        harness.config.iroh.alpn.as_bytes(),
        request,
    )
    .await
    .expect_err("endpoint id mismatch is rejected client-side");

    assert_eq!(err.code(), ErrorCode::EndpointMismatch);
    assert_eq!(
        err.details()["expected_endpoint_id"],
        wrong_endpoint_id.to_string()
    );
    assert_eq!(
        err.details()["actual_remote_endpoint_id"],
        harness.agent_id.to_string()
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !audit_events(&harness.audit_path)
            .iter()
            .any(|event| audit_is_successful_method(event, NODE_PING)),
        "client-side endpoint mismatch must not dispatch node.ping"
    );

    harness.shutdown().await;
}

async fn spawn_local_agent(
    controller_key: SecretKey,
    agent_key: SecretKey,
    dir: &TempDir,
) -> LocalAgentHarness {
    let controller = bind_controller_endpoint_local_only(controller_key.clone())
        .await
        .expect("bind local-only controller endpoint");
    let audit_path = dir.path().join("agent-audit.jsonl");
    let config = test_config(
        controller_key.public(),
        audit_path.clone(),
        dir.path().join("agent.secret"),
    );
    let audit = JsonlAuditWriter::new(audit_path.clone());
    let audit_limiter = Arc::new(Mutex::new(RejectedAuditLimiter::new(&config.audit)));
    let agent =
        bind_agent_endpoint_local_only(&config, agent_key, audit.clone(), audit_limiter.clone())
            .await
            .expect("bind local-only agent endpoint");
    let agent_addr = agent.addr();
    let agent_id = agent.id();
    let state = AgentServerState {
        config: config.clone(),
        audit,
        nonce_cache: Arc::new(Mutex::new(NonceCache::with_limits(
            config.security.max_live_nonces_global,
            config.security.max_live_nonces_per_controller,
        ))),
        limiters: Arc::new(ServerLimiters::from_config(&config.security)),
        audit_limiter,
        agent_endpoint_id: agent_id.to_string(),
    };
    let server_task = tokio::spawn(serve_endpoint(agent.clone(), state));

    tokio::task::yield_now().await;

    LocalAgentHarness {
        controller,
        agent,
        agent_addr,
        agent_id,
        config,
        audit_path,
        server_task,
    }
}

fn test_config(
    controller_endpoint_id: EndpointId,
    audit_path: PathBuf,
    agent_secret_path: PathBuf,
) -> AgentConfig {
    AgentConfig {
        node: NodeConfig {
            id: "hk-ocserv-01".to_string(),
            region: "hk".to_string(),
            role: "ocserv".to_string(),
        },
        iroh: IrohConfig {
            secret_key_path: agent_secret_path,
            alpn: "/com.github.gentlekingson.ocfleet.mgmt/1".to_string(),
        },
        security: SecurityConfig {
            allowed_clock_skew_seconds: 60,
            default_deadline_ms: 5_000,
            max_deadline_ms: 10_000,
            max_rpc_timeout_ms: 5_000,
            max_request_bytes: 65_536,
            max_response_bytes: 2_097_152,
            max_handshake_tasks_global: 256,
            max_connections_global: 256,
            max_connections_per_controller: 32,
            max_streams_global: 1024,
            max_streams_per_controller: 128,
            max_live_nonces_global: 100_000,
            max_live_nonces_per_controller: 10_000,
            controllers: vec![ControllerConfig {
                endpoint_id: controller_endpoint_id.to_string(),
                role: "viewer".to_string(),
            }],
        },
        audit: AuditConfig {
            path: audit_path,
            audit_queue_capacity: 1024,
            rejected_peer_log_burst: 10,
            rejected_peer_log_refill_per_sec: 1,
            rejected_peer_log_max_buckets: 4096,
            rejected_peer_log_bucket_ttl_seconds: 3600,
            rejected_peer_log_aggregate_interval_seconds: 60,
        },
        ocserv: None,
        logs: None,
    }
}

async fn call_agent(harness: &LocalAgentHarness, method: &str) -> RpcResponse {
    call_endpoint_addr(
        &harness.controller,
        harness.agent_addr.clone(),
        harness.agent_id,
        harness.config.iroh.alpn.as_bytes(),
        build_request(method, json!({}), Some("local-cli".into()), 5_000),
    )
    .await
    .expect("agent rpc response")
}

async fn wait_for_audit_event(path: &Path, predicate: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let events = audit_events(path);
        if let Some(event) = events.into_iter().find(|event| predicate(event)) {
            return event;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for audit event in {}:\n{}",
            path.display(),
            std::fs::read_to_string(path).unwrap_or_else(|err| format!("<unreadable: {err}>"))
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn audit_events(path: &Path) -> Vec<Value> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };

    text.lines()
        .map(|line| serde_json::from_str(line).expect("audit line is json"))
        .collect()
}

fn audit_is_successful_method(event: &Value, method: &str) -> bool {
    event.get("stage").and_then(Value::as_str) == Some("dispatch")
        && event.get("method").and_then(Value::as_str) == Some(method)
        && event.get("ok").and_then(Value::as_bool) == Some(true)
}
