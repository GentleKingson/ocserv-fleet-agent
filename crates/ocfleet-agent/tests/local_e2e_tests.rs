use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use ocfleet_agent::audit::JsonlAuditWriter;
use ocfleet_agent::audit_limiter::RejectedAuditLimiter;
use ocfleet_agent::authz::AgentAuthorization;
use ocfleet_agent::nonce::NonceCache;
use ocfleet_agent::peer_echo::{
    PeerEchoAuditContext, PeerEchoCall, PeerEchoLimits, call_peer_echo,
};
use ocfleet_agent::server::{
    AgentServerState, PathTargetResolver, ServerLimiters, bind_agent_endpoint_local_only,
    serve_endpoint,
};
use ocfleet_cli::rpc_client::{
    bind_controller_endpoint_local_only, build_request, call_endpoint_addr,
};
use ocfleet_config::agent::{
    AgentConfig, AuditConfig, ControllerConfig, IrohConfig, NodeConfig, OcservReadonlyProviderKind,
    PathProbeConfig, PeerConfig, SecurityConfig,
};
use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::method::{
    NODE_INFO, NODE_PING, OCSERV_CERT_EXPIRY, OCSERV_CONFIG_FINGERPRINT, OCSERV_SERVICE_SUMMARY,
    OCSERV_SESSIONS_SUMMARY, OCSERV_VERSION, PROBE_CONTROLLER_PING, PROBE_PATH_ECHO,
    PROBE_PEER_ECHO,
};
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

struct LocalPathProbeHarness {
    controller: Endpoint,
    source: Endpoint,
    target: Endpoint,
    source_addr: EndpointAddr,
    source_id: EndpointId,
    target_id: EndpointId,
    source_config: AgentConfig,
    source_audit_path: PathBuf,
    target_audit_path: PathBuf,
    source_task: JoinHandle<anyhow::Result<()>>,
    target_task: JoinHandle<anyhow::Result<()>>,
}

impl LocalPathProbeHarness {
    async fn shutdown(self) {
        self.source.close().await;
        self.target.close().await;
        self.controller.close().await;
        self.source_task.abort();
        self.target_task.abort();
        let _ = self.source_task.await;
        let _ = self.target_task.await;
    }
}

impl LocalAgentHarness {
    async fn shutdown(self) {
        self.agent.close().await;
        self.controller.close().await;
        self.server_task.abort();
        let _ = self.server_task.await;
    }
}

macro_rules! skip_if_local_iroh_unavailable {
    () => {
        if local_iroh_unavailable().await {
            return;
        }
    };
}

async fn local_iroh_unavailable() -> bool {
    match bind_controller_endpoint_local_only(SecretKey::generate()).await {
        Ok(endpoint) => {
            endpoint.close().await;
            false
        }
        Err(err) if err.code() == ErrorCode::ConnectFailed && is_restricted_netmon_error(&err) => {
            eprintln!("skipping local iroh e2e test: {err}");
            true
        }
        Err(err) => panic!("local iroh preflight failed: {err:#?}"),
    }
}

fn is_restricted_netmon_error(err: &ocfleet_cli::rpc_client::RpcClientError) -> bool {
    let message = format!("{err}\n{err:#?}");
    message.contains("Failed to create netmon monitor")
        || (message.contains("netmon") && message.contains("Operation not permitted"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_controller_can_ping_and_get_node_info() {
    skip_if_local_iroh_unavailable!();

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
    skip_if_local_iroh_unavailable!();

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
    skip_if_local_iroh_unavailable!();

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
async fn local_agent_ocserv_readonly_audit_is_low_sensitive_summary_for_fixed_methods() {
    skip_if_local_iroh_unavailable!();

    let dir = tempfile::tempdir().expect("temp dir");
    let harness =
        spawn_local_agent_with_ocserv_snapshot(SecretKey::generate(), SecretKey::generate(), &dir)
            .await;

    for method in [
        OCSERV_SERVICE_SUMMARY,
        OCSERV_VERSION,
        OCSERV_SESSIONS_SUMMARY,
        OCSERV_CERT_EXPIRY,
        OCSERV_CONFIG_FINGERPRINT,
    ] {
        let request = build_request(method, json!({}), Some("local-cli".into()), 5_000);
        let request_id = request.request_id.clone();
        let response = call_endpoint_addr(
            &harness.controller,
            harness.agent_addr.clone(),
            harness.agent_id,
            harness.config.iroh.alpn.as_bytes(),
            request,
        )
        .await
        .expect("ocserv readonly rpc");

        assert!(response.ok, "{method}: {response:#?}");
        let event = wait_for_audit_event(&harness.audit_path, |event| {
            event.get("stage").and_then(Value::as_str) == Some("dispatch")
                && event.get("method").and_then(Value::as_str) == Some(method)
                && event.get("request_id").and_then(Value::as_str) == Some(request_id.as_str())
        })
        .await;

        assert_eq!(
            event.get("result_class").and_then(Value::as_str),
            Some("low_sensitive_summary")
        );
        assert!(event.get("result").is_none_or(Value::is_null));
        assert!(event.get("response").is_none_or(Value::is_null));
        assert!(event.get("response_body").is_none_or(Value::is_null));
        assert!(
            event
                .get("response_bytes")
                .and_then(Value::as_u64)
                .is_some()
        );
    }

    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_agent_rejects_replayed_nonce() {
    skip_if_local_iroh_unavailable!();

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
async fn local_agent_rejects_expired_request() {
    skip_if_local_iroh_unavailable!();

    let dir = tempfile::tempdir().expect("temp dir");
    let harness = spawn_local_agent(SecretKey::generate(), SecretKey::generate(), &dir).await;
    let mut request = build_request(NODE_PING, json!({}), Some("local-cli".into()), 5_000);
    request.issued_at = (time::OffsetDateTime::now_utc() - time::Duration::seconds(6))
        .format(&time::format_description::well_known::Rfc3339)
        .expect("format expired issued_at");

    let response = call_endpoint_addr(
        &harness.controller,
        harness.agent_addr.clone(),
        harness.agent_id,
        harness.config.iroh.alpn.as_bytes(),
        request,
    )
    .await
    .expect("expired request rpc response");

    assert!(!response.ok);
    assert_eq!(
        response.error.as_ref().expect("expired request error").code,
        ErrorCode::RequestExpired
    );
    wait_for_audit_event(&harness.audit_path, |event| {
        event.get("stage").and_then(Value::as_str) == Some("dispatch")
            && event.get("method").and_then(Value::as_str) == Some(NODE_PING)
            && event.get("ok").and_then(Value::as_bool) == Some(false)
            && event.get("error_code").and_then(Value::as_str) == Some("REQUEST_EXPIRED")
    })
    .await;

    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_agent_rejects_unauthorized_controller() {
    skip_if_local_iroh_unavailable!();

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
async fn local_agent_rejects_disabled_peer_at_connection_admission() {
    skip_if_local_iroh_unavailable!();

    let dir = tempfile::tempdir().expect("temp dir");
    let controller_key = SecretKey::generate();
    let disabled_peer_key = SecretKey::generate();
    let harness = spawn_local_agent_with_peers(
        controller_key,
        SecretKey::generate(),
        vec![PeerConfig {
            endpoint_id: disabled_peer_key.public().to_string(),
            enabled: false,
        }],
        &dir,
    )
    .await;
    let disabled_peer = bind_controller_endpoint_local_only(disabled_peer_key)
        .await
        .expect("disabled peer endpoint");
    let request = build_request(NODE_PING, json!({}), Some("local-peer".into()), 5_000);

    let result = call_endpoint_addr(
        &disabled_peer,
        harness.agent_addr.clone(),
        harness.agent_id,
        harness.config.iroh.alpn.as_bytes(),
        request,
    )
    .await;

    assert!(
        result.as_ref().map(|response| !response.ok).unwrap_or(true),
        "disabled peer must not receive a successful response: {result:?}"
    );
    wait_for_audit_event(&harness.audit_path, |event| {
        event["event"] == "rpc_rejected"
            && event["allowed"] == false
            && event["error_code"] == "ENDPOINT_NOT_ALLOWED"
            && event["stage"] == "connection_admission"
            && event["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("disabled peer"))
            && event.get("request_id").is_none_or(Value::is_null)
            && event.get("method").is_none_or(Value::is_null)
            && event.get("params_hash").is_none_or(Value::is_null)
            && event.get("nonce_hash").is_none_or(Value::is_null)
    })
    .await;

    disabled_peer.close().await;
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_peer_echo_helper_calls_authorized_target_and_writes_both_audits() {
    skip_if_local_iroh_unavailable!();

    let dir = tempfile::tempdir().expect("temp dir");
    let controller_key = SecretKey::generate();
    let target_key = SecretKey::generate();
    let source_key = SecretKey::generate();
    let source_id = source_key.public();
    let harness = spawn_local_agent_with_peers(
        controller_key,
        target_key,
        vec![PeerConfig {
            endpoint_id: source_id.to_string(),
            enabled: true,
        }],
        &dir,
    )
    .await;
    let source_endpoint = bind_controller_endpoint_local_only(source_key)
        .await
        .expect("bind local-only source peer endpoint");
    let source_audit_path = dir.path().join("source-peer-audit.jsonl");
    let source_audit = JsonlAuditWriter::new(source_audit_path.clone());

    let output = call_peer_echo(PeerEchoCall {
        endpoint: &source_endpoint,
        target: harness.agent_addr.clone(),
        expected_target_endpoint_id: harness.agent_id,
        source_endpoint_id: source_id,
        alpn: harness.config.iroh.alpn.as_bytes(),
        audit: &source_audit,
        limits: PeerEchoLimits::default(),
        audit_context: PeerEchoAuditContext::default(),
    })
    .await
    .expect("peer echo helper succeeds");

    let result = &output.result;
    assert_eq!(result["message"], "pong");
    assert_eq!(result["probe"], "peer.echo");
    assert_eq!(result["source_agent_endpoint_id"], source_id.to_string());
    assert_eq!(
        result["target_agent_endpoint_id"],
        harness.agent_id.to_string()
    );
    assert_eq!(result["target_node_id"], "hk-ocserv-01");
    assert!(result["agent_version"].as_str().is_some());
    assert!(
        time::OffsetDateTime::parse(
            result["time_utc"].as_str().expect("peer echo time"),
            &time::format_description::well_known::Rfc3339,
        )
        .is_ok()
    );
    let mut fields = result
        .as_object()
        .expect("peer echo result object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    fields.sort_unstable();
    assert_eq!(
        fields,
        vec![
            "agent_version",
            "message",
            "probe",
            "source_agent_endpoint_id",
            "target_agent_endpoint_id",
            "target_node_id",
            "time_utc"
        ]
    );

    wait_for_audit_event(&source_audit_path, |event| {
        event.get("stage").and_then(Value::as_str) == Some("source_peer_echo")
            && event.get("method").and_then(Value::as_str) == Some(PROBE_PEER_ECHO)
            && event.get("remote_endpoint_id").and_then(Value::as_str)
                == Some(harness.agent_id.to_string().as_str())
            && event.get("request_id").and_then(Value::as_str) == Some(output.request_id.as_str())
            && event.get("ok").and_then(Value::as_bool) == Some(true)
    })
    .await;

    wait_for_audit_event(&harness.audit_path, |event| {
        event.get("stage").and_then(Value::as_str) == Some("dispatch")
            && event.get("method").and_then(Value::as_str) == Some(PROBE_PEER_ECHO)
            && event.get("remote_endpoint_id").and_then(Value::as_str)
                == Some(source_id.to_string().as_str())
            && event.get("request_id").and_then(Value::as_str) == Some(output.request_id.as_str())
            && event.get("ok").and_then(Value::as_bool) == Some(true)
    })
    .await;

    source_endpoint.close().await;
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_peer_connection_cannot_call_controller_only_method() {
    skip_if_local_iroh_unavailable!();

    let dir = tempfile::tempdir().expect("temp dir");
    let source_key = SecretKey::generate();
    let source_id = source_key.public();
    let harness = spawn_local_agent_with_peers(
        SecretKey::generate(),
        SecretKey::generate(),
        vec![PeerConfig {
            endpoint_id: source_id.to_string(),
            enabled: true,
        }],
        &dir,
    )
    .await;
    let source_endpoint = bind_controller_endpoint_local_only(source_key)
        .await
        .expect("bind local-only source peer endpoint");
    let request = build_request(NODE_PING, json!({}), Some("local-peer".into()), 5_000);

    let response = call_endpoint_addr(
        &source_endpoint,
        harness.agent_addr.clone(),
        harness.agent_id,
        harness.config.iroh.alpn.as_bytes(),
        request,
    )
    .await
    .expect("peer receives structured method authorization response");

    assert!(!response.ok);
    assert_eq!(
        response.error.as_ref().expect("method auth error").code,
        ErrorCode::MethodNotAllowed
    );
    wait_for_audit_event(&harness.audit_path, |event| {
        event.get("stage").and_then(Value::as_str) == Some("dispatch")
            && event.get("method").and_then(Value::as_str) == Some(NODE_PING)
            && event.get("remote_endpoint_id").and_then(Value::as_str)
                == Some(source_id.to_string().as_str())
            && event.get("ok").and_then(Value::as_bool) == Some(false)
            && event.get("error_code").and_then(Value::as_str) == Some("METHOD_NOT_ALLOWED")
    })
    .await;

    source_endpoint.close().await;
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_controller_can_run_one_hop_path_probe_and_link_three_audits() {
    skip_if_local_iroh_unavailable!();

    let dir = tempfile::tempdir().expect("temp dir");
    let harness = spawn_local_path_probe_agents(&dir, true, true).await;
    let request = build_request(
        PROBE_PATH_ECHO,
        json!({"target_agent_endpoint_id": harness.target_id.to_string()}),
        Some("local-cli".into()),
        5_000,
    );
    let root_request_id = request.request_id.clone();

    let response = call_endpoint_addr(
        &harness.controller,
        harness.source_addr.clone(),
        harness.source_id,
        harness.source_config.iroh.alpn.as_bytes(),
        request,
    )
    .await
    .expect("probe.path.echo rpc");

    assert!(response.ok, "{response:#?}");
    let result = response.result.as_ref().expect("path result");
    assert_eq!(result["probe"], "path.echo");
    assert_eq!(result["ok"], true);
    assert_eq!(
        result["source_agent_endpoint_id"],
        harness.source_id.to_string()
    );
    assert_eq!(
        result["target_agent_endpoint_id"],
        harness.target_id.to_string()
    );
    assert_eq!(result["root_request_id"], root_request_id);
    let peer_request_id = result["peer_request_id"]
        .as_str()
        .expect("peer_request_id")
        .to_string();
    assert_eq!(
        result["target_result"],
        json!({"probe": "peer.echo", "message": "pong"})
    );
    assert!(
        time::OffsetDateTime::parse(
            result["time_utc"].as_str().expect("path time"),
            &time::format_description::well_known::Rfc3339,
        )
        .is_ok()
    );
    let mut fields = result
        .as_object()
        .expect("path result object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    fields.sort_unstable();
    assert_eq!(
        fields,
        vec![
            "ok",
            "peer_request_id",
            "probe",
            "root_request_id",
            "source_agent_endpoint_id",
            "target_agent_endpoint_id",
            "target_result",
            "time_utc"
        ]
    );

    wait_for_audit_event(&harness.source_audit_path, |event| {
        event.get("stage").and_then(Value::as_str) == Some("dispatch")
            && event.get("method").and_then(Value::as_str) == Some(PROBE_PATH_ECHO)
            && event.get("request_id").and_then(Value::as_str) == Some(root_request_id.as_str())
            && event.get("root_request_id").and_then(Value::as_str)
                == Some(root_request_id.as_str())
            && event.get("peer_request_id").and_then(Value::as_str)
                == Some(peer_request_id.as_str())
            && event.get("path_target_endpoint_id").and_then(Value::as_str)
                == Some(harness.target_id.to_string().as_str())
            && event.get("ok").and_then(Value::as_bool) == Some(true)
    })
    .await;

    wait_for_audit_event(&harness.source_audit_path, |event| {
        event.get("stage").and_then(Value::as_str) == Some("source_peer_echo")
            && event.get("method").and_then(Value::as_str) == Some(PROBE_PEER_ECHO)
            && event.get("request_id").and_then(Value::as_str) == Some(peer_request_id.as_str())
            && event.get("root_request_id").and_then(Value::as_str)
                == Some(root_request_id.as_str())
            && event.get("peer_request_id").and_then(Value::as_str)
                == Some(peer_request_id.as_str())
            && event.get("path_target_endpoint_id").and_then(Value::as_str)
                == Some(harness.target_id.to_string().as_str())
            && event.get("ok").and_then(Value::as_bool) == Some(true)
    })
    .await;

    wait_for_audit_event(&harness.target_audit_path, |event| {
        event.get("stage").and_then(Value::as_str) == Some("dispatch")
            && event.get("method").and_then(Value::as_str) == Some(PROBE_PEER_ECHO)
            && event.get("remote_endpoint_id").and_then(Value::as_str)
                == Some(harness.source_id.to_string().as_str())
            && event.get("request_id").and_then(Value::as_str) == Some(peer_request_id.as_str())
            && event.get("root_request_id").is_none_or(Value::is_null)
            && event.get("ok").and_then(Value::as_bool) == Some(true)
    })
    .await;

    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_path_probe_target_segment_failure_is_outer_success_with_correlated_source_audit() {
    skip_if_local_iroh_unavailable!();

    let dir = tempfile::tempdir().expect("temp dir");
    let harness = spawn_local_path_probe_agents(&dir, true, false).await;
    let request = build_request(
        PROBE_PATH_ECHO,
        json!({"target_agent_endpoint_id": harness.target_id.to_string()}),
        Some("local-cli".into()),
        5_000,
    );
    let root_request_id = request.request_id.clone();

    let response = call_endpoint_addr(
        &harness.controller,
        harness.source_addr.clone(),
        harness.source_id,
        harness.source_config.iroh.alpn.as_bytes(),
        request,
    )
    .await
    .expect("probe.path.echo rpc");

    assert!(response.ok, "{response:#?}");
    let result = response.result.as_ref().expect("path result");
    assert_eq!(result["probe"], "path.echo");
    assert_eq!(result["ok"], false);
    assert_eq!(
        result["source_agent_endpoint_id"],
        harness.source_id.to_string()
    );
    assert_eq!(
        result["target_agent_endpoint_id"],
        harness.target_id.to_string()
    );
    assert_eq!(result["root_request_id"], root_request_id);
    assert!(result["peer_request_id"].as_str().is_some());
    assert!(result.get("error_code").is_none());
    assert!(result.get("message").is_none());
    assert_eq!(result["target_result"]["ok"], false);
    assert!(result["target_result"]["error_code"].as_str().is_some());
    assert_eq!(result["target_result"]["stage"], "target_peer_echo");
    assert_eq!(result["target_result"]["reason"], "target peer echo failed");
    let peer_request_id = result["peer_request_id"]
        .as_str()
        .expect("peer request id")
        .to_string();

    wait_for_audit_event(&harness.source_audit_path, |event| {
        event.get("stage").and_then(Value::as_str) == Some("source_peer_echo")
            && event.get("method").and_then(Value::as_str) == Some(PROBE_PEER_ECHO)
            && event.get("request_id").and_then(Value::as_str) == Some(peer_request_id.as_str())
            && event.get("root_request_id").and_then(Value::as_str)
                == Some(root_request_id.as_str())
            && event.get("peer_request_id").and_then(Value::as_str)
                == Some(peer_request_id.as_str())
            && event.get("path_target_endpoint_id").and_then(Value::as_str)
                == Some(harness.target_id.to_string().as_str())
            && event.get("ok").and_then(Value::as_bool) == Some(false)
    })
    .await;

    wait_for_audit_event(&harness.source_audit_path, |event| {
        event.get("stage").and_then(Value::as_str) == Some("dispatch")
            && event.get("method").and_then(Value::as_str) == Some(PROBE_PATH_ECHO)
            && event.get("request_id").and_then(Value::as_str) == Some(root_request_id.as_str())
            && event.get("root_request_id").and_then(Value::as_str)
                == Some(root_request_id.as_str())
            && event.get("peer_request_id").and_then(Value::as_str)
                == Some(peer_request_id.as_str())
            && event.get("path_target_endpoint_id").and_then(Value::as_str)
                == Some(harness.target_id.to_string().as_str())
    })
    .await;

    wait_for_audit_event(&harness.target_audit_path, |event| {
        event.get("event").and_then(Value::as_str) == Some("rpc_rejected")
            && event.get("stage").and_then(Value::as_str) == Some("connection_admission")
            && event.get("request_id").is_none_or(Value::is_null)
            && event.get("root_request_id").is_none_or(Value::is_null)
            && event.get("peer_request_id").is_none_or(Value::is_null)
    })
    .await;

    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_path_probe_rejects_missing_source_authorization() {
    skip_if_local_iroh_unavailable!();

    let dir = tempfile::tempdir().expect("temp dir");
    let harness = spawn_local_path_probe_agents(&dir, false, true).await;
    let request = build_request(
        PROBE_PATH_ECHO,
        json!({"target_agent_endpoint_id": harness.target_id.to_string()}),
        Some("local-cli".into()),
        5_000,
    );
    let root_request_id = request.request_id.clone();

    let response = call_endpoint_addr(
        &harness.controller,
        harness.source_addr.clone(),
        harness.source_id,
        harness.source_config.iroh.alpn.as_bytes(),
        request,
    )
    .await
    .expect("probe.path.echo missing auth rpc");

    assert!(!response.ok, "{response:#?}");
    let error = response.error.as_ref().expect("path auth error");
    assert_eq!(error.code, ErrorCode::EndpointNotAllowed);
    assert!(error.message.contains("authorization is missing"));

    wait_for_audit_event(&harness.source_audit_path, |event| {
        event.get("stage").and_then(Value::as_str) == Some("dispatch")
            && event.get("method").and_then(Value::as_str) == Some(PROBE_PATH_ECHO)
            && event.get("request_id").and_then(Value::as_str) == Some(root_request_id.as_str())
            && event.get("path_target_endpoint_id").and_then(Value::as_str)
                == Some(harness.target_id.to_string().as_str())
            && event.get("ok").and_then(Value::as_bool) == Some(false)
            && event.get("error_code").and_then(Value::as_str) == Some("ENDPOINT_NOT_ALLOWED")
    })
    .await;

    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_client_detects_endpoint_mismatch_before_sending_rpc() {
    skip_if_local_iroh_unavailable!();

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
    spawn_local_agent_with_peers(controller_key, agent_key, Vec::new(), dir).await
}

async fn spawn_local_agent_with_peers(
    controller_key: SecretKey,
    agent_key: SecretKey,
    peers: Vec<PeerConfig>,
    dir: &TempDir,
) -> LocalAgentHarness {
    let controller = bind_controller_endpoint_local_only(controller_key.clone())
        .await
        .expect("bind local-only controller endpoint");
    let audit_path = dir.path().join("agent-audit.jsonl");
    let mut config = test_config(
        controller_key.public(),
        audit_path.clone(),
        dir.path().join("agent.secret"),
    );
    config.security.peers = peers;
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
        authz: Arc::new(
            AgentAuthorization::from_security_config(&config.security).expect("authz table builds"),
        ),
        agent_endpoint_id: agent_id.to_string(),
        outbound_endpoint: Some(agent.clone()),
        path_target_resolver: PathTargetResolver::endpoint_id_only(),
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

async fn spawn_local_agent_with_ocserv_snapshot(
    controller_key: SecretKey,
    agent_key: SecretKey,
    dir: &TempDir,
) -> LocalAgentHarness {
    let controller = bind_controller_endpoint_local_only(controller_key.clone())
        .await
        .expect("bind local-only controller endpoint");
    let audit_path = dir.path().join("agent-audit.jsonl");
    let snapshot_path = dir.path().join("ocserv-readonly.json");
    std::fs::write(
        &snapshot_path,
        r#"{"service":{"state":"running","enabled":"enabled","since":"2026-07-07T12:00:00Z"},"version":"1.3.0","sessions":{"total":12},"collected_at":"2026-07-07T12:00:00Z"}"#,
    )
    .expect("write ocserv snapshot");
    make_private(&snapshot_path);

    let mut config = test_config(
        controller_key.public(),
        audit_path.clone(),
        dir.path().join("agent.secret"),
    );
    config.ocserv_readonly.enabled = true;
    config.ocserv_readonly.provider = OcservReadonlyProviderKind::Snapshot;
    config.ocserv_readonly.snapshot_path = Some(snapshot_path);

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
        authz: Arc::new(
            AgentAuthorization::from_security_config(&config.security).expect("authz table builds"),
        ),
        agent_endpoint_id: agent_id.to_string(),
        outbound_endpoint: Some(agent.clone()),
        path_target_resolver: PathTargetResolver::endpoint_id_only(),
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

async fn spawn_local_path_probe_agents(
    dir: &TempDir,
    source_authorizes_target: bool,
    target_allows_source: bool,
) -> LocalPathProbeHarness {
    let controller_key = SecretKey::generate();
    let source_key = SecretKey::generate();
    let target_key = SecretKey::generate();
    let controller_id = controller_key.public();
    let source_id = source_key.public();
    let controller = bind_controller_endpoint_local_only(controller_key.clone())
        .await
        .expect("bind local-only controller endpoint");

    let target_audit_path = dir.path().join("target-agent-audit.jsonl");
    let mut target_config = test_config(
        controller_id,
        target_audit_path.clone(),
        dir.path().join("target.secret"),
    );
    target_config.node.id = "target-ocserv-01".to_string();
    if target_allows_source {
        target_config.security.peers = vec![PeerConfig {
            endpoint_id: source_id.to_string(),
            enabled: true,
        }];
    }
    let target_audit = JsonlAuditWriter::new(target_audit_path.clone());
    let target_audit_limiter =
        Arc::new(Mutex::new(RejectedAuditLimiter::new(&target_config.audit)));
    let target = bind_agent_endpoint_local_only(
        &target_config,
        target_key,
        target_audit.clone(),
        target_audit_limiter.clone(),
    )
    .await
    .expect("bind local-only target endpoint");
    let target_addr = target.addr();
    let target_id = target.id();
    let target_state = AgentServerState {
        config: target_config.clone(),
        audit: target_audit,
        nonce_cache: Arc::new(Mutex::new(NonceCache::with_limits(
            target_config.security.max_live_nonces_global,
            target_config.security.max_live_nonces_per_controller,
        ))),
        limiters: Arc::new(ServerLimiters::from_config(&target_config.security)),
        audit_limiter: target_audit_limiter,
        authz: Arc::new(
            AgentAuthorization::from_security_config(&target_config.security)
                .expect("target authz table builds"),
        ),
        agent_endpoint_id: target_id.to_string(),
        outbound_endpoint: Some(target.clone()),
        path_target_resolver: PathTargetResolver::endpoint_id_only(),
    };
    let target_task = tokio::spawn(serve_endpoint(target.clone(), target_state));

    let source_audit_path = dir.path().join("source-agent-audit.jsonl");
    let mut source_config = test_config(
        controller_id,
        source_audit_path.clone(),
        dir.path().join("source.secret"),
    );
    source_config.node.id = "source-ocserv-01".to_string();
    if source_authorizes_target {
        source_config.security.path_probes = vec![PathProbeConfig {
            controller_endpoint_id: controller_id.to_string(),
            target_endpoint_id: target_id.to_string(),
            enabled: true,
        }];
    }
    let source_audit = JsonlAuditWriter::new(source_audit_path.clone());
    let source_audit_limiter =
        Arc::new(Mutex::new(RejectedAuditLimiter::new(&source_config.audit)));
    let source = bind_agent_endpoint_local_only(
        &source_config,
        source_key,
        source_audit.clone(),
        source_audit_limiter.clone(),
    )
    .await
    .expect("bind local-only source endpoint");
    let source_addr = source.addr();
    let source_id = source.id();
    let source_state = AgentServerState {
        config: source_config.clone(),
        audit: source_audit,
        nonce_cache: Arc::new(Mutex::new(NonceCache::with_limits(
            source_config.security.max_live_nonces_global,
            source_config.security.max_live_nonces_per_controller,
        ))),
        limiters: Arc::new(ServerLimiters::from_config(&source_config.security)),
        audit_limiter: source_audit_limiter,
        authz: Arc::new(
            AgentAuthorization::from_security_config(&source_config.security)
                .expect("source authz table builds"),
        ),
        agent_endpoint_id: source_id.to_string(),
        outbound_endpoint: Some(source.clone()),
        path_target_resolver: PathTargetResolver::for_local_e2e_tests([(
            target_id,
            target_addr.clone(),
        )]),
    };
    let source_task = tokio::spawn(serve_endpoint(source.clone(), source_state));

    tokio::task::yield_now().await;

    LocalPathProbeHarness {
        controller,
        source,
        target,
        source_addr,
        source_id,
        target_id,
        source_config,
        source_audit_path,
        target_audit_path,
        source_task,
        target_task,
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
            max_handshake_duration_ms: 5_000,
            max_connection_idle_ms: 5_000,
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
            peers: Vec::new(),
            path_probes: Vec::new(),
        },
        audit: AuditConfig {
            path: audit_path,
            audit_queue_capacity: 1024,
            spool_path: None,
            metrics_path: None,
            spool_max_events: 10_000,
            rejected_peer_log_burst: 10,
            rejected_peer_log_refill_per_sec: 1,
            rejected_peer_log_max_buckets: 4096,
            rejected_peer_log_bucket_ttl_seconds: 3600,
            rejected_peer_log_aggregate_interval_seconds: 60,
        },
        ocserv_readonly: Default::default(),
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

#[cfg(unix)]
fn make_private(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod private");
}

#[cfg(not(unix))]
fn make_private(_path: &Path) {}
