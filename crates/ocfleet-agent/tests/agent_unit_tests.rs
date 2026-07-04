use ocfleet_agent::identity::{load_or_create_secret_key, secret_key_file_mode_is_private};
use ocfleet_agent::{
    audit::{AgentAuditEvent, JsonlAuditWriter},
    node_info::collect_node_info,
    nonce::NonceCache,
    server::{
        AgentServerState, bind_agent_endpoint_local_only, handle_request, parse_endpoint_id,
        read_frame,
    },
    AGENT_VERSION,
};
use ocfleet_config::agent::{
    AgentConfig, AuditConfig, ControllerConfig, IrohConfig, NodeConfig, SecurityConfig,
};
use ocfleet_protocol::constants::PROTOCOL_VERSION;
use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::method::{NODE_INFO, NODE_PING};
use ocfleet_protocol::rpc::RpcRequest;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::io::AsyncWriteExt;

#[test]
fn secret_key_is_created_and_reused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("iroh.secret");
    let first = load_or_create_secret_key(&path, false).expect("first key");
    let second = load_or_create_secret_key(&path, false).expect("second key");
    assert_eq!(first.to_bytes(), second.to_bytes());
}

#[cfg(unix)]
#[test]
fn secret_key_file_mode_is_private_after_create() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("iroh.secret");
    load_or_create_secret_key(&path, true).expect("key");
    assert!(secret_key_file_mode_is_private(&path).expect("mode check"));
}

#[cfg(unix)]
#[test]
fn production_mode_rejects_existing_world_readable_secret_key() {
    use base64::Engine;
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("iroh.secret");
    let key = iroh::SecretKey::generate();
    let encoded = base64::engine::general_purpose::STANDARD.encode(key.to_bytes());
    std::fs::write(&path, format!("{encoded}\n")).expect("write key");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

    let err = load_or_create_secret_key(&path, true).expect_err("world-readable key rejected");
    assert!(matches!(
        err,
        ocfleet_agent::identity::IdentityError::InvalidPermissions
    ));
}

#[test]
fn existing_invalid_secret_key_is_rejected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("iroh.secret");
    std::fs::write(&path, "not-base64\n").expect("write bad key");
    assert!(load_or_create_secret_key(&path, false).is_err());
}

#[test]
fn agent_binary_reports_config_load_context_for_missing_config() {
    let dir = tempfile::tempdir().expect("temp dir");
    let missing_config = dir.path().join("missing-agent.toml");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ocfleet-agent"))
        .arg("--config")
        .arg(&missing_config)
        .output()
        .expect("run ocfleet-agent binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to load agent config"),
        "stderr was: {stderr}"
    );
}

#[test]
fn deleting_secret_key_changes_endpoint_identity() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("iroh.secret");
    let first = load_or_create_secret_key(&path, false).expect("first key");
    std::fs::remove_file(&path).expect("remove key");
    let second = load_or_create_secret_key(&path, false).expect("second key");
    assert_ne!(first.public(), second.public());
}

#[test]
fn nonce_cache_rejects_replay_per_remote_endpoint() {
    let mut cache = NonceCache::new();
    let ttl = Duration::from_secs(60);

    assert!(cache.register("remote-a", "nonce-1", ttl));
    assert!(!cache.register("remote-a", "nonce-1", ttl));
    assert!(cache.register("remote-b", "nonce-1", ttl));
}

#[test]
fn jsonl_audit_writer_appends_lines_and_creates_parent_directory() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("audit").join("agent.jsonl");
    let writer = JsonlAuditWriter::new(path.clone());

    let mut first = AgentAuditEvent::new("request.received");
    first.request_id = Some("req-1".to_string());
    first.allowed = Some(true);
    writer.write(&first).expect("write first event");

    let mut second = AgentAuditEvent::new("request.completed");
    second.request_id = Some("req-2".to_string());
    second.ok = Some(true);
    writer.write(&second).expect("write second event");

    let text = std::fs::read_to_string(path).expect("audit file");
    assert!(text.ends_with('\n'));
    let lines = text.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2);

    let first_json: serde_json::Value = serde_json::from_str(lines[0]).expect("first json");
    let second_json: serde_json::Value = serde_json::from_str(lines[1]).expect("second json");
    assert_eq!(first_json["event"], "request.received");
    assert_eq!(first_json["request_id"], "req-1");
    assert_eq!(first_json["allowed"], true);
    assert_eq!(second_json["event"], "request.completed");
    assert_eq!(second_json["request_id"], "req-2");
    assert_eq!(second_json["ok"], true);
}

#[test]
fn collect_node_info_returns_supplied_identity_and_basic_host_metadata() {
    let info = collect_node_info(
        "node-1".to_string(),
        "hk".to_string(),
        "gateway".to_string(),
        AGENT_VERSION.to_string(),
        "endpoint-1".to_string(),
    );

    assert_eq!(info.node_id, "node-1");
    assert_eq!(info.region, "hk");
    assert_eq!(info.role, "gateway");
    assert_eq!(info.agent_version, AGENT_VERSION);
    assert_eq!(info.agent_endpoint_id, "endpoint-1");
    assert!(!info.hostname.trim().is_empty());
    assert!(!info.os_release.trim().is_empty());
    assert!(!info.kernel.trim().is_empty());
    assert!(!info.arch.trim().is_empty());
    assert!(OffsetDateTime::parse(
        &info.current_time_utc,
        &time::format_description::well_known::Rfc3339
    )
    .is_ok());
    let _: u64 = info.uptime_seconds;
}

#[test]
fn parse_endpoint_id_accepts_valid_iroh_endpoint_ids() {
    let endpoint_id = iroh::SecretKey::generate().public();

    assert_eq!(
        parse_endpoint_id(&endpoint_id.to_string()).expect("valid endpoint id"),
        endpoint_id
    );
}

#[test]
fn parse_endpoint_id_rejects_invalid_iroh_endpoint_ids() {
    assert!(parse_endpoint_id("not-an-endpoint-id").is_err());
}

#[tokio::test]
async fn local_only_endpoint_binds_only_to_ipv4_loopback() {
    let dir = tempfile::tempdir().expect("temp dir");
    let secret_key = load_or_create_secret_key(&dir.path().join("iroh.secret"), false)
        .expect("agent secret key");
    let config = test_agent_config(dir.path(), Vec::new());
    let audit = JsonlAuditWriter::new(dir.path().join("audit.log"));

    let endpoint = bind_agent_endpoint_local_only(&config, secret_key, audit)
        .await
        .expect("bind local endpoint");
    let bound_sockets = endpoint.bound_sockets();

    assert_eq!(bound_sockets.len(), 1);
    assert_eq!(bound_sockets[0].ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    endpoint.close().await;
}

#[tokio::test]
async fn endpoint_bind_rejects_invalid_allowed_controller_endpoint_id() {
    let dir = tempfile::tempdir().expect("temp dir");
    let secret_key = load_or_create_secret_key(&dir.path().join("iroh.secret"), false)
        .expect("agent secret key");
    let config = test_agent_config(
        dir.path(),
        vec![ControllerConfig {
            endpoint_id: "not-an-endpoint-id".to_string(),
            role: "viewer".to_string(),
        }],
    );
    let audit = JsonlAuditWriter::new(dir.path().join("audit.log"));

    assert!(
        bind_agent_endpoint_local_only(&config, secret_key, audit)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn read_frame_rejects_oversized_declared_length_without_reading_payload() {
    let (mut writer, mut reader) = tokio::io::duplex(64);
    writer
        .write_all(&8_u32.to_be_bytes())
        .await
        .expect("write frame length");

    let err = tokio::time::timeout(Duration::from_millis(100), read_frame(&mut reader, 4))
        .await
        .expect("read_frame returns after reading only the header")
        .expect_err("oversized frame rejected");

    assert_eq!(err.code(), ErrorCode::FrameTooLarge);
}

#[tokio::test]
async fn handle_request_classifies_phase_one_methods() {
    let dir = tempfile::tempdir().expect("temp dir");
    let state = test_server_state(dir.path(), "agent-endpoint-1");

    let ping = handle_request(
        &state,
        "controller-1",
        test_rpc_request(NODE_PING, valid_nonce(1)),
    )
    .await;
    assert!(ping.ok);
    assert_eq!(ping.result.as_ref().expect("result")["message"], "pong");

    let info = handle_request(
        &state,
        "controller-1",
        test_rpc_request(NODE_INFO, valid_nonce(2)),
    )
    .await;
    assert!(info.ok);
    assert_eq!(
        info.result.as_ref().expect("result")["agent_endpoint_id"],
        "agent-endpoint-1"
    );

    let denied = handle_request(
        &state,
        "controller-1",
        test_rpc_request("ocserv.status", valid_nonce(3)),
    )
    .await;
    assert_eq!(
        denied.error.as_ref().expect("error").code,
        ErrorCode::MethodNotAllowed
    );

    let denied_by_prefix = handle_request(
        &state,
        "controller-1",
        test_rpc_request("ocserv.future.method", valid_nonce(4)),
    )
    .await;
    assert_eq!(
        denied_by_prefix.error.as_ref().expect("error").code,
        ErrorCode::MethodNotAllowed
    );

    let unknown = handle_request(
        &state,
        "controller-1",
        test_rpc_request("shell.exec", valid_nonce(9)),
    )
    .await;
    assert_eq!(
        unknown.error.as_ref().expect("error").code,
        ErrorCode::MethodNotFound
    );
}

#[tokio::test]
async fn handle_request_rejects_non_null_auth() {
    let dir = tempfile::tempdir().expect("temp dir");
    let state = test_server_state(dir.path(), "agent-endpoint-1");
    let mut request = test_rpc_request(NODE_PING, valid_nonce(5));
    request.auth = Some(json!({"scheme": "bearer", "token": "not-supported"}));

    let response = handle_request(&state, "controller-1", request).await;

    assert_eq!(
        response.error.as_ref().expect("error").code,
        ErrorCode::UnsupportedAuthScheme
    );
}

#[tokio::test]
async fn handle_request_rejects_replayed_nonce_per_remote_endpoint() {
    let dir = tempfile::tempdir().expect("temp dir");
    let state = test_server_state(dir.path(), "agent-endpoint-1");
    let nonce = valid_nonce(6);

    let first = handle_request(
        &state,
        "controller-1",
        test_rpc_request(NODE_PING, nonce.clone()),
    )
    .await;
    assert!(first.ok);

    let replay = handle_request(
        &state,
        "controller-1",
        test_rpc_request(NODE_PING, nonce),
    )
    .await;
    assert_eq!(
        replay.error.as_ref().expect("error").code,
        ErrorCode::ReplayedNonce
    );
}

#[tokio::test]
async fn handle_request_rejects_invalid_and_too_large_deadlines() {
    let dir = tempfile::tempdir().expect("temp dir");
    let state = test_server_state(dir.path(), "agent-endpoint-1");

    let mut zero = test_rpc_request(NODE_PING, valid_nonce(7));
    zero.deadline_ms = 0;
    let zero_response = handle_request(&state, "controller-1", zero).await;
    assert_eq!(
        zero_response.error.as_ref().expect("error").code,
        ErrorCode::InvalidDeadline
    );

    let mut too_large = test_rpc_request(NODE_PING, valid_nonce(8));
    too_large.deadline_ms = state.config.security.max_deadline_ms + 1;
    let too_large_response = handle_request(&state, "controller-1", too_large).await;
    assert_eq!(
        too_large_response.error.as_ref().expect("error").code,
        ErrorCode::InvalidDeadline
    );
}

fn test_agent_config(dir: &Path, controllers: Vec<ControllerConfig>) -> AgentConfig {
    AgentConfig {
        node: NodeConfig {
            id: "agent-1".to_string(),
            region: "hk".to_string(),
            role: "ocserv".to_string(),
        },
        iroh: IrohConfig {
            secret_key_path: dir.join("iroh.secret"),
            alpn: "/com.github.gentlekingson.ocfleet.mgmt/1".to_string(),
        },
        security: SecurityConfig {
            allowed_clock_skew_seconds: 60,
            default_deadline_ms: 5_000,
            max_deadline_ms: 10_000,
            max_rpc_timeout_ms: 5_000,
            max_request_bytes: 65_536,
            max_response_bytes: 2_097_152,
            controllers,
        },
        audit: AuditConfig {
            path: dir.join("audit.log"),
        },
        ocserv: None,
        logs: None,
    }
}

fn test_server_state(dir: &Path, agent_endpoint_id: &str) -> AgentServerState {
    AgentServerState {
        config: test_agent_config(dir, Vec::new()),
        audit: JsonlAuditWriter::new(dir.join("audit.log")),
        nonce_cache: std::sync::Arc::new(std::sync::Mutex::new(NonceCache::new())),
        agent_endpoint_id: agent_endpoint_id.to_string(),
    }
}

fn test_rpc_request(method: &str, nonce: String) -> RpcRequest {
    RpcRequest {
        version: PROTOCOL_VERSION,
        request_id: "00000000-0000-4000-8000-000000000001".to_string(),
        method: method.to_string(),
        params: json!({}),
        issued_at: OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .expect("format issued_at"),
        nonce,
        deadline_ms: 5_000,
        actor: Some("test-actor".to_string()),
        auth: None,
    }
}

fn valid_nonce(byte: u8) -> String {
    use base64::Engine;

    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([byte; 16])
}
