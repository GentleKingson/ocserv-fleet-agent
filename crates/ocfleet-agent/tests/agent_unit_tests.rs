use ocfleet_agent::identity::{load_or_create_secret_key, secret_key_file_mode_is_private};
use ocfleet_agent::{
    AGENT_VERSION,
    audit::{AgentAuditEvent, JsonlAuditWriter},
    audit_limiter::{AuditLimitDecision, RejectedAuditLimiter},
    node_info::collect_node_info,
    nonce::{NonceCache, NonceDecision, NonceLimitScope},
    server::{
        AgentServerState, ServerLimiters, bind_agent_endpoint_local_only, handle_request,
        parse_endpoint_id, read_frame,
    },
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

    assert_eq!(
        cache.register("remote-a", "nonce-1", ttl),
        NonceDecision::Accepted
    );
    assert_eq!(
        cache.register("remote-a", "nonce-1", ttl),
        NonceDecision::Replay
    );
    assert_eq!(
        cache.register("remote-b", "nonce-1", ttl),
        NonceDecision::Accepted
    );
}

#[test]
fn nonce_cache_enforces_caps_without_evicting_live_replay_entries() {
    let mut cache = NonceCache::with_limits(2, 1);
    let ttl = Duration::from_secs(60);

    assert_eq!(
        cache.register("remote-a", "nonce-1", ttl),
        NonceDecision::Accepted
    );
    assert_eq!(
        cache.register("remote-a", "nonce-1", ttl),
        NonceDecision::Replay
    );
    assert_eq!(
        cache.register("remote-a", "nonce-2", ttl),
        NonceDecision::ResourceExhausted {
            scope: NonceLimitScope::PerPeer,
            limit: 1,
        }
    );
    assert_eq!(
        cache.register("remote-b", "nonce-1", ttl),
        NonceDecision::Accepted
    );
    assert_eq!(
        cache.register("remote-c", "nonce-1", ttl),
        NonceDecision::ResourceExhausted {
            scope: NonceLimitScope::Global,
            limit: 2,
        }
    );
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

#[cfg(unix)]
#[test]
fn jsonl_audit_writer_creates_private_file_and_parent_directory() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("audit").join("agent.jsonl");
    let writer = JsonlAuditWriter::new(path.clone());

    writer
        .write(&AgentAuditEvent::new("request.completed"))
        .expect("write audit");

    let file_mode = std::fs::metadata(&path)
        .expect("audit metadata")
        .permissions()
        .mode()
        & 0o777;
    let parent_mode = std::fs::metadata(path.parent().expect("parent"))
        .expect("parent metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(file_mode, 0o600);
    assert_eq!(parent_mode, 0o700);
}

#[cfg(unix)]
#[test]
fn jsonl_audit_writer_creates_nested_parent_directories_private_under_permissive_umask() {
    use std::os::unix::fs::PermissionsExt;

    struct UmaskGuard(libc::mode_t);

    impl Drop for UmaskGuard {
        fn drop(&mut self) {
            unsafe {
                libc::umask(self.0);
            }
        }
    }

    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("logs").join("audit").join("agent.jsonl");
    let old_umask = unsafe { libc::umask(0) };
    let _guard = UmaskGuard(old_umask);
    let writer = JsonlAuditWriter::new(path);

    writer
        .write(&AgentAuditEvent::new("request.completed"))
        .expect("write audit");

    for component in [
        dir.path().join("logs"),
        dir.path().join("logs").join("audit"),
    ] {
        let mode = std::fs::metadata(&component)
            .expect("directory metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }
}

#[cfg(unix)]
#[test]
fn jsonl_audit_writer_rejects_existing_world_readable_file_without_writing() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("agent.jsonl");
    std::fs::write(&path, "existing\n").expect("write existing audit");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let writer = JsonlAuditWriter::new(path.clone());

    assert!(
        writer
            .write(&AgentAuditEvent::new("request.completed"))
            .is_err()
    );
    assert_eq!(
        std::fs::read_to_string(path).expect("audit file"),
        "existing\n"
    );
}

#[cfg(unix)]
#[test]
fn jsonl_audit_writer_rejects_final_path_symlink() {
    let dir = tempfile::tempdir().expect("temp dir");
    let real_path = dir.path().join("real.jsonl");
    let link_path = dir.path().join("agent.jsonl");
    std::fs::write(&real_path, "").expect("write real audit");
    std::os::unix::fs::symlink(&real_path, &link_path).expect("symlink");
    let writer = JsonlAuditWriter::new(link_path);

    assert!(
        writer
            .write(&AgentAuditEvent::new("request.completed"))
            .is_err()
    );
}

#[test]
fn rejected_audit_limiter_suppresses_repeated_resource_rejections_and_bounds_buckets() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = AuditConfig {
        path: dir.path().join("audit.log"),
        rejected_peer_log_burst: 1,
        rejected_peer_log_refill_per_sec: 1,
        rejected_peer_log_max_buckets: 2,
        rejected_peer_log_bucket_ttl_seconds: 3600,
        rejected_peer_log_aggregate_interval_seconds: 60,
    };
    let mut limiter = RejectedAuditLimiter::new(&config);

    assert!(matches!(
        limiter.check(Some("peer-a"), "stream", "RESOURCE_EXHAUSTED"),
        AuditLimitDecision::Write {
            suppressed_count: 0,
            ..
        }
    ));
    for _ in 0..5 {
        assert_eq!(
            limiter.check(Some("peer-a"), "stream", "RESOURCE_EXHAUSTED"),
            AuditLimitDecision::Suppress
        );
    }
    assert_eq!(
        limiter.suppressed_count_for_tests(Some("peer-a"), "stream", "RESOURCE_EXHAUSTED"),
        5
    );

    for index in 0..10 {
        let peer = format!("peer-{index}");
        let _ = limiter.check(Some(&peer), "connection", "RESOURCE_EXHAUSTED");
    }
    assert!(limiter.bucket_count_for_tests() <= 3);
    assert!(limiter.overflow_suppressed_count_for_tests() > 0);
}

#[test]
fn rejected_audit_limiter_does_not_write_aggregate_before_interval() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = AuditConfig {
        path: dir.path().join("audit.log"),
        rejected_peer_log_burst: 1,
        rejected_peer_log_refill_per_sec: 1,
        rejected_peer_log_max_buckets: 4,
        rejected_peer_log_bucket_ttl_seconds: 3600,
        rejected_peer_log_aggregate_interval_seconds: 60,
    };
    let mut limiter = RejectedAuditLimiter::new(&config);

    assert!(matches!(
        limiter.check(Some("peer-a"), "stream", "RESOURCE_EXHAUSTED"),
        AuditLimitDecision::Write { .. }
    ));
    assert_eq!(
        limiter.check(Some("peer-a"), "stream", "RESOURCE_EXHAUSTED"),
        AuditLimitDecision::Suppress
    );

    std::thread::sleep(Duration::from_millis(1100));

    assert_eq!(
        limiter.check(Some("peer-a"), "stream", "RESOURCE_EXHAUSTED"),
        AuditLimitDecision::Suppress
    );
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
    assert!(
        OffsetDateTime::parse(
            &info.current_time_utc,
            &time::format_description::well_known::Rfc3339
        )
        .is_ok()
    );
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
    let audit_limiter = std::sync::Arc::new(std::sync::Mutex::new(RejectedAuditLimiter::new(
        &config.audit,
    )));

    let endpoint = bind_agent_endpoint_local_only(&config, secret_key, audit, audit_limiter)
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
    let audit_limiter = std::sync::Arc::new(std::sync::Mutex::new(RejectedAuditLimiter::new(
        &config.audit,
    )));

    assert!(
        bind_agent_endpoint_local_only(&config, secret_key, audit, audit_limiter)
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

    let replay = handle_request(&state, "controller-1", test_rpc_request(NODE_PING, nonce)).await;
    assert_eq!(
        replay.error.as_ref().expect("error").code,
        ErrorCode::ReplayedNonce
    );
}

#[tokio::test]
async fn handle_request_returns_resource_exhausted_with_original_request_id_when_nonce_cache_full()
{
    let dir = tempfile::tempdir().expect("temp dir");
    let state = test_server_state(dir.path(), "agent-endpoint-1");
    {
        let mut cache = state.nonce_cache.lock().expect("nonce cache");
        *cache = NonceCache::with_limits(1, 1);
        assert_eq!(
            cache.register("controller-1", valid_nonce(11), Duration::from_secs(60)),
            NonceDecision::Accepted
        );
    }
    let request = test_rpc_request(NODE_PING, valid_nonce(12));
    let request_id = request.request_id.clone();

    let response = handle_request(&state, "controller-1", request).await;

    let error = response.error.as_ref().expect("error");
    assert_eq!(response.request_id.as_deref(), Some(request_id.as_str()));
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert_eq!(error.details["resource"], "nonce_cache");
}

#[tokio::test]
async fn handle_request_does_not_register_nonce_when_timestamp_invalid() {
    let dir = tempfile::tempdir().expect("temp dir");
    let state = test_server_state(dir.path(), "agent-endpoint-1");
    let mut request = test_rpc_request(NODE_PING, valid_nonce(10));
    request.issued_at = (OffsetDateTime::now_utc() + time::Duration::hours(1))
        .format(&time::format_description::well_known::Rfc3339)
        .expect("format issued_at");

    let first = handle_request(&state, "controller-1", request.clone()).await;
    let second = handle_request(&state, "controller-1", request).await;

    assert_eq!(
        first.error.as_ref().expect("error").code,
        ErrorCode::ClockSkewExceeded
    );
    assert_eq!(
        second.error.as_ref().expect("error").code,
        ErrorCode::ClockSkewExceeded
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
            max_handshake_tasks_global: 256,
            max_connections_global: 256,
            max_connections_per_controller: 32,
            max_streams_global: 1024,
            max_streams_per_controller: 128,
            max_live_nonces_global: 100_000,
            max_live_nonces_per_controller: 10_000,
            controllers,
        },
        audit: AuditConfig {
            path: dir.join("audit.log"),
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

fn test_server_state(dir: &Path, agent_endpoint_id: &str) -> AgentServerState {
    AgentServerState {
        config: test_agent_config(dir, Vec::new()),
        audit: JsonlAuditWriter::new(dir.join("audit.log")),
        nonce_cache: std::sync::Arc::new(std::sync::Mutex::new(NonceCache::with_limits(
            100_000, 10_000,
        ))),
        limiters: std::sync::Arc::new(ServerLimiters::new(256, 256, 32, 1024, 128)),
        audit_limiter: std::sync::Arc::new(std::sync::Mutex::new(RejectedAuditLimiter::new(
            &test_agent_config(dir, Vec::new()).audit,
        ))),
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
