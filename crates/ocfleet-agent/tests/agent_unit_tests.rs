use ocfleet_agent::identity::{load_or_create_secret_key, secret_key_file_mode_is_private};
use ocfleet_agent::{
    AGENT_VERSION,
    audit::{AgentAuditEvent, JsonlAuditWriter},
    audit_limiter::{AuditLimitDecision, RejectedAuditLimiter},
    authz::{AgentAuthorization, CallerClass, PathProbeDecision},
    enrollment::{AgentEnrollment, AgentEnrollmentStateExt},
    node_info::collect_node_info,
    nonce::{NonceCache, NonceDecision, NonceLimitScope},
    server::{
        AgentServerState, PathTargetResolver, ServerLimiters, bind_agent_endpoint_local_only,
        handle_request, parse_endpoint_id, read_frame,
    },
};
use ocfleet_config::agent::{
    AgentConfig, AuditConfig, ControllerConfig, IrohConfig, NodeConfig, OcservReadonlyProviderKind,
    PathProbeConfig, PeerConfig, SecurityConfig,
};
use ocfleet_protocol::constants::PROTOCOL_VERSION;
use ocfleet_protocol::enrollment::{EndpointStatus, TrustBundle};
use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::method::{
    NODE_INFO, NODE_PING, OCSERV_CERT_EXPIRY, OCSERV_CONFIG_FINGERPRINT, OCSERV_SERVICE_SUMMARY,
    OCSERV_SESSIONS_SUMMARY, OCSERV_VERSION, PROBE_CONTROLLER_PING, PROBE_PATH_ECHO,
    PROBE_PEER_ECHO,
};
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
fn agent_binary_reports_version() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ocfleet-agent"))
        .arg("--version")
        .output()
        .expect("run ocfleet-agent binary");

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ocfleet-agent"), "stdout was: {stdout}");
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
    const CHILD_ENV: &str = "OCFLEET_AGENT_UMASK_CHILD";

    if std::env::var_os(CHILD_ENV).is_some() {
        jsonl_audit_writer_creates_nested_parent_directories_private_under_permissive_umask_child();
        return;
    }

    let output = std::process::Command::new(std::env::current_exe().expect("current test binary"))
        .arg("jsonl_audit_writer_creates_nested_parent_directories_private_under_permissive_umask")
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_ENV, "1")
        .output()
        .expect("run umask child test");
    assert!(
        output.status.success(),
        "umask child failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
fn jsonl_audit_writer_creates_nested_parent_directories_private_under_permissive_umask_child() {
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

    writer
        .write(&AgentAuditEvent::new("request.completed"))
        .expect("unsafe primary path falls back to durable spool");
    assert_eq!(
        std::fs::read_to_string(&path).expect("audit file"),
        "existing\n"
    );
    assert!(
        std::fs::read_to_string(dir.path().join("agent.jsonl.spool.jsonl"))
            .expect("spool file")
            .contains("request.completed")
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
    let writer = JsonlAuditWriter::new(link_path.clone());

    writer
        .write(&AgentAuditEvent::new("request.completed"))
        .expect("symlink primary path falls back to durable spool");
    assert_eq!(std::fs::read_to_string(real_path).expect("real audit"), "");
    assert!(
        std::fs::read_to_string(dir.path().join("agent.jsonl.spool.jsonl"))
            .expect("spool file")
            .contains("request.completed")
    );
}

#[cfg(unix)]
#[test]
fn private_file_reader_rejects_hardlinked_private_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("iroh.secret");
    let hardlink = dir.path().join("iroh-hardlink.secret");
    std::fs::write(&path, "secret\n").expect("write private file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    std::fs::hard_link(&path, &hardlink).expect("create hardlink");

    let err = ocfleet_agent::private_file::open_existing_private_read(&path)
        .expect_err("hardlinked private file must be rejected");

    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn rejected_audit_limiter_suppresses_repeated_resource_rejections_and_bounds_buckets() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = AuditConfig {
        path: dir.path().join("audit.log"),
        audit_queue_capacity: 1024,
        spool_path: None,
        metrics_path: None,
        spool_max_events: 10_000,
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
        audit_queue_capacity: 1024,
        spool_path: None,
        metrics_path: None,
        spool_max_events: 10_000,
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
fn collect_node_info_returns_supplied_identity_and_runtime_fields() {
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
    assert!(
        OffsetDateTime::parse(
            &info.current_time_utc,
            &time::format_description::well_known::Rfc3339
        )
        .is_ok()
    );
}

#[test]
fn node_info_schema_contains_only_phase_one_approved_fields() {
    let info = collect_node_info(
        "node-1".to_string(),
        "hk".to_string(),
        "gateway".to_string(),
        AGENT_VERSION.to_string(),
        "endpoint-1".to_string(),
    );

    let value = serde_json::to_value(info).expect("node info json");
    let object = value.as_object().expect("node info object");
    let mut fields = object.keys().map(String::as_str).collect::<Vec<_>>();
    fields.sort_unstable();

    assert_eq!(
        fields,
        vec![
            "agent_endpoint_id",
            "agent_version",
            "current_time_utc",
            "node_id",
            "region",
            "role"
        ]
    );
}

#[test]
fn production_source_does_not_use_process_command_for_phase_one_rpc() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_dir = manifest_dir.join("src");
    let mut violations = Vec::new();

    collect_production_command_violations(&src_dir, &mut violations);

    assert!(
        violations.is_empty(),
        "production command execution boundary violations: {violations:?}"
    );
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

#[test]
fn authorization_derives_caller_class_from_local_config_only() {
    let dir = tempfile::tempdir().expect("temp dir");
    let controller_id = iroh::SecretKey::generate().public();
    let peer_id = iroh::SecretKey::generate().public();
    let disabled_peer_id = iroh::SecretKey::generate().public();
    let unknown_id = iroh::SecretKey::generate().public();
    let mut config = test_agent_config(
        dir.path(),
        vec![ControllerConfig {
            endpoint_id: controller_id.to_string(),
            role: "viewer".to_string(),
        }],
    );
    config.security.peers = vec![
        PeerConfig {
            endpoint_id: peer_id.to_string(),
            enabled: true,
        },
        PeerConfig {
            endpoint_id: disabled_peer_id.to_string(),
            enabled: false,
        },
    ];

    let authz = AgentAuthorization::from_security_config(&config.security)
        .expect("authorization table builds");

    assert_eq!(authz.classify(&controller_id), CallerClass::Controller);
    assert_eq!(authz.classify(&peer_id), CallerClass::Peer);
    assert_eq!(authz.classify(&disabled_peer_id), CallerClass::DisabledPeer);
    assert_eq!(authz.classify(&unknown_id), CallerClass::Unknown);
}

#[test]
fn authorization_enforces_caller_aware_method_matrix() {
    assert!(AgentAuthorization::method_allowed(
        CallerClass::Controller,
        NODE_PING
    ));
    assert!(AgentAuthorization::method_allowed(
        CallerClass::Controller,
        NODE_INFO
    ));
    assert!(AgentAuthorization::method_allowed(
        CallerClass::Controller,
        PROBE_CONTROLLER_PING
    ));
    assert!(AgentAuthorization::method_allowed(
        CallerClass::Controller,
        PROBE_PATH_ECHO
    ));
    for method in [
        OCSERV_SERVICE_SUMMARY,
        OCSERV_VERSION,
        OCSERV_SESSIONS_SUMMARY,
        OCSERV_CERT_EXPIRY,
        OCSERV_CONFIG_FINGERPRINT,
    ] {
        assert!(
            AgentAuthorization::method_allowed(CallerClass::Controller, method),
            "controller must be allowed to call fixed ocserv method {method}"
        );
    }
    assert!(!AgentAuthorization::method_allowed(
        CallerClass::Controller,
        PROBE_PEER_ECHO
    ));

    assert!(AgentAuthorization::method_allowed(
        CallerClass::Peer,
        PROBE_PEER_ECHO
    ));
    for method in [
        NODE_PING,
        NODE_INFO,
        PROBE_CONTROLLER_PING,
        PROBE_PATH_ECHO,
        OCSERV_SERVICE_SUMMARY,
        OCSERV_VERSION,
        OCSERV_SESSIONS_SUMMARY,
        OCSERV_CERT_EXPIRY,
        OCSERV_CONFIG_FINGERPRINT,
    ] {
        assert!(
            !AgentAuthorization::method_allowed(CallerClass::Peer, method),
            "peer caller must not call {method}"
        );
    }

    for caller in [CallerClass::DisabledPeer, CallerClass::Unknown] {
        for method in [
            NODE_PING,
            NODE_INFO,
            PROBE_CONTROLLER_PING,
            PROBE_PEER_ECHO,
            PROBE_PATH_ECHO,
            "relay.forward",
            "mesh.status",
            "probe.path.echo",
            "shell.exec",
            "command.run",
        ] {
            assert!(
                !AgentAuthorization::method_allowed(caller, method),
                "{caller:?} must not call {method}"
            );
        }
    }
}

#[test]
fn authorization_enforces_source_side_path_probe_allowlist() {
    let dir = tempfile::tempdir().expect("temp dir");
    let controller_id = iroh::SecretKey::generate().public();
    let allowed_target_id = iroh::SecretKey::generate().public();
    let disabled_target_id = iroh::SecretKey::generate().public();
    let unknown_target_id = iroh::SecretKey::generate().public();
    let source_id = iroh::SecretKey::generate().public();
    let mut config = test_agent_config(
        dir.path(),
        vec![ControllerConfig {
            endpoint_id: controller_id.to_string(),
            role: "viewer".to_string(),
        }],
    );
    config.security.path_probes = vec![
        PathProbeConfig {
            controller_endpoint_id: controller_id.to_string(),
            target_endpoint_id: allowed_target_id.to_string(),
            enabled: true,
        },
        PathProbeConfig {
            controller_endpoint_id: controller_id.to_string(),
            target_endpoint_id: disabled_target_id.to_string(),
            enabled: false,
        },
    ];
    config.security.peers = vec![
        PeerConfig {
            endpoint_id: allowed_target_id.to_string(),
            enabled: true,
        },
        PeerConfig {
            endpoint_id: disabled_target_id.to_string(),
            enabled: true,
        },
    ];

    let authz = AgentAuthorization::from_security_config(&config.security)
        .expect("authorization table builds");

    assert_eq!(
        authz.path_probe_decision(&controller_id, &allowed_target_id, &source_id),
        PathProbeDecision::Allowed
    );
    assert_eq!(
        authz.path_probe_decision(&controller_id, &disabled_target_id, &source_id),
        PathProbeDecision::Disabled
    );
    assert_eq!(
        authz.path_probe_decision(&controller_id, &unknown_target_id, &source_id),
        PathProbeDecision::Missing
    );
    assert_eq!(
        authz.path_probe_decision(&controller_id, &source_id, &source_id),
        PathProbeDecision::SelfTarget
    );
}

#[test]
fn authorization_rejects_path_probe_when_target_is_not_enabled_peer() {
    let dir = tempfile::tempdir().expect("temp dir");
    let controller_id = iroh::SecretKey::generate().public();
    let missing_peer_id = iroh::SecretKey::generate().public();
    let disabled_peer_id = iroh::SecretKey::generate().public();
    let source_id = iroh::SecretKey::generate().public();
    let mut config = test_agent_config(
        dir.path(),
        vec![ControllerConfig {
            endpoint_id: controller_id.to_string(),
            role: "viewer".to_string(),
        }],
    );
    config.security.peers = vec![PeerConfig {
        endpoint_id: disabled_peer_id.to_string(),
        enabled: false,
    }];
    config.security.path_probes = vec![
        PathProbeConfig {
            controller_endpoint_id: controller_id.to_string(),
            target_endpoint_id: missing_peer_id.to_string(),
            enabled: true,
        },
        PathProbeConfig {
            controller_endpoint_id: controller_id.to_string(),
            target_endpoint_id: disabled_peer_id.to_string(),
            enabled: true,
        },
    ];

    let authz = AgentAuthorization::from_security_config(&config.security)
        .expect("authorization table builds");

    assert_eq!(
        authz.path_probe_decision(&controller_id, &missing_peer_id, &source_id),
        PathProbeDecision::Missing
    );
    assert_eq!(
        authz.path_probe_decision(&controller_id, &disabled_peer_id, &source_id),
        PathProbeDecision::Missing
    );
}

#[test]
fn authorization_rejects_path_probe_target_that_is_controller() {
    let dir = tempfile::tempdir().expect("temp dir");
    let controller_id = iroh::SecretKey::generate().public();
    let target_controller_id = iroh::SecretKey::generate().public();
    let source_id = iroh::SecretKey::generate().public();
    let mut config = test_agent_config(
        dir.path(),
        vec![
            ControllerConfig {
                endpoint_id: controller_id.to_string(),
                role: "viewer".to_string(),
            },
            ControllerConfig {
                endpoint_id: target_controller_id.to_string(),
                role: "viewer".to_string(),
            },
        ],
    );
    config.security.path_probes = vec![PathProbeConfig {
        controller_endpoint_id: controller_id.to_string(),
        target_endpoint_id: target_controller_id.to_string(),
        enabled: true,
    }];

    let authz = AgentAuthorization::from_security_config(&config.security)
        .expect("authorization table builds");

    assert_eq!(
        authz.path_probe_decision(&controller_id, &target_controller_id, &source_id),
        PathProbeDecision::TargetIsController
    );
}

#[test]
fn pending_enrollment_state_does_not_grant_runtime_trust() {
    let dir = tempfile::tempdir().expect("temp dir");
    let state_path = dir.path().join("enrollment-state.json");

    let state = AgentEnrollment::load_or_create_pending(&state_path, "join-request-1", "token-1")
        .expect("pending state written");

    assert!(state.is_pending());
    assert!(!state.is_active());

    let config = test_agent_config(dir.path(), Vec::new());
    let authz =
        AgentAuthorization::from_security_config(&config.security).expect("empty authz builds");
    let unknown = iroh::SecretKey::generate().public();

    assert_eq!(authz.classify(&unknown), CallerClass::Unknown);
    assert!(!authz.is_connection_admitted(&unknown));
}

#[test]
fn approved_enrollment_state_persists_trust_bundle() {
    let dir = tempfile::tempdir().expect("temp dir");
    let state_path = dir.path().join("enrollment-state.json");
    let bundle = TrustBundle {
        endpoint_id: "endpoint-active".to_string(),
        generation: 3,
        status: EndpointStatus::Active,
        trusted_controllers: vec!["controller-one".to_string()],
        trusted_peers: vec!["peer-one".to_string()],
        authorized_path_probes: vec![("controller-one".to_string(), "peer-one".to_string())],
    };

    let state =
        AgentEnrollment::activate(&state_path, bundle.clone()).expect("active state written");
    let loaded = AgentEnrollment::load(&state_path).expect("active state loaded");

    assert!(state.is_active());
    assert_eq!(loaded.trust_bundle(), Some(&bundle));
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

    let endpoint =
        match bind_agent_endpoint_local_only(&config, secret_key, audit, audit_limiter).await {
            Ok(endpoint) => endpoint,
            Err(err) if is_restricted_netmon_environment(&err) => {
                eprintln!("skipping local endpoint bind assertion: {err:#}");
                return;
            }
            Err(err) => panic!("bind local endpoint: {err:#}"),
        };
    let bound_sockets = endpoint.bound_sockets();

    assert_eq!(bound_sockets.len(), 1);
    assert_eq!(bound_sockets[0].ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    endpoint.close().await;
}

fn is_restricted_netmon_environment(err: &anyhow::Error) -> bool {
    let message = format!("{err:#}");
    message.contains("Failed to create netmon monitor")
        && message.contains("Operation not permitted")
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
    let controller = test_controller_remote(&state);

    let ping = handle_request(
        &state,
        &controller,
        test_rpc_request(NODE_PING, valid_nonce(1)),
    )
    .await;
    assert!(ping.ok);
    assert_eq!(ping.result.as_ref().expect("result")["message"], "pong");

    let info = handle_request(
        &state,
        &controller,
        test_rpc_request(NODE_INFO, valid_nonce(2)),
    )
    .await;
    assert!(info.ok);
    assert_eq!(
        info.result.as_ref().expect("result")["agent_endpoint_id"],
        "agent-endpoint-1"
    );

    let probe = handle_request(
        &state,
        &controller,
        test_rpc_request(PROBE_CONTROLLER_PING, valid_nonce(13)),
    )
    .await;
    assert!(probe.ok);
    let probe_result = probe.result.as_ref().expect("probe result");
    assert_eq!(probe_result["message"], "pong");
    assert_eq!(probe_result["probe"], "controller.ping");
    assert_eq!(probe_result["node_id"], "agent-1");
    assert_eq!(probe_result["agent_version"], AGENT_VERSION);
    assert_eq!(probe_result["agent_endpoint_id"], "agent-endpoint-1");
    assert!(
        OffsetDateTime::parse(
            probe_result["time_utc"]
                .as_str()
                .expect("probe time string"),
            &time::format_description::well_known::Rfc3339
        )
        .is_ok()
    );
    let mut probe_fields = probe_result
        .as_object()
        .expect("probe result object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    probe_fields.sort_unstable();
    assert_eq!(
        probe_fields,
        vec![
            "agent_endpoint_id",
            "agent_version",
            "message",
            "node_id",
            "probe",
            "time_utc"
        ]
    );

    let denied = handle_request(
        &state,
        &controller,
        test_rpc_request("ocserv.status", valid_nonce(3)),
    )
    .await;
    assert_eq!(
        denied.error.as_ref().expect("error").code,
        ErrorCode::MethodNotAllowed
    );

    let denied_by_prefix = handle_request(
        &state,
        &controller,
        test_rpc_request("ocserv.future.method", valid_nonce(4)),
    )
    .await;
    assert_eq!(
        denied_by_prefix.error.as_ref().expect("error").code,
        ErrorCode::MethodNotAllowed
    );

    let unknown = handle_request(
        &state,
        &controller,
        test_rpc_request("shell.exec", valid_nonce(9)),
    )
    .await;
    assert_eq!(
        unknown.error.as_ref().expect("error").code,
        ErrorCode::MethodNotFound
    );

    for (index, method) in ["command.run", "occtl.raw", "journalctl.raw"]
        .iter()
        .enumerate()
    {
        let response = handle_request(
            &state,
            &controller,
            test_rpc_request(method, valid_nonce(10 + index as u8)),
        )
        .await;
        assert_eq!(
            response.error.as_ref().expect("error").code,
            ErrorCode::MethodNotFound,
            "{method} must not dispatch in phase 1"
        );
    }
}

#[tokio::test]
async fn handle_request_ocserv_readonly_disabled_by_default() {
    let dir = tempfile::tempdir().expect("temp dir");
    let state = test_server_state(dir.path(), "agent-endpoint-1");
    let controller = test_controller_remote(&state);

    let response = handle_request(
        &state,
        &controller,
        test_rpc_request(OCSERV_SERVICE_SUMMARY, valid_nonce(31)),
    )
    .await;

    assert!(!response.ok);
    assert_eq!(
        response.error.as_ref().expect("error").code,
        ErrorCode::OcservReadonlyDisabled
    );
}

#[tokio::test]
async fn handle_request_accepts_fixed_ocserv_readonly_methods_from_controller() {
    let dir = tempfile::tempdir().expect("temp dir");
    let snapshot_path = dir.path().join("ocserv-readonly.json");
    std::fs::write(
        &snapshot_path,
        r#"{"service":{"state":"running","enabled":"enabled","since":"2026-07-07T12:00:00Z"},"version":"1.3.0","sessions":{"total":12}}"#,
    )
    .expect("write snapshot");
    make_private(&snapshot_path);

    let mut config = test_agent_config(
        dir.path(),
        vec![ControllerConfig {
            endpoint_id: iroh::SecretKey::generate().public().to_string(),
            role: "viewer".to_string(),
        }],
    );
    config.ocserv_readonly.enabled = true;
    config.ocserv_readonly.provider = OcservReadonlyProviderKind::Snapshot;
    config.ocserv_readonly.snapshot_path = Some(snapshot_path);
    let state = test_server_state_from_config(config, "agent-endpoint-1");
    let controller = test_controller_remote(&state);

    let service = handle_request(
        &state,
        &controller,
        test_rpc_request(OCSERV_SERVICE_SUMMARY, valid_nonce(32)),
    )
    .await;
    assert!(service.ok, "{service:#?}");
    assert_eq!(
        service.result.as_ref().expect("service result")["service"]["state"],
        "running"
    );

    let version = handle_request(
        &state,
        &controller,
        test_rpc_request(OCSERV_VERSION, valid_nonce(33)),
    )
    .await;
    assert!(version.ok, "{version:#?}");
    assert_eq!(
        version.result.as_ref().expect("version result")["version"],
        "1.3.0"
    );

    let sessions = handle_request(
        &state,
        &controller,
        test_rpc_request(OCSERV_SESSIONS_SUMMARY, valid_nonce(34)),
    )
    .await;
    assert!(sessions.ok, "{sessions:#?}");
    assert_eq!(
        sessions.result.as_ref().expect("sessions result")["sessions"]["total"],
        12
    );
}

#[tokio::test]
async fn handle_request_rejects_ocserv_readonly_params_with_controller_supplied_sources() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut config = test_agent_config(
        dir.path(),
        vec![ControllerConfig {
            endpoint_id: iroh::SecretKey::generate().public().to_string(),
            role: "viewer".to_string(),
        }],
    );
    config.ocserv_readonly.enabled = true;
    config.ocserv_readonly.provider = OcservReadonlyProviderKind::Snapshot;
    config.ocserv_readonly.snapshot_path = Some(dir.path().join("ocserv-readonly.json"));
    let state = test_server_state_from_config(config, "agent-endpoint-1");
    let controller = test_controller_remote(&state);

    for (index, params) in [
        json!({"path": "/etc/ocserv/ocserv.conf"}),
        json!({"command": "systemctl status ocserv"}),
        json!({"unit": "ssh.service"}),
        json!({"journal": "ocserv"}),
        json!({"service": "ocserv"}),
    ]
    .into_iter()
    .enumerate()
    {
        let mut request =
            test_rpc_request(OCSERV_CONFIG_FINGERPRINT, valid_nonce(40 + index as u8));
        request.params = params;
        let response = handle_request(&state, &controller, request).await;
        assert_eq!(
            response.error.as_ref().expect("error").code,
            ErrorCode::ParamsInvalid
        );
    }
}

#[tokio::test]
async fn handle_request_allows_enabled_peer_echo() {
    let dir = tempfile::tempdir().expect("temp dir");
    let peer_id = iroh::SecretKey::generate().public();
    let mut config = test_agent_config(dir.path(), Vec::new());
    config.security.peers = vec![PeerConfig {
        endpoint_id: peer_id.to_string(),
        enabled: true,
    }];
    let state = test_server_state_from_config(config, "agent-endpoint-1");

    let response = handle_request(
        &state,
        &peer_id.to_string(),
        test_rpc_request(PROBE_PEER_ECHO, valid_nonce(17)),
    )
    .await;

    assert!(response.ok, "{response:#?}");
    let result = response.result.as_ref().expect("peer echo result");
    assert_eq!(result["message"], "pong");
    assert_eq!(result["probe"], "peer.echo");
    assert_eq!(result["source_agent_endpoint_id"], peer_id.to_string());
    assert_eq!(result["target_agent_endpoint_id"], "agent-endpoint-1");
    assert_eq!(result["target_node_id"], "agent-1");
    assert_eq!(result["agent_version"], AGENT_VERSION);
    assert!(
        OffsetDateTime::parse(
            result["time_utc"].as_str().expect("peer echo time"),
            &time::format_description::well_known::Rfc3339
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
}

#[tokio::test]
async fn handle_request_rejects_controller_calling_peer_echo() {
    let dir = tempfile::tempdir().expect("temp dir");
    let controller_id = iroh::SecretKey::generate().public();
    let config = test_agent_config(
        dir.path(),
        vec![ControllerConfig {
            endpoint_id: controller_id.to_string(),
            role: "viewer".to_string(),
        }],
    );
    let state = test_server_state_from_config(config, "agent-endpoint-1");

    let response = handle_request(
        &state,
        &controller_id.to_string(),
        test_rpc_request(PROBE_PEER_ECHO, valid_nonce(18)),
    )
    .await;

    assert!(!response.ok);
    assert_eq!(
        response.error.as_ref().expect("error").code,
        ErrorCode::MethodNotAllowed
    );
}

#[tokio::test]
async fn handle_request_rejects_peer_calling_controller_method() {
    let dir = tempfile::tempdir().expect("temp dir");
    let peer_id = iroh::SecretKey::generate().public();
    let mut config = test_agent_config(dir.path(), Vec::new());
    config.security.peers = vec![PeerConfig {
        endpoint_id: peer_id.to_string(),
        enabled: true,
    }];
    let state = test_server_state_from_config(config, "agent-endpoint-1");

    let response = handle_request(
        &state,
        &peer_id.to_string(),
        test_rpc_request(NODE_PING, valid_nonce(19)),
    )
    .await;

    assert!(!response.ok);
    assert_eq!(
        response.error.as_ref().expect("error").code,
        ErrorCode::MethodNotAllowed
    );
}

#[tokio::test]
async fn handle_request_rejects_peer_calling_path_echo() {
    let dir = tempfile::tempdir().expect("temp dir");
    let peer_id = iroh::SecretKey::generate().public();
    let target_id = iroh::SecretKey::generate().public();
    let mut config = test_agent_config(dir.path(), Vec::new());
    config.security.peers = vec![PeerConfig {
        endpoint_id: peer_id.to_string(),
        enabled: true,
    }];
    let state = test_server_state_from_config(config, "agent-endpoint-1");
    let mut request = test_rpc_request(PROBE_PATH_ECHO, valid_nonce(22));
    request.params = json!({"target_agent_endpoint_id": target_id.to_string()});

    let response = handle_request(&state, &peer_id.to_string(), request).await;

    assert!(!response.ok);
    assert_eq!(
        response.error.as_ref().expect("error").code,
        ErrorCode::MethodNotAllowed
    );
}

#[tokio::test]
async fn handle_request_rejects_path_echo_without_source_authorization_before_outbound_endpoint() {
    let dir = tempfile::tempdir().expect("temp dir");
    let controller_id = iroh::SecretKey::generate().public();
    let target_id = iroh::SecretKey::generate().public();
    let source_id = iroh::SecretKey::generate().public();
    let config = test_agent_config(
        dir.path(),
        vec![ControllerConfig {
            endpoint_id: controller_id.to_string(),
            role: "viewer".to_string(),
        }],
    );
    let state = test_server_state_from_config(config, &source_id.to_string());
    let mut request = test_rpc_request(PROBE_PATH_ECHO, valid_nonce(23));
    request.params = json!({"target_agent_endpoint_id": target_id.to_string()});

    let response = handle_request(&state, &controller_id.to_string(), request).await;

    assert!(!response.ok);
    assert_eq!(
        response.error.as_ref().expect("error").code,
        ErrorCode::EndpointNotAllowed
    );
}

#[tokio::test]
async fn handle_request_rejects_path_echo_self_target_before_outbound_endpoint() {
    let dir = tempfile::tempdir().expect("temp dir");
    let controller_id = iroh::SecretKey::generate().public();
    let source_id = iroh::SecretKey::generate().public();
    let mut config = test_agent_config(
        dir.path(),
        vec![ControllerConfig {
            endpoint_id: controller_id.to_string(),
            role: "viewer".to_string(),
        }],
    );
    config.security.path_probes = vec![PathProbeConfig {
        controller_endpoint_id: controller_id.to_string(),
        target_endpoint_id: source_id.to_string(),
        enabled: true,
    }];
    let state = test_server_state_from_config(config, &source_id.to_string());
    let mut request = test_rpc_request(PROBE_PATH_ECHO, valid_nonce(24));
    request.params = json!({"target_agent_endpoint_id": source_id.to_string()});

    let response = handle_request(&state, &controller_id.to_string(), request).await;

    assert!(!response.ok);
    assert_eq!(
        response.error.as_ref().expect("error").code,
        ErrorCode::ParamsInvalid
    );
}

#[tokio::test]
async fn handle_request_rejects_path_echo_extension_params() {
    let dir = tempfile::tempdir().expect("temp dir");
    let state = test_server_state(dir.path(), "agent-endpoint-1");
    let controller = test_controller_remote(&state);
    let target_id = iroh::SecretKey::generate().public();
    let mut request = test_rpc_request(PROBE_PATH_ECHO, valid_nonce(25));
    request.params = json!({
        "target_agent_endpoint_id": target_id.to_string(),
        "host": "127.0.0.1"
    });

    let response = handle_request(&state, &controller, request).await;

    assert_eq!(
        response.error.as_ref().expect("error").code,
        ErrorCode::ParamsInvalid
    );
}

#[tokio::test]
async fn handle_request_rejects_peer_echo_extension_params() {
    let dir = tempfile::tempdir().expect("temp dir");
    let peer_id = iroh::SecretKey::generate().public();
    let mut config = test_agent_config(dir.path(), Vec::new());
    config.security.peers = vec![PeerConfig {
        endpoint_id: peer_id.to_string(),
        enabled: true,
    }];
    let state = test_server_state_from_config(config, "agent-endpoint-1");
    let mut request = test_rpc_request(PROBE_PEER_ECHO, valid_nonce(20));
    request.params = json!({"payload": "x"});

    let response = handle_request(&state, &peer_id.to_string(), request).await;

    assert_eq!(
        response.error.as_ref().expect("error").code,
        ErrorCode::ParamsInvalid
    );
}

#[tokio::test]
async fn handle_request_rejects_controller_probe_ping_extension_params() {
    let dir = tempfile::tempdir().expect("temp dir");
    let state = test_server_state(dir.path(), "agent-endpoint-1");
    let controller = test_controller_remote(&state);
    let mut request = test_rpc_request(PROBE_CONTROLLER_PING, valid_nonce(15));
    request.params = json!({"payload": "x"});

    let response = handle_request(&state, &controller, request).await;

    assert_eq!(
        response.error.as_ref().expect("error").code,
        ErrorCode::ParamsInvalid
    );
}

#[tokio::test]
async fn handle_request_does_not_dispatch_future_direction_two_methods() {
    let dir = tempfile::tempdir().expect("temp dir");
    let state = test_server_state(dir.path(), "agent-endpoint-1");
    let controller = test_controller_remote(&state);

    for (index, method) in ["probe.peer.echo", "relay.forward", "mesh.status"]
        .iter()
        .enumerate()
    {
        let response = handle_request(
            &state,
            &controller,
            test_rpc_request(method, valid_nonce(16 + index as u8)),
        )
        .await;
        assert!(!response.ok, "{method} must not dispatch");
    }
}

#[tokio::test]
async fn handle_request_rejects_node_info_params_that_name_local_capabilities() {
    let dir = tempfile::tempdir().expect("temp dir");
    let state = test_server_state(dir.path(), "agent-endpoint-1");
    let controller = test_controller_remote(&state);
    let mut request = test_rpc_request(NODE_INFO, valid_nonce(14));
    request.params = json!({
        "path": "/etc/os-release",
        "command": "/usr/bin/uname",
        "args": ["-r"],
        "env": {"PATH": "/tmp"}
    });

    let response = handle_request(&state, &controller, request).await;

    assert_eq!(
        response.error.as_ref().expect("error").code,
        ErrorCode::ParamsInvalid
    );
}

#[tokio::test]
async fn handle_request_rejects_non_null_auth() {
    let dir = tempfile::tempdir().expect("temp dir");
    let state = test_server_state(dir.path(), "agent-endpoint-1");
    let controller = test_controller_remote(&state);
    let mut request = test_rpc_request(NODE_PING, valid_nonce(5));
    request.auth = Some(json!({"scheme": "bearer", "token": "not-supported"}));

    let response = handle_request(&state, &controller, request).await;

    assert_eq!(
        response.error.as_ref().expect("error").code,
        ErrorCode::UnsupportedAuthScheme
    );
}

#[tokio::test]
async fn handle_request_rejects_replayed_nonce_per_remote_endpoint() {
    let dir = tempfile::tempdir().expect("temp dir");
    let state = test_server_state(dir.path(), "agent-endpoint-1");
    let controller = test_controller_remote(&state);
    let nonce = valid_nonce(6);

    let first = handle_request(
        &state,
        &controller,
        test_rpc_request(NODE_PING, nonce.clone()),
    )
    .await;
    assert!(first.ok);

    let replay = handle_request(&state, &controller, test_rpc_request(NODE_PING, nonce)).await;
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
    let controller = test_controller_remote(&state);
    {
        let mut cache = state.nonce_cache.lock().expect("nonce cache");
        *cache = NonceCache::with_limits(1, 1);
        assert_eq!(
            cache.register(&controller, valid_nonce(11), Duration::from_secs(60)),
            NonceDecision::Accepted
        );
    }
    let request = test_rpc_request(NODE_PING, valid_nonce(12));
    let request_id = request.request_id.clone();

    let response = handle_request(&state, &controller, request).await;

    let error = response.error.as_ref().expect("error");
    assert_eq!(response.request_id.as_deref(), Some(request_id.as_str()));
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert_eq!(error.details["resource"], "nonce_cache");
}

#[tokio::test]
async fn handle_request_does_not_register_nonce_when_timestamp_invalid() {
    let dir = tempfile::tempdir().expect("temp dir");
    let state = test_server_state(dir.path(), "agent-endpoint-1");
    let controller = test_controller_remote(&state);
    let mut request = test_rpc_request(NODE_PING, valid_nonce(10));
    request.issued_at = (OffsetDateTime::now_utc() + time::Duration::hours(1))
        .format(&time::format_description::well_known::Rfc3339)
        .expect("format issued_at");

    let first = handle_request(&state, &controller, request.clone()).await;
    let second = handle_request(&state, &controller, request).await;

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
    let controller = test_controller_remote(&state);

    let mut zero = test_rpc_request(NODE_PING, valid_nonce(7));
    zero.deadline_ms = 0;
    let zero_response = handle_request(&state, &controller, zero).await;
    assert_eq!(
        zero_response.error.as_ref().expect("error").code,
        ErrorCode::InvalidDeadline
    );

    let mut too_large = test_rpc_request(NODE_PING, valid_nonce(8));
    too_large.deadline_ms = state.config.security.max_deadline_ms + 1;
    let too_large_response = handle_request(&state, &controller, too_large).await;
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
            controllers,
            peers: Vec::new(),
            path_probes: Vec::new(),
        },
        audit: AuditConfig {
            path: dir.join("audit.log"),
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

fn test_server_state(dir: &Path, agent_endpoint_id: &str) -> AgentServerState {
    let controller_id = iroh::SecretKey::generate().public();
    let config = test_agent_config(
        dir,
        vec![ControllerConfig {
            endpoint_id: controller_id.to_string(),
            role: "viewer".to_string(),
        }],
    );
    test_server_state_from_config(config, agent_endpoint_id)
}

fn test_controller_remote(state: &AgentServerState) -> String {
    state.config.security.controllers[0].endpoint_id.clone()
}

fn test_server_state_from_config(config: AgentConfig, agent_endpoint_id: &str) -> AgentServerState {
    let authz =
        AgentAuthorization::from_security_config(&config.security).expect("authz table builds");
    AgentServerState {
        config: config.clone(),
        audit: JsonlAuditWriter::new(config.audit.path.clone()),
        nonce_cache: std::sync::Arc::new(std::sync::Mutex::new(NonceCache::with_limits(
            100_000, 10_000,
        ))),
        limiters: std::sync::Arc::new(ServerLimiters::new(256, 256, 32, 1024, 128)),
        audit_limiter: std::sync::Arc::new(std::sync::Mutex::new(RejectedAuditLimiter::new(
            &config.audit,
        ))),
        authz: std::sync::Arc::new(authz),
        agent_endpoint_id: agent_endpoint_id.to_string(),
        outbound_endpoint: None,
        path_target_resolver: PathTargetResolver::endpoint_id_only(),
    }
}

#[cfg(unix)]
fn make_private(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod private");
}

#[cfg(not(unix))]
fn make_private(_path: &Path) {}

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

fn collect_production_command_violations(dir: &Path, violations: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).expect("read source dir") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            collect_production_command_violations(&path, violations);
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }

        let text = std::fs::read_to_string(&path).expect("read source file");
        if text.contains("std::process::Command") || text.contains("Command::new") {
            violations.push(path.display().to_string());
        }
    }
}
