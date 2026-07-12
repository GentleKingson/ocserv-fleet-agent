use ocfleet_config::agent::{
    AgentConfig, ConfigError, OcservReadonlyProviderKind, load_agent_config, validate_agent_config,
};
use ocfleet_config::cli::{CliConfig, CliConfigError, load_cli_config, validate_cli_config};
use ocfleet_config::validation::{validate_node_id, validate_region, validate_service_name};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn valid_agent_config() -> AgentConfig {
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    toml::from_str(&format!(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]
allowed_clock_skew_seconds = 60
default_deadline_ms = 5000
max_deadline_ms = 10000
max_rpc_timeout_ms = 5000
max_request_bytes = 65536
max_response_bytes = 2097152

[[security.controllers]]
endpoint_id = "{endpoint_id}"
role = "viewer"

[audit]
path = "/tmp/ocfleet-audit.log"
"#,
    ))
    .expect("valid agent config should parse")
}

fn minimal_agent_config() -> AgentConfig {
    toml::from_str(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[audit]
path = "/tmp/ocfleet-audit.log"
"#,
    )
    .expect("minimal agent config should parse")
}

fn valid_cli_config() -> CliConfig {
    toml::from_str(
        r#"
[controller]
database_path = "/tmp/ocfleet-controller.db"

[iroh]
secret_key_path = "/tmp/cli-iroh.secret"

[security]
request_timeout_ms = 5000
"#,
    )
    .expect("valid cli config should parse")
}

fn temp_config_path(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "ocfleet-config-{name}-{}-{unique}.toml",
        std::process::id()
    ))
}

fn temp_private_dir(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "ocfleet-config-{name}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&path).expect("create temp config dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod temp dir");
    }
    path
}

fn valid_agent_config_text() -> String {
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    format!(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[[security.controllers]]
endpoint_id = "{endpoint_id}"
role = "viewer"

[audit]
path = "/tmp/ocfleet-audit.log"
"#,
    )
}

#[test]
fn node_id_allows_safe_names_only() {
    assert!(validate_node_id("hk-ocserv-01").is_ok());
    assert!(validate_node_id("hk.ocserv_01").is_ok());
    assert!(validate_node_id("bad/id").is_err());
    assert!(validate_node_id("").is_err());
}

#[test]
fn region_allows_short_safe_values() {
    assert!(validate_region("hk").is_ok());
    assert!(validate_region("us-west_1").is_ok());
    assert!(validate_region("bad region").is_err());
}

#[test]
fn service_name_rejects_shell_metacharacters() {
    assert!(validate_service_name("ocserv").is_ok());
    assert!(validate_service_name("ocserv.service").is_ok());
    assert!(validate_service_name("ocserv@blue.service").is_ok());
    assert!(validate_service_name("ocserv;restart").is_err());
    assert!(validate_service_name("ocserv service").is_err());
}

#[test]
fn agent_config_rejects_phase_one_ocserv_section() {
    let config: AgentConfig = toml::from_str(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[audit]
path = "/tmp/ocfleet-audit.log"

[ocserv]
service_name = "ocserv.service"
"#,
    )
    .expect("test config should parse");

    let err = validate_agent_config(&config).expect_err("ocserv section should be rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message)
            if message.contains("[ocserv]") && message.contains("Phase 1 read-only MVP")
    ));
}

#[test]
#[cfg(not(feature = "controlled-writes"))]
fn agent_config_controlled_writes_feature_is_default_disabled() {
    let config: AgentConfig = toml::from_str(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[audit]
path = "/tmp/ocfleet-audit.log"

[controlled_writes]
enabled = true

[controlled_writes.ocserv_reload]
enabled = true
local_identity = "ocserv-primary"
"#,
    )
    .expect("controlled writes config should parse");

    let err = validate_agent_config(&config)
        .expect_err("controlled writes must be compile-time disabled by default");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("controlled writes are disabled")
    ));
}

#[test]
#[cfg(feature = "controlled-writes")]
fn agent_config_accepts_controlled_writes_only_with_feature_enabled() {
    let config: AgentConfig = toml::from_str(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[audit]
path = "/tmp/ocfleet-audit.log"

[controlled_writes]
enabled = true

[controlled_writes.ocserv_reload]
enabled = true
local_identity = "ocserv-primary"

[controlled_writes.ocserv_restart]
enabled = false
emergency_only = true
local_identity = "ocserv-primary"
"#,
    )
    .expect("controlled writes config should parse");

    validate_agent_config(&config).expect("feature-enabled local policy should validate");
    assert!(config.controlled_writes.enabled);
    assert!(config.controlled_writes.ocserv_reload.enabled);
    assert_eq!(
        config
            .controlled_writes
            .ocserv_reload
            .local_identity
            .as_deref(),
        Some("ocserv-primary")
    );
}

#[test]
#[cfg(feature = "controlled-writes")]
fn feature_enabled_config_requires_emergency_restart_and_rejects_session_disconnect() {
    let base = r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[audit]
path = "/tmp/ocfleet-audit.log"

[controlled_writes]
enabled = true
"#;

    let restart: AgentConfig = toml::from_str(&format!(
        "{base}\n[controlled_writes.ocserv_restart]\nenabled = true\n"
    ))
    .expect("restart config parses");
    let err = validate_agent_config(&restart).expect_err("restart acknowledgement is mandatory");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("emergency_only=true")
    ));

    let disconnect: AgentConfig = toml::from_str(&format!(
        "{base}\n[controlled_writes.ocserv_session_disconnect]\nenabled = true\n"
    ))
    .expect("disconnect config parses");
    let err =
        validate_agent_config(&disconnect).expect_err("disconnect policy remains unavailable");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("without a safe selector")
    ));
}

#[test]
fn agent_config_rejects_controlled_write_operation_without_global_enable() {
    let config: AgentConfig = toml::from_str(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[audit]
path = "/tmp/ocfleet-audit.log"

[controlled_writes.ocserv_restart]
enabled = true
emergency_only = true
"#,
    )
    .expect("controlled writes config should parse");

    let err = validate_agent_config(&config)
        .expect_err("operation policy must not enable without global gate");
    assert!(matches!(
        err,
        ConfigError::Invalid(message)
            if message.contains("controlled_writes.enabled must be true")
    ));
}

#[test]
fn agent_config_rejects_unsafe_dormant_controlled_write_identity() {
    let config: AgentConfig = toml::from_str(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[audit]
path = "/tmp/ocfleet-audit.log"

[controlled_writes.ocserv_reload]
enabled = false
local_identity = "/usr/bin/systemctl restart ocserv"
"#,
    )
    .expect("dormant controlled writes config should parse");

    let err = validate_agent_config(&config)
        .expect_err("unsafe dormant local identities must fail closed");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("local_identity")
    ));
}

#[test]
fn agent_config_rejects_unknown_controlled_writes_fields() {
    let err = toml::from_str::<AgentConfig>(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[audit]
path = "/tmp/ocfleet-audit.log"

[controlled_writes]
enabled = false
command = "systemctl restart ocserv"
"#,
    )
    .expect_err("unknown controlled writes fields must be rejected");
    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn agent_config_rejects_unknown_controlled_write_operation_policy_fields() {
    let err = toml::from_str::<AgentConfig>(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[audit]
path = "/tmp/ocfleet-audit.log"

[controlled_writes]
enabled = false

[controlled_writes.ocserv_reload]
enabled = false
unit = "ocserv.service"
"#,
    )
    .expect_err("unknown operation policy fields must be rejected");
    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn agent_config_rejects_phase_one_logs_section() {
    let config: AgentConfig = toml::from_str(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[audit]
path = "/tmp/ocfleet-audit.log"

[logs]
journal_unit = "ocserv.service"
"#,
    )
    .expect("test config should parse");

    let err = validate_agent_config(&config).expect_err("logs section should be rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message)
            if message.contains("[logs]") && message.contains("Phase 1 read-only MVP")
    ));
}

#[test]
fn agent_config_rejects_empty_iroh_secret_key_path() {
    let mut config = valid_agent_config();
    config.iroh.secret_key_path = "".into();

    let err = validate_agent_config(&config).expect_err("empty secret key path should be rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("iroh.secret_key_path")
    ));
}

#[test]
fn agent_config_rejects_empty_audit_path() {
    let mut config = valid_agent_config();
    config.audit.path = "".into();

    let err = validate_agent_config(&config).expect_err("empty audit path should be rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("audit.path")
    ));
}

#[test]
fn agent_config_rejects_empty_controller_endpoint_id() {
    let mut config = valid_agent_config();
    config.security.controllers[0].endpoint_id.clear();

    let err = validate_agent_config(&config).expect_err("empty endpoint_id should be rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("endpoint_id")
    ));
}

#[test]
fn agent_config_rejects_controller_endpoint_id_with_ascii_whitespace() {
    let mut config = valid_agent_config();
    config.security.controllers[0].endpoint_id = "controller endpoint".into();

    let err =
        validate_agent_config(&config).expect_err("endpoint_id whitespace should be rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("endpoint_id")
    ));
}

#[test]
fn agent_config_rejects_malformed_controller_endpoint_id() {
    let mut config = valid_agent_config();
    config.security.controllers[0].endpoint_id = "not-an-endpoint-id".into();

    let err = validate_agent_config(&config).expect_err("malformed endpoint_id should be rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("endpoint_id")
    ));
}

#[cfg(unix)]
#[test]
fn load_agent_config_rejects_group_writable_config_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_private_dir("agent-config-mode");
    let path = dir.join("agent.toml");
    fs::write(&path, valid_agent_config_text()).expect("write config");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o620)).expect("chmod unsafe config");

    let err = load_agent_config(&path).expect_err("unsafe config should fail closed");

    assert!(matches!(err, ConfigError::Read(_)));
    fs::remove_dir_all(dir).expect("cleanup temp dir");
}

#[cfg(unix)]
#[test]
fn load_agent_config_rejects_world_writable_parent_directory() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_private_dir("agent-config-parent");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).expect("chmod unsafe parent");
    let path = dir.join("agent.toml");
    fs::write(&path, valid_agent_config_text()).expect("write config");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod config");

    let err = load_agent_config(&path).expect_err("unsafe parent should fail closed");

    assert!(matches!(err, ConfigError::Read(_)));
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("restore temp dir mode");
    fs::remove_dir_all(dir).expect("cleanup temp dir");
}

#[cfg(unix)]
#[test]
fn load_agent_config_rejects_symlink_and_hardlink_config_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_private_dir("agent-config-links");
    let real_path = dir.join("agent.toml");
    let symlink_path = dir.join("agent-link.toml");
    let hardlink_path = dir.join("agent-hardlink.toml");
    fs::write(&real_path, valid_agent_config_text()).expect("write config");
    fs::set_permissions(&real_path, fs::Permissions::from_mode(0o600)).expect("chmod config");
    std::os::unix::fs::symlink(&real_path, &symlink_path).expect("create symlink");
    fs::hard_link(&real_path, &hardlink_path).expect("create hardlink");

    let symlink_err = load_agent_config(&symlink_path).expect_err("symlink config rejected");
    let hardlink_err = load_agent_config(&real_path).expect_err("hardlinked config rejected");

    assert!(matches!(symlink_err, ConfigError::Read(_)));
    assert!(matches!(hardlink_err, ConfigError::Read(_)));
    fs::remove_dir_all(dir).expect("cleanup temp dir");
}

#[test]
fn agent_config_rejects_non_viewer_controller_role() {
    let mut config = valid_agent_config();
    config.security.controllers[0].role = "admin".into();

    let err = validate_agent_config(&config).expect_err("non-viewer role should be rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("controller role")
    ));
}

#[test]
fn agent_config_rejects_path_probe_target_not_in_enabled_peers() {
    let controller_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let missing_target_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let disabled_target_endpoint_id = iroh::SecretKey::generate().public().to_string();

    let mut missing_peer_config = minimal_agent_config();
    missing_peer_config.security.controllers = vec![ocfleet_config::agent::ControllerConfig {
        endpoint_id: controller_endpoint_id.clone(),
        role: "viewer".to_string(),
    }];
    missing_peer_config.security.path_probes = vec![ocfleet_config::agent::PathProbeConfig {
        controller_endpoint_id: controller_endpoint_id.clone(),
        target_endpoint_id: missing_target_endpoint_id,
        enabled: true,
    }];
    let err = validate_agent_config(&missing_peer_config)
        .expect_err("path probe target must be an enabled peer");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("security.peers")
    ));

    let mut disabled_peer_config = minimal_agent_config();
    disabled_peer_config.security.controllers = vec![ocfleet_config::agent::ControllerConfig {
        endpoint_id: controller_endpoint_id.clone(),
        role: "viewer".to_string(),
    }];
    disabled_peer_config.security.peers = vec![ocfleet_config::agent::PeerConfig {
        endpoint_id: disabled_target_endpoint_id.clone(),
        enabled: false,
    }];
    disabled_peer_config.security.path_probes = vec![ocfleet_config::agent::PathProbeConfig {
        controller_endpoint_id,
        target_endpoint_id: disabled_target_endpoint_id,
        enabled: true,
    }];
    let err = validate_agent_config(&disabled_peer_config)
        .expect_err("path probe target must not be a disabled peer");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("enabled peer")
    ));
}

#[test]
fn agent_config_rejects_unknown_controller_fields() {
    let controller_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let err = toml::from_str::<AgentConfig>(&format!(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[[security.controllers]]
endpoint_id = "{controller_endpoint_id}"
role = "viewer"
enabled = false

[audit]
path = "/tmp/ocfleet-audit.log"
"#
    ))
    .expect_err("unknown controller fields rejected");

    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn agent_config_rejects_non_positive_allowed_clock_skew() {
    for value in [0, -1] {
        let mut config = valid_agent_config();
        config.security.allowed_clock_skew_seconds = value;

        let err = validate_agent_config(&config)
            .expect_err("non-positive allowed_clock_skew_seconds should be rejected");
        assert!(matches!(
            err,
            ConfigError::Invalid(message) if message.contains("allowed_clock_skew_seconds")
        ));
    }
}

#[test]
fn agent_config_rejects_zero_payload_limits() {
    let mut config = valid_agent_config();
    config.security.max_request_bytes = 0;
    let err =
        validate_agent_config(&config).expect_err("zero max_request_bytes should be rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("max_request_bytes")
    ));

    let mut config = valid_agent_config();
    config.security.max_response_bytes = 0;
    let err =
        validate_agent_config(&config).expect_err("zero max_response_bytes should be rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("max_response_bytes")
    ));
}

#[test]
fn agent_config_rejects_too_small_max_response_bytes() {
    let mut config = valid_agent_config();
    config.security.max_response_bytes = 511;

    let err =
        validate_agent_config(&config).expect_err("small max_response_bytes should be rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message)
            if message.contains("max_response_bytes") && message.contains("512")
    ));
}

#[test]
fn agent_config_defaults_include_resource_limits() {
    let config = minimal_agent_config();

    assert!(!config.ocserv_readonly.enabled);
    assert_eq!(
        config.ocserv_readonly.provider,
        OcservReadonlyProviderKind::Disabled
    );
    assert_eq!(config.ocserv_readonly.snapshot_path, None);
    assert!(config.ocserv_readonly.certificates.is_empty());
    assert!(config.ocserv_readonly.config_fingerprint.is_none());
    assert!(!config.controlled_writes.enabled);
    assert!(!config.controlled_writes.ocserv_reload.enabled);
    assert!(!config.controlled_writes.ocserv_restart.enabled);
    assert!(!config.controlled_writes.ocserv_config_apply.enabled);
    assert!(!config.controlled_writes.ocserv_config_rollback.enabled);
    assert!(!config.controlled_writes.ocserv_session_disconnect.enabled);

    assert!(config.security.peers.is_empty());
    assert!(config.security.path_probes.is_empty());
    assert_eq!(config.security.max_handshake_duration_ms, 5_000);
    assert_eq!(config.security.max_connection_idle_ms, 5_000);
    assert_eq!(config.security.max_handshake_tasks_global, 256);
    assert_eq!(config.security.max_connections_global, 256);
    assert_eq!(config.security.max_connections_per_controller, 32);
    assert_eq!(config.security.max_streams_global, 1024);
    assert_eq!(config.security.max_streams_per_controller, 128);
    assert_eq!(config.security.max_live_nonces_global, 100_000);
    assert_eq!(config.security.max_live_nonces_per_controller, 10_000);
    assert_eq!(config.audit.audit_queue_capacity, 1024);
    assert_eq!(config.audit.spool_path, None);
    assert_eq!(config.audit.metrics_path, None);
    assert_eq!(config.audit.spool_max_events, 10_000);
    assert_eq!(config.audit.rejected_peer_log_burst, 10);
    assert_eq!(config.audit.rejected_peer_log_refill_per_sec, 1);
    assert_eq!(config.audit.rejected_peer_log_max_buckets, 4096);
    assert_eq!(config.audit.rejected_peer_log_bucket_ttl_seconds, 3600);
    assert_eq!(
        config.audit.rejected_peer_log_aggregate_interval_seconds,
        60
    );
}

#[test]
fn agent_config_accepts_ocserv_readonly_snapshot_provider() {
    let config: AgentConfig = toml::from_str(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[audit]
path = "/tmp/ocfleet-audit.log"

[ocserv_readonly]
enabled = true
provider = "snapshot"
snapshot_path = "/var/lib/ocfleet-agent/ocserv-readonly.json"

[ocserv_readonly.config_fingerprint]
name = "main"
config_path = "/etc/ocserv/ocserv.conf"
mode = "legacy_sha256"

[[ocserv_readonly.certificates]]
name = "server"
cert_path = "/etc/ocserv/server-cert.pem"
"#,
    )
    .expect("ocserv readonly config parses");

    validate_agent_config(&config).expect("ocserv readonly config validates");
    assert!(config.ocserv_readonly.enabled);
    assert_eq!(
        config.ocserv_readonly.provider,
        OcservReadonlyProviderKind::Snapshot
    );
    assert_eq!(config.ocserv_readonly.certificates.len(), 1);
    assert_eq!(config.ocserv_readonly.certificates[0].name, "server");
}

#[test]
fn agent_config_accepts_ocserv_readonly_collector_snapshot_provider() {
    let config: AgentConfig = toml::from_str(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[audit]
path = "/tmp/ocfleet-audit.log"

[ocserv_readonly]
enabled = true
provider = "collector_snapshot"
snapshot_path = "/var/lib/ocfleet-agent/ocserv-live-snapshot.json"
"#,
    )
    .expect("collector snapshot config parses");

    validate_agent_config(&config).expect("collector snapshot config validates");
    assert_eq!(
        config.ocserv_readonly.provider,
        OcservReadonlyProviderKind::CollectorSnapshot
    );
    assert_eq!(
        config.ocserv_readonly.snapshot_path.as_deref(),
        Some(std::path::Path::new(
            "/var/lib/ocfleet-agent/ocserv-live-snapshot.json"
        ))
    );
}

#[test]
fn agent_config_rejects_enabled_ocserv_readonly_without_explicit_provider() {
    let err = toml::from_str::<AgentConfig>(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[audit]
path = "/tmp/ocfleet-audit.log"

[ocserv_readonly]
enabled = true
snapshot_path = "/var/lib/ocfleet-agent/ocserv-readonly.json"
"#,
    )
    .expect_err("enabled ocserv readonly requires explicit provider");

    assert!(err.to_string().contains("provider"));
}

#[test]
fn agent_config_rejects_unknown_ocserv_readonly_fields() {
    let err = toml::from_str::<AgentConfig>(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[audit]
path = "/tmp/ocfleet-audit.log"

[ocserv_readonly]
enabled = false
provider = "disabled"
command = "systemctl status ocserv"
"#,
    )
    .expect_err("unknown ocserv readonly fields rejected");

    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn agent_config_rejects_ocserv_readonly_command_unit_journal_and_occtl_fields() {
    for (field, value) in [
        ("command", r#""systemctl status ocserv""#),
        ("unit", r#""ocserv.service""#),
        ("journal", r#""ocserv""#),
        ("occtl", r#""show users""#),
    ] {
        let err = toml::from_str::<AgentConfig>(&format!(
            r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[audit]
path = "/tmp/ocfleet-audit.log"

[ocserv_readonly]
enabled = false
provider = "disabled"
{field} = {value}
"#,
        ))
        .expect_err("unknown selector fields rejected");

        assert!(
            err.to_string().contains("unknown field"),
            "{field} should be rejected as unknown: {err}"
        );
    }
}

#[test]
fn agent_config_rejects_relative_ocserv_readonly_paths() {
    let mut config: AgentConfig = toml::from_str(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[audit]
path = "/tmp/ocfleet-audit.log"

[ocserv_readonly]
enabled = true
provider = "snapshot"
snapshot_path = "relative/snapshot.json"
"#,
    )
    .expect("test config parses");

    let err = validate_agent_config(&config).expect_err("relative snapshot path rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("snapshot_path")
    ));

    config.ocserv_readonly.snapshot_path = Some("/var/lib/ocfleet-agent/snapshot.json".into());
    config
        .ocserv_readonly
        .certificates
        .push(ocfleet_config::agent::OcservCertificateConfig {
            name: "server".to_string(),
            cert_path: "server.pem".into(),
        });
    let err = validate_agent_config(&config).expect_err("relative cert path rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("cert_path")
    ));
}

#[test]
fn agent_config_rejects_too_many_ocserv_certificates_and_bad_names() {
    let mut config = minimal_agent_config();
    config.ocserv_readonly.enabled = true;
    config.ocserv_readonly.provider = OcservReadonlyProviderKind::Snapshot;
    config.ocserv_readonly.snapshot_path =
        Some("/var/lib/ocfleet-agent/ocserv-readonly.json".into());
    for index in 0..9 {
        config
            .ocserv_readonly
            .certificates
            .push(ocfleet_config::agent::OcservCertificateConfig {
                name: format!("server-{index}"),
                cert_path: format!("/etc/ocserv/server-{index}.pem").into(),
            });
    }

    let err = validate_agent_config(&config).expect_err("too many certificates rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("certificates")
    ));

    config.ocserv_readonly.certificates.truncate(1);
    config.ocserv_readonly.certificates[0].name = "../server".to_string();
    let err = validate_agent_config(&config).expect_err("bad cert name rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("name")
    ));
}

#[test]
fn agent_config_rejects_config_fingerprint_bad_name() {
    let mut config = minimal_agent_config();
    config.ocserv_readonly.config_fingerprint =
        Some(ocfleet_config::agent::OcservConfigFingerprintConfig {
            name: "../main".to_string(),
            config_path: "/etc/ocserv/ocserv.conf".into(),
            mode: ocfleet_config::agent::ConfigFingerprintMode::LegacySha256,
            key_id: None,
            key_path: None,
            previous_key_id: None,
            previous_key_path: None,
        });

    let err = validate_agent_config(&config).expect_err("bad fingerprint name rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("config_fingerprint.name")
    ));
}

#[test]
fn agent_config_rejects_certificate_name_with_control_char() {
    let mut config = minimal_agent_config();
    config
        .ocserv_readonly
        .certificates
        .push(ocfleet_config::agent::OcservCertificateConfig {
            name: "server\n".to_string(),
            cert_path: "/etc/ocserv/server-cert.pem".into(),
        });

    let err = validate_agent_config(&config).expect_err("control char in cert name rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("certificates.name")
    ));
}

#[test]
fn agent_config_rejects_snapshot_provider_without_snapshot_path() {
    let mut config = minimal_agent_config();
    config.ocserv_readonly.enabled = true;
    config.ocserv_readonly.provider = OcservReadonlyProviderKind::Snapshot;
    config.ocserv_readonly.snapshot_path = None;

    let err = validate_agent_config(&config).expect_err("snapshot path required");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("snapshot_path")
    ));
}

#[test]
fn agent_config_rejects_collector_snapshot_provider_without_snapshot_path() {
    let mut config = minimal_agent_config();
    config.ocserv_readonly.enabled = true;
    config.ocserv_readonly.provider = OcservReadonlyProviderKind::CollectorSnapshot;
    config.ocserv_readonly.snapshot_path = None;

    let err = validate_agent_config(&config).expect_err("collector snapshot path required");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("snapshot_path")
    ));
}

#[test]
fn agent_config_accepts_audit_durability_paths_and_rejects_zero_spool_capacity() {
    let mut config = valid_agent_config();
    config.audit.spool_path = Some("/var/lib/ocfleet-agent/audit.spool.jsonl".into());
    config.audit.metrics_path = Some("/var/lib/ocfleet-agent/audit.metrics.json".into());
    config.audit.spool_max_events = 10;
    validate_agent_config(&config).expect("audit durability settings validate");

    config.audit.spool_max_events = 0;
    let err = validate_agent_config(&config).expect_err("zero spool capacity rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("audit.spool_max_events")
    ));
}

#[test]
fn agent_config_rejects_zero_connection_timeouts() {
    let mut config = valid_agent_config();
    config.security.max_handshake_duration_ms = 0;
    let err = validate_agent_config(&config).expect_err("zero max_handshake_duration_ms rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("max_handshake_duration_ms")
    ));

    let mut config = valid_agent_config();
    config.security.max_connection_idle_ms = 0;
    let err = validate_agent_config(&config).expect_err("zero max_connection_idle_ms rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("max_connection_idle_ms")
    ));
}

#[test]
fn agent_config_accepts_peer_allowlist_with_enabled_default_true() {
    let controller_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let peer_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let config: AgentConfig = toml::from_str(&format!(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[[security.controllers]]
endpoint_id = "{controller_endpoint_id}"
role = "viewer"

[[security.peers]]
endpoint_id = "{peer_endpoint_id}"

[audit]
path = "/tmp/ocfleet-audit.log"
"#
    ))
    .expect("peer config parses");

    validate_agent_config(&config).expect("peer config validates");
    assert_eq!(config.security.peers.len(), 1);
    assert_eq!(config.security.peers[0].endpoint_id, peer_endpoint_id);
    assert!(config.security.peers[0].enabled);
}

#[test]
fn agent_config_accepts_disabled_peer_allowlist_entry() {
    let peer_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let config: AgentConfig = toml::from_str(&format!(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[[security.peers]]
endpoint_id = "{peer_endpoint_id}"
enabled = false

[audit]
path = "/tmp/ocfleet-audit.log"
"#
    ))
    .expect("disabled peer config parses");

    validate_agent_config(&config).expect("disabled peer config validates");
    assert!(!config.security.peers[0].enabled);
}

#[test]
fn agent_config_rejects_malformed_peer_endpoint_id() {
    let mut config = minimal_agent_config();
    config
        .security
        .peers
        .push(ocfleet_config::agent::PeerConfig {
            endpoint_id: "not-an-endpoint-id".into(),
            enabled: true,
        });

    let err = validate_agent_config(&config).expect_err("malformed peer endpoint rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message)
            if message.contains("peer endpoint_id") || message.contains("endpoint_id")
    ));
}

#[test]
fn agent_config_rejects_duplicate_peer_endpoint_id() {
    let peer_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let mut config = minimal_agent_config();
    config
        .security
        .peers
        .push(ocfleet_config::agent::PeerConfig {
            endpoint_id: peer_endpoint_id.clone(),
            enabled: true,
        });
    config
        .security
        .peers
        .push(ocfleet_config::agent::PeerConfig {
            endpoint_id: peer_endpoint_id,
            enabled: false,
        });

    let err = validate_agent_config(&config).expect_err("duplicate peer rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("duplicate peer endpoint_id")
    ));
}

#[test]
fn agent_config_rejects_controller_peer_endpoint_overlap() {
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    let config: AgentConfig = toml::from_str(&format!(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[[security.controllers]]
endpoint_id = "{endpoint_id}"
role = "viewer"

[[security.peers]]
endpoint_id = "{endpoint_id}"
enabled = true

[audit]
path = "/tmp/ocfleet-audit.log"
"#
    ))
    .expect("overlap config parses");

    let err = validate_agent_config(&config).expect_err("controller/peer overlap rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("controller") && message.contains("peer")
    ));
}

#[test]
fn agent_config_rejects_unknown_peer_fields() {
    let peer_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let err = toml::from_str::<AgentConfig>(&format!(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[[security.peers]]
endpoint_id = "{peer_endpoint_id}"
enabled = true
methods = ["probe.peer.echo"]

[audit]
path = "/tmp/ocfleet-audit.log"
"#
    ))
    .expect_err("unknown peer fields rejected");

    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn agent_config_accepts_path_probe_with_enabled_default_true() {
    let controller_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let target_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let config: AgentConfig = toml::from_str(&format!(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[[security.controllers]]
endpoint_id = "{controller_endpoint_id}"
role = "viewer"

[[security.peers]]
endpoint_id = "{target_endpoint_id}"
enabled = true

[[security.path_probes]]
controller_endpoint_id = "{controller_endpoint_id}"
target_endpoint_id = "{target_endpoint_id}"

[audit]
path = "/tmp/ocfleet-audit.log"
"#
    ))
    .expect("path probe config parses");

    validate_agent_config(&config).expect("path probe config validates");
    assert_eq!(config.security.path_probes.len(), 1);
    assert_eq!(
        config.security.path_probes[0].controller_endpoint_id,
        controller_endpoint_id
    );
    assert_eq!(
        config.security.path_probes[0].target_endpoint_id,
        target_endpoint_id
    );
    assert!(config.security.path_probes[0].enabled);
}

#[test]
fn agent_config_accepts_disabled_path_probe_entry() {
    let controller_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let target_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let config: AgentConfig = toml::from_str(&format!(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[[security.controllers]]
endpoint_id = "{controller_endpoint_id}"
role = "viewer"

[[security.peers]]
endpoint_id = "{target_endpoint_id}"
enabled = true

[[security.path_probes]]
controller_endpoint_id = "{controller_endpoint_id}"
target_endpoint_id = "{target_endpoint_id}"
enabled = false

[audit]
path = "/tmp/ocfleet-audit.log"
"#
    ))
    .expect("disabled path probe config parses");

    validate_agent_config(&config).expect("disabled path probe config validates");
    assert!(!config.security.path_probes[0].enabled);
}

#[test]
fn agent_config_rejects_unknown_path_probe_fields() {
    let controller_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let target_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let err = toml::from_str::<AgentConfig>(&format!(
        r#"
[node]
id = "hk-ocserv-01"
region = "hk"
role = "ocserv"

[iroh]
secret_key_path = "/tmp/iroh.secret"

[security]

[[security.controllers]]
endpoint_id = "{controller_endpoint_id}"
role = "viewer"

[[security.path_probes]]
controller_endpoint_id = "{controller_endpoint_id}"
target_endpoint_id = "{target_endpoint_id}"
host = "127.0.0.1"

[audit]
path = "/tmp/ocfleet-audit.log"
"#
    ))
    .expect_err("unknown path probe fields rejected");

    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn agent_config_rejects_duplicate_path_probe_entry() {
    let controller_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let target_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let mut config = minimal_agent_config();
    config
        .security
        .controllers
        .push(ocfleet_config::agent::ControllerConfig {
            endpoint_id: controller_endpoint_id.clone(),
            role: "viewer".into(),
        });
    config
        .security
        .peers
        .push(ocfleet_config::agent::PeerConfig {
            endpoint_id: target_endpoint_id.clone(),
            enabled: true,
        });
    config
        .security
        .path_probes
        .push(ocfleet_config::agent::PathProbeConfig {
            controller_endpoint_id: controller_endpoint_id.clone(),
            target_endpoint_id: target_endpoint_id.clone(),
            enabled: true,
        });
    config
        .security
        .path_probes
        .push(ocfleet_config::agent::PathProbeConfig {
            controller_endpoint_id,
            target_endpoint_id,
            enabled: false,
        });

    let err = validate_agent_config(&config).expect_err("duplicate path probe rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("duplicate path probe")
    ));
}

#[test]
fn agent_config_rejects_path_probe_controller_not_in_controllers() {
    let controller_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let target_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let mut config = minimal_agent_config();
    config
        .security
        .peers
        .push(ocfleet_config::agent::PeerConfig {
            endpoint_id: target_endpoint_id.clone(),
            enabled: true,
        });
    config
        .security
        .path_probes
        .push(ocfleet_config::agent::PathProbeConfig {
            controller_endpoint_id,
            target_endpoint_id,
            enabled: true,
        });

    let err = validate_agent_config(&config).expect_err("unknown controller rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message)
            if message.contains("path probe controller")
                && message.contains("security.controllers")
    ));
}

#[test]
fn agent_config_rejects_path_probe_target_that_is_controller() {
    let controller_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let target_endpoint_id = iroh::SecretKey::generate().public().to_string();
    let mut config = minimal_agent_config();
    config
        .security
        .controllers
        .push(ocfleet_config::agent::ControllerConfig {
            endpoint_id: controller_endpoint_id.clone(),
            role: "viewer".into(),
        });
    config
        .security
        .controllers
        .push(ocfleet_config::agent::ControllerConfig {
            endpoint_id: target_endpoint_id.clone(),
            role: "viewer".into(),
        });
    config
        .security
        .path_probes
        .push(ocfleet_config::agent::PathProbeConfig {
            controller_endpoint_id,
            target_endpoint_id,
            enabled: true,
        });

    let err = validate_agent_config(&config).expect_err("controller target rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message)
            if message.contains("path probe target")
                && message.contains("security.controllers")
    ));
}

#[test]
fn agent_config_rejects_invalid_resource_limit_relationships() {
    let mut config = valid_agent_config();
    config.security.max_connections_per_controller = config.security.max_connections_global + 1;
    let err = validate_agent_config(&config).expect_err("per-controller connection cap rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message)
            if message.contains("max_connections_per_controller")
                && message.contains("max_connections_global")
    ));

    let mut config = valid_agent_config();
    config.security.max_streams_per_controller = config.security.max_streams_global + 1;
    let err = validate_agent_config(&config).expect_err("per-controller stream cap rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message)
            if message.contains("max_streams_per_controller")
                && message.contains("max_streams_global")
    ));

    let mut config = valid_agent_config();
    config.security.max_live_nonces_per_controller = config.security.max_live_nonces_global + 1;
    let err = validate_agent_config(&config).expect_err("per-controller nonce cap rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message)
            if message.contains("max_live_nonces_per_controller")
                && message.contains("max_live_nonces_global")
    ));
}

#[test]
fn agent_config_rejects_invalid_audit_limiter_values() {
    let mut config = valid_agent_config();
    config.audit.audit_queue_capacity = 0;
    let err = validate_agent_config(&config).expect_err("zero audit queue capacity rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("audit_queue_capacity")
    ));

    let mut config = valid_agent_config();
    config.audit.rejected_peer_log_burst = 0;
    let err = validate_agent_config(&config).expect_err("zero burst rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("rejected_peer_log_burst")
    ));

    let mut config = valid_agent_config();
    config.audit.rejected_peer_log_refill_per_sec = 0;
    let err = validate_agent_config(&config).expect_err("zero refill rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("rejected_peer_log_refill_per_sec")
    ));

    let mut config = valid_agent_config();
    config.audit.rejected_peer_log_bucket_ttl_seconds =
        config.audit.rejected_peer_log_aggregate_interval_seconds - 1;
    let err = validate_agent_config(&config).expect_err("ttl smaller than aggregate rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message)
            if message.contains("rejected_peer_log_bucket_ttl_seconds")
                && message.contains("rejected_peer_log_aggregate_interval_seconds")
    ));
}

#[test]
fn cli_config_rejects_empty_controller_database_path() {
    let mut config = valid_cli_config();
    config.controller.database_path = "".into();

    let err = validate_cli_config(&config).expect_err("empty database path should be rejected");
    assert!(matches!(
        err,
        CliConfigError::Invalid(message) if message.contains("controller.database_path")
    ));
}

#[test]
fn cli_config_rejects_empty_iroh_secret_key_path() {
    let mut config = valid_cli_config();
    config.iroh.secret_key_path = "".into();

    let err = validate_cli_config(&config).expect_err("empty secret key path should be rejected");
    assert!(matches!(
        err,
        CliConfigError::Invalid(message) if message.contains("iroh.secret_key_path")
    ));
}

#[test]
fn cli_config_rejects_zero_request_timeout() {
    let mut config = valid_cli_config();
    config.security.request_timeout_ms = 0;

    let err = validate_cli_config(&config).expect_err("zero request timeout should be rejected");
    assert!(matches!(
        err,
        CliConfigError::Invalid(message) if message.contains("request_timeout_ms")
    ));
}

#[test]
fn load_cli_config_rejects_invalid_static_values() {
    let path = temp_config_path("invalid-cli");
    fs::write(
        &path,
        r#"
[controller]
database_path = ""

[iroh]
secret_key_path = "/tmp/cli-iroh.secret"
"#,
    )
    .expect("test config should be written");

    let err = load_cli_config(&path).expect_err("invalid loaded config should be rejected");
    let _ = fs::remove_file(&path);

    assert!(matches!(
        err,
        CliConfigError::Invalid(message) if message.contains("controller.database_path")
    ));
}
