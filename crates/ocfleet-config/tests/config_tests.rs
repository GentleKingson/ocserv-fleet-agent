use ocfleet_config::agent::{AgentConfig, ConfigError, validate_agent_config};
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

    assert_eq!(config.security.max_handshake_tasks_global, 256);
    assert_eq!(config.security.max_connections_global, 256);
    assert_eq!(config.security.max_connections_per_controller, 32);
    assert_eq!(config.security.max_streams_global, 1024);
    assert_eq!(config.security.max_streams_per_controller, 128);
    assert_eq!(config.security.max_live_nonces_global, 100_000);
    assert_eq!(config.security.max_live_nonces_per_controller, 10_000);
    assert_eq!(config.audit.audit_queue_capacity, 1024);
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
