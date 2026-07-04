use ocfleet_config::agent::{validate_agent_config, AgentConfig, ConfigError};
use ocfleet_config::validation::{validate_node_id, validate_region, validate_service_name};

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
fn agent_config_rejects_invalid_ocserv_service_name() {
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
service_name = "ocserv;restart"
"#,
    )
    .expect("test config should parse");

    let err = validate_agent_config(&config).expect_err("invalid service name should be rejected");
    assert!(matches!(
        err,
        ConfigError::Invalid(message) if message.contains("service_name")
    ));
}
