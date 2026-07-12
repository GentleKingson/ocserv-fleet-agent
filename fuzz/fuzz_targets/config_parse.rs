#![no_main]

use libfuzzer_sys::fuzz_target;
use ocfleet_config::agent::{AgentConfig, validate_agent_config};
use ocfleet_config::cli::{CliConfig, validate_cli_config};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(config) = toml::from_str::<AgentConfig>(text) {
        let _ = validate_agent_config(&config);
    }
    if let Ok(config) = toml::from_str::<CliConfig>(text) {
        let _ = validate_cli_config(&config);
    }
});
