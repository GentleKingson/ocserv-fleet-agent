use serde::Serialize;
use std::fs;
use std::process::Command;
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub region: String,
    pub role: String,
    pub agent_version: String,
    pub hostname: String,
    pub os_release: String,
    pub kernel: String,
    pub arch: String,
    pub uptime_seconds: u64,
    pub current_time_utc: String,
    pub agent_endpoint_id: String,
}

pub fn collect_node_info(
    node_id: String,
    region: String,
    role: String,
    agent_version: String,
    agent_endpoint_id: String,
) -> NodeInfo {
    NodeInfo {
        node_id,
        region,
        role,
        agent_version,
        hostname: hostname(),
        os_release: os_release(),
        kernel: kernel_release(),
        arch: std::env::consts::ARCH.to_string(),
        uptime_seconds: uptime_seconds(),
        current_time_utc: OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .expect("RFC3339 formatting succeeds"),
        agent_endpoint_id,
    }
}

fn hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn os_release() -> String {
    fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|text| parse_pretty_name(&text))
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn parse_pretty_name(text: &str) -> Option<String> {
    text.lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(unquote_os_release_value)
}

fn unquote_os_release_value(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

fn kernel_release() -> String {
    let uname = "/usr/bin/uname";
    if !std::path::Path::new(uname).exists() {
        return "unknown".to_string();
    }

    Command::new(uname)
        .arg("-r")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn uptime_seconds() -> u64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|text| text.split_whitespace().next().map(str::to_string))
        .and_then(|seconds| seconds.parse::<f64>().ok())
        .map(|seconds| seconds as u64)
        .unwrap_or(0)
}
