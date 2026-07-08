use anyhow::{Result, bail};
use ocfleet_protocol::ocserv::{
    OcservCertExpiryResponse, OcservConfigFingerprintResponse, OcservFieldStatus,
    OcservServiceSummary, OcservServiceSummaryResponse, OcservSessionsSummaryResponse,
    OcservVersionResponse, is_valid_sha256_hex, validate_ocserv_response_json_size,
};
use serde_json::json;

const CLI_OUTPUT_MAX_BYTES: usize = 8 * 1024;
const HUMAN_FINGERPRINT_PREFIX_BYTES: usize = 12;

#[derive(Debug, Clone)]
pub struct OcservStatusView {
    pub node_id: String,
    pub service: Option<OcservServiceSummary>,
    pub version: Option<String>,
    pub version_status: OcservFieldStatus,
    pub sessions_total: Option<u32>,
    pub sessions_status: OcservFieldStatus,
    pub config_algorithm: Option<String>,
    pub config_hash: Option<String>,
    pub config_status: OcservFieldStatus,
    pub degraded_methods: Vec<&'static str>,
}

impl OcservStatusView {
    fn status(&self) -> &'static str {
        if self.degraded_methods.is_empty() {
            "ok"
        } else {
            "degraded"
        }
    }
}

pub fn format_status_human(
    node_id: &str,
    service: &OcservServiceSummaryResponse,
    version: &OcservVersionResponse,
    sessions: &OcservSessionsSummaryResponse,
    fingerprint: &OcservConfigFingerprintResponse,
) -> Result<String> {
    validate_ocserv_response_json_size(service)?;
    validate_ocserv_response_json_size(version)?;
    validate_ocserv_response_json_size(sessions)?;
    validate_ocserv_response_json_size(fingerprint)?;

    let view = OcservStatusView {
        node_id: node_id.to_string(),
        service: Some(service.service.clone()),
        version: version.version.clone(),
        version_status: version.status,
        sessions_total: sessions.sessions.total,
        sessions_status: sessions.sessions.status,
        config_algorithm: Some(fingerprint.fingerprint.algorithm.clone()),
        config_hash: fingerprint.fingerprint.hash.clone(),
        config_status: fingerprint.fingerprint.status,
        degraded_methods: Vec::new(),
    };
    format_status_view_human(&view)
}

pub fn format_status_view_human(view: &OcservStatusView) -> Result<String> {
    let service_state = view
        .service
        .as_ref()
        .map(|service| service.state.to_string())
        .unwrap_or_else(|| "unavailable".to_string());
    let service_enabled = view
        .service
        .as_ref()
        .map(|service| service.enabled.to_string())
        .unwrap_or_else(|| "unavailable".to_string());
    let degraded_methods = if view.degraded_methods.is_empty() {
        String::new()
    } else {
        format!("degraded_methods={}\n", view.degraded_methods.join(","))
    };
    let output = format!(
        "node_id={}\nstatus={}\nservice_state={}\nservice_enabled={}\nversion={}\nsessions_total={}\nconfig_fingerprint_sha256={}\n{}",
        view.node_id,
        view.status(),
        service_state,
        service_enabled,
        available_option(view.version.as_deref(), view.version_status),
        view.sessions_total
            .map(|value| value.to_string())
            .unwrap_or_else(|| "<unavailable>".to_string()),
        short_fingerprint(view.config_hash.as_deref(), view.config_status)?,
        degraded_methods,
    );
    assert_low_sensitive_ocserv_output(&output)?;
    Ok(output)
}

pub fn format_status_json(view: &OcservStatusView) -> Result<String> {
    let service_state = view
        .service
        .as_ref()
        .map(|service| service.state.to_string())
        .unwrap_or_else(|| "unavailable".to_string());
    let service_enabled = view
        .service
        .as_ref()
        .map(|service| service.enabled.to_string())
        .unwrap_or_else(|| "unavailable".to_string());
    let output = serde_json::to_string_pretty(&json!({
        "node_id": view.node_id.clone(),
        "status": view.status(),
        "service": {
            "state": service_state,
            "enabled": service_enabled,
        },
        "version": view.version.clone(),
        "version_status": view.version_status,
        "sessions": {
            "total": view.sessions_total,
            "status": view.sessions_status,
        },
        "config_fingerprint": {
            "algorithm": view.config_algorithm.as_deref().unwrap_or("sha256"),
            "hash": view.config_hash.clone(),
            "status": view.config_status,
        },
        "degraded_methods": &view.degraded_methods,
    }))? + "\n";
    assert_low_sensitive_ocserv_output(&output)?;
    Ok(output)
}

pub fn format_cert_human(node_id: &str, response: &OcservCertExpiryResponse) -> Result<String> {
    validate_ocserv_response_json_size(response)?;
    let mut output = format!("node_id={node_id}\n");
    for cert in &response.certs {
        output.push_str(&format!(
            "cert={} status={} not_after={} days_remaining={} fingerprint_sha256={}\n",
            cert.name,
            cert.status,
            cert.not_after.as_deref().unwrap_or("<unavailable>"),
            cert.days_remaining
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<unavailable>".to_string()),
            short_fingerprint(
                cert.fingerprint_sha256.as_deref(),
                OcservFieldStatus::Available
            )?,
        ));
    }
    assert_low_sensitive_ocserv_output(&output)?;
    Ok(output)
}

pub fn format_sessions_human(
    node_id: &str,
    response: &OcservSessionsSummaryResponse,
) -> Result<String> {
    validate_ocserv_response_json_size(response)?;
    let total = response
        .sessions
        .total
        .map(|value| value.to_string())
        .unwrap_or_else(|| "<unavailable>".to_string());
    let output = format!("node_id={node_id}\nsessions_total={total}\n");
    assert_low_sensitive_ocserv_output(&output)?;
    Ok(output)
}

pub fn assert_low_sensitive_ocserv_output(output: &str) -> Result<()> {
    if output.len() > CLI_OUTPUT_MAX_BYTES {
        bail!("ocserv output exceeds bounded size");
    }
    if contains_ipv4_address(output) || contains_ipv6_like_address(output) {
        bail!("ocserv output contains forbidden address-like content");
    }
    if contains_forbidden_ocserv_marker(output) {
        bail!("ocserv output contains forbidden content");
    }
    Ok(())
}

pub fn low_sensitive_ocserv_audit_message(message: &str) -> String {
    let mut sanitized = message
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>();
    if contains_ipv4_address(&sanitized)
        || contains_ipv6_like_address(&sanitized)
        || contains_forbidden_ocserv_marker(&sanitized)
    {
        return "ocserv readonly command failed".to_string();
    }
    if sanitized.len() > 128 {
        truncate_to_boundary(&mut sanitized, 128);
    }
    sanitized
}

fn contains_forbidden_ocserv_marker(output: &str) -> bool {
    let lowered = output
        .to_ascii_lowercase()
        .replace("ocserv.config", "ocserv_config");
    for forbidden in [
        "-----begin",
        "begin certificate",
        "private key",
        "/etc/",
        "/var/log",
        concat!("system", "ctl"),
        concat!("journal", "ctl"),
        concat!("occ", "tl"),
        "execstart",
        "ocserv.conf",
        "server-cert",
        "username",
        "\"user\"",
        " user=",
        "client_ip",
        "client-ip",
        "client ip",
        "session_id",
        "session-id",
        "session id",
        "vpn_ip",
        "vpn-ip",
        "assigned_ip",
        "cn=",
        "san",
        "dns:",
        "issuer",
        "serial",
        "subject",
    ] {
        if lowered.contains(forbidden) {
            return true;
        }
    }
    false
}

pub fn short_fingerprint(value: Option<&str>, status: OcservFieldStatus) -> Result<String> {
    if status != OcservFieldStatus::Available {
        return Ok("<unavailable>".to_string());
    }
    let Some(value) = value else {
        return Ok("<unavailable>".to_string());
    };
    if !is_valid_sha256_hex(value) {
        bail!("ocserv fingerprint is invalid");
    }
    Ok(format!("{}...", &value[..HUMAN_FINGERPRINT_PREFIX_BYTES]))
}

fn available_option(value: Option<&str>, status: OcservFieldStatus) -> String {
    if status == OcservFieldStatus::Available {
        value.unwrap_or("<unavailable>").to_string()
    } else {
        "<unavailable>".to_string()
    }
}

fn contains_ipv4_address(output: &str) -> bool {
    output
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '.' || ch == '_'))
        .any(|token| {
            let octets = token.split('.').collect::<Vec<_>>();
            octets.len() == 4
                && octets.iter().all(|octet| {
                    !octet.is_empty()
                        && octet.len() <= 3
                        && octet.bytes().all(|byte| byte.is_ascii_digit())
                        && octet.parse::<u8>().is_ok()
                })
        })
}

fn contains_ipv6_like_address(output: &str) -> bool {
    output
        .split(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | '[' | ']'))
        .any(|token| {
            let token = token.trim_matches(|ch: char| matches!(ch, ':' | ';' | ')' | '('));
            token.contains(':')
                && token.matches(':').count() >= 2
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() || byte == b':')
        })
}

fn truncate_to_boundary(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
}
