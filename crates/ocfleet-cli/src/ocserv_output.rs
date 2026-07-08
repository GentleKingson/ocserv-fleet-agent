use anyhow::{Result, bail};
use ocfleet_protocol::ocserv::{
    OcservCertExpiryResponse, OcservConfigFingerprintResponse, OcservFieldStatus,
    OcservServiceSummaryResponse, OcservSessionsSummaryResponse, OcservVersionResponse,
    validate_ocserv_response_json_size,
};

const CLI_OUTPUT_MAX_BYTES: usize = 8 * 1024;

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

    let output = format!(
        "node_id={node_id}\nservice_state={}\nservice_enabled={}\nversion={}\nsessions_total={}\nconfig_fingerprint_sha256={}\n",
        service.service.state,
        service.service.enabled,
        available_option(version.version.as_deref(), version.status),
        sessions
            .sessions
            .total
            .map(|value| value.to_string())
            .unwrap_or_else(|| "<unavailable>".to_string()),
        available_option(
            fingerprint.fingerprint.hash.as_deref(),
            fingerprint.fingerprint.status
        ),
    );
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
            cert.fingerprint_sha256
                .as_deref()
                .unwrap_or("<unavailable>"),
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
    for forbidden in [
        "-----BEGIN",
        "PRIVATE KEY",
        "/etc/ocserv",
        "/var/log",
        "systemctl",
        "journalctl",
        "occtl",
        "ExecStart",
        "ocserv.conf",
        "username",
        "client_ip",
        "session_id",
    ] {
        if output.contains(forbidden) {
            bail!("ocserv output contains forbidden content");
        }
    }
    Ok(())
}

fn available_option(value: Option<&str>, status: OcservFieldStatus) -> String {
    if status == OcservFieldStatus::Available {
        value.unwrap_or("<unavailable>").to_string()
    } else {
        "<unavailable>".to_string()
    }
}
