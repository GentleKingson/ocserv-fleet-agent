use anyhow::{Context, bail};
use serde_json::{Map, Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::private_file;
use crate::store::AlertEventRecord;

pub const DEFAULT_DELIVERY_LIMIT: u64 = 100;
pub const MAX_DELIVERY_LIMIT: u64 = 1_000;
pub const MAX_JSONL_PAYLOAD_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertHook {
    JsonlFile { path: PathBuf },
    Webhook { hook_id: String },
}

impl AlertHook {
    pub fn hook_type(&self) -> &'static str {
        match self {
            Self::JsonlFile { .. } => "jsonl_file",
            Self::Webhook { .. } => "webhook",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonlWriteSummary {
    pub record_count: usize,
    pub bytes_written: usize,
}

pub fn parse_alert_hook(value: &str) -> anyhow::Result<AlertHook> {
    let (kind, rest) = value
        .split_once(':')
        .with_context(|| "alert hook must use kind:value syntax")?;
    let kind = kind.trim().to_ascii_lowercase();
    let rest = rest.trim();
    if matches!(kind.as_str(), "exec" | "command" | "script" | "shell") {
        bail!("forbidden alert hook type: {kind}");
    }
    match kind.as_str() {
        "jsonl_file" => {
            if rest.is_empty() {
                bail!("jsonl_file hook requires a path");
            }
            Ok(AlertHook::JsonlFile {
                path: PathBuf::from(rest),
            })
        }
        "webhook" => {
            if rest.is_empty() {
                bail!("webhook hook requires a hook id");
            }
            Ok(AlertHook::Webhook {
                hook_id: rest.to_string(),
            })
        }
        _ => bail!("unsupported alert hook type: {kind}"),
    }
}

pub fn validate_delivery_limit(limit: u64) -> anyhow::Result<usize> {
    if !(1..=MAX_DELIVERY_LIMIT).contains(&limit) {
        bail!("--limit must be between 1 and {MAX_DELIVERY_LIMIT}");
    }
    usize::try_from(limit).context("--limit is too large")
}

pub fn write_jsonl_test_event(hook: &AlertHook) -> anyhow::Result<JsonlWriteSummary> {
    match hook {
        AlertHook::JsonlFile { path } => write_jsonl_payloads(path, [jsonl_test_payload()], false),
        AlertHook::Webhook { .. } => bail!("use alert hook test for webhook hooks"),
    }
}

pub fn deliver_jsonl_alerts(
    hook: &AlertHook,
    alerts: &[AlertEventRecord],
    dry_run: bool,
) -> anyhow::Result<JsonlWriteSummary> {
    match hook {
        AlertHook::JsonlFile { path } => {
            write_jsonl_payloads(path, alerts.iter().map(alert_delivery_payload), dry_run)
        }
        AlertHook::Webhook { .. } => bail!("use webhook alert delivery for webhook hooks"),
    }
}

pub fn alert_delivery_payload(alert: &AlertEventRecord) -> Value {
    alert_delivery_payload_for_hook(alert, "jsonl_file")
}

pub fn alert_delivery_payload_for_hook(alert: &AlertEventRecord, hook_type: &str) -> Value {
    json!({
        "schema": "ocfleet.alert.v1",
        "hook_type": hook_type,
        "alert_id": alert.alert_id,
        "dedupe_key": alert.dedupe_key,
        "node_id": alert.node_id,
        "severity": alert.severity,
        "state": alert.state,
        "reason_code": alert.reason_code,
        "first_seen_at": alert.first_seen_at,
        "last_seen_at": alert.last_seen_at,
        "last_sent_at": alert.last_sent_at,
        "resolved_at": alert.resolved_at,
        "methods": alert_methods(alert),
        "summary": alert_summary(alert),
    })
}

fn jsonl_test_payload() -> Value {
    json!({
        "schema": "ocfleet.alert.test.v1",
        "event": "alert.delivery.test",
        "hook_type": "jsonl_file",
        "dry_run": false,
    })
}

fn write_jsonl_payloads<I>(
    path: &Path,
    payloads: I,
    dry_run: bool,
) -> anyhow::Result<JsonlWriteSummary>
where
    I: IntoIterator<Item = Value>,
{
    let mut lines = Vec::new();
    let mut bytes_written = 0_usize;
    for payload in payloads {
        let mut line = serde_json::to_vec(&payload)?;
        if line.len() > MAX_JSONL_PAYLOAD_BYTES {
            bail!("alert delivery payload exceeds limit");
        }
        line.push(b'\n');
        bytes_written = bytes_written
            .checked_add(line.len())
            .context("alert delivery byte count overflow")?;
        lines.push(line);
    }

    if dry_run {
        return Ok(JsonlWriteSummary {
            record_count: lines.len(),
            bytes_written,
        });
    }

    let mut file =
        private_file::open_private_append_create(path).with_context(|| "alert delivery failed")?;
    for line in &lines {
        file.write_all(line)
            .with_context(|| "alert delivery failed")?;
    }
    Ok(JsonlWriteSummary {
        record_count: lines.len(),
        bytes_written,
    })
}

fn alert_methods(alert: &AlertEventRecord) -> Vec<String> {
    alert
        .detail_json
        .get("methods")
        .map(string_array)
        .unwrap_or_default()
}

fn alert_summary(alert: &AlertEventRecord) -> Value {
    alert
        .detail_json
        .get("summary")
        .map(safe_summary)
        .unwrap_or_else(|| json!({}))
}

fn safe_summary(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut output = Map::new();
            for (key, value) in map {
                if !allowed_summary_key(key) {
                    continue;
                }
                output.insert(key.clone(), safe_summary(value));
            }
            Value::Object(output)
        }
        Value::Array(values) => Value::Array(values.iter().map(safe_summary).collect()),
        Value::String(value) if forbidden_payload_value(value) => {
            Value::String("<redacted>".to_string())
        }
        _ => value.clone(),
    }
}

fn allowed_summary_key(key: &str) -> bool {
    matches!(
        key,
        "status"
            | "last_error_code"
            | "freshness_seconds"
            | "consecutive_failures"
            | "days_remaining"
            | "endpoint_id"
            | "endpoint_status"
            | "result_class"
    )
}

fn forbidden_payload_value(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    [
        "/etc/",
        "/var/log",
        "systemctl",
        "journalctl",
        "occtl",
        "username",
        "client_ip",
        "client-ip",
        "client ip",
        "session_id",
        "session-id",
        "session id",
    ]
    .iter()
    .any(|marker| value.contains(marker))
}

fn string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect()
}
