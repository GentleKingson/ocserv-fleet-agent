use ocfleet_cli::audit_export::audit_record_payload;
use ocfleet_cli::observation::observation_to_json;
use ocfleet_cli::store::{
    AlertEventRecord, AuditRecord, ObservabilityJobRecord, ObservabilityRunRecord,
    ProbeObservationRecord,
};
use serde_json::{Map, Value, json};

use crate::RedactionMode;
use crate::readonly_store::NodeHealthRecord;

pub fn health_node_to_json(record: &NodeHealthRecord) -> Value {
    let status = if !record.node.enabled {
        "disabled"
    } else {
        record
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.status.as_str())
            .unwrap_or("unknown")
    };
    let degraded_methods = record
        .snapshot
        .as_ref()
        .map(|snapshot| string_array(&snapshot.degraded_methods_json))
        .unwrap_or_default();
    json!({
        "node_id": record.node.node_id,
        "endpoint_id": record.node.endpoint_id,
        "name": record.node.name,
        "region": record.node.region,
        "role": record.node.role,
        "enabled": record.node.enabled,
        "status": status,
        "computed_at": record.snapshot.as_ref().map(|snapshot| snapshot.computed_at.as_str()),
        "freshness_seconds": record.snapshot.as_ref().and_then(|snapshot| snapshot.freshness_seconds),
        "last_success_at": record.snapshot.as_ref().and_then(|snapshot| snapshot.last_success_at.as_deref()),
        "last_failure_at": record.snapshot.as_ref().and_then(|snapshot| snapshot.last_failure_at.as_deref()),
        "last_error_code": record.snapshot.as_ref().and_then(|snapshot| snapshot.last_error_code.as_deref()),
        "degraded_methods": degraded_methods,
        "summary": record.snapshot.as_ref().map(|snapshot| safe_summary(&snapshot.summary_json)).unwrap_or_else(|| json!({})),
    })
}

pub fn health_summary_to_json(records: &[NodeHealthRecord]) -> Value {
    let mut counts = HealthCounts::default();
    for record in records {
        counts.record(if !record.node.enabled {
            "disabled"
        } else {
            record
                .snapshot
                .as_ref()
                .map(|snapshot| snapshot.status.as_str())
                .unwrap_or("unknown")
        });
    }
    json!({
        "total": counts.total,
        "healthy": counts.healthy,
        "degraded": counts.degraded,
        "unreachable": counts.unreachable,
        "stale": counts.stale,
        "disabled": counts.disabled,
        "unknown": counts.unknown,
    })
}

pub fn job_to_json(job: &ObservabilityJobRecord) -> Value {
    let pair = explicit_pair(job);
    json!({
        "job_id": job.job_id,
        "name": job.selector_json.get("name").and_then(Value::as_str),
        "kind": job.kind,
        "enabled": job.enabled,
        "interval_seconds": job.interval_seconds,
        "jitter_seconds": job.jitter_seconds,
        "timeout_ms": job.timeout_ms,
        "selector": selector_label(job).unwrap_or("<invalid>"),
        "source_node_id": pair.as_ref().and_then(|(source, _)| source.as_deref()),
        "target_node_id": pair.as_ref().and_then(|(_, target)| target.as_deref()),
        "next_run_at": job.next_run_at,
        "last_run_at": job.last_run_at,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
    })
}

pub fn run_to_json(run: &ObservabilityRunRecord) -> Value {
    json!({
        "run_id": run.run_id,
        "job_id": run.job_id,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "status": run.status,
        "triggered_by": run.triggered_by,
        "observation_count": run.observation_count,
        "failed_observation_count": run.failed_observation_count,
    })
}

pub fn observation_record_to_json(observation: &ProbeObservationRecord) -> Value {
    observation_to_json(observation)
}

pub fn alert_to_json(alert: &AlertEventRecord) -> Value {
    json!({
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
        "methods": alert.detail_json.get("methods").map(string_array).unwrap_or_default(),
        "summary": alert
            .detail_json
            .get("summary")
            .map(safe_alert_summary)
            .unwrap_or_else(|| json!({})),
    })
}

pub fn audit_to_json(row: &AuditRecord, redact: RedactionMode) -> Value {
    audit_record_payload(row, redact)
}

fn selector_label(job: &ObservabilityJobRecord) -> Option<&str> {
    job.selector_json.get("selector").and_then(Value::as_str)
}

fn explicit_pair(job: &ObservabilityJobRecord) -> Option<(Option<String>, Option<String>)> {
    let pair = job.pair_selector_json.as_ref()?;
    Some((
        pair.get("source_node_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        pair.get("target_node_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    ))
}

#[derive(Default)]
struct HealthCounts {
    total: usize,
    healthy: usize,
    degraded: usize,
    unreachable: usize,
    stale: usize,
    disabled: usize,
    unknown: usize,
}

impl HealthCounts {
    fn record(&mut self, status: &str) {
        self.total += 1;
        match status {
            "healthy" => self.healthy += 1,
            "degraded" => self.degraded += 1,
            "unreachable" => self.unreachable += 1,
            "stale" => self.stale += 1,
            "disabled" => self.disabled += 1,
            _ => self.unknown += 1,
        }
    }
}

fn safe_summary(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut output = Map::new();
            for (key, value) in map {
                if forbidden_summary_key(key) {
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

fn safe_alert_summary(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut output = Map::new();
            for (key, value) in map {
                if allowed_alert_summary_key(key) {
                    output.insert(key.clone(), safe_alert_summary(value));
                }
            }
            Value::Object(output)
        }
        Value::Array(values) => Value::Array(values.iter().map(safe_alert_summary).collect()),
        Value::String(value) if forbidden_payload_value(value) => {
            Value::String("<redacted>".to_string())
        }
        _ => value.clone(),
    }
}

fn forbidden_summary_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "raw",
        "stdout",
        "stderr",
        "body",
        "username",
        "client_ip",
        "client-ip",
        "session_id",
        "session-id",
        "subject",
        "issuer",
        "serial",
        "san",
        "certificate_pem",
        "private_key",
        "config_content",
    ]
    .iter()
    .any(|marker| key.contains(marker))
}

fn allowed_alert_summary_key(key: &str) -> bool {
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
        "session_id",
        "session-id",
        "-----begin certificate-----",
        "-----begin private key-----",
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
