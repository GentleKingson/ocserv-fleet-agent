use ocfleet_cli::audit_export::audit_record_payload;
use ocfleet_cli::observation::observation_to_json;
use ocfleet_cli::store::{
    AlertEventRecord, AuditRecord, ObservabilityJobRecord, ObservabilityRunRecord,
    ProbeObservationRecord,
};
use ocfleet_protocol::method::{
    NODE_INFO, NODE_PING, OCSERV_CERT_EXPIRY, OCSERV_CONFIG_FINGERPRINT, OCSERV_SERVICE_SUMMARY,
    OCSERV_SESSIONS_SUMMARY, OCSERV_VERSION, PROBE_CONTROLLER_PING, PROBE_PATH_ECHO,
};
use serde_json::{Map, Value, json};

use crate::RedactionMode;
use crate::readonly_store::NodeHealthRecord;

const MAX_METHODS_PER_SUMMARY: usize = 16;
const MAX_METHOD_BYTES: usize = 64;
const MAX_SUMMARY_DEPTH: usize = 4;
const MAX_SUMMARY_ENTRIES: usize = 32;
const MAX_SUMMARY_STRING_BYTES: usize = 256;
const REDACTED: &str = "<redacted>";

pub fn health_node_to_json(record: &NodeHealthRecord) -> Value {
    let status = if !record.node.enabled {
        "disabled"
    } else {
        record
            .snapshot
            .as_ref()
            .map(|snapshot| safe_health_status(&snapshot.status))
            .unwrap_or("unknown")
    };
    let degraded_methods = record
        .snapshot
        .as_ref()
        .map(|snapshot| safe_method_array(&snapshot.degraded_methods_json))
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
    let mut payload = observation_to_json(observation);
    if let Some(object) = payload.as_object_mut() {
        if let Some(summary) = object.get_mut("summary") {
            *summary = safe_summary(summary);
        }
        if !is_api_observation_method(&observation.method) {
            object.insert("method".to_string(), Value::String(REDACTED.to_string()));
        }
    }
    payload
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
        "methods": alert.detail_json.get("methods").map(safe_method_array).unwrap_or_default(),
        "summary": alert
            .detail_json
            .get("summary")
            .map(safe_alert_summary)
            .unwrap_or_else(|| json!({})),
    })
}

pub fn audit_to_json(row: &AuditRecord, redact: RedactionMode) -> Value {
    let mut payload = audit_record_payload(row, redact);
    if let Some(object) = payload.as_object_mut() {
        if let Some(detail) = object.get_mut("detail") {
            *detail = safe_summary(detail);
        }
        if object
            .get("method")
            .and_then(Value::as_str)
            .is_some_and(|method| !is_api_observation_method(method))
        {
            object.insert("method".to_string(), Value::Null);
        }
    }
    payload
}

fn selector_label(job: &ObservabilityJobRecord) -> Option<&str> {
    job.selector_json.get("selector").and_then(Value::as_str)
}

fn safe_health_status(status: &str) -> &str {
    match status {
        "healthy" | "degraded" | "unreachable" | "stale" | "disabled" | "unknown" => status,
        _ => "unknown",
    }
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
    if value.is_object() {
        safe_summary_at_depth(value, 0)
    } else {
        json!({})
    }
}

fn safe_summary_at_depth(value: &Value, depth: usize) -> Value {
    if depth >= MAX_SUMMARY_DEPTH {
        return Value::Null;
    }
    match value {
        Value::Object(map) => {
            if map.len() > MAX_SUMMARY_ENTRIES {
                return json!({});
            }
            let mut output = Map::new();
            for (key, value) in map {
                if key.len() > MAX_SUMMARY_STRING_BYTES || forbidden_summary_key(key) {
                    continue;
                }
                output.insert(key.clone(), safe_summary_at_depth(value, depth + 1));
            }
            Value::Object(output)
        }
        Value::Array(values) => {
            if values.len() > MAX_SUMMARY_ENTRIES {
                return json!([]);
            }
            Value::Array(
                values
                    .iter()
                    .map(|value| safe_summary_at_depth(value, depth + 1))
                    .collect(),
            )
        }
        Value::String(value)
            if value.len() > MAX_SUMMARY_STRING_BYTES || forbidden_payload_value(value) =>
        {
            Value::String(REDACTED.to_string())
        }
        _ => value.clone(),
    }
}

fn safe_alert_summary(value: &Value) -> Value {
    if value.is_object() {
        safe_alert_summary_at_depth(value, 0)
    } else {
        json!({})
    }
}

fn safe_alert_summary_at_depth(value: &Value, depth: usize) -> Value {
    if depth >= MAX_SUMMARY_DEPTH {
        return Value::Null;
    }
    match value {
        Value::Object(map) => {
            if map.len() > MAX_SUMMARY_ENTRIES {
                return json!({});
            }
            let mut output = Map::new();
            for (key, value) in map {
                if allowed_alert_summary_key(key) {
                    output.insert(key.clone(), safe_alert_summary_at_depth(value, depth + 1));
                }
            }
            Value::Object(output)
        }
        Value::Array(values) => {
            if values.len() > MAX_SUMMARY_ENTRIES {
                return json!([]);
            }
            Value::Array(
                values
                    .iter()
                    .map(|value| safe_alert_summary_at_depth(value, depth + 1))
                    .collect(),
            )
        }
        Value::String(value)
            if value.len() > MAX_SUMMARY_STRING_BYTES || forbidden_payload_value(value) =>
        {
            Value::String(REDACTED.to_string())
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
        "command",
        "script",
        "path",
        "selector",
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
        "-----begin openvpn static key-----",
        "bearer ",
    ]
    .iter()
    .any(|marker| value.contains(marker))
}

fn safe_method_array(value: &Value) -> Vec<String> {
    let Some(values) = value.as_array() else {
        return Vec::new();
    };
    if values.len() > MAX_METHODS_PER_SUMMARY {
        return Vec::new();
    }

    let mut methods = Vec::with_capacity(values.len());
    for value in values {
        let Some(method) = value.as_str() else {
            return Vec::new();
        };
        if method.len() > MAX_METHOD_BYTES || !is_api_observation_method(method) {
            return Vec::new();
        }
        if !methods.iter().any(|existing| existing == method) {
            methods.push(method.to_string());
        }
    }
    methods
}

fn is_api_observation_method(method: &str) -> bool {
    matches!(
        method,
        NODE_PING
            | NODE_INFO
            | PROBE_CONTROLLER_PING
            | PROBE_PATH_ECHO
            | OCSERV_SERVICE_SUMMARY
            | OCSERV_VERSION
            | OCSERV_SESSIONS_SUMMARY
            | OCSERV_CERT_EXPIRY
            | OCSERV_CONFIG_FINGERPRINT
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_arrays_accept_only_the_fixed_observation_catalog() {
        assert_eq!(
            safe_method_array(&json!([
                "probe.controller.ping",
                "ocserv.service.summary",
                "probe.controller.ping"
            ])),
            vec!["probe.controller.ping", "ocserv.service.summary"]
        );

        for polluted in [
            json!(["probe.controller.ping", "ocserv.reload"]),
            json!(["probe.controller.ping", "/etc/passwd"]),
            json!(["probe.controller.ping", 7]),
            json!("probe.controller.ping"),
            json!(["x".repeat(MAX_METHOD_BYTES + 1)]),
            Value::Array(
                (0..=MAX_METHODS_PER_SUMMARY)
                    .map(|_| json!("probe.controller.ping"))
                    .collect(),
            ),
        ] {
            assert!(safe_method_array(&polluted).is_empty());
        }
    }

    #[test]
    fn polluted_alert_methods_are_dropped_from_api_projection() {
        let alert = AlertEventRecord {
            alert_id: "alert-a".to_string(),
            dedupe_key: "node:node-a:node_unreachable".to_string(),
            node_id: Some("node-a".to_string()),
            severity: "critical".to_string(),
            state: "open".to_string(),
            reason_code: "NODE_UNREACHABLE".to_string(),
            first_seen_at: "2026-07-09T00:02:00Z".to_string(),
            last_seen_at: "2026-07-09T00:02:00Z".to_string(),
            last_sent_at: None,
            resolved_at: None,
            detail_json: json!({
                "methods": ["probe.controller.ping", "ocserv.reload"]
            }),
        };

        assert_eq!(alert_to_json(&alert)["methods"], json!([]));
    }

    #[test]
    fn polluted_observation_method_and_summary_are_not_reflected() {
        let observation = ProbeObservationRecord {
            observation_id: "obs-a".to_string(),
            run_id: None,
            node_id: Some("node-a".to_string()),
            endpoint_id: Some("endpoint-a".to_string()),
            method: "ocserv.reload".to_string(),
            ok: Some(false),
            error_code: Some("METHOD_NOT_ALLOWED".to_string()),
            duration_ms: Some(1),
            observed_at: "2026-07-09T00:00:00Z".to_string(),
            expires_at: None,
            result_class: "controller_rpc_summary".to_string(),
            summary_json: json!({
                "status": "failed",
                "raw_config": "listen-host = 0.0.0.0",
                "note": "x".repeat(MAX_SUMMARY_STRING_BYTES + 1)
            }),
        };

        let payload = observation_record_to_json(&observation);
        assert_eq!(payload["method"], REDACTED);
        assert!(payload["summary"].get("raw_config").is_none());
        assert_eq!(payload["summary"]["note"], REDACTED);
    }

    #[test]
    fn dynamic_summaries_enforce_depth_entry_and_string_bounds() {
        assert_eq!(safe_summary(&json!(["not", "an", "object"])), json!({}));

        let too_many = Value::Object(
            (0..=MAX_SUMMARY_ENTRIES)
                .map(|index| (format!("key-{index}"), json!(index)))
                .collect(),
        );
        assert_eq!(safe_summary(&too_many), json!({}));

        let too_deep = json!({"a": {"b": {"c": {"d": {"e": "hidden"}}}}});
        assert_eq!(safe_summary(&too_deep)["a"]["b"]["c"]["d"], Value::Null);

        let too_long = json!({"note": "x".repeat(MAX_SUMMARY_STRING_BYTES + 1)});
        assert_eq!(safe_summary(&too_long)["note"], REDACTED);
    }
}
