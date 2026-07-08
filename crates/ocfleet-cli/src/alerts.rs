use anyhow::{Context, bail};
use ocfleet_protocol::enrollment::EndpointStatus;
use ocfleet_protocol::method::{OCSERV_CERT_EXPIRY, OCSERV_SERVICE_SUMMARY, PROBE_CONTROLLER_PING};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::args::AlertCommand;
use crate::audit::AuditEvent;
use crate::store::{AlertEventRecord, ProbeObservationRecord, Store};

const OBSERVATION_READ_LIMIT: u64 = 1_000;
const NODE_UNREACHABLE_FAILURES: usize = 3;

#[derive(Debug, Clone)]
struct AlertCandidate {
    dedupe_key: String,
    node_id: Option<String>,
    severity: &'static str,
    reason_code: &'static str,
    methods: Vec<String>,
    summary: Value,
}

pub fn run_alert_command(store: &Store, command: AlertCommand) -> anyhow::Result<()> {
    match command {
        AlertCommand::List { json } => run_alert_list(store, json),
        AlertCommand::Test { hook } => run_alert_test(store, &hook),
        AlertCommand::Silence {
            dedupe_key,
            for_duration,
            reason,
        } => run_alert_silence(store, &dedupe_key, &for_duration, &reason),
        AlertCommand::Resolve { dedupe_key, reason } => {
            run_alert_resolve(store, &dedupe_key, &reason)
        }
    }
}

pub fn evaluate_alerts(store: &Store) -> anyhow::Result<Vec<AlertEventRecord>> {
    let now = now_rfc3339();
    let existing = store.list_alert_events()?;
    let mut updated = Vec::new();
    for candidate in alert_candidates(store)? {
        let record = upsert_candidate(store, &existing, candidate, &now)?;
        updated.push(record);
    }
    Ok(updated)
}

fn run_alert_list(store: &Store, json_output: bool) -> anyhow::Result<()> {
    evaluate_alerts(store)?;
    let alerts = store.list_alert_events()?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "generated_at": now_rfc3339(),
                "alerts": alerts.iter().map(alert_to_json).collect::<Vec<_>>(),
            }))?
        );
    } else {
        println!("alert_count={}", alerts.len());
        for alert in &alerts {
            println!(
                "dedupe_key={} node_id={} severity={} state={} reason_code={} first_seen_at={} last_seen_at={} resolved_at={}",
                alert.dedupe_key,
                alert.node_id.as_deref().unwrap_or("<none>"),
                alert.severity,
                alert.state,
                alert.reason_code,
                alert.first_seen_at,
                alert.last_seen_at,
                alert.resolved_at.as_deref().unwrap_or("<none>"),
            );
        }
    }
    Ok(())
}

fn run_alert_test(store: &Store, hook: &str) -> anyhow::Result<()> {
    reject_disabled_alert_hook(hook)?;
    evaluate_alerts(store)?;
    unreachable!("disabled alert hooks always return an error")
}

fn run_alert_silence(
    store: &Store,
    dedupe_key: &str,
    for_duration: &str,
    reason: &str,
) -> anyhow::Result<()> {
    let until = (OffsetDateTime::now_utc() + parse_duration(for_duration)?)
        .format(&Rfc3339)
        .expect("RFC3339 formatting succeeds");
    let mut alert = find_alert(store, dedupe_key)?;
    let mut detail = object_from_value(alert.detail_json);
    detail.insert("silenced_until".to_string(), Value::String(until.clone()));
    detail.insert(
        "silence_reason".to_string(),
        Value::String(reason.to_string()),
    );
    alert.detail_json = Value::Object(detail);
    store.upsert_alert_event(&alert)?;
    write_alert_audit(
        store,
        "alert.silence",
        json!({
            "dedupe_key": dedupe_key,
            "for_duration": for_duration,
            "silenced_until": until,
            "reason": reason,
        }),
    )?;
    println!("dedupe_key={dedupe_key}");
    println!("silenced_until={until}");
    Ok(())
}

fn run_alert_resolve(store: &Store, dedupe_key: &str, reason: &str) -> anyhow::Result<()> {
    let now = now_rfc3339();
    let mut alert = find_alert(store, dedupe_key)?;
    alert.state = "resolved".to_string();
    alert.resolved_at = Some(now.clone());
    alert.last_seen_at = now.clone();
    let mut detail = object_from_value(alert.detail_json);
    detail.insert(
        "resolve_reason".to_string(),
        Value::String(reason.to_string()),
    );
    alert.detail_json = Value::Object(detail);
    store.upsert_alert_event(&alert)?;
    write_alert_audit(
        store,
        "alert.resolve",
        json!({
            "dedupe_key": dedupe_key,
            "reason": reason,
        }),
    )?;
    println!("dedupe_key={dedupe_key}");
    println!("state=resolved");
    Ok(())
}

fn alert_candidates(store: &Store) -> anyhow::Result<Vec<AlertCandidate>> {
    let mut candidates = Vec::new();
    candidates.extend(candidates_from_health_snapshots(store)?);
    candidates.extend(candidates_from_probe_observations(store)?);
    candidates.extend(candidates_from_endpoint_trust(store)?);
    candidates.sort_by(|left, right| left.dedupe_key.cmp(&right.dedupe_key));
    candidates.dedup_by(|left, right| left.dedupe_key == right.dedupe_key);
    Ok(candidates)
}

fn candidates_from_health_snapshots(store: &Store) -> anyhow::Result<Vec<AlertCandidate>> {
    let mut candidates = Vec::new();
    for snapshot in store.list_health_snapshots()? {
        match snapshot.status.as_str() {
            "unreachable" => candidates.push(AlertCandidate {
                dedupe_key: format!("node:{}:node_unreachable", snapshot.node_id),
                node_id: Some(snapshot.node_id.clone()),
                severity: "critical",
                reason_code: "NODE_UNREACHABLE",
                methods: vec![PROBE_CONTROLLER_PING.to_string()],
                summary: json!({
                    "status": snapshot.status,
                    "last_error_code": snapshot.last_error_code,
                }),
            }),
            "stale" => candidates.push(AlertCandidate {
                dedupe_key: format!("node:{}:node_stale", snapshot.node_id),
                node_id: Some(snapshot.node_id.clone()),
                severity: "warning",
                reason_code: "NODE_STALE",
                methods: vec![PROBE_CONTROLLER_PING.to_string()],
                summary: json!({
                    "status": snapshot.status,
                    "freshness_seconds": snapshot.freshness_seconds,
                }),
            }),
            "degraded" => {
                let methods = string_array(&snapshot.degraded_methods_json);
                candidates.push(AlertCandidate {
                    dedupe_key: format!("node:{}:ocserv_degraded", snapshot.node_id),
                    node_id: Some(snapshot.node_id.clone()),
                    severity: "warning",
                    reason_code: "OCSERV_DEGRADED",
                    methods: if methods.is_empty() {
                        vec![OCSERV_SERVICE_SUMMARY.to_string()]
                    } else {
                        methods
                    },
                    summary: json!({
                        "status": snapshot.status,
                        "last_error_code": snapshot.last_error_code,
                    }),
                });
            }
            _ => {}
        }
    }
    Ok(candidates)
}

fn candidates_from_probe_observations(store: &Store) -> anyhow::Result<Vec<AlertCandidate>> {
    let observations = store.list_probe_observations(None, OBSERVATION_READ_LIMIT)?;
    let mut candidates = Vec::new();
    candidates.extend(node_unreachable_candidates(&observations));
    candidates.extend(cert_expiry_candidates(&observations));
    Ok(candidates)
}

fn node_unreachable_candidates(observations: &[ProbeObservationRecord]) -> Vec<AlertCandidate> {
    let mut grouped: BTreeMap<String, Vec<&ProbeObservationRecord>> = BTreeMap::new();
    for observation in observations
        .iter()
        .filter(|record| record.method == PROBE_CONTROLLER_PING)
    {
        if let Some(node_id) = &observation.node_id {
            grouped
                .entry(node_id.clone())
                .or_default()
                .push(observation);
        }
    }
    let mut candidates = Vec::new();
    for (node_id, mut records) in grouped {
        records.sort_by(|left, right| right.observed_at.cmp(&left.observed_at));
        let mut failures = 0_usize;
        let mut last_error_code = None;
        for record in records {
            if record.ok == Some(false)
                && record
                    .error_code
                    .as_deref()
                    .is_some_and(is_unreachable_error_code)
            {
                failures += 1;
                last_error_code = record.error_code.clone();
                continue;
            }
            break;
        }
        if failures >= NODE_UNREACHABLE_FAILURES {
            candidates.push(AlertCandidate {
                dedupe_key: format!("node:{node_id}:node_unreachable"),
                node_id: Some(node_id),
                severity: "critical",
                reason_code: "NODE_UNREACHABLE",
                methods: vec![PROBE_CONTROLLER_PING.to_string()],
                summary: json!({
                    "consecutive_failures": failures,
                    "last_error_code": last_error_code,
                }),
            });
        }
    }
    candidates
}

fn cert_expiry_candidates(observations: &[ProbeObservationRecord]) -> Vec<AlertCandidate> {
    let mut latest_by_node: BTreeMap<String, &ProbeObservationRecord> = BTreeMap::new();
    for observation in observations
        .iter()
        .filter(|record| record.method == OCSERV_CERT_EXPIRY)
    {
        let Some(node_id) = &observation.node_id else {
            continue;
        };
        let replace = latest_by_node
            .get(node_id)
            .is_none_or(|existing| observation.observed_at > existing.observed_at);
        if replace {
            latest_by_node.insert(node_id.clone(), observation);
        }
    }
    let mut candidates = Vec::new();
    for (node_id, observation) in latest_by_node {
        let Some(days_remaining) = min_days_remaining(&observation.summary_json) else {
            continue;
        };
        let (severity, reason_code, suffix) = if days_remaining <= 7 {
            (
                "critical",
                "CERT_EXPIRING_CRITICAL",
                "cert_expiring_critical",
            )
        } else if days_remaining <= 30 {
            ("warning", "CERT_EXPIRING_WARNING", "cert_expiring_warning")
        } else {
            continue;
        };
        candidates.push(AlertCandidate {
            dedupe_key: format!("node:{node_id}:{suffix}"),
            node_id: Some(node_id),
            severity,
            reason_code,
            methods: vec![OCSERV_CERT_EXPIRY.to_string()],
            summary: json!({
                "days_remaining": days_remaining,
            }),
        });
    }
    candidates
}

fn candidates_from_endpoint_trust(store: &Store) -> anyhow::Result<Vec<AlertCandidate>> {
    let mut candidates = Vec::new();
    for endpoint in store.trust_snapshot(None)?.endpoints {
        if matches!(
            endpoint.status,
            EndpointStatus::Revoked | EndpointStatus::Quarantined
        ) {
            candidates.push(AlertCandidate {
                dedupe_key: format!("endpoint:{}:endpoint_inactive", endpoint.endpoint_id),
                node_id: endpoint.node_id.clone(),
                severity: "critical",
                reason_code: "ENDPOINT_INACTIVE",
                methods: Vec::new(),
                summary: json!({
                    "endpoint_id": endpoint.endpoint_id,
                    "endpoint_status": endpoint.status.as_str(),
                }),
            });
        }
    }
    Ok(candidates)
}

fn upsert_candidate(
    store: &Store,
    existing_alerts: &[AlertEventRecord],
    candidate: AlertCandidate,
    now: &str,
) -> anyhow::Result<AlertEventRecord> {
    let existing = existing_alerts
        .iter()
        .find(|alert| alert.dedupe_key == candidate.dedupe_key);
    let mut detail = Map::new();
    detail.insert("methods".to_string(), json!(candidate.methods));
    detail.insert("summary".to_string(), safe_summary(&candidate.summary));
    let record = AlertEventRecord {
        alert_id: existing
            .map(|alert| alert.alert_id.clone())
            .unwrap_or_else(|| format!("alert-{}", Uuid::new_v4().simple())),
        dedupe_key: candidate.dedupe_key,
        node_id: candidate.node_id,
        severity: candidate.severity.to_string(),
        state: "open".to_string(),
        reason_code: candidate.reason_code.to_string(),
        first_seen_at: existing
            .map(|alert| alert.first_seen_at.clone())
            .unwrap_or_else(|| now.to_string()),
        last_seen_at: now.to_string(),
        last_sent_at: existing.and_then(|alert| alert.last_sent_at.clone()),
        resolved_at: None,
        detail_json: Value::Object(detail),
    };
    store.upsert_alert_event(&record)?;
    Ok(record)
}

fn reject_disabled_alert_hook(value: &str) -> anyhow::Result<()> {
    let (kind, rest) = value
        .split_once(':')
        .with_context(|| "alert hook must use kind:value syntax")?;
    let kind = kind.trim().to_ascii_lowercase();
    if matches!(kind.as_str(), "exec" | "command" | "script" | "shell") {
        bail!("forbidden alert hook type: {kind}");
    }
    match kind.as_str() {
        "jsonl_file" => {
            if rest.trim().is_empty() {
                bail!("jsonl_file hook requires a path");
            }
            bail!(
                "jsonl_file hooks are disabled until private alert directory support is implemented"
            );
        }
        "webhook" => {
            if rest.trim().is_empty() {
                bail!("webhook hook requires a url");
            }
            bail!("webhook hooks are disabled until HTTPS/HMAC/SSRF protections are implemented");
        }
        _ => bail!("unsupported alert hook type: {kind}"),
    }
}

fn find_alert(store: &Store, dedupe_key: &str) -> anyhow::Result<AlertEventRecord> {
    store
        .list_alert_events()?
        .into_iter()
        .find(|alert| alert.dedupe_key == dedupe_key)
        .with_context(|| format!("alert not found: {dedupe_key}"))
}

fn alert_to_json(alert: &AlertEventRecord) -> Value {
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
        "methods": alert_methods(alert),
        "summary": alert_summary(alert),
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

fn object_from_value(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
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

fn min_days_remaining(summary: &Value) -> Option<i64> {
    let direct = summary.get("days_remaining").and_then(Value::as_i64);
    let nested = summary
        .get("certs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|cert| cert.get("days_remaining").and_then(Value::as_i64))
        .min();
    match (direct, nested) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn is_unreachable_error_code(code: &str) -> bool {
    matches!(
        code,
        "CONNECT_FAILED"
            | "RPC_TIMEOUT"
            | "ENDPOINT_NOT_ALLOWED"
            | "ENDPOINT_MISMATCH"
            | "FRAME_READ_FAILED"
            | "RESPONSE_TOO_LARGE"
    )
}

fn parse_duration(value: &str) -> anyhow::Result<Duration> {
    let Some(unit) = value.chars().last() else {
        bail!("duration must use s, m, h, or d suffix");
    };
    let number = &value[..value.len().saturating_sub(unit.len_utf8())];
    let amount: i64 = number
        .parse()
        .with_context(|| format!("invalid duration value: {value}"))?;
    if amount <= 0 {
        bail!("duration must be greater than zero");
    }
    match unit {
        's' => Ok(Duration::seconds(amount)),
        'm' => Ok(Duration::minutes(amount)),
        'h' => Ok(Duration::hours(amount)),
        'd' => Ok(Duration::days(amount)),
        _ => bail!("duration must use s, m, h, or d suffix"),
    }
}

fn write_alert_audit(store: &Store, event_name: &str, detail_json: Value) -> anyhow::Result<()> {
    let mut event = AuditEvent::new(local_actor(), event_name);
    event.ok = Some(true);
    event.detail_json = detail_json;
    store.insert_audit(&event)?;
    Ok(())
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("RFC3339 formatting succeeds")
}

fn local_actor() -> String {
    match std::env::var("USER") {
        Ok(actor) if !actor.trim().is_empty() => actor,
        _ => "local-cli".to_string(),
    }
}
