use anyhow::Context;
use ocfleet_config::validation::validate_node_id;
use ocfleet_protocol::enrollment::EndpointStatus;
use ocfleet_protocol::method::{OCSERV_CERT_EXPIRY, OCSERV_SERVICE_SUMMARY, PROBE_CONTROLLER_PING};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::alert_delivery::{
    JsonlWriteSummary, deliver_jsonl_alerts, parse_alert_hook, validate_delivery_limit,
    write_jsonl_test_event,
};
use crate::alert_webhook::{
    MAX_WEBHOOK_ATTEMPTS, MAX_WEBHOOK_TIMEOUT_MS, MIN_WEBHOOK_TIMEOUT_MS, ReqwestWebhookSender,
    WebhookHttpResult, WebhookSender, build_webhook_request, hmac_key_id,
    is_retryable_webhook_error, read_hmac_secret_file, validate_webhook_endpoint,
    webhook_error_for_status, webhook_payload_bytes,
};
use crate::args::{AlertCommand, AlertHookCommand, AlertSeverity, AlertState};
use crate::audit::AuditEvent;
use crate::duration_args::parse_duration_seconds;
use crate::input_validation::{local_actor, validate_reason};
use crate::store::{
    AlertDeliveryAttemptRecord, AlertEventRecord, AlertWebhookHookRecord, HealthPolicyRecord,
    ProbeObservationRecord, Store,
};
use std::path::Path;
use std::thread;
use std::time::Duration as StdDuration;

const OBSERVATION_READ_LIMIT: u64 = 1_000;
const ALERT_DELIVERY_ERROR_CODE: &str = "ALERT_DELIVERY_FAILED";

#[derive(Debug, Clone)]
struct AlertCandidate {
    dedupe_key: String,
    node_id: Option<String>,
    severity: &'static str,
    reason_code: &'static str,
    methods: Vec<String>,
    summary: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlertEvaluationSummary {
    pub evaluated_candidates: usize,
    pub upserted_alerts: usize,
    pub open_alerts: usize,
    pub silenced_alerts: usize,
    pub created_or_updated_count: usize,
}

struct DeliveryAttemptOutcome<'a> {
    attempt_no: u64,
    status: &'a str,
    http_status_class: Option<&'a str>,
    error_code: Option<&'a str>,
    bytes_sent: usize,
}

pub fn run_alert_command(store: &Store, command: AlertCommand) -> anyhow::Result<()> {
    match command {
        AlertCommand::Hook { command } => run_alert_hook_command(store, command),
        AlertCommand::List {
            state,
            severity,
            node,
            json,
        } => run_alert_list(store, state, severity, node.as_deref(), json),
        AlertCommand::Test { hook } => run_alert_test(store, &hook),
        AlertCommand::Deliver {
            hook,
            limit,
            dry_run,
            hmac_secret_file,
        } => run_alert_deliver(store, &hook, limit, dry_run, hmac_secret_file.as_deref()),
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
    let (updated, _) = evaluate_alert_records(store)?;
    Ok(updated)
}

pub fn evaluate_alerts_with_summary(store: &Store) -> anyhow::Result<AlertEvaluationSummary> {
    let (_, summary) = evaluate_alert_records(store)?;
    Ok(summary)
}

fn evaluate_alert_records(
    store: &Store,
) -> anyhow::Result<(Vec<AlertEventRecord>, AlertEvaluationSummary)> {
    let now = now_rfc3339();
    let existing = store.list_alert_events()?;
    let policy = store.get_health_policy()?;
    let candidates = alert_candidates(store, &policy)?;
    let mut updated = Vec::new();
    for candidate in candidates {
        let record = upsert_candidate(store, &existing, candidate, &now)?;
        updated.push(record);
    }
    let summary = AlertEvaluationSummary {
        evaluated_candidates: updated.len(),
        upserted_alerts: updated.len(),
        open_alerts: updated.iter().filter(|alert| alert.state == "open").count(),
        silenced_alerts: updated
            .iter()
            .filter(|alert| alert.state == "silenced")
            .count(),
        created_or_updated_count: updated.len(),
    };
    Ok((updated, summary))
}

fn run_alert_list(
    store: &Store,
    state: Option<AlertState>,
    severity: Option<AlertSeverity>,
    node: Option<&str>,
    json_output: bool,
) -> anyhow::Result<()> {
    if let Some(node) = node {
        validate_node_id(node)?;
    }
    evaluate_alerts_and_audit(store)?;
    let state_filter = state.map(alert_state_name);
    let severity_filter = severity.map(alert_severity_name);
    let alerts = store.list_alert_events_filtered(state_filter, severity_filter, node)?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "generated_at": now_rfc3339(),
                "state_filter": state_filter,
                "severity_filter": severity_filter,
                "node_filter": node,
                "alert_count": alerts.len(),
                "alerts": alerts.iter().map(alert_to_json).collect::<Vec<_>>(),
            }))?
        );
    } else {
        println!("state_filter={}", state_filter.unwrap_or("<all>"));
        println!("severity_filter={}", severity_filter.unwrap_or("<all>"));
        println!("node_filter={}", node.unwrap_or("<all>"));
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

fn run_alert_hook_command(store: &Store, command: AlertHookCommand) -> anyhow::Result<()> {
    match command {
        AlertHookCommand::AddWebhook {
            name,
            url,
            hmac_secret_file,
            host_allow,
            max_attempts,
            timeout_ms,
        } => run_alert_hook_add_webhook(
            store,
            &name,
            &url,
            &hmac_secret_file,
            host_allow,
            max_attempts,
            timeout_ms,
        ),
        AlertHookCommand::List { json } => run_alert_hook_list(store, json),
        AlertHookCommand::Test {
            hook_id,
            dry_run,
            hmac_secret_file,
        } => run_alert_hook_test(store, &hook_id, dry_run, hmac_secret_file.as_deref()),
    }
}

fn run_alert_hook_add_webhook(
    store: &Store,
    name: &str,
    url: &str,
    hmac_secret_file: &Path,
    host_allow: Vec<String>,
    max_attempts: u64,
    timeout_ms: u64,
) -> anyhow::Result<()> {
    crate::input_validation::validate_description(name).map_err(anyhow::Error::msg)?;
    if !(1..=MAX_WEBHOOK_ATTEMPTS).contains(&max_attempts) {
        anyhow::bail!("max_attempts must be between 1 and {MAX_WEBHOOK_ATTEMPTS}");
    }
    if !(MIN_WEBHOOK_TIMEOUT_MS..=MAX_WEBHOOK_TIMEOUT_MS).contains(&timeout_ms) {
        anyhow::bail!(
            "timeout_ms must be between {MIN_WEBHOOK_TIMEOUT_MS} and {MAX_WEBHOOK_TIMEOUT_MS}"
        );
    }
    let endpoint = validate_webhook_endpoint(url, &host_allow)?;
    let secret = read_hmac_secret_file(hmac_secret_file)?;
    let now = now_rfc3339();
    let hook = AlertWebhookHookRecord {
        hook_id: format!("webhook-{}", Uuid::new_v4().simple()),
        name: name.trim().to_string(),
        hook_type: "webhook".to_string(),
        endpoint_url: endpoint.url,
        endpoint_url_redacted: endpoint.redacted_url,
        endpoint_host: endpoint.host,
        host_allow: endpoint.host_allow,
        hmac_key_id: hmac_key_id(&secret),
        enabled: true,
        max_attempts,
        timeout_ms,
        created_at: now.clone(),
        updated_at: now,
    };
    store.insert_alert_webhook_hook(&hook)?;
    write_alert_hook_audit(store, "alert.hook.add_webhook", &hook)?;
    println!("hook_id={}", hook.hook_id);
    println!("hook_type=webhook");
    println!("name={}", hook.name);
    println!("endpoint_host={}", hook.endpoint_host);
    println!("endpoint_url={}", hook.endpoint_url_redacted);
    println!("hmac_key_id={}", hook.hmac_key_id);
    println!("enabled={}", hook.enabled);
    Ok(())
}

fn run_alert_hook_list(store: &Store, json_output: bool) -> anyhow::Result<()> {
    let hooks = store.list_alert_webhook_hooks()?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "generated_at": now_rfc3339(),
                "hook_count": hooks.len(),
                "hooks": hooks.iter().map(webhook_hook_to_json).collect::<Vec<_>>(),
            }))?
        );
    } else {
        println!("hook_count={}", hooks.len());
        for hook in hooks {
            println!(
                "hook_id={} name={} hook_type={} enabled={} endpoint_host={} endpoint_url={} hmac_key_id={} max_attempts={} timeout_ms={}",
                hook.hook_id,
                hook.name,
                hook.hook_type,
                hook.enabled,
                hook.endpoint_host,
                hook.endpoint_url_redacted,
                hook.hmac_key_id,
                hook.max_attempts,
                hook.timeout_ms,
            );
        }
    }
    Ok(())
}

fn run_alert_hook_test(
    store: &Store,
    hook_id: &str,
    dry_run: bool,
    hmac_secret_file: Option<&Path>,
) -> anyhow::Result<()> {
    let hook = load_webhook_hook(store, hook_id)?;
    validate_webhook_endpoint(&hook.endpoint_url, &hook.host_allow)?;
    if let Some(path) = hmac_secret_file {
        let secret = read_hmac_secret_file(path)?;
        if hmac_key_id(&secret) != hook.hmac_key_id {
            anyhow::bail!("webhook HMAC secret does not match hook key id");
        }
    }
    if !dry_run {
        anyhow::bail!("webhook test requires --dry-run");
    }
    println!("status=ok");
    println!("hook_id={}", hook.hook_id);
    println!("hook_type=webhook");
    println!("endpoint_host={}", hook.endpoint_host);
    println!("endpoint_url={}", hook.endpoint_url_redacted);
    println!("dry_run=true");
    Ok(())
}

fn run_alert_test(_store: &Store, hook: &str) -> anyhow::Result<()> {
    let hook = parse_alert_hook(hook)?;
    let summary = write_jsonl_test_event(&hook)?;
    println!("status=ok");
    println!("hook_type={}", hook.hook_type());
    println!("test_event=true");
    println!("bytes_written={}", summary.bytes_written);
    Ok(())
}

fn run_alert_deliver(
    store: &Store,
    hook: &str,
    limit: u64,
    dry_run: bool,
    hmac_secret_file: Option<&Path>,
) -> anyhow::Result<()> {
    let hook = match parse_alert_hook(hook) {
        Ok(hook) => hook,
        Err(err) => {
            write_alert_delivery_audit(
                store,
                "rejected",
                false,
                0,
                0,
                dry_run,
                Some(ALERT_DELIVERY_ERROR_CODE),
            )?;
            return Err(err);
        }
    };
    let limit = match validate_delivery_limit(limit) {
        Ok(limit) => limit,
        Err(err) => {
            write_alert_delivery_audit(
                store,
                hook.hook_type(),
                false,
                0,
                0,
                dry_run,
                Some(ALERT_DELIVERY_ERROR_CODE),
            )?;
            return Err(err);
        }
    };
    evaluate_alerts_and_audit(store)?;
    let alerts = store
        .list_alert_events()?
        .into_iter()
        .filter(|alert| alert.state == "open")
        .take(limit)
        .collect::<Vec<_>>();

    let summary = match &hook {
        crate::alert_delivery::AlertHook::JsonlFile { .. } => {
            deliver_jsonl_alerts(&hook, &alerts, dry_run)
        }
        crate::alert_delivery::AlertHook::Webhook { hook_id } => {
            let sender = ReqwestWebhookSender::new()?;
            deliver_webhook_alerts_with_sender(
                store,
                hook_id,
                &alerts,
                dry_run,
                hmac_secret_file,
                &sender,
            )
        }
    };
    let summary = match summary {
        Ok(summary) => summary,
        Err(err) => {
            write_alert_delivery_audit(
                store,
                hook.hook_type(),
                false,
                alerts.len(),
                0,
                dry_run,
                Some(ALERT_DELIVERY_ERROR_CODE),
            )?;
            return Err(err);
        }
    };

    if !dry_run {
        let sent_at = now_rfc3339();
        for mut alert in alerts {
            alert.last_sent_at = Some(sent_at.clone());
            store.upsert_alert_event(&alert)?;
        }
    }
    write_alert_delivery_audit(
        store,
        hook.hook_type(),
        true,
        summary.record_count,
        summary.bytes_written,
        dry_run,
        None,
    )?;
    println!("status=ok");
    println!("hook_type={}", hook.hook_type());
    println!("alert_count={}", summary.record_count);
    println!("bytes_written={}", summary.bytes_written);
    println!("dry_run={dry_run}");
    Ok(())
}

pub fn deliver_webhook_alerts_with_sender(
    store: &Store,
    hook_id: &str,
    alerts: &[AlertEventRecord],
    dry_run: bool,
    hmac_secret_file: Option<&Path>,
    sender: &dyn WebhookSender,
) -> anyhow::Result<JsonlWriteSummary> {
    let hook = load_webhook_hook(store, hook_id)?;
    if !hook.enabled {
        anyhow::bail!("webhook hook is disabled");
    }
    let secret = if dry_run {
        None
    } else {
        let path = hmac_secret_file.context("webhook delivery requires --hmac-secret-file")?;
        let secret = read_hmac_secret_file(path)?;
        if hmac_key_id(&secret) != hook.hmac_key_id {
            anyhow::bail!("webhook HMAC secret does not match hook key id");
        }
        Some(secret)
    };
    validate_webhook_endpoint(&hook.endpoint_url, &hook.host_allow)?;

    let mut bytes_sent = 0_usize;
    for alert in alerts {
        if dry_run {
            let payload = crate::alert_delivery::alert_delivery_payload_for_hook(alert, "webhook");
            let body = webhook_payload_bytes(&payload)?;
            bytes_sent = bytes_sent
                .checked_add(body.len())
                .context("alert delivery byte count overflow")?;
            insert_delivery_attempt(
                store,
                alert,
                &hook,
                DeliveryAttemptOutcome {
                    attempt_no: 1,
                    status: "dry_run",
                    http_status_class: None,
                    error_code: None,
                    bytes_sent: body.len(),
                },
            )?;
            continue;
        }

        let secret = secret.as_deref().expect("secret present for non-dry-run");
        let mut final_error = None;
        for attempt_no in 1..=hook.max_attempts {
            let timestamp = now_rfc3339();
            let delivery_id = format!("delivery-{}", Uuid::new_v4().simple());
            let request = build_webhook_request(&hook, alert, secret, &timestamp, &delivery_id)?;
            let request_bytes = request.body.len();
            let result = sender.send(&request);
            match result {
                WebhookHttpResult::Completed(response) => {
                    let error_code = webhook_error_for_status(response.status_code);
                    if error_code.is_none() {
                        bytes_sent = bytes_sent
                            .checked_add(request_bytes)
                            .context("alert delivery byte count overflow")?;
                        insert_delivery_attempt(
                            store,
                            alert,
                            &hook,
                            DeliveryAttemptOutcome {
                                attempt_no,
                                status: "succeeded",
                                http_status_class: Some(response.status_class.as_str()),
                                error_code: None,
                                bytes_sent: request_bytes,
                            },
                        )?;
                        final_error = None;
                        break;
                    }
                    let error_code = error_code.expect("checked above");
                    insert_delivery_attempt(
                        store,
                        alert,
                        &hook,
                        DeliveryAttemptOutcome {
                            attempt_no,
                            status: "failed",
                            http_status_class: Some(response.status_class.as_str()),
                            error_code: Some(error_code),
                            bytes_sent: request_bytes,
                        },
                    )?;
                    final_error = Some(error_code);
                    if !is_retryable_webhook_error(error_code) || attempt_no == hook.max_attempts {
                        break;
                    }
                }
                WebhookHttpResult::Failed(failure) => {
                    insert_delivery_attempt(
                        store,
                        alert,
                        &hook,
                        DeliveryAttemptOutcome {
                            attempt_no,
                            status: "failed",
                            http_status_class: None,
                            error_code: Some(failure.error_code),
                            bytes_sent: request_bytes,
                        },
                    )?;
                    final_error = Some(failure.error_code);
                    if !is_retryable_webhook_error(failure.error_code)
                        || attempt_no == hook.max_attempts
                    {
                        break;
                    }
                }
            }
            bounded_backoff(attempt_no);
        }
        if let Some(error_code) = final_error {
            anyhow::bail!("webhook alert delivery failed: {error_code}");
        }
    }

    Ok(JsonlWriteSummary {
        record_count: alerts.len(),
        bytes_written: bytes_sent,
    })
}

fn evaluate_alerts_and_audit(store: &Store) -> anyhow::Result<AlertEvaluationSummary> {
    let summary = evaluate_alerts_with_summary(store)?;
    if summary.created_or_updated_count > 0 {
        write_alert_evaluation_audit(store, &summary)?;
    }
    Ok(summary)
}

fn run_alert_silence(
    store: &Store,
    dedupe_key: &str,
    for_duration: &str,
    reason: &str,
) -> anyhow::Result<()> {
    validate_reason(reason).map_err(anyhow::Error::msg)?;
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
    alert.state = "silenced".to_string();
    alert.resolved_at = None;
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
    validate_reason(reason).map_err(anyhow::Error::msg)?;
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

fn alert_candidates(
    store: &Store,
    policy: &HealthPolicyRecord,
) -> anyhow::Result<Vec<AlertCandidate>> {
    let mut candidates = Vec::new();
    candidates.extend(candidates_from_health_snapshots(store)?);
    candidates.extend(candidates_from_probe_observations(store, policy)?);
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
                    "consecutive_failures": snapshot.summary_json.get("consecutive_failures"),
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

fn candidates_from_probe_observations(
    store: &Store,
    policy: &HealthPolicyRecord,
) -> anyhow::Result<Vec<AlertCandidate>> {
    let observations = store.list_probe_observations(None, OBSERVATION_READ_LIMIT)?;
    let mut candidates = Vec::new();
    candidates.extend(node_unreachable_candidates(
        &observations,
        policy.unreachable_consecutive_failures,
    )?);
    candidates.extend(cert_expiry_candidates(&observations, policy)?);
    Ok(candidates)
}

fn node_unreachable_candidates(
    observations: &[ProbeObservationRecord],
    threshold: u64,
) -> anyhow::Result<Vec<AlertCandidate>> {
    let threshold =
        usize::try_from(threshold).context("unreachable failure threshold is too large")?;
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
        if failures >= threshold {
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
    Ok(candidates)
}

fn cert_expiry_candidates(
    observations: &[ProbeObservationRecord],
    policy: &HealthPolicyRecord,
) -> anyhow::Result<Vec<AlertCandidate>> {
    let critical_days =
        i64::try_from(policy.cert_critical_days).context("cert critical threshold is too large")?;
    let warning_days =
        i64::try_from(policy.cert_warning_days).context("cert warning threshold is too large")?;
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
        let (severity, reason_code, suffix) = if days_remaining <= critical_days {
            (
                "critical",
                "CERT_EXPIRING_CRITICAL",
                "cert_expiring_critical",
            )
        } else if days_remaining <= warning_days {
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
                "status": cert_status(&observation.summary_json),
            }),
        });
    }
    Ok(candidates)
}

fn candidates_from_endpoint_trust(store: &Store) -> anyhow::Result<Vec<AlertCandidate>> {
    let mut candidates = Vec::new();
    for endpoint in store.trust_snapshot(None)?.endpoints {
        if endpoint.status != EndpointStatus::Active {
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
    let keep_silenced = existing.is_some_and(|alert| alert_is_silenced(alert, now));
    let mut detail = existing
        .map(|alert| object_from_value(alert.detail_json.clone()))
        .unwrap_or_default();
    detail.insert("methods".to_string(), json!(candidate.methods));
    detail.insert(
        "summary".to_string(),
        crate::alert_projection::project_summary(&candidate.summary),
    );
    let record = AlertEventRecord {
        alert_id: existing
            .map(|alert| alert.alert_id.clone())
            .unwrap_or_else(|| format!("alert-{}", Uuid::new_v4().simple())),
        dedupe_key: candidate.dedupe_key,
        node_id: candidate.node_id,
        severity: candidate.severity.to_string(),
        state: if keep_silenced { "silenced" } else { "open" }.to_string(),
        reason_code: candidate.reason_code.to_string(),
        first_seen_at: existing
            .map(|alert| alert.first_seen_at.clone())
            .unwrap_or_else(|| now.to_string()),
        last_seen_at: now.to_string(),
        last_sent_at: existing.and_then(|alert| alert.last_sent_at.clone()),
        resolved_at: if keep_silenced {
            existing.and_then(|alert| alert.resolved_at.clone())
        } else {
            None
        },
        detail_json: Value::Object(detail),
    };
    store.upsert_alert_event(&record)?;
    Ok(record)
}

fn alert_is_silenced(alert: &AlertEventRecord, now: &str) -> bool {
    if alert.state != "silenced" {
        return false;
    }
    alert
        .detail_json
        .get("silenced_until")
        .and_then(Value::as_str)
        .is_some_and(|until| timestamp_after(until, now).unwrap_or(false))
}

fn timestamp_after(left: &str, right: &str) -> anyhow::Result<bool> {
    let left = OffsetDateTime::parse(left, &Rfc3339)?;
    let right = OffsetDateTime::parse(right, &Rfc3339)?;
    Ok(left > right)
}

fn find_alert(store: &Store, dedupe_key: &str) -> anyhow::Result<AlertEventRecord> {
    store
        .list_alert_events()?
        .into_iter()
        .find(|alert| alert.dedupe_key == dedupe_key)
        .with_context(|| format!("alert not found: {dedupe_key}"))
}

fn load_webhook_hook(store: &Store, hook_id: &str) -> anyhow::Result<AlertWebhookHookRecord> {
    store
        .get_alert_webhook_hook(hook_id)?
        .with_context(|| format!("webhook hook not found: {hook_id}"))
}

fn insert_delivery_attempt(
    store: &Store,
    alert: &AlertEventRecord,
    hook: &AlertWebhookHookRecord,
    outcome: DeliveryAttemptOutcome<'_>,
) -> anyhow::Result<()> {
    store.insert_alert_delivery_attempt(&AlertDeliveryAttemptRecord {
        attempt_id: format!("attempt-{}", Uuid::new_v4().simple()),
        alert_id: alert.alert_id.clone(),
        hook_id: hook.hook_id.clone(),
        attempt_no: outcome.attempt_no,
        attempted_at: now_rfc3339(),
        status: outcome.status.to_string(),
        http_status_class: outcome.http_status_class.map(str::to_string),
        error_code: outcome.error_code.map(str::to_string),
        bytes_sent: u64::try_from(outcome.bytes_sent).context("bytes_sent is too large")?,
    })?;
    Ok(())
}

fn bounded_backoff(attempt_no: u64) {
    let millis = 100_u64.saturating_mul(attempt_no.min(MAX_WEBHOOK_ATTEMPTS));
    thread::sleep(StdDuration::from_millis(millis));
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

fn webhook_hook_to_json(hook: &AlertWebhookHookRecord) -> Value {
    json!({
        "hook_id": hook.hook_id,
        "name": hook.name,
        "hook_type": hook.hook_type,
        "enabled": hook.enabled,
        "endpoint_host": hook.endpoint_host,
        "endpoint_url": hook.endpoint_url_redacted,
        "host_allow": hook.host_allow,
        "hmac_key_id": hook.hmac_key_id,
        "max_attempts": hook.max_attempts,
        "timeout_ms": hook.timeout_ms,
        "created_at": hook.created_at,
        "updated_at": hook.updated_at,
    })
}

fn alert_methods(alert: &AlertEventRecord) -> Vec<String> {
    crate::alert_projection::methods_from_detail(&alert.detail_json)
}

fn alert_summary(alert: &AlertEventRecord) -> Value {
    crate::alert_projection::summary_from_detail(&alert.detail_json)
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
    let direct = summary
        .get("days_remaining")
        .or_else(|| summary.get("min_days_remaining"))
        .and_then(Value::as_i64);
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

fn cert_status(summary: &Value) -> Option<&str> {
    summary
        .get("status")
        .or_else(|| summary.get("cert_status"))
        .and_then(Value::as_str)
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
    let seconds = parse_duration_seconds(value, "duration")?;
    let seconds = i64::try_from(seconds).context("duration is too large")?;
    Ok(Duration::seconds(seconds))
}

fn alert_state_name(state: AlertState) -> &'static str {
    match state {
        AlertState::Open => "open",
        AlertState::Silenced => "silenced",
        AlertState::Resolved => "resolved",
    }
}

fn alert_severity_name(severity: AlertSeverity) -> &'static str {
    match severity {
        AlertSeverity::Warning => "warning",
        AlertSeverity::Critical => "critical",
    }
}

fn write_alert_evaluation_audit(
    store: &Store,
    summary: &AlertEvaluationSummary,
) -> anyhow::Result<()> {
    let mut event = AuditEvent::new(local_actor(), "alert.evaluate");
    event.ok = Some(true);
    event.detail_json = json!({
        "evaluated_candidates": summary.evaluated_candidates,
        "upserted_alerts": summary.upserted_alerts,
        "open_alerts": summary.open_alerts,
        "silenced_alerts": summary.silenced_alerts,
        "created_or_updated_count": summary.created_or_updated_count,
    });
    store.insert_audit(&event)?;
    Ok(())
}

fn write_alert_audit(store: &Store, event_name: &str, detail_json: Value) -> anyhow::Result<()> {
    let mut event = AuditEvent::new(local_actor(), event_name);
    event.ok = Some(true);
    event.detail_json = detail_json;
    store.insert_audit(&event)?;
    Ok(())
}

fn write_alert_hook_audit(
    store: &Store,
    event_name: &str,
    hook: &AlertWebhookHookRecord,
) -> anyhow::Result<()> {
    let mut event = AuditEvent::new(local_actor(), event_name);
    event.ok = Some(true);
    event.detail_json = json!({
        "hook_id": hook.hook_id,
        "hook_type": hook.hook_type,
        "name": hook.name,
        "endpoint_host": hook.endpoint_host,
        "hmac_key_id": hook.hmac_key_id,
        "enabled": hook.enabled,
        "max_attempts": hook.max_attempts,
        "timeout_ms": hook.timeout_ms,
    });
    store.insert_audit(&event)?;
    Ok(())
}

fn write_alert_delivery_audit(
    store: &Store,
    hook_type: &str,
    ok: bool,
    alert_count: usize,
    bytes_written: usize,
    dry_run: bool,
    error_code: Option<&str>,
) -> anyhow::Result<()> {
    let mut event = AuditEvent::new(local_actor(), "alert.delivery");
    event.ok = Some(ok);
    let mut detail = Map::new();
    detail.insert("ok".to_string(), json!(ok));
    detail.insert("hook_type".to_string(), json!(hook_type));
    detail.insert("alert_count".to_string(), json!(alert_count));
    detail.insert("bytes_written".to_string(), json!(bytes_written));
    detail.insert("dry_run".to_string(), json!(dry_run));
    if let Some(error_code) = error_code {
        detail.insert("error_code".to_string(), json!(error_code));
    }
    event.detail_json = Value::Object(detail);
    store.insert_audit(&event)?;
    Ok(())
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("RFC3339 formatting succeeds")
}
