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
use crate::args::{AlertCommand, AlertHookCommand, AlertSeverity, AlertState, AlertWorkerCommand};
use crate::backend::StoreWriter;
use crate::duration_args::parse_duration_seconds;
use crate::input_validation::{local_actor, validate_reason};
use crate::observation::safe_observation_summary;
use crate::storage_payloads::{HealthDegradedMethodsPayloadV1, HealthSummaryPayloadV1};
use crate::store::{
    AlertDeliveryAttemptRecord, AlertDeliveryAttemptWrite, AlertDeliveryFinalizeWrite,
    AlertDeliveryQueueEnqueue, AlertDeliveryQueueOutcome, AlertEvaluationEntry,
    AlertEvaluationWrite, AlertEventRecord, AlertStateTransition, AlertWebhookHookRecord,
    HealthPolicyRecord, ProbeObservationRecord, Store,
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

pub async fn run_alert_command(store: &Store, command: AlertCommand) -> anyhow::Result<()> {
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
        AlertCommand::Worker { command } => run_alert_worker_command(store, command).await,
    }
}

const ALERT_WORKER_LEASE_SECONDS: u64 = 60;
const MAX_ALERT_WORKER_DELIVERIES: usize = 100;
const ALERT_WORKER_REPEAT_SECONDS: i64 = 300;
const MAX_ALERT_WORKER_PER_GROUP: usize = 3;
const ALERT_WORKER_GROUP_DEFER_SECONDS: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlertWorkerSummary {
    pub enqueued: usize,
    pub attempted: usize,
    pub succeeded: usize,
    pub retried: usize,
    pub dead_lettered: usize,
    pub deferred: usize,
}

async fn run_alert_worker_command(
    store: &Store,
    command: AlertWorkerCommand,
) -> anyhow::Result<()> {
    match command {
        AlertWorkerCommand::Run {
            hmac_secret_dir,
            max_deliveries,
            json,
        } => {
            let sender = ReqwestWebhookSender::new()?;
            let summary = run_alert_worker_once_with_sender(
                store,
                &hmac_secret_dir,
                max_deliveries,
                &sender,
            )?;
            print_alert_worker_summary(summary, json)?;
            Ok(())
        }
        AlertWorkerCommand::Daemon {
            hmac_secret_dir,
            interval_seconds,
            max_deliveries,
        } => {
            if !(10..=3_600).contains(&interval_seconds) {
                anyhow::bail!("--interval-seconds must be between 10 and 3600");
            }
            validate_alert_worker_max_deliveries(max_deliveries)?;
            let sender = ReqwestWebhookSender::new()?;
            let shutdown = alert_worker_shutdown_signal();
            tokio::pin!(shutdown);
            loop {
                run_alert_worker_once_with_sender(
                    store,
                    &hmac_secret_dir,
                    max_deliveries,
                    &sender,
                )?;
                tokio::select! {
                    _ = tokio::time::sleep(StdDuration::from_secs(interval_seconds)) => {}
                    _ = &mut shutdown => break,
                }
            }
            println!("status=stopped");
            Ok(())
        }
    }
}

pub fn run_alert_worker_once_with_sender(
    store: &Store,
    hmac_secret_dir: &Path,
    max_deliveries: usize,
    sender: &dyn WebhookSender,
) -> anyhow::Result<AlertWorkerSummary> {
    validate_alert_worker_max_deliveries(max_deliveries)?;
    crate::private_file::validate_existing_private_directory_strict(hmac_secret_dir)
        .context("--hmac-secret-dir must be an owned, non-symlink directory with mode 0700")?;
    evaluate_alerts_and_audit(store)?;
    let now = now_rfc3339();
    let now_instant = OffsetDateTime::parse(&now, &Rfc3339).expect("current timestamp parses");
    let hooks = store
        .list_alert_webhook_hooks()?
        .into_iter()
        .filter(|hook| hook.enabled)
        .collect::<Vec<_>>();
    let alerts = store
        .list_alert_events()?
        .into_iter()
        .filter(|alert| alert.state == "open")
        .map(|alert| alert_worker_alert_due(&alert, now_instant).map(|due| (alert, due)))
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .filter_map(|(alert, due)| due.then_some(alert))
        .collect::<Vec<_>>();
    let mut enqueued = 0;
    for hook in &hooks {
        for alert in &alerts {
            let idempotency_key = alert_queue_idempotency_key(alert, hook);
            StoreWriter::write_alert_delivery_queue_enqueue(
                store,
                &AlertDeliveryQueueEnqueue {
                    queue_id: alert_queue_id(&idempotency_key),
                    alert_id: alert.alert_id.clone(),
                    hook_id: hook.hook_id.clone(),
                    idempotency_key,
                    group_key: format!("{}:{}", alert.severity, alert.reason_code)
                        .to_ascii_lowercase(),
                    enqueued_at: now.clone(),
                },
                &local_actor(),
            )?;
            enqueued += 1;
        }
    }

    let owner_id = format!("alert-worker-{}", Uuid::new_v4().simple());
    let mut summary = AlertWorkerSummary {
        enqueued,
        attempted: 0,
        succeeded: 0,
        retried: 0,
        dead_lettered: 0,
        deferred: 0,
    };
    let mut group_counts = BTreeMap::<String, usize>::new();
    for _ in 0..max_deliveries.saturating_mul(2).min(200) {
        if summary.attempted >= max_deliveries {
            break;
        }
        let claim_now = now_rfc3339();
        let Some(claim) = StoreWriter::write_alert_delivery_queue_claim_next(
            store,
            &owner_id,
            &claim_now,
            ALERT_WORKER_LEASE_SECONDS,
            &local_actor(),
        )?
        else {
            break;
        };
        let group_count = group_counts.entry(claim.group_key.clone()).or_default();
        if *group_count >= MAX_ALERT_WORKER_PER_GROUP {
            let deferred_at = now_rfc3339();
            let next_attempt_at = (OffsetDateTime::now_utc()
                + Duration::seconds(ALERT_WORKER_GROUP_DEFER_SECONDS))
            .format(&Rfc3339)
            .expect("group defer timestamp formats");
            StoreWriter::write_alert_delivery_queue_defer(
                store,
                &claim,
                &deferred_at,
                &next_attempt_at,
                &local_actor(),
            )?;
            summary.deferred += 1;
            continue;
        }
        *group_count += 1;
        let alert = store
            .list_alert_events()?
            .into_iter()
            .find(|alert| alert.alert_id == claim.alert_id)
            .context("claimed delivery alert disappeared")?;
        let hook = load_webhook_hook(store, &claim.hook_id)?;
        let result =
            deliver_alert_queue_attempt(store, hmac_secret_dir, sender, &claim, &alert, &hook)?;
        summary.attempted += 1;
        match result {
            "succeeded" => summary.succeeded += 1,
            "retry" => summary.retried += 1,
            "dead_letter" => summary.dead_lettered += 1,
            _ => unreachable!("fixed queue outcome"),
        }
    }
    Ok(summary)
}

fn deliver_alert_queue_attempt(
    store: &Store,
    hmac_secret_dir: &Path,
    sender: &dyn WebhookSender,
    claim: &crate::store::AlertDeliveryQueueClaim,
    alert: &AlertEventRecord,
    hook: &AlertWebhookHookRecord,
) -> anyhow::Result<&'static str> {
    let attempted_at = now_rfc3339();
    let attempt_no = claim.attempt_count + 1;
    let secret_path = hmac_secret_dir.join(format!("{}.key", hook.hook_id));
    let preflight = read_hmac_secret_file(&secret_path).and_then(|secret| {
        if !hook.enabled {
            anyhow::bail!("webhook hook is disabled");
        }
        if hmac_key_id(&secret) != hook.hmac_key_id {
            anyhow::bail!("webhook HMAC secret does not match hook key id");
        }
        validate_webhook_endpoint(&hook.endpoint_url, &hook.host_allow)?;
        let delivery_id = format!("delivery-{}-{attempt_no}", claim.queue_id);
        build_webhook_request(hook, alert, &secret, &attempted_at, &delivery_id)
    });
    let (status, status_class, error_code, bytes_sent) = match preflight {
        Ok(request) => {
            let bytes_sent = request.body.len();
            match sender.send(&request) {
                WebhookHttpResult::Completed(response) => {
                    let error_code = webhook_error_for_status(response.status_code);
                    (
                        if error_code.is_none() {
                            "succeeded"
                        } else {
                            "failed"
                        },
                        Some(response.status_class),
                        error_code,
                        bytes_sent,
                    )
                }
                WebhookHttpResult::Failed(failure) => {
                    ("failed", None, Some(failure.error_code), bytes_sent)
                }
            }
        }
        Err(_) => ("failed", None, Some("ALERT_DELIVERY_PREFLIGHT_FAILED"), 0),
    };
    let completed_at = now_rfc3339();
    let retryable = error_code.is_some_and(is_retryable_webhook_error);
    let should_retry = status == "failed" && retryable && attempt_no < hook.max_attempts;
    let retry_at = should_retry.then(|| {
        let delay = 1_u64 << attempt_no.saturating_sub(1).min(8);
        (OffsetDateTime::now_utc() + Duration::seconds(delay as i64))
            .format(&Rfc3339)
            .expect("retry timestamp formats")
    });
    StoreWriter::write_alert_delivery_queue_outcome(
        store,
        &AlertDeliveryQueueOutcome {
            claim: claim.clone(),
            attempt: AlertDeliveryAttemptRecord {
                attempt_id: format!("attempt-{}-{attempt_no}", claim.queue_id),
                alert_id: claim.alert_id.clone(),
                hook_id: claim.hook_id.clone(),
                attempt_no,
                attempted_at,
                status: status.to_string(),
                http_status_class: status_class,
                error_code: error_code.map(str::to_string),
                bytes_sent: u64::try_from(bytes_sent).context("delivery body too large")?,
            },
            completed_at,
            retry_at,
            retryable,
            max_attempts: hook.max_attempts,
        },
        &local_actor(),
    )?;
    Ok(if status == "succeeded" {
        "succeeded"
    } else if should_retry {
        "retry"
    } else {
        "dead_letter"
    })
}

fn validate_alert_worker_max_deliveries(max_deliveries: usize) -> anyhow::Result<()> {
    if !(1..=MAX_ALERT_WORKER_DELIVERIES).contains(&max_deliveries) {
        anyhow::bail!("--max-deliveries must be between 1 and {MAX_ALERT_WORKER_DELIVERIES}");
    }
    Ok(())
}

fn alert_worker_alert_due(alert: &AlertEventRecord, now: OffsetDateTime) -> anyhow::Result<bool> {
    let Some(last_sent) = alert.last_sent_at.as_deref() else {
        return Ok(true);
    };
    let last_sent = OffsetDateTime::parse(last_sent, &Rfc3339)
        .context("stored alert last_sent_at is invalid")?;
    Ok(now - last_sent >= Duration::seconds(ALERT_WORKER_REPEAT_SECONDS))
}

fn alert_queue_idempotency_key(alert: &AlertEventRecord, hook: &AlertWebhookHookRecord) -> String {
    blake3::hash(
        format!(
            "{}:{}:{}:{}:{}",
            alert.alert_id, alert.last_seen_at, alert.reason_code, alert.state, hook.hook_id
        )
        .as_bytes(),
    )
    .to_hex()
    .to_string()
}

fn alert_queue_id(idempotency_key: &str) -> String {
    let digest = blake3::hash(idempotency_key.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!("delivery-queue-{}", Uuid::from_bytes(bytes))
}

fn print_alert_worker_summary(
    summary: AlertWorkerSummary,
    json_output: bool,
) -> anyhow::Result<()> {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": "ocfleet.alert_worker.v1",
                "enqueued": summary.enqueued,
                "attempted": summary.attempted,
                "succeeded": summary.succeeded,
                "retried": summary.retried,
                "dead_lettered": summary.dead_lettered,
                "deferred": summary.deferred,
            }))?
        );
    } else {
        println!("enqueued={}", summary.enqueued);
        println!("attempted={}", summary.attempted);
        println!("succeeded={}", summary.succeeded);
        println!("retried={}", summary.retried);
        println!("dead_lettered={}", summary.dead_lettered);
        println!("deferred={}", summary.deferred);
    }
    Ok(())
}

#[cfg(unix)]
fn alert_worker_shutdown_signal() -> impl std::future::Future<Output = ()> {
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .expect("install SIGINT handler");
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
    }
}

#[cfg(not(unix))]
async fn alert_worker_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
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
    let mut entries = Vec::new();
    for candidate in candidates {
        entries.push(candidate_record(&existing, candidate, &now));
    }
    let updated = entries
        .iter()
        .map(|entry| entry.after.clone())
        .collect::<Vec<_>>();
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
    if !updated.is_empty() {
        StoreWriter::write_alert_evaluation(
            store,
            &AlertEvaluationWrite {
                evaluation_id: format!("alert-eval-{}", Uuid::new_v4()),
                entries,
            },
            &local_actor(),
        )?;
    }
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
    StoreWriter::write_alert_webhook_hook_create(store, &hook, &local_actor())?;
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
    let delivery_id = format!("delivery-{}", Uuid::new_v4());
    let hook = match parse_alert_hook(hook) {
        Ok(hook) => hook,
        Err(err) => {
            write_alert_delivery_finalize(
                store,
                AlertDeliveryFinalizeWrite {
                    delivery_id: delivery_id.clone(),
                    hook_type: "rejected".to_string(),
                    ok: false,
                    dry_run,
                    alert_count: 0,
                    bytes_written: 0,
                    error_code: Some(ALERT_DELIVERY_ERROR_CODE.to_string()),
                    entries: Vec::new(),
                },
            )?;
            return Err(err);
        }
    };
    let limit = match validate_delivery_limit(limit) {
        Ok(limit) => limit,
        Err(err) => {
            write_alert_delivery_finalize(
                store,
                AlertDeliveryFinalizeWrite {
                    delivery_id: delivery_id.clone(),
                    hook_type: hook.hook_type().to_string(),
                    ok: false,
                    dry_run,
                    alert_count: 0,
                    bytes_written: 0,
                    error_code: Some(ALERT_DELIVERY_ERROR_CODE.to_string()),
                    entries: Vec::new(),
                },
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
            write_alert_delivery_finalize(
                store,
                AlertDeliveryFinalizeWrite {
                    delivery_id: delivery_id.clone(),
                    hook_type: hook.hook_type().to_string(),
                    ok: false,
                    dry_run,
                    alert_count: alerts.len(),
                    bytes_written: 0,
                    error_code: Some(ALERT_DELIVERY_ERROR_CODE.to_string()),
                    entries: Vec::new(),
                },
            )?;
            return Err(err);
        }
    };

    let entries = if dry_run {
        Vec::new()
    } else {
        let sent_at = now_rfc3339();
        alerts
            .iter()
            .cloned()
            .map(|before| {
                let mut after = before.clone();
                after.last_sent_at = Some(sent_at.clone());
                AlertEvaluationEntry {
                    before: Some(before),
                    after,
                }
            })
            .collect::<Vec<_>>()
    };
    write_alert_delivery_finalize(
        store,
        AlertDeliveryFinalizeWrite {
            delivery_id,
            hook_type: hook.hook_type().to_string(),
            ok: true,
            dry_run,
            alert_count: summary.record_count,
            bytes_written: summary.bytes_written,
            error_code: None,
            entries,
        },
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
    evaluate_alerts_with_summary(store)
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
    let before = find_alert(store, dedupe_key)?;
    let mut alert = before.clone();
    let mut detail = object_from_value(alert.detail_json);
    detail.insert("silenced_until".to_string(), Value::String(until.clone()));
    detail.insert(
        "silence_reason".to_string(),
        Value::String(reason.to_string()),
    );
    alert.state = "silenced".to_string();
    alert.resolved_at = None;
    alert.detail_json = Value::Object(detail);
    StoreWriter::write_alert_state_transition(
        store,
        &AlertStateTransition {
            operation_id: format!("alert-action-{}", Uuid::new_v4()),
            event: "alert.silence".to_string(),
            before,
            after: alert,
            reason: reason.to_string(),
        },
        &local_actor(),
    )?;
    println!("dedupe_key={dedupe_key}");
    println!("silenced_until={until}");
    Ok(())
}

fn run_alert_resolve(store: &Store, dedupe_key: &str, reason: &str) -> anyhow::Result<()> {
    validate_reason(reason).map_err(anyhow::Error::msg)?;
    let now = now_rfc3339();
    let before = find_alert(store, dedupe_key)?;
    let mut alert = before.clone();
    alert.state = "resolved".to_string();
    alert.resolved_at = Some(now.clone());
    alert.last_seen_at = now.clone();
    let mut detail = object_from_value(alert.detail_json);
    detail.insert(
        "resolve_reason".to_string(),
        Value::String(reason.to_string()),
    );
    alert.detail_json = Value::Object(detail);
    StoreWriter::write_alert_state_transition(
        store,
        &AlertStateTransition {
            operation_id: format!("alert-action-{}", Uuid::new_v4()),
            event: "alert.resolve".to_string(),
            before,
            after: alert,
            reason: reason.to_string(),
        },
        &local_actor(),
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
        let summary = HealthSummaryPayloadV1::from_value(&snapshot.summary_json)
            .map_err(anyhow::Error::msg)?;
        let degraded_methods =
            HealthDegradedMethodsPayloadV1::from_value(&snapshot.degraded_methods_json)
                .map_err(anyhow::Error::msg)?;
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
                    "consecutive_failures": summary.consecutive_failures,
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
                let methods = degraded_methods.methods;
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
        let summary = safe_observation_summary(&observation.summary_json);
        let Some(days_remaining) = min_days_remaining(&summary) else {
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
                "status": cert_status(&summary),
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

fn candidate_record(
    existing_alerts: &[AlertEventRecord],
    candidate: AlertCandidate,
    now: &str,
) -> AlertEvaluationEntry {
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
    let after = AlertEventRecord {
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
    AlertEvaluationEntry {
        before: existing.cloned(),
        after,
    }
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
    StoreWriter::write_alert_delivery_attempt(
        store,
        &AlertDeliveryAttemptWrite {
            attempt: AlertDeliveryAttemptRecord {
                attempt_id: format!("attempt-{}", Uuid::new_v4().simple()),
                alert_id: alert.alert_id.clone(),
                hook_id: hook.hook_id.clone(),
                attempt_no: outcome.attempt_no,
                attempted_at: now_rfc3339(),
                status: outcome.status.to_string(),
                http_status_class: outcome.http_status_class.map(str::to_string),
                error_code: outcome.error_code.map(str::to_string),
                bytes_sent: u64::try_from(outcome.bytes_sent).context("bytes_sent is too large")?,
            },
        },
        &local_actor(),
    )?;
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

fn write_alert_delivery_finalize(
    store: &Store,
    write: AlertDeliveryFinalizeWrite,
) -> anyhow::Result<()> {
    StoreWriter::write_alert_delivery_finalize(store, &write, &local_actor())?;
    Ok(())
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("RFC3339 formatting succeeds")
}
