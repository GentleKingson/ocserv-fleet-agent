use anyhow::{Context, bail};
use ocfleet_config::validation::validate_node_id;
use ocfleet_protocol::DEFAULT_DEADLINE_MS;
use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::method::{
    OCSERV_CERT_EXPIRY, OCSERV_CONFIG_FINGERPRINT, OCSERV_SERVICE_SUMMARY, OCSERV_SESSIONS_SUMMARY,
    OCSERV_VERSION, PROBE_CONTROLLER_PING, PROBE_PATH_ECHO,
};
use ocfleet_protocol::ocserv::{
    OcservCertExpiryResponse, OcservConfigFingerprintResponse, OcservServiceSummaryResponse,
    OcservSessionsSummaryResponse, OcservVersionResponse,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::alerts::{AlertEvaluationSummary, evaluate_alerts_with_summary};
use crate::args::{ScheduleCommand, ScheduleJobCommand, ScheduleJobKind, ScheduleRunCommand};
use crate::audit::AuditEvent;
use crate::backend::StoreWriter;
use crate::controller_rpc::{
    CONTROLLER_RPC_RESULT_CLASS, EndpointTrustRejection, FixedControllerRpc, OCSERV_RESULT_CLASS,
    OcservRpcOutcome, RpcAuditRecord, RpcCommandFailure, elapsed_ms, endpoint_trust_rejection,
    error_code_name, execute_fixed_node_rpc_from_database, hash_json_value,
    low_sensitive_fixed_rpc_summary, low_sensitive_ocserv_observation_summary,
    ocserv_failure_detail, rpc_audit_event,
};
use crate::input_validation::{validate_description, validate_selector};
use crate::storage_payloads::{SchedulerPairPayloadV1, SchedulerSelectorPayloadV1};
use crate::store::{
    InvalidObservabilityJobRecord, NodeRecord, ObservabilityJobLoadResult, ObservabilityJobRecord,
    ObservabilityRunRecord, ProbeObservationInsert, SchedulerJobClaim, SchedulerJobClockUpdate,
    SchedulerOutcomeEntry, SchedulerOutcomeWrite, SchedulerRunFinish, SchedulerRunStart, Store,
    StoreError,
};

const DEFAULT_SELECTOR: &str = "role=ocserv";
const EXPLICIT_PAIR_SELECTOR: &str = "explicit-pair";
const SCHEDULER_RESULT_CLASS: &str = "scheduler_summary";
const MIN_INTERVAL_SECONDS: u64 = 60;
const MAX_INTERVAL_SECONDS: u64 = 24 * 60 * 60;
const MIN_TICK_SECONDS: u64 = 10;
const MAX_TICK_SECONDS: u64 = 60 * 60;
pub const MAX_ALLOWED_CONCURRENCY: usize = 32;
const DEFAULT_PER_NODE_CONCURRENCY: usize = 1;
const DEFAULT_RPC_BUDGET_PER_TICK: usize = MAX_ALLOWED_CONCURRENCY * MAX_TARGETS_PER_JOB;
const MAX_TARGETS_PER_JOB: usize = 50;
const MAX_QUERY_LIMIT: u64 = 1_000;
const ALERT_EVALUATION_ERROR_CODE: &str = "ALERT_EVALUATION_FAILED";
const ALERT_EVALUATION_ERROR_MESSAGE: &str = "local alert evaluation failed";
const SCHEDULER_LEASE_SECONDS: u64 = 120;
const SCHEDULER_LEASE_RENEW_SECONDS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredJobKind {
    ControllerPing,
    OcservStatus,
    OcservCert,
    OcservSessions,
    PathProbe,
}

#[derive(Debug, Default)]
struct RunStats {
    due_jobs: usize,
    executed_jobs: usize,
    skipped_jobs: usize,
    observations: usize,
    failed_observations: usize,
    run_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SchedulerAlertEvaluation {
    ok: bool,
    evaluated_candidates: usize,
    alert_events_upserted: usize,
    open_alerts: usize,
    silenced_alerts: usize,
    created_or_updated_count: usize,
    error_code: Option<&'static str>,
    error_message: Option<&'static str>,
}

impl SchedulerAlertEvaluation {
    fn success(summary: AlertEvaluationSummary) -> Self {
        Self {
            ok: true,
            evaluated_candidates: summary.evaluated_candidates,
            alert_events_upserted: summary.upserted_alerts,
            open_alerts: summary.open_alerts,
            silenced_alerts: summary.silenced_alerts,
            created_or_updated_count: summary.created_or_updated_count,
            error_code: None,
            error_message: None,
        }
    }

    fn failure() -> Self {
        Self {
            ok: false,
            evaluated_candidates: 0,
            alert_events_upserted: 0,
            open_alerts: 0,
            silenced_alerts: 0,
            created_or_updated_count: 0,
            error_code: Some(ALERT_EVALUATION_ERROR_CODE),
            error_message: Some(ALERT_EVALUATION_ERROR_MESSAGE),
        }
    }

    fn status_label(self) -> &'static str {
        if self.ok { "ok" } else { "failed" }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SchedulerLimits {
    max_concurrency: usize,
    per_node_concurrency: usize,
    per_method_concurrency: usize,
    rpc_budget_per_tick: usize,
}

impl SchedulerLimits {
    fn from_max_concurrency(max_concurrency: usize) -> anyhow::Result<Self> {
        validate_scheduler_concurrency(max_concurrency)?;
        Ok(Self {
            max_concurrency,
            per_node_concurrency: DEFAULT_PER_NODE_CONCURRENCY,
            per_method_concurrency: max_concurrency,
            rpc_budget_per_tick: DEFAULT_RPC_BUDGET_PER_TICK,
        })
    }
}

struct SchedulerTickContext<'a> {
    store: &'a Store,
    database_path: &'a Path,
    secret_key_path: &'a Path,
    actor: &'a str,
    limits: SchedulerLimits,
    rpc_budget_remaining: &'a mut usize,
}

#[derive(Debug, Clone)]
struct TargetNode {
    node_id: String,
}

#[derive(Debug, Clone)]
struct ResolvedSchedulerTask {
    job_id: String,
    run_id: String,
    actor: String,
    kind: StoredJobKind,
    node: NodeRecord,
    rpc: SchedulerTaskRpc,
    method_key: String,
    ordinal: usize,
}

#[derive(Debug)]
enum PreparedSchedulerJob {
    NodeTargets {
        kind: StoredJobKind,
        targets: Vec<TargetNode>,
    },
    PathProbe,
}

#[derive(Debug, Clone)]
enum SchedulerTaskRpc {
    Fixed(FixedControllerRpc),
    OcservStatusBundle,
    PathProbe {
        target_node_id: String,
        target_endpoint_id: String,
    },
}

#[derive(Debug, Clone)]
struct SchedulerObservationOutcome {
    node_id: Option<String>,
    endpoint_id: Option<String>,
    method: String,
    ok: bool,
    error_code: Option<String>,
    duration_ms: u64,
    result_class: String,
    summary_json: Value,
}

#[derive(Debug, Clone)]
struct SchedulerTaskOutcome {
    task: ResolvedSchedulerTask,
    observations: Vec<SchedulerObservationOutcome>,
    rpc_audits: Vec<RpcAuditRecord>,
}

impl SchedulerTaskOutcome {
    fn from_observations(
        task: ResolvedSchedulerTask,
        observations: Vec<SchedulerObservationOutcome>,
        rpc_audits: Vec<RpcAuditRecord>,
    ) -> Self {
        Self {
            task,
            observations,
            rpc_audits,
        }
    }

    #[cfg(test)]
    fn all_observations_ok(&self) -> bool {
        self.observations.iter().all(|observation| observation.ok)
    }

    fn sort_key(&self) -> (&str, &str, &str, usize) {
        (
            self.task.job_id.as_str(),
            self.task.node.node_id.as_str(),
            self.task.method_key.as_str(),
            self.task.ordinal,
        )
    }
}

trait SchedulerTaskExecutor: Clone + Send + Sync + 'static {
    fn execute(
        &self,
        task: ResolvedSchedulerTask,
    ) -> Pin<Box<dyn Future<Output = SchedulerTaskOutcome> + Send>>;
}

#[derive(Clone)]
struct ProductionSchedulerTaskExecutor {
    database_path: Arc<PathBuf>,
    secret_key_path: Arc<PathBuf>,
}

impl SchedulerTaskExecutor for ProductionSchedulerTaskExecutor {
    fn execute(
        &self,
        task: ResolvedSchedulerTask,
    ) -> Pin<Box<dyn Future<Output = SchedulerTaskOutcome> + Send>> {
        let database_path = Arc::clone(&self.database_path);
        let secret_key_path = Arc::clone(&self.secret_key_path);
        Box::pin(async move {
            execute_production_scheduler_task(database_path, secret_key_path, task).await
        })
    }
}

pub fn parse_interval_seconds(value: &str) -> anyhow::Result<u64> {
    let Some(unit) = value.chars().last() else {
        bail!("interval must use s, m, h, or d suffix");
    };
    let number = &value[..value.len().saturating_sub(unit.len_utf8())];
    if number.is_empty() {
        bail!("interval must include a positive number");
    }
    let amount: i64 = number
        .parse()
        .with_context(|| format!("invalid interval value: {value}"))?;
    if amount <= 0 {
        bail!("interval must be greater than zero");
    }
    let multiplier = match unit {
        's' => 1_u64,
        'm' => 60,
        'h' => 60 * 60,
        'd' => 24 * 60 * 60,
        _ => bail!("interval must use s, m, h, or d suffix"),
    };
    let seconds = (amount as u64)
        .checked_mul(multiplier)
        .context("interval is too large")?;
    if seconds > i64::MAX as u64 {
        bail!("interval is too large");
    }
    if !(MIN_INTERVAL_SECONDS..=MAX_INTERVAL_SECONDS).contains(&seconds) {
        bail!("interval must be between {MIN_INTERVAL_SECONDS} and {MAX_INTERVAL_SECONDS} seconds");
    }
    Ok(seconds)
}

fn validate_scheduler_concurrency(max_concurrency: usize) -> anyhow::Result<()> {
    if max_concurrency == 0 {
        bail!("--max-concurrency must be greater than zero");
    }
    if max_concurrency > MAX_ALLOWED_CONCURRENCY {
        bail!("--max-concurrency must be between 1 and {MAX_ALLOWED_CONCURRENCY}");
    }
    Ok(())
}

fn validate_tick_seconds(tick_seconds: u64) -> anyhow::Result<()> {
    if !(MIN_TICK_SECONDS..=MAX_TICK_SECONDS).contains(&tick_seconds) {
        bail!("--tick-seconds must be between {MIN_TICK_SECONDS} and {MAX_TICK_SECONDS}");
    }
    Ok(())
}

pub async fn run_schedule_command(
    store: &Store,
    secret_key_path: &Path,
    actor: &str,
    command: ScheduleCommand,
) -> anyhow::Result<()> {
    match command {
        ScheduleCommand::Job { command } => run_schedule_job_command(store, actor, command),
        ScheduleCommand::Run {
            command,
            once,
            job_id,
            max_concurrency,
            json,
        } => match command {
            Some(ScheduleRunCommand::List { limit, json }) => {
                run_schedule_run_list(store, limit, json)
            }
            Some(ScheduleRunCommand::Show { run_id, json }) => {
                run_schedule_run_show(store, &run_id, json)
            }
            None => {
                run_schedule_run_once_command(
                    store,
                    secret_key_path,
                    actor,
                    once,
                    job_id.as_deref(),
                    max_concurrency,
                    json,
                )
                .await
            }
        },
        ScheduleCommand::Daemon {
            max_concurrency,
            tick_seconds,
        } => {
            run_schedule_daemon_command(
                store,
                secret_key_path,
                actor,
                max_concurrency,
                tick_seconds,
            )
            .await
        }
        ScheduleCommand::Status { json } => run_schedule_status_command(store, json),
    }
}

fn run_schedule_job_command(
    store: &Store,
    actor: &str,
    command: ScheduleJobCommand,
) -> anyhow::Result<()> {
    match command {
        ScheduleJobCommand::Add {
            name,
            kind,
            interval,
            selector,
            source_node_id,
            target_node_id,
        } => add_job(
            store,
            actor,
            AddJobInput {
                name,
                kind,
                interval,
                selector,
                source_node_id,
                target_node_id,
            },
        ),
        ScheduleJobCommand::List { json } => list_jobs(store, json),
        ScheduleJobCommand::Show { job_id, json } => show_job(store, &job_id, json),
        ScheduleJobCommand::Validate { job_id, json } => validate_job(store, &job_id, json),
        ScheduleJobCommand::Enable { job_id } => set_job_enabled(store, actor, &job_id, true),
        ScheduleJobCommand::Disable { job_id } => set_job_enabled(store, actor, &job_id, false),
    }
}

struct AddJobInput {
    name: Option<String>,
    kind: ScheduleJobKind,
    interval: String,
    selector: Option<String>,
    source_node_id: Option<String>,
    target_node_id: Option<String>,
}

fn add_job(store: &Store, actor: &str, input: AddJobInput) -> anyhow::Result<()> {
    if let Some(name) = &input.name {
        validate_description(name).map_err(anyhow::Error::msg)?;
    }
    let interval_seconds = parse_interval_seconds(&input.interval)?;
    let (selector_value, pair_selector_json) = build_selectors(
        input.kind,
        input.selector,
        input.source_node_id,
        input.target_node_id,
    )?;
    let now = now_rfc3339();
    let job = ObservabilityJobRecord {
        job_id: format!("job-{}", Uuid::new_v4().simple()),
        kind: schedule_kind_name(input.kind).to_string(),
        selector_json: SchedulerSelectorPayloadV1::new(selector_value.clone(), input.name)
            .map_err(anyhow::Error::msg)?
            .to_value(),
        pair_selector_json,
        interval_seconds,
        jitter_seconds: 0,
        timeout_ms: DEFAULT_DEADLINE_MS,
        enabled: true,
        next_run_at: Some(now.clone()),
        last_run_at: None,
        created_at: now.clone(),
        updated_at: now,
    };
    StoreWriter::write_scheduler_job_add(store, &job, actor)?;
    println!("job_id={}", job.job_id);
    println!("name={}", job_name(&job).unwrap_or("<none>"));
    println!("kind={}", job.kind);
    println!("enabled={}", job.enabled);
    println!("interval_seconds={}", job.interval_seconds);
    println!("selector={selector_value}");
    println!(
        "next_run_at={}",
        job.next_run_at.as_deref().unwrap_or("<none>")
    );
    Ok(())
}

fn list_jobs(store: &Store, json_output: bool) -> anyhow::Result<()> {
    let jobs = store.list_observability_jobs()?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "job_count": jobs.len(),
                "jobs": jobs.iter().map(job_to_json).collect::<Vec<_>>(),
            }))?
        );
        return Ok(());
    }
    for job in jobs {
        println!(
            "job_id={} name={} kind={} enabled={} interval_seconds={} selector={} next_run_at={} last_run_at={}",
            job.job_id,
            job_name(&job).unwrap_or("<none>"),
            job.kind,
            job.enabled,
            job.interval_seconds,
            selector_label(&job).unwrap_or("<invalid>"),
            job.next_run_at.as_deref().unwrap_or("<none>"),
            job.last_run_at.as_deref().unwrap_or("<none>")
        );
    }
    Ok(())
}

fn show_job(store: &Store, job_id: &str, json_output: bool) -> anyhow::Result<()> {
    let job = store
        .get_observability_job(job_id)?
        .with_context(|| format!("observability job not found: {job_id}"))?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "job": job_to_json(&job),
            }))?
        );
    } else {
        let pair = explicit_pair(&job).ok();
        println!("job_id={}", job.job_id);
        println!("name={}", job_name(&job).unwrap_or("<none>"));
        println!("kind={}", job.kind);
        println!("enabled={}", job.enabled);
        println!("interval_seconds={}", job.interval_seconds);
        println!("jitter_seconds={}", job.jitter_seconds);
        println!("timeout_ms={}", job.timeout_ms);
        println!("selector={}", selector_label(&job).unwrap_or("<invalid>"));
        println!(
            "source_node_id={}",
            pair.as_ref()
                .map(|(source, _)| source.as_str())
                .unwrap_or("<none>")
        );
        println!(
            "target_node_id={}",
            pair.as_ref()
                .map(|(_, target)| target.as_str())
                .unwrap_or("<none>")
        );
        println!(
            "next_run_at={}",
            job.next_run_at.as_deref().unwrap_or("<none>")
        );
        println!(
            "last_run_at={}",
            job.last_run_at.as_deref().unwrap_or("<none>")
        );
        println!("created_at={}", job.created_at);
        println!("updated_at={}", job.updated_at);
    }
    Ok(())
}

fn validate_job(store: &Store, job_id: &str, json_output: bool) -> anyhow::Result<()> {
    let result = store
        .get_observability_job_tolerant(job_id)?
        .with_context(|| format!("observability job not found: {job_id}"))?;
    let validation = match result {
        ObservabilityJobLoadResult::Valid(job) => validate_job_config(store, &job),
        ObservabilityJobLoadResult::Invalid(job) => JobValidation {
            job_id: job.job_id,
            valid: false,
            reason_code: Some(job.reason_code),
            message: "stored scheduler job row is invalid".to_string(),
            target_count: 0,
        },
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "job_id": validation.job_id,
                "valid": validation.valid,
                "reason_code": validation.reason_code,
                "message": validation.message,
                "target_count": validation.target_count,
            }))?
        );
    } else {
        println!("job_id={}", validation.job_id);
        println!("valid={}", validation.valid);
        println!(
            "reason_code={}",
            validation.reason_code.as_deref().unwrap_or("<none>")
        );
        println!("message={}", validation.message);
        println!("target_count={}", validation.target_count);
    }
    if !validation.valid {
        bail!("scheduler job validation failed: {}", validation.message);
    }
    Ok(())
}

#[derive(Debug)]
struct JobValidation {
    job_id: String,
    valid: bool,
    reason_code: Option<String>,
    message: String,
    target_count: usize,
}

fn validate_job_config(store: &Store, job: &ObservabilityJobRecord) -> JobValidation {
    match validate_job_config_inner(store, job) {
        Ok(target_count) => JobValidation {
            job_id: job.job_id.clone(),
            valid: true,
            reason_code: None,
            message: "ok".to_string(),
            target_count,
        },
        Err((reason_code, message)) => JobValidation {
            job_id: job.job_id.clone(),
            valid: false,
            reason_code: Some(reason_code),
            message,
            target_count: 0,
        },
    }
}

fn validate_job_config_inner(
    store: &Store,
    job: &ObservabilityJobRecord,
) -> Result<usize, (String, String)> {
    let kind =
        stored_job_kind(&job.kind).map_err(|err| ("INVALID_KIND".to_string(), err.to_string()))?;
    match kind {
        StoredJobKind::PathProbe => {
            let (source, target) = explicit_pair(job)
                .map_err(|err| ("INVALID_PATH_PAIR".to_string(), err.to_string()))?;
            validate_registry_node(store, &source)?;
            validate_registry_node(store, &target)?;
            Ok(2)
        }
        StoredJobKind::ControllerPing
        | StoredJobKind::OcservStatus
        | StoredJobKind::OcservCert
        | StoredJobKind::OcservSessions => {
            let selector = selector_label(job)
                .map_err(|err| ("INVALID_SELECTOR".to_string(), err.to_string()))?;
            let targets = resolve_node_targets(store, selector)
                .map_err(|err| ("INVALID_SELECTOR".to_string(), err.to_string()))?;
            if targets.is_empty() {
                return Err((
                    "NO_MATCHING_NODES".to_string(),
                    "selector matched no nodes".to_string(),
                ));
            }
            for target in &targets {
                validate_registry_node(store, &target.node_id)?;
            }
            Ok(targets.len())
        }
    }
}

fn validate_registry_node(store: &Store, node_id: &str) -> Result<(), (String, String)> {
    validate_node_id(node_id).map_err(|err| ("INVALID_NODE_ID".to_string(), err.to_string()))?;
    let node = store
        .get_node(node_id)
        .map_err(|err| ("STORE_ERROR".to_string(), err.to_string()))?
        .ok_or_else(|| {
            (
                "NODE_NOT_FOUND".to_string(),
                format!("node not found: {node_id}"),
            )
        })?;
    if !node.enabled {
        return Err((
            "NODE_DISABLED".to_string(),
            format!("node disabled: {node_id}"),
        ));
    }
    Ok(())
}

fn set_job_enabled(store: &Store, actor: &str, job_id: &str, enabled: bool) -> anyhow::Result<()> {
    if enabled {
        StoreWriter::write_scheduler_job_enable(store, job_id, actor)?;
    } else {
        StoreWriter::write_scheduler_job_disable(store, job_id, actor)?;
    }
    println!("job_id={job_id}");
    println!("enabled={enabled}");
    Ok(())
}

async fn run_schedule_run_once_command(
    store: &Store,
    secret_key_path: &Path,
    actor: &str,
    once: bool,
    job_id: Option<&str>,
    max_concurrency: usize,
    json_output: bool,
) -> anyhow::Result<()> {
    if !once {
        bail!("schedule run currently requires --once");
    }
    let owner_id = scheduler_owner_id();
    let stats = if let Some(job_id) = job_id {
        run_target_job_once(
            store,
            secret_key_path,
            actor,
            &owner_id,
            job_id,
            max_concurrency,
        )
        .await?
    } else {
        run_due_jobs_once(store, secret_key_path, actor, &owner_id, max_concurrency).await?
    };
    let alert_evaluation = evaluate_scheduler_alerts(store);
    write_scheduler_audit(
        store,
        actor,
        "scheduler.run.once",
        true,
        scheduler_run_once_detail_json(&stats, job_id, max_concurrency, &alert_evaluation),
    )?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "ok",
                "job_id": job_id,
                "due_jobs": stats.due_jobs,
                "executed_jobs": stats.executed_jobs,
                "skipped_jobs": stats.skipped_jobs,
                "observations": stats.observations,
                "failed_observations": stats.failed_observations,
                "run_ids": stats.run_ids,
                "alert_evaluation": alert_evaluation.status_label(),
                "alert_events": alert_evaluation.alert_events_upserted,
            }))?
        );
    } else {
        println!("status=ok");
        println!("job_id={}", job_id.unwrap_or("<all-due>"));
        println!("due_jobs={}", stats.due_jobs);
        println!("executed_jobs={}", stats.executed_jobs);
        println!("skipped_jobs={}", stats.skipped_jobs);
        println!("observations={}", stats.observations);
        println!("failed_observations={}", stats.failed_observations);
        println!("run_ids={}", comma_list_or_none(&stats.run_ids));
        println!("alert_evaluation={}", alert_evaluation.status_label());
        println!("alert_events={}", alert_evaluation.alert_events_upserted);
    }
    Ok(())
}

fn run_schedule_run_list(store: &Store, limit: u64, json_output: bool) -> anyhow::Result<()> {
    let limit = validate_query_limit(limit)?;
    let runs = store.list_observability_runs(limit)?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "limit": limit,
                "run_count": runs.len(),
                "runs": runs.iter().map(run_to_json).collect::<Vec<_>>(),
            }))?
        );
    } else {
        println!("limit={limit}");
        println!("run_count={}", runs.len());
        for run in &runs {
            print_run_human(run);
        }
    }
    Ok(())
}

fn run_schedule_run_show(store: &Store, run_id: &str, json_output: bool) -> anyhow::Result<()> {
    let run = store
        .get_observability_run(run_id)?
        .with_context(|| format!("observability run not found: {run_id}"))?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "run": run_to_json(&run),
            }))?
        );
    } else {
        print_run_human(&run);
    }
    Ok(())
}

async fn run_schedule_daemon_command(
    store: &Store,
    secret_key_path: &Path,
    actor: &str,
    max_concurrency: usize,
    tick_seconds: u64,
) -> anyhow::Result<()> {
    validate_scheduler_concurrency(max_concurrency)?;
    validate_tick_seconds(tick_seconds)?;
    write_scheduler_audit(
        store,
        actor,
        "scheduler.daemon.start",
        true,
        json!({
            "tick_seconds": tick_seconds,
            "max_concurrency": max_concurrency,
            "result_class": SCHEDULER_RESULT_CLASS,
        }),
    )?;

    let owner_id = scheduler_owner_id();

    loop {
        run_due_jobs_once(store, secret_key_path, actor, &owner_id, max_concurrency).await?;
        let alert_evaluation = evaluate_scheduler_alerts(store);
        write_scheduler_audit(
            store,
            actor,
            "scheduler.alert.evaluate",
            alert_evaluation.ok,
            scheduler_alert_evaluation_detail_json(&alert_evaluation),
        )?;
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(tick_seconds)) => {}
            _ = shutdown_signal() => {
                break;
            }
        }
    }

    write_scheduler_audit(
        store,
        actor,
        "scheduler.daemon.stop",
        true,
        json!({
            "tick_seconds": tick_seconds,
            "max_concurrency": max_concurrency,
            "result_class": SCHEDULER_RESULT_CLASS,
        }),
    )?;
    println!("status=stopped");
    Ok(())
}

fn run_schedule_status_command(store: &Store, json_output: bool) -> anyhow::Result<()> {
    let jobs = store.list_observability_jobs()?;
    let now = OffsetDateTime::now_utc();
    let enabled_job_count = jobs.iter().filter(|job| job.enabled).count();
    let due_job_count = jobs
        .iter()
        .filter(|job| job.enabled)
        .filter(|job| job_due_at_or_before(job, now).unwrap_or(true))
        .count();
    let last_run = jobs
        .iter()
        .filter_map(|job| job.last_run_at.as_ref().map(|last| (last, job)))
        .max_by(|(left, _), (right, _)| left.cmp(right));

    if json_output {
        let last_run_job_id = last_run.map(|(_, job)| job.job_id.as_str());
        let last_run_at = last_run.map(|(last_run_at, _)| last_run_at.as_str());
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "enabled_jobs": enabled_job_count,
                "due_jobs": due_job_count,
                "last_run_job_id": last_run_job_id,
                "last_run_at": last_run_at,
            }))?
        );
    } else {
        println!("enabled_jobs={enabled_job_count}");
        println!("due_jobs={due_job_count}");
        if let Some((last_run_at, job)) = last_run {
            println!("last_run_job_id={}", job.job_id);
            println!("last_run_at={last_run_at}");
        } else {
            println!("last_run_job_id=<none>");
            println!("last_run_at=<none>");
        }
    }
    Ok(())
}

async fn run_due_jobs_once(
    store: &Store,
    secret_key_path: &Path,
    actor: &str,
    owner_id: &str,
    max_concurrency: usize,
) -> anyhow::Result<RunStats> {
    let limits = SchedulerLimits::from_max_concurrency(max_concurrency)?;
    let mut rpc_budget_remaining = limits.rpc_budget_per_tick;
    let mut tick_context = SchedulerTickContext {
        store,
        database_path: store.database_path(),
        secret_key_path,
        actor,
        limits,
        rpc_budget_remaining: &mut rpc_budget_remaining,
    };
    let jobs = store.list_observability_jobs_tolerant()?;
    let now = OffsetDateTime::now_utc();
    let mut stats = RunStats {
        skipped_jobs: jobs
            .iter()
            .filter(|job| match job {
                ObservabilityJobLoadResult::Valid(job) => !job.enabled,
                ObservabilityJobLoadResult::Invalid(job) => !job.enabled,
            })
            .count(),
        ..RunStats::default()
    };
    for job_load in jobs {
        let job = match job_load {
            ObservabilityJobLoadResult::Valid(job) => job,
            ObservabilityJobLoadResult::Invalid(job) => {
                if !job.enabled {
                    continue;
                }
                if !invalid_job_due_at_or_before(&job, now) {
                    continue;
                }
                stats.due_jobs += 1;
                let Some(claim) = try_claim_due_job(store, &job.job_id, owner_id, actor)? else {
                    stats.skipped_jobs += 1;
                    continue;
                };
                let write_result =
                    record_invalid_scheduler_job_record_observation(store, actor, &job);
                let release_result = release_scheduler_claim(store, &claim, actor);
                write_result?;
                release_result?;
                stats.executed_jobs += 1;
                stats.observations += 1;
                stats.failed_observations += 1;
                continue;
            }
        };
        if !job.enabled {
            continue;
        }
        let due = match job_due_at_or_before(&job, now) {
            Ok(due) => due,
            Err(_) => {
                stats.due_jobs += 1;
                let Some(claim) = try_claim_due_job(store, &job.job_id, owner_id, actor)? else {
                    stats.skipped_jobs += 1;
                    continue;
                };
                let finished_at = now_rfc3339();
                let clock = scheduler_job_clock(&job, &finished_at)?;
                let write_result = record_invalid_scheduler_job_observation(
                    store,
                    actor,
                    &job,
                    "INVALID_NEXT_RUN_AT",
                    Some(clock),
                );
                let release_result = release_scheduler_claim(store, &claim, actor);
                write_result?;
                release_result?;
                stats.executed_jobs += 1;
                stats.observations += 1;
                stats.failed_observations += 1;
                continue;
            }
        };
        if !due {
            continue;
        }
        stats.due_jobs += 1;
        let Some(claim) = try_claim_due_job(store, &job.job_id, owner_id, actor)? else {
            stats.skipped_jobs += 1;
            continue;
        };
        let prepared = match prepare_scheduler_job(store, &job) {
            Ok(prepared) => prepared,
            Err(err) if err.downcast_ref::<StoreError>().is_some() => {
                release_scheduler_claim(store, &claim, actor)?;
                return Err(err);
            }
            Err(_) => {
                let finished_at = now_rfc3339();
                let clock = scheduler_job_clock(&job, &finished_at)?;
                let write_result = record_invalid_scheduler_job_observation(
                    store,
                    actor,
                    &job,
                    "INVALID_JOB_CONFIGURATION",
                    Some(clock),
                );
                let release_result = release_scheduler_claim(store, &claim, actor);
                write_result?;
                release_result?;
                stats.executed_jobs += 1;
                stats.observations += 1;
                stats.failed_observations += 1;
                continue;
            }
        };
        let job_result = run_job(&mut tick_context, &job, prepared, &claim).await;
        let release_result = release_scheduler_claim(store, &claim, actor);
        let job_stats = job_result?;
        release_result?;
        stats.executed_jobs += 1;
        stats.observations += job_stats.observations;
        stats.failed_observations += job_stats.failed_observations;
        stats.run_ids.extend(job_stats.run_ids);
    }
    Ok(stats)
}

async fn run_target_job_once(
    store: &Store,
    secret_key_path: &Path,
    actor: &str,
    owner_id: &str,
    job_id: &str,
    max_concurrency: usize,
) -> anyhow::Result<RunStats> {
    let job = match store
        .get_observability_job_tolerant(job_id)?
        .with_context(|| format!("observability job not found: {job_id}"))?
    {
        ObservabilityJobLoadResult::Valid(job) => job,
        ObservabilityJobLoadResult::Invalid(job) => {
            bail!(
                "observability job {} is invalid: {}",
                job.job_id,
                job.reason_code
            );
        }
    };
    if !job.enabled {
        bail!("observability job is disabled: {job_id}");
    }
    let prepared = prepare_scheduler_job(store, &job)?;
    validate_prepared_scheduler_job(store, &job, &prepared)?;

    let limits = SchedulerLimits::from_max_concurrency(max_concurrency)?;
    let mut rpc_budget_remaining = limits.rpc_budget_per_tick;
    let mut tick_context = SchedulerTickContext {
        store,
        database_path: store.database_path(),
        secret_key_path,
        actor,
        limits,
        rpc_budget_remaining: &mut rpc_budget_remaining,
    };
    let claim = StoreWriter::write_scheduler_claim(
        store,
        job_id,
        owner_id,
        &now_rfc3339(),
        SCHEDULER_LEASE_SECONDS,
        actor,
    )?
    .with_context(|| format!("observability job is already claimed: {job_id}"))?;
    let job_result = run_job(&mut tick_context, &job, prepared, &claim).await;
    let release_result = release_scheduler_claim(store, &claim, actor);
    let job_stats = job_result?;
    release_result?;
    Ok(RunStats {
        due_jobs: 1,
        executed_jobs: 1,
        skipped_jobs: 0,
        observations: job_stats.observations,
        failed_observations: job_stats.failed_observations,
        run_ids: job_stats.run_ids,
    })
}

fn invalid_job_due_at_or_before(job: &InvalidObservabilityJobRecord, now: OffsetDateTime) -> bool {
    job.next_run_at
        .as_deref()
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .is_none_or(|next_run_at| next_run_at <= now)
}

fn try_claim_due_job(
    store: &Store,
    job_id: &str,
    owner_id: &str,
    actor: &str,
) -> Result<Option<SchedulerJobClaim>, StoreError> {
    StoreWriter::write_scheduler_claim_due(
        store,
        job_id,
        owner_id,
        &now_rfc3339(),
        SCHEDULER_LEASE_SECONDS,
        actor,
    )
}

fn release_scheduler_claim(
    store: &Store,
    claim: &SchedulerJobClaim,
    actor: &str,
) -> Result<(), StoreError> {
    StoreWriter::write_scheduler_claim_release(store, claim, &now_rfc3339(), actor)
}

fn scheduler_owner_id() -> String {
    format!("scheduler-{}", Uuid::new_v4().simple())
}

fn evaluate_scheduler_alerts(store: &Store) -> SchedulerAlertEvaluation {
    match evaluate_alerts_with_summary(store) {
        Ok(summary) => SchedulerAlertEvaluation::success(summary),
        Err(_err) => SchedulerAlertEvaluation::failure(),
    }
}

fn scheduler_run_once_detail_json(
    stats: &RunStats,
    job_id: Option<&str>,
    max_concurrency: usize,
    alert_evaluation: &SchedulerAlertEvaluation,
) -> Value {
    let mut detail = Map::new();
    if let Some(job_id) = job_id {
        detail.insert("job_id".to_string(), json!(job_id));
    }
    detail.insert("due_jobs".to_string(), json!(stats.due_jobs));
    detail.insert("executed_jobs".to_string(), json!(stats.executed_jobs));
    detail.insert("skipped_jobs".to_string(), json!(stats.skipped_jobs));
    detail.insert("observations".to_string(), json!(stats.observations));
    detail.insert(
        "failed_observations".to_string(),
        json!(stats.failed_observations),
    );
    detail.insert("run_ids".to_string(), json!(&stats.run_ids));
    detail.insert("max_concurrency".to_string(), json!(max_concurrency));
    append_alert_evaluation_detail(&mut detail, alert_evaluation);
    detail.insert("result_class".to_string(), json!(SCHEDULER_RESULT_CLASS));
    Value::Object(detail)
}

fn scheduler_alert_evaluation_detail_json(alert_evaluation: &SchedulerAlertEvaluation) -> Value {
    let mut detail = Map::new();
    append_alert_evaluation_detail(&mut detail, alert_evaluation);
    detail.insert("result_class".to_string(), json!(SCHEDULER_RESULT_CLASS));
    Value::Object(detail)
}

fn append_alert_evaluation_detail(
    detail: &mut Map<String, Value>,
    alert_evaluation: &SchedulerAlertEvaluation,
) {
    detail.insert(
        "alert_evaluation_ok".to_string(),
        json!(alert_evaluation.ok),
    );
    detail.insert(
        "alert_evaluated_candidates".to_string(),
        json!(alert_evaluation.evaluated_candidates),
    );
    detail.insert(
        "alert_events_upserted".to_string(),
        json!(alert_evaluation.alert_events_upserted),
    );
    detail.insert(
        "alert_open_alerts".to_string(),
        json!(alert_evaluation.open_alerts),
    );
    detail.insert(
        "alert_silenced_alerts".to_string(),
        json!(alert_evaluation.silenced_alerts),
    );
    detail.insert(
        "alert_created_or_updated_count".to_string(),
        json!(alert_evaluation.created_or_updated_count),
    );
    if let Some(code) = alert_evaluation.error_code {
        detail.insert("alert_evaluation_error_code".to_string(), json!(code));
    }
    if let Some(message) = alert_evaluation.error_message {
        detail.insert("alert_evaluation_error_message".to_string(), json!(message));
    }
}

fn scheduler_job_clock(
    job: &ObservabilityJobRecord,
    finished_at: &str,
) -> anyhow::Result<SchedulerJobClockUpdate> {
    let interval_seconds =
        i64::try_from(job.interval_seconds).context("scheduler job interval is too large")?;
    let next_run_at = offset_to_rfc3339(
        OffsetDateTime::parse(finished_at, &Rfc3339)
            .context("scheduler finished_at must be RFC3339")?
            + Duration::seconds(interval_seconds),
    );
    Ok(SchedulerJobClockUpdate {
        job_id: job.job_id.clone(),
        next_run_at,
        last_run_at: finished_at.to_string(),
    })
}

fn prepare_scheduler_job(
    store: &Store,
    job: &ObservabilityJobRecord,
) -> anyhow::Result<PreparedSchedulerJob> {
    let kind = stored_job_kind(&job.kind)?;
    match kind {
        StoredJobKind::PathProbe => {
            let (source_node_id, target_node_id) = explicit_pair(job)?;
            validate_node_id(&source_node_id).map_err(anyhow::Error::msg)?;
            validate_node_id(&target_node_id).map_err(anyhow::Error::msg)?;
            Ok(PreparedSchedulerJob::PathProbe)
        }
        StoredJobKind::ControllerPing
        | StoredJobKind::OcservStatus
        | StoredJobKind::OcservCert
        | StoredJobKind::OcservSessions => {
            let targets = resolve_node_targets(store, selector_label(job)?)?;
            for target in &targets {
                validate_node_id(&target.node_id).map_err(anyhow::Error::msg)?;
            }
            Ok(PreparedSchedulerJob::NodeTargets { kind, targets })
        }
    }
}

fn validate_prepared_scheduler_job(
    store: &Store,
    job: &ObservabilityJobRecord,
    prepared: &PreparedSchedulerJob,
) -> anyhow::Result<()> {
    let node_ids = match prepared {
        PreparedSchedulerJob::PathProbe => {
            let (source_node_id, target_node_id) = explicit_pair(job)?;
            vec![source_node_id, target_node_id]
        }
        PreparedSchedulerJob::NodeTargets { targets, .. } => {
            if targets.is_empty() {
                bail!("scheduler job validation failed: selector matched no nodes");
            }
            targets
                .iter()
                .map(|target| target.node_id.clone())
                .collect()
        }
    };
    for node_id in node_ids {
        validate_node_id(&node_id).map_err(anyhow::Error::msg)?;
        let node = store.get_node(&node_id)?.with_context(|| {
            format!("scheduler job validation failed: node not found: {node_id}")
        })?;
        if !node.enabled {
            bail!("scheduler job validation failed: node disabled: {node_id}");
        }
    }
    Ok(())
}

async fn run_job(
    tick_context: &mut SchedulerTickContext<'_>,
    job: &ObservabilityJobRecord,
    prepared: PreparedSchedulerJob,
    claim: &SchedulerJobClaim,
) -> anyhow::Result<RunStats> {
    let started_at = now_rfc3339();
    let run_id = format!("run-{}", Uuid::new_v4().simple());
    StoreWriter::write_scheduler_claimed_run_start(
        tick_context.store,
        &SchedulerRunStart {
            run_id: run_id.clone(),
            job_id: job.job_id.clone(),
            started_at,
        },
        claim,
        tick_context.actor,
    )?;

    // Use an independent connection so renewal can proceed while the execution future
    // borrows the tick context and waits on bounded RPC work.
    let heartbeat_store = Store::open(tick_context.database_path)?;
    let heartbeat_actor = tick_context.actor;
    let execution = run_job_after_start(tick_context, job, prepared, &run_id);
    let mut stats = run_with_scheduler_claim_heartbeat(
        &heartbeat_store,
        heartbeat_actor,
        claim,
        std::time::Duration::from_secs(SCHEDULER_LEASE_RENEW_SECONDS),
        SCHEDULER_LEASE_SECONDS,
        execution,
    )
    .await?;

    let finished_at = now_rfc3339();
    StoreWriter::write_scheduler_run_finish(
        tick_context.store,
        &SchedulerRunFinish {
            run_id: run_id.clone(),
            finished_at: finished_at.clone(),
            job_clock: scheduler_job_clock(job, &finished_at)?,
        },
        tick_context.actor,
    )?;
    stats.run_ids.push(run_id);
    Ok(stats)
}

async fn run_with_scheduler_claim_heartbeat<F, T>(
    store: &Store,
    actor: &str,
    claim: &SchedulerJobClaim,
    renew_interval: std::time::Duration,
    lease_seconds: u64,
    execution: F,
) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>>,
{
    tokio::pin!(execution);
    let mut renew = tokio::time::interval(renew_interval);
    renew.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    renew.tick().await;

    loop {
        tokio::select! {
            result = &mut execution => return result,
            _ = renew.tick() => {
                StoreWriter::write_scheduler_claim_renew(
                    store,
                    claim,
                    &now_rfc3339(),
                    lease_seconds,
                    actor,
                )?;
            }
        }
    }
}

async fn run_job_after_start(
    tick_context: &mut SchedulerTickContext<'_>,
    job: &ObservabilityJobRecord,
    prepared: PreparedSchedulerJob,
    run_id: &str,
) -> anyhow::Result<RunStats> {
    let mut stats = RunStats::default();
    match prepared {
        PreparedSchedulerJob::PathProbe => {
            run_path_probe_job(tick_context, job, run_id, &mut stats).await?
        }
        PreparedSchedulerJob::NodeTargets { kind, targets } => {
            if targets.is_empty() {
                let outcome =
                    missing_target_outcome(tick_context.actor, run_id, job, "NODE_NOT_FOUND");
                write_scheduler_task_outcomes(
                    tick_context.store,
                    tick_context.actor,
                    vec![outcome],
                    &mut stats,
                )?;
            } else {
                let mut tasks = Vec::new();
                let mut outcomes = Vec::new();
                for (ordinal, target) in targets.into_iter().enumerate() {
                    match prepare_node_target_task(
                        tick_context.store,
                        tick_context.actor,
                        job,
                        kind,
                        run_id,
                        target,
                        ordinal,
                    ) {
                        PreparedSchedulerTask::Task(task) => tasks.push(task),
                        PreparedSchedulerTask::Outcome(outcome) => outcomes.push(outcome),
                    }
                }
                outcomes.extend(limit_tasks_by_rpc_budget(
                    job,
                    tick_context.actor,
                    run_id,
                    kind,
                    &mut tasks,
                    tick_context.rpc_budget_remaining,
                ));
                let executor = ProductionSchedulerTaskExecutor {
                    database_path: Arc::new(tick_context.database_path.to_path_buf()),
                    secret_key_path: Arc::new(tick_context.secret_key_path.to_path_buf()),
                };
                outcomes.extend(
                    execute_resolved_scheduler_tasks(tasks, tick_context.limits, executor).await,
                );
                write_scheduler_task_outcomes(
                    tick_context.store,
                    tick_context.actor,
                    outcomes,
                    &mut stats,
                )?;
            }
        }
    }
    Ok(stats)
}

enum PreparedSchedulerTask {
    Task(ResolvedSchedulerTask),
    Outcome(SchedulerTaskOutcome),
}

fn prepare_node_target_task(
    store: &Store,
    actor: &str,
    job: &ObservabilityJobRecord,
    kind: StoredJobKind,
    run_id: &str,
    target: TargetNode,
    ordinal: usize,
) -> PreparedSchedulerTask {
    let method_key = scheduler_method_key(kind).to_string();
    let rpc = scheduler_rpc_for_kind(kind);
    match load_scheduler_task_node(store, &target.node_id, kind) {
        Ok(node) => PreparedSchedulerTask::Task(ResolvedSchedulerTask {
            job_id: job.job_id.clone(),
            run_id: run_id.to_string(),
            actor: actor.to_string(),
            kind,
            node,
            rpc,
            method_key,
            ordinal,
        }),
        Err(failure) => {
            let node_id = target.node_id;
            let task = ResolvedSchedulerTask {
                job_id: job.job_id.clone(),
                run_id: run_id.to_string(),
                actor: actor.to_string(),
                kind,
                node: NodeRecord {
                    node_id: node_id.clone(),
                    endpoint_id: failure.endpoint_id.clone().unwrap_or_default(),
                    name: node_id,
                    region: String::new(),
                    role: String::new(),
                    enabled: false,
                },
                rpc: scheduler_rpc_for_preflight_failure(kind),
                method_key,
                ordinal,
            };
            PreparedSchedulerTask::Outcome(preflight_failure_outcome(task, failure))
        }
    }
}

fn scheduler_rpc_for_kind(kind: StoredJobKind) -> SchedulerTaskRpc {
    match kind {
        StoredJobKind::ControllerPing => {
            SchedulerTaskRpc::Fixed(FixedControllerRpc::ProbeControllerPing)
        }
        StoredJobKind::OcservStatus => SchedulerTaskRpc::OcservStatusBundle,
        StoredJobKind::OcservCert => SchedulerTaskRpc::Fixed(FixedControllerRpc::OcservCertExpiry),
        StoredJobKind::OcservSessions => {
            SchedulerTaskRpc::Fixed(FixedControllerRpc::OcservSessionsSummary)
        }
        StoredJobKind::PathProbe => unreachable!("path probe tasks carry an explicit target"),
    }
}

fn scheduler_method_key(kind: StoredJobKind) -> &'static str {
    match kind {
        StoredJobKind::ControllerPing => PROBE_CONTROLLER_PING,
        StoredJobKind::OcservStatus => "ocserv.status.bundle",
        StoredJobKind::OcservCert => OCSERV_CERT_EXPIRY,
        StoredJobKind::OcservSessions => OCSERV_SESSIONS_SUMMARY,
        StoredJobKind::PathProbe => PROBE_PATH_ECHO,
    }
}

struct SchedulerPreflightFailure {
    code: ErrorCode,
    observation_error_code: Option<&'static str>,
    endpoint_id: Option<String>,
    detail_json: Value,
}

fn load_scheduler_task_node(
    store: &Store,
    node_id: &str,
    kind: StoredJobKind,
) -> Result<NodeRecord, SchedulerPreflightFailure> {
    validate_node_id(node_id).map_err(|err| SchedulerPreflightFailure {
        code: ErrorCode::ParamsInvalid,
        observation_error_code: None,
        endpoint_id: None,
        detail_json: scheduler_preflight_detail(kind, &err.to_string(), None),
    })?;
    let node = store
        .get_node(node_id)
        .map_err(|_| SchedulerPreflightFailure {
            code: ErrorCode::SqliteError,
            observation_error_code: None,
            endpoint_id: None,
            detail_json: scheduler_preflight_detail(kind, "controller registry read failed", None),
        })?;
    let Some(node) = node else {
        let message = format!("node not found: {node_id}");
        return Err(SchedulerPreflightFailure {
            code: ErrorCode::NodeNotFound,
            observation_error_code: None,
            endpoint_id: None,
            detail_json: scheduler_preflight_detail(kind, &message, None),
        });
    };
    if !node.enabled {
        let message = format!("node disabled: {node_id}");
        return Err(SchedulerPreflightFailure {
            code: ErrorCode::NodeDisabled,
            observation_error_code: None,
            endpoint_id: Some(node.endpoint_id),
            detail_json: scheduler_preflight_detail(kind, &message, None),
        });
    }
    if let Some(rejection) = endpoint_trust_rejection(store, &node.node_id, &node.endpoint_id)
        .map_err(|_| SchedulerPreflightFailure {
            code: ErrorCode::SqliteError,
            observation_error_code: None,
            endpoint_id: Some(node.endpoint_id.clone()),
            detail_json: scheduler_preflight_detail(
                kind,
                "controller endpoint trust read failed",
                None,
            ),
        })?
    {
        let message = scheduler_endpoint_rejection_message(rejection);
        return Err(SchedulerPreflightFailure {
            code: ErrorCode::EndpointNotAllowed,
            observation_error_code: endpoint_trust_observation_code(rejection, false),
            endpoint_id: Some(node.endpoint_id),
            detail_json: scheduler_preflight_detail(kind, &message, Some(rejection)),
        });
    }
    Ok(node)
}

fn scheduler_preflight_detail(
    kind: StoredJobKind,
    message: &str,
    endpoint_rejection: Option<EndpointTrustRejection>,
) -> Value {
    let mut detail = json!({
        "message": message,
        "result_class": scheduler_result_class_for_stored_kind(kind),
    });
    if let Some(rejection) = endpoint_rejection {
        detail["endpoint_trust_state"] = json!(rejection.trust_state());
        if let Some(status) = rejection.endpoint_status() {
            detail["endpoint_status"] = json!(status.as_str());
        }
    }
    detail
}

fn preflight_failure_outcome(
    task: ResolvedSchedulerTask,
    failure: SchedulerPreflightFailure,
) -> SchedulerTaskOutcome {
    let error_code = failure
        .observation_error_code
        .map(str::to_string)
        .unwrap_or_else(|| error_code_name(&failure.code));
    let observations = preflight_failure_observations(&task, &failure.detail_json, &error_code);
    let rpc_audits = preflight_methods_for_kind(task.kind)
        .into_iter()
        .map(|method| RpcAuditRecord {
            actor: task.actor.clone(),
            node_id: task.node.node_id.clone(),
            endpoint_id: failure.endpoint_id.clone(),
            method: method.to_string(),
            request_id: None,
            params_hash: hash_json_value(&json!({})),
            ok: false,
            error_code: Some(failure.code.clone()),
            duration_ms: 0,
            detail_json: failure.detail_json.clone(),
        })
        .collect();
    SchedulerTaskOutcome::from_observations(task, observations, rpc_audits)
}

fn scheduler_rpc_for_preflight_failure(kind: StoredJobKind) -> SchedulerTaskRpc {
    match kind {
        StoredJobKind::PathProbe => SchedulerTaskRpc::PathProbe {
            target_node_id: String::new(),
            target_endpoint_id: String::new(),
        },
        _ => scheduler_rpc_for_kind(kind),
    }
}

fn preflight_failure_observations(
    task: &ResolvedSchedulerTask,
    detail_json: &Value,
    error_code: &str,
) -> Vec<SchedulerObservationOutcome> {
    let methods = preflight_methods_for_kind(task.kind);
    methods
        .into_iter()
        .map(|method| SchedulerObservationOutcome {
            node_id: Some(task.node.node_id.clone()),
            endpoint_id: (!task.node.endpoint_id.is_empty()).then(|| task.node.endpoint_id.clone()),
            method: method.to_string(),
            ok: false,
            error_code: Some(error_code.to_string()),
            duration_ms: 0,
            result_class: scheduler_result_class_for_stored_kind(task.kind).to_string(),
            summary_json: detail_json.clone(),
        })
        .collect()
}

fn preflight_methods_for_kind(kind: StoredJobKind) -> Vec<&'static str> {
    match kind {
        StoredJobKind::OcservStatus => vec![
            OCSERV_SERVICE_SUMMARY,
            OCSERV_VERSION,
            OCSERV_SESSIONS_SUMMARY,
            OCSERV_CONFIG_FINGERPRINT,
        ],
        StoredJobKind::ControllerPing
        | StoredJobKind::OcservCert
        | StoredJobKind::OcservSessions
        | StoredJobKind::PathProbe => vec![first_method_for_stored_kind(kind)],
    }
}

fn limit_tasks_by_rpc_budget(
    job: &ObservabilityJobRecord,
    actor: &str,
    run_id: &str,
    kind: StoredJobKind,
    tasks: &mut Vec<ResolvedSchedulerTask>,
    rpc_budget_remaining: &mut usize,
) -> Vec<SchedulerTaskOutcome> {
    if tasks.len() <= *rpc_budget_remaining {
        *rpc_budget_remaining -= tasks.len();
        return Vec::new();
    }

    let skipped_tasks = tasks.len() - *rpc_budget_remaining;
    tasks.truncate(*rpc_budget_remaining);
    *rpc_budget_remaining = 0;
    vec![budget_exceeded_outcome(
        job,
        actor,
        run_id,
        kind,
        skipped_tasks,
    )]
}

fn budget_exceeded_outcome(
    job: &ObservabilityJobRecord,
    actor: &str,
    run_id: &str,
    kind: StoredJobKind,
    skipped_tasks: usize,
) -> SchedulerTaskOutcome {
    let method = first_method_for_stored_kind(kind);
    let task = ResolvedSchedulerTask {
        job_id: job.job_id.clone(),
        run_id: run_id.to_string(),
        actor: actor.to_string(),
        kind,
        node: NodeRecord {
            node_id: "<scheduler-budget>".to_string(),
            endpoint_id: String::new(),
            name: "<scheduler-budget>".to_string(),
            region: String::new(),
            role: String::new(),
            enabled: false,
        },
        rpc: scheduler_rpc_for_preflight_failure(kind),
        method_key: method.to_string(),
        ordinal: usize::MAX,
    };
    SchedulerTaskOutcome::from_observations(
        task,
        vec![SchedulerObservationOutcome {
            node_id: None,
            endpoint_id: None,
            method: method.to_string(),
            ok: false,
            error_code: Some("SCHEDULER_RPC_BUDGET_EXCEEDED".to_string()),
            duration_ms: 0,
            result_class: SCHEDULER_RESULT_CLASS.to_string(),
            summary_json: json!({
                "message": "scheduler rpc budget exceeded",
                "job_id": job.job_id,
                "kind": job.kind,
                "skipped_tasks": skipped_tasks,
                "result_class": SCHEDULER_RESULT_CLASS,
            }),
        }],
        Vec::new(),
    )
}

async fn execute_resolved_scheduler_tasks<E>(
    tasks: Vec<ResolvedSchedulerTask>,
    limits: SchedulerLimits,
    executor: E,
) -> Vec<SchedulerTaskOutcome>
where
    E: SchedulerTaskExecutor,
{
    if tasks.is_empty() {
        return Vec::new();
    }

    let global = Arc::new(Semaphore::new(limits.max_concurrency));
    let mut node_semaphores = HashMap::new();
    let mut method_semaphores = HashMap::new();
    for task in &tasks {
        node_semaphores
            .entry(task.node.node_id.clone())
            .or_insert_with(|| Arc::new(Semaphore::new(limits.per_node_concurrency)));
        method_semaphores
            .entry(task.method_key.clone())
            .or_insert_with(|| Arc::new(Semaphore::new(limits.per_method_concurrency)));
    }

    let mut handles = Vec::with_capacity(tasks.len());
    for task in tasks {
        let task_for_join = task.clone();
        let executor = executor.clone();
        let global = Arc::clone(&global);
        let node = Arc::clone(
            node_semaphores
                .get(&task.node.node_id)
                .expect("node semaphore exists"),
        );
        let method = Arc::clone(
            method_semaphores
                .get(&task.method_key)
                .expect("method semaphore exists"),
        );
        let handle = tokio::spawn(async move {
            let node_permit = match node.acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => {
                    return scheduler_task_runtime_failure(task, "SCHEDULER_NODE_LIMIT_CLOSED");
                }
            };
            let method_permit = match method.acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => {
                    drop(node_permit);
                    return scheduler_task_runtime_failure(task, "SCHEDULER_METHOD_LIMIT_CLOSED");
                }
            };
            let global_permit = match global.acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => {
                    drop(method_permit);
                    drop(node_permit);
                    return scheduler_task_runtime_failure(task, "SCHEDULER_GLOBAL_LIMIT_CLOSED");
                }
            };
            let outcome = executor.execute(task).await;
            drop(global_permit);
            drop(method_permit);
            drop(node_permit);
            outcome
        });
        handles.push((task_for_join, handle));
    }

    let mut outcomes = Vec::with_capacity(handles.len());
    for (task, handle) in handles {
        match handle.await {
            Ok(outcome) => outcomes.push(outcome),
            Err(_) => outcomes.push(scheduler_task_runtime_failure(
                task,
                "SCHEDULER_TASK_JOIN_FAILED",
            )),
        }
    }
    outcomes.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    outcomes
}

fn scheduler_task_runtime_failure(
    task: ResolvedSchedulerTask,
    error_code: &str,
) -> SchedulerTaskOutcome {
    SchedulerTaskOutcome::from_observations(
        task.clone(),
        vec![SchedulerObservationOutcome {
            node_id: Some(task.node.node_id.clone()),
            endpoint_id: Some(task.node.endpoint_id.clone()),
            method: first_method_for_stored_kind(task.kind).to_string(),
            ok: false,
            error_code: Some(error_code.to_string()),
            duration_ms: 0,
            result_class: SCHEDULER_RESULT_CLASS.to_string(),
            summary_json: json!({
                "message": "scheduler task runtime failed",
                "result_class": SCHEDULER_RESULT_CLASS,
                "error_code": error_code,
            }),
        }],
        Vec::new(),
    )
}

fn write_scheduler_task_outcomes(
    store: &Store,
    actor: &str,
    outcomes: Vec<SchedulerTaskOutcome>,
    stats: &mut RunStats,
) -> anyhow::Result<()> {
    for outcome in outcomes {
        if outcome.task.actor != actor {
            bail!("scheduler task actor does not match command actor");
        }
        let mut rpc_audits = outcome.rpc_audits;
        let observed_at = now_rfc3339();
        let mut entries = Vec::with_capacity(outcome.observations.len());
        let mut failed_observations = 0_usize;
        for observation in outcome.observations {
            let audit = matching_rpc_audit(&observation, &mut rpc_audits)
                .map(rpc_audit_event)
                .unwrap_or_else(|| {
                    scheduler_task_outcome_audit(actor, &outcome.task, &observation)
                });
            if !observation.ok {
                failed_observations += 1;
            }
            entries.push(SchedulerOutcomeEntry {
                observation: ProbeObservationInsert {
                    observation_id: observation_id(),
                    run_id: Some(outcome.task.run_id.clone()),
                    node_id: observation.node_id,
                    endpoint_id: observation.endpoint_id,
                    method: observation.method,
                    ok: Some(observation.ok),
                    error_code: observation.error_code,
                    duration_ms: Some(observation.duration_ms),
                    observed_at: observed_at.clone(),
                    expires_at: None,
                    result_class: observation.result_class,
                    summary_json: observation.summary_json,
                },
                audit,
            });
        }
        if !rpc_audits.is_empty() {
            bail!("scheduler RPC audit does not match an observation");
        }
        let observation_count = entries.len();
        StoreWriter::write_scheduler_outcome(
            store,
            &SchedulerOutcomeWrite {
                job_id: outcome.task.job_id,
                run_id: Some(outcome.task.run_id),
                entries,
                job_clock: None,
            },
            actor,
        )?;
        stats.observations += observation_count;
        stats.failed_observations += failed_observations;
    }
    Ok(())
}

fn matching_rpc_audit(
    observation: &SchedulerObservationOutcome,
    audits: &mut Vec<RpcAuditRecord>,
) -> Option<RpcAuditRecord> {
    let position = audits.iter().position(|audit| {
        audit.method == observation.method
            && Some(audit.node_id.as_str()) == observation.node_id.as_deref()
            && audit.endpoint_id.as_deref() == observation.endpoint_id.as_deref()
            && audit.ok == observation.ok
            && audit.duration_ms == observation.duration_ms
    })?;
    Some(audits.remove(position))
}

fn scheduler_task_outcome_audit(
    actor: &str,
    task: &ResolvedSchedulerTask,
    observation: &SchedulerObservationOutcome,
) -> AuditEvent {
    let mut event = AuditEvent::new(actor, "scheduler.task.outcome");
    event.node_id = observation.node_id.clone();
    event.endpoint_id = observation.endpoint_id.clone();
    event.method = Some(observation.method.clone());
    event.ok = Some(observation.ok);
    event.error_code = observation.error_code.clone();
    event.duration_ms = Some(observation.duration_ms);
    event.detail_json = json!({
        "job_id": task.job_id,
        "run_id": task.run_id,
        "result_class": observation.result_class,
    });
    event
}

async fn execute_production_scheduler_task(
    database_path: Arc<PathBuf>,
    secret_key_path: Arc<PathBuf>,
    task: ResolvedSchedulerTask,
) -> SchedulerTaskOutcome {
    match task.rpc.clone() {
        SchedulerTaskRpc::Fixed(rpc) => {
            execute_scheduler_fixed_rpc(database_path, secret_key_path, task, rpc).await
        }
        SchedulerTaskRpc::OcservStatusBundle => {
            execute_scheduler_ocserv_status_bundle(database_path, secret_key_path, task).await
        }
        SchedulerTaskRpc::PathProbe {
            target_node_id,
            target_endpoint_id,
        } => {
            execute_scheduler_path_probe(
                database_path,
                secret_key_path,
                task,
                target_node_id,
                target_endpoint_id,
            )
            .await
        }
    }
}

async fn execute_scheduler_fixed_rpc(
    database_path: Arc<PathBuf>,
    secret_key_path: Arc<PathBuf>,
    task: ResolvedSchedulerTask,
    rpc: FixedControllerRpc,
) -> SchedulerTaskOutcome {
    let started = Instant::now();
    let method = rpc.method();
    let params_hash = hash_json_value(&rpc.params());
    let result_class = result_class_for_method(method);
    match execute_fixed_node_rpc_from_database(&database_path, &secret_key_path, &task.node, rpc)
        .await
    {
        Ok(success) => fixed_rpc_success_outcome(task, method, success, params_hash, started),
        Err(failure) => fixed_rpc_failure_outcome(
            task,
            method,
            failure,
            params_hash,
            elapsed_ms(started),
            result_class,
        ),
    }
}

fn fixed_rpc_success_outcome(
    task: ResolvedSchedulerTask,
    method: &'static str,
    success: crate::controller_rpc::RpcCommandSuccess,
    params_hash: String,
    started: Instant,
) -> SchedulerTaskOutcome {
    let duration_ms = elapsed_ms(started);
    let result_class = result_class_for_method(method);
    match scheduler_success_summary(method, &success.result) {
        Ok(summary_json) => {
            let audit_detail = if result_class == OCSERV_RESULT_CLASS {
                json!({"result_class": OCSERV_RESULT_CLASS})
            } else {
                summary_json.clone()
            };
            SchedulerTaskOutcome::from_observations(
                task.clone(),
                vec![SchedulerObservationOutcome {
                    node_id: Some(task.node.node_id.clone()),
                    endpoint_id: Some(task.node.endpoint_id.clone()),
                    method: method.to_string(),
                    ok: true,
                    error_code: None,
                    duration_ms,
                    result_class: result_class.to_string(),
                    summary_json,
                }],
                vec![RpcAuditRecord {
                    actor: task.actor.clone(),
                    node_id: task.node.node_id.clone(),
                    endpoint_id: Some(task.node.endpoint_id.clone()),
                    method: method.to_string(),
                    request_id: Some(success.request_id),
                    params_hash,
                    ok: true,
                    error_code: None,
                    duration_ms,
                    detail_json: audit_detail,
                }],
            )
        }
        Err(_) => {
            let failure = RpcCommandFailure::new(
                ErrorCode::InvalidResponse,
                "fixed RPC response summary is invalid",
                Some(success.request_id),
                json!({
                    "message": "fixed RPC response summary is invalid",
                    "result_class": result_class,
                    "error_code": "INVALID_RESPONSE",
                }),
            );
            fixed_rpc_failure_outcome(
                task,
                method,
                failure,
                params_hash,
                duration_ms,
                result_class,
            )
        }
    }
}

fn fixed_rpc_failure_outcome(
    task: ResolvedSchedulerTask,
    method: &'static str,
    failure: RpcCommandFailure,
    params_hash: String,
    duration_ms: u64,
    result_class: &'static str,
) -> SchedulerTaskOutcome {
    let observation_error_code = scheduler_failure_error_code(&failure);
    let detail_json = if result_class == OCSERV_RESULT_CLASS {
        ocserv_failure_detail(&failure)
    } else {
        failure.detail_json.clone()
    };
    SchedulerTaskOutcome::from_observations(
        task.clone(),
        vec![SchedulerObservationOutcome {
            node_id: Some(task.node.node_id.clone()),
            endpoint_id: Some(task.node.endpoint_id.clone()),
            method: method.to_string(),
            ok: false,
            error_code: Some(observation_error_code),
            duration_ms,
            result_class: result_class.to_string(),
            summary_json: detail_json.clone(),
        }],
        vec![RpcAuditRecord {
            actor: task.actor.clone(),
            node_id: task.node.node_id.clone(),
            endpoint_id: Some(task.node.endpoint_id.clone()),
            method: method.to_string(),
            request_id: failure.request_id,
            params_hash,
            ok: false,
            error_code: Some(failure.code),
            duration_ms,
            detail_json,
        }],
    )
}

async fn execute_scheduler_ocserv_status_bundle(
    database_path: Arc<PathBuf>,
    secret_key_path: Arc<PathBuf>,
    task: ResolvedSchedulerTask,
) -> SchedulerTaskOutcome {
    let started = Instant::now();
    let service = execute_scheduler_ocserv_subrpc::<OcservServiceSummaryResponse>(
        &database_path,
        &secret_key_path,
        &task.actor,
        &task.node,
        OCSERV_SERVICE_SUMMARY,
    )
    .await;
    let version = execute_scheduler_ocserv_subrpc::<OcservVersionResponse>(
        &database_path,
        &secret_key_path,
        &task.actor,
        &task.node,
        OCSERV_VERSION,
    )
    .await;
    let sessions = execute_scheduler_ocserv_subrpc::<OcservSessionsSummaryResponse>(
        &database_path,
        &secret_key_path,
        &task.actor,
        &task.node,
        OCSERV_SESSIONS_SUMMARY,
    )
    .await;
    let config_fingerprint = execute_scheduler_ocserv_subrpc::<OcservConfigFingerprintResponse>(
        &database_path,
        &secret_key_path,
        &task.actor,
        &task.node,
        OCSERV_CONFIG_FINGERPRINT,
    )
    .await;
    let duration_ms = elapsed_ms(started);
    let mut audits = Vec::new();
    let mut observations = Vec::new();
    append_ocserv_subrpc_outcome(
        &task,
        OCSERV_SERVICE_SUMMARY,
        service,
        duration_ms,
        &mut audits,
        &mut observations,
    );
    append_ocserv_subrpc_outcome(
        &task,
        OCSERV_VERSION,
        version,
        duration_ms,
        &mut audits,
        &mut observations,
    );
    append_ocserv_subrpc_outcome(
        &task,
        OCSERV_SESSIONS_SUMMARY,
        sessions,
        duration_ms,
        &mut audits,
        &mut observations,
    );
    append_ocserv_subrpc_outcome(
        &task,
        OCSERV_CONFIG_FINGERPRINT,
        config_fingerprint,
        duration_ms,
        &mut audits,
        &mut observations,
    );
    SchedulerTaskOutcome::from_observations(task, observations, audits)
}

struct SchedulerOcservSubrpcOutcome<T> {
    rpc_outcome: OcservRpcOutcome<T>,
    audit: Option<RpcAuditRecord>,
    observation_error_code: Option<String>,
}

fn append_ocserv_subrpc_outcome<T>(
    task: &ResolvedSchedulerTask,
    method: &'static str,
    outcome: SchedulerOcservSubrpcOutcome<T>,
    duration_ms: u64,
    audits: &mut Vec<RpcAuditRecord>,
    observations: &mut Vec<SchedulerObservationOutcome>,
) where
    T: Serialize,
{
    let observation_duration_ms = outcome
        .audit
        .as_ref()
        .map(|audit| audit.duration_ms)
        .unwrap_or(duration_ms);
    if let Some(audit) = outcome.audit {
        audits.push(audit);
    }
    observations.push(ocserv_subrpc_observation(
        task,
        method,
        outcome.rpc_outcome,
        outcome.observation_error_code,
        observation_duration_ms,
    ));
}

async fn execute_scheduler_ocserv_subrpc<T>(
    database_path: &Path,
    secret_key_path: &Path,
    actor: &str,
    node: &NodeRecord,
    method: &'static str,
) -> SchedulerOcservSubrpcOutcome<T>
where
    T: DeserializeOwned,
{
    let started = Instant::now();
    let rpc = FixedControllerRpc::from_method_without_params(method)
        .expect("scheduler ocserv method is fixed");
    let params_hash = hash_json_value(&rpc.params());
    match execute_fixed_node_rpc_from_database(database_path, secret_key_path, node, rpc).await {
        Ok(success) => match serde_json::from_value::<T>(success.result) {
            Ok(value) => SchedulerOcservSubrpcOutcome {
                rpc_outcome: OcservRpcOutcome::Available(value),
                audit: Some(RpcAuditRecord {
                    actor: actor.to_string(),
                    node_id: node.node_id.clone(),
                    endpoint_id: Some(node.endpoint_id.clone()),
                    method: method.to_string(),
                    request_id: Some(success.request_id),
                    params_hash,
                    ok: true,
                    error_code: None,
                    duration_ms: elapsed_ms(started),
                    detail_json: json!({"result_class": OCSERV_RESULT_CLASS}),
                }),
                observation_error_code: None,
            },
            Err(_) => {
                let failure = RpcCommandFailure::new(
                    ErrorCode::InvalidResponse,
                    "ocserv readonly response schema is invalid",
                    Some(success.request_id),
                    json!({
                        "message": "ocserv readonly response schema is invalid",
                        "result_class": OCSERV_RESULT_CLASS,
                        "error_code": "INVALID_RESPONSE",
                    }),
                );
                let detail_json = ocserv_failure_detail(&failure);
                SchedulerOcservSubrpcOutcome {
                    rpc_outcome: OcservRpcOutcome::Unavailable {
                        method,
                        code: failure.code.clone(),
                    },
                    audit: Some(RpcAuditRecord {
                        actor: actor.to_string(),
                        node_id: node.node_id.clone(),
                        endpoint_id: Some(node.endpoint_id.clone()),
                        method: method.to_string(),
                        request_id: failure.request_id,
                        params_hash,
                        ok: false,
                        error_code: Some(failure.code.clone()),
                        duration_ms: elapsed_ms(started),
                        detail_json,
                    }),
                    observation_error_code: Some(error_code_name(&failure.code)),
                }
            }
        },
        Err(failure) => {
            let observation_error_code = scheduler_failure_error_code(&failure);
            let detail_json = ocserv_failure_detail(&failure);
            SchedulerOcservSubrpcOutcome {
                rpc_outcome: OcservRpcOutcome::Unavailable {
                    method,
                    code: failure.code.clone(),
                },
                audit: Some(RpcAuditRecord {
                    actor: actor.to_string(),
                    node_id: node.node_id.clone(),
                    endpoint_id: Some(node.endpoint_id.clone()),
                    method: method.to_string(),
                    request_id: failure.request_id,
                    params_hash,
                    ok: false,
                    error_code: Some(failure.code),
                    duration_ms: elapsed_ms(started),
                    detail_json,
                }),
                observation_error_code: Some(observation_error_code),
            }
        }
    }
}

fn ocserv_subrpc_observation<T>(
    task: &ResolvedSchedulerTask,
    method: &'static str,
    outcome: OcservRpcOutcome<T>,
    error_code_override: Option<String>,
    duration_ms: u64,
) -> SchedulerObservationOutcome
where
    T: Serialize,
{
    let (ok, error_code, summary_json) = match outcome {
        OcservRpcOutcome::Available(value) => {
            let value = serde_json::to_value(value).unwrap_or_else(|_| json!({}));
            (
                true,
                None,
                low_sensitive_ocserv_observation_summary(method, &value).unwrap_or_else(|_| {
                    json!({
                        "message": "ocserv observation summary is invalid",
                        "method": method,
                        "result_class": OCSERV_RESULT_CLASS,
                    })
                }),
            )
        }
        OcservRpcOutcome::Unavailable { code, .. } => (
            false,
            Some(error_code_override.unwrap_or_else(|| error_code_name(&code))),
            json!({
                "message": "ocserv status sub-rpc unavailable",
                "method": method,
                "result_class": OCSERV_RESULT_CLASS,
            }),
        ),
    };
    SchedulerObservationOutcome {
        node_id: Some(task.node.node_id.clone()),
        endpoint_id: Some(task.node.endpoint_id.clone()),
        method: method.to_string(),
        ok,
        error_code,
        duration_ms,
        result_class: OCSERV_RESULT_CLASS.to_string(),
        summary_json,
    }
}

async fn execute_scheduler_path_probe(
    database_path: Arc<PathBuf>,
    secret_key_path: Arc<PathBuf>,
    task: ResolvedSchedulerTask,
    target_node_id: String,
    target_endpoint_id: String,
) -> SchedulerTaskOutcome {
    let started = Instant::now();
    let rpc = FixedControllerRpc::ProbePathEcho {
        target_node_id: target_node_id.clone(),
        target_agent_endpoint_id: target_endpoint_id.clone(),
    };
    let params_hash = hash_json_value(&rpc.params());
    match execute_fixed_node_rpc_from_database(&database_path, &secret_key_path, &task.node, rpc)
        .await
    {
        Ok(success) => {
            let duration_ms = elapsed_ms(started);
            SchedulerTaskOutcome::from_observations(
                task.clone(),
                vec![SchedulerObservationOutcome {
                    node_id: Some(task.node.node_id.clone()),
                    endpoint_id: Some(task.node.endpoint_id.clone()),
                    method: PROBE_PATH_ECHO.to_string(),
                    ok: true,
                    error_code: None,
                    duration_ms,
                    result_class: CONTROLLER_RPC_RESULT_CLASS.to_string(),
                    summary_json: json!({
                        "request_id": success.request_id,
                        "target_node_id": target_node_id,
                        "target_endpoint_id": target_endpoint_id,
                        "result_class": CONTROLLER_RPC_RESULT_CLASS,
                    }),
                }],
                vec![RpcAuditRecord {
                    actor: task.actor.clone(),
                    node_id: task.node.node_id.clone(),
                    endpoint_id: Some(task.node.endpoint_id.clone()),
                    method: PROBE_PATH_ECHO.to_string(),
                    request_id: Some(success.request_id),
                    params_hash,
                    ok: true,
                    error_code: None,
                    duration_ms,
                    detail_json: json!({
                        "result_class": CONTROLLER_RPC_RESULT_CLASS,
                        "target_node_id": target_node_id,
                        "target_endpoint_id": target_endpoint_id,
                    }),
                }],
            )
        }
        Err(failure) => {
            let duration_ms = elapsed_ms(started);
            let observation_error_code = scheduler_failure_error_code(&failure);
            let mut audit_detail = failure.detail_json.clone();
            audit_detail["target_node_id"] = Value::String(target_node_id.clone());
            audit_detail["target_endpoint_id"] = Value::String(target_endpoint_id.clone());
            SchedulerTaskOutcome::from_observations(
                task.clone(),
                vec![SchedulerObservationOutcome {
                    node_id: Some(task.node.node_id.clone()),
                    endpoint_id: Some(task.node.endpoint_id.clone()),
                    method: PROBE_PATH_ECHO.to_string(),
                    ok: false,
                    error_code: Some(observation_error_code),
                    duration_ms,
                    result_class: CONTROLLER_RPC_RESULT_CLASS.to_string(),
                    summary_json: json!({
                        "message": "path probe failed",
                        "target_node_id": target_node_id,
                        "target_endpoint_id": target_endpoint_id,
                        "result_class": CONTROLLER_RPC_RESULT_CLASS,
                    }),
                }],
                vec![RpcAuditRecord {
                    actor: task.actor.clone(),
                    node_id: task.node.node_id.clone(),
                    endpoint_id: Some(task.node.endpoint_id.clone()),
                    method: PROBE_PATH_ECHO.to_string(),
                    request_id: failure.request_id,
                    params_hash,
                    ok: false,
                    error_code: Some(failure.code),
                    duration_ms,
                    detail_json: audit_detail,
                }],
            )
        }
    }
}

fn scheduler_success_summary(method: &str, result: &Value) -> anyhow::Result<Value> {
    match method {
        OCSERV_CERT_EXPIRY => {
            let response: OcservCertExpiryResponse = serde_json::from_value(result.clone())?;
            Ok(json!({ "cert_count": response.certs.len() }))
        }
        OCSERV_SESSIONS_SUMMARY => {
            let response: OcservSessionsSummaryResponse = serde_json::from_value(result.clone())?;
            Ok(json!({ "sessions": response.sessions }))
        }
        _ => low_sensitive_fixed_rpc_summary(method, result),
    }
}

fn result_class_for_method(method: &str) -> &'static str {
    match method {
        OCSERV_SERVICE_SUMMARY
        | OCSERV_VERSION
        | OCSERV_SESSIONS_SUMMARY
        | OCSERV_CERT_EXPIRY
        | OCSERV_CONFIG_FINGERPRINT => OCSERV_RESULT_CLASS,
        _ => CONTROLLER_RPC_RESULT_CLASS,
    }
}

fn scheduler_failure_error_code(failure: &RpcCommandFailure) -> String {
    match failure.endpoint_trust_rejection() {
        Some(rejection) => {
            scheduler_preflight_endpoint_error_code(rejection, failure.endpoint_trust_target())
        }
        None => error_code_name(&failure.code),
    }
}

fn endpoint_trust_observation_code(
    rejection: EndpointTrustRejection,
    target: bool,
) -> Option<&'static str> {
    match (rejection, target) {
        (EndpointTrustRejection::Missing, false) => Some("ENDPOINT_TRUST_MISSING"),
        (EndpointTrustRejection::Missing, true) => Some("TARGET_ENDPOINT_TRUST_MISSING"),
        (EndpointTrustRejection::Unbound, false) => Some("ENDPOINT_TRUST_UNBOUND"),
        (EndpointTrustRejection::Unbound, true) => Some("TARGET_ENDPOINT_TRUST_UNBOUND"),
        (EndpointTrustRejection::BindingMismatch, false) => Some("ENDPOINT_TRUST_BINDING_MISMATCH"),
        (EndpointTrustRejection::BindingMismatch, true) => {
            Some("TARGET_ENDPOINT_TRUST_BINDING_MISMATCH")
        }
        (EndpointTrustRejection::Inactive(_), _) => None,
    }
}

fn scheduler_preflight_endpoint_error_code(
    rejection: EndpointTrustRejection,
    target: bool,
) -> String {
    endpoint_trust_observation_code(rejection, target)
        .map(str::to_string)
        .unwrap_or_else(|| {
            let EndpointTrustRejection::Inactive(status) = rejection else {
                unreachable!("non-inactive trust rejection has a fixed observation code")
            };
            if target {
                format!("TARGET_ENDPOINT_{}", status.as_str().to_ascii_uppercase())
            } else {
                format!("ENDPOINT_{}", status.as_str().to_ascii_uppercase())
            }
        })
}

fn scheduler_endpoint_rejection_message(rejection: EndpointTrustRejection) -> String {
    match rejection {
        EndpointTrustRejection::Missing => "endpoint trust record is missing".to_string(),
        EndpointTrustRejection::Inactive(status) => {
            format!("endpoint is not active: status={}", status.as_str())
        }
        EndpointTrustRejection::Unbound => "endpoint trust is unbound".to_string(),
        EndpointTrustRejection::BindingMismatch => {
            "endpoint trust binding does not match registry node".to_string()
        }
    }
}

fn first_method_for_stored_kind(kind: StoredJobKind) -> &'static str {
    match kind {
        StoredJobKind::ControllerPing => PROBE_CONTROLLER_PING,
        StoredJobKind::OcservStatus => OCSERV_SERVICE_SUMMARY,
        StoredJobKind::OcservCert => OCSERV_CERT_EXPIRY,
        StoredJobKind::OcservSessions => OCSERV_SESSIONS_SUMMARY,
        StoredJobKind::PathProbe => PROBE_PATH_ECHO,
    }
}

fn scheduler_result_class_for_stored_kind(kind: StoredJobKind) -> &'static str {
    match kind {
        StoredJobKind::OcservStatus | StoredJobKind::OcservCert | StoredJobKind::OcservSessions => {
            OCSERV_RESULT_CLASS
        }
        StoredJobKind::ControllerPing | StoredJobKind::PathProbe => CONTROLLER_RPC_RESULT_CLASS,
    }
}

async fn run_path_probe_job(
    tick_context: &mut SchedulerTickContext<'_>,
    job: &ObservabilityJobRecord,
    run_id: &str,
    stats: &mut RunStats,
) -> anyhow::Result<()> {
    let (source_node_id, target_node_id) = explicit_pair(job)?;
    let source = tick_context.store.get_node(&source_node_id)?;
    let target = tick_context.store.get_node(&target_node_id)?;
    let Some(source) = source else {
        record_path_probe_preflight_observation(
            tick_context.store,
            tick_context.actor,
            PathProbePreflight {
                run_id,
                job,
                node_id: &source_node_id,
                endpoint_id: None,
                error_code: "NODE_NOT_FOUND",
            },
            stats,
        )?;
        return Ok(());
    };
    if !source.enabled {
        record_path_probe_preflight_observation(
            tick_context.store,
            tick_context.actor,
            PathProbePreflight {
                run_id,
                job,
                node_id: &source.node_id,
                endpoint_id: Some(&source.endpoint_id),
                error_code: "NODE_DISABLED",
            },
            stats,
        )?;
        return Ok(());
    }
    if let Some(rejection) =
        endpoint_trust_rejection(tick_context.store, &source.node_id, &source.endpoint_id)?
    {
        let error_code = scheduler_preflight_endpoint_error_code(rejection, false);
        record_path_probe_preflight_observation(
            tick_context.store,
            tick_context.actor,
            PathProbePreflight {
                run_id,
                job,
                node_id: &source.node_id,
                endpoint_id: Some(&source.endpoint_id),
                error_code: &error_code,
            },
            stats,
        )?;
        return Ok(());
    }
    let Some(target) = target else {
        record_path_probe_preflight_observation(
            tick_context.store,
            tick_context.actor,
            PathProbePreflight {
                run_id,
                job,
                node_id: &source.node_id,
                endpoint_id: Some(&source.endpoint_id),
                error_code: "TARGET_NODE_NOT_FOUND",
            },
            stats,
        )?;
        return Ok(());
    };
    if !target.enabled {
        record_path_probe_preflight_observation(
            tick_context.store,
            tick_context.actor,
            PathProbePreflight {
                run_id,
                job,
                node_id: &source.node_id,
                endpoint_id: Some(&source.endpoint_id),
                error_code: "TARGET_NODE_DISABLED",
            },
            stats,
        )?;
        return Ok(());
    }
    if let Some(rejection) =
        endpoint_trust_rejection(tick_context.store, &target.node_id, &target.endpoint_id)?
    {
        let error_code = scheduler_preflight_endpoint_error_code(rejection, true);
        record_path_probe_target_preflight_observation(
            tick_context.store,
            tick_context.actor,
            PathProbeTargetPreflight {
                run_id,
                job,
                source_node_id: &source.node_id,
                source_endpoint_id: &source.endpoint_id,
                target_node_id: &target.node_id,
                target_endpoint_id: &target.endpoint_id,
                error_code: &error_code,
            },
            stats,
        )?;
        return Ok(());
    }

    let mut tasks = vec![ResolvedSchedulerTask {
        job_id: job.job_id.clone(),
        run_id: run_id.to_string(),
        actor: tick_context.actor.to_string(),
        kind: StoredJobKind::PathProbe,
        node: source,
        rpc: SchedulerTaskRpc::PathProbe {
            target_node_id: target.node_id,
            target_endpoint_id: target.endpoint_id,
        },
        method_key: PROBE_PATH_ECHO.to_string(),
        ordinal: 0,
    }];
    let mut outcomes = limit_tasks_by_rpc_budget(
        job,
        tick_context.actor,
        run_id,
        StoredJobKind::PathProbe,
        &mut tasks,
        tick_context.rpc_budget_remaining,
    );
    let executor = ProductionSchedulerTaskExecutor {
        database_path: Arc::new(tick_context.database_path.to_path_buf()),
        secret_key_path: Arc::new(tick_context.secret_key_path.to_path_buf()),
    };
    outcomes.extend(execute_resolved_scheduler_tasks(tasks, tick_context.limits, executor).await);
    write_scheduler_task_outcomes(tick_context.store, tick_context.actor, outcomes, stats)?;
    Ok(())
}

fn build_selectors(
    kind: ScheduleJobKind,
    selector: Option<String>,
    source_node_id: Option<String>,
    target_node_id: Option<String>,
) -> anyhow::Result<(String, Option<Value>)> {
    match kind {
        ScheduleJobKind::PathProbe => {
            if selector.is_some() {
                bail!("--selector is not valid for path-probe jobs");
            }
            let source_node_id = source_node_id.context("path-probe requires --source-node-id")?;
            let target_node_id = target_node_id.context("path-probe requires --target-node-id")?;
            validate_node_id(&source_node_id)?;
            validate_node_id(&target_node_id)?;
            Ok((
                EXPLICIT_PAIR_SELECTOR.to_string(),
                Some(
                    SchedulerPairPayloadV1::new(source_node_id, target_node_id)
                        .map_err(anyhow::Error::msg)?
                        .to_value(),
                ),
            ))
        }
        _ => {
            if source_node_id.is_some() || target_node_id.is_some() {
                bail!("--source-node-id and --target-node-id are only valid for path-probe jobs");
            }
            let selector = selector.unwrap_or_else(|| DEFAULT_SELECTOR.to_string());
            validate_selector(&selector).map_err(anyhow::Error::msg)?;
            Ok((selector, None))
        }
    }
}

fn resolve_node_targets(store: &Store, selector: &str) -> anyhow::Result<Vec<TargetNode>> {
    if let Some(node_id) = selector.strip_prefix("node_id=") {
        let node_id = node_id.trim();
        if node_id.is_empty() {
            bail!("selector node_id must not be empty");
        }
        return Ok(vec![TargetNode {
            node_id: node_id.to_string(),
        }]);
    }
    if let Some(role) = selector.strip_prefix("role=") {
        let role = role.trim();
        if role.is_empty() {
            bail!("selector role must not be empty");
        }
        let targets = store
            .list_nodes()?
            .into_iter()
            .filter(|node| node.role == role)
            .map(|node| TargetNode {
                node_id: node.node_id.clone(),
            })
            .collect::<Vec<_>>();
        if targets.len() > MAX_TARGETS_PER_JOB {
            bail!(
                "selector role={role} matched too many targets: {} > {MAX_TARGETS_PER_JOB}",
                targets.len()
            );
        }
        return Ok(targets);
    }
    bail!("selector must use role=<role> or node_id=<node-id>")
}

fn missing_target_outcome(
    actor: &str,
    run_id: &str,
    job: &ObservabilityJobRecord,
    error_code: &str,
) -> SchedulerTaskOutcome {
    let kind = stored_job_kind(&job.kind).expect("prepared scheduler job kind is valid");
    let method = first_method_for_stored_kind(kind);
    let task = ResolvedSchedulerTask {
        job_id: job.job_id.clone(),
        run_id: run_id.to_string(),
        actor: actor.to_string(),
        kind,
        node: NodeRecord {
            node_id: "<scheduler-target>".to_string(),
            endpoint_id: String::new(),
            name: "<scheduler-target>".to_string(),
            region: String::new(),
            role: String::new(),
            enabled: false,
        },
        rpc: scheduler_rpc_for_preflight_failure(kind),
        method_key: method.to_string(),
        ordinal: 0,
    };
    SchedulerTaskOutcome::from_observations(
        task,
        vec![SchedulerObservationOutcome {
            node_id: None,
            endpoint_id: None,
            method: method.to_string(),
            ok: false,
            error_code: Some(error_code.to_string()),
            duration_ms: 0,
            result_class: scheduler_result_class_for_job(&job.kind).to_string(),
            summary_json: json!({
                "message": "no matching node",
                "selector_class": scheduler_selector_class(job),
                "result_class": scheduler_result_class_for_job(&job.kind),
            }),
        }],
        Vec::new(),
    )
}

fn scheduler_selector_class(job: &ObservabilityJobRecord) -> &'static str {
    match selector_label(job) {
        Ok(selector) if selector.starts_with("role=") => "role",
        Ok(selector) if selector.starts_with("node_id=") => "node_id",
        _ => "invalid",
    }
}

fn record_invalid_scheduler_job_observation(
    store: &Store,
    actor: &str,
    job: &ObservabilityJobRecord,
    reason_code: &str,
    job_clock: Option<SchedulerJobClockUpdate>,
) -> anyhow::Result<()> {
    record_invalid_scheduler_job_fields_observation(
        store,
        actor,
        &job.job_id,
        &job.kind,
        reason_code,
        job_clock,
    )
}

fn record_invalid_scheduler_job_record_observation(
    store: &Store,
    actor: &str,
    job: &InvalidObservabilityJobRecord,
) -> anyhow::Result<()> {
    record_invalid_scheduler_job_fields_observation(
        store,
        actor,
        &job.job_id,
        &job.kind,
        &job.reason_code,
        None,
    )
}

fn record_invalid_scheduler_job_fields_observation(
    store: &Store,
    actor: &str,
    job_id: &str,
    kind: &str,
    reason_code: &str,
    job_clock: Option<SchedulerJobClockUpdate>,
) -> anyhow::Result<()> {
    let summary_json = json!({
        "message": "scheduler job configuration is invalid",
        "job_id": job_id,
        "reason_code": reason_code,
        "result_class": SCHEDULER_RESULT_CLASS,
    });
    let observation = ProbeObservationInsert {
        observation_id: observation_id(),
        run_id: None,
        node_id: None,
        endpoint_id: None,
        method: first_method_for_kind(kind)
            .unwrap_or(PROBE_CONTROLLER_PING)
            .to_string(),
        ok: Some(false),
        error_code: Some("SCHEDULER_JOB_INVALID".to_string()),
        duration_ms: Some(0),
        observed_at: now_rfc3339(),
        expires_at: None,
        result_class: SCHEDULER_RESULT_CLASS.to_string(),
        summary_json: summary_json.clone(),
    };
    let mut audit = AuditEvent::new(actor, "scheduler.job.invalid");
    audit.method = Some(observation.method.clone());
    audit.ok = Some(false);
    audit.error_code = observation.error_code.clone();
    audit.duration_ms = observation.duration_ms;
    audit.detail_json = summary_json;
    StoreWriter::write_scheduler_outcome(
        store,
        &SchedulerOutcomeWrite {
            job_id: job_id.to_string(),
            run_id: None,
            entries: vec![SchedulerOutcomeEntry { observation, audit }],
            job_clock,
        },
        actor,
    )?;
    Ok(())
}

struct PathProbePreflight<'a> {
    run_id: &'a str,
    job: &'a ObservabilityJobRecord,
    node_id: &'a str,
    endpoint_id: Option<&'a str>,
    error_code: &'a str,
}

fn record_path_probe_preflight_observation(
    store: &Store,
    actor: &str,
    input: PathProbePreflight<'_>,
    stats: &mut RunStats,
) -> anyhow::Result<()> {
    let PathProbePreflight {
        run_id,
        job,
        node_id,
        endpoint_id,
        error_code,
    } = input;
    let task = path_preflight_task(actor, job, run_id, node_id, endpoint_id);
    let outcome = SchedulerTaskOutcome::from_observations(
        task,
        vec![SchedulerObservationOutcome {
            node_id: Some(node_id.to_string()),
            endpoint_id: endpoint_id.map(ToOwned::to_owned),
            method: PROBE_PATH_ECHO.to_string(),
            ok: false,
            error_code: Some(error_code.to_string()),
            duration_ms: 0,
            result_class: CONTROLLER_RPC_RESULT_CLASS.to_string(),
            summary_json: json!({
                "message": "path probe preflight failed",
                "result_class": CONTROLLER_RPC_RESULT_CLASS,
            }),
        }],
        vec![RpcAuditRecord {
            actor: actor.to_string(),
            node_id: node_id.to_string(),
            endpoint_id: endpoint_id.map(ToOwned::to_owned),
            method: PROBE_PATH_ECHO.to_string(),
            request_id: None,
            params_hash: hash_json_value(&json!({})),
            ok: false,
            error_code: Some(path_preflight_protocol_error(error_code)),
            duration_ms: 0,
            detail_json: json!({
                "message": "path probe rejected before RPC dispatch",
                "result_class": CONTROLLER_RPC_RESULT_CLASS,
                "error_code": error_code,
            }),
        }],
    );
    write_scheduler_task_outcomes(store, actor, vec![outcome], stats)
}

struct PathProbeTargetPreflight<'a> {
    run_id: &'a str,
    job: &'a ObservabilityJobRecord,
    source_node_id: &'a str,
    source_endpoint_id: &'a str,
    target_node_id: &'a str,
    target_endpoint_id: &'a str,
    error_code: &'a str,
}

fn record_path_probe_target_preflight_observation(
    store: &Store,
    actor: &str,
    input: PathProbeTargetPreflight<'_>,
    stats: &mut RunStats,
) -> anyhow::Result<()> {
    let PathProbeTargetPreflight {
        run_id,
        job,
        source_node_id,
        source_endpoint_id,
        target_node_id,
        target_endpoint_id,
        error_code,
    } = input;
    let task = path_preflight_task(actor, job, run_id, source_node_id, Some(source_endpoint_id));
    let outcome = SchedulerTaskOutcome::from_observations(
        task,
        vec![SchedulerObservationOutcome {
            node_id: Some(source_node_id.to_string()),
            endpoint_id: Some(source_endpoint_id.to_string()),
            method: PROBE_PATH_ECHO.to_string(),
            ok: false,
            error_code: Some(error_code.to_string()),
            duration_ms: 0,
            result_class: CONTROLLER_RPC_RESULT_CLASS.to_string(),
            summary_json: json!({
                "message": "path probe target endpoint preflight failed",
                "source_node_id": source_node_id,
                "source_endpoint_id": source_endpoint_id,
                "target_node_id": target_node_id,
                "target_endpoint_id": target_endpoint_id,
                "result_class": CONTROLLER_RPC_RESULT_CLASS,
            }),
        }],
        vec![RpcAuditRecord {
            actor: actor.to_string(),
            node_id: source_node_id.to_string(),
            endpoint_id: Some(source_endpoint_id.to_string()),
            method: PROBE_PATH_ECHO.to_string(),
            request_id: None,
            params_hash: hash_json_value(&json!({"target_agent_endpoint_id": target_endpoint_id})),
            ok: false,
            error_code: Some(path_preflight_protocol_error(error_code)),
            duration_ms: 0,
            detail_json: json!({
                "message": "path probe target rejected before RPC dispatch",
                "target_node_id": target_node_id,
                "target_endpoint_id": target_endpoint_id,
                "result_class": CONTROLLER_RPC_RESULT_CLASS,
                "error_code": error_code,
            }),
        }],
    );
    write_scheduler_task_outcomes(store, actor, vec![outcome], stats)
}

fn path_preflight_task(
    actor: &str,
    job: &ObservabilityJobRecord,
    run_id: &str,
    node_id: &str,
    endpoint_id: Option<&str>,
) -> ResolvedSchedulerTask {
    ResolvedSchedulerTask {
        job_id: job.job_id.clone(),
        run_id: run_id.to_string(),
        actor: actor.to_string(),
        kind: StoredJobKind::PathProbe,
        node: NodeRecord {
            node_id: node_id.to_string(),
            endpoint_id: endpoint_id.unwrap_or_default().to_string(),
            name: node_id.to_string(),
            region: String::new(),
            role: String::new(),
            enabled: false,
        },
        rpc: SchedulerTaskRpc::PathProbe {
            target_node_id: String::new(),
            target_endpoint_id: String::new(),
        },
        method_key: PROBE_PATH_ECHO.to_string(),
        ordinal: 0,
    }
}

fn path_preflight_protocol_error(error_code: &str) -> ErrorCode {
    if error_code.ends_with("NODE_NOT_FOUND") {
        ErrorCode::NodeNotFound
    } else if error_code.ends_with("NODE_DISABLED") {
        ErrorCode::NodeDisabled
    } else {
        ErrorCode::EndpointNotAllowed
    }
}

fn schedule_kind_name(kind: ScheduleJobKind) -> &'static str {
    match kind {
        ScheduleJobKind::ControllerPing => "controller-ping",
        ScheduleJobKind::OcservStatus => "ocserv-status",
        ScheduleJobKind::OcservCert => "ocserv-cert",
        ScheduleJobKind::OcservSessions => "ocserv-sessions",
        ScheduleJobKind::PathProbe => "path-probe",
    }
}

fn stored_job_kind(kind: &str) -> anyhow::Result<StoredJobKind> {
    match kind {
        "controller-ping" => Ok(StoredJobKind::ControllerPing),
        "ocserv-status" => Ok(StoredJobKind::OcservStatus),
        "ocserv-cert" => Ok(StoredJobKind::OcservCert),
        "ocserv-sessions" => Ok(StoredJobKind::OcservSessions),
        "path-probe" => Ok(StoredJobKind::PathProbe),
        _ => bail!("unknown scheduler job kind: {kind}"),
    }
}

fn first_method_for_kind(kind: &str) -> Option<&'static str> {
    match kind {
        "controller-ping" => Some(PROBE_CONTROLLER_PING),
        "ocserv-status" => Some(OCSERV_SERVICE_SUMMARY),
        "ocserv-cert" => Some(OCSERV_CERT_EXPIRY),
        "ocserv-sessions" => Some(OCSERV_SESSIONS_SUMMARY),
        "path-probe" => Some(PROBE_PATH_ECHO),
        _ => None,
    }
}

fn job_to_json(job: &ObservabilityJobRecord) -> Value {
    let pair = explicit_pair(job).ok();
    json!({
        "job_id": job.job_id,
        "name": job_name(job),
        "kind": job.kind,
        "enabled": job.enabled,
        "interval_seconds": job.interval_seconds,
        "jitter_seconds": job.jitter_seconds,
        "timeout_ms": job.timeout_ms,
        "selector": selector_label(job).unwrap_or("<invalid>"),
        "source_node_id": pair.as_ref().map(|(source, _)| source.as_str()),
        "target_node_id": pair.as_ref().map(|(_, target)| target.as_str()),
        "next_run_at": job.next_run_at,
        "last_run_at": job.last_run_at,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
    })
}

fn job_name(job: &ObservabilityJobRecord) -> Option<&str> {
    job.selector_json.get("name").and_then(Value::as_str)
}

fn run_to_json(run: &ObservabilityRunRecord) -> Value {
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

fn print_run_human(run: &ObservabilityRunRecord) {
    println!(
        "run_id={} job_id={} status={} started_at={} finished_at={} observation_count={} failed_observation_count={}",
        run.run_id,
        run.job_id.as_deref().unwrap_or("<none>"),
        run.status,
        run.started_at,
        run.finished_at.as_deref().unwrap_or("<none>"),
        run.observation_count,
        run.failed_observation_count,
    );
}

fn comma_list_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "<none>".to_string()
    } else {
        values.join(",")
    }
}

fn validate_query_limit(limit: u64) -> anyhow::Result<u64> {
    if limit == 0 || limit > MAX_QUERY_LIMIT {
        bail!("--limit must be between 1 and {MAX_QUERY_LIMIT}");
    }
    Ok(limit)
}

fn scheduler_result_class_for_job(kind: &str) -> &'static str {
    match kind {
        "ocserv-status" | "ocserv-cert" | "ocserv-sessions" => OCSERV_RESULT_CLASS,
        _ => CONTROLLER_RPC_RESULT_CLASS,
    }
}

fn selector_label(job: &ObservabilityJobRecord) -> anyhow::Result<&str> {
    let selector = job
        .selector_json
        .get("selector")
        .and_then(Value::as_str)
        .context("scheduler job is missing selector")?;
    if selector.trim().is_empty() {
        bail!("scheduler job selector is empty");
    }
    validate_selector(selector).map_err(anyhow::Error::msg)?;
    Ok(selector)
}

fn explicit_pair(job: &ObservabilityJobRecord) -> anyhow::Result<(String, String)> {
    let pair = job
        .pair_selector_json
        .as_ref()
        .context("path-probe job is missing explicit pair selector")?;
    let source = pair
        .get("source_node_id")
        .and_then(Value::as_str)
        .context("path-probe job is missing source_node_id")?;
    let target = pair
        .get("target_node_id")
        .and_then(Value::as_str)
        .context("path-probe job is missing target_node_id")?;
    Ok((source.to_string(), target.to_string()))
}

fn job_due_at_or_before(job: &ObservabilityJobRecord, now: OffsetDateTime) -> anyhow::Result<bool> {
    let Some(next_run_at) = &job.next_run_at else {
        return Ok(true);
    };
    let next_run_at = OffsetDateTime::parse(next_run_at, &Rfc3339)
        .with_context(|| format!("invalid next_run_at for job {}", job.job_id))?;
    Ok(next_run_at <= now)
}

fn write_scheduler_audit(
    store: &Store,
    actor: &str,
    event_name: &str,
    ok: bool,
    detail_json: Value,
) -> anyhow::Result<()> {
    let mut event = AuditEvent::new(actor, event_name);
    event.ok = Some(ok);
    event.detail_json = detail_json;
    store.insert_audit(&event)?;
    Ok(())
}

fn now_rfc3339() -> String {
    offset_to_rfc3339(OffsetDateTime::now_utc())
}

fn offset_to_rfc3339(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).expect("RFC3339 formatting succeeds")
}

fn observation_id() -> String {
    format!("obs-{}", Uuid::new_v4().simple())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::NodeInsert;
    use rusqlite::Connection;
    use std::collections::{HashMap, HashSet};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::time::Duration as StdDuration;

    #[derive(Clone, Default)]
    struct TrackingExecutor {
        state: Arc<Mutex<TrackingState>>,
        delay: StdDuration,
        fail_nodes: Arc<HashSet<String>>,
    }

    #[derive(Default)]
    struct TrackingState {
        in_flight: usize,
        global_peak: usize,
        active_by_node: HashMap<String, usize>,
        peak_by_node: HashMap<String, usize>,
        active_by_method: HashMap<String, usize>,
        peak_by_method: HashMap<String, usize>,
    }

    #[tokio::test]
    async fn scheduler_claim_heartbeat_renews_during_execution() {
        let dir = tempfile::tempdir().expect("temp dir");
        let database = dir.path().join("controller.sqlite");
        let store = Store::open(&database).expect("open store");
        let now = now_rfc3339();
        let job = ObservabilityJobRecord {
            job_id: "job-heartbeat".to_string(),
            kind: "controller-ping".to_string(),
            selector_json: SchedulerSelectorPayloadV1::new(
                "role=ocserv".to_string(),
                Some("heartbeat test".to_string()),
            )
            .expect("selector")
            .to_value(),
            pair_selector_json: None,
            interval_seconds: MIN_INTERVAL_SECONDS,
            jitter_seconds: 0,
            timeout_ms: DEFAULT_DEADLINE_MS,
            enabled: true,
            next_run_at: Some(now.clone()),
            last_run_at: None,
            created_at: now.clone(),
            updated_at: now.clone(),
        };
        StoreWriter::write_scheduler_job_add(&store, &job, "heartbeat-test").expect("add job");
        let claim = StoreWriter::write_scheduler_claim(
            &store,
            &job.job_id,
            "scheduler-heartbeat-test",
            &now,
            5,
            "heartbeat-test",
        )
        .expect("claim write")
        .expect("claim acquired");
        let audit_count_before = store.audit_count().expect("count audits");

        run_with_scheduler_claim_heartbeat(
            &store,
            "heartbeat-test",
            &claim,
            StdDuration::from_millis(100),
            5,
            async {
                tokio::time::sleep(StdDuration::from_millis(250)).await;
                Ok(())
            },
        )
        .await
        .expect("heartbeat execution");

        let renewed = store
            .get_scheduler_job_claim(&job.job_id)
            .expect("load claim")
            .expect("claim exists");
        assert!(renewed.lease_expires_at > claim.lease_expires_at);
        assert!(store.audit_count().expect("count renewed audits") >= audit_count_before + 2);
    }

    #[derive(Clone)]
    struct MutateTrustThenDispatchExecutor {
        database_path: Arc<PathBuf>,
        secret_key_path: Arc<PathBuf>,
        endpoint_id: Arc<String>,
        mutation: DispatchTrustMutation,
    }

    #[derive(Clone)]
    enum DispatchTrustMutation {
        Delete,
        SetNode(Option<String>),
        SetRegistryEnabled(i64),
    }

    impl SchedulerTaskExecutor for MutateTrustThenDispatchExecutor {
        fn execute(
            &self,
            task: ResolvedSchedulerTask,
        ) -> Pin<Box<dyn Future<Output = SchedulerTaskOutcome> + Send>> {
            let database_path = Arc::clone(&self.database_path);
            let secret_key_path = Arc::clone(&self.secret_key_path);
            let endpoint_id = Arc::clone(&self.endpoint_id);
            let mutation = self.mutation.clone();
            Box::pin(async move {
                let connection =
                    Connection::open(database_path.as_ref()).expect("open scheduler database");
                match mutation {
                    DispatchTrustMutation::Delete => {
                        connection
                            .execute(
                                "DELETE FROM endpoint_trust WHERE endpoint_id = ?1",
                                [endpoint_id.as_str()],
                            )
                            .expect("delete trust after semaphore acquisition");
                    }
                    DispatchTrustMutation::SetNode(node_id) => {
                        connection
                            .execute(
                                "UPDATE endpoint_trust SET node_id = ?1 WHERE endpoint_id = ?2",
                                rusqlite::params![node_id, endpoint_id.as_str()],
                            )
                            .expect("change trust binding after semaphore acquisition");
                    }
                    DispatchTrustMutation::SetRegistryEnabled(enabled) => {
                        connection
                            .pragma_update(None, "ignore_check_constraints", true)
                            .expect("allow malformed registry fixture");
                        let affected = connection
                            .execute(
                                "UPDATE nodes SET enabled = ?1 WHERE node_id = ?2",
                                rusqlite::params![enabled, task.node.node_id.as_str()],
                            )
                            .expect("change registry enabled after semaphore acquisition");
                        assert_eq!(affected, 1, "scheduler node fixture exists");
                    }
                }
                execute_production_scheduler_task(database_path, secret_key_path, task).await
            })
        }
    }

    impl TrackingExecutor {
        fn with_delay(delay: StdDuration) -> Self {
            Self {
                delay,
                ..Self::default()
            }
        }

        fn failing_node(delay: StdDuration, node_id: &str) -> Self {
            Self {
                delay,
                fail_nodes: Arc::new(HashSet::from([node_id.to_string()])),
                ..Self::default()
            }
        }

        fn global_peak(&self) -> usize {
            self.state.lock().expect("tracking state").global_peak
        }

        fn node_peak(&self, node_id: &str) -> usize {
            self.state
                .lock()
                .expect("tracking state")
                .peak_by_node
                .get(node_id)
                .copied()
                .unwrap_or(0)
        }

        fn method_peak(&self, method: &str) -> usize {
            self.state
                .lock()
                .expect("tracking state")
                .peak_by_method
                .get(method)
                .copied()
                .unwrap_or(0)
        }
    }

    impl SchedulerTaskExecutor for TrackingExecutor {
        fn execute(
            &self,
            task: ResolvedSchedulerTask,
        ) -> Pin<Box<dyn Future<Output = SchedulerTaskOutcome> + Send>> {
            let state = Arc::clone(&self.state);
            let delay = self.delay;
            let fail_nodes = Arc::clone(&self.fail_nodes);
            Box::pin(async move {
                {
                    let mut state = state.lock().expect("tracking state");
                    state.in_flight += 1;
                    state.global_peak = state.global_peak.max(state.in_flight);

                    let node_active = {
                        let active = state
                            .active_by_node
                            .entry(task.node.node_id.clone())
                            .or_insert(0);
                        *active += 1;
                        *active
                    };
                    let node_peak = state
                        .peak_by_node
                        .entry(task.node.node_id.clone())
                        .or_insert(0);
                    *node_peak = (*node_peak).max(node_active);

                    let method_active = {
                        let active = state
                            .active_by_method
                            .entry(task.method_key.clone())
                            .or_insert(0);
                        *active += 1;
                        *active
                    };
                    let method_peak = state
                        .peak_by_method
                        .entry(task.method_key.clone())
                        .or_insert(0);
                    *method_peak = (*method_peak).max(method_active);
                }

                tokio::time::sleep(delay).await;

                {
                    let mut state = state.lock().expect("tracking state");
                    state.in_flight -= 1;
                    *state
                        .active_by_node
                        .get_mut(&task.node.node_id)
                        .expect("active node") -= 1;
                    *state
                        .active_by_method
                        .get_mut(&task.method_key)
                        .expect("active method") -= 1;
                }

                let ok = !fail_nodes.contains(&task.node.node_id);
                SchedulerTaskOutcome::from_observations(
                    task.clone(),
                    vec![SchedulerObservationOutcome {
                        node_id: Some(task.node.node_id.clone()),
                        endpoint_id: Some(task.node.endpoint_id.clone()),
                        method: task.method_key.clone(),
                        ok,
                        error_code: (!ok).then(|| "FAKE_RPC_FAILED".to_string()),
                        duration_ms: 1,
                        result_class: CONTROLLER_RPC_RESULT_CLASS.to_string(),
                        summary_json: json!({"result_class": CONTROLLER_RPC_RESULT_CLASS}),
                    }],
                    Vec::new(),
                )
            })
        }
    }

    fn test_task(job_id: &str, node_id: &str, method: &'static str) -> ResolvedSchedulerTask {
        ResolvedSchedulerTask {
            job_id: job_id.to_string(),
            run_id: format!("run-{job_id}"),
            actor: "scheduler-unit-test".to_string(),
            kind: StoredJobKind::ControllerPing,
            node: NodeRecord {
                node_id: node_id.to_string(),
                endpoint_id: format!("{node_id}-endpoint"),
                name: node_id.to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
                enabled: true,
            },
            rpc: SchedulerTaskRpc::Fixed(FixedControllerRpc::ProbeControllerPing),
            method_key: method.to_string(),
            ordinal: 0,
        }
    }

    fn test_job(job_id: &str) -> ObservabilityJobRecord {
        ObservabilityJobRecord {
            job_id: job_id.to_string(),
            kind: "controller-ping".to_string(),
            selector_json: SchedulerSelectorPayloadV1::new("role=ocserv".to_string(), None)
                .expect("valid selector")
                .to_value(),
            pair_selector_json: None,
            interval_seconds: 60,
            jitter_seconds: 0,
            timeout_ms: DEFAULT_DEADLINE_MS,
            enabled: true,
            next_run_at: None,
            last_run_at: None,
            created_at: "2026-07-09T00:00:00Z".to_string(),
            updated_at: "2026-07-09T00:00:00Z".to_string(),
        }
    }

    fn seed_dispatch_node(store: &Store, node_id: &str) -> NodeRecord {
        let endpoint_id = iroh::SecretKey::generate().public().to_string();
        store
            .add_node(
                &NodeInsert {
                    node_id: node_id.to_string(),
                    endpoint_id,
                    name: node_id.to_string(),
                    region: "hk".to_string(),
                    role: "ocserv".to_string(),
                },
                "scheduler-dispatch-test",
            )
            .expect("seed scheduler node");
        store
            .get_node(node_id)
            .expect("load scheduler node")
            .expect("scheduler node exists")
    }

    #[tokio::test]
    async fn scheduler_dispatch_rechecks_source_trust_after_semaphore_acquisition() {
        let dir = tempfile::tempdir().expect("temp dir");
        let database = dir.path().join("controller.sqlite");
        let secret_key = dir.path().join("missing.secret");
        let store = Store::open(&database).expect("open store");
        let node = seed_dispatch_node(&store, "source-node");
        let task = ResolvedSchedulerTask {
            job_id: "job-source".to_string(),
            run_id: "run-source".to_string(),
            actor: "scheduler-dispatch-test".to_string(),
            kind: StoredJobKind::ControllerPing,
            node: node.clone(),
            rpc: SchedulerTaskRpc::Fixed(FixedControllerRpc::ProbeControllerPing),
            method_key: PROBE_CONTROLLER_PING.to_string(),
            ordinal: 0,
        };
        let executor = MutateTrustThenDispatchExecutor {
            database_path: Arc::new(database),
            secret_key_path: Arc::new(secret_key.clone()),
            endpoint_id: Arc::new(node.endpoint_id),
            mutation: DispatchTrustMutation::Delete,
        };

        let outcomes = execute_resolved_scheduler_tasks(
            vec![task],
            SchedulerLimits::from_max_concurrency(1).expect("limits"),
            executor,
        )
        .await;

        assert_eq!(outcomes.len(), 1);
        assert_eq!(
            outcomes[0].observations[0].error_code.as_deref(),
            Some("ENDPOINT_TRUST_MISSING")
        );
        assert_eq!(
            outcomes[0].rpc_audits[0].error_code,
            Some(ErrorCode::EndpointNotAllowed)
        );
        assert_eq!(
            outcomes[0].rpc_audits[0].detail_json["endpoint_trust_state"],
            "missing"
        );
        assert!(!secret_key.exists());
    }

    #[tokio::test]
    async fn scheduler_dispatch_rechecks_unbound_source_after_semaphore_acquisition() {
        let dir = tempfile::tempdir().expect("temp dir");
        let database = dir.path().join("controller.sqlite");
        let secret_key = dir.path().join("missing.secret");
        let store = Store::open(&database).expect("open store");
        let node = seed_dispatch_node(&store, "unbound-source-node");
        let task = ResolvedSchedulerTask {
            job_id: "job-unbound-source".to_string(),
            run_id: "run-unbound-source".to_string(),
            actor: "scheduler-dispatch-test".to_string(),
            kind: StoredJobKind::ControllerPing,
            node: node.clone(),
            rpc: SchedulerTaskRpc::Fixed(FixedControllerRpc::ProbeControllerPing),
            method_key: PROBE_CONTROLLER_PING.to_string(),
            ordinal: 0,
        };
        let executor = MutateTrustThenDispatchExecutor {
            database_path: Arc::new(database),
            secret_key_path: Arc::new(secret_key.clone()),
            endpoint_id: Arc::new(node.endpoint_id),
            mutation: DispatchTrustMutation::SetNode(None),
        };

        let outcomes = execute_resolved_scheduler_tasks(
            vec![task],
            SchedulerLimits::from_max_concurrency(1).expect("limits"),
            executor,
        )
        .await;

        assert_eq!(outcomes.len(), 1);
        assert_eq!(
            outcomes[0].observations[0].error_code.as_deref(),
            Some("ENDPOINT_TRUST_UNBOUND")
        );
        assert_eq!(
            outcomes[0].rpc_audits[0].error_code,
            Some(ErrorCode::EndpointNotAllowed)
        );
        assert_eq!(
            outcomes[0].rpc_audits[0].detail_json["endpoint_trust_state"],
            "unbound"
        );
        assert!(!secret_key.exists());
    }

    #[tokio::test]
    async fn scheduler_dispatch_rechecks_source_binding_after_semaphore_acquisition() {
        let dir = tempfile::tempdir().expect("temp dir");
        let database = dir.path().join("controller.sqlite");
        let secret_key = dir.path().join("missing.secret");
        let store = Store::open(&database).expect("open store");
        let node = seed_dispatch_node(&store, "binding-source-node");
        let wrong = seed_dispatch_node(&store, "different-source-binding-node");
        let task = ResolvedSchedulerTask {
            job_id: "job-source-binding".to_string(),
            run_id: "run-source-binding".to_string(),
            actor: "scheduler-dispatch-test".to_string(),
            kind: StoredJobKind::ControllerPing,
            node: node.clone(),
            rpc: SchedulerTaskRpc::Fixed(FixedControllerRpc::ProbeControllerPing),
            method_key: PROBE_CONTROLLER_PING.to_string(),
            ordinal: 0,
        };
        let executor = MutateTrustThenDispatchExecutor {
            database_path: Arc::new(database),
            secret_key_path: Arc::new(secret_key.clone()),
            endpoint_id: Arc::new(node.endpoint_id),
            mutation: DispatchTrustMutation::SetNode(Some(wrong.node_id)),
        };

        let outcomes = execute_resolved_scheduler_tasks(
            vec![task],
            SchedulerLimits::from_max_concurrency(1).expect("limits"),
            executor,
        )
        .await;

        assert_eq!(outcomes.len(), 1);
        assert_eq!(
            outcomes[0].observations[0].error_code.as_deref(),
            Some("ENDPOINT_TRUST_BINDING_MISMATCH")
        );
        assert_eq!(
            outcomes[0].rpc_audits[0].error_code,
            Some(ErrorCode::EndpointNotAllowed)
        );
        assert_eq!(
            outcomes[0].rpc_audits[0].detail_json["endpoint_trust_state"],
            "binding_mismatch"
        );
        assert!(!secret_key.exists());
    }

    #[tokio::test]
    async fn scheduler_dispatch_rejects_malformed_enabled_after_semaphore_acquisition() {
        let dir = tempfile::tempdir().expect("temp dir");
        let database = dir.path().join("controller.sqlite");
        let secret_key = dir.path().join("missing.secret");
        let store = Store::open(&database).expect("open store");
        let node = seed_dispatch_node(&store, "malformed-enabled-node");
        let task = ResolvedSchedulerTask {
            job_id: "job-malformed-enabled".to_string(),
            run_id: "run-malformed-enabled".to_string(),
            actor: "scheduler-dispatch-test".to_string(),
            kind: StoredJobKind::ControllerPing,
            node: node.clone(),
            rpc: SchedulerTaskRpc::Fixed(FixedControllerRpc::ProbeControllerPing),
            method_key: PROBE_CONTROLLER_PING.to_string(),
            ordinal: 0,
        };
        let executor = MutateTrustThenDispatchExecutor {
            database_path: Arc::new(database),
            secret_key_path: Arc::new(secret_key.clone()),
            endpoint_id: Arc::new(node.endpoint_id),
            mutation: DispatchTrustMutation::SetRegistryEnabled(2),
        };

        let outcomes = execute_resolved_scheduler_tasks(
            vec![task],
            SchedulerLimits::from_max_concurrency(1).expect("limits"),
            executor,
        )
        .await;

        assert_eq!(outcomes.len(), 1);
        assert_eq!(
            outcomes[0].observations[0].error_code.as_deref(),
            Some("SQLITE_ERROR")
        );
        assert_eq!(
            outcomes[0].observations[0].summary_json["message"],
            "controller endpoint trust read failed"
        );
        assert_eq!(
            outcomes[0].rpc_audits[0].error_code,
            Some(ErrorCode::SqliteError)
        );
        assert_eq!(
            outcomes[0].rpc_audits[0].detail_json["message"],
            "controller endpoint trust read failed"
        );
        assert!(
            outcomes[0].rpc_audits[0]
                .detail_json
                .get("endpoint_trust_state")
                .is_none()
        );
        assert!(!secret_key.exists());
    }

    #[tokio::test]
    async fn scheduler_dispatch_rechecks_path_target_trust_after_semaphore_acquisition() {
        let dir = tempfile::tempdir().expect("temp dir");
        let database = dir.path().join("controller.sqlite");
        let secret_key = dir.path().join("missing.secret");
        let store = Store::open(&database).expect("open store");
        let source = seed_dispatch_node(&store, "source-node");
        let target = seed_dispatch_node(&store, "target-node");
        let task = ResolvedSchedulerTask {
            job_id: "job-path".to_string(),
            run_id: "run-path".to_string(),
            actor: "scheduler-dispatch-test".to_string(),
            kind: StoredJobKind::PathProbe,
            node: source,
            rpc: SchedulerTaskRpc::PathProbe {
                target_node_id: target.node_id.clone(),
                target_endpoint_id: target.endpoint_id.clone(),
            },
            method_key: PROBE_PATH_ECHO.to_string(),
            ordinal: 0,
        };
        let executor = MutateTrustThenDispatchExecutor {
            database_path: Arc::new(database),
            secret_key_path: Arc::new(secret_key.clone()),
            endpoint_id: Arc::new(target.endpoint_id),
            mutation: DispatchTrustMutation::Delete,
        };

        let outcomes = execute_resolved_scheduler_tasks(
            vec![task],
            SchedulerLimits::from_max_concurrency(1).expect("limits"),
            executor,
        )
        .await;

        assert_eq!(outcomes.len(), 1);
        assert_eq!(
            outcomes[0].observations[0].error_code.as_deref(),
            Some("TARGET_ENDPOINT_TRUST_MISSING")
        );
        assert_eq!(
            outcomes[0].observations[0].summary_json["target_node_id"],
            "target-node"
        );
        assert!(
            outcomes[0].observations[0].summary_json["target_endpoint_id"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        assert_eq!(
            outcomes[0].rpc_audits[0].error_code,
            Some(ErrorCode::EndpointNotAllowed)
        );
        assert_eq!(
            outcomes[0].rpc_audits[0].detail_json["target_endpoint_trust_state"],
            "missing"
        );
        assert_eq!(
            outcomes[0].rpc_audits[0].detail_json["target_node_id"],
            "target-node"
        );
        assert!(!secret_key.exists());
    }

    #[tokio::test]
    async fn scheduler_dispatch_rechecks_unbound_target_after_semaphore_acquisition() {
        let dir = tempfile::tempdir().expect("temp dir");
        let database = dir.path().join("controller.sqlite");
        let secret_key = dir.path().join("missing.secret");
        let store = Store::open(&database).expect("open store");
        let source = seed_dispatch_node(&store, "unbound-target-source-node");
        let target = seed_dispatch_node(&store, "unbound-target-node");
        let task = ResolvedSchedulerTask {
            job_id: "job-unbound-target".to_string(),
            run_id: "run-unbound-target".to_string(),
            actor: "scheduler-dispatch-test".to_string(),
            kind: StoredJobKind::PathProbe,
            node: source,
            rpc: SchedulerTaskRpc::PathProbe {
                target_node_id: target.node_id.clone(),
                target_endpoint_id: target.endpoint_id.clone(),
            },
            method_key: PROBE_PATH_ECHO.to_string(),
            ordinal: 0,
        };
        let executor = MutateTrustThenDispatchExecutor {
            database_path: Arc::new(database),
            secret_key_path: Arc::new(secret_key.clone()),
            endpoint_id: Arc::new(target.endpoint_id),
            mutation: DispatchTrustMutation::SetNode(None),
        };

        let outcomes = execute_resolved_scheduler_tasks(
            vec![task],
            SchedulerLimits::from_max_concurrency(1).expect("limits"),
            executor,
        )
        .await;

        assert_eq!(outcomes.len(), 1);
        assert_eq!(
            outcomes[0].observations[0].error_code.as_deref(),
            Some("TARGET_ENDPOINT_TRUST_UNBOUND")
        );
        assert_eq!(
            outcomes[0].rpc_audits[0].error_code,
            Some(ErrorCode::EndpointNotAllowed)
        );
        assert_eq!(
            outcomes[0].rpc_audits[0].detail_json["target_endpoint_trust_state"],
            "unbound"
        );
        assert_eq!(
            outcomes[0].rpc_audits[0].detail_json["target_node_id"],
            "unbound-target-node"
        );
        assert!(!secret_key.exists());
    }

    #[tokio::test]
    async fn scheduler_dispatch_rechecks_target_binding_after_semaphore_acquisition() {
        let dir = tempfile::tempdir().expect("temp dir");
        let database = dir.path().join("controller.sqlite");
        let secret_key = dir.path().join("missing.secret");
        let store = Store::open(&database).expect("open store");
        let source = seed_dispatch_node(&store, "binding-source-node");
        let target = seed_dispatch_node(&store, "binding-target-node");
        let wrong = seed_dispatch_node(&store, "different-binding-node");
        let wrong_node_id = wrong.node_id;
        let task = ResolvedSchedulerTask {
            job_id: "job-target-binding".to_string(),
            run_id: "run-target-binding".to_string(),
            actor: "scheduler-dispatch-test".to_string(),
            kind: StoredJobKind::PathProbe,
            node: source,
            rpc: SchedulerTaskRpc::PathProbe {
                target_node_id: target.node_id.clone(),
                target_endpoint_id: target.endpoint_id.clone(),
            },
            method_key: PROBE_PATH_ECHO.to_string(),
            ordinal: 0,
        };
        let executor = MutateTrustThenDispatchExecutor {
            database_path: Arc::new(database),
            secret_key_path: Arc::new(secret_key.clone()),
            endpoint_id: Arc::new(target.endpoint_id),
            mutation: DispatchTrustMutation::SetNode(Some(wrong_node_id)),
        };

        let outcomes = execute_resolved_scheduler_tasks(
            vec![task],
            SchedulerLimits::from_max_concurrency(1).expect("limits"),
            executor,
        )
        .await;

        assert_eq!(outcomes.len(), 1);
        assert_eq!(
            outcomes[0].observations[0].error_code.as_deref(),
            Some("TARGET_ENDPOINT_TRUST_BINDING_MISMATCH")
        );
        assert_eq!(
            outcomes[0].rpc_audits[0].error_code,
            Some(ErrorCode::EndpointNotAllowed)
        );
        assert_eq!(
            outcomes[0].rpc_audits[0].detail_json["target_endpoint_trust_state"],
            "binding_mismatch"
        );
        assert_eq!(
            outcomes[0].rpc_audits[0].detail_json["target_node_id"],
            "binding-target-node"
        );
        assert!(!secret_key.exists());
    }

    #[test]
    fn scheduler_rpc_budget_truncates_tasks_and_reports_skipped_work() {
        let job = test_job("job-a");
        let mut tasks = (0..3)
            .map(|index| test_task("job-a", &format!("node-{index}"), PROBE_CONTROLLER_PING))
            .collect::<Vec<_>>();
        let mut budget = 1;

        let outcomes = limit_tasks_by_rpc_budget(
            &job,
            "scheduler-unit-test",
            "run-job-a",
            StoredJobKind::ControllerPing,
            &mut tasks,
            &mut budget,
        );

        assert_eq!(tasks.len(), 1);
        assert_eq!(budget, 0);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(
            outcomes[0].observations[0].error_code.as_deref(),
            Some("SCHEDULER_RPC_BUDGET_EXCEEDED")
        );
        assert_eq!(outcomes[0].observations[0].summary_json["skipped_tasks"], 2);
    }

    #[tokio::test]
    async fn scheduler_executor_enforces_global_max_concurrency() {
        let tasks = (0..8)
            .map(|index| test_task("job-a", &format!("node-{index}"), PROBE_CONTROLLER_PING))
            .collect::<Vec<_>>();
        let executor = TrackingExecutor::with_delay(StdDuration::from_millis(20));
        let limits = SchedulerLimits {
            max_concurrency: 3,
            per_node_concurrency: 1,
            per_method_concurrency: 3,
            rpc_budget_per_tick: 100,
        };

        let outcomes = execute_resolved_scheduler_tasks(tasks, limits, executor.clone()).await;

        assert_eq!(outcomes.len(), 8);
        assert!(
            outcomes
                .iter()
                .all(SchedulerTaskOutcome::all_observations_ok)
        );
        assert!(executor.global_peak() <= 3);
    }

    #[tokio::test]
    async fn scheduler_executor_enforces_per_node_concurrency_one() {
        let tasks = (0..5)
            .map(|index| {
                let mut task = test_task("job-a", "same-node", PROBE_CONTROLLER_PING);
                task.ordinal = index;
                task
            })
            .collect::<Vec<_>>();
        let executor = TrackingExecutor::with_delay(StdDuration::from_millis(20));
        let limits = SchedulerLimits {
            max_concurrency: 5,
            per_node_concurrency: 1,
            per_method_concurrency: 5,
            rpc_budget_per_tick: 100,
        };

        let outcomes = execute_resolved_scheduler_tasks(tasks, limits, executor.clone()).await;

        assert_eq!(outcomes.len(), 5);
        assert_eq!(executor.node_peak("same-node"), 1);
    }

    #[tokio::test]
    async fn scheduler_executor_enforces_per_method_cap() {
        let tasks = (0..6)
            .map(|index| test_task("job-a", &format!("node-{index}"), PROBE_CONTROLLER_PING))
            .collect::<Vec<_>>();
        let executor = TrackingExecutor::with_delay(StdDuration::from_millis(20));
        let limits = SchedulerLimits {
            max_concurrency: 6,
            per_node_concurrency: 1,
            per_method_concurrency: 2,
            rpc_budget_per_tick: 100,
        };

        let outcomes = execute_resolved_scheduler_tasks(tasks, limits, executor.clone()).await;

        assert_eq!(outcomes.len(), 6);
        assert!(executor.method_peak(PROBE_CONTROLLER_PING) <= 2);
    }

    #[tokio::test]
    async fn scheduler_executor_keeps_partial_failures_and_stable_order() {
        let tasks = vec![
            test_task("job-b", "node-2", PROBE_CONTROLLER_PING),
            test_task("job-a", "node-1", PROBE_CONTROLLER_PING),
            test_task("job-a", "node-0", PROBE_CONTROLLER_PING),
        ];
        let executor = TrackingExecutor::failing_node(StdDuration::from_millis(5), "node-1");
        let limits = SchedulerLimits {
            max_concurrency: 3,
            per_node_concurrency: 1,
            per_method_concurrency: 3,
            rpc_budget_per_tick: 100,
        };

        let outcomes = execute_resolved_scheduler_tasks(tasks, limits, executor).await;

        let ordered_nodes = outcomes
            .iter()
            .map(|outcome| outcome.task.node.node_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ordered_nodes, ["node-0", "node-1", "node-2"]);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| !outcome.all_observations_ok())
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn scheduler_executor_parallel_wall_clock_is_lower_than_serial() {
        let tasks = (0..8)
            .map(|index| test_task("job-a", &format!("node-{index}"), PROBE_CONTROLLER_PING))
            .collect::<Vec<_>>();
        let executor = TrackingExecutor::with_delay(StdDuration::from_millis(35));
        let serial_limits = SchedulerLimits {
            max_concurrency: 1,
            per_node_concurrency: 1,
            per_method_concurrency: 1,
            rpc_budget_per_tick: 100,
        };
        let parallel_limits = SchedulerLimits {
            max_concurrency: 4,
            per_node_concurrency: 1,
            per_method_concurrency: 4,
            rpc_budget_per_tick: 100,
        };

        let serial_started = std::time::Instant::now();
        let serial = execute_resolved_scheduler_tasks(
            tasks.clone(),
            serial_limits,
            TrackingExecutor::with_delay(StdDuration::from_millis(35)),
        )
        .await;
        let serial_elapsed = serial_started.elapsed();

        let parallel_started = std::time::Instant::now();
        let parallel = execute_resolved_scheduler_tasks(tasks, parallel_limits, executor).await;
        let parallel_elapsed = parallel_started.elapsed();

        assert_eq!(serial.len(), parallel.len());
        assert!(
            parallel_elapsed * 2 < serial_elapsed,
            "parallel={parallel_elapsed:?} serial={serial_elapsed:?}"
        );
    }
}
