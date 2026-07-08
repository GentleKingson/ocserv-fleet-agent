use anyhow::{Context, bail};
use ocfleet_config::validation::validate_node_id;
use ocfleet_protocol::DEFAULT_DEADLINE_MS;
use ocfleet_protocol::method::{
    OCSERV_CERT_EXPIRY, OCSERV_CONFIG_FINGERPRINT, OCSERV_SERVICE_SUMMARY, OCSERV_SESSIONS_SUMMARY,
    OCSERV_VERSION, PROBE_CONTROLLER_PING, PROBE_PATH_ECHO,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::path::Path;
use std::time::Instant;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::args::{ScheduleCommand, ScheduleJobCommand, ScheduleJobKind};
use crate::audit::AuditEvent;
use crate::controller_rpc::{
    CONTROLLER_RPC_RESULT_CLASS, ControllerRpcOutcome, ControllerRpcRunner, OCSERV_RESULT_CLASS,
    OcservRpcOutcome, elapsed_ms, error_code_name, execute_node_rpc, hash_json_value,
    inactive_endpoint_status, write_rpc_audit,
};
use crate::store::{ObservabilityJobRecord, ObservabilityRunInsert, ProbeObservationInsert, Store};

const DEFAULT_SELECTOR: &str = "role=ocserv";
const EXPLICIT_PAIR_SELECTOR: &str = "explicit-pair";
const SCHEDULER_RESULT_CLASS: &str = "scheduler_summary";

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
}

#[derive(Debug, Clone)]
struct TargetNode {
    node_id: String,
}

struct OcservObservationContext<'a> {
    store: &'a Store,
    run_id: &'a str,
    node_id: &'a str,
    endpoint_id: Option<&'a str>,
    duration_ms: u64,
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
    Ok(seconds)
}

pub async fn run_schedule_command(
    store: &Store,
    secret_key_path: &Path,
    command: ScheduleCommand,
) -> anyhow::Result<()> {
    match command {
        ScheduleCommand::Job { command } => run_schedule_job_command(store, command),
        ScheduleCommand::Run {
            once,
            max_concurrency,
        } => run_schedule_run_once_command(store, secret_key_path, once, max_concurrency).await,
        ScheduleCommand::Daemon {
            max_concurrency,
            tick_seconds,
        } => {
            run_schedule_daemon_command(store, secret_key_path, max_concurrency, tick_seconds).await
        }
        ScheduleCommand::Status => run_schedule_status_command(store),
    }
}

fn run_schedule_job_command(store: &Store, command: ScheduleJobCommand) -> anyhow::Result<()> {
    match command {
        ScheduleJobCommand::Add {
            kind,
            interval,
            selector,
            source_node_id,
            target_node_id,
        } => add_job(
            store,
            kind,
            &interval,
            selector,
            source_node_id,
            target_node_id,
        ),
        ScheduleJobCommand::List => list_jobs(store),
        ScheduleJobCommand::Enable { job_id } => set_job_enabled(store, &job_id, true),
        ScheduleJobCommand::Disable { job_id } => set_job_enabled(store, &job_id, false),
    }
}

fn add_job(
    store: &Store,
    kind: ScheduleJobKind,
    interval: &str,
    selector: Option<String>,
    source_node_id: Option<String>,
    target_node_id: Option<String>,
) -> anyhow::Result<()> {
    let interval_seconds = parse_interval_seconds(interval)?;
    let (selector_value, pair_selector_json) =
        build_selectors(kind, selector, source_node_id, target_node_id)?;
    let now = now_rfc3339();
    let job = ObservabilityJobRecord {
        job_id: format!("job-{}", Uuid::new_v4().simple()),
        kind: schedule_kind_name(kind).to_string(),
        selector_json: json!({ "selector": selector_value }),
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
    store.insert_observability_job(&job)?;
    write_scheduler_audit(
        store,
        "scheduler.job.add",
        true,
        json!({
            "job_id": job.job_id.as_str(),
            "kind": job.kind.as_str(),
            "interval_seconds": job.interval_seconds,
            "selector": selector_value.as_str(),
            "result_class": SCHEDULER_RESULT_CLASS,
        }),
    )?;
    println!("job_id={}", job.job_id);
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

fn list_jobs(store: &Store) -> anyhow::Result<()> {
    for job in store.list_observability_jobs()? {
        println!(
            "job_id={} kind={} enabled={} interval_seconds={} selector={} next_run_at={} last_run_at={}",
            job.job_id,
            job.kind,
            job.enabled,
            job.interval_seconds,
            selector_label(&job),
            job.next_run_at.as_deref().unwrap_or("<none>"),
            job.last_run_at.as_deref().unwrap_or("<none>")
        );
    }
    Ok(())
}

fn set_job_enabled(store: &Store, job_id: &str, enabled: bool) -> anyhow::Result<()> {
    if !store
        .list_observability_jobs()?
        .iter()
        .any(|job| job.job_id == job_id)
    {
        bail!("observability job not found: {job_id}");
    }
    store.set_observability_job_enabled(job_id, enabled)?;
    let event_name = if enabled {
        "scheduler.job.enable"
    } else {
        "scheduler.job.disable"
    };
    write_scheduler_audit(
        store,
        event_name,
        true,
        json!({
            "job_id": job_id,
            "enabled": enabled,
            "result_class": SCHEDULER_RESULT_CLASS,
        }),
    )?;
    println!("job_id={job_id}");
    println!("enabled={enabled}");
    Ok(())
}

async fn run_schedule_run_once_command(
    store: &Store,
    secret_key_path: &Path,
    once: bool,
    max_concurrency: usize,
) -> anyhow::Result<()> {
    if !once {
        bail!("schedule run currently requires --once");
    }
    let stats = run_due_jobs_once(store, secret_key_path, max_concurrency).await?;
    // TODO(Phase 12): call alert evaluation after scheduler runs once the
    // alert policy surface is finalized for scheduled delivery.
    write_scheduler_audit(
        store,
        "scheduler.run.once",
        true,
        json!({
            "due_jobs": stats.due_jobs,
            "executed_jobs": stats.executed_jobs,
            "skipped_jobs": stats.skipped_jobs,
            "observations": stats.observations,
            "failed_observations": stats.failed_observations,
            "max_concurrency": max_concurrency,
            "result_class": SCHEDULER_RESULT_CLASS,
        }),
    )?;
    println!("status=ok");
    println!("due_jobs={}", stats.due_jobs);
    println!("executed_jobs={}", stats.executed_jobs);
    println!("skipped_jobs={}", stats.skipped_jobs);
    println!("observations={}", stats.observations);
    println!("failed_observations={}", stats.failed_observations);
    Ok(())
}

async fn run_schedule_daemon_command(
    store: &Store,
    secret_key_path: &Path,
    max_concurrency: usize,
    tick_seconds: u64,
) -> anyhow::Result<()> {
    if tick_seconds == 0 {
        bail!("--tick-seconds must be greater than zero");
    }
    if max_concurrency == 0 {
        bail!("--max-concurrency must be greater than zero");
    }
    write_scheduler_audit(
        store,
        "scheduler.daemon.start",
        true,
        json!({
            "tick_seconds": tick_seconds,
            "max_concurrency": max_concurrency,
            "result_class": SCHEDULER_RESULT_CLASS,
        }),
    )?;

    loop {
        run_due_jobs_once(store, secret_key_path, max_concurrency).await?;
        // TODO(Phase 12): call alert evaluation after scheduler ticks once the
        // alert policy surface is finalized for scheduled delivery.
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(tick_seconds)) => {}
            _ = shutdown_signal() => {
                break;
            }
        }
    }

    write_scheduler_audit(
        store,
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

fn run_schedule_status_command(store: &Store) -> anyhow::Result<()> {
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

    println!("enabled_jobs={enabled_job_count}");
    println!("due_jobs={due_job_count}");
    if let Some((last_run_at, job)) = last_run {
        println!("last_run_job_id={}", job.job_id);
        println!("last_run_at={last_run_at}");
    } else {
        println!("last_run_job_id=<none>");
        println!("last_run_at=<none>");
    }
    Ok(())
}

async fn run_due_jobs_once(
    store: &Store,
    secret_key_path: &Path,
    max_concurrency: usize,
) -> anyhow::Result<RunStats> {
    if max_concurrency == 0 {
        bail!("--max-concurrency must be greater than zero");
    }
    let jobs = store.list_observability_jobs()?;
    let now = OffsetDateTime::now_utc();
    let mut stats = RunStats {
        skipped_jobs: jobs.iter().filter(|job| !job.enabled).count(),
        ..RunStats::default()
    };
    for job in jobs {
        if !job.enabled || !job_due_at_or_before(&job, now)? {
            continue;
        }
        stats.due_jobs += 1;
        let job_stats = run_job(store, secret_key_path, &job).await?;
        stats.executed_jobs += 1;
        stats.observations += job_stats.observations;
        stats.failed_observations += job_stats.failed_observations;
        let finished_at = now_rfc3339();
        let next_run_at = offset_to_rfc3339(
            OffsetDateTime::parse(&finished_at, &Rfc3339).expect("formatted timestamp parses")
                + Duration::seconds(job.interval_seconds as i64),
        );
        store.update_observability_job_run_times(
            &job.job_id,
            Some(&next_run_at),
            Some(&finished_at),
        )?;
    }
    Ok(stats)
}

async fn run_job(
    store: &Store,
    secret_key_path: &Path,
    job: &ObservabilityJobRecord,
) -> anyhow::Result<RunStats> {
    let kind = stored_job_kind(&job.kind)?;
    let started_at = now_rfc3339();
    let run_id = format!("run-{}", Uuid::new_v4().simple());
    store.insert_observability_run(&ObservabilityRunInsert {
        run_id: run_id.clone(),
        job_id: Some(job.job_id.clone()),
        started_at: started_at.clone(),
        finished_at: None,
        status: "running".to_string(),
        triggered_by: "scheduler.run.once".to_string(),
        summary_json: json!({
            "job_id": job.job_id,
            "kind": job.kind,
            "result_class": SCHEDULER_RESULT_CLASS,
        }),
    })?;

    let mut stats = RunStats::default();
    match kind {
        StoredJobKind::PathProbe => {
            run_path_probe_job(store, secret_key_path, job, &run_id, &mut stats).await?
        }
        StoredJobKind::ControllerPing
        | StoredJobKind::OcservStatus
        | StoredJobKind::OcservCert
        | StoredJobKind::OcservSessions => {
            let targets = resolve_node_targets(store, selector_label(job))?;
            if targets.is_empty() {
                record_missing_target_observation(store, &run_id, job, "NODE_NOT_FOUND")?;
                stats.observations += 1;
                stats.failed_observations += 1;
            } else {
                for target in targets {
                    run_node_target_job(store, secret_key_path, kind, &run_id, target, &mut stats)
                        .await?;
                }
            }
        }
    }

    let finished_at = now_rfc3339();
    let status = if stats.observations == 0 {
        "skipped"
    } else if stats.failed_observations == 0 {
        "succeeded"
    } else {
        "failed"
    };
    store.finish_observability_run(
        &run_id,
        &finished_at,
        status,
        &json!({
            "job_id": job.job_id,
            "kind": job.kind,
            "status": status,
            "observations": stats.observations,
            "failed_observations": stats.failed_observations,
            "result_class": SCHEDULER_RESULT_CLASS,
        }),
    )?;
    Ok(stats)
}

async fn run_node_target_job(
    store: &Store,
    secret_key_path: &Path,
    kind: StoredJobKind,
    run_id: &str,
    target: TargetNode,
    stats: &mut RunStats,
) -> anyhow::Result<()> {
    let runner = ControllerRpcRunner::new(store, secret_key_path);
    match kind {
        StoredJobKind::ControllerPing => {
            let outcome = runner
                .run_fixed_node_rpc(&target.node_id, PROBE_CONTROLLER_PING)
                .await;
            record_controller_outcome(store, run_id, &outcome)?;
            update_observation_stats(stats, outcome.ok);
        }
        StoredJobKind::OcservStatus => {
            let outcome = runner.run_ocserv_status_bundle(&target.node_id).await;
            let context = OcservObservationContext {
                store,
                run_id,
                node_id: &outcome.node_id,
                endpoint_id: outcome.endpoint_id.as_deref(),
                duration_ms: outcome.duration_ms,
            };
            record_ocserv_suboutcome(&context, OCSERV_SERVICE_SUMMARY, &outcome.service, stats)?;
            record_ocserv_suboutcome(&context, OCSERV_VERSION, &outcome.version, stats)?;
            record_ocserv_suboutcome(&context, OCSERV_SESSIONS_SUMMARY, &outcome.sessions, stats)?;
            record_ocserv_suboutcome(
                &context,
                OCSERV_CONFIG_FINGERPRINT,
                &outcome.config_fingerprint,
                stats,
            )?;
        }
        StoredJobKind::OcservCert => {
            let outcome = runner.run_ocserv_cert(&target.node_id).await;
            record_controller_outcome(store, run_id, &outcome)?;
            update_observation_stats(stats, outcome.ok);
        }
        StoredJobKind::OcservSessions => {
            let outcome = runner.run_ocserv_sessions_summary(&target.node_id).await;
            record_controller_outcome(store, run_id, &outcome)?;
            update_observation_stats(stats, outcome.ok);
        }
        StoredJobKind::PathProbe => unreachable!("path probes use explicit source and target pair"),
    }
    Ok(())
}

async fn run_path_probe_job(
    store: &Store,
    secret_key_path: &Path,
    job: &ObservabilityJobRecord,
    run_id: &str,
    stats: &mut RunStats,
) -> anyhow::Result<()> {
    let (source_node_id, target_node_id) = explicit_pair(job)?;
    let source = store.get_node(&source_node_id)?;
    let target = store.get_node(&target_node_id)?;
    let Some(source) = source else {
        record_path_probe_preflight_observation(
            store,
            run_id,
            &source_node_id,
            None,
            "NODE_NOT_FOUND",
        )?;
        update_observation_stats(stats, false);
        return Ok(());
    };
    if !source.enabled {
        record_path_probe_preflight_observation(
            store,
            run_id,
            &source.node_id,
            Some(&source.endpoint_id),
            "NODE_DISABLED",
        )?;
        update_observation_stats(stats, false);
        return Ok(());
    }
    if let Some(status) = inactive_endpoint_status(store, &source.endpoint_id)? {
        record_path_probe_preflight_observation(
            store,
            run_id,
            &source.node_id,
            Some(&source.endpoint_id),
            &format!("ENDPOINT_{}", status.as_str().to_ascii_uppercase()),
        )?;
        update_observation_stats(stats, false);
        return Ok(());
    }
    let Some(target) = target else {
        record_path_probe_preflight_observation(
            store,
            run_id,
            &source.node_id,
            Some(&source.endpoint_id),
            "TARGET_NODE_NOT_FOUND",
        )?;
        update_observation_stats(stats, false);
        return Ok(());
    };
    if !target.enabled {
        record_path_probe_preflight_observation(
            store,
            run_id,
            &source.node_id,
            Some(&source.endpoint_id),
            "TARGET_NODE_DISABLED",
        )?;
        update_observation_stats(stats, false);
        return Ok(());
    }

    let started = Instant::now();
    let params = json!({ "target_agent_endpoint_id": target.endpoint_id });
    let params_hash = hash_json_value(&params);
    let result = execute_node_rpc(secret_key_path, &source, PROBE_PATH_ECHO, params).await;
    match result {
        Ok(success) => {
            let duration_ms = elapsed_ms(started);
            write_rpc_audit(
                store,
                crate::controller_rpc::RpcAuditRecord {
                    actor: local_actor(),
                    node_id: source.node_id.clone(),
                    endpoint_id: Some(source.endpoint_id.clone()),
                    method: PROBE_PATH_ECHO.to_string(),
                    request_id: Some(success.request_id.clone()),
                    params_hash,
                    ok: true,
                    error_code: None,
                    duration_ms,
                    detail_json: json!({
                        "result_class": CONTROLLER_RPC_RESULT_CLASS,
                        "target_node_id": target.node_id,
                        "target_endpoint_id": target.endpoint_id,
                    }),
                },
            )?;
            store.insert_probe_observation(&ProbeObservationInsert {
                observation_id: observation_id(),
                run_id: Some(run_id.to_string()),
                node_id: Some(source.node_id),
                endpoint_id: Some(source.endpoint_id),
                method: PROBE_PATH_ECHO.to_string(),
                ok: Some(true),
                error_code: None,
                duration_ms: Some(duration_ms),
                observed_at: now_rfc3339(),
                expires_at: None,
                result_class: CONTROLLER_RPC_RESULT_CLASS.to_string(),
                summary_json: json!({
                    "request_id": success.request_id,
                    "target_node_id": target.node_id,
                    "target_endpoint_id": target.endpoint_id,
                    "result_class": CONTROLLER_RPC_RESULT_CLASS,
                }),
            })?;
            update_observation_stats(stats, true);
        }
        Err(failure) => {
            let duration_ms = elapsed_ms(started);
            write_rpc_audit(
                store,
                crate::controller_rpc::RpcAuditRecord {
                    actor: local_actor(),
                    node_id: source.node_id.clone(),
                    endpoint_id: Some(source.endpoint_id.clone()),
                    method: PROBE_PATH_ECHO.to_string(),
                    request_id: failure.request_id.clone(),
                    params_hash,
                    ok: false,
                    error_code: Some(failure.code.clone()),
                    duration_ms,
                    detail_json: failure.detail_json.clone(),
                },
            )?;
            store.insert_probe_observation(&ProbeObservationInsert {
                observation_id: observation_id(),
                run_id: Some(run_id.to_string()),
                node_id: Some(source.node_id),
                endpoint_id: Some(source.endpoint_id),
                method: PROBE_PATH_ECHO.to_string(),
                ok: Some(false),
                error_code: Some(error_code_name(&failure.code)),
                duration_ms: Some(duration_ms),
                observed_at: now_rfc3339(),
                expires_at: None,
                result_class: CONTROLLER_RPC_RESULT_CLASS.to_string(),
                summary_json: json!({
                    "message": "path probe failed",
                    "result_class": CONTROLLER_RPC_RESULT_CLASS,
                }),
            })?;
            update_observation_stats(stats, false);
        }
    }
    Ok(())
}

fn build_selectors(
    kind: ScheduleJobKind,
    selector: Option<String>,
    source_node_id: Option<String>,
    target_node_id: Option<String>,
) -> anyhow::Result<(String, Option<Value>)> {
    let selector = selector.unwrap_or_else(|| {
        if kind == ScheduleJobKind::PathProbe {
            EXPLICIT_PAIR_SELECTOR.to_string()
        } else {
            DEFAULT_SELECTOR.to_string()
        }
    });
    match kind {
        ScheduleJobKind::PathProbe => {
            let source_node_id = source_node_id.context("path-probe requires --source-node-id")?;
            let target_node_id = target_node_id.context("path-probe requires --target-node-id")?;
            validate_node_id(&source_node_id)?;
            validate_node_id(&target_node_id)?;
            Ok((
                selector,
                Some(json!({
                    "source_node_id": source_node_id,
                    "target_node_id": target_node_id,
                })),
            ))
        }
        _ => {
            if source_node_id.is_some() || target_node_id.is_some() {
                bail!("--source-node-id and --target-node-id are only valid for path-probe jobs");
            }
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
            .collect();
        return Ok(targets);
    }
    bail!("selector must use role=<role> or node_id=<node-id>")
}

fn record_controller_outcome(
    store: &Store,
    run_id: &str,
    outcome: &ControllerRpcOutcome,
) -> anyhow::Result<()> {
    store.insert_probe_observation(&ProbeObservationInsert {
        observation_id: observation_id(),
        run_id: Some(run_id.to_string()),
        node_id: Some(outcome.node_id.clone()),
        endpoint_id: outcome.endpoint_id.clone(),
        method: outcome.method.clone(),
        ok: Some(outcome.ok),
        error_code: outcome.error_code.clone(),
        duration_ms: Some(outcome.duration_ms),
        observed_at: now_rfc3339(),
        expires_at: None,
        result_class: outcome.result_class.clone(),
        summary_json: outcome.summary_json.clone(),
    })?;
    Ok(())
}

fn record_ocserv_suboutcome<T>(
    context: &OcservObservationContext<'_>,
    method: &'static str,
    outcome: &OcservRpcOutcome<T>,
    stats: &mut RunStats,
) -> anyhow::Result<()>
where
    T: Serialize,
{
    let (ok, error_code, summary_json) = match outcome {
        OcservRpcOutcome::Available(value) => (true, None, serde_json::to_value(value)?),
        OcservRpcOutcome::Unavailable { code, .. } => (
            false,
            Some(error_code_name(code)),
            json!({
                "message": "ocserv status sub-rpc unavailable",
                "method": method,
                "result_class": OCSERV_RESULT_CLASS,
            }),
        ),
    };
    context
        .store
        .insert_probe_observation(&ProbeObservationInsert {
            observation_id: observation_id(),
            run_id: Some(context.run_id.to_string()),
            node_id: Some(context.node_id.to_string()),
            endpoint_id: context.endpoint_id.map(ToOwned::to_owned),
            method: method.to_string(),
            ok: Some(ok),
            error_code,
            duration_ms: Some(context.duration_ms),
            observed_at: now_rfc3339(),
            expires_at: None,
            result_class: OCSERV_RESULT_CLASS.to_string(),
            summary_json,
        })?;
    update_observation_stats(stats, ok);
    Ok(())
}

fn record_missing_target_observation(
    store: &Store,
    run_id: &str,
    job: &ObservabilityJobRecord,
    error_code: &str,
) -> anyhow::Result<()> {
    store.insert_probe_observation(&ProbeObservationInsert {
        observation_id: observation_id(),
        run_id: Some(run_id.to_string()),
        node_id: None,
        endpoint_id: None,
        method: first_method_for_kind(&job.kind)
            .unwrap_or("unknown")
            .to_string(),
        ok: Some(false),
        error_code: Some(error_code.to_string()),
        duration_ms: Some(0),
        observed_at: now_rfc3339(),
        expires_at: None,
        result_class: scheduler_result_class_for_job(&job.kind).to_string(),
        summary_json: json!({
            "message": "no matching node",
            "selector": selector_label(job),
            "result_class": scheduler_result_class_for_job(&job.kind),
        }),
    })?;
    Ok(())
}

fn record_path_probe_preflight_observation(
    store: &Store,
    run_id: &str,
    node_id: &str,
    endpoint_id: Option<&str>,
    error_code: &str,
) -> anyhow::Result<()> {
    store.insert_probe_observation(&ProbeObservationInsert {
        observation_id: observation_id(),
        run_id: Some(run_id.to_string()),
        node_id: Some(node_id.to_string()),
        endpoint_id: endpoint_id.map(ToOwned::to_owned),
        method: PROBE_PATH_ECHO.to_string(),
        ok: Some(false),
        error_code: Some(error_code.to_string()),
        duration_ms: Some(0),
        observed_at: now_rfc3339(),
        expires_at: None,
        result_class: CONTROLLER_RPC_RESULT_CLASS.to_string(),
        summary_json: json!({
            "message": "path probe preflight failed",
            "result_class": CONTROLLER_RPC_RESULT_CLASS,
        }),
    })?;
    Ok(())
}

fn update_observation_stats(stats: &mut RunStats, ok: bool) {
    stats.observations += 1;
    if !ok {
        stats.failed_observations += 1;
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

fn scheduler_result_class_for_job(kind: &str) -> &'static str {
    match kind {
        "ocserv-status" | "ocserv-cert" | "ocserv-sessions" => OCSERV_RESULT_CLASS,
        _ => CONTROLLER_RPC_RESULT_CLASS,
    }
}

fn selector_label(job: &ObservabilityJobRecord) -> &str {
    job.selector_json
        .get("selector")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_SELECTOR)
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
    event_name: &str,
    ok: bool,
    detail_json: Value,
) -> anyhow::Result<()> {
    let mut event = AuditEvent::new(local_actor(), event_name);
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

fn local_actor() -> String {
    match std::env::var("USER") {
        Ok(actor) if !actor.trim().is_empty() => actor,
        _ => "local-cli".to_string(),
    }
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
