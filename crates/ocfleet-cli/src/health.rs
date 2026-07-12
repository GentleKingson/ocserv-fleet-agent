use anyhow::{Context, bail};
use ocfleet_config::validation::validate_node_id;
use ocfleet_protocol::enrollment::EndpointStatus;
use ocfleet_protocol::method::{
    OCSERV_CERT_EXPIRY, OCSERV_CONFIG_FINGERPRINT, OCSERV_SERVICE_SUMMARY, OCSERV_SESSIONS_SUMMARY,
    OCSERV_VERSION, PROBE_CONTROLLER_PING,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use crate::args::{
    HealthCommand, HealthEvaluatorCommand, HealthPolicyCommand, HealthRollupBucket,
    HealthRollupCommand, HealthSloWindow, HealthSnapshotCommand,
};
use crate::backend::StoreWriter;
use crate::duration_args::parse_duration_seconds;
use crate::input_validation::local_actor;
use crate::observation::safe_observation_summary;
use crate::slo::{SloWindow, project_health_slo};
use crate::storage_payloads::{HealthDegradedMethodsPayloadV1, HealthSummaryPayloadV1};
use crate::store::{
    HealthEvaluationFailure, HealthEvaluationFinish, HealthEvaluationStart, HealthPolicyRecord,
    HealthRollupRecord, HealthRollupSource, HealthRollupWrite, HealthSnapshotRecord,
    HealthSnapshotWrite, NodeRecord, ProbeObservationRecord, Store,
};
use uuid::Uuid;

const OBSERVATION_READ_LIMIT: u64 = 1_000;
const MAX_HEALTH_SNAPSHOT_LIMIT: u64 = 1_000;

pub async fn run_health_command(store: &Store, command: HealthCommand) -> anyhow::Result<()> {
    match command {
        HealthCommand::Summary { json } => run_health_summary(store, json),
        HealthCommand::Node { node_id, json } => run_health_node(store, &node_id, json),
        HealthCommand::Policy { command } => run_health_policy_command(store, command),
        HealthCommand::Snapshot { command } => run_health_snapshot_command(store, command),
        HealthCommand::History {
            from,
            to,
            node,
            limit,
            json,
        } => run_health_history(store, &from, &to, node.as_deref(), limit, json),
        HealthCommand::Rollup { command } => run_health_rollup(store, command),
        HealthCommand::Slo {
            to,
            node,
            window,
            json,
        } => run_health_slo(store, &to, node.as_deref(), slo_window(window), json),
        HealthCommand::Evaluator { command } => run_health_evaluator_command(store, command).await,
    }
}

const HEALTH_COMPUTATION_VERSION: &str = "health-v1";
const HEALTH_EVALUATION_BUCKET_SECONDS: i64 = 60;
const HEALTH_EVALUATION_RECOVERY_SECONDS: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HealthEvaluationOutcome {
    Completed,
    Replayed,
    InProgress,
    Failed,
}

impl HealthEvaluationOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Replayed => "replayed",
            Self::InProgress => "in_progress",
            Self::Failed => "failed",
        }
    }
}

async fn run_health_evaluator_command(
    store: &Store,
    command: HealthEvaluatorCommand,
) -> anyhow::Result<()> {
    match command {
        HealthEvaluatorCommand::Run { json } => {
            let outcome = run_health_evaluation_once(store)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "schema": "ocfleet.health_evaluator.v1",
                        "status": outcome.as_str(),
                    }))?
                );
            } else {
                println!("status={}", outcome.as_str());
            }
            Ok(())
        }
        HealthEvaluatorCommand::Daemon { interval_seconds } => {
            if !(10..=3_600).contains(&interval_seconds) {
                bail!("--interval-seconds must be between 10 and 3600");
            }
            let shutdown = health_shutdown_signal();
            tokio::pin!(shutdown);
            loop {
                run_health_evaluation_once(store)?;
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(interval_seconds)) => {}
                    _ = &mut shutdown => break,
                }
            }
            println!("status=stopped");
            Ok(())
        }
    }
}

fn run_health_evaluation_once(store: &Store) -> anyhow::Result<HealthEvaluationOutcome> {
    let now = OffsetDateTime::now_utc();
    let evaluation_at = OffsetDateTime::from_unix_timestamp(
        now.unix_timestamp()
            .div_euclid(HEALTH_EVALUATION_BUCKET_SECONDS)
            * HEALTH_EVALUATION_BUCKET_SECONDS,
    )?;
    let generated_at = evaluation_at.format(&Rfc3339)?;
    let recovered_at = now.format(&Rfc3339)?;
    let recovery_cutoff =
        (now - time::Duration::seconds(HEALTH_EVALUATION_RECOVERY_SECONDS)).format(&Rfc3339)?;
    StoreWriter::write_health_evaluation_recovery(
        store,
        &recovery_cutoff,
        &recovered_at,
        &local_actor(),
    )?;

    let policy = store.get_health_policy()?;
    let nodes = store.list_nodes()?;
    let policy_version = health_policy_version(&policy);
    let mut rows = Vec::with_capacity(nodes.len());
    for node in &nodes {
        match compute_node_health(store, node, &generated_at, &policy) {
            Ok(row) => rows.push(row),
            Err(_) => {
                return persist_health_evaluation_failure(
                    store,
                    &nodes,
                    &generated_at,
                    &recovered_at,
                    &policy_version,
                );
            }
        }
    }
    let snapshots = rows
        .iter()
        .map(|row| health_snapshot(row, &generated_at))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let input_watermark = health_input_watermark(&snapshots);
    let evaluation_id = health_evaluation_id(&input_watermark, &policy_version);
    let start = HealthEvaluationStart {
        evaluation_id: evaluation_id.clone(),
        input_watermark,
        policy_version,
        computation_version: HEALTH_COMPUTATION_VERSION.to_string(),
        started_at: generated_at.clone(),
    };
    StoreWriter::write_health_evaluation_start(store, &start, &local_actor())?;
    if let Some(existing) = store.get_health_evaluation_run(&evaluation_id)? {
        match existing.status.as_str() {
            "completed" => return Ok(HealthEvaluationOutcome::Replayed),
            "failed" => return Ok(HealthEvaluationOutcome::Replayed),
            "running" if existing.started_at != generated_at => {
                return Ok(HealthEvaluationOutcome::InProgress);
            }
            "running" => {}
            _ => bail!("stored health evaluation status is invalid"),
        }
    }
    StoreWriter::write_health_evaluation_finish(
        store,
        &HealthEvaluationFinish {
            evaluation_id,
            finished_at: recovered_at,
            snapshots,
        },
        &local_actor(),
    )?;
    Ok(HealthEvaluationOutcome::Completed)
}

fn persist_health_evaluation_failure(
    store: &Store,
    nodes: &[NodeRecord],
    generated_at: &str,
    finished_at: &str,
    policy_version: &str,
) -> anyhow::Result<HealthEvaluationOutcome> {
    let input_watermark = blake3::hash(
        &serde_json::to_vec(&json!({
            "evaluation_at": generated_at,
            "nodes": nodes.iter().map(|node| json!({
                "node_id": node.node_id,
                "endpoint_id": node.endpoint_id,
                "enabled": node.enabled,
            })).collect::<Vec<_>>(),
            "input_state": "invalid",
        }))
        .expect("health failure input JSON serializes"),
    )
    .to_hex()
    .to_string();
    let evaluation_id = health_evaluation_id(&input_watermark, policy_version);
    StoreWriter::write_health_evaluation_start(
        store,
        &HealthEvaluationStart {
            evaluation_id: evaluation_id.clone(),
            input_watermark,
            policy_version: policy_version.to_string(),
            computation_version: HEALTH_COMPUTATION_VERSION.to_string(),
            started_at: generated_at.to_string(),
        },
        &local_actor(),
    )?;
    let run = store
        .get_health_evaluation_run(&evaluation_id)?
        .context("health evaluation run disappeared after start")?;
    if run.status != "running" {
        return Ok(HealthEvaluationOutcome::Replayed);
    }
    StoreWriter::write_health_evaluation_failure(
        store,
        &HealthEvaluationFailure {
            evaluation_id,
            finished_at: finished_at.to_string(),
            failure_code: "HEALTH_EVALUATION_FAILED".to_string(),
        },
        &local_actor(),
    )?;
    Ok(HealthEvaluationOutcome::Failed)
}

fn health_policy_version(policy: &HealthPolicyRecord) -> String {
    blake3::hash(
        &serde_json::to_vec(&json!({
            "stale_window_seconds": policy.stale_window_seconds,
            "unreachable_consecutive_failures": policy.unreachable_consecutive_failures,
            "cert_warning_days": policy.cert_warning_days,
            "cert_critical_days": policy.cert_critical_days,
        }))
        .expect("health policy JSON serializes"),
    )
    .to_hex()
    .to_string()
}

fn health_input_watermark(snapshots: &[HealthSnapshotRecord]) -> String {
    let inputs = snapshots
        .iter()
        .map(|snapshot| {
            json!({
                "node_id": snapshot.node_id,
                "endpoint_id": snapshot.endpoint_id,
                "computed_at": snapshot.computed_at,
                "status": snapshot.status,
                "freshness_seconds": snapshot.freshness_seconds,
                "last_success_at": snapshot.last_success_at,
                "last_failure_at": snapshot.last_failure_at,
                "last_error_code": snapshot.last_error_code,
                "degraded_methods": snapshot.degraded_methods_json,
                "summary": snapshot.summary_json,
            })
        })
        .collect::<Vec<_>>();
    blake3::hash(&serde_json::to_vec(&inputs).expect("health input JSON serializes"))
        .to_hex()
        .to_string()
}

fn health_evaluation_id(input_watermark: &str, policy_version: &str) -> String {
    let digest = blake3::hash(
        format!("{input_watermark}:{policy_version}:{HEALTH_COMPUTATION_VERSION}").as_bytes(),
    );
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!("health-eval-{}", Uuid::from_bytes(bytes))
}

#[cfg(unix)]
fn health_shutdown_signal() -> impl std::future::Future<Output = ()> {
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
async fn health_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HealthStatus {
    Healthy,
    Degraded,
    Unreachable,
    Stale,
    Disabled,
    Unknown,
}

impl HealthStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unreachable => "unreachable",
            Self::Stale => "stale",
            Self::Disabled => "disabled",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Default, Clone)]
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
    fn record(&mut self, status: HealthStatus) {
        self.total += 1;
        match status {
            HealthStatus::Healthy => self.healthy += 1,
            HealthStatus::Degraded => self.degraded += 1,
            HealthStatus::Unreachable => self.unreachable += 1,
            HealthStatus::Stale => self.stale += 1,
            HealthStatus::Disabled => self.disabled += 1,
            HealthStatus::Unknown => self.unknown += 1,
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "total": self.total,
            "healthy": self.healthy,
            "degraded": self.degraded,
            "unreachable": self.unreachable,
            "stale": self.stale,
            "disabled": self.disabled,
            "unknown": self.unknown,
        })
    }
}

#[derive(Debug, Clone)]
struct NodeHealth {
    node_id: String,
    endpoint_id: String,
    endpoint_status: Option<String>,
    region: String,
    role: String,
    status: HealthStatus,
    freshness_seconds: Option<u64>,
    last_success_at: Option<String>,
    last_failure_at: Option<String>,
    last_error_code: Option<String>,
    consecutive_unreachable_failures: u64,
    degraded_methods: Vec<String>,
}

impl NodeHealth {
    fn to_json(&self) -> Value {
        json!({
            "node_id": self.node_id,
            "endpoint_id": self.endpoint_id,
            "endpoint_status": self.endpoint_status,
            "region": self.region,
            "role": self.role,
            "status": self.status.as_str(),
            "freshness_seconds": self.freshness_seconds,
            "last_success_at": self.last_success_at,
            "last_failure_at": self.last_failure_at,
            "last_error_code": self.last_error_code,
            "consecutive_unreachable_failures": self.consecutive_unreachable_failures,
            "degraded_methods": self.degraded_methods,
        })
    }
}

fn run_health_summary(store: &Store, json_output: bool) -> anyhow::Result<()> {
    let generated_at = now_rfc3339();
    let policy = store.get_health_policy()?;
    let nodes = store.list_nodes()?;
    let mut rows = Vec::with_capacity(nodes.len());
    for node in &nodes {
        let row = compute_node_health(store, node, &generated_at, &policy)?;
        rows.push(row);
    }
    StoreWriter::write_health_snapshots(
        store,
        &HealthSnapshotWrite {
            evaluation_id: format!("health-eval-{}", Uuid::new_v4()),
            event: "health.summary".to_string(),
            snapshots: rows
                .iter()
                .map(|row| health_snapshot(row, &generated_at))
                .collect::<anyhow::Result<Vec<_>>>()?,
        },
        &local_actor(),
    )?;
    let counts = health_counts(&rows);
    print_health_output(&generated_at, &counts, &rows, json_output)?;
    Ok(())
}

fn run_health_node(store: &Store, node_id: &str, json_output: bool) -> anyhow::Result<()> {
    validate_node_id(node_id)?;
    let generated_at = now_rfc3339();
    let policy = store.get_health_policy()?;
    let node = store
        .get_node(node_id)?
        .with_context(|| format!("node not found: {node_id}"))?;
    let row = compute_node_health(store, &node, &generated_at, &policy)?;
    let rows = vec![row];
    StoreWriter::write_health_snapshots(
        store,
        &HealthSnapshotWrite {
            evaluation_id: format!("health-eval-{}", Uuid::new_v4()),
            event: "health.node".to_string(),
            snapshots: vec![health_snapshot(&rows[0], &generated_at)?],
        },
        &local_actor(),
    )?;
    let counts = health_counts(&rows);
    print_health_output(&generated_at, &counts, &rows, json_output)?;
    Ok(())
}

fn run_health_policy_command(store: &Store, command: HealthPolicyCommand) -> anyhow::Result<()> {
    match command {
        HealthPolicyCommand::Show => {
            let policy = store.get_health_policy()?;
            print_health_policy(&policy);
            Ok(())
        }
        HealthPolicyCommand::Set {
            stale_window,
            unreachable_failures,
            cert_warning_days,
            cert_critical_days,
        } => {
            if stale_window.is_none()
                && unreachable_failures.is_none()
                && cert_warning_days.is_none()
                && cert_critical_days.is_none()
            {
                bail!("health policy set requires at least one threshold flag");
            }
            let mut policy = store.get_health_policy()?;
            if let Some(value) = stale_window {
                policy.stale_window_seconds = parse_duration_seconds(&value, "--stale-window")?;
            }
            if let Some(value) = unreachable_failures {
                if value == 0 {
                    bail!("--unreachable-failures must be greater than zero");
                }
                policy.unreachable_consecutive_failures = value;
            }
            if let Some(value) = cert_warning_days {
                policy.cert_warning_days = value;
            }
            if let Some(value) = cert_critical_days {
                policy.cert_critical_days = value;
            }
            if policy.cert_critical_days > policy.cert_warning_days {
                bail!("--cert-critical-days must be less than or equal to --cert-warning-days");
            }
            policy.updated_at = now_rfc3339();
            StoreWriter::write_health_policy(store, &policy, &local_actor())?;
            print_health_policy(&policy);
            Ok(())
        }
    }
}

fn run_health_snapshot_command(
    store: &Store,
    command: HealthSnapshotCommand,
) -> anyhow::Result<()> {
    match command {
        HealthSnapshotCommand::List { limit, json } => {
            let limit = validate_snapshot_limit(limit)?;
            let snapshots = store.list_health_snapshots_limited(limit)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "schema": "ocfleet.health_snapshots.v1",
                        "limit": limit,
                        "snapshot_count": snapshots.len(),
                        "snapshots": snapshots.iter().map(snapshot_to_json).collect::<Vec<_>>(),
                        "limitation": "latest_per_node",
                    }))?
                );
            } else {
                println!("limit={limit}");
                println!("snapshot_count={}", snapshots.len());
                println!("limitation=latest_per_node");
                for snapshot in &snapshots {
                    println!(
                        "node_id={} endpoint_id={} computed_at={} status={} freshness_seconds={} last_success_at={} last_failure_at={} last_error_code={}",
                        snapshot.node_id,
                        snapshot.endpoint_id.as_deref().unwrap_or("<none>"),
                        snapshot.computed_at,
                        snapshot.status,
                        option_u64(snapshot.freshness_seconds),
                        snapshot.last_success_at.as_deref().unwrap_or("<none>"),
                        snapshot.last_failure_at.as_deref().unwrap_or("<none>"),
                        snapshot.last_error_code.as_deref().unwrap_or("<none>"),
                    );
                }
            }
            Ok(())
        }
    }
}

fn run_health_history(
    store: &Store,
    from: &str,
    to: &str,
    node: Option<&str>,
    limit: u64,
    json_output: bool,
) -> anyhow::Result<()> {
    let history = store.list_health_history(node, from, to, limit)?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": "ocfleet.health_history.v1",
                "from": from,
                "to": to,
                "node_id": node,
                "limit": limit,
                "sample_count": history.len(),
                "samples": history.iter().map(|record| json!({
                    "evaluation_id": record.evaluation_id,
                    "snapshot": snapshot_to_json(&record.snapshot),
                })).collect::<Vec<_>>(),
            }))?
        );
    } else {
        println!("from={from}");
        println!("to={to}");
        println!("node_id={}", node.unwrap_or("<all>"));
        println!("limit={limit}");
        println!("sample_count={}", history.len());
        for record in &history {
            println!(
                "evaluation_id={} node_id={} computed_at={} status={} freshness_seconds={}",
                record.evaluation_id,
                record.snapshot.node_id,
                record.snapshot.computed_at,
                record.snapshot.status,
                option_u64(record.snapshot.freshness_seconds),
            );
        }
    }
    Ok(())
}

fn run_health_rollup(store: &Store, command: HealthRollupCommand) -> anyhow::Result<()> {
    match command {
        HealthRollupCommand::Refresh { at, json } => {
            let at = match at {
                Some(at) => {
                    if at.len() > 64 {
                        bail!("--at must not exceed 64 characters");
                    }
                    OffsetDateTime::parse(&at, &Rfc3339)?
                }
                None => OffsetDateTime::now_utc(),
            };
            refresh_closed_health_rollups(store, at, json)
        }
        HealthRollupCommand::Recompute {
            from,
            to,
            node,
            bucket,
            operation_id,
            json,
        } => recompute_health_rollups(
            store,
            &from,
            &to,
            node.as_deref(),
            rollup_bucket_seconds(bucket),
            operation_id,
            json,
        ),
        HealthRollupCommand::List {
            from,
            to,
            node,
            bucket,
            limit,
            json,
        } => list_health_rollups(
            store,
            &from,
            &to,
            node.as_deref(),
            rollup_bucket_seconds(bucket),
            limit,
            json,
        ),
    }
}

#[derive(Debug, Serialize)]
struct HealthRollupRefreshResult {
    operation_id: String,
    bucket_seconds: u64,
    bucket_start: String,
    bucket_end: String,
    node_count: usize,
    row_count: usize,
    status: &'static str,
}

fn refresh_closed_health_rollups(
    store: &Store,
    at: OffsetDateTime,
    json_output: bool,
) -> anyhow::Result<()> {
    let mut results = Vec::with_capacity(3);
    for bucket_seconds in [300_u64, 3_600, 86_400] {
        let bucket_seconds_i64 = i64::try_from(bucket_seconds)?;
        let bucket_end = OffsetDateTime::from_unix_timestamp(
            at.unix_timestamp().div_euclid(bucket_seconds_i64) * bucket_seconds_i64,
        )?;
        let bucket_start = bucket_end - Duration::seconds(bucket_seconds_i64);
        results.push(write_health_rollup_window(
            store,
            bucket_start,
            bucket_end,
            None,
            bucket_seconds,
            None,
        )?);
    }
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": "ocfleet.health_rollup_refresh.v1",
                "at": at.format(&Rfc3339)?,
                "results": results,
            }))?
        );
    } else {
        for result in results {
            println!(
                "operation_id={} bucket_seconds={} bucket_start={} bucket_end={} node_count={} row_count={} status={}",
                result.operation_id,
                result.bucket_seconds,
                result.bucket_start,
                result.bucket_end,
                result.node_count,
                result.row_count,
                result.status,
            );
        }
    }
    Ok(())
}

fn rollup_bucket_seconds(bucket: HealthRollupBucket) -> u64 {
    match bucket {
        HealthRollupBucket::FiveMinutes => 300,
        HealthRollupBucket::OneHour => 3_600,
        HealthRollupBucket::OneDay => 86_400,
    }
}

fn slo_window(window: HealthSloWindow) -> SloWindow {
    match window {
        HealthSloWindow::Hours24 => SloWindow::Hours24,
        HealthSloWindow::Days7 => SloWindow::Days7,
        HealthSloWindow::Days30 => SloWindow::Days30,
    }
}

fn run_health_slo(
    store: &Store,
    to: &str,
    node: Option<&str>,
    window: SloWindow,
    json_output: bool,
) -> anyhow::Result<()> {
    if to.len() > 64 {
        bail!("--to must not exceed 64 characters");
    }
    if let Some(node_id) = node {
        validate_node_id(node_id)?;
    }
    let to_time = OffsetDateTime::parse(to, &Rfc3339)?;
    if to_time.unix_timestamp() % i64::try_from(window.bucket_seconds())? != 0 {
        bail!("--to must align to the selected SLO rollup bucket");
    }
    let from_time = to_time - Duration::seconds(i64::try_from(window.seconds())?);
    let from = from_time.format(&Rfc3339)?;
    let to = to_time.format(&Rfc3339)?;
    let node_ids = match node {
        Some(node_id) => vec![node_id.to_string()],
        None => store.health_rollup_stored_node_ids(window.bucket_seconds(), &from, &to)?,
    };
    let mut projections = Vec::with_capacity(node_ids.len());
    for node_id in node_ids {
        let rows = store.list_health_rollups(
            Some(&node_id),
            window.bucket_seconds(),
            &from,
            &to,
            window.seconds() / window.bucket_seconds(),
        )?;
        let projection = project_health_slo(&node_id, window, &from, &to, &rows)
            .context("health SLO counters overflow")?;
        projections.push(projection);
    }
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": "ocfleet.health_slo.v1",
                "window": window.as_str(),
                "from": from,
                "to": to,
                "node_count": projections.len(),
                "projections": projections,
            }))?
        );
    } else {
        println!("window={}", window.as_str());
        println!("from={from}");
        println!("to={to}");
        println!("node_count={}", projections.len());
        for projection in projections {
            println!("{}", serde_json::to_string(&projection)?);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn recompute_health_rollups(
    store: &Store,
    from: &str,
    to: &str,
    node: Option<&str>,
    bucket_seconds: u64,
    operation_id: Option<String>,
    json_output: bool,
) -> anyhow::Result<()> {
    let (from, to) = validate_rollup_window(from, to, bucket_seconds)?;
    let operation_id = operation_id.unwrap_or_else(|| format!("health-rollup-{}", Uuid::new_v4()));
    let result = write_health_rollup_window(
        store,
        from,
        to,
        node,
        bucket_seconds,
        Some(operation_id.clone()),
    )?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": "ocfleet.health_rollup_recompute.v1",
                "operation_id": operation_id,
                "from": result.bucket_start,
                "to": result.bucket_end,
                "bucket_seconds": bucket_seconds,
                "node_count": result.node_count,
                "row_count": result.row_count,
                "status": result.status,
            }))?
        );
    } else {
        println!("operation_id={operation_id}");
        println!("node_count={}", result.node_count);
        println!("row_count={}", result.row_count);
        println!("status={}", result.status);
    }
    Ok(())
}

fn write_health_rollup_window(
    store: &Store,
    from: OffsetDateTime,
    to: OffsetDateTime,
    node: Option<&str>,
    bucket_seconds: u64,
    operation_id: Option<String>,
) -> anyhow::Result<HealthRollupRefreshResult> {
    let node_ids = if let Some(node_id) = node {
        validate_node_id(node_id)?;
        vec![node_id.to_string()]
    } else {
        store.health_rollup_node_ids(&from.format(&Rfc3339)?, &to.format(&Rfc3339)?)?
    };
    let bucket_count = u64::try_from((to - from).whole_seconds())? / bucket_seconds;
    let row_count = bucket_count
        .checked_mul(u64::try_from(node_ids.len())?)
        .context("health rollup row count overflow")?;
    if row_count > 100_000 {
        bail!("health rollup recompute exceeds 100000 rows");
    }
    let mut rows = Vec::with_capacity(usize::try_from(row_count)?);
    for bucket_index in 0..bucket_count {
        let seconds = i64::try_from(
            bucket_index
                .checked_mul(bucket_seconds)
                .context("health rollup bucket offset overflow")?,
        )?;
        let bucket_start = from + Duration::seconds(seconds);
        let bucket_end = bucket_start + Duration::seconds(i64::try_from(bucket_seconds)?);
        let bucket_start_text = bucket_start.format(&Rfc3339)?;
        let bucket_end_text = bucket_end.format(&Rfc3339)?;
        for node_id in &node_ids {
            let source =
                store.health_rollup_source(node_id, &bucket_start_text, &bucket_end_text)?;
            rows.push(build_health_rollup(
                node_id,
                bucket_seconds,
                &bucket_start_text,
                &bucket_end_text,
                source,
            )?);
        }
    }
    let operation_id = operation_id.unwrap_or_else(|| {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ocfleet-health-rollup-refresh-v1\0");
        hasher.update(&bucket_seconds.to_be_bytes());
        hasher.update(&from.unix_timestamp().to_be_bytes());
        hasher.update(&to.unix_timestamp().to_be_bytes());
        for row in &rows {
            hasher.update(row.node_id.as_bytes());
            hasher.update(b"\0");
            hasher.update(row.input_watermark.as_bytes());
        }
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        format!("health-rollup-{}", Uuid::from_bytes(bytes))
    });
    let status = if rows.is_empty() {
        "no_source"
    } else {
        StoreWriter::write_health_rollups(
            store,
            &HealthRollupWrite {
                operation_id: operation_id.clone(),
                rows,
            },
            &local_actor(),
        )?;
        "written_or_replayed"
    };
    Ok(HealthRollupRefreshResult {
        operation_id,
        bucket_seconds,
        bucket_start: from.format(&Rfc3339)?,
        bucket_end: to.format(&Rfc3339)?,
        node_count: node_ids.len(),
        row_count: usize::try_from(row_count)?,
        status,
    })
}

fn validate_rollup_window(
    from: &str,
    to: &str,
    bucket_seconds: u64,
) -> anyhow::Result<(OffsetDateTime, OffsetDateTime)> {
    let from = OffsetDateTime::parse(from, &Rfc3339)?;
    let to = OffsetDateTime::parse(to, &Rfc3339)?;
    if from >= to {
        bail!("--from must precede --to");
    }
    if from.unix_timestamp() % i64::try_from(bucket_seconds)? != 0
        || to.unix_timestamp() % i64::try_from(bucket_seconds)? != 0
    {
        bail!("rollup window must align to bucket boundaries");
    }
    let duration = to - from;
    if duration > Duration::days(31) {
        bail!("rollup recompute window must not exceed 31 days");
    }
    Ok((from, to))
}

fn build_health_rollup(
    node_id: &str,
    bucket_seconds: u64,
    bucket_start: &str,
    bucket_end: &str,
    source: HealthRollupSource,
) -> anyhow::Result<HealthRollupRecord> {
    let mut status_by_slot = BTreeMap::new();
    for record in &source.history {
        let index = match record.snapshot.status.as_str() {
            "healthy" => 0,
            "degraded" => 1,
            "unreachable" => 2,
            "stale" => 3,
            "disabled" => 4,
            "unknown" => 5,
            _ => bail!("stored health history status is invalid"),
        };
        let timestamp = OffsetDateTime::parse(&record.snapshot.computed_at, &Rfc3339)?;
        // Source rows are ordered, so the last evaluation in a five-minute slot wins.
        // This prevents interactive re-evaluations from biasing availability.
        status_by_slot.insert(timestamp.unix_timestamp().div_euclid(300), index);
    }
    let mut status_counts = [0_u64; 6];
    for index in status_by_slot.values() {
        status_counts[*index] += 1;
    }

    let classified = source
        .observations
        .iter()
        .filter_map(|observation| observation.ok)
        .collect::<Vec<_>>();
    let observation_count = u64::try_from(classified.len())?;
    let observation_error_count = u64::try_from(classified.iter().filter(|ok| !**ok).count())?;
    let mut durations = source
        .observations
        .iter()
        .filter_map(|observation| observation.duration_ms)
        .collect::<Vec<_>>();
    durations.sort_unstable();
    let duration_p50_ms = percentile(&durations, 50);
    let duration_p95_ms = percentile(&durations, 95);

    let mut cert_warning_count = 0_u64;
    let mut cert_critical_count = 0_u64;
    let mut fingerprints = Vec::new();
    for observation in &source.observations {
        let summary = safe_observation_summary(&observation.summary_json);
        if observation.method == OCSERV_CERT_EXPIRY {
            let days = summary
                .get("cert_min_days_remaining")
                .or_else(|| summary.get("days_remaining"))
                .and_then(Value::as_i64);
            let status = summary.get("status").and_then(Value::as_str);
            if days.is_some_and(|days| days <= 7) || matches!(status, Some("critical" | "expired"))
            {
                cert_critical_count += 1;
            } else if days.is_some_and(|days| days <= 30)
                || matches!(status, Some("warning" | "expiring_soon"))
            {
                cert_warning_count += 1;
            }
        }
        if observation.method == OCSERV_CONFIG_FINGERPRINT {
            let aliases = [
                summary.get("config_fingerprint_prefix"),
                summary.get("config_fingerprint_previous_prefix"),
            ]
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect::<Vec<_>>();
            if !aliases.is_empty() {
                fingerprints.push(aliases);
            }
        }
    }
    let fingerprint_change_count = fingerprints
        .windows(2)
        .filter(|pair| !pair[0].iter().any(|value| pair[1].contains(value)))
        .count();
    let watermark = blake3::hash(&serde_json::to_vec(&json!({
        "history": source.history.iter().map(|record| json!({
            "evaluation_id": record.evaluation_id,
            "node_id": record.snapshot.node_id,
            "computed_at": record.snapshot.computed_at,
            "status": record.snapshot.status,
            "summary": record.snapshot.summary_json,
        })).collect::<Vec<_>>(),
        "observations": source.observations.iter().map(|record| json!({
            "observation_id": record.observation_id,
            "method": record.method,
            "ok": record.ok,
            "duration_ms": record.duration_ms,
            "observed_at": record.observed_at,
            "summary": record.summary_json,
        })).collect::<Vec<_>>(),
    }))?)
    .to_hex()
    .to_string();
    Ok(HealthRollupRecord {
        node_id: node_id.to_string(),
        bucket_seconds,
        bucket_start: bucket_start.to_string(),
        bucket_end: bucket_end.to_string(),
        input_watermark: watermark,
        health_samples: u64::try_from(status_by_slot.len())?,
        covered_slots: u64::try_from(status_by_slot.len())?,
        expected_slots: bucket_seconds / 300,
        healthy_count: status_counts[0],
        degraded_count: status_counts[1],
        unreachable_count: status_counts[2],
        stale_count: status_counts[3],
        disabled_count: status_counts[4],
        unknown_count: status_counts[5],
        observation_count,
        observation_error_count,
        duration_sample_count: u64::try_from(durations.len())?,
        duration_p50_ms,
        duration_p95_ms,
        cert_warning_count,
        cert_critical_count,
        fingerprint_sample_count: u64::try_from(fingerprints.len())?,
        fingerprint_change_count: u64::try_from(fingerprint_change_count)?,
        computed_at: bucket_end.to_string(),
    })
}

fn percentile(values: &[u64], percentile: usize) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let rank = percentile
        .checked_mul(values.len())?
        .checked_add(99)?
        .checked_div(100)?;
    values.get(rank.saturating_sub(1)).copied()
}

fn list_health_rollups(
    store: &Store,
    from: &str,
    to: &str,
    node: Option<&str>,
    bucket_seconds: u64,
    limit: u64,
    json_output: bool,
) -> anyhow::Result<()> {
    let rows = store.list_health_rollups(node, bucket_seconds, from, to, limit)?;
    let values = rows.iter().map(health_rollup_to_json).collect::<Vec<_>>();
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": "ocfleet.health_rollups.v1",
                "from": from,
                "to": to,
                "node_id": node,
                "bucket_seconds": bucket_seconds,
                "limit": limit,
                "row_count": rows.len(),
                "rollups": values,
            }))?
        );
    } else {
        println!("row_count={}", rows.len());
        for row in values {
            println!("{}", serde_json::to_string(&row)?);
        }
    }
    Ok(())
}

fn health_rollup_to_json(row: &HealthRollupRecord) -> Value {
    json!({
        "node_id": row.node_id,
        "bucket_seconds": row.bucket_seconds,
        "bucket_start": row.bucket_start,
        "bucket_end": row.bucket_end,
        "input_watermark": row.input_watermark,
        "health_samples": row.health_samples,
        "covered_slots": row.covered_slots,
        "expected_slots": row.expected_slots,
        "healthy_count": row.healthy_count,
        "degraded_count": row.degraded_count,
        "unreachable_count": row.unreachable_count,
        "stale_count": row.stale_count,
        "disabled_count": row.disabled_count,
        "unknown_count": row.unknown_count,
        "observation_count": row.observation_count,
        "observation_error_count": row.observation_error_count,
        "duration_sample_count": row.duration_sample_count,
        "duration_p50_ms": row.duration_p50_ms,
        "duration_p95_ms": row.duration_p95_ms,
        "cert_warning_count": row.cert_warning_count,
        "cert_critical_count": row.cert_critical_count,
        "fingerprint_sample_count": row.fingerprint_sample_count,
        "fingerprint_change_count": row.fingerprint_change_count,
        "computed_at": row.computed_at,
    })
}

fn print_health_policy(policy: &HealthPolicyRecord) {
    println!("stale_window_seconds={}", policy.stale_window_seconds);
    println!(
        "unreachable_consecutive_failures={}",
        policy.unreachable_consecutive_failures
    );
    println!("cert_warning_days={}", policy.cert_warning_days);
    println!("cert_critical_days={}", policy.cert_critical_days);
    println!("updated_at={}", policy.updated_at);
}

fn compute_node_health(
    store: &Store,
    node: &NodeRecord,
    generated_at: &str,
    policy: &HealthPolicyRecord,
) -> anyhow::Result<NodeHealth> {
    let endpoint_status = store
        .get_endpoint_trust(&node.endpoint_id)?
        .map(|endpoint| endpoint.status);
    let endpoint_error_code = inactive_endpoint_error_code(endpoint_status);
    let observations =
        store.list_probe_observations(Some(&node.node_id), OBSERVATION_READ_LIMIT)?;
    let freshness_seconds = latest_observation(&observations)
        .and_then(|observation| freshness_seconds(generated_at, &observation.observed_at));
    let last_success_at = latest_with_ok(&observations, true).map(|record| record.observed_at);
    let last_failure = latest_with_ok(&observations, false);
    let last_failure_at = last_failure
        .as_ref()
        .map(|record| record.observed_at.clone());
    let last_error_code = endpoint_error_code.map(ToOwned::to_owned).or_else(|| {
        last_failure
            .as_ref()
            .and_then(|record| record.error_code.clone())
    });
    let degraded_methods = degraded_methods(&observations);
    let unreachable_failures = consecutive_unreachable_controller_ping_failures(&observations);

    let status = if !node.enabled {
        HealthStatus::Disabled
    } else if endpoint_error_code.is_some() {
        HealthStatus::Unreachable
    } else if observations.is_empty() {
        HealthStatus::Unknown
    } else if latest_is_stale_or_expired(generated_at, &observations, policy.stale_window_seconds) {
        HealthStatus::Stale
    } else if unreachable_failures >= policy.unreachable_consecutive_failures {
        HealthStatus::Unreachable
    } else if !degraded_methods.is_empty() || latest_controller_ping_failed(&observations) {
        HealthStatus::Degraded
    } else {
        HealthStatus::Healthy
    };

    Ok(NodeHealth {
        node_id: node.node_id.clone(),
        endpoint_id: node.endpoint_id.clone(),
        endpoint_status: endpoint_status.map(|status| status.as_str().to_string()),
        region: node.region.clone(),
        role: node.role.clone(),
        status,
        freshness_seconds,
        last_success_at,
        last_failure_at,
        last_error_code,
        consecutive_unreachable_failures: unreachable_failures,
        degraded_methods,
    })
}

fn latest_observation(observations: &[ProbeObservationRecord]) -> Option<&ProbeObservationRecord> {
    observations
        .iter()
        .max_by(|left, right| left.observed_at.cmp(&right.observed_at))
}

fn inactive_endpoint_error_code(status: Option<EndpointStatus>) -> Option<&'static str> {
    match status {
        None => Some("ENDPOINT_TRUST_MISSING"),
        Some(EndpointStatus::Active) => None,
        Some(EndpointStatus::Revoked) => Some("ENDPOINT_REVOKED"),
        Some(EndpointStatus::Quarantined) => Some("ENDPOINT_QUARANTINED"),
        Some(EndpointStatus::Rotated) => Some("ENDPOINT_ROTATED"),
    }
}

fn latest_with_ok(
    observations: &[ProbeObservationRecord],
    ok: bool,
) -> Option<ProbeObservationRecord> {
    observations
        .iter()
        .filter(|record| record.ok == Some(ok))
        .max_by(|left, right| left.observed_at.cmp(&right.observed_at))
        .cloned()
}

fn latest_for_method<'a>(
    observations: &'a [ProbeObservationRecord],
    method: &str,
) -> Option<&'a ProbeObservationRecord> {
    observations
        .iter()
        .filter(|record| record.method == method)
        .max_by(|left, right| left.observed_at.cmp(&right.observed_at))
}

fn latest_is_stale_or_expired(
    generated_at: &str,
    observations: &[ProbeObservationRecord],
    stale_window_seconds: u64,
) -> bool {
    let Some(latest) = latest_observation(observations) else {
        return false;
    };
    if latest
        .expires_at
        .as_ref()
        .is_some_and(|expires_at| timestamp_before(expires_at, generated_at).unwrap_or(true))
    {
        return true;
    }
    freshness_seconds(generated_at, &latest.observed_at)
        .is_none_or(|freshness| freshness > stale_window_seconds)
}

fn consecutive_unreachable_controller_ping_failures(
    observations: &[ProbeObservationRecord],
) -> u64 {
    let mut pings = observations
        .iter()
        .filter(|record| record.method == PROBE_CONTROLLER_PING)
        .collect::<Vec<_>>();
    pings.sort_by(|left, right| right.observed_at.cmp(&left.observed_at));
    pings
        .into_iter()
        .take_while(|record| {
            record.ok == Some(false)
                && record
                    .error_code
                    .as_deref()
                    .is_some_and(is_unreachable_error_code)
        })
        .count() as u64
}

fn latest_controller_ping_failed(observations: &[ProbeObservationRecord]) -> bool {
    latest_for_method(observations, PROBE_CONTROLLER_PING)
        .is_some_and(|record| record.ok == Some(false))
}

fn is_unreachable_error_code(code: &str) -> bool {
    matches!(
        code,
        "CONNECT_FAILED"
            | "RPC_TIMEOUT"
            | "ENDPOINT_NOT_ALLOWED"
            | "ENDPOINT_MISMATCH"
            | "RESPONSE_TOO_LARGE"
            | "FRAME_READ_FAILED"
            | "NODE_NOT_FOUND"
            | "NODE_DISABLED"
            | "ENDPOINT_REVOKED"
            | "ENDPOINT_QUARANTINED"
            | "ENDPOINT_ROTATED"
            | "ENDPOINT_TRUST_MISSING"
    )
}

fn degraded_methods(observations: &[ProbeObservationRecord]) -> Vec<String> {
    let mut methods = Vec::new();
    for method in [
        OCSERV_SERVICE_SUMMARY,
        OCSERV_VERSION,
        OCSERV_SESSIONS_SUMMARY,
        OCSERV_CONFIG_FINGERPRINT,
        OCSERV_CERT_EXPIRY,
    ] {
        if let Some(record) = latest_for_method(observations, method) {
            if record.ok == Some(false) || cert_observation_warns(record) {
                methods.push(method.to_string());
            }
            for degraded in
                degraded_methods_from_summary(&safe_observation_summary(&record.summary_json))
            {
                if !methods.contains(&degraded) {
                    methods.push(degraded);
                }
            }
        }
    }
    methods.sort();
    methods.dedup();
    methods
}

fn degraded_methods_from_summary(summary: &Value) -> Vec<String> {
    summary
        .get("degraded_methods")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect()
}

fn cert_observation_warns(record: &ProbeObservationRecord) -> bool {
    if record.method != OCSERV_CERT_EXPIRY {
        return false;
    }
    let summary = safe_observation_summary(&record.summary_json);
    if status_is_cert_warning(
        summary
            .get("status")
            .or_else(|| summary.get("cert_status"))
            .and_then(Value::as_str),
    ) {
        return true;
    }
    record
        .summary_json
        .get("certs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|cert| status_is_cert_warning(cert.get("status").and_then(Value::as_str)))
}

fn status_is_cert_warning(status: Option<&str>) -> bool {
    matches!(
        status,
        Some("expiring_soon" | "expired" | "warning" | "critical")
    )
}

fn freshness_seconds(generated_at: &str, observed_at: &str) -> Option<u64> {
    let generated_at = OffsetDateTime::parse(generated_at, &Rfc3339).ok()?;
    let observed_at = OffsetDateTime::parse(observed_at, &Rfc3339).ok()?;
    if observed_at > generated_at {
        return Some(0);
    }
    u64::try_from((generated_at - observed_at).whole_seconds()).ok()
}

fn timestamp_before(left: &str, right: &str) -> anyhow::Result<bool> {
    let left = OffsetDateTime::parse(left, &Rfc3339)?;
    let right = OffsetDateTime::parse(right, &Rfc3339)?;
    Ok(left < right)
}

fn health_counts(rows: &[NodeHealth]) -> HealthCounts {
    let mut counts = HealthCounts::default();
    for row in rows {
        counts.record(row.status);
    }
    counts
}

fn health_snapshot(row: &NodeHealth, generated_at: &str) -> anyhow::Result<HealthSnapshotRecord> {
    Ok(HealthSnapshotRecord {
        node_id: row.node_id.clone(),
        endpoint_id: Some(row.endpoint_id.clone()),
        computed_at: generated_at.to_string(),
        status: row.status.as_str().to_string(),
        freshness_seconds: row.freshness_seconds,
        last_success_at: row.last_success_at.clone(),
        last_failure_at: row.last_failure_at.clone(),
        last_error_code: row.last_error_code.clone(),
        degraded_methods_json: HealthDegradedMethodsPayloadV1::new(row.degraded_methods.clone())
            .map_err(anyhow::Error::msg)?
            .to_value(),
        summary_json: HealthSummaryPayloadV1::new(
            Some(row.region.clone()),
            Some(row.role.clone()),
            row.status.as_str().to_string(),
            row.endpoint_status.clone(),
            Some(row.consecutive_unreachable_failures),
        )
        .map_err(anyhow::Error::msg)?
        .to_value(),
    })
}

fn print_health_output(
    generated_at: &str,
    counts: &HealthCounts,
    rows: &[NodeHealth],
    json_output: bool,
) -> anyhow::Result<()> {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": "ocfleet.health.v1",
                "generated_at": generated_at,
                "summary": counts.to_json(),
                "nodes": rows.iter().map(NodeHealth::to_json).collect::<Vec<_>>(),
            }))?
        );
    } else {
        println!("generated_at={generated_at}");
        println!(
            "total={} healthy={} degraded={} unreachable={} stale={} disabled={} unknown={}",
            counts.total,
            counts.healthy,
            counts.degraded,
            counts.unreachable,
            counts.stale,
            counts.disabled,
            counts.unknown
        );
        for row in rows {
            println!(
                "node_id={} endpoint_id={} endpoint_status={} region={} role={} status={} freshness_seconds={} last_success_at={} last_failure_at={} last_error_code={} degraded_methods={}",
                row.node_id,
                row.endpoint_id,
                row.endpoint_status.as_deref().unwrap_or("<none>"),
                row.region,
                row.role,
                row.status.as_str(),
                option_u64(row.freshness_seconds),
                row.last_success_at.as_deref().unwrap_or("<none>"),
                row.last_failure_at.as_deref().unwrap_or("<none>"),
                row.last_error_code.as_deref().unwrap_or("<none>"),
                if row.degraded_methods.is_empty() {
                    "<none>".to_string()
                } else {
                    row.degraded_methods.join(",")
                },
            );
        }
    }
    Ok(())
}

fn option_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "<none>".to_string())
}

fn snapshot_to_json(snapshot: &HealthSnapshotRecord) -> Value {
    let methods = HealthDegradedMethodsPayloadV1::from_value(&snapshot.degraded_methods_json)
        .expect("store validates health degraded methods");
    let summary = HealthSummaryPayloadV1::from_value(&snapshot.summary_json)
        .expect("store validates health summary");
    json!({
        "node_id": snapshot.node_id,
        "endpoint_id": snapshot.endpoint_id,
        "computed_at": snapshot.computed_at,
        "status": snapshot.status,
        "freshness_seconds": snapshot.freshness_seconds,
        "last_success_at": snapshot.last_success_at,
        "last_failure_at": snapshot.last_failure_at,
        "last_error_code": snapshot.last_error_code,
        "degraded_methods": methods.methods,
        "summary": {
            "region": summary.region,
            "role": summary.role,
            "status": summary.status,
            "endpoint_status": summary.endpoint_status,
            "consecutive_failures": summary.consecutive_failures,
        },
    })
}

fn validate_snapshot_limit(limit: u64) -> anyhow::Result<u64> {
    if limit == 0 || limit > MAX_HEALTH_SNAPSHOT_LIMIT {
        bail!("--limit must be between 1 and {MAX_HEALTH_SNAPSHOT_LIMIT}");
    }
    Ok(limit)
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("RFC3339 formatting succeeds")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::HealthHistoryRecord;

    fn observation(
        id: &str,
        method: &str,
        ok: Option<bool>,
        duration_ms: Option<u64>,
        observed_at: &str,
        summary: Value,
    ) -> ProbeObservationRecord {
        ProbeObservationRecord {
            observation_id: id.to_string(),
            run_id: None,
            node_id: Some("rollup-node".to_string()),
            endpoint_id: None,
            method: method.to_string(),
            ok,
            error_code: None,
            duration_ms,
            observed_at: observed_at.to_string(),
            expires_at: None,
            result_class: "low_sensitive_summary".to_string(),
            summary_json: summary,
        }
    }

    fn history(id: &str, computed_at: &str, status: &str) -> HealthHistoryRecord {
        HealthHistoryRecord {
            evaluation_id: id.to_string(),
            snapshot: HealthSnapshotRecord {
                node_id: "rollup-node".to_string(),
                endpoint_id: None,
                computed_at: computed_at.to_string(),
                status: status.to_string(),
                freshness_seconds: None,
                last_success_at: None,
                last_failure_at: None,
                last_error_code: None,
                degraded_methods_json: HealthDegradedMethodsPayloadV1::new(vec![])
                    .expect("methods")
                    .to_value(),
                summary_json: HealthSummaryPayloadV1::new(
                    None,
                    None,
                    status.to_string(),
                    None,
                    None,
                )
                .expect("summary")
                .to_value(),
            },
        }
    }

    #[test]
    fn rollup_distinguishes_absence_and_recomputes_deterministically() {
        let source = HealthRollupSource {
            history: vec![
                history("eval-a", "2026-07-11T01:00:10Z", "healthy"),
                history("eval-b", "2026-07-11T01:04:10Z", "unreachable"),
            ],
            observations: vec![
                observation(
                    "obs-a",
                    PROBE_CONTROLLER_PING,
                    Some(true),
                    Some(10),
                    "2026-07-11T01:00:20Z",
                    json!({}),
                ),
                observation(
                    "obs-b",
                    PROBE_CONTROLLER_PING,
                    Some(false),
                    Some(20),
                    "2026-07-11T01:01:20Z",
                    json!({}),
                ),
                observation(
                    "obs-c",
                    OCSERV_CERT_EXPIRY,
                    None,
                    Some(100),
                    "2026-07-11T01:02:20Z",
                    json!({"days_remaining": 5}),
                ),
                observation(
                    "obs-d",
                    OCSERV_CONFIG_FINGERPRINT,
                    Some(true),
                    None,
                    "2026-07-11T01:03:20Z",
                    json!({"config_fingerprint_prefix": "aaaaaaaaaaaa"}),
                ),
                observation(
                    "obs-e",
                    OCSERV_CONFIG_FINGERPRINT,
                    Some(true),
                    None,
                    "2026-07-11T01:04:20Z",
                    json!({"config_fingerprint_prefix": "bbbbbbbbbbbb", "config_fingerprint_previous_prefix": "aaaaaaaaaaaa"}),
                ),
            ],
        };
        let first = build_health_rollup(
            "rollup-node",
            300,
            "2026-07-11T01:00:00Z",
            "2026-07-11T01:05:00Z",
            source.clone(),
        )
        .expect("rollup");
        let second = build_health_rollup(
            "rollup-node",
            300,
            "2026-07-11T01:00:00Z",
            "2026-07-11T01:05:00Z",
            source,
        )
        .expect("repeat rollup");
        assert_eq!(first, second);
        assert_eq!(first.health_samples, 1);
        assert_eq!(first.healthy_count, 0);
        assert_eq!(first.unreachable_count, 1);
        assert_eq!(first.unknown_count, 0, "missing is not an unknown sample");
        assert_eq!(first.covered_slots, 1);
        assert_eq!(first.expected_slots, 1);
        assert_eq!(first.observation_count, 4);
        assert_eq!(first.observation_error_count, 1);
        assert_eq!(first.duration_p50_ms, Some(20));
        assert_eq!(first.duration_p95_ms, Some(100));
        assert_eq!(first.cert_critical_count, 1);
        assert_eq!(first.fingerprint_sample_count, 2);
        assert_eq!(
            first.fingerprint_change_count, 0,
            "dual-report rotation preserves continuity"
        );
    }

    #[test]
    fn percentile_preserves_missing_duration() {
        assert_eq!(percentile(&[], 95), None);
        assert_eq!(percentile(&[7], 95), Some(7));
        assert_eq!(percentile(&[1, 2, 3, 4], 50), Some(2));
    }
}
