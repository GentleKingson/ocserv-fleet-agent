use anyhow::{Context, bail};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use crate::args::{RetentionCommand, RetentionScope};
use crate::audit::AuditEvent;
use crate::duration_args::parse_duration_seconds;
use crate::input_validation::local_actor;
use crate::store::{RetentionCandidateReport, RetentionPolicyRecord, Store};

const RETENTION_SCOPES: &[&str] = &[
    "observations",
    "observability-runs",
    "health-snapshots",
    "alert-events",
];
const MAX_RETENTION_BATCH_SIZE: u64 = 1_000;
const MAX_RETENTION_APPLY_LIMIT: u64 = 100_000;

#[derive(Debug, Serialize)]
struct RetentionApplyReport {
    generated_at: String,
    dry_run: bool,
    scopes: Vec<RetentionScopeReport>,
}

#[derive(Debug, Clone, Serialize)]
struct RetentionScopeReport {
    scope: String,
    dry_run: bool,
    cutoff: Option<String>,
    max_rows: Option<u64>,
    matched_count: u64,
    planned_delete_count: u64,
    rows_deleted: u64,
    batch_count: u64,
    batch_size: u64,
    limit: Option<u64>,
    oldest_candidate: Option<String>,
    newest_candidate: Option<String>,
    report_checksum: String,
}

pub fn run_retention_command(store: &Store, command: RetentionCommand) -> anyhow::Result<()> {
    match command {
        RetentionCommand::Show => run_retention_show(store),
        RetentionCommand::Set {
            scope,
            max_age,
            max_rows,
        } => run_retention_set(store, scope, max_age.as_deref(), max_rows),
        RetentionCommand::Apply {
            dry_run,
            scope,
            before,
            limit,
            json,
            batch_size,
        } => run_retention_apply(
            store,
            dry_run,
            scope,
            before.as_deref(),
            limit,
            json,
            batch_size,
        ),
    }
}

fn run_retention_show(store: &Store) -> anyhow::Result<()> {
    for scope in RETENTION_SCOPES {
        let policy = effective_retention_policy(store, scope)?;
        println!(
            "scope={} max_age_days={} max_rows={} updated_at={}",
            policy.scope,
            optional_u64(policy.max_age_days),
            optional_u64(policy.max_rows),
            policy.updated_at
        );
    }
    println!("scope=controller_audit_log retention=never");
    Ok(())
}

fn run_retention_set(
    store: &Store,
    scope: RetentionScope,
    max_age: Option<&str>,
    max_rows: Option<usize>,
) -> anyhow::Result<()> {
    let scope_name = retention_scope_name(scope);
    let mut policy = effective_retention_policy(store, scope_name)?;
    if let Some(max_age) = max_age {
        policy.max_age_days = Some(parse_retention_max_age_days(max_age)?);
    }
    if let Some(max_rows) = max_rows {
        if max_rows == 0 {
            bail!("--max-rows must be greater than zero");
        }
        policy.max_rows = Some(max_rows as u64);
    }
    policy.updated_at = now_rfc3339();
    store.set_retention_policy(&policy)?;
    let mut event = AuditEvent::new(local_actor(), "retention.set");
    event.ok = Some(true);
    event.detail_json = json!({
        "scope": policy.scope.as_str(),
        "max_age_days": policy.max_age_days,
        "max_rows": policy.max_rows,
    });
    store.insert_audit(&event)?;
    println!("scope={}", policy.scope);
    println!("max_age_days={}", optional_u64(policy.max_age_days));
    println!("max_rows={}", optional_u64(policy.max_rows));
    Ok(())
}

fn run_retention_apply(
    store: &Store,
    dry_run: bool,
    scope: Option<RetentionScope>,
    before: Option<&str>,
    limit: Option<u64>,
    json_output: bool,
    batch_size: u64,
) -> anyhow::Result<()> {
    validate_retention_apply_bounds(limit, batch_size)?;
    let explicit_cutoff = match before {
        Some(before) => {
            parse_rfc3339(before)?;
            Some(before.to_string())
        }
        None => None,
    };
    let scopes = selected_retention_scopes(scope);
    let mut reports = Vec::new();
    for scope in scopes {
        let report = apply_retention_scope(
            store,
            scope,
            dry_run,
            explicit_cutoff.as_deref(),
            limit,
            batch_size,
        )?;
        write_retention_apply_audit(store, &report)?;
        reports.push(report);
    }

    if json_output {
        let report = RetentionApplyReport {
            generated_at: now_rfc3339(),
            dry_run,
            scopes: reports,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for report in &reports {
            println!(
                "scope={} cutoff={} max_rows={} matched_count={} deleted_count={} rows_deleted={} batch_count={} oldest_candidate={} newest_candidate={} dry_run={} report_checksum={}",
                report.scope,
                optional_str(report.cutoff.as_deref()),
                optional_u64(report.max_rows),
                report.matched_count,
                report.planned_delete_count,
                report.rows_deleted,
                report.batch_count,
                optional_str(report.oldest_candidate.as_deref()),
                optional_str(report.newest_candidate.as_deref()),
                report.dry_run,
                report.report_checksum,
            );
        }
        println!(
            "scope=controller_audit_log retention=never matched_count=0 deleted_count=0 rows_deleted=0 dry_run={dry_run}"
        );
    }
    Ok(())
}

fn apply_retention_scope(
    store: &Store,
    scope: &str,
    dry_run: bool,
    explicit_cutoff: Option<&str>,
    limit: Option<u64>,
    batch_size: u64,
) -> anyhow::Result<RetentionScopeReport> {
    let policy = effective_retention_policy(store, scope)?;
    let cutoff = explicit_cutoff
        .map(ToOwned::to_owned)
        .or(retention_cutoff(&policy)?);
    let candidate_report =
        store.retention_candidate_report(scope, cutoff.as_deref(), policy.max_rows)?;
    let planned_delete_count = limit
        .map(|limit| candidate_report.matched_count.min(limit))
        .unwrap_or(candidate_report.matched_count);
    let (rows_deleted, batch_count) = if dry_run || planned_delete_count == 0 {
        (0, 0)
    } else {
        delete_retention_batches(
            store,
            scope,
            cutoff.as_deref(),
            policy.max_rows,
            batch_size,
            planned_delete_count,
        )?
    };
    scope_report(
        scope,
        dry_run,
        cutoff,
        policy.max_rows,
        &candidate_report,
        planned_delete_count,
        rows_deleted,
        batch_count,
        batch_size,
        limit,
    )
}

fn delete_retention_batches(
    store: &Store,
    scope: &str,
    cutoff: Option<&str>,
    max_rows: Option<u64>,
    batch_size: u64,
    limit: u64,
) -> anyhow::Result<(u64, u64)> {
    let mut rows_deleted = 0_u64;
    let mut batch_count = 0_u64;
    while rows_deleted < limit {
        let remaining = limit - rows_deleted;
        let this_batch = remaining.min(batch_size);
        let deleted = store.prune_retention_scope_batch(scope, cutoff, max_rows, this_batch)?;
        if deleted == 0 {
            break;
        }
        rows_deleted = rows_deleted
            .checked_add(deleted)
            .context("retention deleted row count overflow")?;
        batch_count = batch_count
            .checked_add(1)
            .context("retention batch count overflow")?;
    }
    Ok((rows_deleted, batch_count))
}

#[allow(clippy::too_many_arguments)]
fn scope_report(
    scope: &str,
    dry_run: bool,
    cutoff: Option<String>,
    max_rows: Option<u64>,
    candidate_report: &RetentionCandidateReport,
    planned_delete_count: u64,
    rows_deleted: u64,
    batch_count: u64,
    batch_size: u64,
    limit: Option<u64>,
) -> anyhow::Result<RetentionScopeReport> {
    let checksum_payload = json!({
        "scope": scope,
        "dry_run": dry_run,
        "cutoff": cutoff,
        "max_rows": max_rows,
        "matched_count": candidate_report.matched_count,
        "planned_delete_count": planned_delete_count,
        "rows_deleted": rows_deleted,
        "batch_count": batch_count,
        "batch_size": batch_size,
        "limit": limit,
        "oldest_candidate": candidate_report.oldest_timestamp,
        "newest_candidate": candidate_report.newest_timestamp,
    });
    let report_checksum = sha256_json(&checksum_payload)?;
    Ok(RetentionScopeReport {
        scope: scope.to_string(),
        dry_run,
        cutoff,
        max_rows,
        matched_count: candidate_report.matched_count,
        planned_delete_count,
        rows_deleted,
        batch_count,
        batch_size,
        limit,
        oldest_candidate: candidate_report.oldest_timestamp.clone(),
        newest_candidate: candidate_report.newest_timestamp.clone(),
        report_checksum,
    })
}

fn write_retention_apply_audit(store: &Store, report: &RetentionScopeReport) -> anyhow::Result<()> {
    let mut event = AuditEvent::new(local_actor(), "retention.apply");
    event.ok = Some(true);
    event.detail_json = json!({
        "dry_run": report.dry_run,
        "scope": report.scope,
        "cutoff": report.cutoff,
        "matched_count": report.matched_count,
        "deleted_count": report.rows_deleted,
        "batch_count": report.batch_count,
        "report_checksum": report.report_checksum,
    });
    store.insert_audit(&event)?;
    Ok(())
}

fn validate_retention_apply_bounds(limit: Option<u64>, batch_size: u64) -> anyhow::Result<()> {
    if let Some(limit) = limit
        && (limit == 0 || limit > MAX_RETENTION_APPLY_LIMIT)
    {
        bail!("--limit must be between 1 and {MAX_RETENTION_APPLY_LIMIT}");
    }
    if batch_size == 0 || batch_size > MAX_RETENTION_BATCH_SIZE {
        bail!("--batch-size must be between 1 and {MAX_RETENTION_BATCH_SIZE}");
    }
    Ok(())
}

fn selected_retention_scopes(scope: Option<RetentionScope>) -> Vec<&'static str> {
    scope
        .map(|scope| vec![retention_scope_name(scope)])
        .unwrap_or_else(|| RETENTION_SCOPES.to_vec())
}

fn retention_scope_name(scope: RetentionScope) -> &'static str {
    match scope {
        RetentionScope::Observations => "observations",
        RetentionScope::ObservabilityRuns => "observability-runs",
        RetentionScope::HealthSnapshots => "health-snapshots",
        RetentionScope::AlertEvents => "alert-events",
    }
}

fn default_retention_policy(scope: &str) -> RetentionPolicyRecord {
    let (max_age_days, max_rows) = match scope {
        "observations" => (Some(30), Some(100_000)),
        "observability-runs" => (Some(30), Some(100_000)),
        "health-snapshots" => (Some(30), None),
        "alert-events" => (Some(180), None),
        _ => (None, None),
    };
    RetentionPolicyRecord {
        scope: scope.to_string(),
        max_age_days,
        max_rows,
        updated_at: "default".to_string(),
    }
}

fn effective_retention_policy(store: &Store, scope: &str) -> anyhow::Result<RetentionPolicyRecord> {
    Ok(store
        .get_retention_policy(scope)?
        .unwrap_or_else(|| default_retention_policy(scope)))
}

fn retention_cutoff(policy: &RetentionPolicyRecord) -> anyhow::Result<Option<String>> {
    let Some(max_age_days) = policy.max_age_days else {
        return Ok(None);
    };
    let days = i64::try_from(max_age_days).context("retention max age is too large")?;
    Ok(Some(
        (OffsetDateTime::now_utc() - Duration::days(days))
            .format(&Rfc3339)
            .expect("RFC3339 formatting succeeds"),
    ))
}

fn parse_retention_max_age_days(value: &str) -> anyhow::Result<u64> {
    let seconds = parse_duration_seconds(value, "--max-age")?;
    const SECONDS_PER_DAY: u64 = 24 * 60 * 60;
    if seconds % SECONDS_PER_DAY != 0 {
        bail!("--max-age must resolve to whole days");
    }
    let days = seconds / SECONDS_PER_DAY;
    if days == 0 {
        bail!("--max-age must be at least one day");
    }
    Ok(days)
}

fn parse_rfc3339(value: &str) -> anyhow::Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).with_context(|| "timestamp must be RFC3339")
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("RFC3339 formatting succeeds")
}

fn optional_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "<none>".to_string())
}

fn optional_str(value: Option<&str>) -> &str {
    value.unwrap_or("<none>")
}

fn sha256_json(value: &Value) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(value)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}
