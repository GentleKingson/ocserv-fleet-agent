use anyhow::{Context, bail};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use crate::args::{RetentionCommand, RetentionScope};
use crate::backend::StoreWriter;
use crate::duration_args::parse_duration_seconds;
use crate::input_validation::local_actor;
use crate::store::{
    MAX_RETENTION_APPLY_LIMIT, MAX_RETENTION_BATCH_SIZE, RetentionApplyInput,
    RetentionCandidateReport, RetentionPolicyRecord, Store,
};
use uuid::Uuid;

const RETENTION_SCOPES: &[&str] = &[
    "observations",
    "observability-runs",
    "health-snapshots",
    "health-history",
    "alert-events",
];
#[derive(Debug, Serialize)]
struct RetentionApplyReport {
    generated_at: String,
    dry_run: bool,
    operation_id: Option<String>,
    scopes: Vec<RetentionScopeReport>,
}

#[derive(Debug, Serialize)]
struct RetentionExplainReport {
    generated_at: String,
    scope: String,
    effective_policy: RetentionPolicyJson,
    cutoff: Option<String>,
    matched_count: u64,
    oldest_candidate: Option<String>,
    newest_candidate: Option<String>,
    dry_run: bool,
}

#[derive(Debug, Serialize)]
struct RetentionPolicyJson {
    max_age_days: Option<u64>,
    max_rows: Option<u64>,
    updated_at: String,
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

struct RetentionApplyOptions {
    dry_run: bool,
    operation_id: Option<String>,
    scope: Option<RetentionScope>,
    before: Option<String>,
    limit: Option<u64>,
    json_output: bool,
    batch_size: u64,
}

struct RetentionScopeApply<'a> {
    dry_run: bool,
    operation_id: Option<&'a str>,
    actor: &'a str,
    explicit_cutoff: Option<&'a str>,
    limit: Option<u64>,
    batch_size: u64,
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
            operation_id,
            scope,
            before,
            limit,
            json,
            batch_size,
        } => run_retention_apply(
            store,
            RetentionApplyOptions {
                dry_run,
                operation_id,
                scope,
                before,
                limit,
                json_output: json,
                batch_size,
            },
        ),
        RetentionCommand::Explain { scope, json } => run_retention_explain(store, scope, json),
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
    if max_age.is_none() && max_rows.is_none() {
        bail!("retention set requires --max-age or --max-rows");
    }
    let scope_name = retention_scope_name(scope);
    let mut policy = effective_retention_policy(store, scope_name)?;
    if let Some(max_age) = max_age {
        policy.max_age_days = Some(parse_retention_max_age_days(max_age)?);
    }
    if let Some(max_rows) = max_rows {
        if max_rows == 0 {
            bail!("--max-rows must be greater than zero");
        }
        policy.max_rows = Some(u64::try_from(max_rows).context("--max-rows is too large")?);
    }
    policy.updated_at = now_rfc3339();
    let policy = StoreWriter::write_retention_policy(store, &policy, &local_actor())?;
    println!("scope={}", policy.scope);
    println!("max_age_days={}", optional_u64(policy.max_age_days));
    println!("max_rows={}", optional_u64(policy.max_rows));
    Ok(())
}

fn run_retention_apply(store: &Store, options: RetentionApplyOptions) -> anyhow::Result<()> {
    validate_retention_apply_bounds(options.limit, options.batch_size)?;
    let operation_id = if options.dry_run {
        None
    } else {
        Some(
            options
                .operation_id
                .unwrap_or_else(|| format!("retention-{}", Uuid::new_v4())),
        )
    };
    let actor = local_actor();
    let explicit_cutoff = match options.before.as_deref() {
        Some(before) => {
            parse_rfc3339(before)?;
            Some(before.to_string())
        }
        None => None,
    };
    let scopes = selected_retention_scopes(options.scope);
    let mut reports = Vec::new();
    for scope in scopes {
        let report = apply_retention_scope(
            store,
            scope,
            &RetentionScopeApply {
                dry_run: options.dry_run,
                operation_id: operation_id.as_deref(),
                actor: &actor,
                explicit_cutoff: explicit_cutoff.as_deref(),
                limit: options.limit,
                batch_size: options.batch_size,
            },
        )?;
        reports.push(report);
    }

    if options.json_output {
        let report = RetentionApplyReport {
            generated_at: now_rfc3339(),
            dry_run: options.dry_run,
            operation_id: operation_id.clone(),
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
        if let Some(operation_id) = &operation_id {
            println!("operation_id={operation_id}");
        }
        println!(
            "scope=controller_audit_log retention=never matched_count=0 deleted_count=0 rows_deleted=0 dry_run={}",
            options.dry_run
        );
    }
    Ok(())
}

fn run_retention_explain(
    store: &Store,
    scope: RetentionScope,
    json_output: bool,
) -> anyhow::Result<()> {
    let scope_name = retention_scope_name(scope);
    let policy = effective_retention_policy(store, scope_name)?;
    let cutoff = retention_cutoff(&policy)?;
    let candidate_report =
        store.retention_candidate_report(scope_name, cutoff.as_deref(), policy.max_rows)?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&RetentionExplainReport {
                generated_at: now_rfc3339(),
                scope: scope_name.to_string(),
                effective_policy: RetentionPolicyJson {
                    max_age_days: policy.max_age_days,
                    max_rows: policy.max_rows,
                    updated_at: policy.updated_at,
                },
                cutoff,
                matched_count: candidate_report.matched_count,
                oldest_candidate: candidate_report.oldest_timestamp,
                newest_candidate: candidate_report.newest_timestamp,
                dry_run: true,
            })?
        );
    } else {
        println!("scope={scope_name}");
        println!("max_age_days={}", optional_u64(policy.max_age_days));
        println!("max_rows={}", optional_u64(policy.max_rows));
        println!("updated_at={}", policy.updated_at);
        println!("cutoff={}", optional_str(cutoff.as_deref()));
        println!("matched_count={}", candidate_report.matched_count);
        println!(
            "oldest_candidate={}",
            optional_str(candidate_report.oldest_timestamp.as_deref())
        );
        println!(
            "newest_candidate={}",
            optional_str(candidate_report.newest_timestamp.as_deref())
        );
        println!("dry_run=true");
    }
    Ok(())
}

fn apply_retention_scope(
    store: &Store,
    scope: &str,
    apply: &RetentionScopeApply<'_>,
) -> anyhow::Result<RetentionScopeReport> {
    let policy = effective_retention_policy(store, scope)?;
    let requested_cutoff = apply.explicit_cutoff.map(ToOwned::to_owned);
    let (cutoff, candidate_report, planned_delete_count, rows_deleted, batch_count) =
        if apply.dry_run {
            let cutoff = requested_cutoff.clone().or(retention_cutoff(&policy)?);
            let candidate_report =
                store.retention_candidate_report(scope, cutoff.as_deref(), policy.max_rows)?;
            let planned_delete_count = apply
                .limit
                .map(|limit| candidate_report.matched_count.min(limit))
                .unwrap_or(candidate_report.matched_count);
            (cutoff, candidate_report, planned_delete_count, 0, 0)
        } else {
            let result = StoreWriter::write_retention_apply(
                store,
                &RetentionApplyInput {
                    operation_id: apply
                        .operation_id
                        .expect("operation id exists for non-dry-run retention")
                        .to_string(),
                    scope: scope.to_string(),
                    cutoff: requested_cutoff,
                    max_age_days: policy.max_age_days,
                    max_rows: policy.max_rows,
                    limit: apply.limit,
                    batch_size: apply.batch_size,
                },
                apply.actor,
            )?;
            (
                result.cutoff,
                result.candidate_report,
                result.planned_delete_count,
                result.rows_deleted,
                result.batch_count,
            )
        };
    scope_report(
        scope,
        apply.dry_run,
        cutoff,
        policy.max_rows,
        &candidate_report,
        planned_delete_count,
        rows_deleted,
        batch_count,
        apply.batch_size,
        apply.limit,
    )
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
        RetentionScope::HealthHistory => "health-history",
        RetentionScope::AlertEvents => "alert-events",
    }
}

fn default_retention_policy(scope: &str) -> RetentionPolicyRecord {
    let (max_age_days, max_rows) = match scope {
        "observations" => (Some(30), Some(100_000)),
        "observability-runs" => (Some(30), Some(100_000)),
        "health-snapshots" => (Some(30), None),
        "health-history" => (Some(90), Some(1_000_000)),
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
