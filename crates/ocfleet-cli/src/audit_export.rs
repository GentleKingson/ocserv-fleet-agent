use anyhow::{Context, bail};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use crate::args::{AuditCommand, AuditExportFormat, RedactionMode};
use crate::audit::AuditEvent;
use crate::input_validation::local_actor;
use crate::private_file;
use crate::store::{AuditRecord, Store};

const MAX_AUDIT_EXPORT_WINDOW_DAYS: i64 = 31;
pub const DEFAULT_MAX_AUDIT_EXPORT_ROWS: usize = 10_000;
const MAX_AUDIT_EXPORT_ROWS: usize = 100_000;
const MAX_AUDIT_EXPORT_RECORD_BYTES: usize = 16 * 1024;
const MAX_AUDIT_EXPORT_BYTES: usize = 64 * 1024 * 1024;
const AUDIT_EXPORT_FAILED: &str = "AUDIT_EXPORT_FAILED";
const AUDIT_EXPORT_TOO_MANY_ROWS: &str = "AUDIT_EXPORT_TOO_MANY_ROWS";

pub fn run_audit_command(store: &Store, command: AuditCommand) -> anyhow::Result<()> {
    match command {
        AuditCommand::Export {
            from,
            to,
            format,
            output,
            redact,
            include_checksum,
            max_rows,
        } => run_audit_export(
            store,
            AuditExportOptions {
                from,
                to,
                format,
                output,
                redact,
                include_checksum,
                max_rows,
            },
        ),
    }
}

struct AuditExportOptions {
    from: String,
    to: String,
    format: AuditExportFormat,
    output: PathBuf,
    redact: RedactionMode,
    include_checksum: bool,
    max_rows: usize,
}

fn run_audit_export(store: &Store, options: AuditExportOptions) -> anyhow::Result<()> {
    let output_path_hash = sha256_hex(options.output.to_string_lossy().as_bytes());
    let result = run_audit_export_inner(store, &options);
    match result {
        Ok(summary) => {
            write_audit_export_audit(
                store,
                &options,
                true,
                summary.row_count,
                summary.checksum.as_deref(),
                &output_path_hash,
                None,
            )?;
            println!("status=ok");
            println!("format=jsonl");
            println!("row_count={}", summary.row_count);
            println!("bytes_written={}", summary.bytes_written);
            println!("redaction_mode={}", redaction_mode_name(options.redact));
            if let Some(checksum) = summary.checksum {
                println!("checksum={checksum}");
            }
            Ok(())
        }
        Err(err) => {
            let error_code = classify_export_error(&err);
            let _ = write_audit_export_audit(
                store,
                &options,
                false,
                0,
                None,
                &output_path_hash,
                Some(error_code),
            );
            Err(err)
        }
    }
}

struct AuditExportSummary {
    row_count: usize,
    bytes_written: usize,
    checksum: Option<String>,
}

fn run_audit_export_inner(
    store: &Store,
    options: &AuditExportOptions,
) -> anyhow::Result<AuditExportSummary> {
    if options.format != AuditExportFormat::Jsonl {
        bail!("only jsonl audit export is supported");
    }
    validate_max_rows(options.max_rows)?;
    validate_window(&options.from, &options.to)?;
    let query_limit = options
        .max_rows
        .checked_add(1)
        .context("--max-rows is too large")?;
    let rows = store.list_audit_window(&options.from, &options.to, query_limit)?;
    if rows.len() > options.max_rows {
        bail!("audit export row count exceeds --max-rows");
    }

    let lines = build_jsonl_lines(&rows, options.redact)?;
    let bytes_written = total_bytes(&lines)?;
    if bytes_written > MAX_AUDIT_EXPORT_BYTES {
        bail!("audit export output exceeds byte limit");
    }
    let checksum =
        write_jsonl_file(&options.output, &lines).with_context(|| "audit export failed")?;
    let checksum = if options.include_checksum {
        write_checksum_sidecar(&options.output, &checksum)
            .with_context(|| "audit export failed")?;
        Some(checksum)
    } else {
        None
    };
    Ok(AuditExportSummary {
        row_count: rows.len(),
        bytes_written,
        checksum,
    })
}

fn validate_window(from: &str, to: &str) -> anyhow::Result<(OffsetDateTime, OffsetDateTime)> {
    let from = OffsetDateTime::parse(from, &Rfc3339).context("--from must be RFC3339")?;
    let to = OffsetDateTime::parse(to, &Rfc3339).context("--to must be RFC3339")?;
    if from >= to {
        bail!("--from must be before --to");
    }
    if to - from > Duration::days(MAX_AUDIT_EXPORT_WINDOW_DAYS) {
        bail!("audit export window must be at most {MAX_AUDIT_EXPORT_WINDOW_DAYS} days");
    }
    Ok((from, to))
}

fn validate_max_rows(max_rows: usize) -> anyhow::Result<()> {
    if max_rows == 0 || max_rows > MAX_AUDIT_EXPORT_ROWS {
        bail!("--max-rows must be between 1 and {MAX_AUDIT_EXPORT_ROWS}");
    }
    Ok(())
}

fn build_jsonl_lines(rows: &[AuditRecord], redact: RedactionMode) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut lines = Vec::with_capacity(rows.len());
    for row in rows {
        let payload = audit_record_payload(row, redact);
        let mut line = serde_json::to_vec(&payload)?;
        if line.len() > MAX_AUDIT_EXPORT_RECORD_BYTES {
            bail!("audit export row exceeds byte limit");
        }
        line.push(b'\n');
        lines.push(line);
    }
    Ok(lines)
}

fn audit_record_payload(row: &AuditRecord, redact: RedactionMode) -> Value {
    let strict = redact == RedactionMode::Strict;
    json!({
        "id": row.id,
        "ts": row.ts,
        "actor": redact_top_level("actor", Some(row.actor.as_str()), strict),
        "event": row.event,
        "node_id": redact_top_level("node_id", row.node_id.as_deref(), strict),
        "endpoint_id": redact_top_level("endpoint_id", row.endpoint_id.as_deref(), strict),
        "method": row.method,
        "request_id": redact_top_level("request_id", row.request_id.as_deref(), strict),
        "params_hash": row.params_hash,
        "ok": row.ok,
        "error_code": row.error_code,
        "duration_ms": row.duration_ms,
        "detail": redact_value(&row.detail_json, redact),
    })
}

fn redact_top_level(key: &str, value: Option<&str>, strict: bool) -> Value {
    let Some(value) = value else {
        return Value::Null;
    };
    if strict && matches!(key, "actor" | "node_id" | "endpoint_id" | "request_id") {
        return Value::String(format!("sha256:{}", &sha256_hex(value.as_bytes())[..16]));
    }
    Value::String(value.to_string())
}

fn redact_value(value: &Value, mode: RedactionMode) -> Value {
    match value {
        Value::Object(map) => {
            let mut output = Map::new();
            for (key, value) in map {
                if is_secret_key(key) {
                    output.insert(key.clone(), Value::String("<redacted>".to_string()));
                } else if mode == RedactionMode::Strict && is_identifier_key(key) {
                    output.insert(key.clone(), redact_identifier_value(value));
                } else {
                    output.insert(key.clone(), redact_value(value, mode));
                }
            }
            Value::Object(output)
        }
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| redact_value(value, mode))
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn redact_identifier_value(value: &Value) -> Value {
    match value {
        Value::String(value) => {
            Value::String(format!("sha256:{}", &sha256_hex(value.as_bytes())[..16]))
        }
        _ => Value::String("<redacted>".to_string()),
    }
}

fn is_secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "private_key",
        "hmac",
        "authorization",
        "cookie",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

fn is_identifier_key(key: &str) -> bool {
    matches!(key, "actor" | "node_id" | "endpoint_id" | "request_id")
}

fn total_bytes(lines: &[Vec<u8>]) -> anyhow::Result<usize> {
    lines.iter().try_fold(0_usize, |total, line| {
        total
            .checked_add(line.len())
            .context("audit export byte count overflow")
    })
}

fn write_jsonl_file(path: &Path, lines: &[Vec<u8>]) -> anyhow::Result<String> {
    let mut file = private_file::open_private_create_new_strict(path)?;
    let mut hasher = Sha256::new();
    for line in lines {
        file.write_all(line)?;
        hasher.update(line);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn write_checksum_sidecar(path: &Path, checksum: &str) -> anyhow::Result<()> {
    let checksum_path = match path.extension().and_then(|extension| extension.to_str()) {
        Some(extension) => path.with_extension(format!("{extension}.sha256")),
        None => path.with_extension("sha256"),
    };
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("audit-export.jsonl");
    let mut file = private_file::open_private_create_new_strict(&checksum_path)?;
    writeln!(file, "{checksum}  {file_name}")?;
    Ok(())
}

fn write_audit_export_audit(
    store: &Store,
    options: &AuditExportOptions,
    ok: bool,
    row_count: usize,
    checksum: Option<&str>,
    output_path_hash: &str,
    error_code: Option<&str>,
) -> anyhow::Result<()> {
    let mut event = AuditEvent::new(local_actor(), "audit.export");
    event.ok = Some(ok);
    event.error_code = error_code.map(ToOwned::to_owned);
    event.detail_json = json!({
        "from": options.from,
        "to": options.to,
        "row_count": row_count,
        "redaction_mode": redaction_mode_name(options.redact),
        "checksum": checksum,
        "output_path_hash": output_path_hash,
        "error_code": error_code,
    });
    store.insert_audit(&event)?;
    Ok(())
}

fn classify_export_error(err: &anyhow::Error) -> &'static str {
    let message = err.to_string();
    if message.contains("row count exceeds") {
        AUDIT_EXPORT_TOO_MANY_ROWS
    } else {
        AUDIT_EXPORT_FAILED
    }
}

fn redaction_mode_name(mode: RedactionMode) -> &'static str {
    match mode {
        RedactionMode::None => "none",
        RedactionMode::Default => "default",
        RedactionMode::Strict => "strict",
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
