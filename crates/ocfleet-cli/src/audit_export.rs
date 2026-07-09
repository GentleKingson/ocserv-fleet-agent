use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
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
const MAX_AUDIT_EXPORT_SIGNING_KEY_BYTES: usize = 16 * 1024;
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
            sign_with_key_file,
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
                sign_with_key_file,
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
    sign_with_key_file: Option<PathBuf>,
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
                AuditExportAuditOutcome {
                    ok: true,
                    row_count: summary.row_count,
                    checksum: summary.checksum.as_deref(),
                    signature: summary.signature.as_ref(),
                    error_code: None,
                },
                &output_path_hash,
            )?;
            println!("status=ok");
            println!("format=jsonl");
            println!("row_count={}", summary.row_count);
            println!("bytes_written={}", summary.bytes_written);
            println!("redaction_mode={}", redaction_mode_name(options.redact));
            if let Some(checksum) = summary.checksum {
                println!("checksum={checksum}");
            }
            if summary.signature.is_some() {
                println!("signature_algorithm=Ed25519");
                println!("signature_sidecar=written");
            }
            Ok(())
        }
        Err(err) => {
            let error_code = classify_export_error(&err);
            let _ = write_audit_export_audit(
                store,
                &options,
                AuditExportAuditOutcome {
                    ok: false,
                    row_count: 0,
                    checksum: None,
                    signature: None,
                    error_code: Some(error_code),
                },
                &output_path_hash,
            );
            Err(err)
        }
    }
}

struct AuditExportSummary {
    row_count: usize,
    bytes_written: usize,
    checksum: Option<String>,
    signature: Option<SignatureSummary>,
}

struct SignatureSummary {
    algorithm: &'static str,
    public_key_fingerprint: String,
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
    let signature = if let Some(key_file) = &options.sign_with_key_file {
        Some(
            write_signature_sidecar(&options.output, &lines, key_file, &checksum)
                .with_context(|| "audit export signing failed")?,
        )
    } else {
        None
    };
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
        signature,
    })
}

pub fn validate_window(from: &str, to: &str) -> anyhow::Result<(OffsetDateTime, OffsetDateTime)> {
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

pub fn audit_record_payload(row: &AuditRecord, redact: RedactionMode) -> Value {
    let strict = redact == RedactionMode::Strict;
    json!({
        "id": row.id,
        "ts": safe_timestamp(&row.ts),
        "actor": redact_top_level("actor", Some(row.actor.as_str()), strict),
        "event": safe_top_level_token(&row.event),
        "node_id": redact_top_level("node_id", row.node_id.as_deref(), strict),
        "endpoint_id": redact_top_level("endpoint_id", row.endpoint_id.as_deref(), strict),
        "method": row.method.as_deref().map(safe_rpc_method),
        "request_id": redact_top_level("request_id", row.request_id.as_deref(), strict),
        "params_hash": row.params_hash.as_deref().map(safe_top_level_token),
        "ok": row.ok,
        "error_code": row.error_code.as_deref().map(safe_top_level_token),
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
    if value.len() > 256
        || value
            .bytes()
            .any(|byte| !byte.is_ascii() || byte.is_ascii_control())
        || has_forbidden_detail_value(value)
    {
        return redacted();
    }
    Value::String(value.to_string())
}

fn safe_timestamp(value: &str) -> Value {
    if OffsetDateTime::parse(value, &Rfc3339).is_ok() {
        Value::String(value.to_string())
    } else {
        redacted()
    }
}

fn safe_top_level_token(value: &str) -> Value {
    if value.len() <= 128 && is_safe_token(value) && !has_forbidden_detail_value(value) {
        Value::String(value.to_string())
    } else {
        redacted()
    }
}

fn safe_rpc_method(value: &str) -> Value {
    if is_fixed_rpc_method(value) {
        Value::String(value.to_string())
    } else {
        redacted()
    }
}

fn redact_value(value: &Value, mode: RedactionMode) -> Value {
    redact_detail_value(None, value, mode, 0)
}

fn redact_detail_value(
    key: Option<&str>,
    value: &Value,
    mode: RedactionMode,
    depth: usize,
) -> Value {
    const MAX_DETAIL_DEPTH: usize = 8;
    const MAX_DETAIL_ENTRIES: usize = 64;
    const MAX_DETAIL_STRING_BYTES: usize = 256;

    if depth >= MAX_DETAIL_DEPTH {
        return Value::String("<redacted>".to_string());
    }
    match value {
        Value::Object(map) => {
            let mut output = Map::new();
            for (key, value) in map.iter().take(MAX_DETAIL_ENTRIES) {
                if is_forbidden_detail_key(key) {
                    output.insert(key.clone(), redacted());
                } else if mode == RedactionMode::Strict && is_identifier_key(key) {
                    output.insert(key.clone(), redact_identifier_value(value));
                } else {
                    output.insert(
                        key.clone(),
                        redact_detail_value(Some(key), value, mode, depth + 1),
                    );
                }
            }
            Value::Object(output)
        }
        Value::Array(values) => Value::Array(
            values
                .iter()
                .take(MAX_DETAIL_ENTRIES)
                .map(|value| redact_detail_value(key, value, mode, depth + 1))
                .collect(),
        ),
        Value::String(value) => {
            let Some(key) = key else {
                return redacted();
            };
            if value.len() > MAX_DETAIL_STRING_BYTES
                || value
                    .bytes()
                    .any(|byte| !byte.is_ascii() || byte.is_ascii_control())
                || has_forbidden_detail_value(value)
                || !is_allowed_detail_string(key, value)
            {
                redacted()
            } else {
                Value::String(value.clone())
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => value.clone(),
    }
}

fn redacted() -> Value {
    Value::String("<redacted>".to_string())
}

fn redact_identifier_value(value: &Value) -> Value {
    match value {
        Value::String(value) => {
            Value::String(format!("sha256:{}", &sha256_hex(value.as_bytes())[..16]))
        }
        _ => Value::String("<redacted>".to_string()),
    }
}

fn is_forbidden_detail_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "private_key",
        "hmac",
        "authorization",
        "cookie",
        "username",
        "user_name",
        "account",
        "client_ip",
        "assigned_vpn_ip",
        "source_address",
        "destination_address",
        "source_port",
        "destination_port",
        "session_id",
        "session_token",
        "certificate_subject",
        "certificate_san",
        "cert_subject",
        "subject_alt_name",
        "issuer",
        "serial",
        "pem",
        "raw_",
        "log",
        "stdout",
        "stderr",
        "command",
        "shell",
        "script",
        "journal",
        "unit_name",
        "provider_selector",
        "path",
        "dsn",
        "url",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

fn is_identifier_key(key: &str) -> bool {
    key == "actor"
        || key == "node_id"
        || key == "endpoint_id"
        || key == "request_id"
        || key.ends_with("_id")
}

fn is_allowed_detail_string(key: &str, value: &str) -> bool {
    if matches!(key, "method" | "methods" | "degraded_methods") {
        return is_fixed_rpc_method(value);
    }
    if is_identifier_key(key) {
        return !value.trim().is_empty();
    }
    if key.ends_with("_at")
        || matches!(
            key,
            "from"
                | "to"
                | "cutoff"
                | "oldest_candidate"
                | "newest_candidate"
                | "checksum"
                | "report_checksum"
                | "params_hash"
                | "fingerprint"
                | "signature_public_key_fingerprint"
        )
    {
        return is_safe_token(value);
    }
    matches!(
        key,
        "status"
            | "state"
            | "reason_code"
            | "error_code"
            | "kind"
            | "hook_type"
            | "policy_class"
            | "scope"
            | "triggered_by"
            | "redaction_mode"
            | "signature_algorithm"
            | "http_status_class"
            | "endpoint_status"
            | "result_class"
            | "operation_kind"
            | "selector_kind"
            | "role"
            | "region"
    ) && is_safe_token(value)
}

fn is_safe_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
        && value.parse::<std::net::IpAddr>().is_err()
}

fn is_fixed_rpc_method(value: &str) -> bool {
    use ocfleet_protocol::method::{
        MethodStatus, PROBE_PATH_ECHO, PROBE_PEER_ECHO, classify_phase_one_method,
    };
    classify_phase_one_method(value) != MethodStatus::Unknown
        || matches!(value, PROBE_PATH_ECHO | PROBE_PEER_ECHO)
}

fn has_forbidden_detail_value(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    [
        "/etc/",
        "/var/",
        "-----begin",
        "systemctl",
        "journalctl",
        "occtl",
        "username",
        "client_ip",
        "client ip",
        "session_id",
        "session id",
        "raw config",
        "raw log",
        "stdout",
        "stderr",
    ]
    .iter()
    .any(|marker| value.contains(marker))
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

fn write_signature_sidecar(
    path: &Path,
    lines: &[Vec<u8>],
    key_file: &Path,
    content_sha256: &str,
) -> anyhow::Result<SignatureSummary> {
    let key_bytes = read_signing_key_file(key_file)?;
    let key_pair = Ed25519KeyPair::from_pkcs8(&key_bytes)
        .map_err(|_| anyhow::anyhow!("invalid Ed25519 PKCS#8 signing key"))?;
    let mut body = Vec::new();
    for line in lines {
        body.extend_from_slice(line);
    }
    let signature = key_pair.sign(&body);
    let public_key = key_pair.public_key().as_ref();
    let public_key_b64 = BASE64.encode(public_key);
    let signature_b64 = BASE64.encode(signature.as_ref());
    let signed_file = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("audit-export.jsonl");
    let sidecar = json!({
        "schema": "ocfleet.audit_export.signature.v1",
        "algorithm": "Ed25519",
        "signed_file": signed_file,
        "content_sha256": content_sha256,
        "public_key": public_key_b64,
        "signature": signature_b64,
        "signed_at": OffsetDateTime::now_utc().format(&Rfc3339)?,
    });
    let signature_path = signature_sidecar_path(path);
    let mut file = private_file::open_private_create_new_strict(&signature_path)?;
    serde_json::to_writer_pretty(&mut file, &sidecar)?;
    file.write_all(b"\n")?;
    Ok(SignatureSummary {
        algorithm: "Ed25519",
        public_key_fingerprint: format!("sha256:{}", &sha256_hex(public_key)[..16]),
    })
}

fn read_signing_key_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    let file = private_file::open_existing_private_read(path)?;
    let mut limited = file.take((MAX_AUDIT_EXPORT_SIGNING_KEY_BYTES + 1) as u64);
    let mut bytes = Vec::new();
    limited.read_to_end(&mut bytes)?;
    if bytes.len() > MAX_AUDIT_EXPORT_SIGNING_KEY_BYTES {
        bail!("audit export signing key file is too large");
    }
    Ok(bytes)
}

fn signature_sidecar_path(path: &Path) -> PathBuf {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some(extension) => path.with_extension(format!("{extension}.sig")),
        None => path.with_extension("sig"),
    }
}

struct AuditExportAuditOutcome<'a> {
    ok: bool,
    row_count: usize,
    checksum: Option<&'a str>,
    signature: Option<&'a SignatureSummary>,
    error_code: Option<&'a str>,
}

fn write_audit_export_audit(
    store: &Store,
    options: &AuditExportOptions,
    outcome: AuditExportAuditOutcome<'_>,
    output_path_hash: &str,
) -> anyhow::Result<()> {
    let mut event = AuditEvent::new(local_actor(), "audit.export");
    event.ok = Some(outcome.ok);
    event.error_code = outcome.error_code.map(ToOwned::to_owned);
    event.detail_json = json!({
        "from": options.from,
        "to": options.to,
        "row_count": outcome.row_count,
        "redaction_mode": redaction_mode_name(options.redact),
        "checksum": outcome.checksum,
        "signature_algorithm": outcome.signature.map(|summary| summary.algorithm),
        "signature_public_key_fingerprint": outcome.signature.map(|summary| summary.public_key_fingerprint.as_str()),
        "output_path_hash": output_path_hash,
        "error_code": outcome.error_code,
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
