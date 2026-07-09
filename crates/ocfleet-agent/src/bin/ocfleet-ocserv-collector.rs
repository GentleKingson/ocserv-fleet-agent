use std::io::Read;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, bail};
use clap::Parser;
use ocfleet_agent::private_file;
use ocfleet_protocol::ocserv::{
    OCSERV_CERT_DAYS_REMAINING_MAX, OCSERV_CERT_DAYS_REMAINING_MIN, OCSERV_ROLLING_COUNT_MAX,
    OcservCollectorStatus, OcservServiceEnabledState, OcservServiceState,
    is_valid_ocserv_collected_at, is_valid_ocserv_version, is_valid_sha256_short_hex,
};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

const SNAPSHOT_SCHEMA_VERSION: &str = "ocfleet.ocserv.snapshot.v2";
const SERVICE_IDENTITY: &str = "ocserv";
const SESSION_TOTAL_MAX: u32 = 1_000_000;
const MAX_CONFIG_BYTES: u64 = 16 * 1024;
const MAX_OUTPUT_BYTES: usize = 16 * 1024;
const EXAMPLE_CONFIG: &str = r#"# Local operator-managed ocserv metadata collector config.
# This file is read locally by ocfleet-ocserv-collector. It is never supplied by
# the controller and does not authorize service-manager or log access.
service_identity = "ocserv"
output_path = "./agent-state/ocserv-live-snapshot.json"
# Producer timestamp for these exact aggregate values. The collector preserves it;
# timer runs never replace it with the current time.
collected_at = "1970-01-01T00:00:00Z"
collector_status = "unknown"
service_state = "unknown"
enabled_state = "unknown"

# Optional low-sensitive aggregate fields.
# version = "ocserv 1.3.x"
# session_total = 0
# auth_failure_count_rolling = 0
# connection_failure_count_rolling = 0
# cert_min_days_remaining = 90
# config_fingerprint_short = "abcdef12"
"#;

#[derive(Debug, Parser)]
#[command(name = "ocfleet-ocserv-collector")]
#[command(version)]
#[command(about = "Local read-only ocserv metadata snapshot normalizer")]
struct Cli {
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
    #[arg(long)]
    check: bool,
    #[arg(long, conflicts_with_all = ["config", "output", "check"])]
    print_example_config: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectorConfig {
    service_identity: String,
    output_path: Option<PathBuf>,
    collected_at: String,
    collector_status: OcservCollectorStatus,
    service_state: OcservServiceState,
    enabled_state: OcservServiceEnabledState,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    session_total: Option<u32>,
    #[serde(default)]
    auth_failure_count_rolling: Option<u64>,
    #[serde(default)]
    connection_failure_count_rolling: Option<u64>,
    #[serde(default)]
    cert_min_days_remaining: Option<i64>,
    #[serde(default)]
    config_fingerprint_short: Option<String>,
}

#[derive(Serialize)]
struct SnapshotDocument<'a> {
    schema_version: &'static str,
    collected_at: &'a str,
    collector_status: OcservCollectorStatus,
    service_state: OcservServiceState,
    enabled_state: OcservServiceEnabledState,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_total: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_failure_count_rolling: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_failure_count_rolling: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cert_min_days_remaining: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config_fingerprint_short: Option<&'a str>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.print_example_config {
        print!("{EXAMPLE_CONFIG}");
        return Ok(());
    }

    let config_path = cli
        .config
        .as_deref()
        .context("--config <collector.toml> is required unless --print-example-config is used")?;
    let config = load_config(config_path)?;
    validate_config(&config)?;

    let output_path = resolve_output_path(&config, cli.output.as_deref())?;
    validate_output_path(output_path)?;
    if cli.check {
        println!("collector_config=ok");
        return Ok(());
    }

    let snapshot = snapshot_from_config(&config);
    let payload = serde_json::to_vec_pretty(&snapshot).context("failed to serialize snapshot")?;
    if payload.len() > MAX_OUTPUT_BYTES {
        bail!("collector snapshot exceeds {MAX_OUTPUT_BYTES} bytes");
    }
    private_file::write_private_replace(output_path, &payload)
        .context("failed to write private collector snapshot")?;
    private_file::open_existing_private_read(output_path)
        .context("collector snapshot failed private-file verification after write")?;
    println!("collector_snapshot=written");
    Ok(())
}

fn load_config(path: &Path) -> anyhow::Result<CollectorConfig> {
    let file = private_file::open_existing_private_read(path)
        .context("collector config is missing or unsafe")?;
    let mut raw = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut raw)
        .context("failed to read collector config")?;
    if raw.len() as u64 > MAX_CONFIG_BYTES {
        bail!("collector config exceeds {MAX_CONFIG_BYTES} bytes");
    }
    toml::from_str(&raw).map_err(|_| anyhow::anyhow!("collector TOML config is invalid"))
}

fn resolve_output_path<'a>(
    config: &'a CollectorConfig,
    cli_output: Option<&'a Path>,
) -> anyhow::Result<&'a Path> {
    match (config.output_path.as_deref(), cli_output) {
        (Some(config_output), Some(cli_output)) if config_output != cli_output => {
            bail!("--output must match output_path from the collector config")
        }
        (Some(config_output), _) => Ok(config_output),
        (None, Some(cli_output)) => Ok(cli_output),
        (None, None) => bail!("--output <path> is required when config output_path is omitted"),
    }
}

fn validate_config(config: &CollectorConfig) -> anyhow::Result<()> {
    if config.service_identity != SERVICE_IDENTITY {
        bail!("service_identity must be exactly {SERVICE_IDENTITY:?}");
    }
    if !is_valid_ocserv_collected_at(&config.collected_at) {
        bail!("collected_at must be a bounded RFC3339 producer timestamp");
    }
    let collected_at = OffsetDateTime::parse(&config.collected_at, &Rfc3339)
        .context("collected_at must be a valid RFC3339 producer timestamp")?;
    if collected_at > OffsetDateTime::now_utc() + Duration::minutes(5) {
        bail!("collected_at must not be more than five minutes in the future");
    }
    if let Some(version) = config.version.as_deref()
        && !is_valid_ocserv_version(version)
    {
        bail!("version must be a bounded printable ocserv version string");
    }
    if let Some(session_total) = config.session_total
        && session_total > SESSION_TOTAL_MAX
    {
        bail!("session_total must be at most {SESSION_TOTAL_MAX}");
    }
    validate_rolling_count(
        "auth_failure_count_rolling",
        config.auth_failure_count_rolling,
    )?;
    validate_rolling_count(
        "connection_failure_count_rolling",
        config.connection_failure_count_rolling,
    )?;
    if let Some(days) = config.cert_min_days_remaining
        && !(OCSERV_CERT_DAYS_REMAINING_MIN..=OCSERV_CERT_DAYS_REMAINING_MAX).contains(&days)
    {
        bail!(
            "cert_min_days_remaining must be between {OCSERV_CERT_DAYS_REMAINING_MIN} and {OCSERV_CERT_DAYS_REMAINING_MAX}"
        );
    }
    if let Some(fingerprint) = config.config_fingerprint_short.as_deref()
        && !is_valid_sha256_short_hex(fingerprint)
    {
        bail!("config_fingerprint_short must be 6-16 hex characters");
    }
    Ok(())
}

fn validate_output_path(path: &Path) -> anyhow::Result<()> {
    if path.as_os_str().is_empty() || path.file_name().is_none() {
        bail!("collector output path must name a file");
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        bail!("collector output path must not contain parent traversal");
    }
    validate_output_path_platform(path)
}

#[cfg(unix)]
fn validate_output_path_platform(path: &Path) -> anyhow::Result<()> {
    use std::fs;
    use std::io;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    match fs::symlink_metadata(parent) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.permissions().mode() & 0o077 != 0
            {
                bail!("collector output parent must be an owner-only directory");
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let ancestor = parent
                .ancestors()
                .find(|ancestor| ancestor.exists())
                .context("collector output path has no existing parent")?;
            let metadata = fs::metadata(ancestor)
                .context("failed to inspect collector output parent ancestor")?;
            if !metadata.is_dir()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.permissions().mode() & 0o022 != 0
            {
                bail!("collector output parent ancestor is unsafe");
            }
        }
        Err(err) => return Err(err).context("failed to inspect collector output parent"),
    }

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("collector output must be a regular non-symlink file")
        }
        Ok(_) => {
            private_file::open_existing_private_read(path)
                .context("existing collector output is unsafe")?;
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).context("failed to inspect collector output"),
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_output_path_platform(_path: &Path) -> anyhow::Result<()> {
    bail!("private collector output is supported only on Unix")
}

fn validate_rolling_count(field: &'static str, value: Option<u64>) -> anyhow::Result<()> {
    if let Some(value) = value
        && value > OCSERV_ROLLING_COUNT_MAX
    {
        bail!("{field} must be at most {OCSERV_ROLLING_COUNT_MAX}");
    }
    Ok(())
}

fn snapshot_from_config(config: &CollectorConfig) -> SnapshotDocument<'_> {
    SnapshotDocument {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        collected_at: &config.collected_at,
        collector_status: config.collector_status,
        service_state: config.service_state,
        enabled_state: config.enabled_state,
        version: config.version.as_deref(),
        session_total: config.session_total,
        auth_failure_count_rolling: config.auth_failure_count_rolling,
        connection_failure_count_rolling: config.connection_failure_count_rolling,
        cert_min_days_remaining: config.cert_min_days_remaining,
        config_fingerprint_short: config.config_fingerprint_short.as_deref(),
    }
}
