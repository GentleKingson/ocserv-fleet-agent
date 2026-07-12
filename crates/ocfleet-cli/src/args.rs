use clap::{ArgGroup, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "ocfleet")]
#[command(version)]
#[command(about = "Read-only ocserv fleet controller")]
pub struct Cli {
    #[arg(long, default_value = "controller.sqlite")]
    pub database: PathBuf,
    #[arg(long, default_value = "controller.secret")]
    pub secret_key: PathBuf,
    #[arg(long, global = true)]
    pub actor: Option<String>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Init,
    Doctor {
        #[arg(long)]
        json: bool,
    },
    Ping {
        node_id: String,
    },
    Probe {
        #[command(subcommand)]
        command: ProbeCommand,
    },
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    Enroll {
        #[command(subcommand)]
        command: EnrollCommand,
    },
    Endpoint {
        #[command(subcommand)]
        command: EndpointCommand,
    },
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },
    Ocserv {
        #[command(subcommand)]
        command: OcservCommand,
    },
    Schedule {
        #[command(subcommand)]
        command: ScheduleCommand,
    },
    Observation {
        #[command(subcommand)]
        command: ObservationCommand,
    },
    Retention {
        #[command(subcommand)]
        command: RetentionCommand,
    },
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    Health {
        #[command(subcommand)]
        command: HealthCommand,
    },
    Alert {
        #[command(subcommand)]
        command: AlertCommand,
    },
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
    Restore {
        #[command(subcommand)]
        command: RestoreCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum BackupCommand {
    Create {
        #[arg(long, value_name = "DIR")]
        output_dir: PathBuf,
        #[arg(long, value_name = "PATH")]
        sign_with_key_file: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    List {
        #[arg(long, value_name = "DIR")]
        backup_dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Verify {
        #[arg(long, value_name = "PATH")]
        manifest: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Inspect {
        #[arg(long, value_name = "PATH")]
        manifest: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum RestoreCommand {
    Plan {
        #[arg(long, value_name = "PATH")]
        manifest: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Apply {
        #[arg(long, value_name = "PATH")]
        manifest: PathBuf,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ProbeCommand {
    Ping {
        node_id: String,
    },
    Path {
        source_node_id: String,
        target_node_id: String,
    },
    Summary {
        source_node_id: String,
        target_node_id: String,
    },
    Topology,
    History {
        node_id: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Observe {
        source_node_id: String,
        target_node_id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HealthRollupBucket {
    #[value(name = "5m")]
    FiveMinutes,
    #[value(name = "1h")]
    OneHour,
    #[value(name = "1d")]
    OneDay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HealthSloWindow {
    #[value(name = "24h")]
    Hours24,
    #[value(name = "7d")]
    Days7,
    #[value(name = "30d")]
    Days30,
}

#[derive(Debug, Subcommand)]
pub enum HealthRollupCommand {
    Recompute {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        node: Option<String>,
        #[arg(long, value_enum)]
        bucket: HealthRollupBucket,
        #[arg(long)]
        operation_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    List {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        node: Option<String>,
        #[arg(long, value_enum)]
        bucket: HealthRollupBucket,
        #[arg(long, default_value_t = 1000)]
        limit: u64,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum NodeCommand {
    Info {
        node_id: String,
    },
    Add {
        node_id: String,
        #[arg(long)]
        endpoint_id: String,
        #[arg(long)]
        region: String,
        #[arg(long, default_value = "ocserv")]
        role: String,
    },
    List,
    Disable {
        node_id: String,
    },
    Enable {
        node_id: String,
    },
    Remove {
        node_id: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum EnrollCommand {
    Token {
        #[command(subcommand)]
        command: EnrollTokenCommand,
    },
    Request {
        #[command(subcommand)]
        command: EnrollRequestCommand,
    },
    Approve {
        join_request_id: String,
        #[arg(long)]
        endpoint_id: String,
        #[arg(long)]
        node_id: String,
        #[arg(long)]
        region: String,
        #[arg(long, default_value = "ocserv")]
        role: String,
        #[arg(long)]
        reason: String,
    },
    Claim {
        join_request_id: String,
        #[arg(long)]
        endpoint_id: String,
        #[arg(long)]
        node_id: String,
        #[arg(long)]
        region: String,
        #[arg(long, default_value = "ocserv")]
        role: String,
        #[arg(long)]
        reason: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum EnrollTokenCommand {
    Create {
        #[arg(long, default_value = "24h")]
        ttl: String,
        #[arg(long, default_value_t = 1)]
        max_uses: u32,
        #[arg(long)]
        description: Option<String>,
    },
    Revoke {
        token_id: String,
        #[arg(long)]
        reason: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum EnrollRequestCommand {
    #[command(group(
        ArgGroup::new("token_source")
            .required(true)
            .multiple(false)
            .args(["token", "token_file", "token_stdin"])
    ))]
    Create {
        #[arg(long)]
        request_id: Option<String>,
        #[arg(
            long,
            help = "Enrollment token as a command-line argument (discouraged; prefer --token-file or --token-stdin)"
        )]
        token: Option<String>,
        #[arg(long, value_name = "PATH")]
        token_file: Option<PathBuf>,
        #[arg(long)]
        token_stdin: bool,
        #[arg(long)]
        agent_public_key: String,
        #[arg(long)]
        fingerprint: String,
        #[arg(long)]
        requested_endpoint_id: Option<String>,
        #[arg(long)]
        hostname: String,
        #[arg(long)]
        agent_version: String,
    },
    Reject {
        join_request_id: String,
        #[arg(long)]
        reason: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum EndpointCommand {
    Rotate {
        old_endpoint_id: String,
        #[arg(long)]
        new_endpoint_id: String,
        #[arg(long)]
        reason: String,
    },
    Revoke {
        endpoint_id: String,
        #[arg(long)]
        reason: String,
    },
    Quarantine {
        endpoint_id: String,
        #[arg(long)]
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TrustDiffFormat {
    Human,
    Json,
}

#[derive(Debug, Subcommand)]
pub enum TrustCommand {
    Diff {
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long, value_enum, default_value = "human")]
        format: TrustDiffFormat,
        #[arg(long)]
        strict: bool,
    },
    Policy {
        #[command(subcommand)]
        command: TrustPolicyCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum TrustPolicyCommand {
    Validate {
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Diff {
        file: PathBuf,
        #[arg(long, conflicts_with_all = ["format", "output"])]
        json: bool,
        #[arg(long, value_enum, default_value_t = TrustPolicyDiffFormat::Human)]
        format: TrustPolicyDiffFormat,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TrustPolicyDiffFormat {
    Human,
    Json,
    Markdown,
}

#[derive(Debug, Subcommand)]
pub enum OcservCommand {
    Status {
        node: String,
        #[arg(long)]
        json: bool,
    },
    Cert {
        node: String,
        #[arg(long)]
        json: bool,
    },
    Sessions {
        #[command(subcommand)]
        command: OcservSessionsCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum OcservSessionsCommand {
    Summary {
        node: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ScheduleCommand {
    Job {
        #[command(subcommand)]
        command: ScheduleJobCommand,
    },
    Run {
        #[command(subcommand)]
        command: Option<ScheduleRunCommand>,
        #[arg(long)]
        once: bool,
        #[arg(long)]
        job_id: Option<String>,
        #[arg(
            long,
            default_value_t = 1,
            help = "Maximum concurrent scheduler RPCs (1-32)"
        )]
        max_concurrency: usize,
        #[arg(long)]
        json: bool,
    },
    Daemon {
        #[arg(
            long,
            default_value_t = 1,
            help = "Maximum concurrent scheduler RPCs (1-32)"
        )]
        max_concurrency: usize,
        #[arg(long, default_value_t = 60)]
        tick_seconds: u64,
    },
    Maintenance {
        #[command(subcommand)]
        command: ScheduleMaintenanceCommand,
    },
    Status {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ScheduleMaintenanceCommand {
    Set {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        reason: String,
    },
    Clear,
    Show {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ScheduleRunCommand {
    List {
        #[arg(long, default_value_t = 50)]
        limit: u64,
        #[arg(long)]
        json: bool,
    },
    Show {
        run_id: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ScheduleJobCommand {
    Add {
        #[arg(long)]
        name: Option<String>,
        #[arg(long, value_enum)]
        kind: ScheduleJobKind,
        #[arg(long)]
        interval: String,
        #[arg(long, default_value_t = 0)]
        jitter_seconds: u64,
        #[arg(long, default_value_t = ocfleet_protocol::DEFAULT_DEADLINE_MS)]
        timeout_ms: u64,
        #[arg(long)]
        selector: Option<String>,
        #[arg(long)]
        source_node_id: Option<String>,
        #[arg(long)]
        target_node_id: Option<String>,
    },
    List {
        #[arg(long)]
        json: bool,
    },
    Show {
        job_id: String,
        #[arg(long)]
        json: bool,
    },
    Validate {
        job_id: String,
        #[arg(long)]
        json: bool,
    },
    Enable {
        job_id: String,
    },
    Disable {
        job_id: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ObservationCommand {
    List {
        #[arg(long)]
        node: Option<String>,
        #[arg(long)]
        method: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: u64,
        #[arg(long)]
        json: bool,
    },
    Show {
        observation_id: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ScheduleJobKind {
    #[value(name = "controller-ping")]
    ControllerPing,
    #[value(name = "ocserv-status")]
    OcservStatus,
    #[value(name = "ocserv-cert")]
    OcservCert,
    #[value(name = "ocserv-sessions")]
    OcservSessions,
    #[value(name = "path-probe")]
    PathProbe,
}

#[derive(Debug, Subcommand)]
pub enum RetentionCommand {
    Show,
    Set {
        #[arg(value_enum)]
        scope: RetentionScope,
        #[arg(long)]
        max_age: Option<String>,
        #[arg(long)]
        max_rows: Option<usize>,
    },
    Apply {
        #[arg(long)]
        dry_run: bool,
        #[arg(long, conflicts_with = "dry_run")]
        operation_id: Option<String>,
        #[arg(long, value_enum)]
        scope: Option<RetentionScope>,
        #[arg(long)]
        before: Option<String>,
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        json: bool,
        #[arg(long, default_value_t = 1_000)]
        batch_size: u64,
    },
    Explain {
        #[arg(long, value_enum)]
        scope: RetentionScope,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RetentionScope {
    Observations,
    #[value(name = "observability-runs")]
    ObservabilityRuns,
    #[value(name = "health-snapshots")]
    HealthSnapshots,
    #[value(name = "health-history")]
    HealthHistory,
    #[value(name = "health-rollups")]
    HealthRollups,
    #[value(name = "alert-events")]
    AlertEvents,
}

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    Export {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long, value_enum, default_value_t = AuditExportFormat::Jsonl)]
        format: AuditExportFormat,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_enum, default_value_t = RedactionMode::Default)]
        redact: RedactionMode,
        #[arg(long)]
        include_checksum: bool,
        #[arg(long)]
        sign_with_key_file: Option<PathBuf>,
        #[arg(long, default_value_t = crate::audit_export::DEFAULT_MAX_AUDIT_EXPORT_ROWS)]
        max_rows: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AuditExportFormat {
    Jsonl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RedactionMode {
    None,
    Default,
    Strict,
}

#[derive(Debug, Subcommand)]
pub enum HealthCommand {
    Summary {
        #[arg(long)]
        json: bool,
    },
    Node {
        node_id: String,
        #[arg(long)]
        json: bool,
    },
    Policy {
        #[command(subcommand)]
        command: HealthPolicyCommand,
    },
    Snapshot {
        #[command(subcommand)]
        command: HealthSnapshotCommand,
    },
    History {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        node: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: u64,
        #[arg(long)]
        json: bool,
    },
    Rollup {
        #[command(subcommand)]
        command: HealthRollupCommand,
    },
    Slo {
        #[arg(long)]
        to: String,
        #[arg(long)]
        node: Option<String>,
        #[arg(long, value_enum)]
        window: HealthSloWindow,
        #[arg(long)]
        json: bool,
    },
    Evaluator {
        #[command(subcommand)]
        command: HealthEvaluatorCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum HealthEvaluatorCommand {
    Run {
        #[arg(long)]
        json: bool,
    },
    Daemon {
        #[arg(long, default_value_t = 60)]
        interval_seconds: u64,
    },
}

#[derive(Debug, Subcommand)]
pub enum HealthSnapshotCommand {
    List {
        #[arg(long, default_value_t = 50)]
        limit: u64,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum HealthPolicyCommand {
    Show,
    Set {
        #[arg(long)]
        stale_window: Option<String>,
        #[arg(long)]
        unreachable_failures: Option<u64>,
        #[arg(long)]
        cert_warning_days: Option<u64>,
        #[arg(long)]
        cert_critical_days: Option<u64>,
    },
}

#[derive(Debug, Subcommand)]
pub enum AlertCommand {
    Hook {
        #[command(subcommand)]
        command: AlertHookCommand,
    },
    List {
        #[arg(long, value_enum)]
        state: Option<AlertState>,
        #[arg(long, value_enum)]
        severity: Option<AlertSeverity>,
        #[arg(long)]
        node: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Test {
        hook: String,
    },
    Deliver {
        #[arg(long)]
        hook: String,
        #[arg(long, default_value_t = crate::alert_delivery::DEFAULT_DELIVERY_LIMIT)]
        limit: u64,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, value_name = "PATH")]
        hmac_secret_file: Option<PathBuf>,
    },
    Silence {
        dedupe_key: String,
        #[arg(long)]
        for_duration: String,
        #[arg(long)]
        reason: String,
    },
    Resolve {
        dedupe_key: String,
        #[arg(long)]
        reason: String,
    },
    Worker {
        #[command(subcommand)]
        command: AlertWorkerCommand,
    },
    #[command(name = "delivery-daemon")]
    DeliveryDaemon {
        #[arg(long, value_name = "DIR")]
        hmac_secret_dir: PathBuf,
        #[arg(long, default_value_t = 60)]
        interval_seconds: u64,
        #[arg(long, default_value_t = 10)]
        max_deliveries: usize,
    },
}

#[derive(Debug, Subcommand)]
pub enum AlertWorkerCommand {
    Run {
        #[arg(long, value_name = "DIR")]
        hmac_secret_dir: PathBuf,
        #[arg(long, default_value_t = 10)]
        max_deliveries: usize,
        #[arg(long)]
        json: bool,
    },
    Daemon {
        #[arg(long, value_name = "DIR")]
        hmac_secret_dir: PathBuf,
        #[arg(long, default_value_t = 60)]
        interval_seconds: u64,
        #[arg(long, default_value_t = 10)]
        max_deliveries: usize,
    },
    Status {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum AlertHookCommand {
    AddWebhook {
        #[arg(long)]
        name: String,
        #[arg(long)]
        url: String,
        #[arg(long, value_name = "PATH")]
        hmac_secret_file: PathBuf,
        #[arg(long = "host-allow", required = true)]
        host_allow: Vec<String>,
        #[arg(long, default_value_t = crate::alert_webhook::DEFAULT_WEBHOOK_MAX_ATTEMPTS)]
        max_attempts: u64,
        #[arg(long, default_value_t = crate::alert_webhook::DEFAULT_WEBHOOK_TIMEOUT_MS)]
        timeout_ms: u64,
    },
    List {
        #[arg(long)]
        json: bool,
    },
    Test {
        hook_id: String,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, value_name = "PATH")]
        hmac_secret_file: Option<PathBuf>,
    },
    Enable {
        hook_id: String,
    },
    Disable {
        hook_id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AlertState {
    Open,
    Silenced,
    Resolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AlertSeverity {
    Warning,
    Critical,
}
