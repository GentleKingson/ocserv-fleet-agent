use anyhow::{Context, bail};
use clap::Parser;
use ocfleet_cli::alerts::run_alert_command;
use ocfleet_cli::args::{
    Cli, Command, EndpointCommand, EnrollCommand, EnrollRequestCommand, EnrollTokenCommand,
    NodeCommand, OcservCommand, OcservSessionsCommand, ProbeCommand, TrustCommand, TrustDiffFormat,
};
use ocfleet_cli::audit::AuditEvent;
use ocfleet_cli::audit_export::run_audit_command;
use ocfleet_cli::controller_rpc::{
    FixedControllerRpc, OcservCommandAudit, RpcAuditRecord, RpcCommandFailure, elapsed_ms,
    error_code_from_name, execute_fixed_node_rpc, execute_ocserv_rpc, execute_optional_ocserv_rpc,
    hash_json_value, inactive_endpoint_status, known_endpoint_id, load_ocserv_rpc_node,
    low_sensitive_detail, low_sensitive_fixed_rpc_summary, ocserv_failure_detail,
    write_ocserv_command_audit, write_rpc_audit,
};
use ocfleet_cli::doctor::{DoctorOptions, format_human, run_doctor};
use ocfleet_cli::duration_args::parse_duration_seconds;
use ocfleet_cli::health::run_health_command;
use ocfleet_cli::identity::load_or_create_secret_key_with_status;
use ocfleet_cli::input_validation::{
    local_actor, validate_agent_version, validate_description, validate_hostname, validate_reason,
};
use ocfleet_cli::ocserv_output::{
    OcservStatusView, assert_low_sensitive_ocserv_output, format_cert_human, format_cert_json,
    format_sessions_human, format_status_json, format_status_view_human,
};
use ocfleet_cli::retention::run_retention_command;
use ocfleet_cli::scheduler::run_schedule_command;
use ocfleet_cli::store::{
    ApprovalInput, EndpointTrustRecord, EnrollmentTokenInsert, JoinRequestInsert, NodeInsert,
    NodeRecord, ProbeHistoryRecord, ProbeObservationRecord, Store,
};
use ocfleet_config::validation::{
    canonicalize_node_endpoint_id, validate_node_id, validate_region, validate_role,
};
use ocfleet_protocol::enrollment::{EndpointStatus, TrustBundle};
use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::method::{
    NODE_INFO, NODE_PING, OCSERV_CERT_EXPIRY, OCSERV_CONFIG_FINGERPRINT, OCSERV_SERVICE_SUMMARY,
    OCSERV_SESSIONS_SUMMARY, OCSERV_VERSION, PROBE_CONTROLLER_PING, PROBE_PATH_ECHO,
};
use ocfleet_protocol::ocserv::{
    OcservCertExpiryResponse, OcservConfigFingerprintResponse, OcservServiceSummaryResponse,
    OcservSessionsSummaryResponse, OcservVersionResponse,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt::init();

    match cli.command {
        Command::Init => {
            let secret_key = load_or_create_secret_key_with_status(&cli.secret_key, false)
                .context("failed to load or create controller SecretKey")?;
            let opened = Store::open_with_status(&cli.database)
                .context("failed to open controller database")?;
            let store = opened.store;
            let mut event = AuditEvent::new(local_actor(), "controller.init");
            event.ok = Some(true);
            event.detail_json = serde_json::json!({
                "created_database": opened.created_database,
                "created_secret_key": secret_key.created,
                "schema_version": store.current_schema_version()?,
            });
            store.insert_audit(&event)?;
            println!("controller_endpoint_id={}", secret_key.secret_key.public());
        }
        Command::Doctor { json } => {
            let report = run_doctor(&DoctorOptions {
                database: cli.database,
                secret_key: cli.secret_key,
            });
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", format_human(&report));
            }
            if report.exit_code != 0 {
                std::process::exit(report.exit_code);
            }
        }
        Command::Ping { node_id } => {
            let store = Store::open(&cli.database).context("failed to open controller database")?;
            run_node_rpc_command(&store, &cli.secret_key, &node_id, NODE_PING).await?;
        }
        Command::Probe { command } => {
            let store = Store::open(&cli.database).context("failed to open controller database")?;
            match command {
                ProbeCommand::Ping { node_id } => {
                    run_node_rpc_command(&store, &cli.secret_key, &node_id, PROBE_CONTROLLER_PING)
                        .await?;
                }
                ProbeCommand::Path {
                    source_node_id,
                    target_node_id,
                } => {
                    run_path_probe_command(
                        &store,
                        &cli.secret_key,
                        &source_node_id,
                        &target_node_id,
                    )
                    .await?;
                }
                ProbeCommand::Summary {
                    source_node_id,
                    target_node_id,
                } => run_probe_summary_command(&store, &source_node_id, &target_node_id)?,
                ProbeCommand::Topology => run_probe_topology_command(&store)?,
                ProbeCommand::History {
                    node_id,
                    limit,
                    since,
                    json,
                } => run_probe_history_command(
                    &store,
                    node_id.as_deref(),
                    limit,
                    since.as_deref(),
                    json,
                )?,
                ProbeCommand::Observe {
                    source_node_id,
                    target_node_id,
                } => run_probe_observe_command(&store, &source_node_id, &target_node_id)?,
            }
        }
        Command::Node { command } => {
            let store = Store::open(&cli.database).context("failed to open controller database")?;
            match command {
                NodeCommand::Info { node_id } => {
                    run_node_rpc_command(&store, &cli.secret_key, &node_id, NODE_INFO).await?;
                }
                NodeCommand::Add {
                    node_id,
                    endpoint_id,
                    region,
                    role,
                } => {
                    validate_node_id(&node_id)?;
                    let endpoint_id = canonicalize_node_endpoint_id(&endpoint_id)?;
                    validate_region(&region)?;
                    validate_role(&role)?;
                    let node = NodeInsert {
                        node_id: node_id.clone(),
                        endpoint_id: endpoint_id.clone(),
                        name: node_id.clone(),
                        region,
                        role,
                    };
                    store.add_node(&node)?;
                    let mut event = AuditEvent::new(local_actor(), "node.add");
                    event.node_id = Some(node_id);
                    event.endpoint_id = Some(endpoint_id);
                    event.ok = Some(true);
                    store.insert_audit(&event)?;
                }
                NodeCommand::List => {
                    let nodes = store.list_nodes()?;
                    let mut event = AuditEvent::new(local_actor(), "node.list");
                    event.ok = Some(true);
                    event.detail_json = serde_json::json!({
                        "node_count": nodes.len(),
                    });
                    store.insert_audit(&event)?;
                    for node in nodes {
                        println!(
                            "{} {} {} enabled={}",
                            node.node_id, node.endpoint_id, node.region, node.enabled
                        );
                    }
                }
                NodeCommand::Disable { node_id } => {
                    validate_node_id(&node_id)?;
                    store.disable_node(&node_id)?;
                    let mut event = AuditEvent::new(local_actor(), "node.disable");
                    event.node_id = Some(node_id);
                    event.ok = Some(true);
                    store.insert_audit(&event)?;
                }
                NodeCommand::Enable { node_id } => {
                    validate_node_id(&node_id)?;
                    store.enable_node(&node_id)?;
                    let mut event = AuditEvent::new(local_actor(), "node.enable");
                    event.node_id = Some(node_id);
                    event.ok = Some(true);
                    store.insert_audit(&event)?;
                }
                NodeCommand::Remove { node_id, yes } => {
                    validate_node_id(&node_id)?;
                    if !yes {
                        bail!("node remove requires --yes");
                    }
                    store.remove_node(&node_id)?;
                    let mut event = AuditEvent::new(local_actor(), "node.remove");
                    event.node_id = Some(node_id);
                    event.ok = Some(true);
                    store.insert_audit(&event)?;
                }
            }
        }
        Command::Enroll { command } => {
            let store = Store::open(&cli.database).context("failed to open controller database")?;
            match command {
                EnrollCommand::Token { command } => match command {
                    EnrollTokenCommand::Create {
                        ttl,
                        max_uses,
                        description,
                    } => run_enroll_token_create(&store, &ttl, max_uses, description)?,
                },
                EnrollCommand::Request { command } => match command {
                    EnrollRequestCommand::Create {
                        token,
                        token_file,
                        token_stdin,
                        agent_public_key,
                        fingerprint,
                        requested_endpoint_id,
                        hostname,
                        agent_version,
                    } => run_enroll_request_create(
                        &store,
                        EnrollRequestCreateInput {
                            token,
                            token_file,
                            token_stdin,
                            agent_public_key,
                            fingerprint,
                            requested_endpoint_id,
                            hostname,
                            agent_version,
                        },
                    )?,
                },
                EnrollCommand::Approve {
                    join_request_id,
                    endpoint_id,
                    reason,
                } => run_enroll_approve(&store, &join_request_id, &endpoint_id, &reason)?,
            }
        }
        Command::Endpoint { command } => {
            let store = Store::open(&cli.database).context("failed to open controller database")?;
            match command {
                EndpointCommand::Rotate {
                    old_endpoint_id,
                    new_endpoint_id,
                    reason,
                } => {
                    let endpoint = store.rotate_endpoint(
                        &old_endpoint_id,
                        &new_endpoint_id,
                        &local_actor(),
                        &reason,
                    )?;
                    println!("endpoint_id={}", endpoint.endpoint_id);
                    println!("status={}", endpoint.status.as_str());
                    println!("generation={}", endpoint.generation);
                    println!(
                        "previous_endpoint_id={}",
                        endpoint.previous_endpoint_id.as_deref().unwrap_or("<none>")
                    );
                }
                EndpointCommand::Revoke {
                    endpoint_id,
                    reason,
                } => {
                    let endpoint = store.revoke_endpoint(&endpoint_id, &local_actor(), &reason)?;
                    println!("endpoint_id={}", endpoint.endpoint_id);
                    println!("status={}", endpoint.status.as_str());
                    println!("generation={}", endpoint.generation);
                }
                EndpointCommand::Quarantine {
                    endpoint_id,
                    reason,
                } => {
                    let endpoint =
                        store.quarantine_endpoint(&endpoint_id, &local_actor(), &reason)?;
                    println!("endpoint_id={}", endpoint.endpoint_id);
                    println!("status={}", endpoint.status.as_str());
                    println!("generation={}", endpoint.generation);
                }
            }
        }
        Command::Trust { command } => {
            let store = Store::open(&cli.database).context("failed to open controller database")?;
            match command {
                TrustCommand::Diff {
                    endpoint,
                    format,
                    strict,
                } => run_trust_diff_command(&store, endpoint.as_deref(), format, strict)?,
            }
        }
        Command::Ocserv { command } => {
            let store = Store::open(&cli.database).context("failed to open controller database")?;
            match command {
                OcservCommand::Status { node, json } => {
                    run_ocserv_status_command(&store, &cli.secret_key, &node, json).await?
                }
                OcservCommand::Cert { node, json } => {
                    run_ocserv_cert_command(&store, &cli.secret_key, &node, json).await?
                }
                OcservCommand::Sessions { command } => match command {
                    OcservSessionsCommand::Summary { node, json } => {
                        run_ocserv_sessions_summary_command(&store, &cli.secret_key, &node, json)
                            .await?
                    }
                },
            }
        }
        Command::Schedule { command } => {
            let store = Store::open(&cli.database).context("failed to open controller database")?;
            run_schedule_command(&store, &cli.secret_key, command).await?;
        }
        Command::Retention { command } => {
            let store = Store::open(&cli.database).context("failed to open controller database")?;
            run_retention_command(&store, command)?;
        }
        Command::Audit { command } => {
            let store = Store::open(&cli.database).context("failed to open controller database")?;
            run_audit_command(&store, command)?;
        }
        Command::Health { command } => {
            let store = Store::open(&cli.database).context("failed to open controller database")?;
            run_health_command(&store, command)?;
        }
        Command::Alert { command } => {
            let store = Store::open(&cli.database).context("failed to open controller database")?;
            run_alert_command(&store, command)?;
        }
    }

    Ok(())
}

fn run_enroll_token_create(
    store: &Store,
    ttl: &str,
    max_uses: u32,
    description: Option<String>,
) -> anyhow::Result<()> {
    if max_uses == 0 {
        bail!("--max-uses must be greater than zero");
    }
    if let Some(description) = &description {
        validate_description(description).map_err(anyhow::Error::msg)?;
    }
    let ttl = parse_ttl(ttl)?;
    let token_id = format!("tok-{}", Uuid::new_v4());
    let token = format!("ocfleet_enroll_{}", Uuid::new_v4().simple());
    let expires_at = (OffsetDateTime::now_utc() + ttl)
        .format(&Rfc3339)
        .expect("RFC3339 formatting succeeds");
    let actor = local_actor();
    store.create_enrollment_token(
        &EnrollmentTokenInsert {
            token_id: token_id.clone(),
            token_hash: Store::hash_enrollment_token(&token),
            created_by: actor.clone(),
            expires_at: expires_at.clone(),
            max_uses,
            description,
            labels_json: json!({}),
            scope_json: json!({}),
        },
        &actor,
    )?;

    println!("token_id={token_id}");
    println!("token={token}");
    println!("expires_at={expires_at}");
    println!("max_uses={max_uses}");
    println!("plaintext_visible_once=true");
    Ok(())
}

fn run_enroll_approve(
    store: &Store,
    join_request_id: &str,
    endpoint_id: &str,
    reason: &str,
) -> anyhow::Result<()> {
    validate_reason(reason).map_err(anyhow::Error::msg)?;
    let approved = store.approve_join_request(&ApprovalInput {
        request_id: join_request_id.to_string(),
        endpoint_id: endpoint_id.to_string(),
        approved_by: local_actor(),
        reason: reason.to_string(),
        approved_labels_json: json!({}),
    })?;
    println!("join_request_id={}", approved.request_id);
    println!("status={}", approved.status.as_str());
    println!(
        "assigned_endpoint_id={}",
        approved.assigned_endpoint_id.as_deref().unwrap_or("<none>")
    );
    Ok(())
}

struct EnrollRequestCreateInput {
    token: Option<String>,
    token_file: Option<PathBuf>,
    token_stdin: bool,
    agent_public_key: String,
    fingerprint: String,
    requested_endpoint_id: Option<String>,
    hostname: String,
    agent_version: String,
}

fn run_enroll_request_create(store: &Store, input: EnrollRequestCreateInput) -> anyhow::Result<()> {
    validate_hostname(&input.hostname).map_err(anyhow::Error::msg)?;
    validate_agent_version(&input.agent_version).map_err(anyhow::Error::msg)?;
    let token = resolve_enrollment_token(input.token, input.token_file, input.token_stdin)?;
    let join = store.submit_join_request(
        &JoinRequestInsert {
            token_plaintext: token,
            agent_public_key: input.agent_public_key,
            fingerprint: input.fingerprint,
            requested_endpoint_id: input.requested_endpoint_id,
            hostname: input.hostname,
            agent_version: input.agent_version,
            requested_labels_json: json!({}),
        },
        "agent",
    )?;
    println!("join_request_id={}", join.request_id);
    println!("token_id={}", join.token_id);
    println!("status={}", join.status.as_str());
    println!("hostname={}", join.hostname);
    Ok(())
}

fn resolve_enrollment_token(
    token: Option<String>,
    token_file: Option<PathBuf>,
    token_stdin: bool,
) -> anyhow::Result<String> {
    let source_count =
        usize::from(token.is_some()) + usize::from(token_file.is_some()) + usize::from(token_stdin);
    if source_count != 1 {
        bail!(
            "provide exactly one enrollment token source: --token, --token-file, or --token-stdin"
        );
    }

    let raw = if let Some(token) = token {
        token
    } else if let Some(path) = token_file {
        std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read enrollment token file: {}", path.display()))?
    } else {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .context("failed to read enrollment token from stdin")?;
        text
    };
    let token = raw.trim_end_matches(['\r', '\n']).to_string();
    if token.is_empty() {
        bail!("enrollment token must not be empty");
    }
    Ok(token)
}

fn parse_ttl(value: &str) -> anyhow::Result<Duration> {
    let (number, unit) = value.split_at(value.len().saturating_sub(1));
    let amount: i64 = number
        .parse()
        .with_context(|| format!("invalid ttl value: {value}"))?;
    if amount <= 0 {
        bail!("--ttl must be greater than zero");
    }
    match unit {
        "s" => Ok(Duration::seconds(amount)),
        "m" => Ok(Duration::minutes(amount)),
        "h" => Ok(Duration::hours(amount)),
        "d" => Ok(Duration::days(amount)),
        _ => bail!("--ttl must use s, m, h, or d suffix"),
    }
}

fn duration_cutoff_rfc3339(value: &str, label: &str) -> anyhow::Result<String> {
    let seconds = parse_duration_seconds(value, label)?;
    let seconds = i64::try_from(seconds).with_context(|| format!("{label} is too large"))?;
    Ok((OffsetDateTime::now_utc() - Duration::seconds(seconds))
        .format(&Rfc3339)
        .expect("RFC3339 formatting succeeds"))
}

#[derive(Debug, Clone)]
struct TrustDiff {
    code: &'static str,
    severity: &'static str,
    endpoint_id: String,
    message: String,
}

fn run_trust_diff_command(
    store: &Store,
    endpoint_filter: Option<&str>,
    format: TrustDiffFormat,
    strict: bool,
) -> anyhow::Result<()> {
    let snapshot = store.trust_snapshot(endpoint_filter)?;
    let diffs = compute_trust_diffs(&snapshot.endpoints);
    match format {
        TrustDiffFormat::Human => {
            print_trust_diff_human(endpoint_filter, &snapshot.endpoints, &diffs)
        }
        TrustDiffFormat::Json => {
            print_trust_diff_json(endpoint_filter, &snapshot.endpoints, &diffs)?
        }
    }
    if strict && diffs.iter().any(|diff| diff.severity == "high") {
        std::process::exit(2);
    }
    Ok(())
}

fn compute_trust_diffs(endpoints: &[EndpointTrustRecord]) -> Vec<TrustDiff> {
    let mut diffs = Vec::new();
    for endpoint in endpoints {
        let bundle: Option<TrustBundle> =
            serde_json::from_value(endpoint.trust_bundle_json.clone()).ok();
        if matches!(endpoint.status, EndpointStatus::Revoked) {
            diffs.push(TrustDiff {
                code: "REVOKED_PEER_STILL_TRUSTED",
                severity: "high",
                endpoint_id: endpoint.endpoint_id.clone(),
                message: "revoked endpoint remains present in trust registry".to_string(),
            });
        }
        if matches!(endpoint.status, EndpointStatus::Quarantined) {
            diffs.push(TrustDiff {
                code: "QUARANTINED_PEER_STILL_ALLOWED",
                severity: "high",
                endpoint_id: endpoint.endpoint_id.clone(),
                message: "quarantined endpoint remains present in trust registry".to_string(),
            });
        }
        if let Some(bundle) = bundle {
            if bundle.generation < endpoint.generation {
                diffs.push(TrustDiff {
                    code: "TRUST_GENERATION_STALE",
                    severity: "high",
                    endpoint_id: endpoint.endpoint_id.clone(),
                    message: format!(
                        "agent trust generation {} is behind controller generation {}",
                        bundle.generation, endpoint.generation
                    ),
                });
            }
            for peer in &bundle.trusted_peers {
                if peer == &endpoint.endpoint_id && endpoint.status == EndpointStatus::Revoked {
                    diffs.push(TrustDiff {
                        code: "REVOKED_PEER_STILL_TRUSTED",
                        severity: "high",
                        endpoint_id: endpoint.endpoint_id.clone(),
                        message: format!("revoked endpoint {peer} is still trusted as a peer"),
                    });
                }
                if peer == &endpoint.endpoint_id && endpoint.status == EndpointStatus::Quarantined {
                    diffs.push(TrustDiff {
                        code: "QUARANTINED_PEER_STILL_ALLOWED",
                        severity: "high",
                        endpoint_id: endpoint.endpoint_id.clone(),
                        message: format!("quarantined endpoint {peer} is still trusted as a peer"),
                    });
                }
            }
        }
    }
    diffs
}

fn print_trust_diff_human(
    endpoint_filter: Option<&str>,
    endpoints: &[EndpointTrustRecord],
    diffs: &[TrustDiff],
) {
    println!("trust_diff=controller_registry");
    println!("endpoint_filter={}", endpoint_filter.unwrap_or("<all>"));
    println!("endpoint_count={}", endpoints.len());
    for endpoint in endpoints {
        println!(
            "endpoint_id={} status={} generation={} previous_endpoint_id={} rotated_to={}",
            endpoint.endpoint_id,
            endpoint.status.as_str(),
            endpoint.generation,
            endpoint.previous_endpoint_id.as_deref().unwrap_or("<none>"),
            endpoint.rotated_to.as_deref().unwrap_or("<none>")
        );
    }
    println!("diff_count={}", diffs.len());
    for diff in diffs {
        println!(
            "diff code={} severity={} endpoint_id={} message={}",
            diff.code, diff.severity, diff.endpoint_id, diff.message
        );
    }
}

fn print_trust_diff_json(
    endpoint_filter: Option<&str>,
    endpoints: &[EndpointTrustRecord],
    diffs: &[TrustDiff],
) -> anyhow::Result<()> {
    let registry = endpoints
        .iter()
        .map(|endpoint| {
            json!({
                "endpoint_id": endpoint.endpoint_id.clone(),
                "status": endpoint.status.as_str(),
                "generation": endpoint.generation,
                "previous_endpoint_id": endpoint.previous_endpoint_id.clone(),
                "rotated_to": endpoint.rotated_to.clone(),
                "agent_controllers": endpoint
                    .trust_bundle_json
                    .get("trusted_controllers")
                    .cloned()
                    .unwrap_or_else(|| json!([])),
                "agent_peers": endpoint
                    .trust_bundle_json
                    .get("trusted_peers")
                    .cloned()
                    .unwrap_or_else(|| json!([])),
                "agent_path_probes": endpoint
                    .trust_bundle_json
                    .get("authorized_path_probes")
                    .cloned()
                    .unwrap_or_else(|| json!([])),
            })
        })
        .collect::<Vec<_>>();
    let diffs = diffs
        .iter()
        .map(|diff| {
            json!({
                "code": diff.code,
                "severity": diff.severity,
                "endpoint_id": diff.endpoint_id,
                "message": diff.message,
            })
        })
        .collect::<Vec<_>>();
    let diff_count = diffs.len();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "endpoint_filter": endpoint_filter,
            "registry": registry,
            "diff_count": diff_count,
            "diffs": diffs,
        }))?
    );
    Ok(())
}

fn run_probe_history_command(
    store: &Store,
    node_filter: Option<&str>,
    limit: usize,
    since: Option<&str>,
    json_output: bool,
) -> anyhow::Result<()> {
    if let Some(node_id) = node_filter {
        validate_node_id(node_id)?;
    }
    let limit = validate_probe_history_limit(limit)?;
    let since_cutoff = since
        .map(|value| duration_cutoff_rfc3339(value, "--since"))
        .transpose()?;

    let observations =
        store.list_probe_observations_since(node_filter, since_cutoff.as_deref(), limit)?;
    let (source, record_count) = if observations.is_empty() {
        let records =
            store.list_probe_history_with_options(node_filter, since_cutoff.as_deref(), limit)?;
        let record_count = records.len();
        if json_output {
            print_probe_history_audit_json(node_filter, since, limit, &records)?;
        } else {
            print_probe_history_audit_human(node_filter, since, limit, &records);
        }
        ("controller_audit", record_count)
    } else {
        let record_count = observations.len();
        if json_output {
            print_probe_observations_json(node_filter, since, limit, &observations)?;
        } else {
            print_probe_observations_human(node_filter, since, limit, &observations);
        }
        ("probe_observations", record_count)
    };

    let mut event = AuditEvent::new(local_actor(), "probe.history");
    event.node_id = node_filter.map(ToOwned::to_owned);
    event.ok = Some(true);
    event.detail_json = json!({
        "node_filter": node_filter,
        "source": source,
        "record_count": record_count,
        "limit": limit,
        "since": since,
        "no_probe_executed": true,
        "health_score": false,
    });
    store.insert_audit(&event)?;
    Ok(())
}

fn validate_probe_history_limit(limit: usize) -> anyhow::Result<u64> {
    if limit == 0 {
        bail!("--limit must be greater than zero");
    }
    if limit > 1000 {
        bail!("--limit must be at most 1000");
    }
    Ok(limit as u64)
}

fn print_probe_observations_human(
    node_filter: Option<&str>,
    since: Option<&str>,
    limit: u64,
    records: &[ProbeObservationRecord],
) {
    println!("probe_history=probe_observations");
    println!("node_filter={}", node_filter.unwrap_or("<all>"));
    println!("since={}", since.unwrap_or("<none>"));
    println!("limit={limit}");
    println!("record_count={}", records.len());
    for record in records {
        println!(
            "record observed_at={} node_id={} method={} ok={} error_code={} duration_ms={} observation_id={} run_id={}",
            record.observed_at,
            record.node_id.as_deref().unwrap_or("<none>"),
            record.method,
            record
                .ok
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            record.error_code.as_deref().unwrap_or("<none>"),
            record
                .duration_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            record.observation_id,
            record.run_id.as_deref().unwrap_or("<none>"),
        );
    }
    println!("no_probe_executed=true");
    println!("health_score=false");
}

fn print_probe_history_audit_human(
    node_filter: Option<&str>,
    since: Option<&str>,
    limit: u64,
    records: &[ProbeHistoryRecord],
) {
    println!("probe_history=controller_audit");
    println!("node_filter={}", node_filter.unwrap_or("<all>"));
    println!("since={}", since.unwrap_or("<none>"));
    println!("limit={limit}");
    println!("record_count={}", records.len());
    for record in records {
        let peer_request_id = record
            .detail_json
            .get("peer_request_id")
            .and_then(Value::as_str);
        println!(
            "record ts={} node_id={} method={} ok={} error_code={} duration_ms={} request_id={} peer_request_id={}",
            record.ts,
            record.node_id.as_deref().unwrap_or("<none>"),
            record.method,
            record
                .ok
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            record.error_code.as_deref().unwrap_or("<none>"),
            record
                .duration_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            record.request_id.as_deref().unwrap_or("<none>"),
            peer_request_id.unwrap_or("<none>"),
        );
    }
    println!("no_probe_executed=true");
    println!("health_score=false");
}

fn print_probe_observations_json(
    node_filter: Option<&str>,
    since: Option<&str>,
    limit: u64,
    records: &[ProbeObservationRecord],
) -> anyhow::Result<()> {
    let records = records
        .iter()
        .map(|record| {
            json!({
                "observation_id": record.observation_id,
                "run_id": record.run_id,
                "node_id": record.node_id,
                "endpoint_id": record.endpoint_id,
                "method": record.method,
                "ok": record.ok,
                "error_code": record.error_code,
                "duration_ms": record.duration_ms,
                "observed_at": record.observed_at,
                "expires_at": record.expires_at,
                "result_class": record.result_class,
                "summary_json": record.summary_json,
            })
        })
        .collect::<Vec<_>>();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "source": "probe_observations",
            "node_filter": node_filter,
            "since": since,
            "limit": limit,
            "record_count": records.len(),
            "records": records,
        }))?
    );
    Ok(())
}

fn print_probe_history_audit_json(
    node_filter: Option<&str>,
    since: Option<&str>,
    limit: u64,
    records: &[ProbeHistoryRecord],
) -> anyhow::Result<()> {
    let records = records
        .iter()
        .map(|record| {
            json!({
                "ts": record.ts,
                "node_id": record.node_id,
                "endpoint_id": record.endpoint_id,
                "method": record.method,
                "request_id": record.request_id,
                "ok": record.ok,
                "error_code": record.error_code,
                "duration_ms": record.duration_ms,
                "peer_request_id": record.detail_json.get("peer_request_id").and_then(Value::as_str),
                "target_node_id": record.detail_json.get("target_node_id").and_then(Value::as_str),
                "target_endpoint_id": record.detail_json.get("target_endpoint_id").and_then(Value::as_str),
            })
        })
        .collect::<Vec<_>>();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "source": "controller_audit",
            "node_filter": node_filter,
            "since": since,
            "limit": limit,
            "record_count": records.len(),
            "records": records,
        }))?
    );
    Ok(())
}

fn run_probe_observe_command(
    store: &Store,
    source_node_id: &str,
    target_node_id: &str,
) -> anyhow::Result<()> {
    validate_node_id(source_node_id)?;
    validate_node_id(target_node_id)?;

    let source = store.get_node(source_node_id)?;
    let target = store.get_node(target_node_id)?;
    let source_status = summary_node_status(source.as_ref());
    let target_status = summary_node_status(target.as_ref());
    let source_endpoint_id = source.as_ref().map(|node| node.endpoint_id.as_str());
    let target_endpoint_id = target.as_ref().map(|node| node.endpoint_id.as_str());
    let records = store.list_probe_history(Some(source_node_id))?;
    let latest_match = records
        .iter()
        .find(|record| is_matching_path_observation(record, target_node_id, target_endpoint_id));

    println!("path_observation=audit_history");
    print_summary_node("source", source_node_id, source_status, source_endpoint_id);
    print_summary_node("target", target_node_id, target_status, target_endpoint_id);

    let mut detail_json = json!({
        "source_node_id": source_node_id,
        "source_endpoint_id": source_endpoint_id,
        "source_status": source_status,
        "target_node_id": target_node_id,
        "target_endpoint_id": target_endpoint_id,
        "target_status": target_status,
        "registry_authorizes_probe": false,
        "no_probe_executed": true,
        "no_route_discovery": true,
        "no_forwarding": true,
    });
    let detail = detail_json
        .as_object_mut()
        .expect("static JSON object must be an object");

    if let Some(record) = latest_match {
        let peer_request_id = record
            .detail_json
            .get("peer_request_id")
            .and_then(Value::as_str);
        println!("last_observation=found");
        println!(
            "root_request_id={}",
            record.request_id.as_deref().unwrap_or("<none>")
        );
        println!("peer_request_id={}", peer_request_id.unwrap_or("<none>"));
        println!(
            "ok={}",
            record
                .ok
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<none>".to_string())
        );
        println!(
            "error_code={}",
            record.error_code.as_deref().unwrap_or("<none>")
        );
        println!(
            "duration_ms={}",
            record
                .duration_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<none>".to_string())
        );
        detail.insert(
            "last_observation".to_string(),
            Value::String("found".to_string()),
        );
        if let Some(root_request_id) = &record.request_id {
            detail.insert(
                "root_request_id".to_string(),
                Value::String(root_request_id.clone()),
            );
        }
        if let Some(peer_request_id) = peer_request_id {
            detail.insert(
                "peer_request_id".to_string(),
                Value::String(peer_request_id.to_string()),
            );
        }
        if let Some(ok) = record.ok {
            detail.insert("ok".to_string(), Value::Bool(ok));
        }
        if let Some(error_code) = &record.error_code {
            detail.insert("error_code".to_string(), Value::String(error_code.clone()));
        }
        if let Some(duration_ms) = record.duration_ms {
            detail.insert("duration_ms".to_string(), json!(duration_ms));
        }
    } else {
        println!("last_observation=missing");
        detail.insert(
            "last_observation".to_string(),
            Value::String("missing".to_string()),
        );
    }

    println!("registry_authorizes_probe=false");
    println!("no_probe_executed=true");
    println!("no_route_discovery=true");
    println!("no_forwarding=true");

    let mut event = AuditEvent::new(local_actor(), "probe.observe");
    event.node_id = Some(source_node_id.to_string());
    event.endpoint_id = source.as_ref().map(|node| node.endpoint_id.clone());
    event.ok = Some(true);
    event.detail_json = detail_json;
    store.insert_audit(&event)?;
    Ok(())
}

fn is_matching_path_observation(
    record: &ProbeHistoryRecord,
    target_node_id: &str,
    target_endpoint_id: Option<&str>,
) -> bool {
    if record.method != PROBE_PATH_ECHO {
        return false;
    }
    let matches_node_id = record
        .detail_json
        .get("target_node_id")
        .and_then(Value::as_str)
        .is_some_and(|record_target_node_id| record_target_node_id == target_node_id);
    let matches_endpoint_id = target_endpoint_id.is_some_and(|target_endpoint_id| {
        record
            .detail_json
            .get("target_endpoint_id")
            .and_then(Value::as_str)
            .is_some_and(|record_target_endpoint_id| {
                record_target_endpoint_id == target_endpoint_id
            })
    });
    matches_node_id || matches_endpoint_id
}

#[derive(Debug, Default)]
struct TopologyGroupCounts {
    total: usize,
    enabled: usize,
    disabled: usize,
}

fn run_probe_topology_command(store: &Store) -> anyhow::Result<()> {
    let nodes = store.list_nodes()?;
    let enabled_node_count = nodes.iter().filter(|node| node.enabled).count();
    let disabled_node_count = nodes.len().saturating_sub(enabled_node_count);
    let registry_potential_pair_count =
        enabled_node_count.saturating_mul(enabled_node_count.saturating_sub(1));

    let mut groups: BTreeMap<(String, String), TopologyGroupCounts> = BTreeMap::new();
    for node in &nodes {
        let counts = groups
            .entry((node.region.clone(), node.role.clone()))
            .or_default();
        counts.total += 1;
        if node.enabled {
            counts.enabled += 1;
        } else {
            counts.disabled += 1;
        }
    }

    println!("topology_summary=registry_observation");
    println!(
        "registered_node_count={} enabled_node_count={} disabled_node_count={}",
        nodes.len(),
        enabled_node_count,
        disabled_node_count
    );
    for ((region, role), counts) in &groups {
        println!(
            "group region={region} role={role} total={} enabled={} disabled={}",
            counts.total, counts.enabled, counts.disabled
        );
    }
    for node in &nodes {
        println!(
            "node_id={} region={} role={} enabled={}",
            node.node_id, node.region, node.role, node.enabled
        );
    }
    println!("registry_potential_pair_count={registry_potential_pair_count}");
    println!("registry_authorizes_probe=false");
    println!("authoritative_authorization=security.path_probes+security.peers");
    println!("topology_discovery=false");
    println!("no_probe_executed=true");
    println!("no_config_generated=true");

    let group_details = groups
        .iter()
        .map(|((region, role), counts)| {
            json!({
                "region": region,
                "role": role,
                "total": counts.total,
                "enabled": counts.enabled,
                "disabled": counts.disabled,
            })
        })
        .collect::<Vec<_>>();
    let node_details = nodes
        .iter()
        .map(|node| {
            json!({
                "node_id": node.node_id,
                "region": node.region,
                "role": node.role,
                "enabled": node.enabled,
            })
        })
        .collect::<Vec<_>>();

    let mut event = AuditEvent::new(local_actor(), "probe.topology");
    event.ok = Some(true);
    event.detail_json = json!({
        "registered_node_count": nodes.len(),
        "enabled_node_count": enabled_node_count,
        "disabled_node_count": disabled_node_count,
        "registry_potential_pair_count": registry_potential_pair_count,
        "registry_authorizes_probe": false,
        "authoritative_authorization": "security.path_probes+security.peers",
        "topology_discovery": false,
        "no_probe_executed": true,
        "no_config_generated": true,
        "groups": group_details,
        "nodes": node_details,
    });
    store.insert_audit(&event)?;
    Ok(())
}

fn run_probe_summary_command(
    store: &Store,
    source_node_id: &str,
    target_node_id: &str,
) -> anyhow::Result<()> {
    validate_node_id(source_node_id)?;
    validate_node_id(target_node_id)?;

    let source = store.get_node(source_node_id)?;
    let target = store.get_node(target_node_id)?;
    let source_status = summary_node_status(source.as_ref());
    let target_status = summary_node_status(target.as_ref());
    let source_endpoint_id = source.as_ref().map(|node| node.endpoint_id.as_str());
    let target_endpoint_id = target.as_ref().map(|node| node.endpoint_id.as_str());

    println!("probe_summary=path_observation");
    print_summary_node("source", source_node_id, source_status, source_endpoint_id);
    print_summary_node("target", target_node_id, target_status, target_endpoint_id);
    println!("registry_authorizes_probe=false");
    println!("required_source_authorization=security.path_probes");
    println!("required_target_authorization=security.peers");
    println!("supported_commands=probe ping,probe path");
    println!("no_probe_executed=true");

    let mut event = AuditEvent::new(local_actor(), "probe.summary");
    event.node_id = Some(source_node_id.to_string());
    event.endpoint_id = source.as_ref().map(|node| node.endpoint_id.clone());
    event.ok = Some(true);
    event.detail_json = json!({
        "source_node_id": source_node_id,
        "source_endpoint_id": source_endpoint_id,
        "source_status": source_status,
        "target_node_id": target_node_id,
        "target_endpoint_id": target_endpoint_id,
        "target_status": target_status,
        "registry_authorizes_probe": false,
        "required_source_authorization": "security.path_probes",
        "required_target_authorization": "security.peers",
        "supported_commands": ["probe ping", "probe path"],
        "no_probe_executed": true,
    });
    store.insert_audit(&event)?;
    Ok(())
}

fn summary_node_status(node: Option<&NodeRecord>) -> &'static str {
    match node {
        Some(node) if node.enabled => "enabled",
        Some(_) => "disabled",
        None => "missing",
    }
}

fn print_summary_node(role: &str, node_id: &str, status: &str, endpoint_id: Option<&str>) {
    match endpoint_id {
        Some(endpoint_id) => {
            println!(
                "{role}_node_id={node_id} {role}_status={status} {role}_endpoint_id={endpoint_id}"
            );
        }
        None => {
            println!(
                "{role}_node_id={node_id} {role}_status={status} {role}_endpoint_id=<missing>"
            );
        }
    }
}

async fn run_path_probe_command(
    store: &Store,
    secret_key_path: &Path,
    source_node_id: &str,
    target_node_id: &str,
) -> anyhow::Result<()> {
    validate_node_id(source_node_id)?;
    validate_node_id(target_node_id)?;
    let actor = local_actor();
    let started = Instant::now();
    let source = match store.get_node(source_node_id)? {
        Some(node) => node,
        None => {
            let message = format!("node not found: {source_node_id}");
            write_rpc_audit(
                store,
                RpcAuditRecord {
                    actor,
                    node_id: source_node_id.to_string(),
                    endpoint_id: None,
                    method: PROBE_PATH_ECHO.to_string(),
                    request_id: None,
                    params_hash: hash_json_value(&json!({})),
                    ok: false,
                    error_code: Some(ErrorCode::NodeNotFound),
                    duration_ms: elapsed_ms(started),
                    detail_json: json!({"message": message, "source_node_id": source_node_id, "target_node_id": target_node_id}),
                },
            )?;
            bail!(message);
        }
    };
    if !source.enabled {
        let message = format!("node disabled: {source_node_id}");
        write_rpc_audit(
            store,
            RpcAuditRecord {
                actor,
                node_id: source.node_id.clone(),
                endpoint_id: Some(source.endpoint_id.clone()),
                method: PROBE_PATH_ECHO.to_string(),
                request_id: None,
                params_hash: hash_json_value(&json!({})),
                ok: false,
                error_code: Some(ErrorCode::NodeDisabled),
                duration_ms: elapsed_ms(started),
                detail_json: json!({"message": message, "source_node_id": source_node_id, "target_node_id": target_node_id}),
            },
        )?;
        bail!(message);
    }
    if let Some(status) = inactive_endpoint_status(store, &source.endpoint_id)? {
        let message = format!(
            "endpoint not active: node_id={} endpoint_id={} status={}",
            source.node_id,
            source.endpoint_id,
            status.as_str()
        );
        write_rpc_audit(
            store,
            RpcAuditRecord {
                actor,
                node_id: source.node_id.clone(),
                endpoint_id: Some(source.endpoint_id.clone()),
                method: PROBE_PATH_ECHO.to_string(),
                request_id: None,
                params_hash: hash_json_value(&json!({})),
                ok: false,
                error_code: Some(ErrorCode::EndpointNotAllowed),
                duration_ms: elapsed_ms(started),
                detail_json: json!({"message": message, "source_node_id": source_node_id, "target_node_id": target_node_id, "endpoint_status": status.as_str()}),
            },
        )?;
        bail!(message);
    }
    let target = match store.get_node(target_node_id)? {
        Some(node) => node,
        None => {
            let message = format!("node not found: {target_node_id}");
            write_rpc_audit(
                store,
                RpcAuditRecord {
                    actor,
                    node_id: source.node_id.clone(),
                    endpoint_id: Some(source.endpoint_id.clone()),
                    method: PROBE_PATH_ECHO.to_string(),
                    request_id: None,
                    params_hash: hash_json_value(&json!({})),
                    ok: false,
                    error_code: Some(ErrorCode::NodeNotFound),
                    duration_ms: elapsed_ms(started),
                    detail_json: json!({"message": message, "source_node_id": source_node_id, "target_node_id": target_node_id}),
                },
            )?;
            bail!(message);
        }
    };
    if !target.enabled {
        let message = format!("node disabled: {target_node_id}");
        write_rpc_audit(
            store,
            RpcAuditRecord {
                actor,
                node_id: source.node_id.clone(),
                endpoint_id: Some(source.endpoint_id.clone()),
                method: PROBE_PATH_ECHO.to_string(),
                request_id: None,
                params_hash: hash_json_value(&json!({})),
                ok: false,
                error_code: Some(ErrorCode::NodeDisabled),
                duration_ms: elapsed_ms(started),
                detail_json: json!({"message": message, "source_node_id": source_node_id, "target_node_id": target_node_id}),
            },
        )?;
        bail!(message);
    }
    if let Some(status) = inactive_endpoint_status(store, &target.endpoint_id)? {
        let message = format!(
            "endpoint not active: node_id={} endpoint_id={} status={}",
            target.node_id,
            target.endpoint_id,
            status.as_str()
        );
        write_rpc_audit(
            store,
            RpcAuditRecord {
                actor,
                node_id: source.node_id.clone(),
                endpoint_id: Some(source.endpoint_id.clone()),
                method: PROBE_PATH_ECHO.to_string(),
                request_id: None,
                params_hash: hash_json_value(&json!({})),
                ok: false,
                error_code: Some(ErrorCode::EndpointNotAllowed),
                duration_ms: elapsed_ms(started),
                detail_json: json!({"message": message, "source_node_id": source_node_id, "target_node_id": target_node_id, "target_endpoint_status": status.as_str()}),
            },
        )?;
        bail!(message);
    }

    let rpc = FixedControllerRpc::ProbePathEcho {
        target_agent_endpoint_id: target.endpoint_id.clone(),
    };
    let params = rpc.params();
    let params_hash = hash_json_value(&params);
    match execute_fixed_node_rpc(secret_key_path, &source, rpc).await {
        Ok(success) => {
            let mut summary = low_sensitive_fixed_rpc_summary(PROBE_PATH_ECHO, &success.result)?;
            let path_ok = summary.get("ok").and_then(Value::as_bool).unwrap_or(true);
            let path_error_code = if path_ok {
                None
            } else {
                summary
                    .get("target_error_code")
                    .and_then(Value::as_str)
                    .and_then(error_code_from_name)
            };
            if let Some(summary) = summary.as_object_mut() {
                summary.insert(
                    "source_node_id".to_string(),
                    Value::String(source.node_id.clone()),
                );
                summary.insert(
                    "target_node_id".to_string(),
                    Value::String(target.node_id.clone()),
                );
            }
            write_rpc_audit(
                store,
                RpcAuditRecord {
                    actor,
                    node_id: source.node_id.clone(),
                    endpoint_id: Some(source.endpoint_id.clone()),
                    method: PROBE_PATH_ECHO.to_string(),
                    request_id: Some(success.request_id.clone()),
                    params_hash,
                    ok: path_ok,
                    error_code: path_error_code,
                    duration_ms: elapsed_ms(started),
                    detail_json: summary,
                },
            )?;
            print_rpc_result(PROBE_PATH_ECHO, &success.result);
            Ok(())
        }
        Err(failure) => {
            write_rpc_audit(
                store,
                RpcAuditRecord {
                    actor,
                    node_id: source.node_id.clone(),
                    endpoint_id: Some(source.endpoint_id.clone()),
                    method: PROBE_PATH_ECHO.to_string(),
                    request_id: failure.request_id.clone(),
                    params_hash,
                    ok: false,
                    error_code: Some(failure.code),
                    duration_ms: elapsed_ms(started),
                    detail_json: failure.detail_json.clone(),
                },
            )?;
            bail!(failure.message);
        }
    }
}

async fn run_node_rpc_command(
    store: &Store,
    secret_key_path: &Path,
    node_id: &str,
    method: &str,
) -> anyhow::Result<()> {
    validate_node_id(node_id)?;
    let actor = local_actor();
    let started = Instant::now();
    let rpc = FixedControllerRpc::from_method_without_params(method)
        .with_context(|| format!("unsupported fixed RPC method: {method}"))?;
    let params = rpc.params();
    let params_hash = hash_json_value(&params);
    let node = match store.get_node(node_id)? {
        Some(node) => node,
        None => {
            let message = format!("node not found: {node_id}");
            write_rpc_audit(
                store,
                RpcAuditRecord {
                    actor,
                    node_id: node_id.to_string(),
                    endpoint_id: None,
                    method: method.to_string(),
                    request_id: None,
                    params_hash,
                    ok: false,
                    error_code: Some(ErrorCode::NodeNotFound),
                    duration_ms: elapsed_ms(started),
                    detail_json: json!({ "message": message }),
                },
            )?;
            bail!(message);
        }
    };
    if !node.enabled {
        let message = format!("node disabled: {node_id}");
        write_rpc_audit(
            store,
            RpcAuditRecord {
                actor,
                node_id: node.node_id.clone(),
                endpoint_id: Some(node.endpoint_id.clone()),
                method: method.to_string(),
                request_id: None,
                params_hash,
                ok: false,
                error_code: Some(ErrorCode::NodeDisabled),
                duration_ms: elapsed_ms(started),
                detail_json: json!({ "message": message }),
            },
        )?;
        bail!(message);
    }
    if let Some(status) = inactive_endpoint_status(store, &node.endpoint_id)? {
        let message = format!(
            "endpoint not active: node_id={} endpoint_id={} status={}",
            node.node_id,
            node.endpoint_id,
            status.as_str()
        );
        write_rpc_audit(
            store,
            RpcAuditRecord {
                actor,
                node_id: node.node_id.clone(),
                endpoint_id: Some(node.endpoint_id.clone()),
                method: method.to_string(),
                request_id: None,
                params_hash,
                ok: false,
                error_code: Some(ErrorCode::EndpointNotAllowed),
                duration_ms: elapsed_ms(started),
                detail_json: json!({ "message": message, "endpoint_status": status.as_str() }),
            },
        )?;
        bail!(message);
    }

    match execute_fixed_node_rpc(secret_key_path, &node, rpc).await {
        Ok(success) => {
            let summary = low_sensitive_fixed_rpc_summary(method, &success.result)?;
            write_rpc_audit(
                store,
                RpcAuditRecord {
                    actor,
                    node_id: node.node_id.clone(),
                    endpoint_id: Some(node.endpoint_id.clone()),
                    method: method.to_string(),
                    request_id: Some(success.request_id.clone()),
                    params_hash,
                    ok: true,
                    error_code: None,
                    duration_ms: elapsed_ms(started),
                    detail_json: summary,
                },
            )?;
            print_rpc_result(method, &success.result);
            Ok(())
        }
        Err(failure) => {
            write_rpc_audit(
                store,
                RpcAuditRecord {
                    actor,
                    node_id: node.node_id.clone(),
                    endpoint_id: Some(node.endpoint_id.clone()),
                    method: method.to_string(),
                    request_id: failure.request_id.clone(),
                    params_hash,
                    ok: false,
                    error_code: Some(failure.code),
                    duration_ms: elapsed_ms(started),
                    detail_json: failure.detail_json.clone(),
                },
            )?;
            bail!(failure.message);
        }
    }
}

async fn run_ocserv_status_command(
    store: &Store,
    secret_key_path: &Path,
    node_id: &str,
    json_output: bool,
) -> anyhow::Result<()> {
    let actor = local_actor();
    let started = Instant::now();
    let node = match load_ocserv_rpc_node(store, node_id) {
        Ok(node) => node,
        Err(failure) => {
            write_ocserv_command_audit(
                store,
                OcservCommandAudit {
                    actor,
                    event: "ocserv.status",
                    node_id: node_id.to_string(),
                    endpoint_id: known_endpoint_id(store, node_id),
                    method: OCSERV_SERVICE_SUMMARY,
                    ok: false,
                    error_code: Some(failure.code),
                    duration_ms: elapsed_ms(started),
                    detail_json: low_sensitive_detail(&failure.message),
                },
            )?;
            bail!(failure.message);
        }
    };

    let service = execute_optional_ocserv_rpc::<OcservServiceSummaryResponse>(
        store,
        secret_key_path,
        &node,
        OCSERV_SERVICE_SUMMARY,
    )
    .await;
    let version = execute_optional_ocserv_rpc::<OcservVersionResponse>(
        store,
        secret_key_path,
        &node,
        OCSERV_VERSION,
    )
    .await;
    let sessions = execute_optional_ocserv_rpc::<OcservSessionsSummaryResponse>(
        store,
        secret_key_path,
        &node,
        OCSERV_SESSIONS_SUMMARY,
    )
    .await;
    let fingerprint = execute_optional_ocserv_rpc::<OcservConfigFingerprintResponse>(
        store,
        secret_key_path,
        &node,
        OCSERV_CONFIG_FINGERPRINT,
    )
    .await;

    let outcomes = [
        service.error_code(),
        version.error_code(),
        sessions.error_code(),
        fingerprint.error_code(),
    ];
    if outcomes.iter().all(Option::is_some) {
        let code = outcomes
            .iter()
            .flatten()
            .next()
            .cloned()
            .unwrap_or(ErrorCode::InternalError);
        write_ocserv_command_audit(
            store,
            OcservCommandAudit {
                actor,
                event: "ocserv.status",
                node_id: node.node_id.clone(),
                endpoint_id: Some(node.endpoint_id.clone()),
                method: OCSERV_SERVICE_SUMMARY,
                ok: false,
                error_code: Some(code),
                duration_ms: elapsed_ms(started),
                detail_json: json!({
                    "result_class": "low_sensitive_summary",
                    "status": "failed",
                    "rpc_methods": [
                        OCSERV_SERVICE_SUMMARY,
                        OCSERV_VERSION,
                        OCSERV_SESSIONS_SUMMARY,
                        OCSERV_CONFIG_FINGERPRINT
                    ],
                    "degraded_methods": [
                        OCSERV_SERVICE_SUMMARY,
                        OCSERV_VERSION,
                        OCSERV_SESSIONS_SUMMARY,
                        OCSERV_CONFIG_FINGERPRINT
                    ],
                }),
            },
        )?;
        return Err(anyhow::anyhow!("ocserv status failed"));
    }

    let degraded_methods = [
        service.unavailable_method(),
        version.unavailable_method(),
        sessions.unavailable_method(),
        fingerprint.unavailable_method(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();

    let view = OcservStatusView {
        node_id: node.node_id.clone(),
        service: service
            .as_available()
            .map(|response| response.service.clone()),
        version: version
            .as_available()
            .and_then(|response| response.version.clone()),
        version_status: version
            .as_available()
            .map(|response| response.status)
            .unwrap_or(ocfleet_protocol::ocserv::OcservFieldStatus::Unavailable),
        sessions_total: sessions
            .as_available()
            .and_then(|response| response.sessions.total),
        sessions_status: sessions
            .as_available()
            .map(|response| response.sessions.status)
            .unwrap_or(ocfleet_protocol::ocserv::OcservFieldStatus::Unavailable),
        config_algorithm: fingerprint
            .as_available()
            .map(|response| response.fingerprint.algorithm.clone()),
        config_hash: fingerprint
            .as_available()
            .and_then(|response| response.fingerprint.hash.clone()),
        config_status: fingerprint
            .as_available()
            .map(|response| response.fingerprint.status)
            .unwrap_or(ocfleet_protocol::ocserv::OcservFieldStatus::Unavailable),
        degraded_methods: degraded_methods.clone(),
    };

    let output = if json_output {
        format_status_json(&view)?
    } else {
        format_status_view_human(&view)?
    };
    assert_low_sensitive_ocserv_output(&output)?;
    print!("{output}");
    write_ocserv_command_audit(
        store,
        OcservCommandAudit {
            actor,
            event: "ocserv.status",
            node_id: node.node_id.clone(),
            endpoint_id: Some(node.endpoint_id.clone()),
            method: OCSERV_SERVICE_SUMMARY,
            ok: true,
            error_code: None,
            duration_ms: elapsed_ms(started),
            detail_json: json!({
                "node_id": node.node_id,
                "endpoint_id": node.endpoint_id,
                "result_class": "low_sensitive_summary",
                "status": if degraded_methods.is_empty() { "ok" } else { "degraded" },
                "rpc_methods": [
                    OCSERV_SERVICE_SUMMARY,
                    OCSERV_VERSION,
                    OCSERV_SESSIONS_SUMMARY,
                    OCSERV_CONFIG_FINGERPRINT
                ],
                "degraded_methods": degraded_methods,
            }),
        },
    )?;
    Ok(())
}

async fn run_ocserv_cert_command(
    store: &Store,
    secret_key_path: &Path,
    node_id: &str,
    json_output: bool,
) -> anyhow::Result<()> {
    let actor = local_actor();
    let started = Instant::now();
    let node = match load_ocserv_rpc_node(store, node_id) {
        Ok(node) => node,
        Err(failure) => {
            write_ocserv_command_audit(
                store,
                OcservCommandAudit {
                    actor,
                    event: "ocserv.cert",
                    node_id: node_id.to_string(),
                    endpoint_id: known_endpoint_id(store, node_id),
                    method: OCSERV_CERT_EXPIRY,
                    ok: false,
                    error_code: Some(failure.code),
                    duration_ms: elapsed_ms(started),
                    detail_json: low_sensitive_detail(&failure.message),
                },
            )?;
            bail!(failure.message);
        }
    };
    let response = match execute_ocserv_rpc::<OcservCertExpiryResponse>(
        store,
        secret_key_path,
        &node,
        OCSERV_CERT_EXPIRY,
    )
    .await
    {
        Ok(value) => value,
        Err(failure) => {
            write_ocserv_command_failure(
                store,
                "ocserv.cert",
                &node,
                OCSERV_CERT_EXPIRY,
                failure,
                started,
            )?;
            return Err(anyhow::anyhow!("ocserv cert failed"));
        }
    };
    let output = if json_output {
        format_cert_json(&node.node_id, &response)?
    } else {
        format_cert_human(&node.node_id, &response)?
    };
    assert_low_sensitive_ocserv_output(&output)?;
    print!("{output}");
    write_ocserv_command_audit(
        store,
        OcservCommandAudit {
            actor,
            event: "ocserv.cert",
            node_id: node.node_id.clone(),
            endpoint_id: Some(node.endpoint_id.clone()),
            method: OCSERV_CERT_EXPIRY,
            ok: true,
            error_code: None,
            duration_ms: elapsed_ms(started),
            detail_json: json!({
                "node_id": node.node_id,
                "endpoint_id": node.endpoint_id,
                "result_class": "low_sensitive_summary",
                "cert_count": response.certs.len(),
            }),
        },
    )?;
    Ok(())
}

async fn run_ocserv_sessions_summary_command(
    store: &Store,
    secret_key_path: &Path,
    node_id: &str,
    json_output: bool,
) -> anyhow::Result<()> {
    let actor = local_actor();
    let started = Instant::now();
    let node = match load_ocserv_rpc_node(store, node_id) {
        Ok(node) => node,
        Err(failure) => {
            write_ocserv_command_audit(
                store,
                OcservCommandAudit {
                    actor,
                    event: "ocserv.sessions.summary",
                    node_id: node_id.to_string(),
                    endpoint_id: known_endpoint_id(store, node_id),
                    method: OCSERV_SESSIONS_SUMMARY,
                    ok: false,
                    error_code: Some(failure.code),
                    duration_ms: elapsed_ms(started),
                    detail_json: low_sensitive_detail(&failure.message),
                },
            )?;
            bail!(failure.message);
        }
    };
    let response = match execute_ocserv_rpc::<OcservSessionsSummaryResponse>(
        store,
        secret_key_path,
        &node,
        OCSERV_SESSIONS_SUMMARY,
    )
    .await
    {
        Ok(value) => value,
        Err(failure) => {
            write_ocserv_command_failure(
                store,
                "ocserv.sessions.summary",
                &node,
                OCSERV_SESSIONS_SUMMARY,
                failure,
                started,
            )?;
            return Err(anyhow::anyhow!("ocserv sessions summary failed"));
        }
    };
    let output = if json_output {
        serde_json::to_string_pretty(&json!({
            "node_id": node.node_id,
            "sessions": response.sessions,
        }))? + "\n"
    } else {
        format_sessions_human(&node.node_id, &response)?
    };
    assert_low_sensitive_ocserv_output(&output)?;
    print!("{output}");
    write_ocserv_command_audit(
        store,
        OcservCommandAudit {
            actor,
            event: "ocserv.sessions.summary",
            node_id: node.node_id.clone(),
            endpoint_id: Some(node.endpoint_id.clone()),
            method: OCSERV_SESSIONS_SUMMARY,
            ok: true,
            error_code: None,
            duration_ms: elapsed_ms(started),
            detail_json: json!({
                "node_id": node.node_id,
                "endpoint_id": node.endpoint_id,
                "result_class": "low_sensitive_summary",
            }),
        },
    )?;
    Ok(())
}

fn write_ocserv_command_failure(
    store: &Store,
    event: &'static str,
    node: &NodeRecord,
    method: &'static str,
    failure: RpcCommandFailure,
    started: Instant,
) -> anyhow::Result<()> {
    let message = failure.message.clone();
    write_ocserv_command_audit(
        store,
        OcservCommandAudit {
            actor: local_actor(),
            event,
            node_id: node.node_id.clone(),
            endpoint_id: Some(node.endpoint_id.clone()),
            method,
            ok: false,
            error_code: Some(failure.code.clone()),
            duration_ms: elapsed_ms(started),
            detail_json: ocserv_failure_detail(&failure),
        },
    )?;
    bail!(message)
}

fn print_rpc_result(method: &str, result: &Value) {
    match method {
        NODE_PING => println!(
            "message={} node_id={} agent_version={} time_utc={}",
            result
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("pong"),
            result
                .get("node_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            result
                .get("agent_version")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            result
                .get("time_utc")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        ),
        PROBE_CONTROLLER_PING => println!(
            "message={} node_id={} probe={} agent_version={} time_utc={}",
            result
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("pong"),
            result
                .get("node_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            result
                .get("probe")
                .and_then(Value::as_str)
                .unwrap_or("controller.ping"),
            result
                .get("agent_version")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            result
                .get("time_utc")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        ),
        PROBE_PATH_ECHO => println!(
            "probe={} ok={} source_agent_endpoint_id={} target_agent_endpoint_id={} root_request_id={} peer_request_id={}",
            result
                .get("probe")
                .and_then(Value::as_str)
                .unwrap_or("path.echo"),
            result.get("ok").and_then(Value::as_bool).unwrap_or(false),
            result
                .get("source_agent_endpoint_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            result
                .get("target_agent_endpoint_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            result
                .get("root_request_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            result
                .get("peer_request_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        ),
        NODE_INFO => {
            for field in [
                "node_id",
                "region",
                "role",
                "agent_version",
                "current_time_utc",
                "agent_endpoint_id",
            ] {
                if let Some(value) = result.get(field) {
                    println!("{field}={value}");
                }
            }
        }
        _ => {}
    }
}
