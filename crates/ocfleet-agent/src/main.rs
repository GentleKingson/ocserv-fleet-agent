use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use clap::Parser;
use ocfleet_agent::audit::JsonlAuditWriter;
use ocfleet_agent::audit_limiter::RejectedAuditLimiter;
use ocfleet_agent::authz::AgentAuthorization;
use ocfleet_agent::identity::load_or_create_secret_key;
use ocfleet_agent::metrics_http::{
    AgentMetricsHttpState, serve_metrics, validate_metrics_listener,
};
use ocfleet_agent::nonce::NonceCache;
use ocfleet_agent::server::{
    AgentServerState, PathTargetResolver, ServerLimiters, bind_agent_endpoint, serve_endpoint,
};
use ocfleet_config::agent::load_agent_config;

#[derive(Debug, Parser)]
#[command(name = "ocfleet-agent")]
#[command(version)]
#[command(about = "Read-only ocserv fleet node agent")]
struct AgentCli {
    #[arg(long, default_value = "/etc/ocfleet-agent/config.toml")]
    config: PathBuf,
    #[arg(long, default_value = "127.0.0.1:9090")]
    metrics_listen: SocketAddr,
    #[arg(long, value_name = "PATH")]
    metrics_auth_token_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = AgentCli::parse();
    tracing_subscriber::fmt::init();

    let config = load_agent_config(&args.config).context("failed to load agent config")?;
    validate_metrics_listener(args.metrics_listen, args.metrics_auth_token_file.as_deref())?;
    let secret_key = load_or_create_secret_key(&config.iroh.secret_key_path, true)
        .context("failed to load or create agent SecretKey")?;
    let audit = JsonlAuditWriter::with_durability(
        config.audit.path.clone(),
        config.audit.audit_queue_capacity,
        config
            .audit
            .spool_path
            .clone()
            .unwrap_or_else(|| JsonlAuditWriter::default_spool_path(&config.audit.path)),
        config
            .audit
            .metrics_path
            .clone()
            .or(Some(JsonlAuditWriter::default_metrics_path(
                &config.audit.path,
            ))),
        config.audit.spool_max_events,
    );
    let audit_limiter = Arc::new(Mutex::new(RejectedAuditLimiter::new(&config.audit)));
    let limiters = Arc::new(ServerLimiters::from_config(&config.security));
    let endpoint = bind_agent_endpoint(
        &config,
        secret_key,
        audit.clone(),
        audit_limiter.clone(),
        limiters.metrics(),
    )
    .await?;
    let endpoint_id = endpoint.id().to_string();
    let authz = Arc::new(AgentAuthorization::from_security_config(&config.security)?);
    let nonce_cache = Arc::new(Mutex::new(NonceCache::with_limits(
        config.security.max_live_nonces_global,
        config.security.max_live_nonces_per_controller,
    )));
    let metrics_state = AgentMetricsHttpState::new(
        limiters.metrics(),
        audit.clone(),
        nonce_cache.clone(),
        args.metrics_auth_token_file.as_deref(),
    )?;
    let metrics_listener = tokio::net::TcpListener::bind(args.metrics_listen)
        .await
        .context("failed to bind agent metrics listener")?;
    let state = AgentServerState {
        config: config.clone(),
        audit,
        nonce_cache,
        limiters,
        audit_limiter,
        authz,
        agent_endpoint_id: endpoint_id.clone(),
        outbound_endpoint: Some(endpoint.clone()),
        path_target_resolver: PathTargetResolver::endpoint_id_only(),
    };

    println!("agent_endpoint_id={endpoint_id}");
    println!("metrics_listen={}", args.metrics_listen);
    println!(
        "join_command=ocfleet node add {} --endpoint-id {} --region {} --role {}",
        config.node.id, endpoint_id, config.node.region, config.node.role
    );

    tokio::try_join!(
        serve_endpoint(endpoint, state),
        serve_metrics(metrics_listener, metrics_state)
    )?;
    Ok(())
}
