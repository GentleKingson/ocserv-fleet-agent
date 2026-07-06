use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use clap::Parser;
use ocfleet_agent::audit::JsonlAuditWriter;
use ocfleet_agent::audit_limiter::RejectedAuditLimiter;
use ocfleet_agent::authz::AgentAuthorization;
use ocfleet_agent::identity::load_or_create_secret_key;
use ocfleet_agent::nonce::NonceCache;
use ocfleet_agent::server::{
    AgentServerState, PathTargetResolver, ServerLimiters, bind_agent_endpoint, serve_endpoint,
};
use ocfleet_config::agent::load_agent_config;

#[derive(Debug, Parser)]
#[command(name = "ocfleet-agent")]
#[command(about = "Read-only ocserv fleet node agent")]
struct AgentCli {
    #[arg(long, default_value = "/etc/ocfleet-agent/config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = AgentCli::parse();
    tracing_subscriber::fmt::init();

    let config = load_agent_config(&args.config).context("failed to load agent config")?;
    let secret_key = load_or_create_secret_key(&config.iroh.secret_key_path, true)
        .context("failed to load or create agent SecretKey")?;
    let audit = JsonlAuditWriter::with_queue_capacity(
        config.audit.path.clone(),
        config.audit.audit_queue_capacity,
    );
    let audit_limiter = Arc::new(Mutex::new(RejectedAuditLimiter::new(&config.audit)));
    let endpoint =
        bind_agent_endpoint(&config, secret_key, audit.clone(), audit_limiter.clone()).await?;
    let endpoint_id = endpoint.id().to_string();
    let authz = Arc::new(AgentAuthorization::from_security_config(&config.security)?);
    let state = AgentServerState {
        config: config.clone(),
        audit,
        nonce_cache: Arc::new(Mutex::new(NonceCache::with_limits(
            config.security.max_live_nonces_global,
            config.security.max_live_nonces_per_controller,
        ))),
        limiters: Arc::new(ServerLimiters::from_config(&config.security)),
        audit_limiter,
        authz,
        agent_endpoint_id: endpoint_id.clone(),
        outbound_endpoint: Some(endpoint.clone()),
        path_target_resolver: PathTargetResolver::endpoint_id_only(),
    };

    println!("agent_endpoint_id={endpoint_id}");
    println!(
        "join_command=ocfleet node add {} --endpoint-id {} --region {} --role {}",
        config.node.id, endpoint_id, config.node.region, config.node.role
    );

    serve_endpoint(endpoint, state).await
}
