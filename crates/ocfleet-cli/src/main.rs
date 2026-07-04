use anyhow::{Context, bail};
use clap::Parser;
use ocfleet_cli::args::{Cli, Command, NodeCommand};
use ocfleet_cli::audit::AuditEvent;
use ocfleet_cli::identity::load_or_create_secret_key_with_status;
use ocfleet_cli::store::{NodeInsert, Store};
use ocfleet_config::validation::{
    validate_controller_endpoint_id, validate_node_id, validate_region, validate_role,
};

fn local_actor() -> String {
    match std::env::var("USER") {
        Ok(actor) if !actor.trim().is_empty() => actor,
        _ => "local-cli".to_string(),
    }
}

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
        Command::Node { command } => {
            let store = Store::open(&cli.database).context("failed to open controller database")?;
            match command {
                NodeCommand::Add {
                    node_id,
                    endpoint_id,
                    region,
                    role,
                } => {
                    validate_node_id(&node_id)?;
                    validate_controller_endpoint_id(&endpoint_id)?;
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
    }

    Ok(())
}
