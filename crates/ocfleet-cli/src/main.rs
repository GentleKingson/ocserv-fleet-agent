use anyhow::{Context, bail};
use clap::Parser;
use iroh::{EndpointAddr, EndpointId};
use ocfleet_cli::args::{Cli, Command, NodeCommand};
use ocfleet_cli::audit::AuditEvent;
use ocfleet_cli::identity::{load_or_create_secret_key_with_status, load_secret_key};
use ocfleet_cli::rpc_client::{
    bind_controller_endpoint, build_request, call_endpoint_addr, validate_rpc_response,
};
use ocfleet_cli::store::{NodeInsert, NodeRecord, Store};
use ocfleet_config::validation::{
    validate_controller_endpoint_id, validate_node_id, validate_region, validate_role,
};
use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::method::{NODE_INFO, NODE_PING};
use ocfleet_protocol::{DEFAULT_ALPN, DEFAULT_DEADLINE_MS, RpcResponse};
use serde_json::{Value, json};
use std::path::Path;
use std::str::FromStr;
use std::time::Instant;

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
        Command::Ping { node_id } => {
            let store = Store::open(&cli.database).context("failed to open controller database")?;
            run_node_rpc_command(&store, &cli.secret_key, &node_id, NODE_PING).await?;
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

async fn run_node_rpc_command(
    store: &Store,
    secret_key_path: &Path,
    node_id: &str,
    method: &str,
) -> anyhow::Result<()> {
    validate_node_id(node_id)?;
    let actor = local_actor();
    let started = Instant::now();
    let params = json!({});
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

    match execute_node_rpc(secret_key_path, &node, method, params).await {
        Ok(success) => {
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
                    detail_json: json!({ "result": success.result }),
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

struct RpcCommandSuccess {
    request_id: String,
    result: Value,
}

struct RpcCommandFailure {
    code: ErrorCode,
    message: String,
    request_id: Option<String>,
    detail_json: Value,
}

impl RpcCommandFailure {
    fn new(
        code: ErrorCode,
        message: impl Into<String>,
        request_id: Option<String>,
        detail_json: Value,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            request_id,
            detail_json,
        }
    }
}

async fn execute_node_rpc(
    secret_key_path: &Path,
    node: &NodeRecord,
    method: &str,
    params: Value,
) -> Result<RpcCommandSuccess, RpcCommandFailure> {
    let secret_key = load_secret_key(secret_key_path, false).map_err(|err| {
        RpcCommandFailure::new(
            ErrorCode::SecretKeyLoadFailed,
            format!("failed to load controller SecretKey: {err}"),
            None,
            json!({ "error": err.to_string() }),
        )
    })?;
    let endpoint = bind_controller_endpoint(secret_key).await.map_err(|err| {
        RpcCommandFailure::new(
            err.code(),
            err.to_string(),
            None,
            json!({ "error": err.to_string() }),
        )
    })?;
    let expected_endpoint_id = EndpointId::from_str(&node.endpoint_id).map_err(|err| {
        RpcCommandFailure::new(
            ErrorCode::ConnectFailed,
            format!("invalid node endpoint_id: {err}"),
            None,
            json!({ "endpoint_id": node.endpoint_id, "error": err.to_string() }),
        )
    })?;
    let request = build_request(
        method,
        params,
        Some(local_actor()),
        DEFAULT_DEADLINE_MS,
    );
    let request_id = request.request_id.clone();
    let response = call_endpoint_addr(
        &endpoint,
        EndpointAddr::new(expected_endpoint_id),
        expected_endpoint_id,
        DEFAULT_ALPN.as_bytes(),
        request,
    )
    .await
    .map_err(|err| {
        RpcCommandFailure::new(
            err.code(),
            err.to_string(),
            Some(request_id.clone()),
            json!({ "error": err.to_string() }),
        )
    })?;

    validate_response_for_method(&response, &request_id, method, node)?;
    Ok(RpcCommandSuccess {
        request_id,
        result: response.result.unwrap_or_else(|| json!({})),
    })
}

fn validate_response_for_method(
    response: &RpcResponse,
    request_id: &str,
    method: &str,
    node: &NodeRecord,
) -> Result<(), RpcCommandFailure> {
    let expected_node_info_endpoint_id = (method == NODE_INFO).then_some(node.endpoint_id.as_str());
    validate_rpc_response(response, request_id, expected_node_info_endpoint_id).map_err(|err| {
        RpcCommandFailure::new(
            err.code(),
            err.to_string(),
            Some(request_id.to_string()),
            json!({ "error": err.to_string() }),
        )
    })
}

struct RpcAuditRecord {
    actor: String,
    node_id: String,
    endpoint_id: Option<String>,
    method: String,
    request_id: Option<String>,
    params_hash: String,
    ok: bool,
    error_code: Option<ErrorCode>,
    duration_ms: u64,
    detail_json: Value,
}

fn write_rpc_audit(store: &Store, record: RpcAuditRecord) -> anyhow::Result<()> {
    let mut event = AuditEvent::new(record.actor, "rpc.completed");
    event.node_id = Some(record.node_id);
    event.endpoint_id = record.endpoint_id;
    event.method = Some(record.method);
    event.request_id = record.request_id;
    event.params_hash = Some(record.params_hash);
    event.ok = Some(record.ok);
    event.error_code = record.error_code.as_ref().map(error_code_name);
    event.duration_ms = Some(record.duration_ms);
    event.detail_json = record.detail_json;
    store.insert_audit(&event)?;
    Ok(())
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
        NODE_INFO => {
            for field in [
                "node_id",
                "region",
                "role",
                "agent_version",
                "hostname",
                "os_release",
                "kernel",
                "arch",
                "uptime_seconds",
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

fn hash_json_value(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_else(|_| b"null".to_vec());
    blake3::hash(&bytes).to_hex().to_string()
}

fn error_code_name(code: &ErrorCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| format!("{code:?}"))
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}
