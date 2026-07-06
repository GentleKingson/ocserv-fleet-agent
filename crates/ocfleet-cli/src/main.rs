use anyhow::{Context, bail};
use clap::Parser;
use iroh::{EndpointAddr, EndpointId};
use ocfleet_cli::args::{Cli, Command, NodeCommand, ProbeCommand};
use ocfleet_cli::audit::AuditEvent;
use ocfleet_cli::identity::{
    IdentityError, load_or_create_secret_key_with_status, load_secret_key,
};
use ocfleet_cli::rpc_client::{
    RpcClientError, bind_controller_endpoint, build_request, call_endpoint_addr,
    validate_path_echo_result, validate_rpc_response,
};
use ocfleet_cli::store::{NodeInsert, NodeRecord, Store};
use ocfleet_config::validation::{
    canonicalize_node_endpoint_id, validate_node_id, validate_region, validate_role,
};
use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::method::{NODE_INFO, NODE_PING, PROBE_CONTROLLER_PING, PROBE_PATH_ECHO};
use ocfleet_protocol::{DEFAULT_ALPN, DEFAULT_DEADLINE_MS, RpcResponse};
use serde_json::{Map, Value, json};
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
    }

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

    let params = json!({"target_agent_endpoint_id": target.endpoint_id.clone()});
    let params_hash = hash_json_value(&params);
    match execute_node_rpc(secret_key_path, &source, PROBE_PATH_ECHO, params).await {
        Ok(success) => {
            let peer_request_id = success
                .result
                .get("peer_request_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let path_ok = success
                .result
                .get("ok")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let path_error_code = if path_ok {
                None
            } else {
                success
                    .result
                    .get("target_result")
                    .and_then(|target_result| target_result.get("error_code"))
                    .and_then(Value::as_str)
                    .and_then(error_code_from_name)
            };
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
                    detail_json: json!({
                        "source_node_id": source.node_id,
                        "source_endpoint_id": source.endpoint_id,
                        "target_node_id": target.node_id,
                        "target_endpoint_id": target.endpoint_id,
                        "root_request_id": success.request_id,
                        "peer_request_id": peer_request_id,
                        "result": success.result,
                    }),
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
        let code = match &err {
            IdentityError::InvalidPermissions => ErrorCode::SecretKeyPermissionInvalid,
            _ => ErrorCode::SecretKeyLoadFailed,
        };
        RpcCommandFailure::new(
            code,
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
            rpc_client_error_detail_json(&err),
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
    let request = build_request(method, params, Some(local_actor()), DEFAULT_DEADLINE_MS);
    let request_id = request.request_id.clone();
    let params_for_validation = request.params.clone();
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
            rpc_client_error_detail_json(&err),
        )
    })?;

    validate_response_for_method(&response, &request_id, method, node, &params_for_validation)?;
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
    params: &Value,
) -> Result<(), RpcCommandFailure> {
    let expected_agent_endpoint_id =
        matches!(method, NODE_INFO | PROBE_CONTROLLER_PING).then_some(node.endpoint_id.as_str());
    validate_rpc_response(response, request_id, expected_agent_endpoint_id).map_err(|err| {
        RpcCommandFailure::new(
            err.code(),
            err.to_string(),
            Some(request_id.to_string()),
            rpc_client_error_detail_json(&err),
        )
    })?;
    if method == PROBE_PATH_ECHO {
        let target_endpoint_id = params
            .get("target_agent_endpoint_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                RpcCommandFailure::new(
                    ErrorCode::ParamsInvalid,
                    "probe.path.echo missing target_agent_endpoint_id",
                    Some(request_id.to_string()),
                    json!({}),
                )
            })?;
        let result = response.result.as_ref().ok_or_else(|| {
            RpcCommandFailure::new(
                ErrorCode::InvalidResponse,
                "path response missing result",
                Some(request_id.to_string()),
                json!({}),
            )
        })?;
        validate_path_echo_result(result, &node.endpoint_id, target_endpoint_id, request_id)
            .map_err(|err| {
                RpcCommandFailure::new(
                    err.code(),
                    err.to_string(),
                    Some(request_id.to_string()),
                    rpc_client_error_detail_json(&err),
                )
            })?;
    }
    Ok(())
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

fn hash_json_value(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_else(|_| b"null".to_vec());
    blake3::hash(&bytes).to_hex().to_string()
}

fn rpc_client_error_detail_json(err: &RpcClientError) -> Value {
    let mut detail = Map::new();
    let details = err.details().clone();
    detail.insert("error".to_string(), Value::String(err.to_string()));
    detail.insert("details".to_string(), details.clone());
    if let Value::Object(details) = details {
        for (key, value) in details {
            detail.entry(key).or_insert(value);
        }
    }
    Value::Object(detail)
}

fn error_code_name(code: &ErrorCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| format!("{code:?}"))
}

fn error_code_from_name(value: &str) -> Option<ErrorCode> {
    serde_json::from_value(Value::String(value.to_string())).ok()
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}
