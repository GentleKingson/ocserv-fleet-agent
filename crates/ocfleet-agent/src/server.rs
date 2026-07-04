use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};

use anyhow::{Context, Result};
use base64::Engine;
use iroh::endpoint::{
    AfterHandshakeOutcome, Connection, EndpointHooks, RecvStream, SendStream, Side, presets,
};
use iroh::{Endpoint, EndpointId, RelayMode, SecretKey};
use ocfleet_config::agent::AgentConfig;
use ocfleet_protocol::constants::PROTOCOL_VERSION;
use ocfleet_protocol::error::{ErrorCode, RpcError};
use ocfleet_protocol::method::{MethodStatus, NODE_INFO, NODE_PING, classify_phase_one_method};
use ocfleet_protocol::rpc::{RpcRequest, RpcResponse};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::audit::{AgentAuditEvent, JsonlAuditWriter};
use crate::node_info::collect_node_info;
use crate::nonce::NonceCache;
use crate::AGENT_VERSION;

#[derive(Debug, Clone)]
pub struct AgentServerState {
    pub config: AgentConfig,
    pub audit: JsonlAuditWriter,
    pub nonce_cache: Arc<Mutex<NonceCache>>,
    pub agent_endpoint_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RpcServerError {
    #[error("{message}")]
    Structured { code: ErrorCode, message: String },
}

impl RpcServerError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Structured { code, .. } => code.clone(),
        }
    }

    fn structured(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Structured {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AllowlistHook {
    allowed: HashSet<EndpointId>,
    audit: JsonlAuditWriter,
}

impl AllowlistHook {
    pub fn new(allowed: HashSet<EndpointId>, audit: JsonlAuditWriter) -> Self {
        Self { allowed, audit }
    }
}

impl EndpointHooks for AllowlistHook {
    async fn after_handshake(&self, conn: &Connection) -> AfterHandshakeOutcome {
        if conn.side() != Side::Server {
            return AfterHandshakeOutcome::Accept;
        }

        let remote_endpoint_id = conn.remote_id();
        if self.allowed.contains(&remote_endpoint_id) {
            return AfterHandshakeOutcome::Accept;
        }

        let alpn = String::from_utf8_lossy(conn.alpn());
        let reason = format!("endpoint not allowed for ALPN {alpn}");
        let mut event = AgentAuditEvent::new("rpc_rejected");
        event.remote_endpoint_id = Some(remote_endpoint_id.to_string());
        event.stage = Some("endpoint_allowlist".to_string());
        event.allowed = Some(false);
        event.error_code = Some("ENDPOINT_NOT_ALLOWED".to_string());
        event.reason = Some(reason.clone());
        if let Err(err) = self.audit.write(&event) {
            tracing::warn!(error = %err, "failed to write endpoint allowlist rejection audit event");
        }

        AfterHandshakeOutcome::Reject {
            error_code: 403u32.into(),
            reason: reason.into_bytes(),
        }
    }
}

pub async fn bind_agent_endpoint(
    config: &AgentConfig,
    secret_key: SecretKey,
    audit: JsonlAuditWriter,
) -> Result<Endpoint> {
    agent_endpoint_builder(config, secret_key, audit)?
        .bind()
        .await
        .context("failed to bind agent iroh endpoint")
}

pub async fn bind_agent_endpoint_local_only(
    config: &AgentConfig,
    secret_key: SecretKey,
    audit: JsonlAuditWriter,
) -> Result<Endpoint> {
    agent_endpoint_builder(config, secret_key, audit)?
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .context("failed to configure local-only agent endpoint bind address")?
        .bind()
        .await
        .context("failed to bind local-only agent iroh endpoint")
}

pub fn parse_endpoint_id(value: &str) -> Result<EndpointId> {
    EndpointId::from_str(value).context("invalid endpoint id")
}

pub fn error_response(
    request_id: Option<String>,
    code: ErrorCode,
    message: impl Into<String>,
    details: Value,
) -> RpcResponse {
    let now = now_rfc3339();
    RpcResponse {
        version: PROTOCOL_VERSION,
        request_id,
        ok: false,
        result: None,
        error: Some(RpcError {
            code,
            message: message.into(),
            details,
        }),
        started_at: now.clone(),
        finished_at: now,
        duration_ms: 0,
    }
}

pub fn ok_response(request_id: String, result: Value) -> RpcResponse {
    let now = now_rfc3339();
    RpcResponse {
        version: PROTOCOL_VERSION,
        request_id: Some(request_id),
        ok: true,
        result: Some(result),
        error: None,
        started_at: now.clone(),
        finished_at: now,
        duration_ms: 0,
    }
}

pub async fn read_frame<R>(
    reader: &mut R,
    max_request_bytes: usize,
) -> std::result::Result<Vec<u8>, RpcServerError>
where
    R: AsyncRead + Unpin,
{
    let mut length_bytes = [0_u8; 4];
    reader
        .read_exact(&mut length_bytes)
        .await
        .map_err(|err| RpcServerError::structured(ErrorCode::FrameReadFailed, err.to_string()))?;

    let declared = u32::from_be_bytes(length_bytes) as usize;
    if declared > max_request_bytes {
        return Err(RpcServerError::structured(
            ErrorCode::FrameTooLarge,
            format!("frame too large: {declared} > {max_request_bytes}"),
        ));
    }

    let mut payload = vec![0_u8; declared];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|err| RpcServerError::structured(ErrorCode::FrameReadFailed, err.to_string()))?;
    Ok(payload)
}

async fn read_frame_with_timeout<R>(
    reader: &mut R,
    max_request_bytes: usize,
    timeout: StdDuration,
) -> std::result::Result<Vec<u8>, RpcServerError>
where
    R: AsyncRead + Unpin,
{
    match tokio::time::timeout(timeout, read_frame(reader, max_request_bytes)).await {
        Ok(result) => result,
        Err(_) => Err(RpcServerError::structured(
            ErrorCode::RpcTimeout,
            format!("frame read timed out after {} ms", timeout.as_millis()),
        )),
    }
}

pub async fn write_response<W>(
    writer: &mut W,
    response: &RpcResponse,
    max_response_bytes: usize,
) -> std::result::Result<(), RpcServerError>
where
    W: AsyncWrite + Unpin,
{
    let payload = serialize_response(response, max_response_bytes)?;
    write_response_payload(writer, &payload).await
}

pub async fn handle_request(
    state: &AgentServerState,
    remote_endpoint_id: &str,
    request: RpcRequest,
) -> RpcResponse {
    let started_at = OffsetDateTime::now_utc();
    let response = match validate_and_dispatch_request(state, remote_endpoint_id, request).await {
        Ok((request_id, result)) => ok_response(request_id, result),
        Err(err) => error_response(err.request_id, err.code, err.message, err.details),
    };
    with_response_timing(response, started_at)
}

pub async fn serve_endpoint(endpoint: Endpoint, state: AgentServerState) -> Result<()> {
    while let Some(incoming) = endpoint.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            let connecting = match incoming.accept() {
                Ok(connecting) => connecting,
                Err(err) => {
                    tracing::warn!(error = %err, "failed to accept incoming iroh connection");
                    return;
                }
            };

            match connecting.await {
                Ok(conn) => serve_connection(state, conn).await,
                Err(err) => {
                    tracing::warn!(error = %err, "incoming iroh handshake failed");
                }
            }
        });
    }
    Ok(())
}

fn agent_endpoint_builder(
    config: &AgentConfig,
    secret_key: SecretKey,
    audit: JsonlAuditWriter,
) -> Result<iroh::endpoint::Builder> {
    let allowed = config
        .security
        .controllers
        .iter()
        .map(|controller| {
            parse_endpoint_id(&controller.endpoint_id).with_context(|| {
                format!(
                    "invalid allowed controller endpoint id: {}",
                    controller.endpoint_id
                )
            })
        })
        .collect::<Result<HashSet<_>>>()?;

    Ok(Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(vec![config.iroh.alpn.as_bytes().to_vec()])
        .hooks(AllowlistHook::new(allowed, audit)))
}

async fn serve_connection(state: AgentServerState, conn: Connection) {
    let remote_endpoint_id = conn.remote_id().to_string();
    while let Ok((send, recv)) = conn.accept_bi().await {
        let state = state.clone();
        let remote_endpoint_id = remote_endpoint_id.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_bi_stream(state, remote_endpoint_id, recv, send).await {
                tracing::warn!(error = %err, "failed to handle rpc stream");
            }
        });
    }
}

async fn handle_bi_stream(
    state: AgentServerState,
    remote_endpoint_id: String,
    mut recv: RecvStream,
    mut send: SendStream,
) -> Result<()> {
    let started = Instant::now();
    let max_request_bytes = state.config.security.max_request_bytes;
    let max_response_bytes = state.config.security.max_response_bytes;
    let frame_timeout = StdDuration::from_millis(state.config.security.max_rpc_timeout_ms);

    let payload = match read_frame_with_timeout(&mut recv, max_request_bytes, frame_timeout).await {
        Ok(payload) => payload,
        Err(err) => {
            let response = error_response(
                None,
                err.code(),
                err.to_string(),
                json!({"max_request_bytes": max_request_bytes}),
            );
            let mut event = base_audit_event(&remote_endpoint_id, "read_frame", started);
            event.allowed = Some(false);
            event.ok = Some(false);
            event.error_code = response_error_code(&response);
            event.reason = Some(err.to_string());
            audit_then_write_response(&state, &mut send, response, event, max_response_bytes)
                .await?;
            return Ok(());
        }
    };

    let request_value: Value = match serde_json::from_slice(&payload) {
        Ok(value) => value,
        Err(err) => {
            let response = error_response(
                None,
                ErrorCode::InvalidJson,
                err.to_string(),
                json!({"payload_length": payload.len()}),
            );
            let mut event = base_audit_event(&remote_endpoint_id, "decode_json", started);
            event.allowed = Some(false);
            event.ok = Some(false);
            event.error_code = response_error_code(&response);
            event.reason = Some(format!("payload_length={}; {err}", payload.len()));
            audit_then_write_response(&state, &mut send, response, event, max_response_bytes)
                .await?;
            return Ok(());
        }
    };

    let request_id = request_value
        .get("request_id")
        .and_then(Value::as_str)
        .filter(|value| valid_request_id(value))
        .map(ToOwned::to_owned);
    let method = request_value
        .get("method")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let params_hash = request_value.get("params").map(hash_json_value);
    let nonce_hash = request_value
        .get("nonce")
        .and_then(Value::as_str)
        .map(hash_string);

    let request: RpcRequest = match serde_json::from_value(request_value) {
        Ok(request) => request,
        Err(err) => {
            let response = error_response(
                request_id.clone(),
                ErrorCode::InvalidJson,
                err.to_string(),
                json!({"payload_length": payload.len()}),
            );
            let mut event = base_audit_event(&remote_endpoint_id, "decode_request", started);
            event.request_id = request_id;
            event.method = method;
            event.params_hash = params_hash;
            event.nonce_hash = nonce_hash;
            event.allowed = Some(false);
            event.ok = Some(false);
            event.error_code = response_error_code(&response);
            event.reason = Some(format!("payload_length={}; {err}", payload.len()));
            audit_then_write_response(&state, &mut send, response, event, max_response_bytes)
                .await?;
            return Ok(());
        }
    };

    let response = handle_request(&state, &remote_endpoint_id, request.clone()).await;
    let mut event = base_audit_event(&remote_endpoint_id, "dispatch", started);
    event.request_id = response.request_id.clone();
    event.method = Some(request.method);
    event.params_hash = Some(hash_json_value(&request.params));
    event.nonce_hash = Some(hash_string(&request.nonce));
    event.allowed = Some(response.ok);
    event.ok = Some(response.ok);
    event.error_code = response_error_code(&response);
    audit_then_write_response(&state, &mut send, response, event, max_response_bytes).await?;
    Ok(())
}

async fn audit_then_write_response<W>(
    state: &AgentServerState,
    writer: &mut W,
    mut response: RpcResponse,
    mut event: AgentAuditEvent,
    max_response_bytes: usize,
) -> std::result::Result<(), RpcServerError>
where
    W: AsyncWrite + Unpin,
{
    let payload = match serialize_response(&response, max_response_bytes) {
        Ok(payload) => payload,
        Err(err) if err.code() == ErrorCode::ResponseTooLarge => {
            response = error_response(
                response.request_id.clone(),
                ErrorCode::ResponseTooLarge,
                err.to_string(),
                json!({"max_response_bytes": max_response_bytes}),
            );
            serialize_response(&response, max_response_bytes)?
        }
        Err(err) => return Err(err),
    };

    sync_audit_event_with_response(&mut event, &response, payload.len());
    if let Err(err) = state.audit.write(&event) {
        let audit_response = error_response(
            response.request_id.clone(),
            ErrorCode::AuditWriteFailed,
            "failed to write agent audit event",
            json!({"error": err.to_string()}),
        );
        write_response(writer, &audit_response, max_response_bytes).await?;
        return Ok(());
    }

    write_response_payload(writer, &payload).await
}

fn sync_audit_event_with_response(
    event: &mut AgentAuditEvent,
    response: &RpcResponse,
    response_bytes: usize,
) {
    event.ok = Some(response.ok);
    event.allowed = Some(response.ok);
    event.error_code = response_error_code(response);
    event.response_bytes = Some(response_bytes);
}

fn serialize_response(
    response: &RpcResponse,
    max_response_bytes: usize,
) -> std::result::Result<Vec<u8>, RpcServerError> {
    let payload = serde_json::to_vec(response)
        .map_err(|err| RpcServerError::structured(ErrorCode::InvalidResponse, err.to_string()))?;
    if payload.len() > max_response_bytes {
        return Err(RpcServerError::structured(
            ErrorCode::ResponseTooLarge,
            format!("response too large: {} > {max_response_bytes}", payload.len()),
        ));
    }
    Ok(payload)
}

async fn write_response_payload<W>(
    writer: &mut W,
    payload: &[u8],
) -> std::result::Result<(), RpcServerError>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .map_err(|err| RpcServerError::structured(ErrorCode::InternalError, err.to_string()))?;
    writer
        .write_all(payload)
        .await
        .map_err(|err| RpcServerError::structured(ErrorCode::InternalError, err.to_string()))?;
    writer
        .shutdown()
        .await
        .map_err(|err| RpcServerError::structured(ErrorCode::InternalError, err.to_string()))?;
    Ok(())
}

#[derive(Debug)]
struct RequestDispatchError {
    request_id: Option<String>,
    code: ErrorCode,
    message: String,
    details: Value,
}

impl RequestDispatchError {
    fn new(
        request_id: Option<String>,
        code: ErrorCode,
        message: impl Into<String>,
        details: Value,
    ) -> Self {
        Self {
            request_id,
            code,
            message: message.into(),
            details,
        }
    }
}

async fn validate_and_dispatch_request(
    state: &AgentServerState,
    remote_endpoint_id: &str,
    request: RpcRequest,
) -> std::result::Result<(String, Value), RequestDispatchError> {
    let request_id_for_error = valid_request_id(&request.request_id).then(|| request.request_id.clone());

    if request.version != PROTOCOL_VERSION {
        return Err(RequestDispatchError::new(
            request_id_for_error,
            ErrorCode::InvalidVersion,
            format!("unsupported protocol version: {}", request.version),
            json!({"expected": PROTOCOL_VERSION, "actual": request.version}),
        ));
    }

    if !valid_request_id(&request.request_id) {
        return Err(RequestDispatchError::new(
            None,
            ErrorCode::InvalidRequestId,
            "request_id must be a UUID",
            json!({}),
        ));
    }
    let request_id = request.request_id.clone();

    if request.auth.is_some() {
        return Err(RequestDispatchError::new(
            Some(request_id),
            ErrorCode::UnsupportedAuthScheme,
            "auth must be null for phase 1",
            json!({}),
        ));
    }

    if request.deadline_ms == 0 || request.deadline_ms > state.config.security.max_deadline_ms {
        return Err(RequestDispatchError::new(
            Some(request_id),
            ErrorCode::InvalidDeadline,
            "deadline_ms must be positive and no larger than max_deadline_ms",
            json!({
                "deadline_ms": request.deadline_ms,
                "max_deadline_ms": state.config.security.max_deadline_ms,
            }),
        ));
    }

    validate_nonce(&request.nonce).map_err(|message| {
        RequestDispatchError::new(
            Some(request_id.clone()),
            ErrorCode::InvalidNonce,
            message,
            json!({}),
        )
    })?;

    validate_issued_at(
        &request.issued_at,
        request.deadline_ms,
        state.config.security.allowed_clock_skew_seconds,
    )
    .map_err(|err| RequestDispatchError::new(Some(request_id.clone()), err.0, err.1, err.2))?;

    let nonce_ttl = nonce_ttl(
        request.deadline_ms,
        state.config.security.allowed_clock_skew_seconds,
    );
    let nonce_registered = state
        .nonce_cache
        .lock()
        .map_err(|_| {
            RequestDispatchError::new(
                Some(request_id.clone()),
                ErrorCode::InternalError,
                "nonce cache lock poisoned",
                json!({}),
            )
        })?
        .register(remote_endpoint_id, request.nonce.clone(), nonce_ttl);
    if !nonce_registered {
        return Err(RequestDispatchError::new(
            Some(request_id),
            ErrorCode::ReplayedNonce,
            "nonce was already used by this remote endpoint",
            json!({}),
        ));
    }

    match classify_phase_one_method(&request.method) {
        MethodStatus::KnownButNotAllowed => {
            return Err(RequestDispatchError::new(
                Some(request_id),
                ErrorCode::MethodNotAllowed,
                format!("method is known but not allowed in phase 1: {}", request.method),
                json!({"method": request.method}),
            ));
        }
        MethodStatus::Unknown if request.method.starts_with("ocserv.") => {
            return Err(RequestDispatchError::new(
                Some(request_id),
                ErrorCode::MethodNotAllowed,
                format!("method is known but not allowed in phase 1: {}", request.method),
                json!({"method": request.method}),
            ));
        }
        MethodStatus::Unknown => {
            return Err(RequestDispatchError::new(
                Some(request_id),
                ErrorCode::MethodNotFound,
                format!("method not found: {}", request.method),
                json!({"method": request.method}),
            ));
        }
        MethodStatus::Allowed => {}
    }

    if !params_are_empty(&request.params) {
        return Err(RequestDispatchError::new(
            Some(request_id),
            ErrorCode::ParamsInvalid,
            "node.ping and node.info accept only null or empty object params in phase 1",
            json!({}),
        ));
    }

    let timeout = StdDuration::from_millis(
        request
            .deadline_ms
            .min(state.config.security.max_rpc_timeout_ms),
    );
    match tokio::time::timeout(
        timeout,
        dispatch_allowed_method(state, &request.method, &request_id),
    )
    .await
    {
        Ok(result) => result.map(|value| (request.request_id, value)),
        Err(_) => Err(RequestDispatchError::new(
            Some(request.request_id),
            ErrorCode::RpcTimeout,
            "rpc execution exceeded timeout",
            json!({"timeout_ms": timeout.as_millis()}),
        )),
    }
}

async fn dispatch_allowed_method(
    state: &AgentServerState,
    method: &str,
    request_id: &str,
) -> std::result::Result<Value, RequestDispatchError> {
    match method {
        NODE_PING => Ok(json!({
            "message": "pong",
            "node_id": state.config.node.id,
            "agent_version": AGENT_VERSION,
            "time_utc": now_rfc3339(),
        })),
        NODE_INFO => {
            let node_id = state.config.node.id.clone();
            let region = state.config.node.region.clone();
            let role = state.config.node.role.clone();
            let agent_version = AGENT_VERSION.to_string();
            let agent_endpoint_id = state.agent_endpoint_id.clone();
            let info = tokio::task::spawn_blocking(move || {
                collect_node_info(node_id, region, role, agent_version, agent_endpoint_id)
            })
            .await
            .map_err(|err| {
                RequestDispatchError::new(
                    Some(request_id.to_string()),
                    ErrorCode::InternalError,
                    err.to_string(),
                    json!({}),
                )
            })?;

            serde_json::to_value(info).map_err(|err| {
                RequestDispatchError::new(
                    Some(request_id.to_string()),
                    ErrorCode::InternalError,
                    err.to_string(),
                    json!({}),
                )
            })
        }
        _ => Err(RequestDispatchError::new(
            Some(request_id.to_string()),
            ErrorCode::MethodNotFound,
            format!("method not found: {method}"),
            json!({"method": method}),
        )),
    }
}

fn valid_request_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }

    for (index, byte) in bytes.iter().enumerate() {
        match index {
            8 | 13 | 18 | 23 => {
                if *byte != b'-' {
                    return false;
                }
            }
            _ if !byte.is_ascii_hexdigit() => return false,
            _ => {}
        }
    }
    true
}

fn validate_nonce(nonce: &str) -> std::result::Result<(), String> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(nonce.as_bytes())
        .map_err(|_| "nonce must be base64url without padding".to_string())?;
    if bytes.len() != 16 {
        return Err("nonce must decode to exactly 16 bytes".to_string());
    }
    Ok(())
}

fn validate_issued_at(
    issued_at: &str,
    deadline_ms: u64,
    allowed_clock_skew_seconds: i64,
) -> std::result::Result<(), (ErrorCode, String, Value)> {
    if !issued_at.ends_with('Z') {
        return Err((
            ErrorCode::InvalidTimestamp,
            "issued_at must be RFC3339 UTC".to_string(),
            json!({}),
        ));
    }

    let issued = OffsetDateTime::parse(issued_at, &time::format_description::well_known::Rfc3339)
        .map_err(|err| {
            (
                ErrorCode::InvalidTimestamp,
                err.to_string(),
                json!({"issued_at": issued_at}),
            )
        })?;
    let now = OffsetDateTime::now_utc();
    let skew = time::Duration::seconds(allowed_clock_skew_seconds);
    if issued > now + skew {
        return Err((
            ErrorCode::ClockSkewExceeded,
            "issued_at is too far in the future".to_string(),
            json!({"allowed_clock_skew_seconds": allowed_clock_skew_seconds}),
        ));
    }

    let deadline = time::Duration::milliseconds(deadline_ms as i64);
    if now > issued + deadline {
        return Err((
            ErrorCode::RequestExpired,
            "request deadline has expired".to_string(),
            json!({"deadline_ms": deadline_ms}),
        ));
    }

    if issued < now - skew {
        return Err((
            ErrorCode::ClockSkewExceeded,
            "issued_at is too far in the past".to_string(),
            json!({"allowed_clock_skew_seconds": allowed_clock_skew_seconds}),
        ));
    }

    Ok(())
}

fn params_are_empty(params: &Value) -> bool {
    match params {
        Value::Null => true,
        Value::Object(map) => map.is_empty(),
        _ => false,
    }
}

fn nonce_ttl(deadline_ms: u64, allowed_clock_skew_seconds: i64) -> StdDuration {
    let skew_ms = u64::try_from(allowed_clock_skew_seconds)
        .unwrap_or(0)
        .saturating_mul(1_000);
    StdDuration::from_millis(deadline_ms.saturating_add(skew_ms))
}

fn with_response_timing(mut response: RpcResponse, started_at: OffsetDateTime) -> RpcResponse {
    let finished_at = OffsetDateTime::now_utc();
    response.started_at = format_rfc3339(started_at);
    response.finished_at = format_rfc3339(finished_at);
    response.duration_ms = (finished_at - started_at)
        .whole_milliseconds()
        .max(0) as u64;
    response
}

fn base_audit_event(
    remote_endpoint_id: &str,
    stage: &str,
    started: Instant,
) -> AgentAuditEvent {
    let mut event = AgentAuditEvent::new("rpc_request");
    event.remote_endpoint_id = Some(remote_endpoint_id.to_string());
    event.stage = Some(stage.to_string());
    event.duration_ms = Some(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
    event
}

fn response_error_code(response: &RpcResponse) -> Option<String> {
    response.error.as_ref().and_then(|error| {
        serde_json::to_value(&error.code)
            .ok()
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
    })
}

fn hash_json_value(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_else(|_| b"null".to_vec());
    blake3::hash(&bytes).to_hex().to_string()
}

fn hash_string(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

fn now_rfc3339() -> String {
    format_rfc3339(OffsetDateTime::now_utc())
}

fn format_rfc3339(value: OffsetDateTime) -> String {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .expect("RFC3339 formatting succeeds")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ocfleet_config::agent::{
        AuditConfig, ControllerConfig, IrohConfig, NodeConfig, SecurityConfig,
    };

    #[tokio::test]
    async fn response_too_large_fallback_audit_matches_actual_response() {
        let dir = tempfile::tempdir().expect("temp dir");
        let state = AgentServerState {
            config: test_agent_config(dir.path()),
            audit: JsonlAuditWriter::new(dir.path().join("audit.log")),
            nonce_cache: Arc::new(Mutex::new(NonceCache::new())),
            agent_endpoint_id: "agent-endpoint-1".to_string(),
        };
        let response = ok_response(
            "00000000-0000-4000-8000-000000000001".to_string(),
            json!({"large": "x".repeat(2048)}),
        );
        let mut event = AgentAuditEvent::new("rpc_request");
        event.remote_endpoint_id = Some("controller-1".to_string());
        event.request_id = response.request_id.clone();
        event.stage = Some("dispatch".to_string());
        event.allowed = Some(true);
        event.ok = Some(true);

        let mut writer = tokio::io::sink();
        audit_then_write_response(&state, &mut writer, response, event, 512)
            .await
            .expect("write fallback response");

        let audit_text =
            std::fs::read_to_string(dir.path().join("audit.log")).expect("audit log");
        let audit_json: Value = serde_json::from_str(audit_text.trim()).expect("audit json");
        assert_eq!(audit_json["ok"], false);
        assert_eq!(audit_json["allowed"], false);
        assert_eq!(audit_json["error_code"], "RESPONSE_TOO_LARGE");
        assert!(audit_json["response_bytes"].as_u64().expect("response bytes") <= 512);
    }

    #[tokio::test]
    async fn read_frame_with_timeout_rejects_incomplete_header() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(&[0, 0]).await.expect("write partial header");

        let err = read_frame_with_timeout(&mut reader, 64, StdDuration::from_millis(10))
            .await
            .expect_err("incomplete header times out");

        assert_eq!(err.code(), ErrorCode::RpcTimeout);
    }

    fn test_agent_config(dir: &std::path::Path) -> AgentConfig {
        AgentConfig {
            node: NodeConfig {
                id: "agent-1".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            iroh: IrohConfig {
                secret_key_path: dir.join("iroh.secret"),
                alpn: "/com.github.gentlekingson.ocfleet.mgmt/1".to_string(),
            },
            security: SecurityConfig {
                allowed_clock_skew_seconds: 60,
                default_deadline_ms: 5_000,
                max_deadline_ms: 10_000,
                max_rpc_timeout_ms: 5_000,
                max_request_bytes: 65_536,
                max_response_bytes: 512,
                controllers: Vec::<ControllerConfig>::new(),
            },
            audit: AuditConfig {
                path: dir.join("audit.log"),
            },
            ocserv: None,
            logs: None,
        }
    }
}
