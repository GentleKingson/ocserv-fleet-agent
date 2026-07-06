use std::time::{Duration, Instant};

use base64::Engine;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use ocfleet_protocol::constants::{
    DEFAULT_MAX_REQUEST_BYTES, DEFAULT_MAX_RESPONSE_BYTES, PROTOCOL_VERSION,
};
use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::method::PROBE_PEER_ECHO;
use ocfleet_protocol::rpc::{RpcRequest, RpcResponse};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::audit::{AgentAuditEvent, JsonlAuditWriter};

#[derive(Debug, Clone, Copy)]
pub struct PeerEchoLimits {
    pub deadline_ms: u64,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
}

impl Default for PeerEchoLimits {
    fn default() -> Self {
        Self {
            deadline_ms: 5_000,
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerEchoOutput {
    pub request_id: String,
    pub result: Value,
}

#[derive(Debug, Clone, Default)]
pub struct PeerEchoAuditContext {
    pub root_request_id: Option<String>,
    pub path_target_endpoint_id: Option<String>,
}

pub struct PeerEchoCall<'a> {
    pub endpoint: &'a Endpoint,
    pub target: EndpointAddr,
    pub expected_target_endpoint_id: EndpointId,
    pub source_endpoint_id: EndpointId,
    pub alpn: &'a [u8],
    pub audit: &'a JsonlAuditWriter,
    pub limits: PeerEchoLimits,
    pub audit_context: PeerEchoAuditContext,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct PeerEchoError {
    code: ErrorCode,
    message: String,
    details: Value,
    request_id: Option<String>,
}

impl PeerEchoError {
    pub fn code(&self) -> ErrorCode {
        self.code.clone()
    }

    pub fn details(&self) -> &Value {
        &self.details
    }

    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }

    fn structured(code: ErrorCode, message: impl Into<String>, details: Value) -> Self {
        Self {
            code,
            message: message.into(),
            details,
            request_id: None,
        }
    }

    fn with_request_id(mut self, request_id: String) -> Self {
        if self.request_id.is_none() {
            self.request_id = Some(request_id);
        }
        self
    }
}

pub async fn call_peer_echo(call: PeerEchoCall<'_>) -> Result<PeerEchoOutput, PeerEchoError> {
    let PeerEchoCall {
        endpoint,
        target,
        expected_target_endpoint_id,
        source_endpoint_id,
        alpn,
        audit,
        limits,
        audit_context,
    } = call;
    let request = build_peer_echo_request(limits.deadline_ms);
    let started = Instant::now();
    let request_id = request.request_id.clone();
    let params_hash = hash_json_value(&request.params);
    let nonce_hash = hash_string(&request.nonce);
    let timeout = Duration::from_millis(limits.deadline_ms);

    let result = match tokio::time::timeout(
        timeout,
        call_peer_echo_inner(
            endpoint,
            target,
            expected_target_endpoint_id,
            source_endpoint_id,
            alpn,
            request,
            limits,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(PeerEchoError::structured(
            ErrorCode::RpcTimeout,
            format!("peer echo timed out after {} ms", timeout.as_millis()),
            json!({}),
        )
        .with_request_id(request_id.clone())),
    };
    let result = result.map_err(|err| err.with_request_id(request_id.clone()));

    let mut event = AgentAuditEvent::new("peer_echo");
    event.request_id = Some(request_id.clone());
    event.remote_endpoint_id = Some(expected_target_endpoint_id.to_string());
    event.method = Some(PROBE_PEER_ECHO.to_string());
    event.params_hash = Some(params_hash);
    event.nonce_hash = Some(nonce_hash);
    event.stage = Some("source_peer_echo".to_string());
    event.duration_ms = Some(started.elapsed().as_millis() as u64);
    if audit_context.root_request_id.is_some() || audit_context.path_target_endpoint_id.is_some() {
        event.root_request_id = audit_context.root_request_id;
        event.peer_request_id = Some(request_id.clone());
        event.path_target_endpoint_id = audit_context.path_target_endpoint_id;
    }
    match &result {
        Ok(success) => {
            event.allowed = Some(true);
            event.ok = Some(true);
            event.response_bytes = Some(success.response_bytes);
        }
        Err(err) => {
            event.allowed = Some(false);
            event.ok = Some(false);
            event.error_code = Some(error_code_name(err.code()));
            event.reason = Some(err.to_string());
        }
    }

    audit.write_async(&event).await.map_err(|err| {
        PeerEchoError::structured(ErrorCode::AuditWriteFailed, err.to_string(), json!({}))
    })?;

    result.map(|success| success.output)
}

struct PeerEchoSuccess {
    output: PeerEchoOutput,
    response_bytes: usize,
}

async fn call_peer_echo_inner(
    endpoint: &Endpoint,
    target: EndpointAddr,
    expected_target_endpoint_id: EndpointId,
    source_endpoint_id: EndpointId,
    alpn: &[u8],
    request: RpcRequest,
    limits: PeerEchoLimits,
) -> Result<PeerEchoSuccess, PeerEchoError> {
    let conn = endpoint.connect(target, alpn).await.map_err(|err| {
        PeerEchoError::structured(ErrorCode::ConnectFailed, err.to_string(), json!({}))
    })?;
    let actual_endpoint_id = conn.remote_id();
    if actual_endpoint_id != expected_target_endpoint_id {
        conn.close(0_u8.into(), b"endpoint mismatch");
        return Err(PeerEchoError::structured(
            ErrorCode::EndpointMismatch,
            format!(
                "ENDPOINT_MISMATCH expected={expected_target_endpoint_id} actual={actual_endpoint_id}"
            ),
            json!({
                "expected_endpoint_id": expected_target_endpoint_id.to_string(),
                "actual_remote_endpoint_id": actual_endpoint_id.to_string(),
            }),
        ));
    }

    let (mut send, mut recv) = conn.open_bi().await.map_err(|err| {
        PeerEchoError::structured(ErrorCode::ConnectFailed, err.to_string(), json!({}))
    })?;
    write_request_frame(&mut send, &request, limits.max_request_bytes).await?;
    let payload = read_response_frame(&mut recv, limits.max_response_bytes).await?;
    let response: RpcResponse = serde_json::from_slice(&payload).map_err(|err| {
        PeerEchoError::structured(ErrorCode::InvalidResponse, err.to_string(), json!({}))
    })?;
    let result = validate_peer_echo_response(
        &response,
        &request.request_id,
        source_endpoint_id,
        expected_target_endpoint_id,
    )?;

    Ok(PeerEchoSuccess {
        output: PeerEchoOutput {
            request_id: request.request_id,
            result,
        },
        response_bytes: payload.len(),
    })
}

fn build_peer_echo_request(deadline_ms: u64) -> RpcRequest {
    let nonce_key = iroh::SecretKey::generate();
    let nonce_bytes = nonce_key.to_bytes();
    RpcRequest {
        version: PROTOCOL_VERSION,
        request_id: uuid::Uuid::new_v4().to_string(),
        method: PROBE_PEER_ECHO.to_string(),
        params: json!({}),
        issued_at: OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .expect("RFC3339 formatting succeeds"),
        nonce: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&nonce_bytes[..16]),
        deadline_ms,
        actor: None,
        auth: None,
    }
}

async fn write_request_frame<W>(
    writer: &mut W,
    request: &RpcRequest,
    max_request_bytes: usize,
) -> Result<(), PeerEchoError>
where
    W: AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(request).map_err(|err| {
        PeerEchoError::structured(ErrorCode::InvalidJson, err.to_string(), json!({}))
    })?;
    if payload.len() > max_request_bytes {
        return Err(PeerEchoError::structured(
            ErrorCode::FrameTooLarge,
            format!(
                "request frame too large: {} > {max_request_bytes}",
                payload.len()
            ),
            json!({"max_request_bytes": max_request_bytes}),
        ));
    }

    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .map_err(|err| {
            PeerEchoError::structured(ErrorCode::ConnectFailed, err.to_string(), json!({}))
        })?;
    writer.write_all(&payload).await.map_err(|err| {
        PeerEchoError::structured(ErrorCode::ConnectFailed, err.to_string(), json!({}))
    })?;
    Ok(())
}

async fn read_response_frame<R>(
    reader: &mut R,
    max_response_bytes: usize,
) -> Result<Vec<u8>, PeerEchoError>
where
    R: AsyncRead + Unpin,
{
    let mut length_bytes = [0_u8; 4];
    reader.read_exact(&mut length_bytes).await.map_err(|err| {
        PeerEchoError::structured(ErrorCode::FrameReadFailed, err.to_string(), json!({}))
    })?;
    let declared = u32::from_be_bytes(length_bytes) as usize;
    if declared > max_response_bytes {
        return Err(PeerEchoError::structured(
            ErrorCode::FrameTooLarge,
            format!("frame too large: {declared} > {max_response_bytes}"),
            json!({"max_response_bytes": max_response_bytes}),
        ));
    }

    let mut payload = vec![0_u8; declared];
    reader.read_exact(&mut payload).await.map_err(|err| {
        PeerEchoError::structured(ErrorCode::FrameReadFailed, err.to_string(), json!({}))
    })?;
    Ok(payload)
}

fn validate_peer_echo_response(
    response: &RpcResponse,
    expected_request_id: &str,
    expected_source_endpoint_id: EndpointId,
    expected_target_endpoint_id: EndpointId,
) -> Result<Value, PeerEchoError> {
    if response.version != PROTOCOL_VERSION {
        return Err(invalid_response(format!(
            "invalid response version: expected {PROTOCOL_VERSION}, got {}",
            response.version
        )));
    }
    if response.request_id.as_deref() != Some(expected_request_id) {
        return Err(invalid_response(
            "response request_id does not match request",
        ));
    }
    if !response.ok {
        let Some(error) = &response.error else {
            return Err(invalid_response("error response must include error"));
        };
        return Err(PeerEchoError::structured(
            error.code.clone(),
            error.message.clone(),
            error.details.clone(),
        ));
    }
    if response.error.is_some() {
        return Err(invalid_response("ok response must omit error"));
    }
    let result = response
        .result
        .as_ref()
        .ok_or_else(|| invalid_response("ok response must include result"))?;
    let object = result
        .as_object()
        .ok_or_else(|| invalid_response("peer echo result must be an object"))?;
    validate_closed_fields(object)?;
    require_str(object, "message", "pong")?;
    require_str(object, "probe", "peer.echo")?;
    require_str(
        object,
        "source_agent_endpoint_id",
        &expected_source_endpoint_id.to_string(),
    )?;
    require_str(
        object,
        "target_agent_endpoint_id",
        &expected_target_endpoint_id.to_string(),
    )?;
    require_string_field(object, "target_node_id")?;
    require_string_field(object, "agent_version")?;
    let time_utc = require_string_field(object, "time_utc")?;
    OffsetDateTime::parse(time_utc, &time::format_description::well_known::Rfc3339)
        .map_err(|err| invalid_response(format!("invalid time_utc: {err}")))?;
    Ok(result.clone())
}

fn validate_closed_fields(object: &Map<String, Value>) -> Result<(), PeerEchoError> {
    let mut fields = object.keys().map(String::as_str).collect::<Vec<_>>();
    fields.sort_unstable();
    let expected = [
        "agent_version",
        "message",
        "probe",
        "source_agent_endpoint_id",
        "target_agent_endpoint_id",
        "target_node_id",
        "time_utc",
    ];
    if fields != expected {
        return Err(invalid_response(format!(
            "peer echo result fields mismatch: {:?}",
            fields
        )));
    }
    Ok(())
}

fn require_str(
    object: &Map<String, Value>,
    field: &str,
    expected: &str,
) -> Result<(), PeerEchoError> {
    let actual = require_string_field(object, field)?;
    if actual != expected {
        return Err(invalid_response(format!(
            "{field} mismatch: expected={expected} actual={actual}"
        )));
    }
    Ok(())
}

fn require_string_field<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, PeerEchoError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_response(format!("{field} must be a string")))
}

fn invalid_response(message: impl Into<String>) -> PeerEchoError {
    PeerEchoError::structured(ErrorCode::InvalidResponse, message, json!({}))
}

fn hash_json_value(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_else(|_| b"null".to_vec());
    blake3::hash(&bytes).to_hex().to_string()
}

fn hash_string(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

fn error_code_name(code: ErrorCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "INTERNAL_ERROR".to_string())
}
