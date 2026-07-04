use std::net::Ipv4Addr;
use std::time::Duration;

use base64::Engine;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
use ocfleet_protocol::constants::{
    DEFAULT_MAX_REQUEST_BYTES, DEFAULT_MAX_RESPONSE_BYTES, PROTOCOL_VERSION,
};
use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::rpc::{RpcRequest, RpcResponse};
use serde_json::Value;
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, thiserror::Error)]
pub enum RpcClientError {
    #[error("{message}")]
    Structured { code: ErrorCode, message: String },
}

impl RpcClientError {
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

pub async fn bind_controller_endpoint(secret_key: SecretKey) -> Result<Endpoint, RpcClientError> {
    Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .bind()
        .await
        .map_err(|err| RpcClientError::structured(ErrorCode::ConnectFailed, err.to_string()))
}

pub async fn bind_controller_endpoint_local_only(
    secret_key: SecretKey,
) -> Result<Endpoint, RpcClientError> {
    Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .map_err(|err| RpcClientError::structured(ErrorCode::ConnectFailed, err.to_string()))?
        .bind()
        .await
        .map_err(|err| RpcClientError::structured(ErrorCode::ConnectFailed, err.to_string()))
}

pub fn build_request(
    method: impl Into<String>,
    params: Value,
    actor: Option<String>,
    deadline_ms: u64,
) -> RpcRequest {
    let nonce_key = SecretKey::generate();
    let nonce_bytes = nonce_key.to_bytes();
    RpcRequest {
        version: PROTOCOL_VERSION,
        request_id: uuid::Uuid::new_v4().to_string(),
        method: method.into(),
        params,
        issued_at: OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .expect("RFC3339 formatting succeeds"),
        nonce: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&nonce_bytes[..16]),
        deadline_ms,
        actor,
        auth: None,
    }
}

pub async fn call_endpoint_addr(
    endpoint: &Endpoint,
    target: EndpointAddr,
    expected_endpoint_id: EndpointId,
    alpn: &[u8],
    request: RpcRequest,
) -> Result<RpcResponse, RpcClientError> {
    let timeout = Duration::from_millis(request.deadline_ms);
    match tokio::time::timeout(
        timeout,
        call_endpoint_addr_inner(endpoint, target, expected_endpoint_id, alpn, request),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(RpcClientError::structured(
            ErrorCode::RpcTimeout,
            format!("rpc timed out after {} ms", timeout.as_millis()),
        )),
    }
}

async fn call_endpoint_addr_inner(
    endpoint: &Endpoint,
    target: EndpointAddr,
    expected_endpoint_id: EndpointId,
    alpn: &[u8],
    request: RpcRequest,
) -> Result<RpcResponse, RpcClientError> {
    let timeout = Duration::from_millis(request.deadline_ms);
    let conn = endpoint
        .connect(target, alpn)
        .await
        .map_err(|err| RpcClientError::structured(ErrorCode::ConnectFailed, err.to_string()))?;
    let actual_endpoint_id = conn.remote_id();
    if actual_endpoint_id != expected_endpoint_id {
        let message =
            format!("ENDPOINT_MISMATCH expected={expected_endpoint_id} actual={actual_endpoint_id}");
        conn.close(0_u8.into(), message.as_bytes());
        return Err(RpcClientError::structured(
            ErrorCode::EndpointMismatch,
            message,
        ));
    }

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|err| RpcClientError::structured(ErrorCode::ConnectFailed, err.to_string()))?;
    write_request_frame(&mut send, &request).await?;
    let payload =
        read_response_frame_with_timeout(&mut recv, DEFAULT_MAX_RESPONSE_BYTES, timeout).await?;
    serde_json::from_slice(&payload)
        .map_err(|err| RpcClientError::structured(ErrorCode::InvalidResponse, err.to_string()))
}

pub async fn read_response_frame<R>(
    reader: &mut R,
    max_response_bytes: usize,
) -> Result<Vec<u8>, RpcClientError>
where
    R: AsyncRead + Unpin,
{
    let mut length_bytes = [0_u8; 4];
    reader
        .read_exact(&mut length_bytes)
        .await
        .map_err(|err| RpcClientError::structured(ErrorCode::FrameReadFailed, err.to_string()))?;
    let declared = u32::from_be_bytes(length_bytes) as usize;
    if declared > max_response_bytes {
        return Err(RpcClientError::structured(
            ErrorCode::FrameTooLarge,
            format!("frame too large: {declared} > {max_response_bytes}"),
        ));
    }

    let mut payload = vec![0_u8; declared];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|err| RpcClientError::structured(ErrorCode::FrameReadFailed, err.to_string()))?;
    Ok(payload)
}

pub async fn read_response_frame_with_timeout<R>(
    reader: &mut R,
    max_response_bytes: usize,
    timeout: Duration,
) -> Result<Vec<u8>, RpcClientError>
where
    R: AsyncRead + Unpin,
{
    match tokio::time::timeout(timeout, read_response_frame(reader, max_response_bytes)).await {
        Ok(result) => result,
        Err(_) => Err(RpcClientError::structured(
            ErrorCode::RpcTimeout,
            format!("response frame read timed out after {} ms", timeout.as_millis()),
        )),
    }
}

pub fn validate_rpc_response(
    response: &RpcResponse,
    expected_request_id: &str,
    expected_node_info_endpoint_id: Option<&str>,
) -> Result<(), RpcClientError> {
    if response.version != PROTOCOL_VERSION {
        return Err(RpcClientError::structured(
            ErrorCode::InvalidResponse,
            format!(
                "invalid response version: expected {PROTOCOL_VERSION}, got {}",
                response.version
            ),
        ));
    }

    if response.request_id.as_deref() != Some(expected_request_id) {
        return Err(RpcClientError::structured(
            ErrorCode::InvalidResponse,
            "response request_id does not match request".to_string(),
        ));
    }

    if response.ok {
        if response.error.is_some() || response.result.is_none() {
            return Err(RpcClientError::structured(
                ErrorCode::InvalidResponse,
                "ok response must include result and omit error".to_string(),
            ));
        }
        if let Some(expected_endpoint_id) = expected_node_info_endpoint_id {
            let actual = response
                .result
                .as_ref()
                .and_then(|result| result.get("agent_endpoint_id"))
                .and_then(Value::as_str);
            if actual != Some(expected_endpoint_id) {
                return Err(RpcClientError::structured(
                    ErrorCode::InvalidResponse,
                    format!(
                        "node.info endpoint mismatch: expected={expected_endpoint_id} actual={}",
                        actual.unwrap_or("<missing>")
                    ),
                ));
            }
        }
        return Ok(());
    }

    if let Some(error) = &response.error {
        return Err(RpcClientError::structured(
            error.code.clone(),
            error.message.clone(),
        ));
    }

    Err(RpcClientError::structured(
        ErrorCode::InvalidResponse,
        "error response must include error".to_string(),
    ))
}

async fn write_request_frame<W>(
    writer: &mut W,
    request: &RpcRequest,
) -> Result<(), RpcClientError>
where
    W: AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(request)
        .map_err(|err| RpcClientError::structured(ErrorCode::InternalError, err.to_string()))?;
    if payload.len() > DEFAULT_MAX_REQUEST_BYTES {
        return Err(RpcClientError::structured(
            ErrorCode::FrameTooLarge,
            format!(
                "request frame too large: {} > {DEFAULT_MAX_REQUEST_BYTES}",
                payload.len()
            ),
        ));
    }

    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .map_err(|err| RpcClientError::structured(ErrorCode::ConnectFailed, err.to_string()))?;
    writer
        .write_all(&payload)
        .await
        .map_err(|err| RpcClientError::structured(ErrorCode::ConnectFailed, err.to_string()))?;
    writer
        .shutdown()
        .await
        .map_err(|err| RpcClientError::structured(ErrorCode::ConnectFailed, err.to_string()))?;
    Ok(())
}
