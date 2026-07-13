use std::collections::HashMap;
use std::future::Future;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};

use anyhow::{Context, Result};
use base64::Engine;
use iroh::endpoint::{
    AfterHandshakeOutcome, Connection, EndpointHooks, RecvStream, SendStream, Side, presets,
};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
use ocfleet_config::agent::{AgentConfig, SecurityConfig};
use ocfleet_protocol::constants::PROTOCOL_VERSION;
use ocfleet_protocol::error::{ErrorCode, RpcError};
use ocfleet_protocol::method::{
    MethodStatus, NODE_CAPABILITIES, NODE_INFO, NODE_PING, OCSERV_CERT_EXPIRY,
    OCSERV_CONFIG_FINGERPRINT, OCSERV_SERVICE_SUMMARY, OCSERV_SESSIONS_SUMMARY, OCSERV_VERSION,
    PROBE_CONTROLLER_PING, PROBE_PATH_ECHO, PROBE_PEER_ECHO, classify_phase_one_method,
};
use ocfleet_protocol::rpc::{RpcRequest, RpcResponse};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::AGENT_VERSION;
use crate::audit::{AgentAuditEvent, JsonlAuditWriter};
use crate::audit_limiter::{AuditLimitDecision, RejectedAuditLimiter};
use crate::authz::{AgentAuthorization, CallerClass, PathProbeDecision};
use crate::capabilities::collect_node_capabilities;
use crate::metrics::{AgentMetrics, Resource as MetricResource};
use crate::node_info::collect_node_info;
use crate::nonce::{NonceCache, NonceDecision, NonceLimitScope};
use crate::ocserv::{OcservReadonlyError, provider_from_config};
use crate::peer_echo::{PeerEchoAuditContext, PeerEchoCall, PeerEchoLimits, call_peer_echo};

#[derive(Debug, Clone)]
pub struct AgentServerState {
    pub config: AgentConfig,
    pub audit: JsonlAuditWriter,
    pub nonce_cache: Arc<Mutex<NonceCache>>,
    pub limiters: Arc<ServerLimiters>,
    pub audit_limiter: Arc<Mutex<RejectedAuditLimiter>>,
    pub authz: Arc<AgentAuthorization>,
    pub agent_endpoint_id: String,
    pub outbound_endpoint: Option<Endpoint>,
    pub path_target_resolver: PathTargetResolver,
}

#[derive(Debug, Clone)]
pub struct PathTargetResolver {
    test_addrs: Arc<HashMap<EndpointId, EndpointAddr>>,
}

impl PathTargetResolver {
    pub fn endpoint_id_only() -> Self {
        Self {
            test_addrs: Arc::new(HashMap::new()),
        }
    }

    /// Local E2E-only address injection. This must not be wired into runtime
    /// request schema, CLI UX, production config, or controller registry data.
    #[doc(hidden)]
    pub fn for_local_e2e_tests(
        entries: impl IntoIterator<Item = (EndpointId, EndpointAddr)>,
    ) -> Self {
        Self {
            test_addrs: Arc::new(entries.into_iter().collect()),
        }
    }

    fn resolve(&self, target_endpoint_id: EndpointId) -> EndpointAddr {
        self.test_addrs
            .get(&target_endpoint_id)
            .cloned()
            .unwrap_or_else(|| EndpointAddr::new(target_endpoint_id))
    }
}

#[derive(Debug)]
pub struct ServerLimiters {
    metrics: Arc<AgentMetrics>,
    handshake_global: Arc<Semaphore>,
    connections_global: Arc<Semaphore>,
    connections_per_controller_limit: usize,
    connections_per_controller: Mutex<HashMap<String, Arc<Semaphore>>>,
    streams_global: Arc<Semaphore>,
    streams_per_controller_limit: usize,
    streams_per_controller: Mutex<HashMap<String, Arc<Semaphore>>>,
}

#[derive(Debug)]
pub struct ConnectionPermits {
    _global: OwnedSemaphorePermit,
    _per_controller: OwnedSemaphorePermit,
    metrics: Arc<AgentMetrics>,
}

#[derive(Debug)]
pub struct StreamPermits {
    _global: OwnedSemaphorePermit,
    _per_controller: OwnedSemaphorePermit,
    metrics: Arc<AgentMetrics>,
}

#[derive(Debug)]
pub struct HandshakePermit {
    _permit: OwnedSemaphorePermit,
    metrics: Arc<AgentMetrics>,
}

impl Drop for HandshakePermit {
    fn drop(&mut self) {
        self.metrics.admission_finished(MetricResource::Handshake);
    }
}

impl Drop for ConnectionPermits {
    fn drop(&mut self) {
        self.metrics.admission_finished(MetricResource::Connection);
    }
}

impl Drop for StreamPermits {
    fn drop(&mut self) {
        self.metrics.admission_finished(MetricResource::Stream);
    }
}

impl ServerLimiters {
    pub fn from_config(config: &SecurityConfig) -> Self {
        Self::new(
            config.max_handshake_tasks_global,
            config.max_connections_global,
            config.max_connections_per_controller,
            config.max_streams_global,
            config.max_streams_per_controller,
        )
    }

    pub fn new(
        max_handshake_tasks_global: usize,
        max_connections_global: usize,
        max_connections_per_controller: usize,
        max_streams_global: usize,
        max_streams_per_controller: usize,
    ) -> Self {
        Self {
            metrics: Arc::new(AgentMetrics::default()),
            handshake_global: Arc::new(Semaphore::new(max_handshake_tasks_global)),
            connections_global: Arc::new(Semaphore::new(max_connections_global)),
            connections_per_controller_limit: max_connections_per_controller,
            connections_per_controller: Mutex::new(HashMap::new()),
            streams_global: Arc::new(Semaphore::new(max_streams_global)),
            streams_per_controller_limit: max_streams_per_controller,
            streams_per_controller: Mutex::new(HashMap::new()),
        }
    }

    pub fn metrics(&self) -> Arc<AgentMetrics> {
        self.metrics.clone()
    }

    pub fn try_acquire_handshake(&self) -> Option<HandshakePermit> {
        let Some(permit) = self.handshake_global.clone().try_acquire_owned().ok() else {
            self.metrics.admission_rejected(MetricResource::Handshake);
            return None;
        };
        self.metrics.admission_started(MetricResource::Handshake);
        Some(HandshakePermit {
            _permit: permit,
            metrics: self.metrics.clone(),
        })
    }

    pub fn try_acquire_connection(&self, remote_endpoint_id: &str) -> Option<ConnectionPermits> {
        let Some(global) = self.connections_global.clone().try_acquire_owned().ok() else {
            self.metrics.admission_rejected(MetricResource::Connection);
            return None;
        };
        let per_controller = self
            .connection_controller_semaphore(remote_endpoint_id)
            .try_acquire_owned()
            .ok();
        let Some(per_controller) = per_controller else {
            self.metrics.admission_rejected(MetricResource::Connection);
            return None;
        };
        self.metrics.admission_started(MetricResource::Connection);
        Some(ConnectionPermits {
            _global: global,
            _per_controller: per_controller,
            metrics: self.metrics.clone(),
        })
    }

    pub fn try_acquire_stream(&self, remote_endpoint_id: &str) -> Option<StreamPermits> {
        let Some(global) = self.streams_global.clone().try_acquire_owned().ok() else {
            self.metrics.admission_rejected(MetricResource::Stream);
            return None;
        };
        let per_controller = self
            .stream_controller_semaphore(remote_endpoint_id)
            .try_acquire_owned()
            .ok();
        let Some(per_controller) = per_controller else {
            self.metrics.admission_rejected(MetricResource::Stream);
            return None;
        };
        self.metrics.admission_started(MetricResource::Stream);
        Some(StreamPermits {
            _global: global,
            _per_controller: per_controller,
            metrics: self.metrics.clone(),
        })
    }

    fn connection_controller_semaphore(&self, remote_endpoint_id: &str) -> Arc<Semaphore> {
        let mut semaphores = self
            .connections_per_controller
            .lock()
            .expect("connection limiter mutex poisoned");
        semaphores
            .entry(remote_endpoint_id.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(self.connections_per_controller_limit)))
            .clone()
    }

    fn stream_controller_semaphore(&self, remote_endpoint_id: &str) -> Arc<Semaphore> {
        let mut semaphores = self
            .streams_per_controller
            .lock()
            .expect("stream limiter mutex poisoned");
        semaphores
            .entry(remote_endpoint_id.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(self.streams_per_controller_limit)))
            .clone()
    }
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
    authz: Arc<AgentAuthorization>,
    audit: JsonlAuditWriter,
    audit_limiter: Arc<Mutex<RejectedAuditLimiter>>,
    metrics: Arc<AgentMetrics>,
}

impl AllowlistHook {
    pub fn new(
        authz: Arc<AgentAuthorization>,
        audit: JsonlAuditWriter,
        audit_limiter: Arc<Mutex<RejectedAuditLimiter>>,
        metrics: Arc<AgentMetrics>,
    ) -> Self {
        Self {
            authz,
            audit,
            audit_limiter,
            metrics,
        }
    }
}

impl EndpointHooks for AllowlistHook {
    async fn after_handshake(&self, conn: &Connection) -> AfterHandshakeOutcome {
        if conn.side() != Side::Server {
            return AfterHandshakeOutcome::Accept;
        }

        let remote_endpoint_id = conn.remote_id();
        let caller_class = self.authz.classify(&remote_endpoint_id);
        if self.authz.is_connection_admitted(&remote_endpoint_id) {
            return AfterHandshakeOutcome::Accept;
        }

        let alpn = String::from_utf8_lossy(conn.alpn());
        self.metrics.admission_rejected(MetricResource::Handshake);
        let reason = match caller_class {
            CallerClass::DisabledPeer => format!("disabled peer not allowed for ALPN {alpn}"),
            CallerClass::Unknown => format!("endpoint not allowed for ALPN {alpn}"),
            CallerClass::Controller | CallerClass::Peer => {
                format!("endpoint not admitted for ALPN {alpn}")
            }
        };
        write_limited_audit_event(
            &self.audit,
            &self.audit_limiter,
            Some(&remote_endpoint_id.to_string()),
            "connection",
            "ENDPOINT_NOT_ALLOWED",
            |suppressed_count, limit_key| {
                let mut event = AgentAuditEvent::new("rpc_rejected");
                event.remote_endpoint_id = Some(remote_endpoint_id.to_string());
                event.stage = Some("connection_admission".to_string());
                event.allowed = Some(false);
                event.ok = Some(false);
                event.error_code = Some("ENDPOINT_NOT_ALLOWED".to_string());
                event.reason = Some(reason.clone());
                event.resource = Some("connection".to_string());
                event.suppressed_count = Some(suppressed_count);
                event.limit_key = Some(limit_key);
                event
            },
        )
        .await;

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
    audit_limiter: Arc<Mutex<RejectedAuditLimiter>>,
    metrics: Arc<AgentMetrics>,
) -> Result<Endpoint> {
    agent_endpoint_builder(config, secret_key, audit, audit_limiter, metrics)?
        .bind()
        .await
        .context("failed to bind agent iroh endpoint")
}

pub async fn bind_agent_endpoint_local_only(
    config: &AgentConfig,
    secret_key: SecretKey,
    audit: JsonlAuditWriter,
    audit_limiter: Arc<Mutex<RejectedAuditLimiter>>,
) -> Result<Endpoint> {
    agent_endpoint_builder(
        config,
        secret_key,
        audit,
        audit_limiter,
        Arc::new(AgentMetrics::default()),
    )?
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TimeoutElapsed {
    resource: &'static str,
    timeout: StdDuration,
}

impl TimeoutElapsed {
    fn resource(&self) -> &'static str {
        self.resource
    }

    fn timeout(&self) -> StdDuration {
        self.timeout
    }
}

async fn timeout_boundary<F, T>(
    resource: &'static str,
    timeout: StdDuration,
    future: F,
) -> std::result::Result<T, TimeoutElapsed>
where
    F: Future<Output = T>,
{
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| TimeoutElapsed { resource, timeout })
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
        let Some(handshake_permit) = state.limiters.try_acquire_handshake() else {
            tracing::warn!(
                "incoming iroh connection rejected because handshake task limit is full"
            );
            audit_resource_rejection(
                &state,
                None,
                "handshake",
                "handshake_admission",
                "handshake task limit exceeded",
            )
            .await;
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let handshake_permit = handshake_permit;
            let connecting = match incoming.accept() {
                Ok(connecting) => connecting,
                Err(err) => {
                    tracing::warn!(error = %err, "failed to accept incoming iroh connection");
                    return;
                }
            };
            let handshake_timeout =
                StdDuration::from_millis(state.config.security.max_handshake_duration_ms);

            match timeout_boundary("handshake", handshake_timeout, connecting).await {
                Ok(conn) => {
                    drop(handshake_permit);
                    match conn {
                        Ok(conn) => {
                            let remote_endpoint_id = conn.remote_id().to_string();
                            let Some(connection_permits) =
                                state.limiters.try_acquire_connection(&remote_endpoint_id)
                            else {
                                audit_resource_rejection(
                                    &state,
                                    Some(&remote_endpoint_id),
                                    "connection",
                                    "connection_admission",
                                    "connection limit exceeded",
                                )
                                .await;
                                return;
                            };
                            serve_connection(state, conn, connection_permits).await
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "incoming iroh handshake failed");
                        }
                    }
                }
                Err(err) => {
                    drop(handshake_permit);
                    tracing::warn!(
                        resource = err.resource(),
                        timeout_ms = err.timeout().as_millis(),
                        "incoming iroh handshake timed out"
                    );
                    audit_timeout_rejection(
                        &state,
                        None,
                        "handshake",
                        "handshake_timeout",
                        &format!("handshake timed out after {} ms", err.timeout().as_millis()),
                    )
                    .await;
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
    audit_limiter: Arc<Mutex<RejectedAuditLimiter>>,
    metrics: Arc<AgentMetrics>,
) -> Result<iroh::endpoint::Builder> {
    let authz = Arc::new(AgentAuthorization::from_security_config(&config.security)?);

    Ok(Endpoint::builder(presets::Minimal)
        .secret_key(secret_key)
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .alpns(vec![config.iroh.alpn.as_bytes().to_vec()])
        .hooks(AllowlistHook::new(authz, audit, audit_limiter, metrics)))
}

async fn serve_connection(
    state: AgentServerState,
    conn: Connection,
    _connection_permits: ConnectionPermits,
) {
    let remote_endpoint_id = conn.remote_id().to_string();
    loop {
        let idle_timeout = StdDuration::from_millis(state.config.security.max_connection_idle_ms);
        let accepted = timeout_boundary("connection", idle_timeout, conn.accept_bi()).await;
        let (send, recv) = match accepted {
            Ok(Ok(streams)) => streams,
            Ok(Err(_)) => break,
            Err(err) => {
                tracing::warn!(
                    remote_endpoint_id = %remote_endpoint_id,
                    resource = err.resource(),
                    timeout_ms = err.timeout().as_millis(),
                    "iroh connection closed after idle timeout"
                );
                audit_timeout_rejection(
                    &state,
                    Some(&remote_endpoint_id),
                    "connection",
                    "connection_idle_timeout",
                    &format!(
                        "connection idle timed out after {} ms",
                        err.timeout().as_millis()
                    ),
                )
                .await;
                break;
            }
        };

        let Some(stream_permits) = state.limiters.try_acquire_stream(&remote_endpoint_id) else {
            let mut send = send;
            audit_resource_rejection(
                &state,
                Some(&remote_endpoint_id),
                "stream",
                "stream_admission",
                "stream limit exceeded",
            )
            .await;
            let response = error_response(
                None,
                ErrorCode::ResourceExhausted,
                "stream limit exceeded",
                json!({"resource": "stream"}),
            );
            if let Err(err) = write_response(
                &mut send,
                &response,
                state.config.security.max_response_bytes,
            )
            .await
            {
                tracing::warn!(error = %err, "failed to write stream admission rejection response");
            }
            continue;
        };
        let state = state.clone();
        let remote_endpoint_id = remote_endpoint_id.clone();
        tokio::spawn(async move {
            let _stream_permits = stream_permits;
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
    let method = request.method.clone();
    event.method = Some(method.clone());
    event.params_hash = Some(hash_json_value(&request.params));
    event.nonce_hash = Some(hash_string(&request.nonce));
    event.allowed = Some(response.ok);
    event.ok = Some(response.ok);
    event.error_code = response_error_code(&response);
    if is_ocserv_readonly_method(&method) {
        event.result_class = Some("low_sensitive_summary".to_string());
    }
    sync_path_audit_fields(&mut event, &method, &request.params, &response);
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
    state.limiters.metrics().record_rpc(
        response.error.as_ref().map(|error| &error.code),
        event.duration_ms.unwrap_or(response.duration_ms),
    );
    if let Err(err) = state.audit.write_async(&event).await {
        tracing::warn!(error = %err, "failed to write agent audit event");
        let audit_response = error_response(
            response.request_id.clone(),
            ErrorCode::AuditWriteFailed,
            "failed to write agent audit event",
            json!({}),
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

fn sync_path_audit_fields(
    event: &mut AgentAuditEvent,
    method: &str,
    params: &Value,
    response: &RpcResponse,
) {
    if method != PROBE_PATH_ECHO {
        return;
    }

    event.root_request_id = event.request_id.clone();
    if let Some(target) = params
        .get("target_agent_endpoint_id")
        .and_then(Value::as_str)
        .and_then(|value| parse_endpoint_id(value).ok())
    {
        event.path_target_endpoint_id = Some(target.to_string());
    }

    let Some(result) = response.result.as_ref().and_then(Value::as_object) else {
        return;
    };
    if let Some(root_request_id) = result.get("root_request_id").and_then(Value::as_str) {
        event.root_request_id = Some(root_request_id.to_string());
    }
    if let Some(peer_request_id) = result.get("peer_request_id").and_then(Value::as_str) {
        event.peer_request_id = Some(peer_request_id.to_string());
    }
    if let Some(target_endpoint_id) = result
        .get("target_agent_endpoint_id")
        .and_then(Value::as_str)
        .and_then(|value| parse_endpoint_id(value).ok())
    {
        event.path_target_endpoint_id = Some(target_endpoint_id.to_string());
    }
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
            format!(
                "response too large: {} > {max_response_bytes}",
                payload.len()
            ),
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

#[derive(Debug, Clone)]
struct ValidatedPathProbe {
    target_endpoint_id: EndpointId,
}

async fn validate_and_dispatch_request(
    state: &AgentServerState,
    remote_endpoint_id: &str,
    request: RpcRequest,
) -> std::result::Result<(String, Value), RequestDispatchError> {
    let request_id_for_error =
        valid_request_id(&request.request_id).then(|| request.request_id.clone());

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
    let nonce_decision = state
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
    match nonce_decision {
        NonceDecision::Accepted => {}
        NonceDecision::Replay => {
            state.limiters.metrics().nonce_rejected(false);
            return Err(RequestDispatchError::new(
                Some(request_id),
                ErrorCode::ReplayedNonce,
                "nonce was already used by this remote endpoint",
                json!({}),
            ));
        }
        NonceDecision::ResourceExhausted { scope, limit } => {
            state.limiters.metrics().nonce_rejected(true);
            return Err(RequestDispatchError::new(
                Some(request_id),
                ErrorCode::ResourceExhausted,
                "nonce cache limit exceeded",
                json!({
                    "resource": "nonce_cache",
                    "scope": nonce_limit_scope_name(scope),
                    "limit": limit,
                }),
            ));
        }
    }

    let caller_class = classify_request_caller(state, remote_endpoint_id);
    authorize_request_method(caller_class, &request.method, &request_id)?;

    let path_probe = if request.method == PROBE_PATH_ECHO {
        let target_endpoint_id = validate_path_echo_params(&request.params, &request_id)?;
        authorize_path_probe_target(state, remote_endpoint_id, target_endpoint_id, &request_id)?;
        Some(ValidatedPathProbe { target_endpoint_id })
    } else {
        if !params_are_empty(&request.params) {
            return Err(RequestDispatchError::new(
                Some(request_id),
                ErrorCode::ParamsInvalid,
                "this fixed rpc method accepts only null or empty object params",
                json!({}),
            ));
        }
        None
    };

    let timeout = StdDuration::from_millis(
        request
            .deadline_ms
            .min(state.config.security.max_rpc_timeout_ms),
    );
    match tokio::time::timeout(
        timeout,
        dispatch_allowed_method(
            state,
            remote_endpoint_id,
            &request.method,
            &request_id,
            path_probe,
        ),
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

fn validate_path_echo_params(
    params: &Value,
    request_id: &str,
) -> std::result::Result<EndpointId, RequestDispatchError> {
    let object = params.as_object().ok_or_else(|| {
        RequestDispatchError::new(
            Some(request_id.to_string()),
            ErrorCode::ParamsInvalid,
            "probe.path.echo params must be an object with target_agent_endpoint_id",
            json!({}),
        )
    })?;
    if object.len() != 1 || !object.contains_key("target_agent_endpoint_id") {
        return Err(RequestDispatchError::new(
            Some(request_id.to_string()),
            ErrorCode::ParamsInvalid,
            "probe.path.echo params must contain only target_agent_endpoint_id",
            json!({}),
        ));
    }
    let target = object
        .get("target_agent_endpoint_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            RequestDispatchError::new(
                Some(request_id.to_string()),
                ErrorCode::ParamsInvalid,
                "target_agent_endpoint_id must be a string",
                json!({}),
            )
        })?;
    parse_endpoint_id(target).map_err(|err| {
        RequestDispatchError::new(
            Some(request_id.to_string()),
            ErrorCode::ParamsInvalid,
            format!("invalid target_agent_endpoint_id: {err}"),
            json!({}),
        )
    })
}

fn authorize_path_probe_target(
    state: &AgentServerState,
    remote_endpoint_id: &str,
    target_endpoint_id: EndpointId,
    request_id: &str,
) -> std::result::Result<(), RequestDispatchError> {
    let controller_endpoint_id = parse_endpoint_id(remote_endpoint_id).map_err(|err| {
        RequestDispatchError::new(
            Some(request_id.to_string()),
            ErrorCode::EndpointNotAllowed,
            format!("invalid controller EndpointID: {err}"),
            json!({}),
        )
    })?;
    let source_endpoint_id = parse_endpoint_id(&state.agent_endpoint_id).map_err(|err| {
        RequestDispatchError::new(
            Some(request_id.to_string()),
            ErrorCode::InternalError,
            format!("invalid source agent EndpointID: {err}"),
            json!({}),
        )
    })?;

    match state.authz.path_probe_decision(
        &controller_endpoint_id,
        &target_endpoint_id,
        &source_endpoint_id,
    ) {
        PathProbeDecision::Allowed => Ok(()),
        PathProbeDecision::SelfTarget => Err(RequestDispatchError::new(
            Some(request_id.to_string()),
            ErrorCode::ParamsInvalid,
            "probe.path.echo target must not be the source agent",
            json!({"target_agent_endpoint_id": target_endpoint_id.to_string()}),
        )),
        PathProbeDecision::TargetIsController => Err(RequestDispatchError::new(
            Some(request_id.to_string()),
            ErrorCode::EndpointNotAllowed,
            "probe.path.echo target must not be a controller EndpointID",
            json!({"target_agent_endpoint_id": target_endpoint_id.to_string()}),
        )),
        PathProbeDecision::Disabled => Err(RequestDispatchError::new(
            Some(request_id.to_string()),
            ErrorCode::EndpointNotAllowed,
            "probe.path.echo authorization is disabled",
            json!({"target_agent_endpoint_id": target_endpoint_id.to_string()}),
        )),
        PathProbeDecision::Missing => Err(RequestDispatchError::new(
            Some(request_id.to_string()),
            ErrorCode::EndpointNotAllowed,
            "probe.path.echo authorization is missing",
            json!({"target_agent_endpoint_id": target_endpoint_id.to_string()}),
        )),
    }
}

fn classify_request_caller(state: &AgentServerState, remote_endpoint_id: &str) -> CallerClass {
    parse_endpoint_id(remote_endpoint_id)
        .map(|endpoint_id| state.authz.classify(&endpoint_id))
        .unwrap_or(CallerClass::Unknown)
}

fn authorize_request_method(
    caller_class: CallerClass,
    method: &str,
    request_id: &str,
) -> std::result::Result<(), RequestDispatchError> {
    if matches!(
        caller_class,
        CallerClass::DisabledPeer | CallerClass::Unknown
    ) {
        return Err(RequestDispatchError::new(
            Some(request_id.to_string()),
            ErrorCode::EndpointNotAllowed,
            "remote endpoint is not authorized",
            json!({"method": method}),
        ));
    }

    if AgentAuthorization::method_allowed(caller_class, method) {
        return Ok(());
    }

    match caller_class {
        CallerClass::Controller if method == PROBE_PEER_ECHO => Err(method_not_allowed_for_caller(
            request_id,
            method,
            caller_class,
        )),
        CallerClass::Controller => authorize_controller_method(method, request_id),
        CallerClass::Peer => authorize_peer_method(method, request_id),
        CallerClass::DisabledPeer | CallerClass::Unknown => unreachable!(),
    }
}

fn authorize_controller_method(
    method: &str,
    request_id: &str,
) -> std::result::Result<(), RequestDispatchError> {
    match classify_phase_one_method(method) {
        MethodStatus::KnownButNotAllowed => Err(known_but_not_allowed(request_id, method)),
        MethodStatus::Unknown if method.starts_with("ocserv.") => {
            Err(known_but_not_allowed(request_id, method))
        }
        MethodStatus::Unknown => Err(RequestDispatchError::new(
            Some(request_id.to_string()),
            ErrorCode::MethodNotFound,
            format!("method not found: {method}"),
            json!({"method": method}),
        )),
        MethodStatus::Allowed => Ok(()),
    }
}

fn authorize_peer_method(
    method: &str,
    request_id: &str,
) -> std::result::Result<(), RequestDispatchError> {
    match classify_phase_one_method(method) {
        MethodStatus::Allowed | MethodStatus::KnownButNotAllowed => Err(
            method_not_allowed_for_caller(request_id, method, CallerClass::Peer),
        ),
        MethodStatus::Unknown if method == PROBE_PATH_ECHO => Err(method_not_allowed_for_caller(
            request_id,
            method,
            CallerClass::Peer,
        )),
        MethodStatus::Unknown if method.starts_with("ocserv.") => Err(
            method_not_allowed_for_caller(request_id, method, CallerClass::Peer),
        ),
        MethodStatus::Unknown => Err(RequestDispatchError::new(
            Some(request_id.to_string()),
            ErrorCode::MethodNotFound,
            format!("method not found: {method}"),
            json!({"method": method}),
        )),
    }
}

fn known_but_not_allowed(request_id: &str, method: &str) -> RequestDispatchError {
    RequestDispatchError::new(
        Some(request_id.to_string()),
        ErrorCode::MethodNotAllowed,
        format!("method is known but not allowed in phase 1: {method}"),
        json!({"method": method}),
    )
}

fn method_not_allowed_for_caller(
    request_id: &str,
    method: &str,
    caller_class: CallerClass,
) -> RequestDispatchError {
    RequestDispatchError::new(
        Some(request_id.to_string()),
        ErrorCode::MethodNotAllowed,
        format!("method is not allowed for {caller_class:?}: {method}"),
        json!({"method": method}),
    )
}

async fn dispatch_allowed_method(
    state: &AgentServerState,
    remote_endpoint_id: &str,
    method: &str,
    request_id: &str,
    path_probe: Option<ValidatedPathProbe>,
) -> std::result::Result<Value, RequestDispatchError> {
    match method {
        NODE_PING => Ok(json!({
            "message": "pong",
            "node_id": state.config.node.id,
            "agent_version": AGENT_VERSION,
            "time_utc": now_rfc3339(),
        })),
        PROBE_CONTROLLER_PING => Ok(json!({
            "message": "pong",
            "probe": "controller.ping",
            "node_id": state.config.node.id,
            "agent_version": AGENT_VERSION,
            "agent_endpoint_id": state.agent_endpoint_id,
            "time_utc": now_rfc3339(),
        })),
        PROBE_PEER_ECHO => Ok(json!({
            "message": "pong",
            "probe": "peer.echo",
            "source_agent_endpoint_id": remote_endpoint_id,
            "target_agent_endpoint_id": state.agent_endpoint_id,
            "target_node_id": state.config.node.id,
            "agent_version": AGENT_VERSION,
            "time_utc": now_rfc3339(),
        })),
        PROBE_PATH_ECHO => {
            let path_probe = path_probe.ok_or_else(|| {
                RequestDispatchError::new(
                    Some(request_id.to_string()),
                    ErrorCode::InternalError,
                    "missing validated path probe params",
                    json!({}),
                )
            })?;
            dispatch_path_echo(state, request_id, path_probe).await
        }
        NODE_INFO => {
            let info = collect_node_info(
                state.config.node.id.clone(),
                state.config.node.region.clone(),
                state.config.node.role.clone(),
                AGENT_VERSION.to_string(),
                state.agent_endpoint_id.clone(),
            );
            serde_json::to_value(info).map_err(|err| {
                RequestDispatchError::new(
                    Some(request_id.to_string()),
                    ErrorCode::InternalError,
                    err.to_string(),
                    json!({}),
                )
            })
        }
        NODE_CAPABILITIES => serde_json::to_value(collect_node_capabilities(&state.config))
            .map_err(|_| {
                RequestDispatchError::new(
                    Some(request_id.to_string()),
                    ErrorCode::InternalError,
                    "failed to serialize node capabilities",
                    json!({}),
                )
            }),
        OCSERV_SERVICE_SUMMARY
        | OCSERV_VERSION
        | OCSERV_SESSIONS_SUMMARY
        | OCSERV_CERT_EXPIRY
        | OCSERV_CONFIG_FINGERPRINT => dispatch_ocserv_readonly(state, method, request_id),
        _ => Err(RequestDispatchError::new(
            Some(request_id.to_string()),
            ErrorCode::MethodNotFound,
            format!("method not found: {method}"),
            json!({"method": method}),
        )),
    }
}

fn dispatch_ocserv_readonly(
    state: &AgentServerState,
    method: &str,
    request_id: &str,
) -> std::result::Result<Value, RequestDispatchError> {
    let provider = provider_from_config(&state.config.ocserv_readonly);
    let value = match method {
        OCSERV_SERVICE_SUMMARY => serde_json::to_value(
            provider
                .service_summary()
                .map_err(|err| ocserv_provider_error(request_id, err))?,
        ),
        OCSERV_VERSION => serde_json::to_value(
            provider
                .version()
                .map_err(|err| ocserv_provider_error(request_id, err))?,
        ),
        OCSERV_SESSIONS_SUMMARY => serde_json::to_value(
            provider
                .sessions_summary()
                .map_err(|err| ocserv_provider_error(request_id, err))?,
        ),
        OCSERV_CERT_EXPIRY => serde_json::to_value(
            provider
                .cert_expiry()
                .map_err(|err| ocserv_provider_error(request_id, err))?,
        ),
        OCSERV_CONFIG_FINGERPRINT => serde_json::to_value(
            provider
                .config_fingerprint()
                .map_err(|err| ocserv_provider_error(request_id, err))?,
        ),
        _ => unreachable!("caller only passes fixed ocserv methods"),
    }
    .map_err(|_| {
        RequestDispatchError::new(
            Some(request_id.to_string()),
            ErrorCode::InvalidResponse,
            "ocserv readonly response could not be encoded",
            json!({}),
        )
    })?;
    Ok(value)
}

fn is_ocserv_readonly_method(method: &str) -> bool {
    matches!(
        method,
        OCSERV_SERVICE_SUMMARY
            | OCSERV_VERSION
            | OCSERV_SESSIONS_SUMMARY
            | OCSERV_CERT_EXPIRY
            | OCSERV_CONFIG_FINGERPRINT
    )
}

fn ocserv_provider_error(request_id: &str, err: OcservReadonlyError) -> RequestDispatchError {
    RequestDispatchError::new(
        Some(request_id.to_string()),
        err.code(),
        err.message().to_string(),
        json!({"result_class": "low_sensitive_summary"}),
    )
}

async fn dispatch_path_echo(
    state: &AgentServerState,
    request_id: &str,
    path_probe: ValidatedPathProbe,
) -> std::result::Result<Value, RequestDispatchError> {
    let source_endpoint_id = parse_endpoint_id(&state.agent_endpoint_id).map_err(|err| {
        RequestDispatchError::new(
            Some(request_id.to_string()),
            ErrorCode::InternalError,
            format!("invalid source agent EndpointID: {err}"),
            json!({}),
        )
    })?;
    let Some(endpoint) = state.outbound_endpoint.as_ref() else {
        return Err(RequestDispatchError::new(
            Some(request_id.to_string()),
            ErrorCode::InternalError,
            "source agent outbound endpoint is unavailable",
            json!({}),
        ));
    };

    let target_endpoint_id = path_probe.target_endpoint_id;
    let target = state.path_target_resolver.resolve(target_endpoint_id);
    let limits = PeerEchoLimits {
        deadline_ms: state.config.security.max_rpc_timeout_ms,
        max_request_bytes: state.config.security.max_request_bytes,
        max_response_bytes: state.config.security.max_response_bytes,
    };
    let output = call_peer_echo(PeerEchoCall {
        endpoint,
        target,
        expected_target_endpoint_id: target_endpoint_id,
        source_endpoint_id,
        alpn: state.config.iroh.alpn.as_bytes(),
        audit: &state.audit,
        limits,
        audit_context: PeerEchoAuditContext {
            root_request_id: Some(request_id.to_string()),
            path_target_endpoint_id: Some(target_endpoint_id.to_string()),
        },
    })
    .await;

    match output {
        Ok(output) => Ok(json!({
            "probe": "path.echo",
            "ok": true,
            "source_agent_endpoint_id": source_endpoint_id.to_string(),
            "target_agent_endpoint_id": target_endpoint_id.to_string(),
            "root_request_id": request_id,
            "peer_request_id": output.request_id,
            "target_result": normalize_peer_echo_result(&output.result, request_id)?,
            "time_utc": now_rfc3339(),
        })),
        Err(err) if err.code() == ErrorCode::AuditWriteFailed => Err(RequestDispatchError::new(
            Some(request_id.to_string()),
            err.code(),
            err.to_string(),
            err.details().clone(),
        )),
        Err(err) => Ok(json!({
            "probe": "path.echo",
            "ok": false,
            "source_agent_endpoint_id": source_endpoint_id.to_string(),
            "target_agent_endpoint_id": target_endpoint_id.to_string(),
            "root_request_id": request_id,
            "peer_request_id": err.request_id(),
            "target_result": {
                "ok": false,
                "error_code": error_code_name(&err.code()),
                "stage": "target_peer_echo",
                "reason": "target peer echo failed",
            },
            "time_utc": now_rfc3339(),
        })),
    }
}

fn normalize_peer_echo_result(
    result: &Value,
    request_id: &str,
) -> std::result::Result<Value, RequestDispatchError> {
    let object = result.as_object().ok_or_else(|| {
        RequestDispatchError::new(
            Some(request_id.to_string()),
            ErrorCode::InvalidResponse,
            "peer echo result must be an object",
            json!({}),
        )
    })?;
    let probe = object.get("probe").and_then(Value::as_str);
    let message = object.get("message").and_then(Value::as_str);
    if probe != Some("peer.echo") || message != Some("pong") {
        return Err(RequestDispatchError::new(
            Some(request_id.to_string()),
            ErrorCode::InvalidResponse,
            "peer echo result did not contain expected fixed response",
            json!({}),
        ));
    }
    Ok(json!({"probe": "peer.echo", "message": "pong"}))
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

fn nonce_limit_scope_name(scope: NonceLimitScope) -> &'static str {
    match scope {
        NonceLimitScope::Global => "global",
        NonceLimitScope::PerPeer => "per_peer",
    }
}

fn with_response_timing(mut response: RpcResponse, started_at: OffsetDateTime) -> RpcResponse {
    let finished_at = OffsetDateTime::now_utc();
    response.started_at = format_rfc3339(started_at);
    response.finished_at = format_rfc3339(finished_at);
    response.duration_ms = (finished_at - started_at).whole_milliseconds().max(0) as u64;
    response
}

fn base_audit_event(remote_endpoint_id: &str, stage: &str, started: Instant) -> AgentAuditEvent {
    let mut event = AgentAuditEvent::new("rpc_request");
    event.remote_endpoint_id = Some(remote_endpoint_id.to_string());
    event.stage = Some(stage.to_string());
    event.duration_ms = Some(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
    event
}

async fn audit_resource_rejection(
    state: &AgentServerState,
    remote_endpoint_id: Option<&str>,
    resource: &str,
    stage: &str,
    reason: &str,
) {
    audit_limited_rejection(
        state,
        remote_endpoint_id,
        resource,
        stage,
        "RESOURCE_EXHAUSTED",
        reason,
        "resource_rejected",
    )
    .await;
}

async fn audit_timeout_rejection(
    state: &AgentServerState,
    remote_endpoint_id: Option<&str>,
    resource: &str,
    stage: &str,
    reason: &str,
) {
    let error_code = error_code_name(&ErrorCode::RpcTimeout);
    audit_limited_rejection(
        state,
        remote_endpoint_id,
        resource,
        stage,
        &error_code,
        reason,
        "rpc_rejected",
    )
    .await;
}

async fn audit_limited_rejection(
    state: &AgentServerState,
    remote_endpoint_id: Option<&str>,
    resource: &str,
    stage: &str,
    error_code: &str,
    reason: &str,
    event_name: &str,
) {
    write_limited_audit_event(
        &state.audit,
        &state.audit_limiter,
        remote_endpoint_id,
        resource,
        error_code,
        |suppressed_count, limit_key| {
            let mut event = AgentAuditEvent::new(event_name);
            event.remote_endpoint_id = remote_endpoint_id.map(ToOwned::to_owned);
            event.stage = Some(stage.to_string());
            event.allowed = Some(false);
            event.ok = Some(false);
            event.error_code = Some(error_code.to_string());
            event.reason = Some(reason.to_string());
            event.resource = Some(resource.to_string());
            event.suppressed_count = Some(suppressed_count);
            event.limit_key = Some(limit_key);
            event
        },
    )
    .await;
}

async fn write_limited_audit_event(
    audit: &JsonlAuditWriter,
    audit_limiter: &Arc<Mutex<RejectedAuditLimiter>>,
    remote_endpoint_id: Option<&str>,
    resource: &str,
    error_code: &str,
    event_builder: impl FnOnce(u64, String) -> AgentAuditEvent,
) {
    let decision = match audit_limiter.lock() {
        Ok(mut limiter) => limiter.check(remote_endpoint_id, resource, error_code),
        Err(err) => {
            tracing::warn!(error = %err, "audit limiter lock poisoned");
            return;
        }
    };

    match decision {
        AuditLimitDecision::Write {
            suppressed_count,
            limit_key,
        } => {
            let event = event_builder(suppressed_count, limit_key);
            if let Err(err) = audit.write_async(&event).await {
                tracing::warn!(error = %err, "failed to write limited audit event");
            }
        }
        AuditLimitDecision::Suppress => {}
    }
}

fn response_error_code(response: &RpcResponse) -> Option<String> {
    response.error.as_ref().and_then(|error| {
        serde_json::to_value(&error.code)
            .ok()
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
    })
}

fn error_code_name(code: &ErrorCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| format!("{code:?}"))
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

    #[test]
    fn server_limiters_use_admission_and_release_permits_on_drop() {
        let limiters = ServerLimiters::new(1, 1, 1, 1, 1);

        let handshake = limiters
            .try_acquire_handshake()
            .expect("first handshake permit");
        assert!(limiters.try_acquire_handshake().is_none());
        drop(handshake);
        assert!(limiters.try_acquire_handshake().is_some());

        let connection = limiters
            .try_acquire_connection("controller-1")
            .expect("first connection permit");
        assert!(limiters.try_acquire_connection("controller-1").is_none());
        drop(connection);
        assert!(limiters.try_acquire_connection("controller-1").is_some());

        let stream = limiters
            .try_acquire_stream("controller-1")
            .expect("first stream permit");
        assert!(limiters.try_acquire_stream("controller-1").is_none());
        drop(stream);
        assert!(limiters.try_acquire_stream("controller-1").is_some());

        let rendered = limiters.metrics().render(
            0,
            &crate::audit::AuditMetricsSnapshot {
                audit_queued: 0,
                audit_dropped: 0,
                audit_replayed: 0,
                audit_flush_failures: 0,
                audit_oldest_age_seconds: None,
            },
        );
        assert!(rendered.contains("ocfleet_agent_handshakes{state=\"rejected\"} 1"));
        assert!(rendered.contains("ocfleet_agent_connections{state=\"rejected\"} 1"));
        assert!(rendered.contains("ocfleet_agent_streams{state=\"rejected\"} 1"));
    }

    #[tokio::test]
    async fn response_too_large_fallback_audit_matches_actual_response() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = test_agent_config(dir.path());
        let authz =
            AgentAuthorization::from_security_config(&config.security).expect("authz table builds");
        let state = AgentServerState {
            config: config.clone(),
            audit: JsonlAuditWriter::new(dir.path().join("audit.log")),
            nonce_cache: Arc::new(Mutex::new(NonceCache::new())),
            limiters: Arc::new(ServerLimiters::new(256, 256, 32, 1024, 128)),
            audit_limiter: Arc::new(Mutex::new(RejectedAuditLimiter::new(&config.audit))),
            authz: Arc::new(authz),
            agent_endpoint_id: "agent-endpoint-1".to_string(),
            outbound_endpoint: None,
            path_target_resolver: PathTargetResolver::endpoint_id_only(),
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

        let audit_text = std::fs::read_to_string(dir.path().join("audit.log")).expect("audit log");
        let audit_json: Value = serde_json::from_str(audit_text.trim()).expect("audit json");
        assert_eq!(audit_json["ok"], false);
        assert_eq!(audit_json["allowed"], false);
        assert_eq!(audit_json["error_code"], "RESPONSE_TOO_LARGE");
        assert!(
            audit_json["response_bytes"]
                .as_u64()
                .expect("response bytes")
                <= 512
        );
        let metrics = state.limiters.metrics().render(
            0,
            &crate::audit::AuditMetricsSnapshot {
                audit_queued: 0,
                audit_dropped: 0,
                audit_replayed: 0,
                audit_flush_failures: 0,
                audit_oldest_age_seconds: None,
            },
        );
        assert!(metrics.contains("ocfleet_agent_rpc_calls_total{state=\"failed\"} 1"));
        assert!(metrics.contains("ocfleet_agent_rpc_results_total{state=\"validation\"} 1"));
    }

    #[tokio::test]
    async fn audit_write_failure_response_does_not_expose_local_error_details() {
        let dir = tempfile::tempdir().expect("temp dir");
        let audit_directory = dir.path().join("audit-directory");
        let spool_directory = dir.path().join("audit-spool-directory");
        std::fs::create_dir(&audit_directory).expect("audit directory");
        std::fs::create_dir(&spool_directory).expect("spool directory");
        let mut config = test_agent_config(dir.path());
        config.audit.path = audit_directory.clone();
        config.audit.spool_path = Some(spool_directory.clone());
        let authz =
            AgentAuthorization::from_security_config(&config.security).expect("authz table builds");
        let state = AgentServerState {
            config: config.clone(),
            audit: JsonlAuditWriter::with_durability(
                audit_directory,
                1024,
                spool_directory,
                None,
                1,
            ),
            nonce_cache: Arc::new(Mutex::new(NonceCache::new())),
            limiters: Arc::new(ServerLimiters::new(256, 256, 32, 1024, 128)),
            audit_limiter: Arc::new(Mutex::new(RejectedAuditLimiter::new(&config.audit))),
            authz: Arc::new(authz),
            agent_endpoint_id: "agent-endpoint-1".to_string(),
            outbound_endpoint: None,
            path_target_resolver: PathTargetResolver::endpoint_id_only(),
        };
        let response = ok_response(
            "00000000-0000-4000-8000-000000000001".to_string(),
            json!({"message": "pong"}),
        );
        let mut event = AgentAuditEvent::new("rpc_request");
        event.remote_endpoint_id = Some("controller-1".to_string());
        event.request_id = response.request_id.clone();
        event.stage = Some("dispatch".to_string());
        event.allowed = Some(true);
        event.ok = Some(true);

        let (mut client, mut server) = tokio::io::duplex(4096);
        audit_then_write_response(&state, &mut server, response, event, 2048)
            .await
            .expect("write audit failure response");
        let payload = read_frame(&mut client, 4096).await.expect("response frame");
        let response: RpcResponse = serde_json::from_slice(&payload).expect("rpc response");
        let error = response.error.expect("audit error");

        assert_eq!(error.code, ErrorCode::AuditWriteFailed);
        assert_eq!(error.message, "failed to write agent audit event");
        assert_eq!(error.details, json!({}));
    }

    #[tokio::test]
    async fn read_frame_with_timeout_rejects_incomplete_header() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer
            .write_all(&[0, 0])
            .await
            .expect("write partial header");

        let err = read_frame_with_timeout(&mut reader, 64, StdDuration::from_millis(10))
            .await
            .expect_err("incomplete header times out");

        assert_eq!(err.code(), ErrorCode::RpcTimeout);
    }

    #[tokio::test]
    async fn timeout_boundary_rejects_pending_operation() {
        let err = timeout_boundary(
            "handshake",
            StdDuration::from_millis(10),
            std::future::pending::<()>(),
        )
        .await
        .expect_err("pending operation times out");

        assert_eq!(err.resource(), "handshake");
        assert_eq!(err.timeout(), StdDuration::from_millis(10));
    }

    #[tokio::test]
    async fn timeout_boundary_returns_ready_operation() {
        let result = timeout_boundary("connection", StdDuration::from_millis(10), async { 42 })
            .await
            .expect("ready operation succeeds");

        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn timeout_rejection_audit_records_rpc_timeout() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = test_agent_config(dir.path());
        let authz =
            AgentAuthorization::from_security_config(&config.security).expect("authz table builds");
        let state = AgentServerState {
            config: config.clone(),
            audit: JsonlAuditWriter::new(dir.path().join("audit.log")),
            nonce_cache: Arc::new(Mutex::new(NonceCache::new())),
            limiters: Arc::new(ServerLimiters::new(256, 256, 32, 1024, 128)),
            audit_limiter: Arc::new(Mutex::new(RejectedAuditLimiter::new(&config.audit))),
            authz: Arc::new(authz),
            agent_endpoint_id: "agent-endpoint-1".to_string(),
            outbound_endpoint: None,
            path_target_resolver: PathTargetResolver::endpoint_id_only(),
        };

        audit_timeout_rejection(
            &state,
            Some("remote-1"),
            "connection",
            "connection_idle_timeout",
            "connection idle timed out after 10 ms",
        )
        .await;

        let audit_text = std::fs::read_to_string(dir.path().join("audit.log")).expect("audit log");
        let audit_json: Value = serde_json::from_str(audit_text.trim()).expect("audit json");
        assert_eq!(audit_json["event"], "rpc_rejected");
        assert_eq!(audit_json["remote_endpoint_id"], "remote-1");
        assert_eq!(audit_json["stage"], "connection_idle_timeout");
        assert_eq!(audit_json["error_code"], "RPC_TIMEOUT");
        assert_eq!(audit_json["resource"], "connection");
        assert_eq!(audit_json["ok"], false);
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
                max_handshake_duration_ms: 5_000,
                max_connection_idle_ms: 5_000,
                max_request_bytes: 65_536,
                max_response_bytes: 512,
                max_handshake_tasks_global: 256,
                max_connections_global: 256,
                max_connections_per_controller: 32,
                max_streams_global: 1024,
                max_streams_per_controller: 128,
                max_live_nonces_global: 100_000,
                max_live_nonces_per_controller: 10_000,
                controllers: Vec::<ControllerConfig>::new(),
                peers: Vec::new(),
                path_probes: Vec::new(),
            },
            audit: AuditConfig {
                path: dir.join("audit.log"),
                audit_queue_capacity: 1024,
                spool_path: None,
                metrics_path: None,
                spool_max_events: 10_000,
                rejected_peer_log_burst: 10,
                rejected_peer_log_refill_per_sec: 1,
                rejected_peer_log_max_buckets: 4096,
                rejected_peer_log_bucket_ttl_seconds: 3600,
                rejected_peer_log_aggregate_interval_seconds: 60,
            },
            ocserv_readonly: Default::default(),
            controlled_writes: Default::default(),
            ocserv: None,
            logs: None,
        }
    }
}
