use anyhow::Result;
use iroh::{EndpointAddr, EndpointId};
use ocfleet_config::validation::validate_node_id;
use ocfleet_protocol::DEFAULT_ALPN;
use ocfleet_protocol::RpcResponse;
use ocfleet_protocol::enrollment::EndpointStatus;
use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::method::{
    NODE_INFO, OCSERV_CERT_EXPIRY, OCSERV_CONFIG_FINGERPRINT, OCSERV_SERVICE_SUMMARY,
    OCSERV_SESSIONS_SUMMARY, OCSERV_VERSION, PROBE_CONTROLLER_PING, PROBE_PATH_ECHO,
};
use ocfleet_protocol::ocserv::{
    OcservCertExpiryResponse, OcservConfigFingerprintResponse, OcservServiceSummaryResponse,
    OcservSessionsSummaryResponse, OcservVersionResponse,
};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use std::path::Path;
use std::str::FromStr;
use std::time::Instant;

use crate::audit::AuditEvent;
use crate::identity::{IdentityError, load_secret_key};
use crate::ocserv_output::low_sensitive_ocserv_audit_message;
use crate::rpc_client::{
    RpcClientError, bind_controller_endpoint, build_request, call_endpoint_addr,
    validate_path_echo_result, validate_rpc_response,
};
use crate::store::{NodeRecord, Store};

pub const CONTROLLER_RPC_RESULT_CLASS: &str = "controller_rpc_summary";
pub const OCSERV_RESULT_CLASS: &str = "low_sensitive_summary";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerRpcOutcome {
    pub node_id: String,
    pub endpoint_id: Option<String>,
    pub method: String,
    pub request_id: Option<String>,
    pub ok: bool,
    pub error_code: Option<String>,
    pub duration_ms: u64,
    pub result_class: String,
    pub summary_json: Value,
    pub message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OcservStatusBundleOutcome {
    pub node_id: String,
    pub endpoint_id: Option<String>,
    pub ok: bool,
    pub error_code: Option<String>,
    pub duration_ms: u64,
    pub result_class: String,
    pub service: OcservRpcOutcome<OcservServiceSummaryResponse>,
    pub version: OcservRpcOutcome<OcservVersionResponse>,
    pub sessions: OcservRpcOutcome<OcservSessionsSummaryResponse>,
    pub config_fingerprint: OcservRpcOutcome<OcservConfigFingerprintResponse>,
    pub degraded_methods: Vec<&'static str>,
    pub summary_json: Value,
    pub message: Option<String>,
}

pub struct ControllerRpcRunner<'a> {
    store: &'a Store,
    secret_key_path: &'a Path,
}

impl<'a> ControllerRpcRunner<'a> {
    pub fn new(store: &'a Store, secret_key_path: &'a Path) -> Self {
        Self {
            store,
            secret_key_path,
        }
    }

    pub async fn run_fixed_node_rpc(&self, node_id: &str, method: &str) -> ControllerRpcOutcome {
        let actor = local_actor();
        let started = Instant::now();
        let params = json!({});
        let params_hash = hash_json_value(&params);
        let node = match load_fixed_rpc_node(self.store, node_id) {
            Ok(node) => node,
            Err(failure) => {
                let duration_ms = elapsed_ms(started);
                let _ = write_rpc_audit(
                    self.store,
                    RpcAuditRecord {
                        actor,
                        node_id: node_id.to_string(),
                        endpoint_id: failure.endpoint_id.clone(),
                        method: method.to_string(),
                        request_id: None,
                        params_hash,
                        ok: false,
                        error_code: Some(failure.code.clone()),
                        duration_ms,
                        detail_json: failure.detail_json.clone(),
                    },
                );
                return failure_to_outcome(
                    node_id.to_string(),
                    failure.endpoint_id.clone(),
                    method.to_string(),
                    failure,
                    duration_ms,
                    CONTROLLER_RPC_RESULT_CLASS,
                );
            }
        };

        match execute_node_rpc(self.secret_key_path, &node, method, params).await {
            Ok(success) => {
                let duration_ms = elapsed_ms(started);
                let detail_json = json!({ "result": success.result.clone() });
                match write_rpc_audit(
                    self.store,
                    RpcAuditRecord {
                        actor,
                        node_id: node.node_id.clone(),
                        endpoint_id: Some(node.endpoint_id.clone()),
                        method: method.to_string(),
                        request_id: Some(success.request_id.clone()),
                        params_hash,
                        ok: true,
                        error_code: None,
                        duration_ms,
                        detail_json,
                    },
                ) {
                    Ok(()) => ControllerRpcOutcome {
                        node_id: node.node_id,
                        endpoint_id: Some(node.endpoint_id),
                        method: method.to_string(),
                        request_id: Some(success.request_id),
                        ok: true,
                        error_code: None,
                        duration_ms,
                        result_class: CONTROLLER_RPC_RESULT_CLASS.to_string(),
                        summary_json: success.result,
                        message: None,
                    },
                    Err(err) => audit_failure_outcome(
                        node.node_id,
                        Some(node.endpoint_id),
                        method.to_string(),
                        duration_ms,
                        err.to_string(),
                        CONTROLLER_RPC_RESULT_CLASS,
                    ),
                }
            }
            Err(failure) => {
                let duration_ms = elapsed_ms(started);
                let _ = write_rpc_audit(
                    self.store,
                    RpcAuditRecord {
                        actor,
                        node_id: node.node_id.clone(),
                        endpoint_id: Some(node.endpoint_id.clone()),
                        method: method.to_string(),
                        request_id: failure.request_id.clone(),
                        params_hash,
                        ok: false,
                        error_code: Some(failure.code.clone()),
                        duration_ms,
                        detail_json: failure.detail_json.clone(),
                    },
                );
                failure_to_outcome(
                    node.node_id,
                    Some(node.endpoint_id),
                    method.to_string(),
                    failure,
                    duration_ms,
                    CONTROLLER_RPC_RESULT_CLASS,
                )
            }
        }
    }

    pub async fn run_ocserv_status_bundle(&self, node_id: &str) -> OcservStatusBundleOutcome {
        let started = Instant::now();
        let node = match load_ocserv_rpc_node(self.store, node_id) {
            Ok(node) => node,
            Err(failure) => {
                let duration_ms = elapsed_ms(started);
                return OcservStatusBundleOutcome {
                    node_id: node_id.to_string(),
                    endpoint_id: known_endpoint_id(self.store, node_id),
                    ok: false,
                    error_code: Some(error_code_name(&failure.code)),
                    duration_ms,
                    result_class: OCSERV_RESULT_CLASS.to_string(),
                    service: OcservRpcOutcome::Unavailable {
                        method: OCSERV_SERVICE_SUMMARY,
                        code: failure.code.clone(),
                    },
                    version: OcservRpcOutcome::Unavailable {
                        method: OCSERV_VERSION,
                        code: failure.code.clone(),
                    },
                    sessions: OcservRpcOutcome::Unavailable {
                        method: OCSERV_SESSIONS_SUMMARY,
                        code: failure.code.clone(),
                    },
                    config_fingerprint: OcservRpcOutcome::Unavailable {
                        method: OCSERV_CONFIG_FINGERPRINT,
                        code: failure.code.clone(),
                    },
                    degraded_methods: vec![
                        OCSERV_SERVICE_SUMMARY,
                        OCSERV_VERSION,
                        OCSERV_SESSIONS_SUMMARY,
                        OCSERV_CONFIG_FINGERPRINT,
                    ],
                    summary_json: ocserv_failure_detail(&failure),
                    message: Some(failure.message),
                };
            }
        };

        let service = execute_optional_ocserv_rpc::<OcservServiceSummaryResponse>(
            self.store,
            self.secret_key_path,
            &node,
            OCSERV_SERVICE_SUMMARY,
        )
        .await;
        let version = execute_optional_ocserv_rpc::<OcservVersionResponse>(
            self.store,
            self.secret_key_path,
            &node,
            OCSERV_VERSION,
        )
        .await;
        let sessions = execute_optional_ocserv_rpc::<OcservSessionsSummaryResponse>(
            self.store,
            self.secret_key_path,
            &node,
            OCSERV_SESSIONS_SUMMARY,
        )
        .await;
        let config_fingerprint = execute_optional_ocserv_rpc::<OcservConfigFingerprintResponse>(
            self.store,
            self.secret_key_path,
            &node,
            OCSERV_CONFIG_FINGERPRINT,
        )
        .await;
        let degraded_methods = [
            service.unavailable_method(),
            version.unavailable_method(),
            sessions.unavailable_method(),
            config_fingerprint.unavailable_method(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let error_codes = [
            service.error_code(),
            version.error_code(),
            sessions.error_code(),
            config_fingerprint.error_code(),
        ];
        let all_failed = error_codes.iter().all(Option::is_some);
        let status = if all_failed {
            "failed"
        } else if degraded_methods.is_empty() {
            "ok"
        } else {
            "degraded"
        };
        let error_code = all_failed
            .then(|| error_codes.iter().flatten().next().map(error_code_name))
            .flatten();
        let duration_ms = elapsed_ms(started);
        let summary_json = json!({
            "node_id": node.node_id,
            "endpoint_id": node.endpoint_id,
            "result_class": OCSERV_RESULT_CLASS,
            "status": status,
            "rpc_methods": [
                OCSERV_SERVICE_SUMMARY,
                OCSERV_VERSION,
                OCSERV_SESSIONS_SUMMARY,
                OCSERV_CONFIG_FINGERPRINT,
            ],
            "degraded_methods": degraded_methods,
        });

        OcservStatusBundleOutcome {
            node_id: node.node_id,
            endpoint_id: Some(node.endpoint_id),
            ok: !all_failed,
            error_code,
            duration_ms,
            result_class: OCSERV_RESULT_CLASS.to_string(),
            service,
            version,
            sessions,
            config_fingerprint,
            degraded_methods,
            summary_json,
            message: all_failed.then(|| "ocserv status failed".to_string()),
        }
    }

    pub async fn run_ocserv_cert(&self, node_id: &str) -> ControllerRpcOutcome {
        self.run_single_ocserv_rpc::<OcservCertExpiryResponse>(
            node_id,
            OCSERV_CERT_EXPIRY,
            |value| json!({ "cert_count": value.certs.len() }),
        )
        .await
    }

    pub async fn run_ocserv_sessions_summary(&self, node_id: &str) -> ControllerRpcOutcome {
        self.run_single_ocserv_rpc::<OcservSessionsSummaryResponse>(
            node_id,
            OCSERV_SESSIONS_SUMMARY,
            |value| json!({ "sessions": value.sessions }),
        )
        .await
    }

    async fn run_single_ocserv_rpc<T>(
        &self,
        node_id: &str,
        method: &'static str,
        summary: impl FnOnce(&T) -> Value,
    ) -> ControllerRpcOutcome
    where
        T: DeserializeOwned,
    {
        let started = Instant::now();
        let node = match load_ocserv_rpc_node(self.store, node_id) {
            Ok(node) => node,
            Err(failure) => {
                return failure_to_outcome(
                    node_id.to_string(),
                    known_endpoint_id(self.store, node_id),
                    method.to_string(),
                    failure,
                    elapsed_ms(started),
                    OCSERV_RESULT_CLASS,
                );
            }
        };
        match execute_ocserv_rpc::<T>(self.store, self.secret_key_path, &node, method).await {
            Ok(value) => ControllerRpcOutcome {
                node_id: node.node_id,
                endpoint_id: Some(node.endpoint_id),
                method: method.to_string(),
                request_id: None,
                ok: true,
                error_code: None,
                duration_ms: elapsed_ms(started),
                result_class: OCSERV_RESULT_CLASS.to_string(),
                summary_json: summary(&value),
                message: None,
            },
            Err(failure) => failure_to_outcome(
                node.node_id,
                Some(node.endpoint_id),
                method.to_string(),
                failure,
                elapsed_ms(started),
                OCSERV_RESULT_CLASS,
            ),
        }
    }
}

pub fn inactive_endpoint_status(
    store: &Store,
    endpoint_id: &str,
) -> Result<Option<EndpointStatus>> {
    Ok(store
        .get_endpoint_trust(endpoint_id)?
        .map(|endpoint| endpoint.status)
        .filter(|status| *status != EndpointStatus::Active))
}

pub fn load_ocserv_rpc_node(store: &Store, node_id: &str) -> Result<NodeRecord, RpcCommandFailure> {
    validate_node_id(node_id).map_err(|err| {
        RpcCommandFailure::new(
            ErrorCode::ParamsInvalid,
            err.to_string(),
            None,
            low_sensitive_detail(&err.to_string()),
        )
    })?;
    let node = store.get_node(node_id).map_err(|err| {
        RpcCommandFailure::new(
            ErrorCode::SqliteError,
            err.to_string(),
            None,
            low_sensitive_detail("controller registry read failed"),
        )
    })?;
    let Some(node) = node else {
        let message = format!("node not found: {node_id}");
        return Err(RpcCommandFailure::new(
            ErrorCode::NodeNotFound,
            message.clone(),
            None,
            low_sensitive_detail(&message),
        ));
    };
    if !node.enabled {
        let message = format!("node disabled: {node_id}");
        return Err(RpcCommandFailure::new(
            ErrorCode::NodeDisabled,
            message.clone(),
            None,
            low_sensitive_detail(&message),
        ));
    }
    if let Some(status) = inactive_endpoint_status(store, &node.endpoint_id).map_err(|err| {
        RpcCommandFailure::new(
            ErrorCode::SqliteError,
            err.to_string(),
            None,
            low_sensitive_detail("controller endpoint trust read failed"),
        )
    })? {
        let message = format!(
            "endpoint not active: node_id={} endpoint_id={} status={}",
            node.node_id,
            node.endpoint_id,
            status.as_str()
        );
        return Err(RpcCommandFailure::new(
            ErrorCode::EndpointNotAllowed,
            message.clone(),
            None,
            json!({
                "message": "endpoint is not active",
                "result_class": OCSERV_RESULT_CLASS,
                "endpoint_status": status.as_str(),
            }),
        ));
    }
    Ok(node)
}

pub async fn execute_ocserv_rpc<T>(
    store: &Store,
    secret_key_path: &Path,
    node: &NodeRecord,
    method: &str,
) -> Result<T, RpcCommandFailure>
where
    T: DeserializeOwned,
{
    let started = Instant::now();
    let params = json!({});
    let params_hash = hash_json_value(&params);
    let result = execute_node_rpc(secret_key_path, node, method, params).await;
    match result {
        Ok(success) => {
            let typed = match serde_json::from_value::<T>(success.result.clone()) {
                Ok(typed) => typed,
                Err(_) => {
                    let failure = RpcCommandFailure::new(
                        ErrorCode::InvalidResponse,
                        "ocserv readonly response schema is invalid",
                        Some(success.request_id.clone()),
                        json!({
                            "message": "ocserv readonly response schema is invalid",
                            "result_class": OCSERV_RESULT_CLASS,
                            "error_code": "INVALID_RESPONSE",
                        }),
                    );
                    let _ = write_rpc_audit(
                        store,
                        RpcAuditRecord {
                            actor: local_actor(),
                            node_id: node.node_id.clone(),
                            endpoint_id: Some(node.endpoint_id.clone()),
                            method: method.to_string(),
                            request_id: Some(success.request_id),
                            params_hash,
                            ok: false,
                            error_code: Some(ErrorCode::InvalidResponse),
                            duration_ms: elapsed_ms(started),
                            detail_json: ocserv_failure_detail(&failure),
                        },
                    );
                    return Err(failure);
                }
            };
            write_rpc_audit(
                store,
                RpcAuditRecord {
                    actor: local_actor(),
                    node_id: node.node_id.clone(),
                    endpoint_id: Some(node.endpoint_id.clone()),
                    method: method.to_string(),
                    request_id: Some(success.request_id),
                    params_hash,
                    ok: true,
                    error_code: None,
                    duration_ms: elapsed_ms(started),
                    detail_json: json!({"result_class": OCSERV_RESULT_CLASS}),
                },
            )
            .map_err(|err| {
                RpcCommandFailure::new(
                    ErrorCode::AuditWriteFailed,
                    err.to_string(),
                    None,
                    low_sensitive_detail("controller audit write failed"),
                )
            })?;
            Ok(typed)
        }
        Err(failure) => {
            let _ = write_rpc_audit(
                store,
                RpcAuditRecord {
                    actor: local_actor(),
                    node_id: node.node_id.clone(),
                    endpoint_id: Some(node.endpoint_id.clone()),
                    method: method.to_string(),
                    request_id: failure.request_id.clone(),
                    params_hash,
                    ok: false,
                    error_code: Some(failure.code.clone()),
                    duration_ms: elapsed_ms(started),
                    detail_json: ocserv_failure_detail(&failure),
                },
            );
            Err(failure)
        }
    }
}

#[derive(Debug, Clone)]
pub enum OcservRpcOutcome<T> {
    Available(T),
    Unavailable {
        method: &'static str,
        code: ErrorCode,
    },
}

impl<T> OcservRpcOutcome<T> {
    pub fn as_available(&self) -> Option<&T> {
        match self {
            Self::Available(value) => Some(value),
            Self::Unavailable { .. } => None,
        }
    }

    pub fn unavailable_method(&self) -> Option<&'static str> {
        match self {
            Self::Available(_) => None,
            Self::Unavailable { method, .. } => Some(*method),
        }
    }

    pub fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Available(_) => None,
            Self::Unavailable { code, .. } => Some(code.clone()),
        }
    }
}

pub async fn execute_optional_ocserv_rpc<T>(
    store: &Store,
    secret_key_path: &Path,
    node: &NodeRecord,
    method: &'static str,
) -> OcservRpcOutcome<T>
where
    T: DeserializeOwned,
{
    match execute_ocserv_rpc(store, secret_key_path, node, method).await {
        Ok(value) => OcservRpcOutcome::Available(value),
        Err(failure) => OcservRpcOutcome::Unavailable {
            method,
            code: failure.code,
        },
    }
}

#[derive(Debug, Clone)]
pub struct OcservCommandAudit {
    pub actor: String,
    pub event: &'static str,
    pub node_id: String,
    pub endpoint_id: Option<String>,
    pub method: &'static str,
    pub ok: bool,
    pub error_code: Option<ErrorCode>,
    pub duration_ms: u64,
    pub detail_json: Value,
}

pub fn write_ocserv_command_audit(store: &Store, record: OcservCommandAudit) -> Result<()> {
    let mut event = AuditEvent::new(record.actor, record.event);
    event.node_id = Some(record.node_id);
    event.endpoint_id = record.endpoint_id;
    event.method = Some(record.method.to_string());
    event.ok = Some(record.ok);
    event.error_code = record.error_code.as_ref().map(error_code_name);
    event.duration_ms = Some(record.duration_ms);
    event.detail_json = record.detail_json;
    store.insert_audit(&event)?;
    Ok(())
}

pub fn low_sensitive_detail(message: &str) -> Value {
    json!({
        "message": low_sensitive_ocserv_audit_message(message),
        "result_class": OCSERV_RESULT_CLASS,
    })
}

pub fn ocserv_failure_detail(failure: &RpcCommandFailure) -> Value {
    json!({
        "message": low_sensitive_ocserv_audit_message(&failure.message),
        "result_class": OCSERV_RESULT_CLASS,
        "error_code": error_code_name(&failure.code),
    })
}

#[derive(Debug, Clone)]
pub struct RpcCommandSuccess {
    pub request_id: String,
    pub result: Value,
}

#[derive(Debug, Clone)]
pub struct RpcCommandFailure {
    pub code: ErrorCode,
    pub message: String,
    pub request_id: Option<String>,
    pub detail_json: Value,
    endpoint_id: Option<String>,
}

impl RpcCommandFailure {
    pub fn new(
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
            endpoint_id: None,
        }
    }

    fn with_endpoint_id(mut self, endpoint_id: Option<String>) -> Self {
        self.endpoint_id = endpoint_id;
        self
    }
}

pub async fn execute_node_rpc(
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
    let request = build_request(
        method,
        params,
        Some(local_actor()),
        ocfleet_protocol::DEFAULT_DEADLINE_MS,
    );
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

#[derive(Debug, Clone)]
pub struct RpcAuditRecord {
    pub actor: String,
    pub node_id: String,
    pub endpoint_id: Option<String>,
    pub method: String,
    pub request_id: Option<String>,
    pub params_hash: String,
    pub ok: bool,
    pub error_code: Option<ErrorCode>,
    pub duration_ms: u64,
    pub detail_json: Value,
}

pub fn write_rpc_audit(store: &Store, record: RpcAuditRecord) -> Result<()> {
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

pub fn hash_json_value(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_else(|_| b"null".to_vec());
    blake3::hash(&bytes).to_hex().to_string()
}

pub fn error_code_name(code: &ErrorCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| format!("{code:?}"))
}

pub fn error_code_from_name(value: &str) -> Option<ErrorCode> {
    serde_json::from_value(Value::String(value.to_string())).ok()
}

pub fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

pub fn known_endpoint_id(store: &Store, node_id: &str) -> Option<String> {
    store
        .get_node(node_id)
        .ok()
        .flatten()
        .map(|node| node.endpoint_id)
}

fn load_fixed_rpc_node(store: &Store, node_id: &str) -> Result<NodeRecord, RpcCommandFailure> {
    validate_node_id(node_id).map_err(|err| {
        RpcCommandFailure::new(
            ErrorCode::ParamsInvalid,
            err.to_string(),
            None,
            json!({ "message": err.to_string() }),
        )
    })?;
    let node = store.get_node(node_id).map_err(|err| {
        RpcCommandFailure::new(
            ErrorCode::SqliteError,
            err.to_string(),
            None,
            json!({ "message": "controller registry read failed" }),
        )
    })?;
    let Some(node) = node else {
        let message = format!("node not found: {node_id}");
        return Err(RpcCommandFailure::new(
            ErrorCode::NodeNotFound,
            message.clone(),
            None,
            json!({ "message": message }),
        ));
    };
    if !node.enabled {
        let message = format!("node disabled: {node_id}");
        return Err(RpcCommandFailure::new(
            ErrorCode::NodeDisabled,
            message.clone(),
            None,
            json!({ "message": message }),
        )
        .with_endpoint_id(Some(node.endpoint_id)));
    }
    if let Some(status) = inactive_endpoint_status(store, &node.endpoint_id).map_err(|err| {
        RpcCommandFailure::new(
            ErrorCode::SqliteError,
            err.to_string(),
            None,
            json!({ "message": "controller endpoint trust read failed" }),
        )
    })? {
        let message = format!(
            "endpoint not active: node_id={} endpoint_id={} status={}",
            node.node_id,
            node.endpoint_id,
            status.as_str()
        );
        return Err(RpcCommandFailure::new(
            ErrorCode::EndpointNotAllowed,
            message.clone(),
            None,
            json!({ "message": message, "endpoint_status": status.as_str() }),
        )
        .with_endpoint_id(Some(node.endpoint_id)));
    }
    Ok(node)
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

fn failure_to_outcome(
    node_id: String,
    endpoint_id: Option<String>,
    method: String,
    failure: RpcCommandFailure,
    duration_ms: u64,
    result_class: &str,
) -> ControllerRpcOutcome {
    ControllerRpcOutcome {
        node_id,
        endpoint_id,
        method,
        request_id: failure.request_id,
        ok: false,
        error_code: Some(error_code_name(&failure.code)),
        duration_ms,
        result_class: result_class.to_string(),
        summary_json: failure.detail_json,
        message: Some(failure.message),
    }
}

fn audit_failure_outcome(
    node_id: String,
    endpoint_id: Option<String>,
    method: String,
    duration_ms: u64,
    message: String,
    result_class: &str,
) -> ControllerRpcOutcome {
    ControllerRpcOutcome {
        node_id,
        endpoint_id,
        method,
        request_id: None,
        ok: false,
        error_code: Some(error_code_name(&ErrorCode::AuditWriteFailed)),
        duration_ms,
        result_class: result_class.to_string(),
        summary_json: json!({ "message": message }),
        message: Some("controller audit write failed".to_string()),
    }
}

fn local_actor() -> String {
    match std::env::var("USER") {
        Ok(actor) if !actor.trim().is_empty() => actor,
        _ => "local-cli".to_string(),
    }
}
