use axum::extract::rejection::QueryRejection;
use axum::extract::{Path as AxumPath, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine as _;
use ocfleet_cli::args::RedactionMode;
use ocfleet_cli::audit_export::validate_window;
use ocfleet_cli::slo::{SloWindow, project_health_slo};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::args::ApiConfig;
use crate::auth::{AuthToken, Principal};
use crate::metrics::{CONTENT_TYPE as METRICS_CONTENT_TYPE, render_controller};
use crate::projections::{
    alert_to_json, audit_to_json, health_node_to_json, health_summary_to_json, job_to_json,
    observation_record_to_json, run_to_json,
};
use crate::readonly_store::{ApiReadStore, ReadOnlyStore};
use crate::responses::{
    ApiError, ApiResult, ListResponse, SingleResponse, SummaryResponse, list_response, now_rfc3339,
    single_response, summary_response, with_request_id,
};
use crate::v1::v1_router;
use crate::web::DASHBOARD_HTML;

const DEFAULT_QUERY_LIMIT: u64 = 50;
static DASHBOARD_CSP: OnceLock<HeaderValue> = OnceLock::new();

#[derive(Clone)]
pub struct AppState {
    pub(crate) store: Arc<dyn ApiReadStore>,
    pub(crate) max_limit: u64,
    pub(crate) redact: RedactionMode,
    pub(crate) auth_token: Option<AuthToken>,
    pub(crate) cursor_key: Arc<[u8; 32]>,
}

impl AppState {
    pub fn from_config(config: ApiConfig) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(Uuid::new_v4().as_bytes());
        hasher.update(config.database.as_os_str().as_encoded_bytes());
        let cursor_key: [u8; 32] = hasher.finalize().into();
        Self {
            store: Arc::new(ReadOnlyStore::new(config.database)),
            max_limit: config.max_limit,
            redact: config.redact,
            auth_token: config.auth_token,
            cursor_key: Arc::new(cursor_key),
        }
    }

    pub fn check_readable(&self) -> rusqlite::Result<()> {
        self.store.check_readable()
    }

    pub fn validate_startup(&self) -> Result<(), crate::readonly_store::StoreValidationError> {
        self.store.validate_startup()
    }
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .nest("/api/v1", v1_router())
        .route("/", get(dashboard))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/health/summary", get(health_summary))
        .route("/health/nodes", get(health_nodes))
        .route("/health/nodes/{node_id}", get(health_node))
        .route("/health/slo", get(health_slo))
        .route("/jobs", get(jobs))
        .route("/jobs/{job_id}", get(job))
        .route("/runs", get(runs))
        .route("/runs/{run_id}", get(run))
        .route("/observations", get(observations))
        .route("/observations/{observation_id}", get(observation))
        .route("/alerts", get(alerts))
        .route("/alerts/{lookup}", get(alert))
        .route("/audit/export", get(audit_export))
        .fallback(route_not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state)
        .layer(middleware::from_fn(response_security_headers))
}

async fn response_security_headers(request: Request, next: Next) -> Response {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| validate_correlation_id(value))
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let mut response = with_request_id(request_id.clone(), next.run(request)).await;
    if !response.headers().contains_key(header::CACHE_CONTROL) {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&request_id).expect("validated request id is a header value"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn validate_correlation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

async fn dashboard() -> (HeaderMap, Html<&'static str>) {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_SECURITY_POLICY, dashboard_csp().clone());
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    (headers, Html(DASHBOARD_HTML))
}

async fn route_not_found() -> ApiError {
    ApiError::not_found("route not found")
}

async fn method_not_allowed() -> ApiError {
    ApiError::method_not_allowed()
}

async fn healthz(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authorize(&state, &headers)?;
    db(state.store.check_readable())?;
    Ok(Json(json!({
        "generated_at": now_rfc3339(),
        "status": "ok",
        "read_only": true,
        "auth_enabled": state.auth_token.is_some(),
    })))
}

async fn metrics(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    authorize(&state, &headers)?;
    let generated_at = now_rfc3339();
    let snapshot = db(state.store.controller_metrics(&generated_at))?;
    let mut response = render_controller(&snapshot).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(METRICS_CONTENT_TYPE),
    );
    Ok(response)
}

async fn health_summary(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<SummaryResponse>> {
    authorize(&state, &headers)?;
    let records = db(state.store.list_node_health(state.max_limit))?;
    Ok(summary_response(health_summary_to_json(&records)))
}

async fn health_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse>> {
    authorize(&state, &headers)?;
    let records = db(state.store.list_node_health(state.max_limit))?;
    let items = records.iter().map(health_node_to_json).collect();
    Ok(list_response(state.max_limit, items))
}

async fn health_node(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(node_id): AxumPath<String>,
) -> ApiResult<Json<SingleResponse>> {
    authorize(&state, &headers)?;
    validate_identifier("node_id", &node_id)?;
    let record = db(state.store.get_node_health(&node_id))?
        .ok_or_else(|| ApiError::not_found(format!("node not found: {node_id}")))?;
    Ok(single_response(health_node_to_json(&record)))
}

async fn health_slo(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<HealthSloQuery>, QueryRejection>,
) -> ApiResult<Json<serde_json::Value>> {
    authorize(&state, &headers)?;
    let query = parse_query(query)?;
    let to = query
        .to
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("to is required"))?;
    if to.len() > 64 {
        return Err(ApiError::bad_request("to must not exceed 64 characters"));
    }
    let window = match query.window.as_deref() {
        Some("24h") => SloWindow::Hours24,
        Some("7d") => SloWindow::Days7,
        Some("30d") => SloWindow::Days30,
        _ => return Err(ApiError::bad_request("window must be one of 24h, 7d, 30d")),
    };
    if let Some(node_id) = &query.node_id {
        validate_identifier("node_id", node_id)?;
    }
    let to_time = OffsetDateTime::parse(to, &Rfc3339)
        .map_err(|_| ApiError::bad_request("to must be RFC3339"))?;
    let bucket_seconds =
        i64::try_from(window.bucket_seconds()).map_err(|_| ApiError::internal())?;
    if to_time.unix_timestamp() % bucket_seconds != 0 {
        return Err(ApiError::bad_request(
            "to must align to the selected SLO rollup bucket",
        ));
    }
    let window_seconds = i64::try_from(window.seconds()).map_err(|_| ApiError::internal())?;
    let from_time = to_time - Duration::seconds(window_seconds);
    let from = from_time
        .format(&Rfc3339)
        .map_err(|_| ApiError::internal())?;
    let to = to_time.format(&Rfc3339).map_err(|_| ApiError::internal())?;
    let node_ids = match query.node_id {
        Some(node_id) => vec![node_id],
        None => {
            let nodes = db(state
                .store
                .health_slo_node_ids(window.bucket_seconds(), &from, &to))?;
            if nodes.len() > 1_000 || nodes.len() > state.max_limit as usize {
                return Err(ApiError::bad_request(
                    "health SLO node count exceeds the bounded fleet maximum",
                ));
            }
            nodes
        }
    };
    let mut projections = Vec::with_capacity(node_ids.len());
    for node_id in node_ids {
        validate_identifier("stored node_id", &node_id).map_err(|_| ApiError::internal())?;
        let rows = db(state.store.list_health_rollups(
            &node_id,
            window.bucket_seconds(),
            &from,
            &to,
            window.seconds() / window.bucket_seconds(),
        ))?;
        let projection = project_health_slo(&node_id, window, &from, &to, &rows)
            .ok_or_else(ApiError::internal)?;
        projections.push(projection);
    }
    Ok(Json(json!({
        "schema": "ocfleet.health_slo.v1",
        "generated_at": now_rfc3339(),
        "window": window.as_str(),
        "from": from,
        "to": to,
        "node_count": projections.len(),
        "projections": projections,
    })))
}

async fn jobs(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<ListResponse>> {
    authorize(&state, &headers)?;
    let jobs = db(state.store.list_jobs(state.max_limit))?;
    let items = jobs.iter().map(job_to_json).collect();
    Ok(list_response(state.max_limit, items))
}

async fn job(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(job_id): AxumPath<String>,
) -> ApiResult<Json<SingleResponse>> {
    authorize(&state, &headers)?;
    validate_identifier("job_id", &job_id)?;
    let job = db(state.store.get_job(&job_id))?
        .ok_or_else(|| ApiError::not_found(format!("job not found: {job_id}")))?;
    Ok(single_response(job_to_json(&job)))
}

async fn runs(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<RunsQuery>, QueryRejection>,
) -> ApiResult<Json<ListResponse>> {
    authorize(&state, &headers)?;
    let query = parse_query(query)?;
    let limit = bounded_limit(query.limit, state.max_limit)?;
    if let Some(job_id) = &query.job_id {
        validate_identifier("job_id", job_id)?;
    }
    if let Some(status) = &query.status {
        validate_allowed(
            "status",
            status,
            &["running", "succeeded", "failed", "skipped"],
        )?;
    }
    let runs = db(state
        .store
        .list_runs(limit, query.job_id.as_deref(), query.status.as_deref()))?;
    let items = runs.iter().map(run_to_json).collect();
    Ok(list_response(limit, items))
}

async fn run(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(run_id): AxumPath<String>,
) -> ApiResult<Json<SingleResponse>> {
    authorize(&state, &headers)?;
    validate_identifier("run_id", &run_id)?;
    let run = db(state.store.get_run(&run_id))?
        .ok_or_else(|| ApiError::not_found(format!("run not found: {run_id}")))?;
    Ok(single_response(run_to_json(&run)))
}

async fn observations(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<ObservationsQuery>, QueryRejection>,
) -> ApiResult<Json<ListResponse>> {
    authorize(&state, &headers)?;
    let query = parse_query(query)?;
    let limit = bounded_limit(query.limit, state.max_limit)?;
    if let Some(node_id) = &query.node_id {
        validate_identifier("node_id", node_id)?;
    }
    if let Some(method) = &query.method {
        validate_identifier("method", method)?;
    }
    let observations = db(state.store.list_observations(
        limit,
        query.node_id.as_deref(),
        query.method.as_deref(),
    ))?;
    let items = observations
        .iter()
        .map(observation_record_to_json)
        .collect();
    Ok(list_response(limit, items))
}

async fn observation(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(observation_id): AxumPath<String>,
) -> ApiResult<Json<SingleResponse>> {
    authorize(&state, &headers)?;
    validate_identifier("observation_id", &observation_id)?;
    let observation = db(state.store.get_observation(&observation_id))?
        .ok_or_else(|| ApiError::not_found(format!("observation not found: {observation_id}")))?;
    Ok(single_response(observation_record_to_json(&observation)))
}

async fn alerts(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<AlertsQuery>, QueryRejection>,
) -> ApiResult<Json<ListResponse>> {
    authorize(&state, &headers)?;
    let query = parse_query(query)?;
    let limit = bounded_limit(query.limit, state.max_limit)?;
    if let Some(state_filter) = &query.state {
        validate_allowed("state", state_filter, &["open", "silenced", "resolved"])?;
    }
    if let Some(severity) = &query.severity {
        validate_allowed("severity", severity, &["warning", "critical"])?;
    }
    if let Some(node_id) = &query.node_id {
        validate_identifier("node_id", node_id)?;
    }
    let alerts = db(state.store.list_alerts(
        limit,
        query.state.as_deref(),
        query.severity.as_deref(),
        query.node_id.as_deref(),
    ))?;
    let items = alerts.iter().map(alert_to_json).collect();
    Ok(list_response(limit, items))
}

async fn alert(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(lookup): AxumPath<String>,
) -> ApiResult<Json<SingleResponse>> {
    authorize(&state, &headers)?;
    validate_identifier("alert lookup", &lookup)?;
    let alert = db(state.store.get_alert(&lookup))?
        .ok_or_else(|| ApiError::not_found(format!("alert not found: {lookup}")))?;
    Ok(single_response(alert_to_json(&alert)))
}

async fn audit_export(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<AuditExportQuery>, QueryRejection>,
) -> ApiResult<Json<ListResponse>> {
    authorize(&state, &headers)?;
    let query = parse_query(query)?;
    let from = query
        .from
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("from is required"))?;
    let to = query
        .to
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("to is required"))?;
    validate_window(from, to).map_err(|err| ApiError::bad_request(err.to_string()))?;
    let max_rows = bounded_value(query.max_rows, state.max_limit, "max_rows")?;
    let redact = parse_redaction(query.redact.as_deref(), state.redact)?;
    let query_limit = max_rows
        .checked_add(1)
        .ok_or_else(|| ApiError::bad_request("max_rows is too large"))?;
    let mut rows = db(state.store.list_audit_window(from, to, query_limit))?;
    if rows.len() > max_rows as usize {
        return Err(ApiError::bad_request(
            "audit export row count exceeds max_rows",
        ));
    }
    let items = rows
        .drain(..)
        .map(|row| audit_to_json(&row, redact))
        .collect();
    Ok(list_response(max_rows, items))
}

pub(crate) fn authorize(state: &AppState, headers: &HeaderMap) -> ApiResult<Principal> {
    match &state.auth_token {
        Some(token) => token
            .authenticate_headers(headers)
            .ok_or_else(ApiError::unauthorized),
        None => Ok(Principal::local_viewer()),
    }
}

pub(crate) fn db<T>(result: rusqlite::Result<T>) -> ApiResult<T> {
    result.map_err(|err| {
        tracing::warn!(error = %err, "read-only API query failed");
        ApiError::internal()
    })
}

fn bounded_limit(value: Option<u64>, max_limit: u64) -> ApiResult<u64> {
    bounded_value(value, max_limit, "limit")
}

fn bounded_value(value: Option<u64>, maximum: u64, name: &str) -> ApiResult<u64> {
    let value = value.unwrap_or(DEFAULT_QUERY_LIMIT.min(maximum));
    if value == 0 || value > maximum {
        return Err(ApiError::bad_request(format!(
            "{name} must be between 1 and {maximum}"
        )));
    }
    Ok(value)
}

fn parse_query<T>(query: Result<Query<T>, QueryRejection>) -> ApiResult<T> {
    query
        .map(|Query(query)| query)
        .map_err(|_| ApiError::bad_request("invalid or unsupported query parameters"))
}

fn parse_redaction(value: Option<&str>, default: RedactionMode) -> ApiResult<RedactionMode> {
    match value {
        None => Ok(default),
        Some("none") => Ok(RedactionMode::None),
        Some("default") => Ok(RedactionMode::Default),
        Some("strict") => Ok(RedactionMode::Strict),
        Some(_) => Err(ApiError::bad_request(
            "redact must be one of none, default, strict",
        )),
    }
}

fn validate_allowed(field: &str, value: &str, allowed: &[&str]) -> ApiResult<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!(
            "{field} must be one of {}",
            allowed.join(", ")
        )))
    }
}

fn validate_identifier(field: &str, value: &str) -> ApiResult<()> {
    let valid = !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'));
    if valid {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!(
            "{field} must be a safe identifier"
        )))
    }
}

fn dashboard_csp() -> &'static HeaderValue {
    DASHBOARD_CSP.get_or_init(|| {
        let style_hash = csp_hash(extract_tag_body(DASHBOARD_HTML, "<style>", "</style>"));
        let script_hash = csp_hash(extract_tag_body(DASHBOARD_HTML, "<script>", "</script>"));
        HeaderValue::from_str(&format!(
            "default-src 'none'; script-src 'sha256-{script_hash}'; style-src 'sha256-{style_hash}'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        ))
        .expect("dashboard CSP header is valid")
    })
}

fn extract_tag_body(html: &'static str, open: &str, close: &str) -> &'static str {
    let start = html
        .find(open)
        .map(|offset| offset + open.len())
        .expect("dashboard tag open marker exists");
    let end = html[start..]
        .find(close)
        .map(|offset| start + offset)
        .expect("dashboard tag close marker exists");
    &html[start..end]
}

fn csp_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(digest)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunsQuery {
    limit: Option<u64>,
    job_id: Option<String>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthSloQuery {
    window: Option<String>,
    to: Option<String>,
    node_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationsQuery {
    limit: Option<u64>,
    node_id: Option<String>,
    method: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AlertsQuery {
    state: Option<String>,
    severity: Option<String>,
    node_id: Option<String>,
    limit: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditExportQuery {
    from: Option<String>,
    to: Option<String>,
    redact: Option<String>,
    max_rows: Option<u64>,
}
