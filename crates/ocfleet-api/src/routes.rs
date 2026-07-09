use axum::extract::rejection::QueryRejection;
use axum::extract::{Path as AxumPath, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::middleware::{self, Next};
use axum::response::{Html, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine as _;
use ocfleet_cli::args::RedactionMode;
use ocfleet_cli::audit_export::validate_window;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};

use crate::args::ApiConfig;
use crate::auth::{AuthToken, Principal};
use crate::projections::{
    alert_to_json, audit_to_json, health_node_to_json, health_summary_to_json, job_to_json,
    observation_record_to_json, run_to_json,
};
use crate::readonly_store::{ApiReadStore, ReadOnlyStore};
use crate::responses::{
    ApiError, ApiResult, ListResponse, SingleResponse, SummaryResponse, list_response, now_rfc3339,
    single_response, summary_response,
};
use crate::web::DASHBOARD_HTML;

const DEFAULT_QUERY_LIMIT: u64 = 50;
static DASHBOARD_CSP: OnceLock<HeaderValue> = OnceLock::new();

#[derive(Clone)]
pub struct AppState {
    store: Arc<dyn ApiReadStore>,
    max_limit: u64,
    redact: RedactionMode,
    auth_token: Option<AuthToken>,
}

impl AppState {
    pub fn from_config(config: ApiConfig) -> Self {
        Self {
            store: Arc::new(ReadOnlyStore::new(config.database)),
            max_limit: config.max_limit,
            redact: config.redact,
            auth_token: config.auth_token,
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
        .route("/", get(dashboard))
        .route("/healthz", get(healthz))
        .route("/health/summary", get(health_summary))
        .route("/health/nodes", get(health_nodes))
        .route("/health/nodes/{node_id}", get(health_node))
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
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
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

fn authorize(state: &AppState, headers: &HeaderMap) -> ApiResult<Principal> {
    match &state.auth_token {
        Some(token) => token
            .authenticate_headers(headers)
            .ok_or_else(ApiError::unauthorized),
        None => Ok(Principal::local_viewer()),
    }
}

fn db<T>(result: rusqlite::Result<T>) -> ApiResult<T> {
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
