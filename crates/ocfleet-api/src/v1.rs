use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine as _;
use ocfleet_cli::audit_export::validate_window;
use ocfleet_cli::input_validation::validate_label_json;
use ocfleet_cli::version_governance::{MAX_VERSION_GOVERNANCE_NODES, build_fleet_version_report};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::projections::{alert_to_json, health_node_to_json};
use crate::readonly_store::{AlertPageFilters, HistoryPageFilters, NodeListFilters};
use crate::responses::{ApiError, ApiResult, now_rfc3339};
use crate::routes::{AppState, authorize, db};

const DEFAULT_LIMIT: u64 = 50;
const MAX_CURSOR_BYTES: usize = 2_048;

pub fn v1_router() -> Router<AppState> {
    Router::new()
        .route("/fleet/summary", get(fleet_summary))
        .route("/version/readiness", get(version_readiness))
        .route("/nodes", get(nodes))
        .route("/nodes/{node_id}", get(node))
        .route("/health/history", get(health_history))
        .route("/alerts", get(alerts))
        .route("/alerts/{lookup}", get(alert))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodesQuery {
    limit: Option<u64>,
    cursor: Option<String>,
    region: Option<String>,
    role: Option<String>,
    environment: Option<String>,
    label: Option<String>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyQuery {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryQuery {
    from: String,
    to: String,
    limit: Option<u64>,
    cursor: Option<String>,
    node_id: Option<String>,
    status: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AlertsQuery {
    from: String,
    to: String,
    limit: Option<u64>,
    cursor: Option<String>,
    state: Option<String>,
    severity: Option<String>,
    node_id: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorPayload {
    version: u8,
    resource: String,
    after: String,
    filter_hash: String,
}

async fn fleet_summary(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<EmptyQuery>, QueryRejection>,
) -> ApiResult<Response> {
    authorize(&state, &headers)?;
    query.map_err(|_| ApiError::bad_request("query parameters are not supported"))?;
    let counts = db(state.store.fleet_health_summary())?;
    let data = json!({
        "schema": "ocfleet.api.v1.fleet-summary",
        "total": counts.iter().sum::<u64>(),
        "status": {
            "healthy": counts[0],
            "degraded": counts[1],
            "unreachable": counts[2],
            "stale": counts[3],
            "disabled": counts[4],
            "unknown": counts[5],
        }
    });
    conditional_json(&headers, data)
}

async fn version_readiness(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<EmptyQuery>, QueryRejection>,
) -> ApiResult<Response> {
    authorize(&state, &headers)?;
    query.map_err(|_| ApiError::bad_request("query parameters are not supported"))?;
    let fetch_limit =
        u64::try_from(MAX_VERSION_GOVERNANCE_NODES + 1).map_err(|_| ApiError::internal())?;
    let inputs = db(state.store.version_governance_inputs(fetch_limit))?;
    let report = build_fleet_version_report(inputs).map_err(|_| ApiError::internal())?;
    conditional_json(
        &headers,
        serde_json::to_value(report).map_err(|_| ApiError::internal())?,
    )
}

async fn node(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
    query: Result<Query<EmptyQuery>, QueryRejection>,
) -> ApiResult<Response> {
    authorize(&state, &headers)?;
    query.map_err(|_| ApiError::bad_request("query parameters are not supported"))?;
    validate_filter_value("node_id", &node_id)?;
    let record = db(state.store.get_node_health(&node_id))?
        .ok_or_else(|| ApiError::not_found(format!("node not found: {node_id}")))?;
    conditional_json(
        &headers,
        json!({"schema":"ocfleet.api.v1.node","item":health_node_to_json(&record)}),
    )
}

async fn nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<NodesQuery>, QueryRejection>,
) -> ApiResult<Response> {
    authorize(&state, &headers)?;
    let Query(query) =
        query.map_err(|_| ApiError::bad_request("invalid or unsupported query parameters"))?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT.min(state.max_limit));
    if limit == 0 || limit > state.max_limit {
        return Err(ApiError::bad_request(format!(
            "limit must be between 1 and {}",
            state.max_limit
        )));
    }
    for (field, value) in [
        ("region", query.region.as_deref()),
        ("role", query.role.as_deref()),
        ("environment", query.environment.as_deref()),
    ] {
        if let Some(value) = value {
            validate_filter_value(field, value)?;
        }
    }
    if let Some(status) = query.status.as_deref()
        && !matches!(
            status,
            "healthy" | "degraded" | "unreachable" | "stale" | "disabled" | "unknown"
        )
    {
        return Err(ApiError::bad_request("status is not supported"));
    }
    let (label_key, label_value) = query
        .label
        .as_deref()
        .map(parse_label_filter)
        .transpose()?
        .map_or((None, None), |(key, value)| (Some(key), Some(value)));
    let filter_hash = filter_hash(&query);
    let after = query
        .cursor
        .as_deref()
        .map(|cursor| decode_cursor(cursor, &state.cursor_key, "nodes", &filter_hash))
        .transpose()?;
    let fetch_limit = limit
        .checked_add(1)
        .ok_or_else(|| ApiError::bad_request("limit is too large"))?;
    let mut records = db(state.store.list_node_health_page(
        fetch_limit,
        &NodeListFilters {
            after_node_id: after.as_deref(),
            region: query.region.as_deref(),
            role: query.role.as_deref(),
            environment: query.environment.as_deref(),
            label_key,
            label_value,
            status: query.status.as_deref(),
        },
    ))?;
    let has_more = records.len() > limit as usize;
    records.truncate(limit as usize);
    let next_cursor = if has_more {
        records
            .last()
            .map(|record| {
                encode_cursor(
                    &CursorPayload {
                        version: 1,
                        resource: "nodes".to_string(),
                        after: record.node.node_id.clone(),
                        filter_hash: filter_hash.clone(),
                    },
                    &state.cursor_key,
                )
            })
            .transpose()?
    } else {
        None
    };
    let items = records.iter().map(health_node_to_json).collect::<Vec<_>>();
    let data = json!({
        "schema": "ocfleet.api.v1.page",
        "limit": limit,
        "count": items.len(),
        "next_cursor": next_cursor,
        "items": items,
    });
    conditional_json(&headers, data)
}

async fn health_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<HistoryQuery>, QueryRejection>,
) -> ApiResult<Response> {
    authorize(&state, &headers)?;
    let Query(query) =
        query.map_err(|_| ApiError::bad_request("invalid or unsupported query parameters"))?;
    validate_window(&query.from, &query.to).map_err(|e| ApiError::bad_request(e.to_string()))?;
    let limit = page_limit(query.limit, state.max_limit)?;
    if let Some(v) = query.node_id.as_deref() {
        validate_filter_value("node_id", v)?;
    }
    if let Some(v) = query.status.as_deref()
        && !matches!(
            v,
            "healthy" | "degraded" | "unreachable" | "stale" | "disabled" | "unknown"
        )
    {
        return Err(ApiError::bad_request("status is not supported"));
    }
    let hash = generic_filter_hash(
        &json!({"from":query.from,"to":query.to,"node_id":query.node_id,"status":query.status}),
    );
    let after = query
        .cursor
        .as_deref()
        .map(|c| decode_cursor(c, &state.cursor_key, "health-history", &hash))
        .transpose()?;
    let parts = after.as_deref().map(|v| split_after(v, 3)).transpose()?;
    let mut rows = db(state.store.list_health_history_page(
        limit + 1,
        &HistoryPageFilters {
            after: parts.as_ref().map(|p| (p[0], p[1], p[2])),
            node_id: query.node_id.as_deref(),
            status: query.status.as_deref(),
            from: &query.from,
            to: &query.to,
        },
    ))?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next = if more {
        rows.last()
            .map(|r| {
                encode_cursor(
                    &CursorPayload {
                        version: 1,
                        resource: "health-history".into(),
                        after: format!(
                            "{}|{}|{}",
                            r.snapshot.computed_at, r.snapshot.node_id, r.evaluation_id
                        ),
                        filter_hash: hash.clone(),
                    },
                    &state.cursor_key,
                )
            })
            .transpose()?
    } else {
        None
    };
    let items=rows.iter().map(|r|json!({"evaluation_id":r.evaluation_id,"node_id":r.snapshot.node_id,"endpoint_id":r.snapshot.endpoint_id,"computed_at":r.snapshot.computed_at,"status":r.snapshot.status,"freshness_seconds":r.snapshot.freshness_seconds,"last_success_at":r.snapshot.last_success_at,"last_failure_at":r.snapshot.last_failure_at,"last_error_code":r.snapshot.last_error_code})).collect::<Vec<_>>();
    conditional_json(&headers, page_data(limit, next, items))
}

async fn alerts(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<AlertsQuery>, QueryRejection>,
) -> ApiResult<Response> {
    authorize(&state, &headers)?;
    let Query(query) =
        query.map_err(|_| ApiError::bad_request("invalid or unsupported query parameters"))?;
    validate_window(&query.from, &query.to).map_err(|e| ApiError::bad_request(e.to_string()))?;
    let limit = page_limit(query.limit, state.max_limit)?;
    for (field, value) in [
        ("node_id", query.node_id.as_deref()),
        ("reason", query.reason.as_deref()),
    ] {
        if let Some(v) = value {
            validate_filter_value(field, v)?;
        }
    }
    if let Some(v) = query.state.as_deref()
        && !matches!(v, "open" | "silenced" | "resolved")
    {
        return Err(ApiError::bad_request("state is not supported"));
    }
    if let Some(v) = query.severity.as_deref()
        && !matches!(v, "warning" | "critical")
    {
        return Err(ApiError::bad_request("severity is not supported"));
    }
    let hash = generic_filter_hash(
        &json!({"from":query.from,"to":query.to,"state":query.state,"severity":query.severity,"node_id":query.node_id,"reason":query.reason}),
    );
    let after = query
        .cursor
        .as_deref()
        .map(|c| decode_cursor(c, &state.cursor_key, "alerts", &hash))
        .transpose()?;
    let parts = after.as_deref().map(|v| split_after(v, 2)).transpose()?;
    let mut rows = db(state.store.list_alert_page(
        limit + 1,
        &AlertPageFilters {
            after: parts.as_ref().map(|p| (p[0], p[1])),
            state: query.state.as_deref(),
            severity: query.severity.as_deref(),
            node_id: query.node_id.as_deref(),
            reason: query.reason.as_deref(),
            from: &query.from,
            to: &query.to,
        },
    ))?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next = if more {
        rows.last()
            .map(|r| {
                encode_cursor(
                    &CursorPayload {
                        version: 1,
                        resource: "alerts".into(),
                        after: format!("{}|{}", r.last_seen_at, r.alert_id),
                        filter_hash: hash.clone(),
                    },
                    &state.cursor_key,
                )
            })
            .transpose()?
    } else {
        None
    };
    let items = rows.iter().map(alert_to_json).collect();
    conditional_json(&headers, page_data(limit, next, items))
}

async fn alert(
    State(state): State<AppState>,
    Path(lookup): Path<String>,
    headers: HeaderMap,
    query: Result<Query<EmptyQuery>, QueryRejection>,
) -> ApiResult<Response> {
    authorize(&state, &headers)?;
    query.map_err(|_| ApiError::bad_request("query parameters are not supported"))?;
    validate_lookup(&lookup)?;
    let record = db(state.store.get_alert(&lookup))?
        .ok_or_else(|| ApiError::not_found(format!("alert not found: {lookup}")))?;
    conditional_json(
        &headers,
        json!({"schema":"ocfleet.api.v1.alert","item":alert_to_json(&record)}),
    )
}

fn page_limit(value: Option<u64>, max: u64) -> ApiResult<u64> {
    let v = value.unwrap_or(DEFAULT_LIMIT.min(max));
    if v == 0 || v > max {
        Err(ApiError::bad_request(format!(
            "limit must be between 1 and {max}"
        )))
    } else {
        Ok(v)
    }
}
fn generic_filter_hash(value: &Value) -> String {
    hex(&Sha256::digest(
        serde_json::to_vec(value).expect("filter serializes"),
    ))
}
fn split_after(value: &str, count: usize) -> ApiResult<Vec<&str>> {
    let parts = value.split('|').collect::<Vec<_>>();
    if parts.len() != count || parts.iter().any(|v| v.is_empty()) {
        Err(ApiError::invalid_cursor("cursor position is invalid"))
    } else {
        Ok(parts)
    }
}
fn page_data(limit: u64, next: Option<String>, items: Vec<Value>) -> Value {
    json!({"schema":"ocfleet.api.v1.page","limit":limit,"count":items.len(),"next_cursor":next,"items":items})
}

fn validate_filter_value(field: &str, value: &str) -> ApiResult<()> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@'));
    if valid {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!("{field} is invalid")))
    }
}

fn validate_lookup(value: &str) -> ApiResult<()> {
    let valid = !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'));
    if valid {
        Ok(())
    } else {
        Err(ApiError::bad_request("alert lookup is invalid"))
    }
}

fn parse_label_filter(value: &str) -> ApiResult<(&str, &str)> {
    let (key, value) = value
        .split_once('=')
        .ok_or_else(|| ApiError::bad_request("label must use key=value"))?;
    validate_label_json(&json!({key:value}), "label").map_err(ApiError::bad_request)?;
    Ok((key, value))
}

fn filter_hash(query: &NodesQuery) -> String {
    let canonical = json!({
        "region": query.region,
        "role": query.role,
        "environment": query.environment,
        "label": query.label,
        "status": query.status,
    });
    hex(&Sha256::digest(
        serde_json::to_vec(&canonical).expect("query filter serializes"),
    ))
}

fn encode_cursor(payload: &CursorPayload, key: &[u8; 32]) -> ApiResult<String> {
    let payload = serde_json::to_vec(payload)
        .map_err(|_| ApiError::invalid_cursor("cursor encoding failed"))?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload);
    let signature = hex(&hmac_sha256(key, encoded.as_bytes()));
    Ok(format!("{encoded}.{signature}"))
}

fn decode_cursor(
    cursor: &str,
    key: &[u8; 32],
    resource: &str,
    filter_hash: &str,
) -> ApiResult<String> {
    if cursor.len() > MAX_CURSOR_BYTES {
        return Err(ApiError::invalid_cursor("cursor is too large"));
    }
    let (encoded, supplied_signature) = cursor
        .split_once('.')
        .ok_or_else(|| ApiError::invalid_cursor("cursor is malformed"))?;
    let expected_signature = hex(&hmac_sha256(key, encoded.as_bytes()));
    if !constant_time_eq(supplied_signature.as_bytes(), expected_signature.as_bytes()) {
        return Err(ApiError::invalid_cursor("cursor signature is invalid"));
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ApiError::invalid_cursor("cursor payload is invalid"))?;
    let payload: CursorPayload = serde_json::from_slice(&bytes)
        .map_err(|_| ApiError::invalid_cursor("cursor payload is invalid"))?;
    if payload.version != 1
        || payload.resource != resource
        || payload.filter_hash != filter_hash
        || payload.after.is_empty()
        || payload.after.len() > 256
    {
        return Err(ApiError::invalid_cursor("cursor does not match this query"));
    }
    Ok(payload.after)
}

fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut inner_key = [0x36_u8; 64];
    let mut outer_key = [0x5c_u8; 64];
    for (index, byte) in key.iter().enumerate() {
        inner_key[index] ^= byte;
        outer_key[index] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_key);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_key);
    outer.update(inner);
    outer.finalize().into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String succeeds");
    }
    output
}

fn conditional_json(headers: &HeaderMap, data: Value) -> ApiResult<Response> {
    let etag = format!(
        "\"{}\"",
        hex(&Sha256::digest(
            serde_json::to_vec(&data).map_err(|_| ApiError::internal())?
        ))
    );
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|candidate| candidate.trim() == etag))
    {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        set_cache_headers(&mut response, &etag)?;
        return Ok(response);
    }
    let body = json!({
        "generated_at": now_rfc3339(),
        "data": data,
    });
    let mut response = axum::Json(body).into_response();
    set_cache_headers(&mut response, &etag)?;
    Ok(response)
}

fn set_cache_headers(response: &mut Response, etag: &str) -> ApiResult<()> {
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(etag).map_err(|_| ApiError::internal())?,
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=0, must-revalidate"),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_cursor_rejects_tampering_and_filter_reuse() {
        let key = [7_u8; 32];
        let cursor = encode_cursor(
            &CursorPayload {
                version: 1,
                resource: "nodes".to_string(),
                after: "node-a".to_string(),
                filter_hash: "filters-a".to_string(),
            },
            &key,
        )
        .expect("cursor");
        assert_eq!(
            decode_cursor(&cursor, &key, "nodes", "filters-a").expect("decode"),
            "node-a"
        );
        let mut tampered = cursor.into_bytes();
        tampered[0] ^= 1;
        let tampered = String::from_utf8(tampered).expect("ASCII cursor");
        assert!(decode_cursor(&tampered, &key, "nodes", "filters-a").is_err());
        assert!(
            decode_cursor(
                &encode_cursor(
                    &CursorPayload {
                        version: 1,
                        resource: "nodes".to_string(),
                        after: "node-a".to_string(),
                        filter_hash: "filters-a".to_string(),
                    },
                    &key
                )
                .expect("cursor"),
                &key,
                "nodes",
                "filters-b"
            )
            .is_err()
        );
    }
}
