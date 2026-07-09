use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    error_code: &'static str,
    message: String,
    request_id: String,
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    generated_at: String,
    error_code: &'static str,
    message: String,
    request_id: String,
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "BAD_REQUEST", message)
    }

    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "missing or invalid bearer token",
        )
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "NOT_FOUND", message)
    }

    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "internal server error",
        )
    }

    fn new(status: StatusCode, error_code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            error_code,
            message: message.into(),
            request_id: Uuid::new_v4().to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ApiErrorBody {
            generated_at: now_rfc3339(),
            error_code: self.error_code,
            message: self.message,
            request_id: self.request_id,
        };
        (self.status, Json(body)).into_response()
    }
}

#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub generated_at: String,
    pub limit: u64,
    pub count: usize,
    pub items: Vec<Value>,
}

#[derive(Debug, Serialize)]
pub struct SingleResponse {
    pub generated_at: String,
    pub item: Value,
}

#[derive(Debug, Serialize)]
pub struct SummaryResponse {
    pub generated_at: String,
    pub summary: Value,
}

pub fn list_response(limit: u64, items: Vec<Value>) -> Json<ListResponse> {
    Json(ListResponse {
        generated_at: now_rfc3339(),
        limit,
        count: items.len(),
        items,
    })
}

pub fn single_response(item: Value) -> Json<SingleResponse> {
    Json(SingleResponse {
        generated_at: now_rfc3339(),
        item,
    })
}

pub fn summary_response(summary: Value) -> Json<SummaryResponse> {
    Json(SummaryResponse {
        generated_at: now_rfc3339(),
        summary,
    })
}

pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("RFC3339 formatting succeeds")
}
