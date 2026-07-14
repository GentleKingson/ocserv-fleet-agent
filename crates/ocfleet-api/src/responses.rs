use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::Value;
use std::future::Future;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

tokio::task_local! {
    static REQUEST_ID: String;
}

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

    pub fn invalid_cursor(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "INVALID_CURSOR", message)
    }

    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "missing or invalid bearer token",
        )
    }

    pub fn forbidden() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "authenticated principal is not permitted for this route",
        )
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "NOT_FOUND", message)
    }

    pub fn method_not_allowed() -> Self {
        Self::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "METHOD_NOT_ALLOWED",
            "method not allowed; this API exposes read-only GET routes only",
        )
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
            request_id: REQUEST_ID
                .try_with(Clone::clone)
                .unwrap_or_else(|_| Uuid::new_v4().to_string()),
        }
    }
}

pub async fn with_request_id<F: Future>(request_id: String, future: F) -> F::Output {
    REQUEST_ID.scope(request_id, future).await
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status;
        let body = ApiErrorBody {
            generated_at: now_rfc3339(),
            error_code: self.error_code,
            message: self.message,
            request_id: self.request_id,
        };
        let mut response = (status, Json(body)).into_response();
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"ocfleet-api\""),
            );
        } else if status == StatusCode::METHOD_NOT_ALLOWED {
            response
                .headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        }
        response
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
