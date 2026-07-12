use anyhow::{Context, bail};
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::audit::JsonlAuditWriter;
use crate::metrics::{AgentMetrics, CONTENT_TYPE};
use crate::nonce::NonceCache;
use crate::private_file;

const MIN_TOKEN_BYTES: usize = 32;
const MAX_TOKEN_BYTES: usize = 4_096;

#[derive(Clone)]
pub struct AgentMetricsHttpState {
    metrics: Arc<AgentMetrics>,
    audit: JsonlAuditWriter,
    nonce_cache: Arc<Mutex<NonceCache>>,
    auth_digest: Option<[u8; 32]>,
}

impl AgentMetricsHttpState {
    pub fn new(
        metrics: Arc<AgentMetrics>,
        audit: JsonlAuditWriter,
        nonce_cache: Arc<Mutex<NonceCache>>,
        auth_token_file: Option<&Path>,
    ) -> anyhow::Result<Self> {
        let auth_digest = auth_token_file.map(read_token_digest).transpose()?;
        Ok(Self {
            metrics,
            audit,
            nonce_cache,
            auth_digest,
        })
    }
}

pub fn validate_metrics_listener(
    listen: SocketAddr,
    auth_token_file: Option<&Path>,
) -> anyhow::Result<()> {
    if !listen.ip().is_loopback() && auth_token_file.is_none() {
        bail!("--metrics-auth-token-file is required when --metrics-listen is not loopback");
    }
    Ok(())
}

pub async fn serve_metrics(
    listener: tokio::net::TcpListener,
    state: AgentMetricsHttpState,
) -> anyhow::Result<()> {
    axum::serve(listener, build_metrics_router(state)).await?;
    Ok(())
}

pub fn build_metrics_router(state: AgentMetricsHttpState) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .fallback(StatusCode::NOT_FOUND)
        .with_state(state)
        .layer(middleware::from_fn(security_headers))
}

async fn metrics(State(state): State<AgentMetricsHttpState>, request: Request) -> Response {
    if !authorized(&state, &request) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let nonce_cache_size = match state.nonce_cache.lock() {
        Ok(cache) => u64::try_from(cache.live_len()).unwrap_or(u64::MAX),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let body = state
        .metrics
        .render(nonce_cache_size, &state.audit.metrics_snapshot());
    let mut response = body.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE));
    response
}

async fn security_headers(request: Request, next: Next) -> Response {
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

fn authorized(state: &AgentMetricsHttpState, request: &Request) -> bool {
    let Some(expected) = &state.auth_digest else {
        return true;
    };
    let Some(token) = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    constant_time_eq(expected, &digest(token.as_bytes()))
}

fn read_token_digest(path: &Path) -> anyhow::Result<[u8; 32]> {
    let file = private_file::open_existing_private_read(path)
        .context("failed to read private agent metrics auth token")?;
    let mut text = String::new();
    file.take(u64::try_from(MAX_TOKEN_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_string(&mut text)?;
    if text.len() > MAX_TOKEN_BYTES {
        bail!("agent metrics auth token is too large");
    }
    let token = text.trim_end_matches(['\r', '\n']);
    if !(MIN_TOKEN_BYTES..=MAX_TOKEN_BYTES).contains(&token.len())
        || token
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        bail!("agent metrics auth token must be 32-4096 non-whitespace bytes");
    }
    Ok(digest(token.as_bytes()))
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tower::ServiceExt;

    const TOKEN: &str = "abcdefghijklmnopqrstuvwxyz123456";

    fn state(token_path: Option<&Path>) -> (tempfile::TempDir, AgentMetricsHttpState) {
        let dir = tempfile::tempdir().expect("temp dir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod temp dir");
        let audit = JsonlAuditWriter::with_queue_capacity(dir.path().join("audit.jsonl"), 16);
        let state = AgentMetricsHttpState::new(
            Arc::new(AgentMetrics::default()),
            audit,
            Arc::new(Mutex::new(NonceCache::with_limits(16, 8))),
            token_path,
        )
        .expect("metrics state");
        (dir, state)
    }

    #[tokio::test]
    async fn metrics_route_is_bounded_and_bearer_protected() {
        let token_dir = tempfile::tempdir().expect("token dir");
        fs::set_permissions(token_dir.path(), fs::Permissions::from_mode(0o700))
            .expect("chmod token dir");
        let token_path = token_dir.path().join("metrics.token");
        fs::write(&token_path, format!("{TOKEN}\n")).expect("write token");
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).expect("chmod token");
        let (_dir, state) = state(Some(&token_path));
        let router = build_metrics_router(state);

        let unauthorized = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], CONTENT_TYPE);
        let body = String::from_utf8(
            to_bytes(response.into_body(), 16 * 1024)
                .await
                .expect("body")
                .to_vec(),
        )
        .expect("utf8");
        assert!(body.contains("ocfleet_agent_nonce_cache_size"));
        assert!(body.len() < 8_192);
        for forbidden in [
            "endpoint_id",
            "request_id",
            "session_id",
            "client_ip",
            "token",
            "path",
        ] {
            assert!(!body.contains(forbidden));
        }
    }

    #[test]
    fn non_loopback_listener_requires_auth() {
        let listen: SocketAddr = "0.0.0.0:9090".parse().expect("listen");
        assert!(validate_metrics_listener(listen, None).is_err());
        assert!(validate_metrics_listener(listen, Some(Path::new("metrics.token"))).is_ok());
    }
}
