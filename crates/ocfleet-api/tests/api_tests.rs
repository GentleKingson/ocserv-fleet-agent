use std::net::SocketAddr;
use std::path::Path;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use ocfleet_api::{ApiCli, ApiConfig, AppState, RedactionMode, build_router};
use ocfleet_cli::audit::AuditEvent;
use ocfleet_cli::store::{
    AlertEventRecord, HealthSnapshotRecord, NodeInsert, ObservabilityJobRecord,
    ObservabilityRunInsert, ProbeObservationInsert, Store,
};
use rusqlite::Connection;
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

const TOKEN: &str = "abcdefghijklmnopqrstuvwxyz123456";

#[tokio::test]
async fn get_routes_return_fixed_shapes() {
    let fixture = Fixture::new();
    let router = fixture.router(None);

    let (_, healthz) = json_request(router.clone(), Method::GET, "/healthz", None).await;
    assert_eq!(healthz["status"], "ok");
    assert!(healthz.get("generated_at").is_some());

    let (_, summary) = json_request(router.clone(), Method::GET, "/health/summary", None).await;
    assert!(summary.get("generated_at").is_some());
    assert_eq!(summary["summary"]["total"], 1);

    let (_, nodes) = json_request(router.clone(), Method::GET, "/health/nodes", None).await;
    assert_list_shape(&nodes, 1);

    let (_, node) = json_request(router.clone(), Method::GET, "/health/nodes/node-a", None).await;
    assert_eq!(node["item"]["node_id"], "node-a");

    let (_, jobs) = json_request(router.clone(), Method::GET, "/jobs", None).await;
    assert_list_shape(&jobs, 1);

    let (_, job) = json_request(router.clone(), Method::GET, "/jobs/job-a", None).await;
    assert_eq!(job["item"]["name"], "daily checks");

    let (_, runs) = json_request(router.clone(), Method::GET, "/runs?limit=10", None).await;
    assert_list_shape(&runs, 1);

    let (_, run) = json_request(router.clone(), Method::GET, "/runs/run-a", None).await;
    assert_eq!(run["item"]["observation_count"], 1);

    let (_, observations) =
        json_request(router.clone(), Method::GET, "/observations?limit=10", None).await;
    assert_list_shape(&observations, 1);

    let (_, observation) =
        json_request(router.clone(), Method::GET, "/observations/obs-a", None).await;
    assert_eq!(observation["item"]["method"], "probe.controller.ping");

    let (_, alerts) = json_request(
        router.clone(),
        Method::GET,
        "/alerts?state=open&limit=10",
        None,
    )
    .await;
    assert_list_shape(&alerts, 1);

    let (_, alert) = json_request(
        router.clone(),
        Method::GET,
        "/alerts/node:node-a:node_unreachable",
        None,
    )
    .await;
    assert_eq!(alert["item"]["severity"], "critical");

    let (_, audit) = json_request(
        router,
        Method::GET,
        "/audit/export?from=2026-07-09T00:00:00Z&to=2026-07-10T00:00:00Z&max_rows=10",
        None,
    )
    .await;
    assert_list_shape(&audit, 1);
}

#[tokio::test]
async fn forbidden_methods_do_not_write() {
    let fixture = Fixture::new();
    let before = table_counts(&fixture.database);
    let router = fixture.router(None);

    for (method, uri) in [
        (Method::POST, "/rpc"),
        (Method::POST, "/jobs/job-a/run"),
        (Method::POST, "/alerts/alert-a/resolve"),
        (Method::POST, "/alerts/alert-a/silence"),
        (Method::PUT, "/jobs/job-a"),
        (Method::PATCH, "/alerts/alert-a"),
        (Method::DELETE, "/alerts/alert-a"),
    ] {
        let (status, _) = text_request(router.clone(), method, uri, None).await;
        assert!(matches!(
            status,
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
        ));
    }

    assert_eq!(table_counts(&fixture.database), before);
}

#[tokio::test]
async fn authenticated_viewer_token_has_no_mutating_routes() {
    let fixture = Fixture::new();
    let token_file = fixture.write_token_file(TOKEN);
    let router = fixture.router(Some(token_file));
    let before = table_counts(&fixture.database);

    for (method, uri) in [
        (Method::POST, "/jobs/job-a/run"),
        (Method::POST, "/alerts/alert-a/resolve"),
        (Method::POST, "/alerts/alert-a/silence"),
        (Method::PUT, "/jobs/job-a"),
        (Method::PATCH, "/alerts/alert-a"),
        (Method::DELETE, "/alerts/alert-a"),
    ] {
        let (status, _) = text_request(router.clone(), method, uri, Some(TOKEN)).await;
        assert!(matches!(
            status,
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
        ));
    }

    assert_eq!(table_counts(&fixture.database), before);
}

#[tokio::test]
async fn read_only_queries_do_not_mutate_sqlite_state() {
    let fixture = Fixture::new();
    let before = table_counts(&fixture.database);
    let router = fixture.router(None);

    for uri in [
        "/health/summary",
        "/health/nodes",
        "/jobs",
        "/runs?limit=10",
        "/observations?limit=10",
        "/alerts?limit=10",
        "/audit/export?from=2026-07-09T00:00:00Z&to=2026-07-10T00:00:00Z&max_rows=10",
    ] {
        let (status, _) = json_request(router.clone(), Method::GET, uri, None).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
    }

    assert_eq!(table_counts(&fixture.database), before);
}

#[test]
fn non_loopback_without_auth_token_file_fails_closed() {
    let fixture = Fixture::new();
    let cli = ApiCli {
        database: fixture.database.clone(),
        read_only: true,
        listen: "0.0.0.0:8080".parse::<SocketAddr>().expect("addr"),
        max_limit: 1_000,
        redact: RedactionMode::Default,
        auth_token_file: None,
    };
    let err = ApiConfig::from_cli(cli).expect_err("must reject non-loopback no-auth");
    assert!(err.to_string().contains("--auth-token-file is required"));
}

#[test]
fn read_only_flag_is_required() {
    let fixture = Fixture::new();
    let cli = ApiCli {
        database: fixture.database.clone(),
        read_only: false,
        listen: "127.0.0.1:8080".parse::<SocketAddr>().expect("addr"),
        max_limit: 1_000,
        redact: RedactionMode::Default,
        auth_token_file: None,
    };
    let err = ApiConfig::from_cli(cli).expect_err("must reject missing read-only flag");
    assert!(err.to_string().contains("--read-only is required"));
}

#[tokio::test]
async fn bearer_auth_accepts_configured_token_and_rejects_others() {
    let fixture = Fixture::new();
    let token_file = fixture.write_token_file(TOKEN);
    let router = fixture.router(Some(token_file));

    let (status, _) = json_request(router.clone(), Method::GET, "/healthz", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = json_request(router.clone(), Method::GET, "/healthz", Some("wrong")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = json_request(router, Method::GET, "/healthz", Some(TOKEN)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["auth_enabled"], true);
}

#[tokio::test]
async fn limit_bounds_are_enforced() {
    let fixture = Fixture::new();
    let router = fixture.router(None);

    let (status, body) = json_request(
        router.clone(),
        Method::GET,
        "/observations?limit=1001",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error_code"], "BAD_REQUEST");

    let (status, _) =
        json_request(router.clone(), Method::GET, "/observations?limit=0", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = json_request(router, Method::GET, "/runs?limit=1", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["limit"], 1);
}

#[tokio::test]
async fn redaction_removes_forbidden_observation_and_audit_fields() {
    let fixture = Fixture::new();
    let router = fixture.router(None);

    let (_, observation) =
        json_request(router.clone(), Method::GET, "/observations/obs-a", None).await;
    let observation_text = serde_json::to_string(&observation).expect("json");
    assert!(!observation_text.contains("alice"));
    assert!(!observation_text.contains("raw_body"));
    assert!(!observation_text.contains("raw-secret"));

    let (_, audit) = json_request(
        router,
        Method::GET,
        "/audit/export?from=2026-07-09T00:00:00Z&to=2026-07-10T00:00:00Z&max_rows=10&redact=strict",
        None,
    )
    .await;
    let audit_text = serde_json::to_string(&audit).expect("json");
    assert!(!audit_text.contains("super-secret"));
    assert!(!audit_text.contains("Bearer abc"));
    assert!(audit_text.contains("sha256:"));
    assert_eq!(audit["items"][0]["detail"]["token"], "<redacted>");
}

#[tokio::test]
async fn audit_export_rejects_oversized_windows_and_rows() {
    let fixture = Fixture::new();
    let router = fixture.router(None);

    let (status, body) = json_request(
        router.clone(),
        Method::GET,
        "/audit/export?from=2026-01-01T00:00:00Z&to=2026-03-01T00:00:00Z&max_rows=10",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("31 days")
    );

    let (status, body) = json_request(
        router,
        Method::GET,
        "/audit/export?from=2026-07-09T00:00:00Z&to=2026-07-10T00:00:00Z&max_rows=1001",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("1000")
    );
}

#[tokio::test]
async fn dashboard_contains_no_mutating_route_wiring() {
    let fixture = Fixture::new();
    let router = fixture.router(None);
    let (status, body) = text_request(router, Method::GET, "/", None).await;
    assert_eq!(status, StatusCode::OK);
    for forbidden in ["POST", "PUT", "PATCH", "DELETE", "/rpc", "/jobs/{id}/run"] {
        assert!(!body.contains(forbidden), "dashboard contains {forbidden}");
    }
}

fn assert_list_shape(value: &Value, count: usize) {
    assert!(value.get("generated_at").is_some());
    assert!(value.get("limit").is_some());
    assert_eq!(value["count"], count);
    assert!(value["items"].is_array());
}

async fn json_request(
    router: Router,
    method: Method,
    uri: &str,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let (status, body) = text_request(router, method, uri, token).await;
    let value = serde_json::from_str(&body).unwrap_or_else(|err| {
        panic!("response body is not JSON: {err}; status={status}; body={body}")
    });
    (status, value)
}

async fn text_request(
    router: Router,
    method: Method,
    uri: &str,
    token: Option<&str>,
) -> (StatusCode, String) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = router
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        status,
        String::from_utf8(bytes.to_vec()).expect("utf8 body"),
    )
}

fn table_counts(path: &Path) -> Vec<i64> {
    let conn = Connection::open(path).expect("open db");
    [
        "nodes",
        "observability_jobs",
        "observability_runs",
        "probe_observations",
        "health_snapshots",
        "alert_events",
        "controller_audit_log",
    ]
    .iter()
    .map(|table| {
        conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .expect("count")
    })
    .collect()
}

struct Fixture {
    _dir: TempDir,
    database: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let database = dir.path().join("controller.sqlite");
        seed_database(&database);
        Self {
            _dir: dir,
            database,
        }
    }

    fn router(&self, auth_token_file: Option<std::path::PathBuf>) -> Router {
        let cli = ApiCli {
            database: self.database.clone(),
            read_only: true,
            listen: "127.0.0.1:0".parse::<SocketAddr>().expect("addr"),
            max_limit: 1_000,
            redact: RedactionMode::Default,
            auth_token_file,
        };
        let config = ApiConfig::from_cli(cli).expect("config");
        build_router(AppState::from_config(config))
    }

    fn write_token_file(&self, token: &str) -> std::path::PathBuf {
        let path = self._dir.path().join("api-token");
        std::fs::write(&path, format!("{token}\n")).expect("write token");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("permissions");
        }
        path
    }
}

fn seed_database(path: &Path) {
    let store = Store::open(path).expect("open store");
    store
        .add_node(&NodeInsert {
            node_id: "node-a".to_string(),
            endpoint_id: "endpoint-a".to_string(),
            name: "node-a".to_string(),
            region: "hk".to_string(),
            role: "ocserv".to_string(),
        })
        .expect("add node");
    store
        .insert_observability_job(&ObservabilityJobRecord {
            job_id: "job-a".to_string(),
            kind: "controller-ping".to_string(),
            selector_json: json!({"selector": "role=ocserv", "name": "daily checks"}),
            pair_selector_json: None,
            interval_seconds: 300,
            jitter_seconds: 0,
            timeout_ms: 5_000,
            enabled: true,
            next_run_at: Some("2026-07-09T00:00:00Z".to_string()),
            last_run_at: Some("2026-07-09T00:01:00Z".to_string()),
            created_at: "2026-07-09T00:00:00Z".to_string(),
            updated_at: "2026-07-09T00:01:00Z".to_string(),
        })
        .expect("insert job");
    store
        .insert_observability_run(&ObservabilityRunInsert {
            run_id: "run-a".to_string(),
            job_id: Some("job-a".to_string()),
            started_at: "2026-07-09T00:01:00Z".to_string(),
            finished_at: Some("2026-07-09T00:01:02Z".to_string()),
            status: "succeeded".to_string(),
            triggered_by: "scheduler.run.once".to_string(),
            summary_json: json!({"result_class": "scheduler_summary"}),
        })
        .expect("insert run");
    store
        .insert_probe_observation(&ProbeObservationInsert {
            observation_id: "obs-a".to_string(),
            run_id: Some("run-a".to_string()),
            node_id: Some("node-a".to_string()),
            endpoint_id: Some("endpoint-a".to_string()),
            method: "probe.controller.ping".to_string(),
            ok: Some(false),
            error_code: Some("ENDPOINT_NOT_ALLOWED".to_string()),
            duration_ms: Some(12),
            observed_at: "2026-07-09T00:01:02Z".to_string(),
            expires_at: None,
            result_class: "controller_rpc_summary".to_string(),
            summary_json: json!({
                "status": "failed",
                "username": "alice",
                "raw_body": "raw-secret"
            }),
        })
        .expect("insert observation");
    store
        .upsert_health_snapshot(&HealthSnapshotRecord {
            node_id: "node-a".to_string(),
            endpoint_id: Some("endpoint-a".to_string()),
            computed_at: "2026-07-09T00:02:00Z".to_string(),
            status: "unreachable".to_string(),
            freshness_seconds: Some(60),
            last_success_at: None,
            last_failure_at: Some("2026-07-09T00:01:02Z".to_string()),
            last_error_code: Some("ENDPOINT_NOT_ALLOWED".to_string()),
            degraded_methods_json: json!(["probe.controller.ping"]),
            summary_json: json!({"status": "unreachable", "raw_body": "hidden"}),
        })
        .expect("insert health");
    store
        .upsert_alert_event(&AlertEventRecord {
            alert_id: "alert-a".to_string(),
            dedupe_key: "node:node-a:node_unreachable".to_string(),
            node_id: Some("node-a".to_string()),
            severity: "critical".to_string(),
            state: "open".to_string(),
            reason_code: "NODE_UNREACHABLE".to_string(),
            first_seen_at: "2026-07-09T00:02:00Z".to_string(),
            last_seen_at: "2026-07-09T00:02:00Z".to_string(),
            last_sent_at: None,
            resolved_at: None,
            detail_json: json!({
                "methods": ["probe.controller.ping"],
                "summary": {
                    "status": "unreachable",
                    "username": "alice",
                    "last_error_code": "ENDPOINT_NOT_ALLOWED"
                }
            }),
        })
        .expect("insert alert");

    let mut event = AuditEvent::new("operator", "test.event");
    event.ts = "2026-07-09T00:03:00Z".to_string();
    event.node_id = Some("node-a".to_string());
    event.endpoint_id = Some("endpoint-a".to_string());
    event.method = Some("probe.controller.ping".to_string());
    event.request_id = Some("request-a".to_string());
    event.ok = Some(true);
    event.detail_json = json!({
        "token": "super-secret",
        "authorization": "Bearer abc",
        "node_id": "node-a",
        "result_class": "controller_rpc_summary"
    });
    store.insert_audit(&event).expect("insert audit");
}
