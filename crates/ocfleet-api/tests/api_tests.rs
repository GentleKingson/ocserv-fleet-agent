use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::Path;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine as _;
use ocfleet_api::{ApiCli, ApiConfig, AppState, RedactionMode, build_router};
use ocfleet_cli::audit::AuditEvent;
use ocfleet_cli::backend::StoreWriter;
use ocfleet_cli::storage_payloads::{
    HealthDegradedMethodsPayloadV1, HealthSummaryPayloadV1, SchedulerSelectorPayloadV1,
};
use ocfleet_cli::store::{
    AlertEventRecord, CURRENT_SCHEMA_VERSION, HealthRollupRecord, HealthRollupWrite,
    HealthSnapshotRecord, HealthSnapshotWrite, NodeInsert, NodeMetadataRecord,
    ObservabilityJobRecord, ObservabilityRunInsert, ProbeObservationInsert, Store,
};
use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::ServiceExt;

const TOKEN: &str = "abcdefghijklmnopqrstuvwxyz123456";
const OPENAPI: &str = include_str!("../../../docs/api/openapi.yaml");
const ROUTES_SOURCE: &str = include_str!("../src/routes.rs");
const V1_ROUTES_SOURCE: &str = include_str!("../src/v1.rs");

#[test]
fn openapi_contract_is_get_only_and_matches_router_paths() {
    let spec: Value = serde_json::from_str(OPENAPI)
        .expect("OpenAPI file is valid JSON, which is also valid YAML 1.2");
    assert_eq!(spec["openapi"], "3.1.1");
    assert_eq!(
        spec["components"]["securitySchemes"]["BearerAuth"]["type"],
        "http"
    );
    assert_eq!(
        spec["components"]["securitySchemes"]["BearerAuth"]["scheme"],
        "bearer"
    );
    assert_eq!(
        spec["x-ocfleet-listener-auth"]["non_loopback"],
        "bearer-required-viewer-only"
    );
    assert_eq!(
        spec["components"]["schemas"]["ObservationMethods"]["maxItems"],
        16
    );
    for schema in [
        "HealthSummaryResponse",
        "HealthNodeListResponse",
        "HealthNodeResponse",
        "JobListResponse",
        "JobResponse",
        "RunListResponse",
        "RunResponse",
        "ObservationListResponse",
        "ObservationResponse",
        "AlertListResponse",
        "AlertResponse",
        "AuditListResponse",
        "HealthSloResponse",
        "ErrorResponse",
        "V1VersionReadinessEnvelope",
    ] {
        assert!(
            spec["components"]["schemas"].get(schema).is_some(),
            "missing explicit response schema: {schema}"
        );
    }

    assert_local_refs_resolve(&spec, &spec);

    let paths = spec["paths"].as_object().expect("paths object");
    let declared = paths.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = [
        "/",
        "/api/v1/fleet/summary",
        "/api/v1/version/readiness",
        "/api/v1/health/history",
        "/api/v1/alerts",
        "/api/v1/nodes",
        "/api/v1/nodes/{node_id}",
        "/api/v1/alerts/{dedupe_key_or_alert_id}",
        "/healthz",
        "/metrics",
        "/health/summary",
        "/health/nodes",
        "/health/nodes/{node_id}",
        "/health/slo",
        "/jobs",
        "/jobs/{job_id}",
        "/runs",
        "/runs/{run_id}",
        "/observations",
        "/observations/{observation_id}",
        "/alerts",
        "/alerts/{dedupe_key_or_alert_id}",
        "/audit/export",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    assert_eq!(declared, expected);

    let router_paths = [
        "/",
        "/healthz",
        "/metrics",
        "/health/summary",
        "/health/nodes",
        "/health/nodes/{node_id}",
        "/health/slo",
        "/jobs",
        "/jobs/{job_id}",
        "/runs",
        "/runs/{run_id}",
        "/observations",
        "/observations/{observation_id}",
        "/alerts",
        "/alerts/{lookup}",
        "/audit/export",
    ];
    assert_eq!(ROUTES_SOURCE.matches(".route(").count(), router_paths.len());
    for path in router_paths {
        assert!(
            ROUTES_SOURCE.contains(&format!(".route(\"{path}\", get(")),
            "router route missing from contract audit: {path}"
        );
    }
    for path in [
        "/fleet/summary",
        "/version/readiness",
        "/nodes",
        "/nodes/{node_id}",
        "/health/history",
        "/alerts",
        "/alerts/{lookup}",
    ] {
        assert!(
            V1_ROUTES_SOURCE.contains(&format!(".route(\"{path}\", get(")),
            "v1 router route missing from contract audit: {path}"
        );
    }

    for (path, item) in paths {
        let operations = item.as_object().expect("path item object");
        assert_eq!(
            operations.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["get"],
            "{path} must declare only GET"
        );
    }

    for forbidden in [
        "\"post\"",
        "\"put\"",
        "\"patch\"",
        "\"delete\"",
        "/rpc",
        "/jobs/{id}/run",
        "/alerts/{id}/resolve",
        "/alerts/{id}/silence",
    ] {
        assert!(
            !OPENAPI.contains(forbidden),
            "OpenAPI must not declare forbidden surface: {forbidden}"
        );
    }
}

fn assert_local_refs_resolve(value: &Value, root: &Value) {
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                assert!(reference.starts_with("#/"), "only local refs are allowed");
                assert!(
                    root.pointer(&reference[1..]).is_some(),
                    "unresolved OpenAPI ref: {reference}"
                );
            }
            for child in object.values() {
                assert_local_refs_resolve(child, root);
            }
        }
        Value::Array(values) => {
            for child in values {
                assert_local_refs_resolve(child, root);
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn get_routes_return_fixed_shapes() {
    let fixture = Fixture::new();
    let router = fixture.router(None);

    let (status, headers, _) = raw_request(router.clone(), Method::GET, "/healthz", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(
        headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
        "nosniff"
    );

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
async fn health_slo_is_bounded_read_only_and_preserves_missing_coverage() {
    let fixture = Fixture::new();
    let store = Store::open(&fixture.database).expect("open store");
    StoreWriter::write_health_rollups(
        &store,
        &HealthRollupWrite {
            operation_id: "health-rollup-00000000-0000-4000-8000-000000000099".into(),
            rows: vec![HealthRollupRecord {
                node_id: "node-a".into(),
                bucket_seconds: 300,
                bucket_start: "2026-07-11T00:00:00Z".into(),
                bucket_end: "2026-07-11T00:05:00Z".into(),
                input_watermark: "a".repeat(64),
                health_samples: 1,
                covered_slots: 1,
                expected_slots: 1,
                healthy_count: 1,
                degraded_count: 0,
                unreachable_count: 0,
                stale_count: 0,
                disabled_count: 0,
                unknown_count: 0,
                observation_count: 5,
                observation_error_count: 1,
                duration_sample_count: 5,
                duration_p50_ms: Some(10),
                duration_p95_ms: Some(50),
                cert_warning_count: 1,
                cert_critical_count: 0,
                fingerprint_sample_count: 2,
                fingerprint_change_count: 1,
                computed_at: "2026-07-11T00:05:00Z".into(),
            }],
        },
        "api-test",
    )
    .expect("write rollup");
    drop(store);
    let before = table_counts(&fixture.database);
    let router = fixture.router(None);
    let (status, body) = json_request(
        router.clone(),
        Method::GET,
        "/health/slo?window=24h&to=2026-07-12T00:00:00Z&node_id=node-a",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["schema"], "ocfleet.health_slo.v1");
    assert_eq!(body["projections"][0]["covered_slots"], 1);
    assert_eq!(body["projections"][0]["missing_slots"], 287);
    assert_eq!(
        body["projections"][0]["service_available_basis_points"],
        10_000
    );
    let (status, offset_body) = json_request(
        router,
        Method::GET,
        "/health/slo?window=24h&to=2026-07-12T08:00:00%2B08:00&node_id=node-a",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(offset_body["from"], "2026-07-11T00:00:00Z");
    assert_eq!(offset_body["to"], "2026-07-12T00:00:00Z");
    assert_eq!(offset_body["projections"], body["projections"]);
    let spec: Value = serde_json::from_str(OPENAPI).expect("OpenAPI JSON");
    let required = spec["components"]["schemas"]["HealthSloProjection"]["required"]
        .as_array()
        .expect("required projection keys")
        .iter()
        .map(|value| value.as_str().expect("required key"))
        .collect::<BTreeSet<_>>();
    let actual = body["projections"][0]
        .as_object()
        .expect("projection object")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual, required,
        "runtime projection must match OpenAPI exactly"
    );
    assert_eq!(table_counts(&fixture.database), before);
}

#[tokio::test]
async fn api_v1_nodes_cursor_filters_etag_and_correlation_are_stable() {
    let fixture = Fixture::new();
    let store = Store::open(&fixture.database).expect("store");
    store
        .add_node(
            &NodeInsert {
                node_id: "node-b".to_string(),
                endpoint_id: "endpoint-b".to_string(),
                name: "node-b".to_string(),
                region: "sg".to_string(),
                role: "ocserv".to_string(),
            },
            "api-test",
        )
        .expect("node-b");
    for (node_id, environment, color) in
        [("node-a", "prod", "blue"), ("node-b", "staging", "green")]
    {
        StoreWriter::write_node_metadata(
            &store,
            &NodeMetadataRecord {
                node_id: node_id.to_string(),
                environment: environment.to_string(),
                site: "site-1".to_string(),
                owner_team: "network".to_string(),
                service_tier: "tier-1".to_string(),
                labels_json: json!({"color":color}),
                expected_agent_version: Some("0.4.0".to_string()),
                updated_at: "2026-07-12T00:00:00Z".to_string(),
            },
            "api-test",
        )
        .expect("metadata");
    }
    drop(store);
    let router = fixture.router(None);

    let request = Request::builder()
        .uri("/api/v1/nodes?limit=1")
        .header("x-request-id", "client-request-1")
        .body(Body::empty())
        .expect("request");
    let response = router.clone().oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-request-id"], "client-request-1");
    let etag = response.headers()[header::ETAG].clone();
    let first_body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let value: Value = serde_json::from_slice(&first_body).expect("json");
    assert!(value.get("generated_at").is_none());
    let digest = Sha256::digest(&first_body);
    let expected_etag = format!(
        "\"{}\"",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    assert_eq!(etag, expected_etag);
    assert_eq!(value["data"]["count"], 1);
    assert_eq!(value["data"]["items"][0]["node_id"], "node-a");
    let cursor = value["data"]["next_cursor"].as_str().expect("next cursor");

    let repeated = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/nodes?limit=1")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(repeated.status(), StatusCode::OK);
    assert_eq!(repeated.headers()[header::ETAG], etag);
    assert_eq!(
        to_bytes(repeated.into_body(), usize::MAX)
            .await
            .expect("repeated body"),
        first_body,
        "the same strong ETag must identify byte-identical response bodies"
    );

    let (status, second) = json_request(
        router.clone(),
        Method::GET,
        &format!("/api/v1/nodes?limit=1&cursor={cursor}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["data"]["items"][0]["node_id"], "node-b");
    assert!(second["data"]["next_cursor"].is_null());

    let mut tampered = cursor.as_bytes().to_vec();
    tampered[0] ^= 1;
    let tampered = String::from_utf8(tampered).expect("cursor ASCII");
    let (status, error) = json_request(
        router.clone(),
        Method::GET,
        &format!("/api/v1/nodes?limit=1&cursor={tampered}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["error_code"], "INVALID_CURSOR");

    let (_, filtered) = json_request(
        router.clone(),
        Method::GET,
        "/api/v1/nodes?environment=prod&label=color%3Dblue&status=unreachable",
        None,
    )
    .await;
    assert_eq!(filtered["data"]["count"], 1);
    assert_eq!(filtered["data"]["items"][0]["node_id"], "node-a");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/nodes?limit=1")
                .header(header::IF_NONE_MATCH, etag)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body")
            .len(),
        0
    );
}

#[tokio::test]
async fn api_v1_cursor_survives_restart_and_current_previous_key_rotation() {
    let fixture = Fixture::new();
    Store::open(&fixture.database)
        .expect("store")
        .add_node(
            &NodeInsert {
                node_id: "node-b".to_string(),
                endpoint_id: "endpoint-b".to_string(),
                name: "node-b".to_string(),
                region: "sg".to_string(),
                role: "ocserv".to_string(),
            },
            "api-test",
        )
        .expect("node-b");
    let first_router = fixture.router(None);
    let (_, first_page) =
        json_request(first_router, Method::GET, "/api/v1/nodes?limit=1", None).await;
    let cursor = first_page["data"]["next_cursor"]
        .as_str()
        .expect("next cursor")
        .to_string();

    let restarted = fixture.router(None);
    let (status, second_page) = json_request(
        restarted,
        Method::GET,
        &format!("/api/v1/nodes?limit=1&cursor={cursor}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second_page["data"]["items"][0]["node_id"], "node-b");

    write_cursor_key_file(
        &fixture.cursor_key_file,
        "key-2",
        [2_u8; 32],
        Some(("key-1", [1_u8; 32])),
    );
    let rotated = fixture.router(None);
    let (status, _) = json_request(
        rotated,
        Method::GET,
        &format!("/api/v1/nodes?limit=1&cursor={cursor}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    write_cursor_key_file(&fixture.cursor_key_file, "key-2", [2_u8; 32], None);
    let retired = fixture.router(None);
    let (status, body) = json_request(
        retired,
        Method::GET,
        &format!("/api/v1/nodes?limit=1&cursor={cursor}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error_code"], "INVALID_CURSOR");
}

#[tokio::test]
async fn api_v1_node_metadata_fails_closed_on_contaminated_labels() {
    let fixture = Fixture::new();
    let store = Store::open(&fixture.database).expect("store");
    StoreWriter::write_node_metadata(
        &store,
        &NodeMetadataRecord {
            node_id: "node-a".to_string(),
            environment: "prod".to_string(),
            site: "hk-1".to_string(),
            owner_team: "network".to_string(),
            service_tier: "tier-1".to_string(),
            labels_json: json!({"color":"blue"}),
            expected_agent_version: None,
            updated_at: "2026-07-12T00:00:00Z".to_string(),
        },
        "api-test",
    )
    .expect("metadata");
    drop(store);
    Connection::open(&fixture.database)
        .expect("sqlite")
        .execute(
            "UPDATE node_metadata SET labels_json = ?1 WHERE node_id = 'node-a'",
            [r#"{"color":{"nested":"must-not-project"}}"#],
        )
        .expect("contaminate metadata");

    let (status, body) = json_request(
        fixture.router(None),
        Method::GET,
        "/api/v1/nodes/node-a",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error_code"], "INTERNAL_ERROR");
    assert!(!body.to_string().contains("must-not-project"));
}

#[tokio::test]
async fn api_v1_version_readiness_projects_distribution_alerts_and_no_actions() {
    let fixture = Fixture::new();
    let store = Store::open(&fixture.database).expect("store");
    StoreWriter::write_node_metadata(
        &store,
        &NodeMetadataRecord {
            node_id: "node-a".to_string(),
            environment: "prod".to_string(),
            site: "hk-1".to_string(),
            owner_team: "network".to_string(),
            service_tier: "tier-1".to_string(),
            labels_json: json!({}),
            expected_agent_version: Some("0.4.0".to_string()),
            updated_at: "2026-07-12T00:00:00Z".to_string(),
        },
        "api-test",
    )
    .expect("metadata");
    drop(store);
    Connection::open(&fixture.database)
        .expect("sqlite")
        .execute(
            "INSERT INTO node_capability_snapshots
             (node_id,endpoint_id,observed_at,status,agent_version,protocol_min,protocol_max,
              ocserv_snapshot_min,ocserv_snapshot_max,controlled_writes_compiled,
              controlled_writes_locally_enabled)
             VALUES ('node-a','endpoint-a','2026-07-12T00:01:00Z','compatible','0.3.0',1,1,2,2,0,0)",
            [],
        )
        .expect("capability snapshot");
    let before = table_counts(&fixture.database);
    let router = fixture.router(None);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/version/readiness")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let etag = response.headers()[header::ETAG].clone();
    let value: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body"),
    )
    .expect("json");
    assert_eq!(value["data"]["outdated_count"], 1);
    assert_eq!(value["data"]["blocked_count"], 1);
    assert_eq!(value["data"]["distribution"][0]["version"], "0.3.0");
    assert_eq!(
        value["data"]["alerts"][0]["reason_code"],
        "AGENT_VERSION_OUTDATED"
    );
    assert_eq!(value["data"]["actions_enabled"], false);
    let encoded = value.to_string();
    for forbidden in ["/etc/", "systemctl", "local_policy", "package_manager"] {
        assert!(!encoded.contains(forbidden));
    }

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/version/readiness")
                .header(header::IF_NONE_MATCH, etag)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(table_counts(&fixture.database), before);
}

#[tokio::test]
async fn api_v1_history_and_alerts_enforce_windows_and_reason_filters() {
    let fixture = Fixture::new();
    let router = fixture.router(None);
    let (status,history)=json_request(router.clone(),Method::GET,"/api/v1/health/history?from=2026-07-09T00:00:00Z&to=2026-07-10T00:00:00Z&node_id=node-a&status=unreachable&limit=1",None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(history["data"]["count"], 1);
    assert_eq!(history["data"]["items"][0]["status"], "unreachable");
    let (status,positive_offset)=json_request(router.clone(),Method::GET,"/api/v1/health/history?from=2026-07-09T08:00:00%2B08:00&to=2026-07-10T08:00:00%2B08:00&node_id=node-a&status=unreachable&limit=1",None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(positive_offset["data"], history["data"]);
    let (status,alerts)=json_request(router.clone(),Method::GET,"/api/v1/alerts?from=2026-07-09T00:00:00Z&to=2026-07-10T00:00:00Z&reason=NODE_UNREACHABLE&state=open",None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(alerts["data"]["count"], 1);
    assert_eq!(
        alerts["data"]["items"][0]["reason_code"],
        "NODE_UNREACHABLE"
    );
    let (status,negative_offset)=json_request(router.clone(),Method::GET,"/api/v1/alerts?from=2026-07-08T17:00:00-07:00&to=2026-07-09T17:00:00-07:00&reason=NODE_UNREACHABLE&state=open",None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(negative_offset["data"], alerts["data"]);
    for uri in [
        "/api/v1/health/history?from=2026-07-10T00:00:00Z&to=2026-07-09T00:00:00Z",
        "/api/v1/alerts?from=2026-07-09T00:00:00Z&to=2026-07-10T00:00:00Z&unknown=x",
        "/api/v1/alerts?from=2026-07-09T00:00:00Z&to=2026-07-10T00:00:00Z&reason=a&reason=b",
    ] {
        let (status, error) = json_request(router.clone(), Method::GET, uri, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        assert!(error["error_code"].is_string());
    }
}

#[tokio::test]
async fn api_v1_single_records_reject_queries_and_correlate_errors() {
    let fixture = Fixture::new();
    let router = fixture.router(None);
    let (_, node) = json_request(router.clone(), Method::GET, "/api/v1/nodes/node-a", None).await;
    assert_eq!(node["data"]["item"]["node_id"], "node-a");
    let (_, alert) = json_request(
        router.clone(),
        Method::GET,
        "/api/v1/alerts/node:node-a:node_unreachable",
        None,
    )
    .await;
    assert_eq!(alert["data"]["item"]["reason_code"], "NODE_UNREACHABLE");

    let request = Request::builder()
        .uri("/api/v1/fleet/summary?unknown=x")
        .header("x-request-id", "client-error-42")
        .body(Body::empty())
        .expect("request");
    let response = router.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["x-request-id"], "client-error-42");
    let body: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body"),
    )
    .expect("json");
    assert_eq!(body["request_id"], "client-error-42");
}

#[tokio::test]
async fn jobs_route_fails_closed_for_contaminated_versioned_selector() {
    let fixture = Fixture::new();
    Connection::open(&fixture.database)
        .expect("open fixture")
        .execute(
            "UPDATE observability_jobs SET selector_json = ?1 WHERE job_id = 'job-a'",
            [r#"{"schema":"ocfleet.scheduler.selector.v1","selector":"role=ocserv","name":null,"client_address":"10.0.0.2"}"#],
        )
        .expect("contaminate selector");

    let (status, _, body) = raw_request(fixture.router(None), Method::GET, "/jobs", None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!body.contains("10.0.0.2"));
}

#[tokio::test]
async fn health_route_fails_closed_for_contaminated_versioned_summary() {
    let fixture = Fixture::new();
    Connection::open(&fixture.database)
        .expect("open fixture")
        .execute(
            "UPDATE health_snapshots SET summary_json = ?1 WHERE node_id = 'node-a'",
            [r#"{"schema":"ocfleet.health.summary.v1","region":null,"role":null,"status":"unreachable","endpoint_status":null,"consecutive_failures":null,"client_address":"10.0.0.2"}"#],
        )
        .expect("contaminate health summary");

    let (status, _, body) =
        raw_request(fixture.router(None), Method::GET, "/health/nodes", None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!body.contains("10.0.0.2"));
}

#[tokio::test]
async fn observations_route_fails_closed_for_contaminated_versioned_summary() {
    let fixture = Fixture::new();
    Connection::open(&fixture.database)
        .expect("open fixture")
        .execute(
            "UPDATE probe_observations SET summary_json = ?1 WHERE observation_id = 'obs-a'",
            [r#"{"schema":"ocfleet.observation.summary.v1","result_class":"controller_rpc_summary","method":"probe.controller.ping","fields":{"message":"pong","client_address":"10.0.0.2"}}"#],
        )
        .expect("contaminate observation summary");

    let (status, _, body) = raw_request(
        fixture.router(None),
        Method::GET,
        "/observations?limit=10",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!body.contains("10.0.0.2"));
}

#[tokio::test]
async fn runs_route_fails_closed_for_contaminated_versioned_summary() {
    let fixture = Fixture::new();
    Connection::open(&fixture.database)
        .expect("open fixture")
        .execute(
            "UPDATE observability_runs SET summary_json = ?1 WHERE run_id = 'run-a'",
            [r#"{"schema":"ocfleet.run.summary.v1","result_class":"scheduler_summary","job_id":"job-a","kind":null,"status":"succeeded","triggered_by":"scheduler.run.once","observations":null,"failed_observations":null,"client_address":"10.0.0.2"}"#],
        )
        .expect("contaminate run summary");

    let (status, _, body) = raw_request(fixture.router(None), Method::GET, "/runs", None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!body.contains("10.0.0.2"));
}

#[tokio::test]
async fn alerts_route_fails_closed_for_contaminated_versioned_detail() {
    let fixture = Fixture::new();
    Connection::open(&fixture.database)
        .expect("open fixture")
        .execute(
            "UPDATE alert_events SET detail_json = ?1 WHERE alert_id = 'alert-a'",
            [r#"{"schema":"ocfleet.alert.detail.v1","methods":["probe.controller.ping"],"summary":{"status":"unreachable","client_address":"10.0.0.2"},"silenced_until":null,"silence_reason":null,"resolve_reason":null}"#],
        )
        .expect("contaminate alert detail");

    let (status, _, body) =
        raw_request(fixture.router(None), Method::GET, "/alerts?limit=10", None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!body.contains("10.0.0.2"));
}

#[tokio::test]
async fn audit_route_fails_closed_for_contaminated_versioned_detail() {
    let fixture = Fixture::new();
    let conn = Connection::open(&fixture.database).expect("open fixture");
    let raw: String = conn
        .query_row(
            "SELECT detail_json FROM controller_audit_log WHERE event = 'test.event'",
            [],
            |row| row.get(0),
        )
        .expect("load audit detail");
    let mut detail: Value = serde_json::from_str(&raw).expect("parse audit detail");
    detail["_audit"]["client_address"] = json!("10.0.0.2");
    conn.execute(
        "UPDATE controller_audit_log SET detail_json = ?1 WHERE event = 'test.event'",
        [detail.to_string()],
    )
    .expect("contaminate audit detail");

    let (status, _, body) = raw_request(
        fixture.router(None),
        Method::GET,
        "/audit/export?from=2026-07-09T00:00:00Z&to=2026-07-10T00:00:00Z&max_rows=10",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!body.contains("10.0.0.2"));
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
        let (status, body) = json_request(router.clone(), method, uri, None).await;
        assert!(matches!(
            status,
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
        ));
        assert!(matches!(
            body["error_code"].as_str(),
            Some("NOT_FOUND" | "METHOD_NOT_ALLOWED")
        ));
        assert_error_shape(&body);
    }

    let (status, headers, _) = raw_request(router, Method::POST, "/jobs", None).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(headers.get(header::ALLOW).unwrap(), "GET, HEAD");

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
        let (status, body) = json_request(router.clone(), method, uri, Some(TOKEN)).await;
        assert!(matches!(
            status,
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
        ));
        assert_error_shape(&body);
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
        cursor_key_file: Some(fixture.cursor_key_file.clone()),
    };
    let err = ApiConfig::from_cli(cli).expect_err("must reject non-loopback no-auth");
    assert!(err.to_string().contains("--auth-token-file is required"));
}

#[test]
fn max_limit_is_bounded_at_startup() {
    let fixture = Fixture::new();
    for max_limit in [0, 10_001] {
        let cli = ApiCli {
            database: fixture.database.clone(),
            read_only: true,
            listen: "127.0.0.1:8080".parse::<SocketAddr>().expect("addr"),
            max_limit,
            redact: RedactionMode::Default,
            auth_token_file: None,
            cursor_key_file: Some(fixture.cursor_key_file.clone()),
        };
        let err = ApiConfig::from_cli(cli).expect_err("must reject unsafe max limit");
        assert!(err.to_string().contains("between 1 and 10000"));
    }
}

#[test]
fn startup_validation_requires_the_current_complete_schema() {
    let fixture = Fixture::new();
    fixture
        .state(None)
        .validate_startup()
        .expect("current schema");

    let conn = Connection::open(&fixture.database).expect("open db");
    conn.execute(
        "DELETE FROM schema_migrations WHERE version = ?1",
        [CURRENT_SCHEMA_VERSION],
    )
    .expect("downgrade migration marker");
    drop(conn);

    let err = fixture
        .state(None)
        .validate_startup()
        .expect_err("old schema must fail closed");
    assert!(err.to_string().contains("schema version"));
    assert!(
        err.to_string()
            .contains(&CURRENT_SCHEMA_VERSION.to_string())
    );
}

#[test]
fn startup_validation_rejects_missing_api_tables() {
    let fixture = Fixture::new();
    let conn = Connection::open(&fixture.database).expect("open db");
    conn.execute("DROP TABLE alert_events", [])
        .expect("drop required table");
    drop(conn);

    let err = fixture
        .state(None)
        .validate_startup()
        .expect_err("missing table must fail closed");
    assert!(err.to_string().contains("alert_events"));
}

#[cfg(unix)]
#[test]
fn startup_validation_rejects_symlink_and_world_readable_databases() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let fixture = Fixture::new();
    let link = fixture._dir.path().join("controller-link.sqlite");
    symlink(&fixture.database, &link).expect("symlink database");
    let err = state_for_database(link)
        .validate_startup()
        .expect_err("symlink database must fail closed");
    assert!(err.to_string().contains("private-file validation"));

    std::fs::set_permissions(&fixture.database, std::fs::Permissions::from_mode(0o644))
        .expect("chmod database");
    let err = fixture
        .state(None)
        .validate_startup()
        .expect_err("world-readable database must fail closed");
    assert!(err.to_string().contains("private-file validation"));
}

#[cfg(unix)]
#[test]
fn startup_validation_rejects_unsafe_sqlite_sidecars() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let wal = sqlite_sidecar_path(&fixture.database, "-wal");
    std::fs::write(&wal, b"unsafe sidecar").expect("write sidecar");
    std::fs::set_permissions(&wal, std::fs::Permissions::from_mode(0o644)).expect("chmod sidecar");
    let err = fixture
        .state(None)
        .validate_startup()
        .expect_err("unsafe sidecar must fail closed");
    assert!(err.to_string().contains("private-file validation"));
}

#[cfg(unix)]
#[test]
fn startup_validation_prepares_private_fixed_sqlite_sidecars() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fixture = Fixture::new();
    for suffix in ["-wal", "-shm"] {
        let sidecar = sqlite_sidecar_path(&fixture.database, suffix);
        match std::fs::remove_file(&sidecar) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => panic!("remove stale sidecar: {err}"),
        }
    }

    fixture
        .state(None)
        .validate_startup()
        .expect("prepare private sidecars");
    for suffix in ["-wal", "-shm"] {
        let metadata = std::fs::metadata(sqlite_sidecar_path(&fixture.database, suffix))
            .expect("sidecar metadata");
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o077, 0);
        assert_eq!(metadata.nlink(), 1);
    }
}

#[cfg(unix)]
#[test]
fn startup_validation_rejects_symlinked_sqlite_sidecars() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let fixture = Fixture::new();
    let origin = fixture._dir.path().join("sidecar-target");
    std::fs::write(&origin, b"symlinked sidecar").expect("write target");
    std::fs::set_permissions(&origin, std::fs::Permissions::from_mode(0o600))
        .expect("chmod target");
    let wal = sqlite_sidecar_path(&fixture.database, "-wal");
    symlink(&origin, &wal).expect("symlink sidecar");
    let err = fixture
        .state(None)
        .validate_startup()
        .expect_err("symlinked sidecar must fail closed");
    assert!(err.to_string().contains("private-file validation"));
}

#[cfg(unix)]
#[test]
fn startup_validation_rejects_hardlinked_sqlite_sidecars() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let origin = fixture._dir.path().join("sidecar-origin");
    std::fs::write(&origin, b"hardlinked sidecar").expect("write origin");
    std::fs::set_permissions(&origin, std::fs::Permissions::from_mode(0o600))
        .expect("chmod origin");
    let shm = sqlite_sidecar_path(&fixture.database, "-shm");
    std::fs::hard_link(&origin, &shm).expect("hardlink sidecar");
    let err = fixture
        .state(None)
        .validate_startup()
        .expect_err("hardlinked sidecar must fail closed");
    assert!(err.to_string().contains("private-file validation"));
}

#[cfg(unix)]
#[test]
fn bearer_token_file_must_be_private() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let token_file = fixture._dir.path().join("public-api-token");
    std::fs::write(&token_file, TOKEN).expect("write token");
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o644))
        .expect("permissions");
    let cli = ApiCli {
        database: fixture.database.clone(),
        read_only: true,
        listen: "127.0.0.1:8080".parse::<SocketAddr>().expect("addr"),
        max_limit: 1_000,
        redact: RedactionMode::Default,
        auth_token_file: Some(token_file),
        cursor_key_file: Some(fixture.cursor_key_file.clone()),
    };
    let err = ApiConfig::from_cli(cli).expect_err("must reject public token file");
    assert!(err.to_string().contains("failed to load --auth-token-file"));
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
        cursor_key_file: Some(fixture.cursor_key_file.clone()),
    };
    let err = ApiConfig::from_cli(cli).expect_err("must reject missing read-only flag");
    assert!(err.to_string().contains("--read-only is required"));
}

#[test]
fn cursor_key_file_is_required() {
    let fixture = Fixture::new();
    let cli = ApiCli {
        database: fixture.database.clone(),
        read_only: true,
        listen: "127.0.0.1:8080".parse::<SocketAddr>().expect("addr"),
        max_limit: 1_000,
        redact: RedactionMode::Default,
        auth_token_file: None,
        cursor_key_file: None,
    };
    let err = ApiConfig::from_cli(cli).expect_err("must require persistent cursor keys");
    assert!(err.to_string().contains("--cursor-key-file is required"));
}

#[cfg(unix)]
#[test]
fn cursor_key_file_must_be_private_and_closed() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let public = fixture._dir.path().join("public-cursor-keys.json");
    write_cursor_key_file(&public, "key-1", [1_u8; 32], None);
    std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o644))
        .expect("public permissions");
    let cli = ApiCli {
        database: fixture.database.clone(),
        read_only: true,
        listen: "127.0.0.1:8080".parse::<SocketAddr>().expect("addr"),
        max_limit: 1_000,
        redact: RedactionMode::Default,
        auth_token_file: None,
        cursor_key_file: Some(public),
    };
    let err = ApiConfig::from_cli(cli).expect_err("must reject public cursor key file");
    assert!(err.to_string().contains("failed to load --cursor-key-file"));

    let contaminated = fixture._dir.path().join("contaminated-cursor-keys.json");
    std::fs::write(
        &contaminated,
        r#"{"schema":"ocfleet.cursor-keys.v1","current":{"key_id":"key-1","key_base64":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","unexpected":true}}"#,
    )
    .expect("write contaminated keys");
    std::fs::set_permissions(&contaminated, std::fs::Permissions::from_mode(0o600))
        .expect("private permissions");
    let cli = ApiCli {
        database: fixture.database.clone(),
        read_only: true,
        listen: "127.0.0.1:8080".parse::<SocketAddr>().expect("addr"),
        max_limit: 1_000,
        redact: RedactionMode::Default,
        auth_token_file: None,
        cursor_key_file: Some(contaminated),
    };
    let err = ApiConfig::from_cli(cli).expect_err("must reject unknown key fields");
    assert!(err.to_string().contains("failed to load --cursor-key-file"));
}

#[tokio::test]
async fn bearer_auth_accepts_configured_token_and_rejects_others() {
    let fixture = Fixture::new();
    let token_file = fixture.write_token_file(TOKEN);
    let router = fixture.router(Some(token_file));

    let (status, headers, body) = raw_request(router.clone(), Method::GET, "/healthz", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        headers.get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer realm=\"ocfleet-api\""
    );
    assert_error_shape(&serde_json::from_str(&body).expect("JSON error"));

    let (status, _) = json_request(router.clone(), Method::GET, "/healthz", Some("wrong")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = json_request(router, Method::GET, "/healthz", Some(TOKEN)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["auth_enabled"], true);
}

#[tokio::test]
async fn metrics_are_prometheus_compatible_bounded_and_read_only() {
    let fixture = Fixture::new();
    let before = table_counts(&fixture.database);
    let router = fixture.router(None);
    let (status, headers, body) = raw_request(router, Method::GET, "/metrics", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).expect("content type"),
        "text/plain; version=0.0.4; charset=utf-8"
    );
    assert!(body.contains("# TYPE ocfleet_controller_health_nodes gauge"));
    assert!(body.contains("ocfleet_controller_alerts{state=\"open\"}"));
    assert!(body.contains("ocfleet_controller_rpc_duration_milliseconds_count"));
    assert!(body.contains("ocfleet_controller_retention_deleted_rows_total"));
    assert!(body.len() < 8_192);
    for forbidden in [
        "node_id",
        "endpoint_id",
        "request_id",
        "session_id",
        "client_ip",
        "token",
        "cookie",
    ] {
        assert!(!body.contains(forbidden), "metrics leaked {forbidden}");
    }
    assert_eq!(table_counts(&fixture.database), before);
}

#[tokio::test]
async fn metrics_require_the_configured_bearer_token() {
    let fixture = Fixture::new();
    let token_file = fixture.write_token_file(TOKEN);
    let router = fixture.router(Some(token_file));
    let (status, _, _) = raw_request(router.clone(), Method::GET, "/metrics", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, body) = raw_request(router, Method::GET, "/metrics", Some(TOKEN)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("ocfleet_controller_sqlite_bytes"));
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
async fn malformed_and_unknown_query_parameters_return_json_errors() {
    let fixture = Fixture::new();
    let router = fixture.router(None);

    for uri in [
        "/runs?limit=not-a-number",
        "/observations?unknown=value",
        "/alerts?limit=1&limit=2",
        "/audit/export?from=2026-07-09T00:00:00Z&to=2026-07-10T00:00:00Z&extra=value",
        "/health/slo?window=24h&to=2026-07-12T00:00:00Z&extra=value",
        "/health/slo?window=90d&to=2026-07-12T00:00:00Z",
        "/health/slo?window=24h&to=2026-07-12T00:00:01Z",
        "/health/slo?window=24h",
        "/api/v1/version/readiness?unknown=value",
    ] {
        let (status, body) = json_request(router.clone(), Method::GET, uri, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(body["error_code"], "BAD_REQUEST");
        assert_error_shape(&body);
    }
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
    assert!(!audit_text.contains("_audit"));
    assert!(audit_text.contains("sha256:"));
    assert_eq!(
        audit["items"][0]["detail"]["result_class"],
        "controller_rpc_summary"
    );
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
    let (status, headers, body) = raw_request(router, Method::GET, "/", None).await;
    assert_eq!(status, StatusCode::OK);
    let csp = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .expect("dashboard CSP header")
        .to_str()
        .expect("valid CSP header");
    assert!(csp.contains("default-src 'none'"));
    assert!(csp.contains("connect-src 'self'"));
    assert!(csp.contains("frame-ancestors 'none'"));
    assert!(csp.contains("script-src 'sha256-"));
    assert!(csp.contains("style-src 'sha256-"));
    assert!(!csp.contains("unsafe-inline"));
    assert!(!csp.contains("unsafe-eval"));
    assert_eq!(
        headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
        "nosniff"
    );
    assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");

    for required in [
        "id=\"summary\"",
        "id=\"version-summary\"",
        "id=\"versions\"",
        "loadJson(\"/api/v1/version/readiness\")",
        "id=\"nodes\"",
        "id=\"jobs\"",
        "id=\"runs\"",
        "id=\"observations\"",
        "id=\"alerts\"",
        "id=\"audit-form\"",
        "method=\"get\"",
        "action=\"/audit/export\"",
        "fetch(path, { method: \"GET\"",
    ] {
        assert!(body.contains(required), "dashboard is missing {required}");
    }

    let lower = body.to_ascii_lowercase();
    for forbidden in [
        "run job",
        "resolve alert",
        "silence alert",
        "mutate retention",
        "mutate trust",
        "add node",
        "remove node",
        "reload ocserv",
        "restart ocserv",
        "apply config",
        "rollback config",
        "disconnect session",
        "install package",
        "package manager",
        "upgrade agent",
        "/rpc",
        "/jobs/{id}/run",
        "/alerts/{id}/resolve",
        "/alerts/{id}/silence",
        "method: \"post\"",
        "method: \"put\"",
        "method: \"patch\"",
        "method: \"delete\"",
        "xmlhttprequest",
        "sendbeacon",
        "innerhtml",
        "outerhtml",
        "insertadjacenthtml",
    ] {
        assert!(!lower.contains(forbidden), "dashboard contains {forbidden}");
    }
}

#[tokio::test]
async fn invalid_identifiers_are_rejected() {
    let fixture = Fixture::new();
    let router = fixture.router(None);

    for uri in [
        "/health/nodes/bad%20node",
        "/jobs/bad%20job",
        "/runs/bad%20run",
        "/observations/bad%20observation",
        "/alerts/bad%20alert",
        "/observations?method=../../etc/passwd",
        "/runs?job_id=bad%20job",
        "/alerts?node_id=node/a",
    ] {
        let (status, body) = json_request(router.clone(), Method::GET, uri, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(body["error_code"], "BAD_REQUEST");
    }
}

fn assert_list_shape(value: &Value, count: usize) {
    assert!(value.get("generated_at").is_some());
    assert!(value.get("limit").is_some());
    assert_eq!(value["count"], count);
    assert!(value["items"].is_array());
}

fn assert_error_shape(value: &Value) {
    assert!(value["generated_at"].is_string());
    assert!(value["error_code"].is_string());
    assert!(value["message"].is_string());
    assert!(value["request_id"].is_string());
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
    let (status, _, body) = raw_request(router, method, uri, token).await;
    (status, body)
}

async fn raw_request(
    router: Router,
    method: Method,
    uri: &str,
    token: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = router
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        status,
        headers,
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
        "node_capability_snapshots",
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
    cursor_key_file: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let database = dir.path().join("controller.sqlite");
        let cursor_key_file = dir.path().join("cursor-keys.json");
        write_cursor_key_file(&cursor_key_file, "key-1", [1_u8; 32], None);
        seed_database(&database);
        Self {
            _dir: dir,
            database,
            cursor_key_file,
        }
    }

    fn router(&self, auth_token_file: Option<std::path::PathBuf>) -> Router {
        build_router(self.state(auth_token_file))
    }

    fn state(&self, auth_token_file: Option<std::path::PathBuf>) -> AppState {
        let cli = ApiCli {
            database: self.database.clone(),
            read_only: true,
            listen: "127.0.0.1:0".parse::<SocketAddr>().expect("addr"),
            max_limit: 1_000,
            redact: RedactionMode::Default,
            auth_token_file,
            cursor_key_file: Some(self.cursor_key_file.clone()),
        };
        let config = ApiConfig::from_cli(cli).expect("config");
        AppState::from_config(config)
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

fn state_for_database(database: std::path::PathBuf) -> AppState {
    let cursor_key_file = database.with_extension("cursor-keys.json");
    write_cursor_key_file(&cursor_key_file, "key-1", [1_u8; 32], None);
    let cli = ApiCli {
        database,
        read_only: true,
        listen: "127.0.0.1:0".parse::<SocketAddr>().expect("addr"),
        max_limit: 1_000,
        redact: RedactionMode::Default,
        auth_token_file: None,
        cursor_key_file: Some(cursor_key_file),
    };
    AppState::from_config(ApiConfig::from_cli(cli).expect("config"))
}

fn write_cursor_key_file(
    path: &Path,
    key_id: &str,
    key: [u8; 32],
    previous: Option<(&str, [u8; 32])>,
) {
    let entry = |key_id: &str, key: [u8; 32]| {
        json!({
            "key_id": key_id,
            "key_base64": base64::engine::general_purpose::STANDARD.encode(key),
        })
    };
    let value = json!({
        "schema": "ocfleet.cursor-keys.v1",
        "current": entry(key_id, key),
        "previous": previous.map(|(id, key)| entry(id, key)),
    });
    std::fs::write(path, serde_json::to_vec(&value).expect("cursor key JSON"))
        .expect("write cursor key file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("cursor key permissions");
    }
}

fn sqlite_sidecar_path(database: &Path, suffix: &str) -> std::path::PathBuf {
    let mut path = database.as_os_str().to_os_string();
    path.push(suffix);
    path.into()
}

fn seed_database(path: &Path) {
    let store = Store::open(path).expect("open store");
    store
        .add_node(
            &NodeInsert {
                node_id: "node-a".to_string(),
                endpoint_id: "endpoint-a".to_string(),
                name: "node-a".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            "api-test",
        )
        .expect("add node");
    store
        .insert_observability_job(
            &ObservabilityJobRecord {
                job_id: "job-a".to_string(),
                kind: "controller-ping".to_string(),
                selector_json: SchedulerSelectorPayloadV1::new(
                    "role=ocserv".to_string(),
                    Some("daily checks".to_string()),
                )
                .expect("valid selector")
                .to_value(),
                pair_selector_json: None,
                interval_seconds: 300,
                jitter_seconds: 0,
                timeout_ms: 5_000,
                enabled: true,
                next_run_at: Some("2026-07-09T00:00:00Z".to_string()),
                last_run_at: Some("2026-07-09T00:01:00Z".to_string()),
                created_at: "2026-07-09T00:00:00Z".to_string(),
                updated_at: "2026-07-09T00:01:00Z".to_string(),
            },
            "api-test",
        )
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
            summary_json: json!({"status": "failed"}),
        })
        .expect("insert observation");
    StoreWriter::write_health_snapshots(
        &store,
        &HealthSnapshotWrite {
            evaluation_id: "health-eval-00000000-0000-4000-8000-000000000004".to_string(),
            event: "health.node".to_string(),
            snapshots: vec![HealthSnapshotRecord {
                node_id: "node-a".to_string(),
                endpoint_id: None,
                computed_at: "2026-07-09T00:02:00Z".to_string(),
                status: "unreachable".to_string(),
                freshness_seconds: Some(60),
                last_success_at: None,
                last_failure_at: Some("2026-07-09T00:01:02Z".to_string()),
                last_error_code: Some("ENDPOINT_NOT_ALLOWED".to_string()),
                degraded_methods_json: HealthDegradedMethodsPayloadV1::new(vec![])
                    .expect("valid methods")
                    .to_value(),
                summary_json: HealthSummaryPayloadV1::new(
                    None,
                    None,
                    "unreachable".to_string(),
                    None,
                    None,
                )
                .expect("valid summary")
                .to_value(),
            }],
        },
        "api-test",
    )
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
        "node_id": "node-a",
        "result_class": "controller_rpc_summary"
    });
    store.insert_audit(&event).expect("insert audit");
    drop(store);
}
