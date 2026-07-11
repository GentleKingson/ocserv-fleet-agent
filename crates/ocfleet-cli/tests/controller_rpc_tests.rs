use ocfleet_cli::controller_rpc::{
    CONTROLLER_RPC_RESULT_CLASS, ControllerRpcRunner, EndpointTrustRejection, FixedControllerRpc,
    endpoint_trust_rejection, low_sensitive_fixed_rpc_summary,
    low_sensitive_ocserv_observation_summary,
};
use ocfleet_cli::store::{NodeInsert, Store};
use ocfleet_protocol::method::{
    OCSERV_CERT_EXPIRY, OCSERV_CONFIG_FINGERPRINT, OCSERV_SERVICE_SUMMARY, OCSERV_SESSIONS_SUMMARY,
    OCSERV_VERSION, PROBE_CONTROLLER_PING, PROBE_PATH_ECHO,
};
use rusqlite::Connection;
use serde_json::json;

const TEST_NODE_ID: &str = "node-a";
const TEST_ACTOR: &str = "controller-rpc-test";

fn seed_active_node(store: &Store) -> String {
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    store
        .add_node(
            &NodeInsert {
                node_id: TEST_NODE_ID.to_string(),
                endpoint_id: endpoint_id.clone(),
                name: TEST_NODE_ID.to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            TEST_ACTOR,
        )
        .expect("seed node");
    endpoint_id
}

fn delete_endpoint_trust(database: &std::path::Path, endpoint_id: &str) {
    Connection::open(database)
        .expect("open sqlite")
        .execute(
            "DELETE FROM endpoint_trust WHERE endpoint_id = ?1",
            [endpoint_id],
        )
        .expect("delete endpoint trust");
}

fn set_endpoint_trust_node(database: &std::path::Path, endpoint_id: &str, node_id: Option<&str>) {
    Connection::open(database)
        .expect("open sqlite")
        .execute(
            "UPDATE endpoint_trust SET node_id = ?1 WHERE endpoint_id = ?2",
            rusqlite::params![node_id, endpoint_id],
        )
        .expect("update endpoint trust binding");
}

fn rpc_rejection_audits(database: &std::path::Path) -> Vec<(String, String, serde_json::Value)> {
    let conn = Connection::open(database).expect("open sqlite");
    let mut stmt = conn
        .prepare(
            "SELECT method, error_code, detail_json
             FROM controller_audit_log
             WHERE event = 'rpc.completed' AND ok = 0
             ORDER BY id",
        )
        .expect("prepare audit query");
    stmt.query_map([], |row| {
        let detail: String = row.get(2)?;
        Ok((
            row.get(0)?,
            row.get(1)?,
            serde_json::from_str(&detail).expect("parse audit detail"),
        ))
    })
    .expect("query rejection audits")
    .collect::<rusqlite::Result<Vec<_>>>()
    .expect("collect rejection audits")
}

#[tokio::test]
async fn controller_rpc_missing_node_returns_node_not_found_outcome() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("controller.secret");
    let store = Store::open(&db).expect("store opens");
    let runner = ControllerRpcRunner::new(&store, &secret_key);

    let outcome = runner
        .run_fixed_node_rpc("missing-node", PROBE_CONTROLLER_PING)
        .await;

    assert_eq!(outcome.node_id, "missing-node");
    assert_eq!(outcome.endpoint_id, None);
    assert_eq!(outcome.method, PROBE_CONTROLLER_PING);
    assert_eq!(outcome.request_id, None);
    assert!(!outcome.ok);
    assert_eq!(outcome.error_code.as_deref(), Some("NODE_NOT_FOUND"));
    assert_eq!(outcome.result_class, "controller_rpc_summary");
    assert_eq!(
        outcome.summary_json["message"],
        "node not found: missing-node"
    );
}

#[tokio::test]
async fn controller_rpc_missing_endpoint_trust_fails_closed_before_secret_io() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let missing_secret_key = dir.path().join("does-not-exist.secret");
    let store = Store::open(&db).expect("store opens");
    let endpoint_id = seed_active_node(&store);
    delete_endpoint_trust(&db, &endpoint_id);
    let runner = ControllerRpcRunner::new(&store, &missing_secret_key);

    let outcome = runner
        .run_fixed_node_rpc(TEST_NODE_ID, PROBE_CONTROLLER_PING)
        .await;

    assert_eq!(outcome.endpoint_id.as_deref(), Some(endpoint_id.as_str()));
    assert_eq!(outcome.error_code.as_deref(), Some("ENDPOINT_NOT_ALLOWED"));
    assert_eq!(outcome.summary_json["endpoint_trust_state"], "missing");
    assert!(outcome.summary_json.get("endpoint_status").is_none());
    assert!(
        outcome
            .message
            .as_deref()
            .is_some_and(|message| message.contains("endpoint trust missing"))
    );
    assert!(!missing_secret_key.exists());
    let audits = rpc_rejection_audits(&db);
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].0, PROBE_CONTROLLER_PING);
    assert_eq!(audits[0].1, "ENDPOINT_NOT_ALLOWED");
    assert_eq!(audits[0].2["endpoint_trust_state"], "missing");
}

#[tokio::test]
async fn controller_rpc_unbound_endpoint_trust_fails_closed_before_secret_io() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let missing_secret_key = dir.path().join("does-not-exist.secret");
    let store = Store::open(&db).expect("store opens");
    let endpoint_id = seed_active_node(&store);
    set_endpoint_trust_node(&db, &endpoint_id, None);

    let outcome = ControllerRpcRunner::new(&store, &missing_secret_key)
        .run_fixed_node_rpc(TEST_NODE_ID, PROBE_CONTROLLER_PING)
        .await;

    assert_eq!(outcome.error_code.as_deref(), Some("ENDPOINT_NOT_ALLOWED"));
    assert_eq!(outcome.summary_json["endpoint_trust_state"], "unbound");
    assert_eq!(outcome.summary_json["endpoint_status"], "active");
    assert!(
        outcome
            .message
            .as_deref()
            .is_some_and(|message| message.contains("trust is unbound"))
    );
    assert!(!missing_secret_key.exists());
    let audits = rpc_rejection_audits(&db);
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].1, "ENDPOINT_NOT_ALLOWED");
    assert_eq!(audits[0].2["endpoint_trust_state"], "unbound");
}

#[tokio::test]
async fn controller_rpc_binding_mismatch_fails_closed_before_secret_io() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let missing_secret_key = dir.path().join("does-not-exist.secret");
    let store = Store::open(&db).expect("store opens");
    let endpoint_id = seed_active_node(&store);
    set_endpoint_trust_node(&db, &endpoint_id, Some("different-node"));

    let outcome = ControllerRpcRunner::new(&store, &missing_secret_key)
        .run_fixed_node_rpc(TEST_NODE_ID, PROBE_CONTROLLER_PING)
        .await;

    assert_eq!(outcome.error_code.as_deref(), Some("ENDPOINT_NOT_ALLOWED"));
    assert_eq!(
        outcome.summary_json["endpoint_trust_state"],
        "binding_mismatch"
    );
    assert_eq!(outcome.summary_json["endpoint_status"], "active");
    assert!(
        outcome
            .message
            .as_deref()
            .is_some_and(|message| message.contains("trust binding mismatch"))
    );
    assert!(!missing_secret_key.exists());
    let audits = rpc_rejection_audits(&db);
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].1, "ENDPOINT_NOT_ALLOWED");
    assert_eq!(audits[0].2["endpoint_trust_state"], "binding_mismatch");
}

#[tokio::test]
async fn ocserv_rpc_missing_endpoint_trust_fails_closed_before_secret_io() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let missing_secret_key = dir.path().join("does-not-exist.secret");
    let store = Store::open(&db).expect("store opens");
    let endpoint_id = seed_active_node(&store);
    delete_endpoint_trust(&db, &endpoint_id);
    let runner = ControllerRpcRunner::new(&store, &missing_secret_key);

    let outcome = runner.run_ocserv_cert(TEST_NODE_ID).await;

    assert_eq!(outcome.endpoint_id.as_deref(), Some(endpoint_id.as_str()));
    assert_eq!(outcome.error_code.as_deref(), Some("ENDPOINT_NOT_ALLOWED"));
    assert_eq!(outcome.summary_json["endpoint_trust_state"], "missing");
    assert!(outcome.summary_json.get("endpoint_status").is_none());
    assert!(!missing_secret_key.exists());
    let audits = rpc_rejection_audits(&db);
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].0, OCSERV_CERT_EXPIRY);
    assert_eq!(audits[0].1, "ENDPOINT_NOT_ALLOWED");
    assert_eq!(audits[0].2["endpoint_trust_state"], "missing");
}

#[tokio::test]
async fn ocserv_status_missing_endpoint_trust_audits_every_rejected_subrpc() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let missing_secret_key = dir.path().join("does-not-exist.secret");
    let store = Store::open(&db).expect("store opens");
    let endpoint_id = seed_active_node(&store);
    delete_endpoint_trust(&db, &endpoint_id);

    let outcome = ControllerRpcRunner::new(&store, &missing_secret_key)
        .run_ocserv_status_bundle(TEST_NODE_ID)
        .await;

    assert!(!outcome.ok);
    assert_eq!(outcome.error_code.as_deref(), Some("ENDPOINT_NOT_ALLOWED"));
    assert!(!missing_secret_key.exists());
    let audits = rpc_rejection_audits(&db);
    assert_eq!(audits.len(), 4);
    assert_eq!(
        audits
            .iter()
            .map(|audit| audit.0.as_str())
            .collect::<Vec<_>>(),
        [
            OCSERV_SERVICE_SUMMARY,
            OCSERV_VERSION,
            OCSERV_SESSIONS_SUMMARY,
            OCSERV_CONFIG_FINGERPRINT,
        ]
    );
    assert!(audits.iter().all(|audit| audit.1 == "ENDPOINT_NOT_ALLOWED"));
    assert!(
        audits
            .iter()
            .all(|audit| audit.2["endpoint_trust_state"] == "missing")
    );
}

#[tokio::test]
async fn controller_rpc_preserves_active_and_inactive_endpoint_behavior() {
    let active_dir = tempfile::tempdir().expect("active temp dir");
    let active_db = active_dir.path().join("controller.sqlite");
    let active_secret_key = active_dir.path().join("does-not-exist.secret");
    let active_store = Store::open(&active_db).expect("active store opens");
    let active_endpoint_id = seed_active_node(&active_store);
    assert_eq!(
        endpoint_trust_rejection(&active_store, TEST_NODE_ID, &active_endpoint_id)
            .expect("read active trust"),
        None
    );

    let active_outcome = ControllerRpcRunner::new(&active_store, &active_secret_key)
        .run_fixed_node_rpc(TEST_NODE_ID, PROBE_CONTROLLER_PING)
        .await;
    assert_eq!(
        active_outcome.error_code.as_deref(),
        Some("SECRET_KEY_LOAD_FAILED")
    );

    let inactive_dir = tempfile::tempdir().expect("inactive temp dir");
    let inactive_db = inactive_dir.path().join("controller.sqlite");
    let inactive_secret_key = inactive_dir.path().join("does-not-exist.secret");
    let inactive_store = Store::open(&inactive_db).expect("inactive store opens");
    let inactive_endpoint_id = seed_active_node(&inactive_store);
    Connection::open(&inactive_db)
        .expect("open inactive fixture database")
        .execute(
            "UPDATE endpoint_trust
             SET status = 'revoked',
                 trust_bundle_json = json_set(trust_bundle_json, '$.status', 'revoked')
             WHERE endpoint_id = ?1",
            [&inactive_endpoint_id],
        )
        .expect("mark endpoint inactive without changing node state");
    assert_eq!(
        endpoint_trust_rejection(&inactive_store, TEST_NODE_ID, &inactive_endpoint_id)
            .expect("read inactive trust"),
        Some(EndpointTrustRejection::Inactive(
            ocfleet_protocol::enrollment::EndpointStatus::Revoked
        ))
    );

    let inactive_outcome = ControllerRpcRunner::new(&inactive_store, &inactive_secret_key)
        .run_fixed_node_rpc(TEST_NODE_ID, PROBE_CONTROLLER_PING)
        .await;
    assert_eq!(
        inactive_outcome.error_code.as_deref(),
        Some("ENDPOINT_NOT_ALLOWED")
    );
    assert_eq!(
        inactive_outcome.summary_json["endpoint_trust_state"],
        "inactive"
    );
    assert_eq!(inactive_outcome.summary_json["endpoint_status"], "revoked");
    assert!(!inactive_secret_key.exists());
}

#[test]
fn controller_rpc_ping_summary_drops_unexpected_raw_fields() {
    let summary = low_sensitive_fixed_rpc_summary(
        PROBE_CONTROLLER_PING,
        &json!({
            "message": "pong",
            "probe": "controller.ping",
            "node_id": "hk-ocserv-01",
            "agent_version": "0.1.0",
            "agent_endpoint_id": "agent-endpoint-1",
            "time_utc": "2026-07-08T00:00:00Z",
            "username": "alice",
            "client_ip": "10.0.0.2"
        }),
    )
    .expect("summary");

    assert_eq!(summary["result_class"], CONTROLLER_RPC_RESULT_CLASS);
    assert_eq!(summary["message"], "pong");
    assert_eq!(summary["probe"], "controller.ping");
    assert_eq!(summary["agent_endpoint_id"], "agent-endpoint-1");
    assert!(summary.get("username").is_none());
    assert!(summary.get("client_ip").is_none());
}

#[test]
fn controller_rpc_path_summary_drops_nested_target_result() {
    let summary = low_sensitive_fixed_rpc_summary(
        PROBE_PATH_ECHO,
        &json!({
            "probe": "path.echo",
            "ok": false,
            "source_agent_endpoint_id": "source-endpoint",
            "target_agent_endpoint_id": "target-endpoint",
            "root_request_id": "root-request",
            "peer_request_id": "peer-request",
            "time_utc": "2026-07-08T00:00:00Z",
            "target_result": {
                "error_code": "CONNECT_FAILED",
                "username": "alice",
                "client_ip": "10.0.0.2",
                "raw": {"stdout": "secret"}
            }
        }),
    )
    .expect("summary");

    assert_eq!(summary["result_class"], CONTROLLER_RPC_RESULT_CLASS);
    assert_eq!(summary["probe"], "path.echo");
    assert_eq!(summary["ok"], false);
    assert_eq!(summary["source_agent_endpoint_id"], "source-endpoint");
    assert_eq!(summary["target_agent_endpoint_id"], "target-endpoint");
    assert_eq!(summary["root_request_id"], "root-request");
    assert_eq!(summary["peer_request_id"], "peer-request");
    assert_eq!(summary["target_error_code"], "CONNECT_FAILED");
    assert!(summary.get("target_result").is_none());
    assert!(!summary.to_string().contains("alice"));
    assert!(!summary.to_string().contains("10.0.0.2"));
    assert!(!summary.to_string().contains("stdout"));
}

#[test]
fn controller_rpc_fixed_rpc_variants_define_method_and_params() {
    assert_eq!(
        FixedControllerRpc::ProbeControllerPing.method(),
        PROBE_CONTROLLER_PING
    );
    assert_eq!(FixedControllerRpc::ProbeControllerPing.params(), json!({}));

    let path = FixedControllerRpc::ProbePathEcho {
        target_node_id: "target-node".to_string(),
        target_agent_endpoint_id: "target-endpoint".to_string(),
    };
    assert_eq!(path.method(), PROBE_PATH_ECHO);
    assert_eq!(
        path.params(),
        json!({"target_agent_endpoint_id": "target-endpoint"})
    );

    let allowlist = FixedControllerRpc::allowlisted_methods();
    assert!(allowlist.contains(&PROBE_CONTROLLER_PING));
    assert!(allowlist.contains(&PROBE_PATH_ECHO));
    assert!(!allowlist.contains(&"shell.exec"));
}

#[test]
fn controller_rpc_ocserv_observation_summary_drops_raw_dto_fields() {
    let service = low_sensitive_ocserv_observation_summary(
        OCSERV_SERVICE_SUMMARY,
        &json!({
            "service": {"state": "running", "enabled": "enabled", "since": "2026-07-08T00:00:00Z"},
            "live": {
                "collector_status": "ok",
                "last_snapshot_at": "2026-07-08T00:00:00Z",
                "auth_failure_count_rolling": 2,
                "connection_failure_count_rolling": 1,
                "cert_min_days_remaining": 42,
                "config_fingerprint_short": "abcdef123456"
            },
            "meta": {"source": "provider", "collected_at": "2026-07-08T00:00:00Z", "freshness": "live"},
            "username": "alice",
            "client_ip": "10.0.0.2",
            "config_path": "/etc/ocserv/ocserv.conf"
        }),
    )
    .expect("service summary");
    assert_eq!(service["result_class"], "low_sensitive_summary");
    assert_eq!(service["service_state"], "running");
    assert_eq!(service["service_enabled"], "enabled");
    assert_eq!(service["collector_status"], "ok");
    assert_eq!(service["auth_failure_count_rolling"], 2);
    assert_eq!(service["connection_failure_count_rolling"], 1);
    assert_eq!(service["cert_min_days_remaining"], 42);
    assert_eq!(service["config_fingerprint_short"], "abcdef123456");
    assert!(service.get("service").is_none());
    assert!(service.get("meta").is_none());

    let version = low_sensitive_ocserv_observation_summary(
        OCSERV_VERSION,
        &json!({
            "version": "1.2.3",
            "status": "available",
            "meta": {"source": "provider", "collected_at": "2026-07-08T00:00:00Z", "freshness": "live"},
            "stdout": "secret"
        }),
    )
    .expect("version summary");
    assert_eq!(version["version"], "1.2.3");
    assert_eq!(version["status"], "available");
    assert!(version.get("meta").is_none());

    let sessions = low_sensitive_ocserv_observation_summary(
        OCSERV_SESSIONS_SUMMARY,
        &json!({
            "sessions": {"total": 12, "status": "available", "users": ["alice"]},
            "meta": {"source": "provider", "collected_at": "2026-07-08T00:00:00Z", "freshness": "live"}
        }),
    )
    .expect("sessions summary");
    assert_eq!(sessions["sessions_total"], 12);
    assert_eq!(sessions["sessions_status"], "available");
    assert!(sessions.get("users").is_none());

    let fingerprint = low_sensitive_ocserv_observation_summary(
        OCSERV_CONFIG_FINGERPRINT,
        &json!({
            "fingerprint": {
                "algorithm": "sha256",
                "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "status": "available",
                "path": "/etc/ocserv/ocserv.conf"
            },
            "meta": {"source": "provider", "collected_at": "2026-07-08T00:00:00Z", "freshness": "live"}
        }),
    )
    .expect("fingerprint summary");
    assert_eq!(fingerprint["config_fingerprint_algorithm"], "sha256");
    assert_eq!(fingerprint["config_fingerprint_prefix"], "aaaaaaaaaaaa");
    assert_eq!(fingerprint["config_fingerprint_status"], "available");
    assert!(fingerprint.get("hash").is_none());

    let combined = json!([service, version, sessions, fingerprint]).to_string();
    for marker in [
        "alice",
        "10.0.0.2",
        "/etc/ocserv",
        "stdout",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        assert!(!combined.contains(marker), "raw marker leaked: {marker}");
    }
}

#[test]
fn controller_rpc_cert_summary_uses_alert_and_health_consumable_fields() {
    let summary = low_sensitive_ocserv_observation_summary(
        OCSERV_CERT_EXPIRY,
        &json!({
            "certs": [
                {
                    "name": "server",
                    "status": "valid",
                    "days_remaining": 40,
                    "fingerprint_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "subject": "CN=vpn.example"
                },
                {
                    "name": "intermediate",
                    "status": "expiring_soon",
                    "days_remaining": 3,
                    "issuer": "CN=ca"
                }
            ],
            "meta": {"source": "provider", "collected_at": "2026-07-08T00:00:00Z", "freshness": "live"}
        }),
    )
    .expect("cert summary");

    assert_eq!(summary["result_class"], "low_sensitive_summary");
    assert_eq!(summary["cert_count"], 2);
    assert_eq!(summary["days_remaining"], 3);
    assert_eq!(summary["status"], "expiring_soon");
    assert!(summary.get("min_days_remaining").is_none());
    assert!(summary.get("cert_status").is_none());
    assert!(!summary.to_string().contains("bbbbbbbbbbbbbbbb"));
    assert!(!summary.to_string().contains("subject"));
    assert!(!summary.to_string().contains("issuer"));
}
