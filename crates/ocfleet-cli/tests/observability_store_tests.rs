use ocfleet_cli::store::{
    AlertEventRecord, CURRENT_SCHEMA_VERSION, HealthSnapshotRecord, ObservabilityJobRecord,
    ObservabilityRunInsert, ProbeObservationInsert, RetentionPolicyRecord, Store,
};
use rusqlite::Connection;
use serde_json::json;

fn open_temp_store() -> (tempfile::TempDir, Store, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    (dir, store, db)
}

#[test]
fn observability_store_tests_new_database_uses_schema_version_4() {
    let (_dir, store, _db) = open_temp_store();

    assert_eq!(
        store.current_schema_version().expect("version"),
        CURRENT_SCHEMA_VERSION
    );
    assert_eq!(CURRENT_SCHEMA_VERSION, 5);
}

#[test]
fn observability_store_tests_new_observability_tables_exist() {
    let (_dir, _store, db) = open_temp_store();
    let conn = Connection::open(db).expect("open db");

    for table in [
        "observability_jobs",
        "observability_runs",
        "probe_observations",
        "health_snapshots",
        "alert_events",
        "retention_policies",
    ] {
        let exists: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .expect("table query");
        assert_eq!(exists, 1, "missing table {table}");
    }
}

#[test]
fn observability_store_tests_inserts_and_lists_observability_job() {
    let (_dir, store, _db) = open_temp_store();
    let job = ObservabilityJobRecord {
        job_id: "job-1".to_string(),
        kind: "controller-ping".to_string(),
        selector_json: json!({"node_id": "hk-ocserv-01", "method": "ocserv.service.summary"}),
        pair_selector_json: None,
        interval_seconds: 60,
        jitter_seconds: 5,
        timeout_ms: 2_000,
        enabled: true,
        next_run_at: Some("2026-07-08T08:00:00Z".to_string()),
        last_run_at: None,
        created_at: "2026-07-08T07:00:00Z".to_string(),
        updated_at: "2026-07-08T07:00:00Z".to_string(),
    };

    store
        .insert_observability_job(&job)
        .expect("insert observability job");

    let jobs = store
        .list_observability_jobs()
        .expect("list observability jobs");
    assert_eq!(jobs, vec![job.clone()]);

    store
        .set_observability_job_enabled("job-1", false)
        .expect("disable observability job");
    let jobs = store
        .list_observability_jobs()
        .expect("list observability jobs after disable");
    assert_eq!(jobs[0].job_id, job.job_id);
    assert!(!jobs[0].enabled);
}

#[test]
fn observability_store_tests_inserts_and_lists_probe_observation() {
    let (_dir, store, _db) = open_temp_store();
    let observation = ProbeObservationInsert {
        observation_id: "obs-1".to_string(),
        run_id: Some("run-1".to_string()),
        node_id: Some("hk-ocserv-01".to_string()),
        endpoint_id: Some("endpoint-1".to_string()),
        method: "ocserv.sessions.summary".to_string(),
        ok: Some(true),
        error_code: None,
        duration_ms: Some(42),
        observed_at: "2026-07-08T07:30:00Z".to_string(),
        expires_at: Some("2026-07-08T07:35:00Z".to_string()),
        result_class: "low_sensitive_summary".to_string(),
        summary_json: json!({"sessions_total": 12}),
    };

    store
        .insert_probe_observation(&observation)
        .expect("insert observation");

    let observations = store
        .list_probe_observations(Some("hk-ocserv-01"), 10)
        .expect("list observations");
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].observation_id, observation.observation_id);
    assert_eq!(observations[0].node_id, observation.node_id);
    assert_eq!(observations[0].method, observation.method);
    assert_eq!(observations[0].ok, observation.ok);
    assert_eq!(observations[0].duration_ms, observation.duration_ms);
    assert_eq!(observations[0].summary_json, observation.summary_json);
}

#[test]
fn observability_store_tests_insert_and_finish_observability_run() {
    let (_dir, store, db) = open_temp_store();
    let run = ObservabilityRunInsert {
        run_id: "run-1".to_string(),
        job_id: Some("job-1".to_string()),
        started_at: "2026-07-08T07:30:00Z".to_string(),
        finished_at: None,
        status: "running".to_string(),
        triggered_by: "manual".to_string(),
        summary_json: json!({"started": true}),
    };

    store
        .insert_observability_run(&run)
        .expect("insert observability run");
    store
        .finish_observability_run(
            "run-1",
            "2026-07-08T07:31:00Z",
            "succeeded",
            &json!({"observations": 1}),
        )
        .expect("finish observability run");

    let conn = Connection::open(db).expect("open db");
    let (finished_at, status, summary_json): (String, String, String) = conn
        .query_row(
            "SELECT finished_at, status, summary_json FROM observability_runs WHERE run_id = ?1",
            ["run-1"],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("query observability run");
    assert_eq!(finished_at, "2026-07-08T07:31:00Z");
    assert_eq!(status, "succeeded");
    assert_eq!(summary_json, r#"{"observations":1}"#);
}

#[test]
fn observability_store_tests_upserts_health_snapshot() {
    let (_dir, store, _db) = open_temp_store();
    let initial = HealthSnapshotRecord {
        node_id: "hk-ocserv-01".to_string(),
        endpoint_id: Some("endpoint-1".to_string()),
        computed_at: "2026-07-08T07:00:00Z".to_string(),
        status: "healthy".to_string(),
        freshness_seconds: Some(30),
        last_success_at: Some("2026-07-08T07:00:00Z".to_string()),
        last_failure_at: None,
        last_error_code: None,
        degraded_methods_json: json!([]),
        summary_json: json!({"state": "running"}),
    };
    store
        .upsert_health_snapshot(&initial)
        .expect("insert health snapshot");

    let updated = HealthSnapshotRecord {
        status: "degraded".to_string(),
        freshness_seconds: Some(90),
        last_failure_at: Some("2026-07-08T07:05:00Z".to_string()),
        last_error_code: Some("RPC_UNAVAILABLE".to_string()),
        degraded_methods_json: json!(["ocserv.version"]),
        summary_json: json!({"state": "running", "version_status": "unavailable"}),
        ..initial.clone()
    };
    store
        .upsert_health_snapshot(&updated)
        .expect("update health snapshot");

    let snapshots = store
        .list_health_snapshots()
        .expect("list health snapshots");
    assert_eq!(snapshots, vec![updated]);
}

#[test]
fn observability_store_tests_upserts_and_lists_alert_event() {
    let (_dir, store, _db) = open_temp_store();
    let initial = AlertEventRecord {
        alert_id: "alert-1".to_string(),
        dedupe_key: "node:hk-ocserv-01:cert-expiring".to_string(),
        node_id: Some("hk-ocserv-01".to_string()),
        severity: "warning".to_string(),
        state: "open".to_string(),
        reason_code: "CERT_EXPIRING".to_string(),
        first_seen_at: "2026-07-08T07:00:00Z".to_string(),
        last_seen_at: "2026-07-08T07:00:00Z".to_string(),
        last_sent_at: None,
        resolved_at: None,
        detail_json: json!({"days_remaining": 14}),
    };
    store
        .upsert_alert_event(&initial)
        .expect("insert alert event");

    let updated = AlertEventRecord {
        state: "resolved".to_string(),
        last_seen_at: "2026-07-08T08:00:00Z".to_string(),
        resolved_at: Some("2026-07-08T08:00:00Z".to_string()),
        detail_json: json!({"days_remaining": 30}),
        ..initial.clone()
    };
    store
        .upsert_alert_event(&updated)
        .expect("update alert event");

    let alerts = store.list_alert_events().expect("list alert events");
    assert_eq!(alerts, vec![updated]);
}

#[test]
fn observability_store_tests_sets_and_gets_retention_policy() {
    let (_dir, store, _db) = open_temp_store();
    let policy = RetentionPolicyRecord {
        scope: "observations".to_string(),
        max_age_days: Some(30),
        max_rows: Some(100_000),
        updated_at: "2026-07-08T07:00:00Z".to_string(),
    };

    assert!(
        store
            .get_retention_policy("observations")
            .expect("get missing retention policy")
            .is_none()
    );
    store
        .set_retention_policy(&policy)
        .expect("set retention policy");

    assert_eq!(
        store
            .get_retention_policy("observations")
            .expect("get retention policy"),
        Some(policy)
    );
}

#[test]
fn observability_store_tests_invalid_job_kind_rejected_by_db() {
    let (_dir, _store, db) = open_temp_store();
    let conn = Connection::open(db).expect("open db");

    let err = conn
        .execute(
            "INSERT INTO observability_jobs
             (job_id, kind, selector_json, interval_seconds, jitter_seconds, timeout_ms, enabled, created_at, updated_at)
             VALUES ('bad-kind', 'node_rpc', '{\"selector\":\"role=ocserv\"}', 60, 0, 5000, 1, '2026-07-08T00:00:00Z', '2026-07-08T00:00:00Z')",
            [],
        )
        .expect_err("invalid kind must be rejected");

    assert!(err.to_string().contains("CHECK"));
}

#[test]
fn observability_store_tests_invalid_bool_rejected_by_db() {
    let (_dir, _store, db) = open_temp_store();
    let conn = Connection::open(db).expect("open db");

    let err = conn
        .execute(
            "INSERT INTO observability_jobs
             (job_id, kind, selector_json, interval_seconds, jitter_seconds, timeout_ms, enabled, created_at, updated_at)
             VALUES ('bad-bool', 'controller-ping', '{\"selector\":\"role=ocserv\"}', 60, 0, 5000, 2, '2026-07-08T00:00:00Z', '2026-07-08T00:00:00Z')",
            [],
        )
        .expect_err("invalid bool must be rejected");

    assert!(err.to_string().contains("CHECK"));
}

#[test]
fn observability_store_tests_migration_is_idempotent_when_reopening_database() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");

    let first = Store::open(&db).expect("first open");
    assert_eq!(
        first.current_schema_version().expect("first version"),
        CURRENT_SCHEMA_VERSION
    );
    drop(first);

    let second = Store::open(&db).expect("second open");
    assert_eq!(
        second.current_schema_version().expect("second version"),
        CURRENT_SCHEMA_VERSION
    );
}
