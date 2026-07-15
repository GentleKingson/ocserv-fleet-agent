use ocfleet_cli::audit::AuditEvent;
use ocfleet_cli::backend::StoreWriter;
use ocfleet_cli::storage_payloads::{HealthDegradedMethodsPayloadV1, HealthSummaryPayloadV1};
use ocfleet_cli::store::{
    AlertEventRecord, HealthSnapshotRecord, HealthSnapshotWrite, ObservabilityRunInsert,
    ProbeObservationInsert, RetentionApplyInput, Store, StoreError,
};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, Barrier};

fn run_ocfleet(args: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_ocfleet"))
        .args(args)
        .env("USER", "retention-user")
        .output()
        .expect("run ocfleet");
    assert!(
        output.status.success(),
        "ocfleet failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn run_ocfleet_failure(args: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_ocfleet"))
        .args(args)
        .env("USER", "retention-user")
        .output()
        .expect("run ocfleet");
    assert!(
        !output.status.success(),
        "ocfleet unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn insert_observation(store: &Store, observation_id: &str, observed_at: &str) {
    store
        .insert_probe_observation(&ProbeObservationInsert {
            observation_id: observation_id.to_string(),
            run_id: None,
            node_id: Some("hk-ocserv-01".to_string()),
            endpoint_id: Some("endpoint-1".to_string()),
            method: "probe.controller.ping".to_string(),
            ok: Some(true),
            error_code: None,
            duration_ms: Some(10),
            observed_at: observed_at.to_string(),
            expires_at: None,
            result_class: "controller_rpc_summary".to_string(),
            summary_json: json!({"message": "pong"}),
        })
        .expect("insert observation");
}

fn insert_old_health_and_alert(store: &Store) {
    StoreWriter::write_health_snapshots(
        store,
        &HealthSnapshotWrite {
            evaluation_id: format!("health-eval-{}", uuid::Uuid::new_v4()),
            event: "health.node".to_string(),
            snapshots: vec![HealthSnapshotRecord {
                node_id: "hk-ocserv-01".to_string(),
                endpoint_id: None,
                computed_at: "2026-01-01T00:00:00Z".to_string(),
                status: "stale".to_string(),
                freshness_seconds: Some(86_400),
                last_success_at: None,
                last_failure_at: Some("2026-01-01T00:00:00Z".to_string()),
                last_error_code: Some("RPC_TIMEOUT".to_string()),
                degraded_methods_json: HealthDegradedMethodsPayloadV1::new(vec![])
                    .expect("valid methods")
                    .to_value(),
                summary_json: HealthSummaryPayloadV1::new(
                    None,
                    None,
                    "stale".to_string(),
                    None,
                    None,
                )
                .expect("valid summary")
                .to_value(),
            }],
        },
        "test-setup",
    )
    .expect("insert health snapshot");
    store
        .upsert_alert_event(&AlertEventRecord {
            alert_id: "alert-1".to_string(),
            dedupe_key: "node:hk-ocserv-01".to_string(),
            node_id: Some("hk-ocserv-01".to_string()),
            severity: "warning".to_string(),
            state: "open".to_string(),
            reason_code: "NODE_STALE".to_string(),
            first_seen_at: "2026-01-01T00:00:00Z".to_string(),
            last_seen_at: "2026-01-01T00:00:00Z".to_string(),
            last_sent_at: None,
            resolved_at: None,
            detail_json: json!({"status": "stale"}),
        })
        .expect("insert alert");
}

fn audit_count(database: &Path) -> i64 {
    Connection::open(database)
        .expect("open db")
        .query_row("SELECT count(*) FROM controller_audit_log", [], |row| {
            row.get(0)
        })
        .expect("count audit")
}

fn audit_event_count(database: &Path, event: &str) -> i64 {
    Connection::open(database)
        .expect("open db")
        .query_row(
            "SELECT count(*) FROM controller_audit_log WHERE event = ?1",
            [event],
            |row| row.get(0),
        )
        .expect("count audit event")
}

fn inject_audit_event_failure(database: &Path, event: &str) {
    assert!(matches!(event, "retention.set" | "retention.apply"));
    Connection::open(database)
        .expect("open db")
        .execute_batch(&format!(
            "CREATE TRIGGER fail_retention_audit
             BEFORE INSERT ON controller_audit_log
             WHEN NEW.event = '{event}'
             BEGIN
               SELECT RAISE(FAIL, 'injected retention audit failure');
             END;"
        ))
        .expect("install audit failure trigger");
}

fn observation_count(database: &Path) -> i64 {
    Connection::open(database)
        .expect("open db")
        .query_row("SELECT count(*) FROM probe_observations", [], |row| {
            row.get(0)
        })
        .expect("count observations")
}

fn table_count(database: &Path, table: &str) -> i64 {
    assert!(matches!(
        table,
        "probe_observations"
            | "observability_runs"
            | "health_snapshots"
            | "health_history"
            | "health_rollups"
            | "alert_events"
    ));
    Connection::open(database)
        .expect("open db")
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .expect("count table")
}

fn run_count(database: &Path) -> i64 {
    Connection::open(database)
        .expect("open db")
        .query_row("SELECT count(*) FROM observability_runs", [], |row| {
            row.get(0)
        })
        .expect("count runs")
}

fn latest_audit(database: &Path) -> (String, Value) {
    let (event, detail): (String, String) = Connection::open(database)
        .expect("open db")
        .query_row(
            "SELECT event, detail_json FROM controller_audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("latest audit");
    (
        event,
        serde_json::from_str(&detail).expect("parse detail json"),
    )
}

fn latest_audit_with_ok(database: &Path) -> (String, i64, Value) {
    let (event, ok, detail): (String, i64, String) = Connection::open(database)
        .expect("open db")
        .query_row(
            "SELECT event, ok, detail_json FROM controller_audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("latest audit");
    (
        event,
        ok,
        serde_json::from_str(&detail).expect("parse detail json"),
    )
}

#[test]
fn retention_tests_show_outputs_default_policies() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let output = run_ocfleet(&["--database", &database_arg, "retention", "show"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("scope=observations"));
    assert!(stdout.contains("max_age_days=30"));
    assert!(stdout.contains("max_rows=100000"));
    assert!(stdout.contains("scope=observability-runs"));
    assert!(stdout.contains("scope=health-snapshots"));
    assert!(stdout.contains("scope=health-history"));
    assert!(stdout.contains("scope=alert-events"));
    assert!(stdout.contains("max_age_days=180"));
    assert!(stdout.contains("scope=controller_audit_log"));
    assert!(stdout.contains("retention=never"));
}

#[test]
fn retention_tests_set_writes_policy() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    run_ocfleet(&[
        "--database",
        &database_arg,
        "retention",
        "set",
        "observations",
        "--max-age",
        "7d",
        "--max-rows",
        "10",
    ]);

    let store = Store::open(&database).expect("open store");
    let policy = store
        .get_retention_policy("observations")
        .expect("get policy")
        .expect("policy exists");
    assert_eq!(policy.scope, "observations");
    assert_eq!(policy.max_age_days, Some(7));
    assert_eq!(policy.max_rows, Some(10));

    let (event, detail) = latest_audit(&database);
    assert_eq!(event, "retention.set");
    assert_eq!(detail["target_id"], "observations");
    assert_eq!(detail["after"]["max_age_days"], 7);
    assert_eq!(detail["after"]["max_rows"], 10);

    let audit_count = audit_event_count(&database, "retention.set");
    run_ocfleet(&[
        "--database",
        &database_arg,
        "retention",
        "set",
        "observations",
        "--max-age",
        "7d",
        "--max-rows",
        "10",
    ]);
    assert_eq!(audit_event_count(&database, "retention.set"), audit_count);
}

#[test]
fn retention_tests_policy_and_apply_roll_back_when_audit_fails() {
    let policy_dir = tempfile::tempdir().expect("temp dir");
    let policy_database = policy_dir.path().join("controller.sqlite");
    let policy_arg = policy_database.to_string_lossy().into_owned();
    Store::open(&policy_database).expect("initialize policy database");
    inject_audit_event_failure(&policy_database, "retention.set");
    run_ocfleet_failure(&[
        "--database",
        &policy_arg,
        "retention",
        "set",
        "observations",
        "--max-age",
        "7d",
    ]);
    assert!(
        Store::open(&policy_database)
            .expect("reopen policy store")
            .get_retention_policy("observations")
            .expect("query policy")
            .is_none()
    );

    let apply_dir = tempfile::tempdir().expect("temp dir");
    let apply_database = apply_dir.path().join("controller.sqlite");
    let apply_arg = apply_database.to_string_lossy().into_owned();
    let store = Store::open(&apply_database).expect("open apply store");
    for index in 0..5 {
        insert_observation(
            &store,
            &format!("obs-rollback-{index}"),
            "2026-01-01T00:00:00Z",
        );
    }
    drop(store);
    inject_audit_event_failure(&apply_database, "retention.apply");
    run_ocfleet_failure(&[
        "--database",
        &apply_arg,
        "retention",
        "apply",
        "--scope",
        "observations",
        "--before",
        "2026-06-01T00:00:00Z",
        "--limit",
        "5",
        "--batch-size",
        "2",
        "--operation-id",
        "retention-00000000-0000-4000-8000-000000000010",
    ]);
    assert_eq!(observation_count(&apply_database), 5);
    assert_eq!(audit_event_count(&apply_database, "retention.apply"), 0);
}

#[test]
fn retention_tests_multiscope_retry_resumes_after_audited_partial_progress() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    insert_observation(&store, "obs-multiscope", "2026-01-01T00:00:00Z");
    store
        .insert_observability_run(&ObservabilityRunInsert {
            run_id: "run-multiscope".to_string(),
            job_id: None,
            started_at: "2026-01-01T00:00:00Z".to_string(),
            finished_at: Some("2026-01-01T00:00:00Z".to_string()),
            status: "succeeded".to_string(),
            triggered_by: "scheduler.run.once".to_string(),
            summary_json: json!({"result_class": "scheduler_summary"}),
        })
        .expect("insert run");
    insert_old_health_and_alert(&store);
    drop(store);

    Connection::open(&database)
        .expect("open db")
        .execute_batch(
            "CREATE TRIGGER fail_health_retention_audit
             BEFORE INSERT ON controller_audit_log
             WHEN NEW.event = 'retention.apply'
              AND json_extract(NEW.detail_json, '$.target_id') = 'health-snapshots'
             BEGIN
               SELECT RAISE(FAIL, 'injected scope audit failure');
             END;",
        )
        .expect("install scope failure trigger");
    let operation_id = "retention-00000000-0000-4000-8000-000000000011";
    run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "retention",
        "apply",
        "--operation-id",
        operation_id,
    ]);
    assert_eq!(table_count(&database, "probe_observations"), 0);
    assert_eq!(table_count(&database, "observability_runs"), 0);
    assert_eq!(table_count(&database, "health_snapshots"), 1);
    assert_eq!(table_count(&database, "alert_events"), 1);
    assert_eq!(audit_event_count(&database, "retention.apply"), 2);

    Connection::open(&database)
        .expect("open db")
        .execute("DROP TRIGGER fail_health_retention_audit", [])
        .expect("drop failure trigger");
    run_ocfleet(&[
        "--database",
        &database_arg,
        "retention",
        "apply",
        "--operation-id",
        operation_id,
    ]);
    for table in [
        "probe_observations",
        "observability_runs",
        "health_snapshots",
        "health_history",
        "health_rollups",
        "alert_events",
    ] {
        assert_eq!(table_count(&database, table), 0);
    }
    assert_eq!(audit_event_count(&database, "retention.apply"), 6);
}

#[test]
fn retention_tests_apply_deletes_expired_observability_runs() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    for (run_id, started_at) in [
        ("run-old", "2026-01-01T00:00:00Z"),
        ("run-new", "2099-07-08T00:00:00Z"),
    ] {
        store
            .insert_observability_run(&ObservabilityRunInsert {
                run_id: run_id.to_string(),
                job_id: None,
                started_at: started_at.to_string(),
                finished_at: Some(started_at.to_string()),
                status: "succeeded".to_string(),
                triggered_by: "scheduler.run.once".to_string(),
                summary_json: json!({"result_class": "scheduler_summary"}),
            })
            .expect("insert run");
    }
    drop(store);

    run_ocfleet(&[
        "--database",
        &database_arg,
        "retention",
        "set",
        "observability-runs",
        "--max-age",
        "7d",
    ]);
    run_ocfleet(&["--database", &database_arg, "retention", "apply"]);

    assert_eq!(run_count(&database), 1);
    let remaining: String = Connection::open(&database)
        .expect("open db")
        .query_row("SELECT run_id FROM observability_runs", [], |row| {
            row.get(0)
        })
        .expect("remaining run");
    assert_eq!(remaining, "run-new");
}

#[test]
fn retention_tests_apply_dry_run_does_not_delete() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    insert_observation(&store, "obs-old", "2026-01-01T00:00:00Z");
    let audit_count_before = store.audit_count().expect("count audit before dry-run");
    drop(store);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "retention",
        "apply",
        "--dry-run",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("scope=observations"));
    assert!(stdout.contains("matched_count=1"));
    assert!(stdout.contains("deleted_count=1"));
    assert!(stdout.contains("oldest_candidate=2026-01-01T00:00:00Z"));
    assert!(stdout.contains("newest_candidate=2026-01-01T00:00:00Z"));
    assert!(stdout.contains("dry_run=true"));

    let store = Store::open(&database).expect("reopen store");
    assert_eq!(
        store.audit_count().expect("count audit after dry-run"),
        audit_count_before,
        "retention dry-run must not write audit rows"
    );
    assert_eq!(
        store
            .list_probe_observations(None, 10)
            .expect("list observations")
            .len(),
        1
    );
}

#[test]
fn retention_tests_apply_json_report_includes_window_and_candidates() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    insert_observation(&store, "obs-old", "2026-01-01T00:00:00Z");
    insert_observation(&store, "obs-new", "2026-07-08T00:00:00Z");
    drop(store);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "retention",
        "apply",
        "--dry-run",
        "--scope",
        "observations",
        "--before",
        "2026-06-01T00:00:00Z",
        "--json",
    ]);
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid JSON report");

    assert_eq!(report["dry_run"], true);
    assert_eq!(report["scopes"].as_array().expect("scopes").len(), 1);
    let scope = &report["scopes"][0];
    assert_eq!(scope["scope"], "observations");
    assert_eq!(scope["cutoff"], "2026-06-01T00:00:00Z");
    assert_eq!(scope["matched_count"], 1);
    assert_eq!(scope["rows_deleted"], 0);
    assert_eq!(scope["oldest_candidate"], "2026-01-01T00:00:00Z");
    assert_eq!(scope["newest_candidate"], "2026-01-01T00:00:00Z");
    assert!(scope["report_checksum"].as_str().expect("checksum").len() >= 64);
}

#[test]
fn retention_tests_explain_is_dry_run_and_does_not_delete_or_audit() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    insert_observation(&store, "obs-old", "2026-01-01T00:00:00Z");
    insert_observation(&store, "obs-new", "2026-07-08T00:00:00Z");
    store
        .set_retention_policy(
            &ocfleet_cli::store::RetentionPolicyRecord {
                scope: "observations".to_string(),
                max_age_days: None,
                max_rows: Some(1),
                updated_at: "2026-07-09T00:00:00Z".to_string(),
            },
            "test-setup",
        )
        .expect("set policy");
    drop(store);
    let audit_before = audit_count(&database);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "retention",
        "explain",
        "--scope",
        "observations",
        "--json",
    ]);
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid explain JSON");

    assert_eq!(report["scope"], "observations");
    assert_eq!(report["dry_run"], true);
    assert_eq!(report["effective_policy"]["max_rows"], 1);
    assert_eq!(report["cutoff"], Value::Null);
    assert_eq!(report["matched_count"], 1);
    assert_eq!(report["oldest_candidate"], "2026-01-01T00:00:00Z");
    assert_eq!(report["newest_candidate"], "2026-01-01T00:00:00Z");
    assert_eq!(observation_count(&database), 2);
    assert_eq!(audit_count(&database), audit_before);
}

#[test]
fn retention_tests_apply_deletes_in_batches_and_audits_report() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    for index in 0..5 {
        insert_observation(&store, &format!("obs-old-{index}"), "2026-01-01T00:00:00Z");
    }
    drop(store);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "retention",
        "apply",
        "--scope",
        "observations",
        "--before",
        "2026-06-01T00:00:00Z",
        "--limit",
        "3",
        "--batch-size",
        "2",
        "--operation-id",
        "retention-00000000-0000-4000-8000-000000000020",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("matched_count=5"));
    assert!(stdout.contains("rows_deleted=3"));
    assert!(stdout.contains("batch_count=2"));
    assert_eq!(observation_count(&database), 2);

    let (event, ok, detail) = latest_audit_with_ok(&database);
    assert_eq!(event, "retention.apply");
    assert_eq!(ok, 1);
    assert_eq!(detail["scope"], "observations");
    assert_eq!(detail["dry_run"], false);
    assert_eq!(detail["matched_count"], 5);
    assert_eq!(detail["deleted_count"], 3);
    assert_eq!(detail["batch_count"], 2);
    let audit_checksum = detail["report_checksum"].as_str().expect("checksum");
    assert!(audit_checksum.len() >= 64);
    assert!(stdout.contains(audit_checksum));
    assert_eq!(
        Connection::open(&database)
            .expect("open db")
            .query_row(
                "SELECT request_id FROM controller_audit_log WHERE event = 'retention.apply'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("retention operation id"),
        "retention-00000000-0000-4000-8000-000000000020"
    );

    let audit_count = audit_event_count(&database, "retention.apply");
    let replay = run_ocfleet(&[
        "--database",
        &database_arg,
        "retention",
        "apply",
        "--scope",
        "observations",
        "--before",
        "2026-06-01T00:00:00Z",
        "--limit",
        "3",
        "--batch-size",
        "2",
        "--operation-id",
        "retention-00000000-0000-4000-8000-000000000020",
    ]);
    assert!(String::from_utf8_lossy(&replay.stdout).contains("rows_deleted=3"));
    assert_eq!(observation_count(&database), 2);
    assert_eq!(audit_event_count(&database, "retention.apply"), audit_count);

    let conflict = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "retention",
        "apply",
        "--scope",
        "observations",
        "--before",
        "2026-05-01T00:00:00Z",
        "--limit",
        "3",
        "--batch-size",
        "2",
        "--operation-id",
        "retention-00000000-0000-4000-8000-000000000020",
    ]);
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("retention operation conflict"));
    assert_eq!(observation_count(&database), 2);
}

#[test]
fn retention_writer_rejects_invalid_bounds_and_actor_replay() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let store = Store::open(&database).expect("open store");
    insert_observation(&store, "obs-writer", "2026-01-01T00:00:00Z");
    let input = RetentionApplyInput {
        operation_id: "retention-00000000-0000-4000-8000-000000000030".to_string(),
        scope: "observations".to_string(),
        cutoff: Some("2026-06-01T00:00:00Z".to_string()),
        max_age_days: None,
        max_rows: None,
        limit: Some(1),
        batch_size: 1,
    };
    let result = StoreWriter::write_retention_apply(&store, &input, "retention-user")
        .expect("apply retention");
    assert_eq!(result.rows_deleted, 1);
    assert!(matches!(
        StoreWriter::write_retention_apply(&store, &input, "different-actor"),
        Err(StoreError::RetentionOperationConflict { .. })
    ));

    let mut invalid = input;
    invalid.operation_id = "invalid-operation".to_string();
    assert!(matches!(
        StoreWriter::write_retention_apply(&store, &invalid, "retention-user"),
        Err(StoreError::InvalidInput(_))
    ));

    insert_observation(&store, "obs-policy-replay", "2026-01-02T00:00:00Z");
    let policy_derived = RetentionApplyInput {
        operation_id: "retention-00000000-0000-4000-8000-000000000031".to_string(),
        scope: "observations".to_string(),
        cutoff: None,
        max_age_days: Some(30),
        max_rows: None,
        limit: Some(1),
        batch_size: 1,
    };
    let first = StoreWriter::write_retention_apply(&store, &policy_derived, "retention-user")
        .expect("apply policy-derived retention");
    let retry = StoreWriter::write_retention_apply(&store, &policy_derived, "retention-user")
        .expect("replay policy-derived retention");
    assert_eq!(retry, first);
    assert!(first.cutoff.is_some());
    assert_eq!(audit_event_count(&database, "retention.apply"), 2);
}

#[test]
fn retention_writer_serializes_concurrent_exact_operation_ids() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let store = Store::open(&database).expect("open store");
    for index in 0..3 {
        insert_observation(
            &store,
            &format!("obs-concurrent-{index}"),
            "2026-01-01T00:00:00Z",
        );
    }
    drop(store);
    let input = RetentionApplyInput {
        operation_id: "retention-00000000-0000-4000-8000-000000000040".to_string(),
        scope: "observations".to_string(),
        cutoff: Some("2026-06-01T00:00:00Z".to_string()),
        max_age_days: None,
        max_rows: None,
        limit: Some(2),
        batch_size: 1,
    };
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let database = database.clone();
        let input = input.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let store = Store::open(&database).expect("open racing store");
            barrier.wait();
            StoreWriter::write_retention_apply(&store, &input, "retention-user")
        }));
    }
    let results = handles
        .into_iter()
        .map(|handle| handle.join().expect("racing writer joins").expect("apply"))
        .collect::<Vec<_>>();
    assert_eq!(results[0], results[1]);
    assert_eq!(results[0].rows_deleted, 2);
    assert_eq!(observation_count(&database), 1);
    assert_eq!(audit_event_count(&database, "retention.apply"), 1);
}

#[test]
fn retention_tests_apply_no_window_policy_is_noop_without_full_delete() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    insert_observation(&store, "obs-old", "2026-01-01T00:00:00Z");
    store
        .set_retention_policy(
            &ocfleet_cli::store::RetentionPolicyRecord {
                scope: "observations".to_string(),
                max_age_days: None,
                max_rows: None,
                updated_at: "2026-07-09T00:00:00Z".to_string(),
            },
            "test-setup",
        )
        .expect("set no-op policy");
    drop(store);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "retention",
        "apply",
        "--scope",
        "observations",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("matched_count=0"));
    assert!(stdout.contains("rows_deleted=0"));
    assert_eq!(observation_count(&database), 1);
}

#[test]
fn retention_tests_apply_deletes_expired_probe_observations() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    insert_observation(&store, "obs-old", "2026-01-01T00:00:00Z");
    insert_observation(&store, "obs-new", "2026-07-08T00:00:00Z");
    insert_old_health_and_alert(&store);
    drop(store);

    run_ocfleet(&["--database", &database_arg, "retention", "apply"]);

    let store = Store::open(&database).expect("reopen store");
    let observations = store
        .list_probe_observations(None, 10)
        .expect("list observations");
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].observation_id, "obs-new");
}

#[test]
fn retention_tests_apply_does_not_delete_controller_audit_log() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    let mut event = AuditEvent::new("retention-user", "probe.history");
    event.ts = "2026-01-01T00:00:00Z".to_string();
    event.method = Some("probe.controller.ping".to_string());
    event.node_id = Some("hk-ocserv-01".to_string());
    event.ok = Some(true);
    event.detail_json = json!({"message": "legacy audit history"});
    store.insert_audit(&event).expect("insert audit");
    drop(store);
    let before = audit_count(&database);

    run_ocfleet(&["--database", &database_arg, "retention", "apply"]);

    assert!(audit_count(&database) >= before);
    let (event, detail) = latest_audit(&database);
    assert_eq!(event, "retention.apply");
    assert!(detail.get("scope").is_some());
    assert!(detail.get("cutoff").is_some());
    assert!(detail.get("deleted_count").is_some());
    assert!(detail.get("dry_run").is_some());
}

#[test]
fn retention_tests_probe_history_json_outputs_valid_json() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let store = Store::open(&database).expect("open store");
    insert_observation(&store, "obs-json", "2026-07-08T00:00:00Z");
    drop(store);

    let output = run_ocfleet(&["--database", &database_arg, "probe", "history", "--json"]);
    let value: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");

    assert_eq!(value["source"], "probe_observations");
    assert_eq!(value["record_count"], 1);
    assert_eq!(value["records"][0]["observation_id"], "obs-json");
    assert_eq!(value["records"][0]["method"], "probe.controller.ping");
}

#[test]
fn retention_tests_probe_history_rejects_limit_above_1000() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "probe",
        "history",
        "--limit",
        "1001",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--limit must be at most 1000"));
}
