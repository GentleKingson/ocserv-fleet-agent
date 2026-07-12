use ocfleet_cli::audit::AuditEvent;
use ocfleet_cli::backend::StoreWriter;
use ocfleet_cli::storage_payloads::{
    HealthDegradedMethodsPayloadV1, HealthSummaryPayloadV1, SchedulerSelectorPayloadV1,
};
use ocfleet_cli::store::{
    AlertDeliveryAttemptRecord, AlertDeliveryAttemptWrite, AlertDeliveryFinalizeWrite,
    AlertDeliveryQueueEnqueue, AlertDeliveryQueueOutcome, AlertEvaluationEntry,
    AlertEvaluationWrite, AlertEventRecord, AlertStateTransition, AlertWebhookHookRecord,
    CURRENT_SCHEMA_VERSION, HealthEvaluationFailure, HealthEvaluationFinish, HealthEvaluationStart,
    HealthRollupRecord, HealthRollupWrite, HealthSnapshotRecord, HealthSnapshotWrite,
    ObservabilityJobRecord, ObservabilityRunInsert, ProbeObservationInsert, RetentionPolicyRecord,
    SchedulerJobClockUpdate, SchedulerOutcomeEntry, SchedulerOutcomeWrite, SchedulerRunFinish,
    SchedulerRunStart, Store, StoreError,
};
use ocfleet_protocol::method::{
    OCSERV_CONFIG_FINGERPRINT, OCSERV_SERVICE_SUMMARY, OCSERV_SESSIONS_SUMMARY, OCSERV_VERSION,
    PROBE_CONTROLLER_PING,
};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::sync::{Arc, Barrier};

const TEST_ACTOR: &str = "observability-store-test";

fn health_methods(methods: &[&str]) -> Value {
    HealthDegradedMethodsPayloadV1::new(methods.iter().map(|value| (*value).to_string()).collect())
        .expect("valid health methods")
        .to_value()
}

fn health_summary(status: &str) -> Value {
    HealthSummaryPayloadV1::new(None, None, status.to_string(), None, None)
        .expect("valid health summary")
        .to_value()
}

fn open_temp_store() -> (tempfile::TempDir, Store, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let store = Store::open(&db).expect("store opens");
    (dir, store, db)
}

fn sample_job(job_id: &str, enabled: bool) -> ObservabilityJobRecord {
    ObservabilityJobRecord {
        job_id: job_id.to_string(),
        kind: "controller-ping".to_string(),
        selector_json: SchedulerSelectorPayloadV1::new(
            "node_id=hk-ocserv-01".to_string(),
            Some("HK controller ping".to_string()),
        )
        .expect("valid selector")
        .to_value(),
        pair_selector_json: None,
        interval_seconds: 60,
        jitter_seconds: 5,
        timeout_ms: 2_000,
        enabled,
        next_run_at: Some("2026-07-08T08:00:00Z".to_string()),
        last_run_at: None,
        created_at: "2026-07-08T07:00:00Z".to_string(),
        updated_at: "2026-07-08T07:00:00Z".to_string(),
    }
}

#[test]
fn scheduler_claims_are_deterministic_exclusive_expiring_and_fenced() {
    let (_dir, store_a, db) = open_temp_store();
    let job_b = sample_job("job-claim-b", true);
    let job_a = sample_job("job-claim-a", true);
    StoreWriter::write_scheduler_job_add(&store_a, &job_b, TEST_ACTOR).expect("add job b");
    StoreWriter::write_scheduler_job_add(&store_a, &job_a, TEST_ACTOR).expect("add job a");
    let store_b = Store::open(&db).expect("open competing store");

    let claim_a = StoreWriter::write_scheduler_claim_next_due(
        &store_a,
        "scheduler-a",
        "2026-07-08T09:00:00Z",
        30,
        TEST_ACTOR,
    )
    .expect("claim next job")
    .expect("claim acquired");
    assert_eq!(claim_a.job_id, "job-claim-a");
    assert_eq!(claim_a.fence_token, 1);

    let claim_b = StoreWriter::write_scheduler_claim_next_due(
        &store_b,
        "scheduler-b",
        "2026-07-08T09:00:01Z",
        30,
        TEST_ACTOR,
    )
    .expect("claim distinct due job")
    .expect("second job acquired");
    assert_eq!(claim_b.job_id, "job-claim-b");
    assert!(
        StoreWriter::write_scheduler_claim(
            &store_b,
            "job-claim-a",
            "scheduler-b",
            "2026-07-08T09:00:01Z",
            30,
            TEST_ACTOR,
        )
        .expect("contended claim")
        .is_none()
    );

    let takeover = StoreWriter::write_scheduler_claim(
        &store_b,
        "job-claim-a",
        "scheduler-b",
        "2026-07-08T09:00:30Z",
        30,
        TEST_ACTOR,
    )
    .expect("expired takeover")
    .expect("takeover acquired");
    assert_eq!(takeover.fence_token, 2);
    assert!(matches!(
        StoreWriter::write_scheduler_claim_renew(
            &store_a,
            &claim_a,
            "2026-07-08T09:00:31Z",
            30,
            TEST_ACTOR,
        ),
        Err(StoreError::SchedulerClaimLost(job_id)) if job_id == "job-claim-a"
    ));
    assert!(matches!(
        StoreWriter::write_scheduler_claim_release(
            &store_a,
            &claim_a,
            "2026-07-08T09:00:31Z",
            TEST_ACTOR,
        ),
        Err(StoreError::SchedulerClaimLost(job_id)) if job_id == "job-claim-a"
    ));
    assert_eq!(
        store_b
            .get_scheduler_job_claim("job-claim-a")
            .expect("read current claim")
            .expect("claim exists"),
        takeover
    );
}

#[test]
fn scheduler_claim_mutation_rolls_back_when_audit_fails() {
    let (_dir, store, db) = open_temp_store();
    let job = sample_job("job-claim-audit-rollback", true);
    StoreWriter::write_scheduler_job_add(&store, &job, TEST_ACTOR).expect("add job");
    inject_job_audit_failure(&db, "scheduler.claim.acquire");

    let result = StoreWriter::write_scheduler_claim(
        &store,
        &job.job_id,
        "scheduler-a",
        "2026-07-08T09:00:00Z",
        30,
        TEST_ACTOR,
    );
    assert!(matches!(result, Err(StoreError::Sqlite(_))));
    assert!(
        store
            .get_scheduler_job_claim(&job.job_id)
            .expect("read rolled-back claim")
            .is_none()
    );
}

#[test]
fn competing_scheduler_instances_claim_one_due_job_exactly_once() {
    let (_dir, store, db) = open_temp_store();
    let job = sample_job("job-competing-claim", true);
    StoreWriter::write_scheduler_job_add(&store, &job, TEST_ACTOR).expect("add job");
    drop(store);

    let barrier = Arc::new(Barrier::new(3));
    let handles = ["scheduler-a", "scheduler-b"].map(|owner| {
        let barrier = Arc::clone(&barrier);
        let db = db.clone();
        std::thread::spawn(move || {
            let store = Store::open(&db).expect("open competing store");
            barrier.wait();
            StoreWriter::write_scheduler_claim_due(
                &store,
                "job-competing-claim",
                owner,
                "2026-07-08T09:00:00Z",
                30,
                TEST_ACTOR,
            )
            .expect("attempt competing claim")
        })
    });
    barrier.wait();
    let claims = handles
        .into_iter()
        .map(|handle| handle.join().expect("join claim thread"))
        .collect::<Vec<_>>();
    assert_eq!(claims.iter().filter(|claim| claim.is_some()).count(), 1);
    assert_eq!(claims.iter().filter(|claim| claim.is_none()).count(), 1);
}

#[test]
fn scheduler_stale_fence_cannot_persist_run_outcomes_after_takeover() {
    let (_dir, store_a, db) = open_temp_store();
    let job = sample_job("job-stale-fence", true);
    StoreWriter::write_scheduler_job_add(&store_a, &job, TEST_ACTOR).expect("add job");
    let claim_a = StoreWriter::write_scheduler_claim(
        &store_a,
        &job.job_id,
        "scheduler-a",
        "2026-07-08T07:59:50Z",
        30,
        TEST_ACTOR,
    )
    .expect("claim job")
    .expect("claim acquired");
    let start = scheduler_start(&job.job_id, "run-stale-fence");
    StoreWriter::write_scheduler_claimed_run_start(&store_a, &start, &claim_a, TEST_ACTOR)
        .expect("start claimed run");

    let store_b = Store::open(&db).expect("open takeover store");
    let claim_b = StoreWriter::write_scheduler_claim(
        &store_b,
        &job.job_id,
        "scheduler-b",
        "2026-07-08T08:00:20Z",
        30,
        TEST_ACTOR,
    )
    .expect("take over expired claim")
    .expect("takeover acquired");
    assert_eq!(claim_b.fence_token, claim_a.fence_token + 1);
    let recovered = store_b
        .get_observability_run(&start.run_id)
        .expect("load recovered run")
        .expect("recovered run exists");
    assert_eq!(recovered.status, "failed");
    assert_eq!(
        recovered.finished_at.as_deref(),
        Some("2026-07-08T08:00:20Z")
    );
    let recovery_audits: i64 = Connection::open(&db)
        .expect("open recovery audit query")
        .query_row(
            "SELECT COUNT(*) FROM controller_audit_log
             WHERE event = 'scheduler.run.recover' AND error_code = 'SCHEDULER_LEASE_EXPIRED'",
            [],
            |row| row.get(0),
        )
        .expect("count recovery audits");
    assert_eq!(recovery_audits, 1);

    let outcome = SchedulerOutcomeWrite {
        job_id: job.job_id.clone(),
        run_id: Some(start.run_id.clone()),
        entries: vec![scheduler_outcome_entry(
            TEST_ACTOR,
            "scheduler.task.outcome",
            Some(&start.run_id),
            "obs-stale-fence",
            PROBE_CONTROLLER_PING,
            true,
        )],
        job_clock: None,
    };
    assert!(matches!(
        StoreWriter::write_scheduler_outcome(&store_a, &outcome, TEST_ACTOR),
        Err(StoreError::SchedulerClaimLost(job_id)) if job_id == "job-stale-fence"
    ));
    assert!(
        store_a
            .list_probe_observations(None, 10)
            .expect("list observations")
            .is_empty()
    );
}

fn latest_job_audit(database: &std::path::Path) -> (String, String, Value) {
    let conn = Connection::open(database).expect("open db for audit query");
    let (actor, event, detail): (String, String, String) = conn
        .query_row(
            "SELECT actor, event, detail_json FROM controller_audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("latest scheduler job audit");
    (
        actor,
        event,
        serde_json::from_str(&detail).expect("parse scheduler job audit detail"),
    )
}

fn inject_job_audit_failure(database: &std::path::Path, event: &str) {
    let conn = Connection::open(database).expect("open db for audit failure injection");
    conn.execute_batch(&format!(
        "CREATE TRIGGER fail_scheduler_job_audit
         BEFORE INSERT ON controller_audit_log
         WHEN NEW.event = '{event}'
         BEGIN
           SELECT RAISE(ABORT, 'injected scheduler job audit failure');
         END;"
    ))
    .expect("install scheduler job audit failure trigger");
}

fn assert_injected_job_audit_failure(result: Result<(), StoreError>) {
    match result {
        Err(StoreError::Sqlite(error)) => assert!(
            error
                .to_string()
                .contains("injected scheduler job audit failure"),
            "unexpected SQLite error: {error}"
        ),
        other => panic!("expected injected scheduler job audit failure, got {other:?}"),
    }
}

fn assert_job_state_rolls_back_when_audit_fails(enabled_before: bool, enabled_after: bool) {
    let (_dir, store, db) = open_temp_store();
    let job = sample_job("job-state-rollback", enabled_before);
    StoreWriter::write_scheduler_job_add(&store, &job, TEST_ACTOR).expect("seed job");
    let before = store
        .get_observability_job(&job.job_id)
        .expect("load job before failed state change")
        .expect("job exists before failed state change");
    let event = if enabled_after {
        "scheduler.job.enable"
    } else {
        "scheduler.job.disable"
    };
    inject_job_audit_failure(&db, event);

    let result = if enabled_after {
        StoreWriter::write_scheduler_job_enable(&store, &job.job_id, TEST_ACTOR)
    } else {
        StoreWriter::write_scheduler_job_disable(&store, &job.job_id, TEST_ACTOR)
    };
    assert_injected_job_audit_failure(result);

    let after = store
        .get_observability_job(&job.job_id)
        .expect("load job after failed state change")
        .expect("job remains after failed state change");
    assert_eq!(after, before);
    assert_eq!(after.updated_at, before.updated_at);
    assert_eq!(store.audit_count().expect("audit count"), 1);
}

fn scheduler_start(job_id: &str, run_id: &str) -> SchedulerRunStart {
    SchedulerRunStart {
        run_id: run_id.to_string(),
        job_id: job_id.to_string(),
        started_at: "2026-07-08T08:00:00Z".to_string(),
    }
}

fn scheduler_clock(job_id: &str) -> SchedulerJobClockUpdate {
    SchedulerJobClockUpdate {
        job_id: job_id.to_string(),
        next_run_at: "2026-07-08T08:02:00Z".to_string(),
        last_run_at: "2026-07-08T08:01:00Z".to_string(),
    }
}

fn scheduler_outcome_entry(
    actor: &str,
    event: &str,
    run_id: Option<&str>,
    observation_id: &str,
    method: &str,
    ok: bool,
) -> SchedulerOutcomeEntry {
    let error_code = (!ok).then(|| {
        if event == "scheduler.job.invalid" {
            "SCHEDULER_JOB_INVALID".to_string()
        } else {
            "SCHEDULER_TEST_FAILED".to_string()
        }
    });
    let observation = ProbeObservationInsert {
        observation_id: observation_id.to_string(),
        run_id: run_id.map(ToOwned::to_owned),
        node_id: Some("scheduler-node".to_string()),
        endpoint_id: Some("scheduler-endpoint".to_string()),
        method: method.to_string(),
        ok: Some(ok),
        error_code: error_code.clone(),
        duration_ms: Some(7),
        observed_at: "2026-07-08T08:00:30Z".to_string(),
        expires_at: None,
        result_class: "controller_rpc_summary".to_string(),
        summary_json: json!({
            "message": "bounded scheduler test summary",
            "result_class": "controller_rpc_summary",
        }),
    };
    let mut audit = AuditEvent::new(actor, event);
    audit.node_id = observation.node_id.clone();
    audit.endpoint_id = observation.endpoint_id.clone();
    audit.method = Some(observation.method.clone());
    audit.ok = observation.ok;
    audit.error_code = error_code;
    audit.duration_ms = observation.duration_ms;
    audit.detail_json = json!({"result_class": "scheduler_summary"});
    SchedulerOutcomeEntry { observation, audit }
}

fn scheduler_outcome(
    job_id: &str,
    run_id: Option<&str>,
    entries: Vec<SchedulerOutcomeEntry>,
) -> SchedulerOutcomeWrite {
    SchedulerOutcomeWrite {
        job_id: job_id.to_string(),
        run_id: run_id.map(ToOwned::to_owned),
        entries,
        job_clock: None,
    }
}

fn install_failure_trigger(database: &std::path::Path, sql: &str) {
    Connection::open(database)
        .expect("open database for scheduler failure injection")
        .execute_batch(sql)
        .expect("install scheduler failure trigger");
}

fn table_count(database: &std::path::Path, table: &str) -> i64 {
    Connection::open(database)
        .expect("open database for count")
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .expect("count scheduler table")
}

fn assert_injected_scheduler_failure(result: Result<(), StoreError>, marker: &str) {
    match result {
        Err(StoreError::Sqlite(error)) => assert!(
            error.to_string().contains(marker),
            "unexpected SQLite error: {error}"
        ),
        other => panic!("expected injected scheduler failure, got {other:?}"),
    }
}

#[test]
fn observability_store_tests_new_database_uses_current_schema_version() {
    let (_dir, store, _db) = open_temp_store();

    assert_eq!(
        store.current_schema_version().expect("version"),
        CURRENT_SCHEMA_VERSION
    );
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
        "health_policy",
        "alert_hooks",
        "alert_delivery_attempts",
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
fn observability_store_tests_inserts_webhook_hook_and_delivery_attempt() {
    let (_dir, store, db) = open_temp_store();
    let hook = AlertWebhookHookRecord {
        hook_id: "webhook-1".to_string(),
        name: "ops".to_string(),
        hook_type: "webhook".to_string(),
        endpoint_url: "https://93.184.216.34/alerts".to_string(),
        endpoint_url_redacted: "https://93.184.216.34/<redacted>".to_string(),
        endpoint_host: "93.184.216.34".to_string(),
        host_allow: vec!["93.184.216.34".to_string()],
        hmac_key_id: "abcd1234abcd1234".to_string(),
        enabled: true,
        max_attempts: 2,
        timeout_ms: 1_500,
        created_at: "2026-07-08T07:00:00Z".to_string(),
        updated_at: "2026-07-08T07:00:00Z".to_string(),
    };
    StoreWriter::write_alert_webhook_hook_create(&store, &hook, TEST_ACTOR)
        .expect("insert webhook hook");
    store
        .upsert_alert_event(&AlertEventRecord {
            alert_id: "alert-1".to_string(),
            dedupe_key: "node:hk-ocserv-01:node_stale".to_string(),
            node_id: Some("hk-ocserv-01".to_string()),
            severity: "warning".to_string(),
            state: "open".to_string(),
            reason_code: "NODE_STALE".to_string(),
            first_seen_at: "2026-07-08T07:00:00Z".to_string(),
            last_seen_at: "2026-07-08T07:00:00Z".to_string(),
            last_sent_at: None,
            resolved_at: None,
            detail_json: json!({"summary": {"status": "stale"}}),
        })
        .expect("insert alert");
    let attempt = AlertDeliveryAttemptRecord {
        attempt_id: "attempt-1".to_string(),
        alert_id: "alert-1".to_string(),
        hook_id: "webhook-1".to_string(),
        attempt_no: 1,
        attempted_at: "2026-07-08T07:01:00Z".to_string(),
        status: "failed".to_string(),
        http_status_class: Some("5xx".to_string()),
        error_code: Some("WEBHOOK_HTTP_5XX".to_string()),
        bytes_sent: 512,
    };
    StoreWriter::write_alert_delivery_attempt(
        &store,
        &AlertDeliveryAttemptWrite {
            attempt: attempt.clone(),
        },
        TEST_ACTOR,
    )
    .expect("insert delivery attempt");

    let hooks = store
        .list_alert_webhook_hooks()
        .expect("list webhook hooks");
    assert_eq!(hooks, vec![hook.clone()]);
    assert_eq!(
        store
            .get_alert_webhook_hook("webhook-1")
            .expect("get webhook hook"),
        Some(hook)
    );
    let attempts = store
        .list_alert_delivery_attempts()
        .expect("list delivery attempts");
    assert_eq!(attempts, vec![attempt]);

    let conn = Connection::open(&db).expect("open delivery detail fixture");
    let raw: String = conn
        .query_row(
            "SELECT detail_json FROM alert_delivery_attempts WHERE attempt_id = 'attempt-1'",
            [],
            |row| row.get(0),
        )
        .expect("read typed delivery detail");
    let mut raw: Value = serde_json::from_str(&raw).expect("typed delivery detail");
    assert_eq!(raw["schema"], "ocfleet.delivery-attempt.detail.v1");
    assert_eq!(raw["bytes_sent"], 512);
    raw["client_address"] = json!("10.0.0.2");
    conn.execute(
        "UPDATE alert_delivery_attempts SET detail_json = ?1 WHERE attempt_id = 'attempt-1'",
        [raw.to_string()],
    )
    .expect("contaminate delivery detail");
    let error = store
        .list_alert_delivery_attempts()
        .expect_err("contaminated delivery detail must fail closed");
    assert!(error.to_string().contains("delivery attempt detail"));
    assert!(!error.to_string().contains("10.0.0.2"));
}

#[test]
fn observability_store_tests_alert_host_allow_is_closed_and_fails_closed() {
    let (_dir, store, db) = open_temp_store();
    let hook = AlertWebhookHookRecord {
        hook_id: "webhook-typed".to_string(),
        name: "typed".to_string(),
        hook_type: "webhook".to_string(),
        endpoint_url: "https://93.184.216.34/alerts".to_string(),
        endpoint_url_redacted: "https://93.184.216.34/<redacted>".to_string(),
        endpoint_host: "93.184.216.34".to_string(),
        host_allow: vec!["93.184.216.34".to_string()],
        hmac_key_id: "abcd1234abcd1234".to_string(),
        enabled: true,
        max_attempts: 2,
        timeout_ms: 1_500,
        created_at: "2026-07-08T07:00:00Z".to_string(),
        updated_at: "2026-07-08T07:00:00Z".to_string(),
    };
    StoreWriter::write_alert_webhook_hook_create(&store, &hook, TEST_ACTOR)
        .expect("insert typed webhook hook");
    let conn = Connection::open(&db).expect("open fixture database");
    let raw: String = conn
        .query_row(
            "SELECT host_allow_json FROM alert_hooks WHERE hook_id = 'webhook-typed'",
            [],
            |row| row.get(0),
        )
        .expect("read stored host allowlist");
    let mut raw: Value = serde_json::from_str(&raw).expect("typed host allowlist");
    assert_eq!(raw["schema"], "ocfleet.alert.host-allow.v1");
    assert_eq!(raw["hosts"], json!(["93.184.216.34"]));
    raw["client_address"] = json!("10.0.0.2");
    conn.execute(
        "UPDATE alert_hooks SET host_allow_json = ?1 WHERE hook_id = 'webhook-typed'",
        [raw.to_string()],
    )
    .expect("contaminate stored host allowlist");

    let error = store
        .list_alert_webhook_hooks()
        .expect_err("contaminated host allowlist must fail closed");
    assert!(error.to_string().contains("host allowlist"));
    assert!(!error.to_string().contains("10.0.0.2"));
}

#[test]
fn observability_store_tests_inserts_and_lists_observability_job() {
    let (_dir, store, db) = open_temp_store();
    let job = sample_job("job-1", true);

    StoreWriter::write_scheduler_job_add(&store, &job, TEST_ACTOR)
        .expect("insert observability job");

    let jobs = store
        .list_observability_jobs()
        .expect("list observability jobs");
    assert_eq!(jobs, vec![job.clone()]);
    let (actor, event, detail) = latest_job_audit(&db);
    assert_eq!(actor, TEST_ACTOR);
    assert_eq!(event, "scheduler.job.add");
    assert_eq!(detail["target_type"], "observability_job");
    assert_eq!(detail["target_id"], "job-1");
    assert_eq!(detail["before"], Value::Null);
    assert_eq!(detail["after"]["enabled"], true);
    assert_eq!(detail["selector_class"], "node_id");
    assert_eq!(detail["after"]["selector_class"], "node_id");
    assert!(detail.get("name").is_none());
    assert!(detail.get("selector").is_none());
    assert!(detail["after"].get("selector_json").is_none());
    assert!(detail["after"].get("pair_selector_json").is_none());
    assert!(detail["after"].get("updated_at").is_none());

    StoreWriter::write_scheduler_job_disable(&store, "job-1", TEST_ACTOR)
        .expect("disable observability job");
    let jobs = store
        .list_observability_jobs()
        .expect("list observability jobs after disable");
    assert_eq!(jobs[0].job_id, job.job_id);
    assert!(!jobs[0].enabled);
    let (actor, event, detail) = latest_job_audit(&db);
    assert_eq!(actor, TEST_ACTOR);
    assert_eq!(event, "scheduler.job.disable");
    assert_eq!(detail["job_id"], "job-1");
    assert_eq!(detail["enabled"], false);
    assert_eq!(detail["before"]["enabled"], true);
    assert_eq!(detail["after"]["enabled"], false);
}

#[test]
fn observability_store_tests_scheduler_job_add_rolls_back_when_audit_fails() {
    let (_dir, store, db) = open_temp_store();
    let job = sample_job("job-add-rollback", true);
    inject_job_audit_failure(&db, "scheduler.job.add");

    assert_injected_job_audit_failure(StoreWriter::write_scheduler_job_add(
        &store, &job, TEST_ACTOR,
    ));
    assert!(
        store
            .get_observability_job(&job.job_id)
            .expect("load job after failed add")
            .is_none()
    );
    assert_eq!(store.audit_count().expect("audit count"), 0);
}

#[test]
fn observability_store_tests_scheduler_job_add_requires_versioned_closed_payloads() {
    let (_dir, store, _db) = open_temp_store();

    for (job_id, selector) in [
        ("job-unversioned", json!({"selector": "role=ocserv"})),
        (
            "job-future-schema",
            json!({
                "schema": "ocfleet.scheduler.selector.v2",
                "selector": "role=ocserv",
                "name": null
            }),
        ),
        (
            "job-contaminated",
            json!({
                "schema": "ocfleet.scheduler.selector.v1",
                "selector": "role=ocserv",
                "name": null,
                "client_address": "10.0.0.2"
            }),
        ),
    ] {
        let mut job = sample_job(job_id, true);
        job.selector_json = selector;
        assert!(StoreWriter::write_scheduler_job_add(&store, &job, TEST_ACTOR).is_err());
    }

    assert_eq!(store.audit_count().expect("audit count"), 0);
}

#[test]
fn observability_store_tests_scheduler_job_state_rolls_back_exact_row_when_audit_fails() {
    assert_job_state_rolls_back_when_audit_fails(true, false);
    assert_job_state_rolls_back_when_audit_fails(false, true);
}

#[test]
fn observability_store_tests_scheduler_job_state_rejects_contaminated_selector_payload() {
    let (_dir, store, db) = open_temp_store();
    let job = sample_job("job-closed-audit", true);
    StoreWriter::write_scheduler_job_add(&store, &job, TEST_ACTOR).expect("seed job");
    Connection::open(&db)
        .expect("open contaminated fixture")
        .execute(
            "UPDATE observability_jobs SET selector_json = ?1 WHERE job_id = ?2",
            [
                r#"{"selector":"role=/etc/ops","name":"credential alpha"}"#,
                job.job_id.as_str(),
            ],
        )
        .expect("contaminate stored job selector");

    assert!(StoreWriter::write_scheduler_job_disable(&store, &job.job_id, TEST_ACTOR).is_err());
    let conn = Connection::open(&db).expect("open db");
    let enabled: i64 = conn
        .query_row(
            "SELECT enabled FROM observability_jobs WHERE job_id = ?1",
            [job.job_id],
            |row| row.get(0),
        )
        .expect("read enabled");
    assert_eq!(enabled, 1);
    assert_eq!(store.audit_count().expect("audit count"), 1);
}

#[test]
fn observability_store_tests_scheduler_job_writer_rejects_invalid_actor_and_missing_job() {
    let (_dir, store, _db) = open_temp_store();
    let job = sample_job("job-invalid-actor", true);

    assert!(matches!(
        StoreWriter::write_scheduler_job_add(&store, &job, "bad\nactor"),
        Err(StoreError::InvalidInput(_))
    ));
    assert!(
        store
            .get_observability_job(&job.job_id)
            .expect("load rejected job")
            .is_none()
    );
    assert!(matches!(
        StoreWriter::write_scheduler_job_enable(&store, "missing-job", TEST_ACTOR),
        Err(StoreError::ObservabilityJobNotFound(job_id)) if job_id == "missing-job"
    ));
    assert!(matches!(
        StoreWriter::write_scheduler_job_disable(&store, "missing-job", TEST_ACTOR),
        Err(StoreError::ObservabilityJobNotFound(job_id)) if job_id == "missing-job"
    ));
    assert_eq!(store.audit_count().expect("audit count"), 0);
}

#[test]
fn observability_store_tests_inserts_and_lists_probe_observation() {
    let (_dir, store, _db) = open_temp_store();
    let observation = ProbeObservationInsert {
        observation_id: "obs-1".to_string(),
        run_id: None,
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
    assert_eq!(observations[0].summary_json["sessions_total"], 12);
    assert_eq!(
        observations[0].summary_json["result_class"],
        "low_sensitive_summary"
    );
}

#[test]
fn observability_store_tests_rejects_forbidden_or_unbounded_summary_storage() {
    let (_dir, store, _db) = open_temp_store();
    for summary_json in [
        json!({"username": "alice"}),
        json!({"user": "alice"}),
        json!({"client_address": "10.0.0.2"}),
        json!({"secret": "hunter2"}),
        json!({"api_token": "opaque123"}),
        json!({"sessionToken": "opaque123"}),
        json!({"authorization": "opaque123"}),
        json!({"cookie": "opaque123"}),
        json!({"cert_san": "vpn.example.test"}),
        json!({"message": "client_ip=10.0.0.2"}),
        json!({"message": "10.0.0.2"}),
        json!({"message": "peer=10.0.0.2"}),
        json!({"message": "peer=10.0.0.2:443"}),
        json!({"message": "from 10.0.0.2."}),
        json!({"message": "peer 10.0.0.2:"}),
        json!({"message": "peer=[2001:db8::1]"}),
        json!({"raw_body": "opaque"}),
        json!({"value": "x".repeat(513)}),
        json!({"values": (0..257).collect::<Vec<_>>() }),
    ] {
        let observation = ProbeObservationInsert {
            observation_id: format!("obs-{}", uuid::Uuid::new_v4()),
            run_id: None,
            node_id: Some("hk-ocserv-01".to_string()),
            endpoint_id: Some("endpoint-1".to_string()),
            method: "probe.controller.ping".to_string(),
            ok: Some(false),
            error_code: Some("RPC_TIMEOUT".to_string()),
            duration_ms: Some(42),
            observed_at: "2026-07-08T07:30:00Z".to_string(),
            expires_at: None,
            result_class: "controller_rpc_summary".to_string(),
            summary_json,
        };
        let result = store.insert_probe_observation(&observation);
        assert!(
            result.is_err(),
            "unsafe summary was accepted: {}",
            observation.summary_json
        );
        let err = result.expect_err("checked error");
        assert!(err.to_string().contains("observation summary"));
    }
    assert!(
        store
            .list_probe_observations(None, 10)
            .expect("list observations")
            .is_empty()
    );
}

#[test]
fn observability_store_tests_insert_and_finish_observability_run() {
    let (_dir, store, db) = open_temp_store();
    let run = ObservabilityRunInsert {
        run_id: "run-1".to_string(),
        job_id: None,
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
    let summary_json: Value = serde_json::from_str(&summary_json).expect("typed run summary");
    assert_eq!(summary_json["schema"], "ocfleet.run.summary.v1");
    assert_eq!(summary_json["status"], "succeeded");
    assert_eq!(summary_json["triggered_by"], "manual");
    assert_eq!(summary_json["observations"], 1);
}

#[test]
fn observability_store_tests_run_summary_is_closed_and_reader_fails_closed() {
    let (_dir, store, db) = open_temp_store();
    let mut run = ObservabilityRunInsert {
        run_id: "run-closed-summary".to_string(),
        job_id: None,
        started_at: "2026-07-08T07:30:00Z".to_string(),
        finished_at: None,
        status: "running".to_string(),
        triggered_by: "manual".to_string(),
        summary_json: json!({"started": true, "client_address": "10.0.0.2"}),
    };
    assert!(store.insert_observability_run(&run).is_err());

    run.summary_json = json!({"started": true});
    store
        .insert_observability_run(&run)
        .expect("canonicalize safe legacy run summary");
    Connection::open(db)
        .expect("open contaminated fixture")
        .execute(
            "UPDATE observability_runs SET summary_json = ?1 WHERE run_id = ?2",
            rusqlite::params![
                json!({
                    "schema": "ocfleet.run.summary.v1",
                    "result_class": "scheduler_summary",
                    "job_id": null,
                    "kind": null,
                    "status": "running",
                    "triggered_by": "manual",
                    "observations": null,
                    "failed_observations": null,
                    "token": "secret"
                })
                .to_string(),
                run.run_id
            ],
        )
        .expect("contaminate run summary");
    assert!(store.list_observability_runs(10).is_err());
}

#[test]
fn scheduler_atomic_writers_persist_closed_run_state_and_explicit_actor() {
    let (_dir, store, db) = open_temp_store();
    let job = sample_job("job-atomic-success", true);
    StoreWriter::write_scheduler_job_add(&store, &job, TEST_ACTOR).expect("seed job");
    let start = scheduler_start(&job.job_id, "run-atomic-success");

    StoreWriter::write_scheduler_run_start(&store, &start, "scheduler-actor")
        .expect("start scheduler run");
    let running = store
        .get_observability_run(&start.run_id)
        .expect("load running run")
        .expect("running run exists");
    assert_eq!(running.status, "running");
    assert_eq!(running.summary_json["job_id"], job.job_id);
    assert_eq!(running.summary_json["kind"], "controller-ping");
    assert!(running.summary_json.get("caller_marker").is_none());

    let outcome = scheduler_outcome(
        &job.job_id,
        Some(&start.run_id),
        vec![scheduler_outcome_entry(
            "scheduler-actor",
            "scheduler.task.outcome",
            Some(&start.run_id),
            "obs-atomic-success",
            PROBE_CONTROLLER_PING,
            true,
        )],
    );
    StoreWriter::write_scheduler_outcome(&store, &outcome, "scheduler-actor")
        .expect("write scheduler outcome");
    let clock = scheduler_clock(&job.job_id);
    StoreWriter::write_scheduler_run_finish(
        &store,
        &SchedulerRunFinish {
            run_id: start.run_id.clone(),
            finished_at: clock.last_run_at.clone(),
            job_clock: clock.clone(),
        },
        "scheduler-actor",
    )
    .expect("finish scheduler run");

    let finished = store
        .get_observability_run(&start.run_id)
        .expect("load finished run")
        .expect("finished run exists");
    assert_eq!(finished.status, "succeeded");
    assert_eq!(finished.observation_count, 1);
    assert_eq!(finished.failed_observation_count, 0);
    assert_eq!(finished.summary_json["observations"], 1);
    assert_eq!(finished.summary_json["failed_observations"], 0);
    assert!(finished.summary_json.get("caller_marker").is_none());
    let updated_job = store
        .get_observability_job(&job.job_id)
        .expect("load updated job")
        .expect("updated job exists");
    assert_eq!(
        updated_job.next_run_at.as_deref(),
        Some(clock.next_run_at.as_str())
    );
    assert_eq!(
        updated_job.last_run_at.as_deref(),
        Some(clock.last_run_at.as_str())
    );

    let conn = Connection::open(db).expect("open scheduler audit database");
    for event in [
        "scheduler.run.start",
        "scheduler.task.outcome",
        "scheduler.run.finish",
    ] {
        let actor: String = conn
            .query_row(
                "SELECT actor FROM controller_audit_log WHERE event = ?1",
                [event],
                |row| row.get(0),
            )
            .expect("load scheduler audit actor");
        assert_eq!(actor, "scheduler-actor");
    }
    let finish_detail: String = conn
        .query_row(
            "SELECT detail_json FROM controller_audit_log WHERE event = 'scheduler.run.finish'",
            [],
            |row| row.get(0),
        )
        .expect("load finish audit detail");
    let finish_detail: Value = serde_json::from_str(&finish_detail).expect("parse finish detail");
    assert_eq!(finish_detail["run_id"], start.run_id);
    assert_eq!(finish_detail["status"], "succeeded");
    assert!(finish_detail.get("caller_marker").is_none());
}

#[test]
fn scheduler_run_start_rolls_back_when_audit_insert_fails() {
    let (_dir, store, db) = open_temp_store();
    let job = sample_job("job-start-rollback", true);
    StoreWriter::write_scheduler_job_add(&store, &job, TEST_ACTOR).expect("seed job");
    let audit_count_before = store.audit_count().expect("audit count before start");
    install_failure_trigger(
        &db,
        "CREATE TRIGGER fail_scheduler_run_start_audit
         BEFORE INSERT ON controller_audit_log
         WHEN NEW.event = 'scheduler.run.start'
         BEGIN SELECT RAISE(ABORT, 'injected scheduler start failure'); END;",
    );

    assert_injected_scheduler_failure(
        StoreWriter::write_scheduler_run_start(
            &store,
            &scheduler_start(&job.job_id, "run-start-rollback"),
            TEST_ACTOR,
        ),
        "injected scheduler start failure",
    );
    assert!(
        store
            .get_observability_run("run-start-rollback")
            .expect("load rolled back run")
            .is_none()
    );
    assert_eq!(
        store.audit_count().expect("audit count after start"),
        audit_count_before
    );
}

#[test]
fn scheduler_run_start_rejects_job_disabled_before_start_boundary() {
    let (_dir, store, _db) = open_temp_store();
    let job = sample_job("job-disabled-before-start", true);
    StoreWriter::write_scheduler_job_add(&store, &job, TEST_ACTOR).expect("seed job");
    StoreWriter::write_scheduler_job_disable(&store, &job.job_id, TEST_ACTOR)
        .expect("disable job before start");

    let result = StoreWriter::write_scheduler_run_start(
        &store,
        &scheduler_start(&job.job_id, "run-disabled-before-start"),
        TEST_ACTOR,
    );
    assert!(
        matches!(result, Err(StoreError::InvalidInput(message)) if message.contains("disabled"))
    );
    assert!(
        store
            .get_observability_run("run-disabled-before-start")
            .expect("load rejected run")
            .is_none()
    );
}

fn assert_four_entry_scheduler_outcome_rolls_back(trigger_sql: &str, marker: &str) {
    let (_dir, store, db) = open_temp_store();
    let mut job = sample_job("job-bundle-rollback", true);
    job.kind = "ocserv-status".to_string();
    StoreWriter::write_scheduler_job_add(&store, &job, TEST_ACTOR).expect("seed job");
    let start = scheduler_start(&job.job_id, "run-bundle-rollback");
    StoreWriter::write_scheduler_run_start(&store, &start, TEST_ACTOR).expect("start run");
    let audit_count_before = store.audit_count().expect("audit count before bundle");
    install_failure_trigger(&db, trigger_sql);
    let entries = [
        OCSERV_SERVICE_SUMMARY,
        OCSERV_VERSION,
        OCSERV_SESSIONS_SUMMARY,
        OCSERV_CONFIG_FINGERPRINT,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, method)| {
        scheduler_outcome_entry(
            TEST_ACTOR,
            "scheduler.task.outcome",
            Some(&start.run_id),
            &format!("obs-bundle-{index}"),
            method,
            true,
        )
    })
    .collect();

    assert_injected_scheduler_failure(
        StoreWriter::write_scheduler_outcome(
            &store,
            &scheduler_outcome(&job.job_id, Some(&start.run_id), entries),
            TEST_ACTOR,
        ),
        marker,
    );
    assert_eq!(table_count(&db, "probe_observations"), 0);
    assert_eq!(
        store.audit_count().expect("audit count after bundle"),
        audit_count_before
    );
}

#[test]
fn scheduler_four_entry_outcome_rolls_back_when_last_audit_fails() {
    assert_four_entry_scheduler_outcome_rolls_back(
        "CREATE TRIGGER fail_scheduler_bundle_audit
         BEFORE INSERT ON controller_audit_log
         WHEN NEW.event = 'scheduler.task.outcome'
          AND NEW.method = 'ocserv.config.fingerprint'
         BEGIN SELECT RAISE(ABORT, 'injected scheduler bundle audit failure'); END;",
        "injected scheduler bundle audit failure",
    );
}

#[test]
fn scheduler_four_entry_outcome_rolls_back_when_last_observation_fails() {
    assert_four_entry_scheduler_outcome_rolls_back(
        "CREATE TRIGGER fail_scheduler_bundle_observation
         BEFORE INSERT ON probe_observations
         WHEN NEW.method = 'ocserv.config.fingerprint'
         BEGIN SELECT RAISE(ABORT, 'injected scheduler observation failure'); END;",
        "injected scheduler observation failure",
    );
}

#[test]
fn scheduler_runless_outcome_rolls_back_observation_and_audit_when_clock_fails() {
    let (_dir, store, db) = open_temp_store();
    let job = sample_job("job-invalid-clock-rollback", true);
    StoreWriter::write_scheduler_job_add(&store, &job, TEST_ACTOR).expect("seed job");
    let before = store
        .get_observability_job(&job.job_id)
        .expect("load job before clock failure")
        .expect("job exists");
    let audit_count_before = store
        .audit_count()
        .expect("audit count before invalid outcome");
    install_failure_trigger(
        &db,
        "CREATE TRIGGER fail_scheduler_clock_update
         BEFORE UPDATE ON observability_jobs
         WHEN NEW.job_id = 'job-invalid-clock-rollback'
         BEGIN SELECT RAISE(ABORT, 'injected scheduler clock failure'); END;",
    );
    let mut outcome = scheduler_outcome(
        &job.job_id,
        None,
        vec![scheduler_outcome_entry(
            TEST_ACTOR,
            "scheduler.job.invalid",
            None,
            "obs-invalid-clock-rollback",
            PROBE_CONTROLLER_PING,
            false,
        )],
    );
    outcome.job_clock = Some(scheduler_clock(&job.job_id));

    assert_injected_scheduler_failure(
        StoreWriter::write_scheduler_outcome(&store, &outcome, TEST_ACTOR),
        "injected scheduler clock failure",
    );
    assert_eq!(table_count(&db, "probe_observations"), 0);
    assert_eq!(
        store
            .audit_count()
            .expect("audit count after invalid outcome"),
        audit_count_before
    );
    let after = store
        .get_observability_job(&job.job_id)
        .expect("load job after clock failure")
        .expect("job exists");
    assert_eq!(after, before);
}

#[test]
fn scheduler_finish_rolls_back_run_and_clock_when_audit_or_clock_fails() {
    for fail_clock in [false, true] {
        let (_dir, store, db) = open_temp_store();
        let job_id = if fail_clock {
            "job-finish-clock-rollback"
        } else {
            "job-finish-audit-rollback"
        };
        let job = sample_job(job_id, true);
        StoreWriter::write_scheduler_job_add(&store, &job, TEST_ACTOR).expect("seed job");
        let start = scheduler_start(&job.job_id, &format!("run-{job_id}"));
        StoreWriter::write_scheduler_run_start(&store, &start, TEST_ACTOR).expect("start run");
        let outcome = scheduler_outcome(
            &job.job_id,
            Some(&start.run_id),
            vec![scheduler_outcome_entry(
                TEST_ACTOR,
                "scheduler.task.outcome",
                Some(&start.run_id),
                &format!("obs-{job_id}"),
                PROBE_CONTROLLER_PING,
                true,
            )],
        );
        StoreWriter::write_scheduler_outcome(&store, &outcome, TEST_ACTOR).expect("write outcome");
        let job_before = store
            .get_observability_job(&job.job_id)
            .expect("load job before finish")
            .expect("job exists");
        let marker = if fail_clock {
            "injected scheduler finish clock failure"
        } else {
            "injected scheduler finish audit failure"
        };
        let trigger = if fail_clock {
            format!(
                "CREATE TRIGGER fail_scheduler_finish_clock
                 BEFORE UPDATE ON observability_jobs
                 WHEN NEW.job_id = '{job_id}'
                 BEGIN SELECT RAISE(ABORT, '{marker}'); END;"
            )
        } else {
            format!(
                "CREATE TRIGGER fail_scheduler_finish_audit
                 BEFORE INSERT ON controller_audit_log
                 WHEN NEW.event = 'scheduler.run.finish'
                 BEGIN SELECT RAISE(ABORT, '{marker}'); END;"
            )
        };
        install_failure_trigger(&db, &trigger);
        let clock = scheduler_clock(&job.job_id);

        assert_injected_scheduler_failure(
            StoreWriter::write_scheduler_run_finish(
                &store,
                &SchedulerRunFinish {
                    run_id: start.run_id.clone(),
                    finished_at: clock.last_run_at.clone(),
                    job_clock: clock,
                },
                TEST_ACTOR,
            ),
            marker,
        );
        let run = store
            .get_observability_run(&start.run_id)
            .expect("load rolled back finish")
            .expect("run exists");
        assert_eq!(run.status, "running");
        assert!(run.finished_at.is_none());
        let job_after = store
            .get_observability_job(&job.job_id)
            .expect("load job after finish failure")
            .expect("job exists");
        assert_eq!(job_after, job_before);
    }
}

#[test]
fn scheduler_outcome_rejects_invalid_bounds_identity_and_required_fields() {
    let (_dir, store, db) = open_temp_store();
    let job = sample_job("job-outcome-validation", true);
    let other_job = sample_job("job-outcome-other", true);
    StoreWriter::write_scheduler_job_add(&store, &job, TEST_ACTOR).expect("seed job");
    StoreWriter::write_scheduler_job_add(&store, &other_job, TEST_ACTOR).expect("seed other job");
    let start = scheduler_start(&job.job_id, "run-outcome-validation");
    StoreWriter::write_scheduler_run_start(&store, &start, TEST_ACTOR).expect("start run");

    let empty = scheduler_outcome(&job.job_id, Some(&start.run_id), Vec::new());
    assert!(matches!(
        StoreWriter::write_scheduler_outcome(&store, &empty, TEST_ACTOR),
        Err(StoreError::InvalidInput(_))
    ));

    let runless_success = scheduler_outcome(
        &job.job_id,
        None,
        vec![scheduler_outcome_entry(
            TEST_ACTOR,
            "scheduler.job.invalid",
            None,
            "obs-runless-success",
            PROBE_CONTROLLER_PING,
            true,
        )],
    );
    assert!(matches!(
        StoreWriter::write_scheduler_outcome(&store, &runless_success, TEST_ACTOR),
        Err(StoreError::InvalidInput(_))
    ));

    let mut runless_wrong_error = scheduler_outcome_entry(
        TEST_ACTOR,
        "scheduler.job.invalid",
        None,
        "obs-runless-wrong-error",
        PROBE_CONTROLLER_PING,
        false,
    );
    runless_wrong_error.observation.error_code = Some("OTHER_ERROR".to_string());
    runless_wrong_error.audit.error_code = Some("OTHER_ERROR".to_string());
    assert!(matches!(
        StoreWriter::write_scheduler_outcome(
            &store,
            &scheduler_outcome(&job.job_id, None, vec![runless_wrong_error]),
            TEST_ACTOR,
        ),
        Err(StoreError::InvalidInput(_))
    ));

    let too_many = (0..5)
        .map(|index| {
            scheduler_outcome_entry(
                TEST_ACTOR,
                "scheduler.task.outcome",
                Some(&start.run_id),
                &format!("obs-too-many-{index}"),
                PROBE_CONTROLLER_PING,
                true,
            )
        })
        .collect();
    assert!(matches!(
        StoreWriter::write_scheduler_outcome(
            &store,
            &scheduler_outcome(&job.job_id, Some(&start.run_id), too_many),
            TEST_ACTOR,
        ),
        Err(StoreError::InvalidInput(_))
    ));

    let mixed_actor = scheduler_outcome(
        &job.job_id,
        Some(&start.run_id),
        vec![scheduler_outcome_entry(
            "different-actor",
            "scheduler.task.outcome",
            Some(&start.run_id),
            "obs-mixed-actor",
            PROBE_CONTROLLER_PING,
            true,
        )],
    );
    assert!(matches!(
        StoreWriter::write_scheduler_outcome(&store, &mixed_actor, TEST_ACTOR),
        Err(StoreError::InvalidInput(_))
    ));

    let mixed_run = scheduler_outcome(
        &job.job_id,
        Some(&start.run_id),
        vec![scheduler_outcome_entry(
            TEST_ACTOR,
            "scheduler.task.outcome",
            Some("run-different"),
            "obs-mixed-run",
            PROBE_CONTROLLER_PING,
            true,
        )],
    );
    assert!(matches!(
        StoreWriter::write_scheduler_outcome(&store, &mixed_run, TEST_ACTOR),
        Err(StoreError::InvalidInput(_))
    ));

    let mut missing_required = scheduler_outcome_entry(
        TEST_ACTOR,
        "scheduler.task.outcome",
        Some(&start.run_id),
        "obs-missing-required",
        PROBE_CONTROLLER_PING,
        true,
    );
    missing_required.observation.ok = None;
    missing_required.audit.ok = None;
    assert!(matches!(
        StoreWriter::write_scheduler_outcome(
            &store,
            &scheduler_outcome(&job.job_id, Some(&start.run_id), vec![missing_required]),
            TEST_ACTOR,
        ),
        Err(StoreError::InvalidInput(_))
    ));

    let mut missing_duration = scheduler_outcome_entry(
        TEST_ACTOR,
        "scheduler.task.outcome",
        Some(&start.run_id),
        "obs-missing-duration",
        PROBE_CONTROLLER_PING,
        true,
    );
    missing_duration.observation.duration_ms = None;
    missing_duration.audit.duration_ms = None;
    assert!(matches!(
        StoreWriter::write_scheduler_outcome(
            &store,
            &scheduler_outcome(&job.job_id, Some(&start.run_id), vec![missing_duration]),
            TEST_ACTOR,
        ),
        Err(StoreError::InvalidInput(_))
    ));

    let mut mismatched_error = scheduler_outcome_entry(
        TEST_ACTOR,
        "scheduler.task.outcome",
        Some(&start.run_id),
        "obs-mismatched-error",
        PROBE_CONTROLLER_PING,
        false,
    );
    mismatched_error.audit.error_code = Some("DIFFERENT_ERROR".to_string());
    assert!(matches!(
        StoreWriter::write_scheduler_outcome(
            &store,
            &scheduler_outcome(&job.job_id, Some(&start.run_id), vec![mismatched_error]),
            TEST_ACTOR,
        ),
        Err(StoreError::InvalidInput(_))
    ));

    let wrong_method = scheduler_outcome(
        &job.job_id,
        Some(&start.run_id),
        vec![scheduler_outcome_entry(
            TEST_ACTOR,
            "scheduler.task.outcome",
            Some(&start.run_id),
            "obs-wrong-kind-method",
            OCSERV_SERVICE_SUMMARY,
            true,
        )],
    );
    assert!(matches!(
        StoreWriter::write_scheduler_outcome(&store, &wrong_method, TEST_ACTOR),
        Err(StoreError::InvalidInput(message)) if message.contains("job kind")
    ));

    let mut rpc_missing_error = scheduler_outcome_entry(
        TEST_ACTOR,
        "rpc.completed",
        Some(&start.run_id),
        "obs-rpc-missing-error",
        PROBE_CONTROLLER_PING,
        false,
    );
    rpc_missing_error.audit.error_code = None;
    assert!(matches!(
        StoreWriter::write_scheduler_outcome(
            &store,
            &scheduler_outcome(&job.job_id, Some(&start.run_id), vec![rpc_missing_error]),
            TEST_ACTOR,
        ),
        Err(StoreError::InvalidInput(_))
    ));

    let missing_run = scheduler_outcome(
        &job.job_id,
        Some("run-missing"),
        vec![scheduler_outcome_entry(
            TEST_ACTOR,
            "scheduler.task.outcome",
            Some("run-missing"),
            "obs-missing-run",
            PROBE_CONTROLLER_PING,
            true,
        )],
    );
    assert!(matches!(
        StoreWriter::write_scheduler_outcome(&store, &missing_run, TEST_ACTOR),
        Err(StoreError::ObservabilityRunNotFound(run_id)) if run_id == "run-missing"
    ));

    let mismatched_job = scheduler_outcome(
        &other_job.job_id,
        Some(&start.run_id),
        vec![scheduler_outcome_entry(
            TEST_ACTOR,
            "scheduler.task.outcome",
            Some(&start.run_id),
            "obs-mismatched-job",
            PROBE_CONTROLLER_PING,
            true,
        )],
    );
    assert!(matches!(
        StoreWriter::write_scheduler_outcome(&store, &mismatched_job, TEST_ACTOR),
        Err(StoreError::InvalidInput(_))
    ));
    assert_eq!(table_count(&db, "probe_observations"), 0);

    let valid = scheduler_outcome(
        &job.job_id,
        Some(&start.run_id),
        vec![scheduler_outcome_entry(
            TEST_ACTOR,
            "scheduler.task.outcome",
            Some(&start.run_id),
            "obs-before-terminal",
            PROBE_CONTROLLER_PING,
            true,
        )],
    );
    StoreWriter::write_scheduler_outcome(&store, &valid, TEST_ACTOR).expect("write valid outcome");
    let clock = scheduler_clock(&job.job_id);
    StoreWriter::write_scheduler_run_finish(
        &store,
        &SchedulerRunFinish {
            run_id: start.run_id.clone(),
            finished_at: clock.last_run_at.clone(),
            job_clock: clock,
        },
        TEST_ACTOR,
    )
    .expect("finish run");
    let terminal = scheduler_outcome(
        &job.job_id,
        Some(&start.run_id),
        vec![scheduler_outcome_entry(
            TEST_ACTOR,
            "scheduler.task.outcome",
            Some(&start.run_id),
            "obs-after-terminal",
            PROBE_CONTROLLER_PING,
            true,
        )],
    );
    assert!(matches!(
        StoreWriter::write_scheduler_outcome(&store, &terminal, TEST_ACTOR),
        Err(StoreError::ObservabilityRunNotRunning(run_id))
            if run_id == "run-outcome-validation"
    ));
    assert_eq!(table_count(&db, "probe_observations"), 1);
}

#[test]
fn scheduler_failed_rpc_outcome_allows_distinct_present_error_codes() {
    let (_dir, store, db) = open_temp_store();
    let job = sample_job("job-rpc-error-mapping", true);
    StoreWriter::write_scheduler_job_add(&store, &job, TEST_ACTOR).expect("seed job");
    let start = scheduler_start(&job.job_id, "run-rpc-error-mapping");
    StoreWriter::write_scheduler_run_start(&store, &start, TEST_ACTOR).expect("start run");
    let mut entry = scheduler_outcome_entry(
        TEST_ACTOR,
        "rpc.completed",
        Some(&start.run_id),
        "obs-rpc-error-mapping",
        PROBE_CONTROLLER_PING,
        false,
    );
    assert_eq!(
        entry.observation.error_code.as_deref(),
        Some("SCHEDULER_TEST_FAILED")
    );
    entry.audit.error_code = Some("ENDPOINT_NOT_ALLOWED".to_string());

    StoreWriter::write_scheduler_outcome(
        &store,
        &scheduler_outcome(&job.job_id, Some(&start.run_id), vec![entry]),
        TEST_ACTOR,
    )
    .expect("write mapped RPC failure");
    assert_eq!(table_count(&db, "probe_observations"), 1);
    let audit_error: String = Connection::open(db)
        .expect("open audit database")
        .query_row(
            "SELECT error_code FROM controller_audit_log WHERE event = 'rpc.completed'",
            [],
            |row| row.get(0),
        )
        .expect("load RPC audit error");
    assert_eq!(audit_error, "ENDPOINT_NOT_ALLOWED");
}

#[test]
fn scheduler_clock_update_rejects_regression_and_rolls_back_outcome_pair() {
    let (_dir, store, db) = open_temp_store();
    let job = sample_job("job-clock-monotonic", true);
    StoreWriter::write_scheduler_job_add(&store, &job, TEST_ACTOR).expect("seed job");
    let newer_clock = SchedulerJobClockUpdate {
        job_id: job.job_id.clone(),
        next_run_at: "2026-07-08T08:06:00Z".to_string(),
        last_run_at: "2026-07-08T08:05:00.000500Z".to_string(),
    };
    let mut newer = scheduler_outcome(
        &job.job_id,
        None,
        vec![scheduler_outcome_entry(
            TEST_ACTOR,
            "scheduler.job.invalid",
            None,
            "obs-clock-newer",
            PROBE_CONTROLLER_PING,
            false,
        )],
    );
    newer.job_clock = Some(newer_clock.clone());
    StoreWriter::write_scheduler_outcome(&store, &newer, TEST_ACTOR).expect("write newer clock");
    let audit_count_before = store.audit_count().expect("audit count before stale clock");

    let mut stale = scheduler_outcome(
        &job.job_id,
        None,
        vec![scheduler_outcome_entry(
            TEST_ACTOR,
            "scheduler.job.invalid",
            None,
            "obs-clock-stale",
            PROBE_CONTROLLER_PING,
            false,
        )],
    );
    stale.job_clock = Some(SchedulerJobClockUpdate {
        job_id: job.job_id.clone(),
        next_run_at: "2026-07-08T08:06:00Z".to_string(),
        last_run_at: "2026-07-08T08:05:00.000400Z".to_string(),
    });
    let result = StoreWriter::write_scheduler_outcome(&store, &stale, TEST_ACTOR);
    assert!(
        matches!(result, Err(StoreError::InvalidInput(message)) if message.contains("regress"))
    );
    let mut earlier_next = scheduler_outcome(
        &job.job_id,
        None,
        vec![scheduler_outcome_entry(
            TEST_ACTOR,
            "scheduler.job.invalid",
            None,
            "obs-clock-earlier-next",
            PROBE_CONTROLLER_PING,
            false,
        )],
    );
    earlier_next.job_clock = Some(SchedulerJobClockUpdate {
        job_id: job.job_id.clone(),
        next_run_at: "2026-07-08T08:05:30Z".to_string(),
        last_run_at: newer_clock.last_run_at.clone(),
    });
    let result = StoreWriter::write_scheduler_outcome(&store, &earlier_next, TEST_ACTOR);
    assert!(
        matches!(result, Err(StoreError::InvalidInput(message)) if message.contains("next_run_at"))
    );
    assert_eq!(table_count(&db, "probe_observations"), 1);
    assert_eq!(
        store.audit_count().expect("audit count after stale clock"),
        audit_count_before
    );
    let stored = store
        .get_observability_job(&job.job_id)
        .expect("load job")
        .expect("job exists");
    assert_eq!(
        stored.next_run_at.as_deref(),
        Some(newer_clock.next_run_at.as_str())
    );
    assert_eq!(
        stored.last_run_at.as_deref(),
        Some(newer_clock.last_run_at.as_str())
    );
}

#[test]
fn scheduler_clock_order_uses_rfc3339_instants_not_text_order() {
    let (_dir, store, db) = open_temp_store();
    let job = sample_job("job-clock-offset-order", true);
    StoreWriter::write_scheduler_job_add(&store, &job, TEST_ACTOR).expect("seed job");

    let offset_clock = SchedulerJobClockUpdate {
        job_id: job.job_id.clone(),
        next_run_at: "2026-07-08T09:01:00+01:00".to_string(),
        last_run_at: "2026-07-08T09:00:00+01:00".to_string(),
    };
    let mut first = scheduler_outcome(
        &job.job_id,
        None,
        vec![scheduler_outcome_entry(
            TEST_ACTOR,
            "scheduler.job.invalid",
            None,
            "obs-clock-offset-first",
            PROBE_CONTROLLER_PING,
            false,
        )],
    );
    first.job_clock = Some(offset_clock);
    StoreWriter::write_scheduler_outcome(&store, &first, TEST_ACTOR)
        .expect("write initial offset clock");

    let newer_clock = SchedulerJobClockUpdate {
        job_id: job.job_id.clone(),
        next_run_at: "2026-07-08T08:31:00Z".to_string(),
        last_run_at: "2026-07-08T08:30:00Z".to_string(),
    };
    let mut newer = scheduler_outcome(
        &job.job_id,
        None,
        vec![scheduler_outcome_entry(
            TEST_ACTOR,
            "scheduler.job.invalid",
            None,
            "obs-clock-offset-newer",
            PROBE_CONTROLLER_PING,
            false,
        )],
    );
    newer.job_clock = Some(newer_clock.clone());
    StoreWriter::write_scheduler_outcome(&store, &newer, TEST_ACTOR)
        .expect("chronologically newer clock must not be rejected lexically");

    let stale_clock = SchedulerJobClockUpdate {
        job_id: job.job_id.clone(),
        next_run_at: "2026-07-08T09:01:00+01:00".to_string(),
        last_run_at: "2026-07-08T09:00:00+01:00".to_string(),
    };
    let mut stale = scheduler_outcome(
        &job.job_id,
        None,
        vec![scheduler_outcome_entry(
            TEST_ACTOR,
            "scheduler.job.invalid",
            None,
            "obs-clock-offset-stale",
            PROBE_CONTROLLER_PING,
            false,
        )],
    );
    stale.job_clock = Some(stale_clock);
    assert!(matches!(
        StoreWriter::write_scheduler_outcome(&store, &stale, TEST_ACTOR),
        Err(StoreError::InvalidInput(message)) if message.contains("regress")
    ));
    assert_eq!(table_count(&db, "probe_observations"), 2);
    let stored = store
        .get_observability_job(&job.job_id)
        .expect("load job")
        .expect("job exists");
    assert_eq!(
        stored.next_run_at.as_deref(),
        Some(newer_clock.next_run_at.as_str())
    );
    assert_eq!(
        stored.last_run_at.as_deref(),
        Some(newer_clock.last_run_at.as_str())
    );
}

#[test]
fn scheduler_finish_derives_skipped_and_failed_statuses_from_persisted_rows() {
    let (_dir, store, _db) = open_temp_store();
    for (suffix, write_failure, expected_status) in
        [("skipped", false, "skipped"), ("failed", true, "failed")]
    {
        let job = sample_job(&format!("job-derived-{suffix}"), true);
        StoreWriter::write_scheduler_job_add(&store, &job, TEST_ACTOR).expect("seed job");
        let start = scheduler_start(&job.job_id, &format!("run-derived-{suffix}"));
        StoreWriter::write_scheduler_run_start(&store, &start, TEST_ACTOR).expect("start run");
        if write_failure {
            StoreWriter::write_scheduler_outcome(
                &store,
                &scheduler_outcome(
                    &job.job_id,
                    Some(&start.run_id),
                    vec![scheduler_outcome_entry(
                        TEST_ACTOR,
                        "scheduler.task.outcome",
                        Some(&start.run_id),
                        "obs-derived-failed",
                        PROBE_CONTROLLER_PING,
                        false,
                    )],
                ),
                TEST_ACTOR,
            )
            .expect("write failed outcome");
        }
        let clock = scheduler_clock(&job.job_id);
        StoreWriter::write_scheduler_run_finish(
            &store,
            &SchedulerRunFinish {
                run_id: start.run_id.clone(),
                finished_at: clock.last_run_at.clone(),
                job_clock: clock,
            },
            TEST_ACTOR,
        )
        .expect("finish derived run");
        let run = store
            .get_observability_run(&start.run_id)
            .expect("load derived run")
            .expect("derived run exists");
        assert_eq!(run.status, expected_status);
        assert_eq!(run.summary_json["status"], expected_status);
    }
}

#[test]
fn scheduler_finish_rejects_missing_terminal_and_mismatched_job() {
    let (_dir, store, _db) = open_temp_store();
    let job = sample_job("job-finish-validation", true);
    let other_job = sample_job("job-finish-validation-other", true);
    StoreWriter::write_scheduler_job_add(&store, &job, TEST_ACTOR).expect("seed job");
    StoreWriter::write_scheduler_job_add(&store, &other_job, TEST_ACTOR).expect("seed other job");
    let missing_clock = scheduler_clock(&job.job_id);
    assert!(matches!(
        StoreWriter::write_scheduler_run_finish(
            &store,
            &SchedulerRunFinish {
                run_id: "run-finish-missing".to_string(),
                finished_at: missing_clock.last_run_at.clone(),
                job_clock: missing_clock,
            },
            TEST_ACTOR,
        ),
        Err(StoreError::ObservabilityRunNotFound(run_id)) if run_id == "run-finish-missing"
    ));

    let start = scheduler_start(&job.job_id, "run-finish-validation");
    StoreWriter::write_scheduler_run_start(&store, &start, TEST_ACTOR).expect("start run");
    let other_clock = scheduler_clock(&other_job.job_id);
    assert!(matches!(
        StoreWriter::write_scheduler_run_finish(
            &store,
            &SchedulerRunFinish {
                run_id: start.run_id.clone(),
                finished_at: other_clock.last_run_at.clone(),
                job_clock: other_clock,
            },
            TEST_ACTOR,
        ),
        Err(StoreError::InvalidInput(_))
    ));

    let clock = scheduler_clock(&job.job_id);
    let finish = SchedulerRunFinish {
        run_id: start.run_id.clone(),
        finished_at: clock.last_run_at.clone(),
        job_clock: clock,
    };
    StoreWriter::write_scheduler_run_finish(&store, &finish, TEST_ACTOR).expect("finish run once");
    assert!(matches!(
        StoreWriter::write_scheduler_run_finish(&store, &finish, TEST_ACTOR),
        Err(StoreError::ObservabilityRunNotRunning(run_id))
            if run_id == "run-finish-validation"
    ));
}

#[test]
fn observability_store_tests_upserts_health_snapshot() {
    let (_dir, store, _db) = open_temp_store();
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    let initial = HealthSnapshotRecord {
        node_id: "hk-ocserv-01".to_string(),
        endpoint_id: Some(endpoint_id),
        computed_at: "2026-07-08T07:00:00Z".to_string(),
        status: "healthy".to_string(),
        freshness_seconds: Some(30),
        last_success_at: Some("2026-07-08T07:00:00Z".to_string()),
        last_failure_at: None,
        last_error_code: None,
        degraded_methods_json: health_methods(&[]),
        summary_json: health_summary("healthy"),
    };
    StoreWriter::write_health_snapshots(
        &store,
        &HealthSnapshotWrite {
            evaluation_id: format!("health-eval-{}", uuid::Uuid::new_v4()),
            event: "health.node".to_string(),
            snapshots: vec![initial.clone()],
        },
        TEST_ACTOR,
    )
    .expect("insert health snapshot");

    let updated = HealthSnapshotRecord {
        status: "degraded".to_string(),
        freshness_seconds: Some(90),
        last_failure_at: Some("2026-07-08T07:05:00Z".to_string()),
        last_error_code: Some("RPC_UNAVAILABLE".to_string()),
        degraded_methods_json: health_methods(&["ocserv.version"]),
        summary_json: health_summary("degraded"),
        ..initial.clone()
    };
    StoreWriter::write_health_snapshots(
        &store,
        &HealthSnapshotWrite {
            evaluation_id: format!("health-eval-{}", uuid::Uuid::new_v4()),
            event: "health.node".to_string(),
            snapshots: vec![updated.clone()],
        },
        TEST_ACTOR,
    )
    .expect("update health snapshot");

    let snapshots = store
        .list_health_snapshots()
        .expect("list health snapshots");
    assert_eq!(snapshots, vec![updated]);
}

#[test]
fn health_snapshot_writer_is_atomic_idempotent_and_actor_bound() {
    let (_dir, store, db) = open_temp_store();
    let snapshots = vec![
        HealthSnapshotRecord {
            node_id: "health-batch-a".to_string(),
            endpoint_id: None,
            computed_at: "2026-07-11T01:00:00Z".to_string(),
            status: "healthy".to_string(),
            freshness_seconds: Some(1),
            last_success_at: Some("2026-07-11T01:00:00Z".to_string()),
            last_failure_at: None,
            last_error_code: None,
            degraded_methods_json: health_methods(&[]),
            summary_json: health_summary("healthy"),
        },
        HealthSnapshotRecord {
            node_id: "health-batch-b".to_string(),
            endpoint_id: None,
            computed_at: "2026-07-11T01:00:00Z".to_string(),
            status: "degraded".to_string(),
            freshness_seconds: Some(2),
            last_success_at: None,
            last_failure_at: Some("2026-07-11T00:59:00Z".to_string()),
            last_error_code: Some("RPC_TIMEOUT".to_string()),
            degraded_methods_json: health_methods(&[]),
            summary_json: health_summary("degraded"),
        },
    ];
    let write = HealthSnapshotWrite {
        evaluation_id: "health-eval-00000000-0000-4000-8000-000000000001".to_string(),
        event: "health.summary".to_string(),
        snapshots: snapshots.clone(),
    };
    StoreWriter::write_health_snapshots(&store, &write, TEST_ACTOR).expect("write health batch");
    let audit_count = store.audit_count().expect("audit count");
    StoreWriter::write_health_snapshots(&store, &write, TEST_ACTOR).expect("exact health retry");
    assert_eq!(store.audit_count().expect("audit count"), audit_count);
    assert_eq!(store.list_health_snapshots().expect("snapshots"), snapshots);
    let history = store
        .list_health_history(None, "2026-07-11T00:00:00Z", "2026-07-11T02:00:00Z", 100)
        .expect("history");
    assert_eq!(history.len(), 2, "exact replay must not append duplicates");
    assert!(matches!(
        StoreWriter::write_health_snapshots(&store, &write, "different-actor"),
        Err(StoreError::HealthEvaluationConflict { .. })
    ));
    let mut divergent = write.clone();
    divergent.snapshots[0].status = "degraded".to_string();
    divergent.snapshots[0].summary_json = health_summary("degraded");
    assert!(matches!(
        StoreWriter::write_health_snapshots(&store, &divergent, TEST_ACTOR),
        Err(StoreError::HealthEvaluationConflict { .. })
    ));

    let (actor, event, detail) = latest_job_audit(&db);
    assert_eq!(actor, TEST_ACTOR);
    assert_eq!(event, "health.summary");
    assert_eq!(detail["node_count"], 2);
    assert_eq!(detail["status_counts"]["healthy"], 1);
    assert_eq!(detail["status_counts"]["degraded"], 1);
}

#[test]
fn health_snapshot_writer_rolls_back_every_row_when_audit_fails() {
    let (_dir, store, db) = open_temp_store();
    inject_job_audit_failure(&db, "health.summary");
    let write = HealthSnapshotWrite {
        evaluation_id: "health-eval-00000000-0000-4000-8000-000000000002".to_string(),
        event: "health.summary".to_string(),
        snapshots: vec![HealthSnapshotRecord {
            node_id: "health-rollback".to_string(),
            endpoint_id: None,
            computed_at: "2026-07-11T01:00:00Z".to_string(),
            status: "unknown".to_string(),
            freshness_seconds: None,
            last_success_at: None,
            last_failure_at: None,
            last_error_code: None,
            degraded_methods_json: health_methods(&[]),
            summary_json: health_summary("unknown"),
        }],
    };
    assert_injected_job_audit_failure(StoreWriter::write_health_snapshots(
        &store, &write, TEST_ACTOR,
    ));
    assert!(store.list_health_snapshots().expect("snapshots").is_empty());
    assert!(
        store
            .list_health_history(None, "2026-07-11T00:00:00Z", "2026-07-11T02:00:00Z", 100,)
            .expect("history")
            .is_empty()
    );
}

fn sample_health_rollup() -> HealthRollupRecord {
    HealthRollupRecord {
        node_id: "health-rollup-node".to_string(),
        bucket_seconds: 300,
        bucket_start: "2026-07-11T01:00:00Z".to_string(),
        bucket_end: "2026-07-11T01:05:00Z".to_string(),
        input_watermark: "a".repeat(64),
        health_samples: 2,
        covered_slots: 1,
        expected_slots: 1,
        healthy_count: 1,
        degraded_count: 1,
        unreachable_count: 0,
        stale_count: 0,
        disabled_count: 0,
        unknown_count: 0,
        observation_count: 3,
        observation_error_count: 1,
        duration_sample_count: 3,
        duration_p50_ms: Some(20),
        duration_p95_ms: Some(30),
        cert_warning_count: 1,
        cert_critical_count: 0,
        fingerprint_sample_count: 2,
        fingerprint_change_count: 1,
        computed_at: "2026-07-11T01:05:00Z".to_string(),
    }
}

#[test]
fn health_rollup_writer_is_idempotent_bounded_and_atomic() {
    let (_dir, store, db) = open_temp_store();
    let operation_id = "health-rollup-00000000-0000-4000-8000-000000000001";
    let write = HealthRollupWrite {
        operation_id: operation_id.to_string(),
        rows: vec![sample_health_rollup()],
    };
    StoreWriter::write_health_rollups(&store, &write, TEST_ACTOR).expect("write rollup");
    let audit_count = store.audit_count().expect("audit count");
    StoreWriter::write_health_rollups(&store, &write, TEST_ACTOR).expect("exact replay");
    assert_eq!(store.audit_count().expect("audit count"), audit_count);
    assert_eq!(
        store
            .list_health_rollups(
                Some("health-rollup-node"),
                300,
                "2026-07-11T01:00:00Z",
                "2026-07-11T01:10:00Z",
                10,
            )
            .expect("rollups"),
        vec![sample_health_rollup()]
    );

    let mut invalid = write.clone();
    invalid.operation_id = "health-rollup-00000000-0000-4000-8000-000000000002".to_string();
    invalid.rows[0].healthy_count = 2;
    assert!(matches!(
        StoreWriter::write_health_rollups(&store, &invalid, TEST_ACTOR),
        Err(StoreError::InvalidInput(_))
    ));

    inject_job_audit_failure(&db, "health.rollup.recompute");
    let mut rollback = write;
    rollback.operation_id = "health-rollup-00000000-0000-4000-8000-000000000003".to_string();
    rollback.rows[0].input_watermark = "b".repeat(64);
    assert_injected_job_audit_failure(StoreWriter::write_health_rollups(
        &store, &rollback, TEST_ACTOR,
    ));
    let stored = store
        .list_health_rollups(
            Some("health-rollup-node"),
            300,
            "2026-07-11T01:00:00Z",
            "2026-07-11T01:10:00Z",
            10,
        )
        .expect("rollup after rollback");
    assert_eq!(stored[0].input_watermark, "a".repeat(64));
}

fn health_evaluation_start(evaluation_id: &str, watermark: char) -> HealthEvaluationStart {
    HealthEvaluationStart {
        evaluation_id: evaluation_id.to_string(),
        input_watermark: watermark.to_string().repeat(64),
        policy_version: "b".repeat(64),
        computation_version: "health-v1".to_string(),
        started_at: "2026-07-11T01:00:00Z".to_string(),
    }
}

#[test]
fn health_evaluation_lifecycle_is_atomic_idempotent_and_actor_bound() {
    let (_dir, store, db) = open_temp_store();
    let evaluation_id = "health-eval-00000000-0000-4000-8000-000000000010";
    let start = health_evaluation_start(evaluation_id, 'a');
    StoreWriter::write_health_evaluation_start(&store, &start, TEST_ACTOR)
        .expect("start evaluation");
    let audit_count = store.audit_count().expect("audit count");
    StoreWriter::write_health_evaluation_start(&store, &start, TEST_ACTOR)
        .expect("exact start replay");
    assert_eq!(store.audit_count().expect("audit count"), audit_count);
    assert!(matches!(
        StoreWriter::write_health_evaluation_start(&store, &start, "different-actor"),
        Err(StoreError::HealthEvaluationConflict { .. })
    ));
    let mut duplicate_key = start.clone();
    duplicate_key.evaluation_id = "health-eval-00000000-0000-4000-8000-000000000011".to_string();
    assert!(matches!(
        StoreWriter::write_health_evaluation_start(&store, &duplicate_key, TEST_ACTOR),
        Err(StoreError::HealthEvaluationConflict { .. })
    ));

    let snapshot = HealthSnapshotRecord {
        node_id: "health-evaluator-node".to_string(),
        endpoint_id: None,
        computed_at: "2026-07-11T01:00:01Z".to_string(),
        status: "healthy".to_string(),
        freshness_seconds: Some(1),
        last_success_at: Some("2026-07-11T01:00:00Z".to_string()),
        last_failure_at: None,
        last_error_code: None,
        degraded_methods_json: health_methods(&[]),
        summary_json: health_summary("healthy"),
    };
    StoreWriter::write_health_evaluation_finish(
        &store,
        &HealthEvaluationFinish {
            evaluation_id: evaluation_id.to_string(),
            finished_at: "2026-07-11T01:00:02Z".to_string(),
            snapshots: vec![snapshot.clone()],
        },
        TEST_ACTOR,
    )
    .expect("finish evaluation");
    let run = store
        .get_health_evaluation_run(evaluation_id)
        .expect("read run")
        .expect("run exists");
    assert_eq!(run.status, "completed");
    assert_eq!(run.snapshot_count, 1);
    assert_eq!(
        store.list_health_snapshots().expect("snapshots"),
        vec![snapshot.clone()]
    );
    let history = store
        .list_health_history(
            Some("health-evaluator-node"),
            "2026-07-11T00:00:00Z",
            "2026-07-11T02:00:00Z",
            100,
        )
        .expect("history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].evaluation_id, evaluation_id);
    assert_eq!(history[0].snapshot, snapshot);
    assert!(
        store
            .list_health_history(None, "2026-07-11T01:00:00Z", "2026-07-11T01:00:01Z", 100,)
            .expect("half-open history")
            .is_empty(),
        "sample at the end boundary must be excluded"
    );
    assert!(matches!(
        store.list_health_history(None, "2026-07-11T01:00:00Z", "2026-07-11T01:00:00Z", 100,),
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        store.list_health_history(None, "2026-07-11T00:00:00Z", "2026-07-11T02:00:00Z", 1_001,),
        Err(StoreError::InvalidInput(_))
    ));
    let update_error = Connection::open(&db)
        .expect("open history database")
        .execute(
            "UPDATE health_history SET status = 'degraded' WHERE evaluation_id = ?1",
            [evaluation_id],
        )
        .expect_err("append-only history rejects update");
    assert!(update_error.to_string().contains("append-only"));
    assert!(matches!(
        StoreWriter::write_health_evaluation_failure(
            &store,
            &HealthEvaluationFailure {
                evaluation_id: evaluation_id.to_string(),
                finished_at: "2026-07-11T01:00:03Z".to_string(),
                failure_code: "HEALTH_EVALUATION_FAILED".to_string(),
            },
            TEST_ACTOR,
        ),
        Err(StoreError::HealthEvaluationConflict { .. })
    ));
}

#[test]
fn health_evaluation_mutations_roll_back_when_audit_fails() {
    let (_dir, store, db) = open_temp_store();
    let start_id = "health-eval-00000000-0000-4000-8000-000000000012";
    inject_job_audit_failure(&db, "health.evaluation.start");
    assert_injected_job_audit_failure(StoreWriter::write_health_evaluation_start(
        &store,
        &health_evaluation_start(start_id, 'c'),
        TEST_ACTOR,
    ));
    assert!(
        store
            .get_health_evaluation_run(start_id)
            .expect("read start rollback")
            .is_none()
    );
    Connection::open(&db)
        .expect("open database")
        .execute_batch("DROP TRIGGER fail_scheduler_job_audit")
        .expect("remove start failure trigger");

    let finish_id = "health-eval-00000000-0000-4000-8000-000000000013";
    StoreWriter::write_health_evaluation_start(
        &store,
        &health_evaluation_start(finish_id, 'd'),
        TEST_ACTOR,
    )
    .expect("start finish rollback run");
    inject_job_audit_failure(&db, "health.evaluation.finish");
    assert_injected_job_audit_failure(StoreWriter::write_health_evaluation_finish(
        &store,
        &HealthEvaluationFinish {
            evaluation_id: finish_id.to_string(),
            finished_at: "2026-07-11T01:00:02Z".to_string(),
            snapshots: vec![],
        },
        TEST_ACTOR,
    ));
    assert_eq!(
        store
            .get_health_evaluation_run(finish_id)
            .expect("read run")
            .expect("run exists")
            .status,
        "running"
    );
    assert!(
        store
            .list_health_history(None, "2026-07-11T00:00:00Z", "2026-07-11T02:00:00Z", 100,)
            .expect("history after finish rollback")
            .is_empty()
    );
    Connection::open(&db)
        .expect("open database")
        .execute_batch("DROP TRIGGER fail_scheduler_job_audit")
        .expect("remove finish failure trigger");

    let failure_id = "health-eval-00000000-0000-4000-8000-000000000014";
    StoreWriter::write_health_evaluation_start(
        &store,
        &health_evaluation_start(failure_id, 'e'),
        TEST_ACTOR,
    )
    .expect("start failed evaluation");
    StoreWriter::write_health_evaluation_failure(
        &store,
        &HealthEvaluationFailure {
            evaluation_id: failure_id.to_string(),
            finished_at: "2026-07-11T01:00:02Z".to_string(),
            failure_code: "HEALTH_INPUT_INVALID".to_string(),
        },
        TEST_ACTOR,
    )
    .expect("persist bounded failure");
    let failed = store
        .get_health_evaluation_run(failure_id)
        .expect("read failed run")
        .expect("failed run exists");
    assert_eq!(failed.status, "failed");
    assert_eq!(failed.failure_code.as_deref(), Some("HEALTH_INPUT_INVALID"));
}

#[test]
fn health_evaluation_recovery_is_bounded_atomic_and_instant_ordered() {
    let (_dir, store, db) = open_temp_store();
    let old_id = "health-eval-00000000-0000-4000-8000-000000000015";
    let recent_id = "health-eval-00000000-0000-4000-8000-000000000016";
    let mut old = health_evaluation_start(old_id, 'f');
    old.started_at = "2026-07-11T02:00:00+02:00".to_string();
    let mut recent = health_evaluation_start(recent_id, '1');
    recent.started_at = "2026-07-11T00:30:00Z".to_string();
    StoreWriter::write_health_evaluation_start(&store, &old, TEST_ACTOR).expect("start old");
    StoreWriter::write_health_evaluation_start(&store, &recent, TEST_ACTOR).expect("start recent");

    inject_job_audit_failure(&db, "health.evaluation.recover");
    assert_injected_job_audit_failure(
        StoreWriter::write_health_evaluation_recovery(
            &store,
            "2026-07-11T00:15:00Z",
            "2026-07-11T01:00:00Z",
            TEST_ACTOR,
        )
        .map(|_| ()),
    );
    assert_eq!(
        store
            .get_health_evaluation_run(old_id)
            .expect("read old")
            .expect("old exists")
            .status,
        "running"
    );
    Connection::open(&db)
        .expect("open database")
        .execute_batch("DROP TRIGGER fail_scheduler_job_audit")
        .expect("remove recovery failure trigger");

    assert_eq!(
        StoreWriter::write_health_evaluation_recovery(
            &store,
            "2026-07-11T00:15:00Z",
            "2026-07-11T01:00:00Z",
            TEST_ACTOR,
        )
        .expect("recover abandoned run"),
        1
    );
    let old = store
        .get_health_evaluation_run(old_id)
        .expect("read old")
        .expect("old exists");
    assert_eq!(old.status, "failed");
    assert_eq!(
        old.failure_code.as_deref(),
        Some("HEALTH_EVALUATION_ABANDONED")
    );
    assert_eq!(
        store
            .get_health_evaluation_run(recent_id)
            .expect("read recent")
            .expect("recent exists")
            .status,
        "running"
    );
    assert_eq!(
        StoreWriter::write_health_evaluation_recovery(
            &store,
            "2026-07-11T00:15:00Z",
            "2026-07-11T01:00:00Z",
            TEST_ACTOR,
        )
        .expect("idempotent recovery"),
        0
    );
}

#[test]
fn health_snapshot_writer_rejects_unversioned_and_contaminated_payloads() {
    let (_dir, store, _db) = open_temp_store();
    let base = HealthSnapshotRecord {
        node_id: "health-closed-payload".to_string(),
        endpoint_id: None,
        computed_at: "2026-07-11T01:00:00Z".to_string(),
        status: "healthy".to_string(),
        freshness_seconds: None,
        last_success_at: None,
        last_failure_at: None,
        last_error_code: None,
        degraded_methods_json: health_methods(&[]),
        summary_json: health_summary("healthy"),
    };
    for (evaluation_id, summary) in [
        ("health-eval-unversioned", json!({"status": "healthy"})),
        (
            "health-eval-contaminated",
            json!({
                "schema": "ocfleet.health.summary.v1",
                "region": null,
                "role": null,
                "status": "healthy",
                "endpoint_status": null,
                "consecutive_failures": null,
                "token": "secret"
            }),
        ),
    ] {
        let mut snapshot = base.clone();
        snapshot.summary_json = summary;
        let write = HealthSnapshotWrite {
            evaluation_id: evaluation_id.to_string(),
            event: "health.node".to_string(),
            snapshots: vec![snapshot],
        };
        assert!(StoreWriter::write_health_snapshots(&store, &write, TEST_ACTOR).is_err());
    }
    assert!(store.list_health_snapshots().expect("snapshots").is_empty());
    assert_eq!(store.audit_count().expect("audit count"), 0);
}

#[test]
fn alert_evaluation_writer_is_atomic_idempotent_and_actor_bound() {
    let (_dir, store, db) = open_temp_store();
    let alerts = vec![
        AlertEventRecord {
            alert_id: "alert-eval-a".to_string(),
            dedupe_key: "node:health-a:stale".to_string(),
            node_id: Some("health-a".to_string()),
            severity: "warning".to_string(),
            state: "open".to_string(),
            reason_code: "NODE_STALE".to_string(),
            first_seen_at: "2026-07-11T01:00:00Z".to_string(),
            last_seen_at: "2026-07-11T01:00:00Z".to_string(),
            last_sent_at: None,
            resolved_at: None,
            detail_json: json!({"methods": ["probe.controller.ping"], "summary": {}}),
        },
        AlertEventRecord {
            alert_id: "alert-eval-b".to_string(),
            dedupe_key: "node:health-b:stale".to_string(),
            node_id: Some("health-b".to_string()),
            severity: "critical".to_string(),
            state: "silenced".to_string(),
            reason_code: "NODE_UNREACHABLE".to_string(),
            first_seen_at: "2026-07-11T01:00:00Z".to_string(),
            last_seen_at: "2026-07-11T01:00:00Z".to_string(),
            last_sent_at: None,
            resolved_at: None,
            detail_json: json!({"methods": ["probe.controller.ping"], "summary": {}}),
        },
    ];
    let write = AlertEvaluationWrite {
        evaluation_id: "alert-eval-00000000-0000-4000-8000-000000000001".to_string(),
        entries: alerts
            .iter()
            .cloned()
            .map(|after| AlertEvaluationEntry {
                before: None,
                after,
            })
            .collect(),
    };
    StoreWriter::write_alert_evaluation(&store, &write, TEST_ACTOR)
        .expect("write alert evaluation");
    let audit_count = store.audit_count().expect("audit count");
    StoreWriter::write_alert_evaluation(&store, &write, TEST_ACTOR)
        .expect("exact alert evaluation retry");
    assert_eq!(store.audit_count().expect("audit count"), audit_count);
    assert_eq!(store.list_alert_events().expect("alerts"), alerts);
    assert!(matches!(
        StoreWriter::write_alert_evaluation(&store, &write, "different-actor"),
        Err(StoreError::AlertEvaluationConflict { .. })
    ));
    let mut divergent = write.clone();
    divergent.entries[0].after.severity = "critical".to_string();
    assert!(matches!(
        StoreWriter::write_alert_evaluation(&store, &divergent, TEST_ACTOR),
        Err(StoreError::AlertEvaluationConflict { .. })
    ));

    let (actor, event, detail) = latest_job_audit(&db);
    assert_eq!(actor, TEST_ACTOR);
    assert_eq!(event, "alert.evaluate");
    assert_eq!(detail["evaluated_candidates"], 2);
    assert_eq!(detail["open_alerts"], 1);
    assert_eq!(detail["silenced_alerts"], 1);
}

#[test]
fn alert_evaluation_writer_rolls_back_every_row_when_audit_fails() {
    let (_dir, store, db) = open_temp_store();
    inject_job_audit_failure(&db, "alert.evaluate");
    let write = AlertEvaluationWrite {
        evaluation_id: "alert-eval-00000000-0000-4000-8000-000000000002".to_string(),
        entries: vec![AlertEvaluationEntry {
            before: None,
            after: AlertEventRecord {
                alert_id: "alert-eval-rollback".to_string(),
                dedupe_key: "node:health-rollback:stale".to_string(),
                node_id: Some("health-rollback".to_string()),
                severity: "warning".to_string(),
                state: "open".to_string(),
                reason_code: "NODE_STALE".to_string(),
                first_seen_at: "2026-07-11T01:00:00Z".to_string(),
                last_seen_at: "2026-07-11T01:00:00Z".to_string(),
                last_sent_at: None,
                resolved_at: None,
                detail_json: json!({"methods": [], "summary": {}}),
            },
        }],
    };
    assert_injected_job_audit_failure(StoreWriter::write_alert_evaluation(
        &store, &write, TEST_ACTOR,
    ));
    assert!(store.list_alert_events().expect("alerts").is_empty());
}

#[test]
fn alert_evaluation_writer_rejects_stale_candidate_state() {
    let (_dir, store, _db) = open_temp_store();
    let before = AlertEventRecord {
        alert_id: "alert-eval-stale".to_string(),
        dedupe_key: "node:health-stale:stale".to_string(),
        node_id: Some("health-stale".to_string()),
        severity: "warning".to_string(),
        state: "open".to_string(),
        reason_code: "NODE_STALE".to_string(),
        first_seen_at: "2026-07-11T01:00:00Z".to_string(),
        last_seen_at: "2026-07-11T01:00:00Z".to_string(),
        last_sent_at: None,
        resolved_at: None,
        detail_json: json!({"methods": [], "summary": {}}),
    };
    store.upsert_alert_event(&before).expect("seed alert");
    let mut after = before.clone();
    after.last_seen_at = "2026-07-11T01:01:00Z".to_string();
    let mut concurrently_silenced = before.clone();
    concurrently_silenced.state = "silenced".to_string();
    concurrently_silenced.detail_json = json!({
        "methods": [],
        "summary": {},
        "silenced_until": "2026-07-11T02:00:00Z"
    });
    store
        .upsert_alert_event(&concurrently_silenced)
        .expect("concurrent silence");
    let audit_count = store.audit_count().expect("audit count");

    let result = StoreWriter::write_alert_evaluation(
        &store,
        &AlertEvaluationWrite {
            evaluation_id: "alert-eval-00000000-0000-4000-8000-000000000003".to_string(),
            entries: vec![AlertEvaluationEntry {
                before: Some(before),
                after,
            }],
        },
        TEST_ACTOR,
    );

    assert!(matches!(
        result,
        Err(StoreError::AlertEvaluationConflict { .. })
    ));
    assert_eq!(store.audit_count().expect("audit count"), audit_count);
    assert_eq!(
        store.list_alert_events().expect("alerts"),
        vec![concurrently_silenced]
    );
}

#[test]
fn alert_state_transition_is_atomic_replay_safe_and_stale_rejecting() {
    let (_dir, store, db) = open_temp_store();
    let before = AlertEventRecord {
        alert_id: "alert-action-a".to_string(),
        dedupe_key: "node:action-a:stale".to_string(),
        node_id: Some("action-a".to_string()),
        severity: "warning".to_string(),
        state: "open".to_string(),
        reason_code: "NODE_STALE".to_string(),
        first_seen_at: "2026-07-11T01:00:00Z".to_string(),
        last_seen_at: "2026-07-11T01:00:00Z".to_string(),
        last_sent_at: None,
        resolved_at: None,
        detail_json: json!({"methods": [], "summary": {}}),
    };
    store.upsert_alert_event(&before).expect("seed alert");
    let mut after = before.clone();
    after.state = "resolved".to_string();
    after.last_seen_at = "2026-07-11T01:01:00Z".to_string();
    after.resolved_at = Some(after.last_seen_at.clone());
    after.detail_json =
        json!({"methods": [], "summary": {}, "resolve_reason": "operator confirmed"});
    let write = AlertStateTransition {
        operation_id: "alert-action-00000000-0000-4000-8000-000000000001".to_string(),
        event: "alert.resolve".to_string(),
        before: before.clone(),
        after: after.clone(),
        reason: "operator confirmed".to_string(),
    };
    StoreWriter::write_alert_state_transition(&store, &write, TEST_ACTOR).expect("resolve alert");
    let audit_count = store.audit_count().expect("audit count");
    StoreWriter::write_alert_state_transition(&store, &write, TEST_ACTOR).expect("exact retry");
    assert_eq!(store.audit_count().expect("audit count"), audit_count);
    assert!(matches!(
        StoreWriter::write_alert_state_transition(&store, &write, "other-actor"),
        Err(StoreError::AlertMutationConflict { .. })
    ));

    let stale = AlertStateTransition {
        operation_id: "alert-action-00000000-0000-4000-8000-000000000002".to_string(),
        ..write.clone()
    };
    assert!(matches!(
        StoreWriter::write_alert_state_transition(&store, &stale, TEST_ACTOR),
        Err(StoreError::AlertMutationConflict { .. })
    ));
    assert_eq!(
        store.list_alert_events().expect("alerts"),
        vec![after.clone()]
    );

    inject_job_audit_failure(&db, "alert.silence");
    let mut silence_after = before.clone();
    silence_after.state = "silenced".to_string();
    silence_after.detail_json = json!({
        "methods": [],
        "summary": {},
        "silence_reason": "maintenance",
        "silenced_until": "2026-07-11T02:00:00Z"
    });
    let rollback = AlertStateTransition {
        operation_id: "alert-action-00000000-0000-4000-8000-000000000003".to_string(),
        event: "alert.silence".to_string(),
        before: after.clone(),
        after: AlertEventRecord {
            alert_id: after.alert_id.clone(),
            dedupe_key: after.dedupe_key.clone(),
            node_id: after.node_id.clone(),
            severity: after.severity.clone(),
            state: "silenced".to_string(),
            reason_code: after.reason_code.clone(),
            first_seen_at: after.first_seen_at.clone(),
            last_seen_at: after.last_seen_at.clone(),
            last_sent_at: after.last_sent_at.clone(),
            resolved_at: None,
            detail_json: silence_after.detail_json,
        },
        reason: "maintenance".to_string(),
    };
    assert_injected_job_audit_failure(StoreWriter::write_alert_state_transition(
        &store, &rollback, TEST_ACTOR,
    ));
    assert_eq!(store.list_alert_events().expect("alerts"), vec![after]);
}

#[test]
fn alert_webhook_hook_create_is_atomic_and_actor_bound() {
    let (_dir, store, db) = open_temp_store();
    let hook = AlertWebhookHookRecord {
        hook_id: "webhook-atomic".to_string(),
        name: "ops".to_string(),
        hook_type: "webhook".to_string(),
        endpoint_url: "https://93.184.216.34/alerts".to_string(),
        endpoint_url_redacted: "https://93.184.216.34/<redacted>".to_string(),
        endpoint_host: "93.184.216.34".to_string(),
        host_allow: vec!["93.184.216.34".to_string()],
        hmac_key_id: "abcd1234abcd1234".to_string(),
        enabled: true,
        max_attempts: 2,
        timeout_ms: 1_500,
        created_at: "2026-07-11T01:00:00Z".to_string(),
        updated_at: "2026-07-11T01:00:00Z".to_string(),
    };
    inject_job_audit_failure(&db, "alert.hook.add_webhook");
    assert_injected_job_audit_failure(StoreWriter::write_alert_webhook_hook_create(
        &store, &hook, TEST_ACTOR,
    ));
    assert!(store.list_alert_webhook_hooks().expect("hooks").is_empty());
    Connection::open(&db)
        .expect("open db")
        .execute_batch("DROP TRIGGER fail_scheduler_job_audit")
        .expect("remove failure trigger");
    StoreWriter::write_alert_webhook_hook_create(&store, &hook, TEST_ACTOR).expect("create hook");
    let audit_count = store.audit_count().expect("audit count");
    StoreWriter::write_alert_webhook_hook_create(&store, &hook, TEST_ACTOR).expect("exact retry");
    assert_eq!(store.audit_count().expect("audit count"), audit_count);
    assert!(matches!(
        StoreWriter::write_alert_webhook_hook_create(&store, &hook, "other-actor"),
        Err(StoreError::AlertMutationConflict { .. })
    ));
}

#[test]
fn alert_delivery_attempt_and_finalize_writers_are_atomic_and_replay_safe() {
    let (_dir, store, db) = open_temp_store();
    let hook = AlertWebhookHookRecord {
        hook_id: "webhook-delivery".to_string(),
        name: "delivery".to_string(),
        hook_type: "webhook".to_string(),
        endpoint_url: "https://93.184.216.34/alerts".to_string(),
        endpoint_url_redacted: "https://93.184.216.34/<redacted>".to_string(),
        endpoint_host: "93.184.216.34".to_string(),
        host_allow: vec!["93.184.216.34".to_string()],
        hmac_key_id: "abcd1234abcd1234".to_string(),
        enabled: true,
        max_attempts: 2,
        timeout_ms: 1_500,
        created_at: "2026-07-11T01:00:00Z".to_string(),
        updated_at: "2026-07-11T01:00:00Z".to_string(),
    };
    StoreWriter::write_alert_webhook_hook_create(&store, &hook, TEST_ACTOR).expect("create hook");
    let alert = AlertEventRecord {
        alert_id: "alert-delivery".to_string(),
        dedupe_key: "node:delivery:stale".to_string(),
        node_id: Some("delivery".to_string()),
        severity: "warning".to_string(),
        state: "open".to_string(),
        reason_code: "NODE_STALE".to_string(),
        first_seen_at: "2026-07-11T01:00:00Z".to_string(),
        last_seen_at: "2026-07-11T01:00:00Z".to_string(),
        last_sent_at: None,
        resolved_at: None,
        detail_json: json!({"methods": [], "summary": {}}),
    };
    store.upsert_alert_event(&alert).expect("seed alert");
    let attempt = AlertDeliveryAttemptWrite {
        attempt: AlertDeliveryAttemptRecord {
            attempt_id: "attempt-delivery-1".to_string(),
            alert_id: alert.alert_id.clone(),
            hook_id: hook.hook_id.clone(),
            attempt_no: 1,
            attempted_at: "2026-07-11T01:01:00Z".to_string(),
            status: "succeeded".to_string(),
            http_status_class: Some("2xx".to_string()),
            error_code: None,
            bytes_sent: 128,
        },
    };
    inject_job_audit_failure(&db, "alert.delivery.attempt");
    assert_injected_job_audit_failure(StoreWriter::write_alert_delivery_attempt(
        &store, &attempt, TEST_ACTOR,
    ));
    assert!(
        store
            .list_alert_delivery_attempts()
            .expect("attempts")
            .is_empty()
    );
    Connection::open(&db)
        .expect("open db")
        .execute_batch("DROP TRIGGER fail_scheduler_job_audit")
        .expect("remove failure trigger");
    StoreWriter::write_alert_delivery_attempt(&store, &attempt, TEST_ACTOR).expect("write attempt");
    let audit_count = store.audit_count().expect("audit count");
    StoreWriter::write_alert_delivery_attempt(&store, &attempt, TEST_ACTOR).expect("retry attempt");
    assert_eq!(store.audit_count().expect("audit count"), audit_count);
    assert!(matches!(
        StoreWriter::write_alert_delivery_attempt(&store, &attempt, "other-actor"),
        Err(StoreError::AlertMutationConflict { .. })
    ));

    let mut delivered = alert.clone();
    delivered.last_sent_at = Some("2026-07-11T01:02:00Z".to_string());
    let finalize = AlertDeliveryFinalizeWrite {
        delivery_id: "delivery-00000000-0000-4000-8000-000000000001".to_string(),
        hook_type: "webhook".to_string(),
        ok: true,
        dry_run: false,
        alert_count: 1,
        bytes_written: 128,
        error_code: None,
        entries: vec![AlertEvaluationEntry {
            before: Some(alert.clone()),
            after: delivered.clone(),
        }],
    };
    inject_job_audit_failure(&db, "alert.delivery");
    assert_injected_job_audit_failure(StoreWriter::write_alert_delivery_finalize(
        &store, &finalize, TEST_ACTOR,
    ));
    assert_eq!(store.list_alert_events().expect("alerts"), vec![alert]);
    Connection::open(&db)
        .expect("open db")
        .execute_batch("DROP TRIGGER fail_scheduler_job_audit")
        .expect("remove failure trigger");
    StoreWriter::write_alert_delivery_finalize(&store, &finalize, TEST_ACTOR)
        .expect("finalize delivery");
    StoreWriter::write_alert_delivery_finalize(&store, &finalize, TEST_ACTOR)
        .expect("retry finalization");
    let stale = AlertDeliveryFinalizeWrite {
        delivery_id: "delivery-00000000-0000-4000-8000-000000000002".to_string(),
        ..finalize
    };
    assert!(matches!(
        StoreWriter::write_alert_delivery_finalize(&store, &stale, TEST_ACTOR),
        Err(StoreError::AlertMutationConflict { .. })
    ));
    assert_eq!(store.list_alert_events().expect("alerts"), vec![delivered]);
}

#[test]
fn alert_delivery_queue_is_fenced_retryable_and_idempotent() {
    let (_dir, store, db) = open_temp_store();
    let hook = AlertWebhookHookRecord {
        hook_id: "webhook-queue".to_string(),
        name: "queue".to_string(),
        hook_type: "webhook".to_string(),
        endpoint_url: "https://93.184.216.34/alerts".to_string(),
        endpoint_url_redacted: "https://93.184.216.34/<redacted>".to_string(),
        endpoint_host: "93.184.216.34".to_string(),
        host_allow: vec!["93.184.216.34".to_string()],
        hmac_key_id: "abcd1234abcd1234".to_string(),
        enabled: true,
        max_attempts: 2,
        timeout_ms: 1_500,
        created_at: "2026-07-11T01:00:00Z".to_string(),
        updated_at: "2026-07-11T01:00:00Z".to_string(),
    };
    StoreWriter::write_alert_webhook_hook_create(&store, &hook, TEST_ACTOR).expect("create hook");
    store
        .upsert_alert_event(&AlertEventRecord {
            alert_id: "alert-queue".to_string(),
            dedupe_key: "node:queue:stale".to_string(),
            node_id: Some("queue".to_string()),
            severity: "warning".to_string(),
            state: "open".to_string(),
            reason_code: "NODE_STALE".to_string(),
            first_seen_at: "2026-07-11T01:00:00Z".to_string(),
            last_seen_at: "2026-07-11T01:00:00Z".to_string(),
            last_sent_at: None,
            resolved_at: None,
            detail_json: json!({"methods": [], "summary": {}}),
        })
        .expect("seed alert");
    let enqueue = AlertDeliveryQueueEnqueue {
        queue_id: "delivery-queue-00000000-0000-4000-8000-000000000001".to_string(),
        alert_id: "alert-queue".to_string(),
        hook_id: "webhook-queue".to_string(),
        idempotency_key: "a".repeat(64),
        group_key: "warning:node_stale".to_string(),
        enqueued_at: "2026-07-11T01:00:00Z".to_string(),
    };
    StoreWriter::write_alert_delivery_queue_enqueue(&store, &enqueue, TEST_ACTOR).expect("enqueue");
    let audit_count = store.audit_count().expect("audit count");
    StoreWriter::write_alert_delivery_queue_enqueue(&store, &enqueue, TEST_ACTOR)
        .expect("exact enqueue retry");
    assert_eq!(store.audit_count().expect("audit count"), audit_count);
    assert!(matches!(
        StoreWriter::write_alert_delivery_queue_enqueue(&store, &enqueue, "different-actor"),
        Err(StoreError::AlertMutationConflict { .. })
    ));

    let claim = StoreWriter::write_alert_delivery_queue_claim_next(
        &store,
        "worker-a",
        "2026-07-11T01:00:01Z",
        60,
        TEST_ACTOR,
    )
    .expect("claim queue")
    .expect("claim exists");
    assert_eq!(claim.fence_token, 1);
    assert!(
        StoreWriter::write_alert_delivery_queue_claim_next(
            &Store::open(&db).expect("second store"),
            "worker-b",
            "2026-07-11T01:00:02Z",
            60,
            TEST_ACTOR,
        )
        .expect("competing claim")
        .is_none()
    );
    let expired_claim = claim.clone();
    let claim = StoreWriter::write_alert_delivery_queue_claim_next(
        &store,
        "worker-b",
        "2026-07-11T01:01:02Z",
        60,
        TEST_ACTOR,
    )
    .expect("recover expired claim")
    .expect("recovered claim exists");
    assert_eq!(claim.fence_token, 2);
    assert!(matches!(
        StoreWriter::write_alert_delivery_queue_renew(
            &store,
            &expired_claim,
            "2026-07-11T01:01:03Z",
            60,
            TEST_ACTOR,
        ),
        Err(StoreError::AlertMutationConflict { .. })
    ));
    let claim = StoreWriter::write_alert_delivery_queue_renew(
        &store,
        &claim,
        "2026-07-11T01:01:30Z",
        60,
        TEST_ACTOR,
    )
    .expect("renew claim");
    let retry_outcome = AlertDeliveryQueueOutcome {
        claim: claim.clone(),
        attempt: AlertDeliveryAttemptRecord {
            attempt_id: "queue-attempt-1".to_string(),
            alert_id: claim.alert_id.clone(),
            hook_id: claim.hook_id.clone(),
            attempt_no: 1,
            attempted_at: "2026-07-11T01:01:31Z".to_string(),
            status: "failed".to_string(),
            http_status_class: Some("5xx".to_string()),
            error_code: Some("WEBHOOK_HTTP_5XX".to_string()),
            bytes_sent: 128,
        },
        completed_at: "2026-07-11T01:01:31Z".to_string(),
        retry_at: Some("2026-07-11T01:01:41Z".to_string()),
        retryable: true,
        max_attempts: 2,
    };
    inject_job_audit_failure(&db, "alert.delivery.queue.outcome");
    assert_injected_job_audit_failure(StoreWriter::write_alert_delivery_queue_outcome(
        &store,
        &retry_outcome,
        TEST_ACTOR,
    ));
    assert!(
        store
            .list_alert_delivery_attempts()
            .expect("attempts")
            .is_empty()
    );
    assert_eq!(
        Connection::open(&db)
            .expect("open queue database")
            .query_row("SELECT status FROM alert_delivery_queue", [], |row| {
                row.get::<_, String>(0)
            })
            .expect("queue status"),
        "claimed"
    );
    Connection::open(&db)
        .expect("open queue database")
        .execute_batch("DROP TRIGGER fail_scheduler_job_audit")
        .expect("remove outcome audit failure trigger");
    StoreWriter::write_alert_delivery_queue_outcome(&store, &retry_outcome, TEST_ACTOR)
        .expect("persist retry outcome");
    assert!(
        StoreWriter::write_alert_delivery_queue_claim_next(
            &store,
            "worker-a",
            "2026-07-11T01:01:40Z",
            60,
            TEST_ACTOR,
        )
        .expect("early claim")
        .is_none()
    );
    let second_claim = StoreWriter::write_alert_delivery_queue_claim_next(
        &store,
        "worker-b",
        "2026-07-11T01:01:41Z",
        60,
        TEST_ACTOR,
    )
    .expect("retry claim")
    .expect("retry claim exists");
    assert_eq!(second_claim.fence_token, 3);
    assert_eq!(second_claim.attempt_count, 1);
    StoreWriter::write_alert_delivery_queue_outcome(
        &store,
        &AlertDeliveryQueueOutcome {
            claim: second_claim.clone(),
            attempt: AlertDeliveryAttemptRecord {
                attempt_id: "queue-attempt-2".to_string(),
                alert_id: second_claim.alert_id.clone(),
                hook_id: second_claim.hook_id.clone(),
                attempt_no: 2,
                attempted_at: "2026-07-11T01:01:42Z".to_string(),
                status: "succeeded".to_string(),
                http_status_class: Some("2xx".to_string()),
                error_code: None,
                bytes_sent: 128,
            },
            completed_at: "2026-07-11T01:01:42Z".to_string(),
            retry_at: None,
            retryable: false,
            max_attempts: 2,
        },
        TEST_ACTOR,
    )
    .expect("persist success");
    let (status, attempt_count, delivered): (String, i64, Option<String>) = Connection::open(&db)
        .expect("open queue database")
        .query_row(
            "SELECT status, attempt_count, delivered_at FROM alert_delivery_queue",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("queue state");
    assert_eq!(status, "succeeded");
    assert_eq!(attempt_count, 2);
    assert_eq!(delivered.as_deref(), Some("2026-07-11T01:01:42Z"));
    let mut dead_enqueue = enqueue.clone();
    dead_enqueue.queue_id = "delivery-queue-00000000-0000-4000-8000-000000000002".to_string();
    dead_enqueue.idempotency_key = "b".repeat(64);
    dead_enqueue.enqueued_at = "2026-07-11T01:02:00Z".to_string();
    StoreWriter::write_alert_delivery_queue_enqueue(&store, &dead_enqueue, TEST_ACTOR)
        .expect("enqueue dead-letter fixture");
    let dead_claim = StoreWriter::write_alert_delivery_queue_claim_next(
        &store,
        "worker-a",
        "2026-07-11T01:02:00Z",
        60,
        TEST_ACTOR,
    )
    .expect("claim dead-letter fixture")
    .expect("dead-letter claim exists");
    StoreWriter::write_alert_delivery_queue_outcome(
        &store,
        &AlertDeliveryQueueOutcome {
            claim: dead_claim.clone(),
            attempt: AlertDeliveryAttemptRecord {
                attempt_id: "queue-attempt-dead".to_string(),
                alert_id: dead_claim.alert_id.clone(),
                hook_id: dead_claim.hook_id.clone(),
                attempt_no: 1,
                attempted_at: "2026-07-11T01:02:01Z".to_string(),
                status: "failed".to_string(),
                http_status_class: Some("4xx".to_string()),
                error_code: Some("WEBHOOK_HTTP_4XX".to_string()),
                bytes_sent: 128,
            },
            completed_at: "2026-07-11T01:02:01Z".to_string(),
            retry_at: None,
            retryable: false,
            max_attempts: 2,
        },
        TEST_ACTOR,
    )
    .expect("persist dead-letter outcome");
    assert_eq!(
        Connection::open(&db)
            .expect("open queue database")
            .query_row(
                "SELECT status FROM alert_delivery_queue WHERE queue_id = ?1",
                [dead_enqueue.queue_id],
                |row| row.get::<_, String>(0),
            )
            .expect("dead-letter status"),
        "dead_letter"
    );
    assert!(matches!(
        StoreWriter::write_alert_delivery_queue_renew(
            &store,
            &claim,
            "2026-07-11T01:01:50Z",
            60,
            TEST_ACTOR,
        ),
        Err(StoreError::AlertMutationConflict { .. })
    ));
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
        reason_code: "CERT_EXPIRING_WARNING".to_string(),
        first_seen_at: "2026-07-08T07:00:00Z".to_string(),
        last_seen_at: "2026-07-08T07:00:00Z".to_string(),
        last_sent_at: None,
        resolved_at: None,
        detail_json: json!({"methods": [], "summary": {"days_remaining": 14}}),
    };
    store
        .upsert_alert_event(&initial)
        .expect("insert alert event");

    let updated = AlertEventRecord {
        state: "resolved".to_string(),
        last_seen_at: "2026-07-08T08:00:00Z".to_string(),
        resolved_at: Some("2026-07-08T08:00:00Z".to_string()),
        detail_json: json!({"methods": [], "summary": {"days_remaining": 30}}),
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
        .set_retention_policy(&policy, "store-test")
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
fn observability_store_tests_rejects_invalid_triggered_by_and_reason_code() {
    let (_dir, _store, db) = open_temp_store();
    let conn = Connection::open(db).expect("open db");

    let run_err = conn
        .execute(
            "INSERT INTO observability_runs
             (run_id, job_id, started_at, status, triggered_by, summary_json)
             VALUES ('run-bad', NULL, '2026-07-08T00:00:00Z', 'running', 'shell.exec', '{}')",
            [],
        )
        .expect_err("invalid triggered_by must be rejected");
    assert!(run_err.to_string().contains("CHECK"));

    let alert_err = conn
        .execute(
            "INSERT INTO alert_events
             (alert_id, dedupe_key, severity, state, reason_code, first_seen_at, last_seen_at, detail_json)
             VALUES ('alert-bad', 'alert:bad', 'warning', 'open', 'SHELL_EXEC', '2026-07-08T00:00:00Z', '2026-07-08T00:00:00Z', '{}')",
            [],
        )
        .expect_err("invalid reason_code must be rejected");
    assert!(alert_err.to_string().contains("CHECK"));
}

#[test]
fn observability_store_tests_enforces_observability_foreign_keys() {
    let (_dir, store, _db) = open_temp_store();

    let run = ObservabilityRunInsert {
        run_id: "run-orphan".to_string(),
        job_id: Some("missing-job".to_string()),
        started_at: "2026-07-08T07:30:00Z".to_string(),
        finished_at: None,
        status: "running".to_string(),
        triggered_by: "scheduler.run.once".to_string(),
        summary_json: json!({"started": true}),
    };
    let err = store
        .insert_observability_run(&run)
        .expect_err("orphaned job_id must be rejected");
    assert!(err.to_string().contains("FOREIGN KEY"));

    let observation = ProbeObservationInsert {
        observation_id: "obs-orphan".to_string(),
        run_id: Some("missing-run".to_string()),
        node_id: Some("hk-ocserv-01".to_string()),
        endpoint_id: Some("endpoint-1".to_string()),
        method: "probe.controller.ping".to_string(),
        ok: Some(true),
        error_code: None,
        duration_ms: Some(42),
        observed_at: "2026-07-08T07:30:00Z".to_string(),
        expires_at: None,
        result_class: "controller_rpc_summary".to_string(),
        summary_json: json!({"message": "pong"}),
    };
    let err = store
        .insert_probe_observation(&observation)
        .expect_err("orphaned run_id must be rejected");
    assert!(err.to_string().contains("FOREIGN KEY"));
}

#[test]
fn observability_store_tests_creates_scheduler_history_and_alert_indexes() {
    let (_dir, _store, db) = open_temp_store();
    let conn = Connection::open(db).expect("open db");

    for index in [
        "idx_observability_jobs_enabled_next_run_at",
        "idx_probe_observations_node_observed_at",
        "idx_probe_observations_run_id",
        "idx_alert_events_state_last_seen_at",
    ] {
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
                [index],
                |row| row.get(0),
            )
            .expect("query index");
        assert_eq!(count, 1, "missing index {index}");
    }
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
