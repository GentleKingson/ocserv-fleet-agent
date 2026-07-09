use ocfleet_cli::store::{NodeInsert, ProbeObservationInsert, Store};
use ocfleet_protocol::enrollment::EndpointStatus;
use ocfleet_protocol::method::PROBE_CONTROLLER_PING;
use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn run_ocfleet(args: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_ocfleet"))
        .args(args)
        .env("USER", "scheduler-user")
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
        .env("USER", "scheduler-user")
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

fn spawn_ocfleet(args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_ocfleet"))
        .args(args)
        .env("USER", "scheduler-user")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ocfleet")
}

fn parse_job_id(stdout: &[u8]) -> String {
    String::from_utf8_lossy(stdout)
        .lines()
        .find_map(|line| line.strip_prefix("job_id=").map(ToOwned::to_owned))
        .expect("job id in stdout")
}

fn latest_audit(database: &Path) -> (String, i64, Value) {
    let conn = Connection::open(database).expect("open db");
    let (event, ok, detail): (String, i64, String) = conn
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

fn wait_for_audit_event(
    database: &Path,
    event_name: &str,
    timeout: Duration,
) -> Option<(i64, Value)> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        let result = Connection::open(database)
            .expect("open db")
            .query_row(
                "SELECT ok, detail_json FROM controller_audit_log
                 WHERE event = ?1
                 ORDER BY id DESC
                 LIMIT 1",
                [event_name],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .expect("query audit event");
        if let Some((ok, detail)) = result {
            return Some((
                ok,
                serde_json::from_str(&detail).expect("parse detail json"),
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
    None
}

#[test]
fn scheduler_tests_schedule_job_add_and_list() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let add = run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "add",
        "--kind",
        "controller-ping",
        "--interval",
        "60s",
    ]);
    let job_id = parse_job_id(&add.stdout);

    let list = run_ocfleet(&["--database", &database_arg, "schedule", "job", "list"]);
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains(&format!("job_id={job_id}")));
    assert!(stdout.contains("kind=controller-ping"));
    assert!(stdout.contains("enabled=true"));
    assert!(stdout.contains("interval_seconds=60"));
    assert!(stdout.contains("selector=role=ocserv"));
    assert!(stdout.contains("next_run_at="));
    assert!(stdout.contains("last_run_at="));
}

#[test]
fn scheduler_tests_invalid_interval_rejected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "add",
        "--kind",
        "controller-ping",
        "--interval",
        "0s",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("interval"));
}

#[test]
fn scheduler_tests_too_frequent_interval_rejected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "add",
        "--kind",
        "controller-ping",
        "--interval",
        "1s",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("between 60 and 86400"));
}

#[test]
fn scheduler_tests_max_concurrency_validation_accepts_bounded_parallelism() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let zero = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "schedule",
        "run",
        "--once",
        "--max-concurrency",
        "0",
    ]);
    let stderr = String::from_utf8_lossy(&zero.stderr);
    assert!(stderr.contains("greater than zero"));

    let two = run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "run",
        "--once",
        "--max-concurrency",
        "2",
    ]);
    let stdout = String::from_utf8_lossy(&two.stdout);
    assert!(stdout.contains("status=ok"));

    let four = run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "run",
        "--once",
        "--max-concurrency",
        "4",
    ]);
    let stdout = String::from_utf8_lossy(&four.stdout);
    assert!(stdout.contains("status=ok"));
    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "scheduler.run.once");
    assert_eq!(ok, 1);
    assert_eq!(detail["max_concurrency"], 4);

    let above_limit = (ocfleet_cli::scheduler::MAX_ALLOWED_CONCURRENCY + 1).to_string();
    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "schedule",
        "run",
        "--once",
        "--max-concurrency",
        &above_limit,
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("must be between 1 and"));
}

#[test]
fn scheduler_tests_daemon_tick_too_low_rejected_before_loop() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "schedule",
        "daemon",
        "--tick-seconds",
        "1",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("tick-seconds"));
}

#[test]
fn scheduler_tests_path_probe_without_explicit_pair_rejected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "add",
        "--kind",
        "path-probe",
        "--interval",
        "60s",
        "--source-node-id",
        "hk-ocserv-01",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("path-probe requires --target-node-id"));
}

#[test]
fn scheduler_tests_path_probe_rejects_user_selector() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "add",
        "--kind",
        "path-probe",
        "--interval",
        "60s",
        "--source-node-id",
        "hk-ocserv-01",
        "--target-node-id",
        "sg-ocserv-01",
        "--selector",
        "role=ocserv",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--selector is not valid for path-probe"));
}

#[test]
fn scheduler_tests_non_path_job_with_pair_rejected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "add",
        "--kind",
        "controller-ping",
        "--interval",
        "60s",
        "--source-node-id",
        "hk-ocserv-01",
        "--target-node-id",
        "sg-ocserv-01",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("only valid for path-probe jobs"));
}

#[test]
fn scheduler_tests_role_selector_rejects_too_many_targets_before_rpc() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    {
        let store = Store::open(&database).expect("open store");
        for index in 0..51 {
            add_node_with_generated_endpoint(&store, &format!("node-{index:02}"));
        }
    }

    run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "add",
        "--kind",
        "controller-ping",
        "--interval",
        "60s",
        "--selector",
        "role=ocserv",
    ]);

    let output = run_ocfleet(&["--database", &database_arg, "schedule", "run", "--once"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("status=ok"));
    assert!(stdout.contains("observations=1"));
    assert!(stdout.contains("failed_observations=1"));
    assert!(!stdout.contains("observations=51"));

    let store = Store::open(&database).expect("open store");
    let observations = store
        .list_probe_observations(None, 10)
        .expect("list observations");
    assert_eq!(observations.len(), 1);
    assert_eq!(
        observations[0].error_code.as_deref(),
        Some("SCHEDULER_JOB_INVALID")
    );
}

#[test]
fn scheduler_tests_enable_disable_writes_audit() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let add = run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "add",
        "--kind",
        "controller-ping",
        "--interval",
        "60s",
    ]);
    let job_id = parse_job_id(&add.stdout);

    run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "disable",
        &job_id,
    ]);
    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "scheduler.job.disable");
    assert_eq!(ok, 1);
    assert_eq!(detail["job_id"], job_id);
    assert_eq!(detail["enabled"], false);

    run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "enable",
        &job_id,
    ]);
    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "scheduler.job.enable");
    assert_eq!(ok, 1);
    assert_eq!(detail["job_id"], job_id);
    assert_eq!(detail["enabled"], true);
}

#[test]
fn scheduler_tests_run_once_with_no_due_jobs_succeeds() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let output = run_ocfleet(&["--database", &database_arg, "schedule", "run", "--once"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("status=ok"));
    assert!(stdout.contains("due_jobs=0"));
    assert!(stdout.contains("executed_jobs=0"));

    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "scheduler.run.once");
    assert_eq!(ok, 1);
    assert_eq!(detail["due_jobs"], 0);
}

#[test]
fn scheduler_tests_run_once_evaluates_alerts_from_probe_observations() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    {
        let store = Store::open(&database).expect("open store");
        let endpoint_id = add_node_with_generated_endpoint(&store, "hk-ocserv-01");
        let mut policy = Store::default_health_policy();
        policy.unreachable_consecutive_failures = 1;
        store
            .set_health_policy(&policy, "scheduler-test")
            .expect("set health policy");
        store
            .insert_probe_observation(&ProbeObservationInsert {
                observation_id: "obs-timeout-1".to_string(),
                run_id: None,
                node_id: Some("hk-ocserv-01".to_string()),
                endpoint_id: Some(endpoint_id),
                method: PROBE_CONTROLLER_PING.to_string(),
                ok: Some(false),
                error_code: Some("RPC_TIMEOUT".to_string()),
                duration_ms: Some(100),
                observed_at: "2026-07-08T00:00:00Z".to_string(),
                expires_at: None,
                result_class: "controller_rpc_summary".to_string(),
                summary_json: serde_json::json!({
                    "result_class": "controller_rpc_summary"
                }),
            })
            .expect("insert observation");
    }

    let output = run_ocfleet(&["--database", &database_arg, "schedule", "run", "--once"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("status=ok"));
    assert!(stdout.contains("alert_evaluation=ok"));
    assert!(stdout.contains("alert_events=1"));

    let store = Store::open(&database).expect("reopen store");
    let alerts = store.list_alert_events().expect("list alerts");
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].dedupe_key, "node:hk-ocserv-01:node_unreachable");
    assert_eq!(alerts[0].reason_code, "NODE_UNREACHABLE");

    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "scheduler.run.once");
    assert_eq!(ok, 1);
    assert_eq!(detail["alert_evaluation_ok"], true);
    assert_eq!(detail["alert_events_upserted"], 1);
    assert_eq!(detail["alert_open_alerts"], 1);
}

#[test]
fn scheduler_tests_repeated_run_once_dedupes_alert_events() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    {
        let store = Store::open(&database).expect("open store");
        let endpoint_id = add_node_with_generated_endpoint(&store, "hk-ocserv-01");
        let mut policy = Store::default_health_policy();
        policy.unreachable_consecutive_failures = 1;
        store
            .set_health_policy(&policy, "scheduler-test")
            .expect("set health policy");
        store
            .insert_probe_observation(&ProbeObservationInsert {
                observation_id: "obs-timeout-1".to_string(),
                run_id: None,
                node_id: Some("hk-ocserv-01".to_string()),
                endpoint_id: Some(endpoint_id),
                method: PROBE_CONTROLLER_PING.to_string(),
                ok: Some(false),
                error_code: Some("RPC_TIMEOUT".to_string()),
                duration_ms: Some(100),
                observed_at: "2026-07-08T00:00:00Z".to_string(),
                expires_at: None,
                result_class: "controller_rpc_summary".to_string(),
                summary_json: serde_json::json!({
                    "result_class": "controller_rpc_summary"
                }),
            })
            .expect("insert observation");
    }

    run_ocfleet(&["--database", &database_arg, "schedule", "run", "--once"]);
    run_ocfleet(&["--database", &database_arg, "schedule", "run", "--once"]);

    let store = Store::open(&database).expect("reopen store");
    let alerts = store.list_alert_events().expect("list alerts");
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].dedupe_key, "node:hk-ocserv-01:node_unreachable");
}

#[test]
fn scheduler_tests_alert_evaluation_failure_keeps_run_once_successful() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    {
        let store = Store::open(&database).expect("open store");
        drop(store);
        let conn = Connection::open(&database).expect("open db");
        conn.pragma_update(None, "ignore_check_constraints", true)
            .expect("ignore check constraints");
        conn.execute(
            "UPDATE health_policy SET unreachable_consecutive_failures = -1 WHERE id = 1",
            [],
        )
        .expect("corrupt health policy");
    }

    let output = run_ocfleet(&["--database", &database_arg, "schedule", "run", "--once"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("status=ok"));
    assert!(stdout.contains("alert_evaluation=failed"));
    assert!(stdout.contains("alert_events=0"));

    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "scheduler.run.once");
    assert_eq!(ok, 1);
    assert_eq!(detail["alert_evaluation_ok"], false);
    assert_eq!(
        detail["alert_evaluation_error_code"],
        "ALERT_EVALUATION_FAILED"
    );
    assert_eq!(
        detail["alert_evaluation_error_message"],
        "local alert evaluation failed"
    );
}

#[test]
fn scheduler_tests_daemon_alert_evaluation_failure_writes_warning_and_continues() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    {
        let store = Store::open(&database).expect("open store");
        drop(store);
        let conn = Connection::open(&database).expect("open db");
        conn.pragma_update(None, "ignore_check_constraints", true)
            .expect("ignore check constraints");
        conn.execute(
            "UPDATE health_policy SET unreachable_consecutive_failures = -1 WHERE id = 1",
            [],
        )
        .expect("corrupt health policy");
    }

    let mut child = spawn_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "daemon",
        "--tick-seconds",
        "10",
    ]);
    let audit = wait_for_audit_event(
        &database,
        "scheduler.alert.evaluate",
        Duration::from_secs(5),
    );
    let still_running = child.try_wait().expect("try wait").is_none();
    let _ = child.kill();
    let output = child.wait_with_output().expect("wait for daemon");

    let (ok, detail) = audit.unwrap_or_else(|| {
        panic!(
            "missing scheduler.alert.evaluate audit: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_eq!(ok, 0);
    assert_eq!(detail["alert_evaluation_ok"], false);
    assert_eq!(
        detail["alert_evaluation_error_code"],
        "ALERT_EVALUATION_FAILED"
    );
    assert!(
        still_running,
        "daemon exited after alert evaluation failure"
    );
}

#[test]
fn scheduler_tests_run_once_disabled_job_skipped() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let add = run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "add",
        "--kind",
        "controller-ping",
        "--interval",
        "60s",
    ]);
    let job_id = parse_job_id(&add.stdout);
    run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "disable",
        &job_id,
    ]);

    let output = run_ocfleet(&["--database", &database_arg, "schedule", "run", "--once"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("due_jobs=0"));
    assert!(stdout.contains("executed_jobs=0"));
    assert!(stdout.contains("skipped_jobs=1"));

    let store = Store::open(&database).expect("open store");
    let observations = store
        .list_probe_observations(None, 10)
        .expect("list observations");
    assert!(observations.is_empty());
}

#[test]
fn scheduler_tests_run_once_missing_and_disabled_node_write_failed_observations() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    {
        let store = Store::open(&database).expect("open store");
        store
            .add_node(&NodeInsert {
                node_id: "disabled-node".to_string(),
                endpoint_id: iroh::SecretKey::generate().public().to_string(),
                name: "disabled-node".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            })
            .expect("add node");
        store.disable_node("disabled-node").expect("disable node");
    }

    run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "add",
        "--kind",
        "controller-ping",
        "--interval",
        "60s",
        "--selector",
        "node_id=missing-node",
    ]);
    run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "add",
        "--kind",
        "controller-ping",
        "--interval",
        "60s",
        "--selector",
        "node_id=disabled-node",
    ]);

    let output = run_ocfleet(&["--database", &database_arg, "schedule", "run", "--once"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("due_jobs=2"));
    assert!(stdout.contains("executed_jobs=2"));
    assert!(stdout.contains("failed_observations=2"));

    let store = Store::open(&database).expect("open store");
    let observations = store
        .list_probe_observations(None, 10)
        .expect("list observations");
    assert_eq!(observations.len(), 2);
    let error_codes = observations
        .iter()
        .map(|observation| observation.error_code.as_deref())
        .collect::<Vec<_>>();
    assert!(error_codes.contains(&Some("NODE_NOT_FOUND")));
    assert!(error_codes.contains(&Some("NODE_DISABLED")));
    assert!(
        observations
            .iter()
            .all(|observation| observation.ok == Some(false))
    );
}

#[test]
fn scheduler_tests_malformed_job_does_not_block_valid_job() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    {
        let store = Store::open(&database).expect("open store");
        drop(store);
        let conn = Connection::open(&database).expect("open db");
        conn.execute(
            "INSERT INTO observability_jobs
             (job_id, kind, selector_json, interval_seconds, jitter_seconds, timeout_ms, enabled, next_run_at, created_at, updated_at)
             VALUES ('bad-job', 'controller-ping', '{\"selector\":\"role=ocserv\"}', 60, 0, 5000, 1, 'not-a-timestamp', '2026-07-08T00:00:00Z', '2026-07-08T00:00:00Z')",
            [],
        )
        .expect("insert malformed job");
    }

    run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "add",
        "--kind",
        "controller-ping",
        "--interval",
        "60s",
        "--selector",
        "node_id=missing-node",
    ]);

    let output = run_ocfleet(&["--database", &database_arg, "schedule", "run", "--once"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("status=ok"));

    let store = Store::open(&database).expect("open store");
    let observations = store
        .list_probe_observations(None, 10)
        .expect("list observations");
    let error_codes = observations
        .iter()
        .map(|observation| observation.error_code.as_deref())
        .collect::<Vec<_>>();
    assert!(error_codes.contains(&Some("SCHEDULER_JOB_INVALID")));
    assert!(error_codes.contains(&Some("NODE_NOT_FOUND")));
}

#[test]
fn scheduler_tests_malformed_job_json_does_not_block_valid_job() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    {
        let store = Store::open(&database).expect("open store");
        drop(store);
        let conn = Connection::open(&database).expect("open db");
        conn.pragma_update(None, "ignore_check_constraints", true)
            .expect("disable check constraints for corruption fixture");
        conn.execute(
            "INSERT INTO observability_jobs
             (job_id, kind, selector_json, interval_seconds, jitter_seconds, timeout_ms, enabled, next_run_at, created_at, updated_at)
             VALUES ('bad-json-job', 'controller-ping', 'not-json', 60, 0, 5000, 1, '2026-07-08T00:00:00Z', '2026-07-08T00:00:00Z', '2026-07-08T00:00:00Z')",
            [],
        )
        .expect("insert malformed json job");
    }

    run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "add",
        "--kind",
        "controller-ping",
        "--interval",
        "60s",
        "--selector",
        "node_id=missing-node",
    ]);

    let output = run_ocfleet(&["--database", &database_arg, "schedule", "run", "--once"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("status=ok"));
    assert!(stdout.contains("executed_jobs=2"));

    let store = Store::open(&database).expect("open store");
    let observations = store
        .list_probe_observations(None, 10)
        .expect("list observations");
    let error_codes = observations
        .iter()
        .map(|observation| observation.error_code.as_deref())
        .collect::<Vec<_>>();
    assert!(error_codes.contains(&Some("SCHEDULER_JOB_INVALID")));
    assert!(error_codes.contains(&Some("NODE_NOT_FOUND")));
}

#[test]
fn scheduler_tests_failed_after_run_insert_finishes_run_as_failed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    {
        let store = Store::open(&database).expect("open store");
        for index in 0..51 {
            add_node_with_generated_endpoint(&store, &format!("node-{index:02}"));
        }
    }

    let add = run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "add",
        "--kind",
        "controller-ping",
        "--interval",
        "60s",
        "--selector",
        "role=ocserv",
    ]);
    let job_id = parse_job_id(&add.stdout);

    run_ocfleet(&["--database", &database_arg, "schedule", "run", "--once"]);

    let conn = Connection::open(&database).expect("open db");
    let (status, finished_at, summary): (String, Option<String>, String) = conn
        .query_row(
            "SELECT status, finished_at, summary_json FROM observability_runs WHERE job_id = ?1",
            [&job_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("scheduler run");
    let summary: Value = serde_json::from_str(&summary).expect("run summary");
    assert_eq!(status, "failed");
    assert!(finished_at.is_some());
    assert_eq!(summary["error_code"], "SCHEDULER_JOB_INVALID");
    assert!(
        !summary
            .to_string()
            .contains("maximum scheduler targets exceeded")
    );
}

fn add_node_with_generated_endpoint(store: &Store, node_id: &str) -> String {
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    store
        .add_node(&NodeInsert {
            node_id: node_id.to_string(),
            endpoint_id: endpoint_id.clone(),
            name: node_id.to_string(),
            region: "hk".to_string(),
            role: "ocserv".to_string(),
        })
        .expect("add node");
    endpoint_id
}

fn assert_path_probe_target_endpoint_status_rejected(status: EndpointStatus, expected_code: &str) {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    let target_endpoint_id = {
        let store = Store::open(&database).expect("open store");
        add_node_with_generated_endpoint(&store, "source-node");
        let target_endpoint_id = add_node_with_generated_endpoint(&store, "target-node");
        match status {
            EndpointStatus::Revoked => {
                store
                    .revoke_endpoint(&target_endpoint_id, "operator", "test revoke")
                    .expect("revoke endpoint");
            }
            EndpointStatus::Quarantined => {
                store
                    .quarantine_endpoint(&target_endpoint_id, "operator", "test quarantine")
                    .expect("quarantine endpoint");
            }
            EndpointStatus::Rotated => {
                let new_endpoint_id = iroh::SecretKey::generate().public().to_string();
                store
                    .rotate_endpoint(
                        &target_endpoint_id,
                        &new_endpoint_id,
                        "operator",
                        "test rotate",
                    )
                    .expect("rotate endpoint");
            }
            EndpointStatus::Active => panic!("active endpoint is not a rejection case"),
        }
        target_endpoint_id
    };

    run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "add",
        "--kind",
        "path-probe",
        "--interval",
        "60s",
        "--source-node-id",
        "source-node",
        "--target-node-id",
        "target-node",
    ]);

    let output = run_ocfleet(&["--database", &database_arg, "schedule", "run", "--once"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("due_jobs=1"));
    assert!(stdout.contains("failed_observations=1"));

    let store = Store::open(&database).expect("open store");
    let observations = store
        .list_probe_observations(None, 10)
        .expect("list observations");
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].ok, Some(false));
    assert_eq!(observations[0].error_code.as_deref(), Some(expected_code));
    assert_eq!(
        observations[0].summary_json["target_endpoint_id"],
        target_endpoint_id
    );
}

#[test]
fn scheduler_tests_path_probe_target_revoked_writes_failed_preflight() {
    assert_path_probe_target_endpoint_status_rejected(
        EndpointStatus::Revoked,
        "TARGET_ENDPOINT_REVOKED",
    );
}

#[test]
fn scheduler_tests_path_probe_target_quarantined_writes_failed_preflight() {
    assert_path_probe_target_endpoint_status_rejected(
        EndpointStatus::Quarantined,
        "TARGET_ENDPOINT_QUARANTINED",
    );
}

#[test]
fn scheduler_tests_path_probe_target_rotated_writes_failed_preflight() {
    assert_path_probe_target_endpoint_status_rejected(
        EndpointStatus::Rotated,
        "TARGET_ENDPOINT_ROTATED",
    );
}
