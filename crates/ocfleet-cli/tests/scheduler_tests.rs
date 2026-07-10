use ocfleet_cli::store::{NodeInsert, ProbeObservationInsert, Store};
use ocfleet_protocol::enrollment::EndpointStatus;
use ocfleet_protocol::method::{OCSERV_CERT_EXPIRY, PROBE_CONTROLLER_PING, PROBE_PATH_ECHO};
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

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("valid JSON stdout")
}

fn assert_no_raw_scheduler_fields(value: &Value) {
    match value {
        Value::Object(map) => {
            for key in map.keys() {
                assert!(
                    !matches!(
                        key.as_str(),
                        "raw" | "raw_body" | "stdout" | "stderr" | "response_body"
                    ),
                    "forbidden raw scheduler field present: {key}"
                );
            }
            for value in map.values() {
                assert_no_raw_scheduler_fields(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                assert_no_raw_scheduler_fields(value);
            }
        }
        _ => {}
    }
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

fn latest_audit_actor(database: &Path) -> String {
    Connection::open(database)
        .expect("open db")
        .query_row(
            "SELECT actor FROM controller_audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("latest audit actor")
}

fn install_scheduler_audit_failure(database: &Path, event: &str) {
    Connection::open(database)
        .expect("open database for audit failure trigger")
        .execute_batch(&format!(
            "CREATE TRIGGER fail_selected_scheduler_audit
             BEFORE INSERT ON controller_audit_log
             WHEN NEW.event = '{event}'
             BEGIN
               SELECT RAISE(ABORT, 'injected scheduler audit failure');
             END;"
        ))
        .expect("install scheduler audit failure trigger");
}

fn scheduler_job_clocks(database: &Path, job_id: &str) -> (Option<String>, Option<String>) {
    Connection::open(database)
        .expect("open database for scheduler clock query")
        .query_row(
            "SELECT next_run_at, last_run_at FROM observability_jobs WHERE job_id = ?1",
            [job_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("scheduler job clocks")
}

fn scheduler_audit_count(database: &Path, event: &str) -> i64 {
    Connection::open(database)
        .expect("open database for scheduler audit count")
        .query_row(
            "SELECT count(*) FROM controller_audit_log WHERE event = ?1",
            [event],
            |row| row.get(0),
        )
        .expect("scheduler audit count")
}

fn add_controller_ping_job(database_arg: &str, selector: &str) -> String {
    let output = run_ocfleet(&[
        "--database",
        database_arg,
        "schedule",
        "job",
        "add",
        "--kind",
        "controller-ping",
        "--interval",
        "60s",
        "--selector",
        selector,
    ]);
    parse_job_id(&output.stdout)
}

fn seed_missing_trust_job(database: &Path, database_arg: &str, node_id: &str) -> String {
    let endpoint_id = {
        let store = Store::open(database).expect("open store");
        add_node_with_generated_endpoint(&store, node_id)
    };
    Connection::open(database)
        .expect("open database to remove endpoint trust")
        .execute(
            "DELETE FROM endpoint_trust WHERE endpoint_id = ?1",
            [&endpoint_id],
        )
        .expect("remove endpoint trust");
    add_controller_ping_job(database_arg, &format!("node_id={node_id}"))
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
fn scheduler_tests_job_name_show_validate_status_and_json_outputs() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    {
        let store = Store::open(&database).expect("open store");
        add_node_with_generated_endpoint(&store, "hk-ocserv-01");
    }

    let add = run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "add",
        "--name",
        "HK ping",
        "--kind",
        "controller-ping",
        "--interval",
        "60s",
        "--selector",
        "node_id=hk-ocserv-01",
    ]);
    let job_id = parse_job_id(&add.stdout);

    let list = run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "list",
        "--json",
    ]);
    let payload = json_stdout(&list);
    assert_eq!(payload["job_count"], 1);
    assert_eq!(payload["jobs"][0]["job_id"], job_id);
    assert_eq!(payload["jobs"][0]["name"], "HK ping");
    assert_eq!(payload["jobs"][0]["selector"], "node_id=hk-ocserv-01");
    assert_no_raw_scheduler_fields(&payload);

    let show = run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "show",
        &job_id,
        "--json",
    ]);
    let payload = json_stdout(&show);
    assert_eq!(payload["job"]["job_id"], job_id);
    assert_eq!(payload["job"]["name"], "HK ping");
    assert_no_raw_scheduler_fields(&payload);

    let validate = run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "validate",
        &job_id,
        "--json",
    ]);
    let payload = json_stdout(&validate);
    assert_eq!(payload["valid"], true);
    assert_eq!(payload["target_count"], 1);

    let status = run_ocfleet(&["--database", &database_arg, "schedule", "status", "--json"]);
    let payload = json_stdout(&status);
    assert!(payload.get("enabled_jobs").is_some());
    assert!(payload.get("due_jobs").is_some());
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
fn scheduler_tests_path_probe_validate_requires_explicit_pair_without_mesh_enumeration() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    {
        let store = Store::open(&database).expect("open store");
        add_node_with_generated_endpoint(&store, "source-node");
        add_node_with_generated_endpoint(&store, "target-node");
        drop(store);
        let conn = Connection::open(&database).expect("open db");
        conn.execute(
            "INSERT INTO observability_jobs
             (job_id, kind, selector_json, pair_selector_json, interval_seconds, jitter_seconds, timeout_ms, enabled, next_run_at, created_at, updated_at)
             VALUES ('bad-path-job', 'path-probe', '{\"selector\":\"explicit_pair\"}', NULL, 60, 0, 5000, 1, '2026-07-08T00:00:00Z', '2026-07-08T00:00:00Z', '2026-07-08T00:00:00Z')",
            [],
        )
        .expect("insert path-probe job without pair");
    }

    let output = run_ocfleet_failure(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "validate",
        "bad-path-job",
        "--json",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let payload: Value = serde_json::from_str(&stdout).expect("valid validation JSON");
    assert_eq!(payload["valid"], false);
    assert_eq!(payload["reason_code"], "INVALID_PATH_PAIR");
    assert_eq!(payload["target_count"], 0);
    assert!(!stdout.contains("mesh"));

    let store = Store::open(&database).expect("open store");
    assert!(
        store
            .list_probe_observations(None, 10)
            .expect("list observations")
            .is_empty()
    );
    assert!(
        store
            .list_observability_runs(10)
            .expect("list runs")
            .is_empty()
    );
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
        "--actor",
        "scheduler-operator",
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
    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(latest_audit_actor(&database), "scheduler-operator");
    assert_eq!(event, "scheduler.job.add");
    assert_eq!(ok, 1);
    assert_eq!(detail["job_id"], job_id);
    assert_eq!(detail["before"], Value::Null);
    assert_eq!(detail["after"]["enabled"], true);

    run_ocfleet(&[
        "--actor",
        "scheduler-operator",
        "--database",
        &database_arg,
        "schedule",
        "job",
        "disable",
        &job_id,
    ]);
    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(latest_audit_actor(&database), "scheduler-operator");
    assert_eq!(event, "scheduler.job.disable");
    assert_eq!(ok, 1);
    assert_eq!(detail["job_id"], job_id);
    assert_eq!(detail["enabled"], false);
    assert_eq!(detail["before"]["enabled"], true);
    assert_eq!(detail["after"]["enabled"], false);

    run_ocfleet(&[
        "--actor",
        "scheduler-operator",
        "--database",
        &database_arg,
        "schedule",
        "job",
        "enable",
        &job_id,
    ]);
    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(latest_audit_actor(&database), "scheduler-operator");
    assert_eq!(event, "scheduler.job.enable");
    assert_eq!(ok, 1);
    assert_eq!(detail["job_id"], job_id);
    assert_eq!(detail["enabled"], true);
    assert_eq!(detail["before"]["enabled"], false);
    assert_eq!(detail["after"]["enabled"], true);
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
        // Leave margin above SQLite's busy timeout on loaded CI runners.
        Duration::from_secs(30),
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
fn scheduler_tests_targeted_run_executes_only_selected_job_and_queries_run() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    {
        let store = Store::open(&database).expect("open store");
        let first_endpoint = add_node_with_generated_endpoint(&store, "hk-ocserv-01");
        let second_endpoint = add_node_with_generated_endpoint(&store, "sg-ocserv-01");
        store
            .revoke_endpoint(&first_endpoint, "scheduler-user", "test preflight")
            .expect("revoke first endpoint");
        store
            .revoke_endpoint(&second_endpoint, "scheduler-user", "test preflight")
            .expect("revoke second endpoint");
    }

    let first = run_ocfleet(&[
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
        "node_id=hk-ocserv-01",
    ]);
    let first_job_id = parse_job_id(&first.stdout);
    let second = run_ocfleet(&[
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
        "node_id=sg-ocserv-01",
    ]);
    let second_job_id = parse_job_id(&second.stdout);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "--actor",
        "scheduler-run-operator",
        "schedule",
        "run",
        "--once",
        "--job-id",
        &first_job_id,
        "--json",
    ]);
    let payload = json_stdout(&output);
    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["job_id"], first_job_id);
    assert_eq!(payload["due_jobs"], 1);
    assert_eq!(payload["executed_jobs"], 1);
    let json_run_id = payload["run_ids"][0]
        .as_str()
        .expect("run id in run once JSON")
        .to_string();
    assert_no_raw_scheduler_fields(&payload);

    let store = Store::open(&database).expect("open store");
    let runs = store.list_observability_runs(10).expect("list runs");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, json_run_id);
    assert_eq!(runs[0].job_id.as_deref(), Some(first_job_id.as_str()));
    assert_eq!(runs[0].observation_count, 1);
    let first_job = store
        .get_observability_job(&first_job_id)
        .expect("load executed job")
        .expect("executed job exists");
    assert_eq!(first_job.last_run_at, runs[0].finished_at);
    let last_run_at = time::OffsetDateTime::parse(
        first_job
            .last_run_at
            .as_deref()
            .expect("last run timestamp"),
        &time::format_description::well_known::Rfc3339,
    )
    .expect("last run timestamp parses");
    let next_run_at = time::OffsetDateTime::parse(
        first_job
            .next_run_at
            .as_deref()
            .expect("next run timestamp"),
        &time::format_description::well_known::Rfc3339,
    )
    .expect("next run timestamp parses");
    assert_eq!((next_run_at - last_run_at).whole_seconds(), 60);
    let observations = store
        .list_probe_observations(None, 10)
        .expect("list observations");
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].node_id.as_deref(), Some("hk-ocserv-01"));
    assert_ne!(runs[0].job_id.as_deref(), Some(second_job_id.as_str()));
    let run_id = runs[0].run_id.clone();
    drop(store);

    let list = run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "run",
        "list",
        "--limit",
        "10",
        "--json",
    ]);
    let payload = json_stdout(&list);
    assert_eq!(payload["run_count"], 1);
    assert_eq!(payload["runs"][0]["run_id"], run_id);
    assert_eq!(payload["runs"][0]["job_id"], first_job_id);
    assert_eq!(payload["runs"][0]["observation_count"], 1);
    assert_no_raw_scheduler_fields(&payload);

    let show = run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "run",
        "show",
        &run_id,
        "--json",
    ]);
    let payload = json_stdout(&show);
    assert_eq!(payload["run"]["run_id"], run_id);
    assert_eq!(payload["run"]["job_id"], first_job_id);
    assert_eq!(payload["run"]["failed_observation_count"], 1);
    assert_no_raw_scheduler_fields(&payload);

    let (event, ok, detail) = latest_audit(&database);
    assert_eq!(event, "scheduler.run.once");
    assert_eq!(ok, 1);
    assert_eq!(detail["job_id"], first_job_id);
    let conn = Connection::open(&database).expect("open db for scheduler actor audit");
    for event_name in [
        "scheduler.run.start",
        "rpc.completed",
        "scheduler.run.finish",
        "scheduler.run.once",
    ] {
        let actor: String = conn
            .query_row(
                "SELECT actor FROM controller_audit_log WHERE event = ?1 ORDER BY id DESC LIMIT 1",
                [event_name],
                |row| row.get(0),
            )
            .expect("scheduler audit actor");
        assert_eq!(actor, "scheduler-run-operator", "event={event_name}");
    }
}

#[test]
fn scheduler_tests_run_all_due_jobs_still_executes_every_due_job() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

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
        "node_id=missing-a",
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
        "node_id=missing-b",
    ]);

    let output = run_ocfleet(&["--database", &database_arg, "schedule", "run", "--once"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("due_jobs=2"));
    assert!(stdout.contains("executed_jobs=2"));
    assert!(stdout.contains("failed_observations=2"));
}

#[test]
fn scheduler_tests_invalid_job_and_run_ids_return_clear_errors() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    for args in [
        vec![
            "--database",
            &database_arg,
            "schedule",
            "job",
            "show",
            "missing-job",
        ],
        vec![
            "--database",
            &database_arg,
            "schedule",
            "job",
            "enable",
            "missing-job",
        ],
        vec![
            "--database",
            &database_arg,
            "schedule",
            "job",
            "disable",
            "missing-job",
        ],
        vec![
            "--database",
            &database_arg,
            "schedule",
            "run",
            "--once",
            "--job-id",
            "missing-job",
        ],
        vec![
            "--database",
            &database_arg,
            "schedule",
            "run",
            "show",
            "missing-run",
        ],
    ] {
        let output = run_ocfleet_failure(&args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("not found"),
            "expected not found error, got: {stderr}"
        );
    }
}

#[test]
fn scheduler_tests_run_once_missing_and_disabled_node_write_failed_observations() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();

    {
        let store = Store::open(&database).expect("open store");
        store
            .add_node(
                &NodeInsert {
                    node_id: "disabled-node".to_string(),
                    endpoint_id: iroh::SecretKey::generate().public().to_string(),
                    name: "disabled-node".to_string(),
                    region: "hk".to_string(),
                    role: "ocserv".to_string(),
                },
                "scheduler-test",
            )
            .expect("add node");
        store
            .disable_node("disabled-node", "scheduler-test")
            .expect("disable node");
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
fn scheduler_tests_missing_endpoint_trust_fails_closed_without_network_attempt() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let unused_secret = dir.path().join("unused-controller.secret");
    let unused_secret_arg = unused_secret.to_string_lossy().into_owned();

    let endpoint_id = {
        let store = Store::open(&database).expect("open store");
        add_node_with_generated_endpoint(&store, "missing-trust-node")
    };
    let conn = Connection::open(&database).expect("open db");
    conn.execute(
        "DELETE FROM endpoint_trust WHERE endpoint_id = ?1",
        [&endpoint_id],
    )
    .expect("delete endpoint trust");
    drop(conn);

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
        "node_id=missing-trust-node",
    ]);

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "--secret-key",
        &unused_secret_arg,
        "schedule",
        "run",
        "--once",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("due_jobs=1"));
    assert!(stdout.contains("failed_observations=1"));
    assert!(!unused_secret.exists());

    let store = Store::open(&database).expect("open store");
    let observations = store
        .list_probe_observations(None, 10)
        .expect("list observations");
    assert_eq!(observations.len(), 1);
    assert_eq!(
        observations[0].node_id.as_deref(),
        Some("missing-trust-node")
    );
    assert_eq!(
        observations[0].endpoint_id.as_deref(),
        Some(endpoint_id.as_str())
    );
    assert_eq!(observations[0].ok, Some(false));
    assert_eq!(
        observations[0].error_code.as_deref(),
        Some("ENDPOINT_TRUST_MISSING")
    );
    assert_eq!(observations[0].duration_ms, Some(0));
    assert_eq!(
        observations[0].summary_json["result_class"],
        "controller_rpc_summary"
    );
    let conn = Connection::open(&database).expect("open db");
    let (error_code, detail): (String, String) = conn
        .query_row(
            "SELECT error_code, detail_json
             FROM controller_audit_log
             WHERE event = 'rpc.completed' AND method = ?1
             ORDER BY id DESC LIMIT 1",
            [PROBE_CONTROLLER_PING],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("missing-trust rejection audit");
    let detail: Value = serde_json::from_str(&detail).expect("parse rejection audit");
    assert_eq!(error_code, "ENDPOINT_NOT_ALLOWED");
    assert_eq!(detail["endpoint_trust_state"], "missing");
}

#[test]
fn scheduler_tests_ocserv_missing_trust_writes_rejection_audit() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let unused_secret = dir.path().join("unused-controller.secret");
    let unused_secret_arg = unused_secret.to_string_lossy().into_owned();

    let endpoint_id = {
        let store = Store::open(&database).expect("open store");
        add_node_with_generated_endpoint(&store, "missing-trust-ocserv")
    };
    Connection::open(&database)
        .expect("open db")
        .execute(
            "DELETE FROM endpoint_trust WHERE endpoint_id = ?1",
            [&endpoint_id],
        )
        .expect("delete endpoint trust");

    run_ocfleet(&[
        "--database",
        &database_arg,
        "schedule",
        "job",
        "add",
        "--kind",
        "ocserv-cert",
        "--interval",
        "60s",
        "--selector",
        "node_id=missing-trust-ocserv",
    ]);
    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "--secret-key",
        &unused_secret_arg,
        "schedule",
        "run",
        "--once",
    ]);
    assert!(String::from_utf8_lossy(&output.stdout).contains("failed_observations=1"));
    assert!(!unused_secret.exists());

    let store = Store::open(&database).expect("open store");
    let observations = store
        .list_probe_observations(None, 10)
        .expect("list observations");
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].method, OCSERV_CERT_EXPIRY);
    assert_eq!(
        observations[0].error_code.as_deref(),
        Some("ENDPOINT_TRUST_MISSING")
    );
    drop(store);
    let conn = Connection::open(&database).expect("open db");
    let (error_code, detail): (String, String) = conn
        .query_row(
            "SELECT error_code, detail_json
             FROM controller_audit_log
             WHERE event = 'rpc.completed' AND method = ?1
             ORDER BY id DESC LIMIT 1",
            [OCSERV_CERT_EXPIRY],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("ocserv rejection audit");
    let detail: Value = serde_json::from_str(&detail).expect("parse rejection audit");
    assert_eq!(error_code, "ENDPOINT_NOT_ALLOWED");
    assert_eq!(detail["endpoint_trust_state"], "missing");
    assert_eq!(detail["result_class"], "low_sensitive_summary");
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
fn scheduler_tests_invalid_target_set_is_recorded_before_run_start() {
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
    let run_count: i64 = conn
        .query_row(
            "SELECT count(*) FROM observability_runs WHERE job_id = ?1",
            [&job_id],
            |row| row.get(0),
        )
        .expect("scheduler run count");
    assert_eq!(run_count, 0);
    let (run_id, error_code, summary): (Option<String>, String, String) = conn
        .query_row(
            "SELECT run_id, error_code, summary_json
             FROM probe_observations
             WHERE error_code = 'SCHEDULER_JOB_INVALID'
             ORDER BY observed_at DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("invalid scheduler observation");
    assert!(run_id.is_none());
    assert_eq!(error_code, "SCHEDULER_JOB_INVALID");
    assert!(!summary.contains("maximum scheduler targets exceeded"));
    assert_eq!(scheduler_audit_count(&database, "scheduler.job.invalid"), 1);
    let (next_run_at, last_run_at) = scheduler_job_clocks(&database, &job_id);
    assert!(next_run_at.is_some());
    assert!(last_run_at.is_some());
}

#[test]
fn scheduler_tests_run_start_audit_failure_rolls_back_run_and_clock() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let job_id = add_controller_ping_job(&database_arg, "node_id=missing-node");
    let clocks_before = scheduler_job_clocks(&database, &job_id);
    install_scheduler_audit_failure(&database, "scheduler.run.start");

    let output = run_ocfleet_failure(&["--database", &database_arg, "schedule", "run", "--once"]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("injected scheduler audit failure"));

    let conn = Connection::open(&database).expect("open db");
    let run_count: i64 = conn
        .query_row(
            "SELECT count(*) FROM observability_runs WHERE job_id = ?1",
            [&job_id],
            |row| row.get(0),
        )
        .expect("run count");
    let observation_count: i64 = conn
        .query_row("SELECT count(*) FROM probe_observations", [], |row| {
            row.get(0)
        })
        .expect("observation count");
    assert_eq!(run_count, 0);
    assert_eq!(observation_count, 0);
    assert_eq!(scheduler_audit_count(&database, "scheduler.run.start"), 0);
    assert_eq!(scheduler_job_clocks(&database, &job_id), clocks_before);
}

#[test]
fn scheduler_tests_rpc_audit_failure_rolls_back_outcome_without_relabeling() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let job_id = seed_missing_trust_job(&database, &database_arg, "missing-trust-node");
    let clocks_before = scheduler_job_clocks(&database, &job_id);
    install_scheduler_audit_failure(&database, "rpc.completed");

    let output = run_ocfleet_failure(&["--database", &database_arg, "schedule", "run", "--once"]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("injected scheduler audit failure"));

    let conn = Connection::open(&database).expect("open db");
    let (run_id, status, finished_at): (String, String, Option<String>) = conn
        .query_row(
            "SELECT run_id, status, finished_at FROM observability_runs WHERE job_id = ?1",
            [&job_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("running scheduler run");
    let observation_count: i64 = conn
        .query_row(
            "SELECT count(*) FROM probe_observations WHERE run_id = ?1",
            [&run_id],
            |row| row.get(0),
        )
        .expect("outcome observation count");
    assert_eq!(status, "running");
    assert!(finished_at.is_none());
    assert_eq!(observation_count, 0);
    assert_eq!(scheduler_audit_count(&database, "rpc.completed"), 0);
    assert_eq!(scheduler_audit_count(&database, "scheduler.job.invalid"), 0);
    assert_eq!(scheduler_audit_count(&database, "scheduler.run.finish"), 0);
    assert_eq!(scheduler_job_clocks(&database, &job_id), clocks_before);
}

#[test]
fn scheduler_tests_run_finish_audit_failure_keeps_committed_outcome_and_running_run() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let job_id = seed_missing_trust_job(&database, &database_arg, "finish-failure-node");
    let clocks_before = scheduler_job_clocks(&database, &job_id);
    install_scheduler_audit_failure(&database, "scheduler.run.finish");

    let output = run_ocfleet_failure(&["--database", &database_arg, "schedule", "run", "--once"]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("injected scheduler audit failure"));

    let conn = Connection::open(&database).expect("open db");
    let (run_id, status, finished_at): (String, String, Option<String>) = conn
        .query_row(
            "SELECT run_id, status, finished_at FROM observability_runs WHERE job_id = ?1",
            [&job_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("running scheduler run");
    let observation_count: i64 = conn
        .query_row(
            "SELECT count(*) FROM probe_observations WHERE run_id = ?1",
            [&run_id],
            |row| row.get(0),
        )
        .expect("outcome observation count");
    assert_eq!(status, "running");
    assert!(finished_at.is_none());
    assert_eq!(observation_count, 1);
    assert_eq!(scheduler_audit_count(&database, "rpc.completed"), 1);
    assert_eq!(scheduler_audit_count(&database, "scheduler.run.finish"), 0);
    assert_eq!(scheduler_job_clocks(&database, &job_id), clocks_before);
}

fn add_node_with_generated_endpoint(store: &Store, node_id: &str) -> String {
    let endpoint_id = iroh::SecretKey::generate().public().to_string();
    store
        .add_node(
            &NodeInsert {
                node_id: node_id.to_string(),
                endpoint_id: endpoint_id.clone(),
                name: node_id.to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            "scheduler-test",
        )
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

#[test]
fn scheduler_tests_path_probe_missing_target_trust_fails_closed_without_network_attempt() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let database_arg = database.to_string_lossy().into_owned();
    let unused_secret = dir.path().join("unused-controller.secret");
    let unused_secret_arg = unused_secret.to_string_lossy().into_owned();

    let (source_endpoint_id, target_endpoint_id) = {
        let store = Store::open(&database).expect("open store");
        (
            add_node_with_generated_endpoint(&store, "source-node"),
            add_node_with_generated_endpoint(&store, "target-node"),
        )
    };
    let conn = Connection::open(&database).expect("open db");
    conn.execute(
        "DELETE FROM endpoint_trust WHERE endpoint_id = ?1",
        [&target_endpoint_id],
    )
    .expect("delete target endpoint trust");
    drop(conn);

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

    let output = run_ocfleet(&[
        "--database",
        &database_arg,
        "--secret-key",
        &unused_secret_arg,
        "schedule",
        "run",
        "--once",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("due_jobs=1"));
    assert!(stdout.contains("failed_observations=1"));
    assert!(!unused_secret.exists());

    let store = Store::open(&database).expect("open store");
    let observations = store
        .list_probe_observations(None, 10)
        .expect("list observations");
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].node_id.as_deref(), Some("source-node"));
    assert_eq!(
        observations[0].endpoint_id.as_deref(),
        Some(source_endpoint_id.as_str())
    );
    assert_eq!(observations[0].ok, Some(false));
    assert_eq!(
        observations[0].error_code.as_deref(),
        Some("TARGET_ENDPOINT_TRUST_MISSING")
    );
    assert_eq!(observations[0].duration_ms, Some(0));
    assert_eq!(
        observations[0].summary_json["target_endpoint_id"],
        target_endpoint_id
    );
    assert_eq!(
        observations[0].summary_json["result_class"],
        "controller_rpc_summary"
    );
    let conn = Connection::open(&database).expect("open db");
    let (error_code, detail): (String, String) = conn
        .query_row(
            "SELECT error_code, detail_json
             FROM controller_audit_log
             WHERE event = 'rpc.completed' AND method = ?1
             ORDER BY id DESC LIMIT 1",
            [PROBE_PATH_ECHO],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("path rejection audit");
    let detail: Value = serde_json::from_str(&detail).expect("parse path rejection audit");
    assert_eq!(error_code, "ENDPOINT_NOT_ALLOWED");
    assert_eq!(detail["error_code"], "TARGET_ENDPOINT_TRUST_MISSING");
    assert_eq!(detail["target_endpoint_id"], target_endpoint_id);
}
