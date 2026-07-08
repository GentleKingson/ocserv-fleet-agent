use ocfleet_cli::store::{NodeInsert, Store};
use rusqlite::Connection;
use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output};

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
