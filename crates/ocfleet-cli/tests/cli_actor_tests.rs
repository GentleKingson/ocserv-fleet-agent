use rusqlite::Connection;
use std::path::Path;
use std::process::Command;

#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

fn run_init_with_user(database: &Path, secret_key: &Path, user: Option<&str>) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ocfleet"));
    command
        .arg("--database")
        .arg(database)
        .arg("--secret-key")
        .arg(secret_key)
        .arg("init");
    command.env_remove("OCFLEET_ACTOR");
    match user {
        Some(value) => {
            command.env("USER", value);
        }
        None => {
            command.env_remove("USER");
        }
    }

    let output = command.output().expect("run ocfleet init");
    assert!(
        output.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn latest_actor(database: &Path) -> String {
    let conn = Connection::open(database).expect("open db");
    conn.query_row(
        "SELECT actor FROM controller_audit_log ORDER BY id DESC LIMIT 1",
        [],
        |row| row.get(0),
    )
    .expect("latest actor")
}

#[test]
fn init_audit_actor_falls_back_when_user_is_missing_or_blank() {
    for user in [None, Some(""), Some(" \t ")] {
        let dir = tempfile::tempdir().expect("temp dir");
        let database = dir.path().join("controller.sqlite");
        let secret_key = dir.path().join("controller.secret");

        run_init_with_user(&database, &secret_key, user);

        assert_eq!(latest_actor(&database), "local-cli");
    }
}

fn run_init_with_actor(
    database: &Path,
    secret_key: &Path,
    actor_flag: Option<&str>,
    actor_env: Option<&str>,
) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ocfleet"));
    command.arg("--database").arg(database);
    if let Some(actor) = actor_flag {
        command.arg("--actor").arg(actor);
    }
    command
        .arg("--secret-key")
        .arg(secret_key)
        .arg("init")
        .env("USER", "fallback-user");
    match actor_env {
        Some(value) => {
            command.env("OCFLEET_ACTOR", value);
        }
        None => {
            command.env_remove("OCFLEET_ACTOR");
        }
    }

    let output = command.output().expect("run ocfleet init");
    assert!(
        output.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn init_audit_actor_uses_non_blank_user() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("controller.secret");

    run_init_with_user(&database, &secret_key, Some("alice"));

    assert_eq!(latest_actor(&database), "alice");
}

#[test]
fn init_audit_actor_uses_explicit_actor_before_environment() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("controller.secret");

    run_init_with_actor(
        &database,
        &secret_key,
        Some("flag-actor@example.test"),
        Some("env-actor@example.test"),
    );

    assert_eq!(latest_actor(&database), "flag-actor@example.test");
}

#[test]
fn init_audit_actor_uses_ocfleet_actor_environment() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("controller.secret");

    run_init_with_actor(&database, &secret_key, None, Some("env-actor@example.test"));

    assert_eq!(latest_actor(&database), "env-actor@example.test");
}

#[test]
fn init_audit_actor_rejects_control_characters_and_overlong_user() {
    for user in [
        "alice\nadmin".to_string(),
        "\x1b[31madmin".to_string(),
        "a".repeat(129),
    ] {
        let dir = tempfile::tempdir().expect("temp dir");
        let database = dir.path().join("controller.sqlite");
        let secret_key = dir.path().join("controller.secret");

        run_init_with_user(&database, &secret_key, Some(&user));

        assert_eq!(latest_actor(&database), "local-cli");
    }
}

#[cfg(unix)]
#[test]
fn explicit_actor_environment_rejects_non_utf8_without_fallback() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("controller.secret");
    let output = Command::new(env!("CARGO_BIN_EXE_ocfleet"))
        .arg("--database")
        .arg(&database)
        .arg("--secret-key")
        .arg(&secret_key)
        .arg("init")
        .env("USER", "fallback-user")
        .env("OCFLEET_ACTOR", OsString::from_vec(vec![0xff, 0xfe]))
        .output()
        .expect("run ocfleet init");

    assert!(!output.status.success());
    assert!(!database.exists());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("OCFLEET_ACTOR must be valid UTF-8"));
    assert!(!stderr.contains("fallback-user"));
}
