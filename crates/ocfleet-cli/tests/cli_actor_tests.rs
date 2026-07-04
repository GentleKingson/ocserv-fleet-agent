use rusqlite::Connection;
use std::path::Path;
use std::process::Command;

fn run_init_with_user(database: &Path, secret_key: &Path, user: Option<&str>) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ocfleet"));
    command
        .arg("--database")
        .arg(database)
        .arg("--secret-key")
        .arg(secret_key)
        .arg("init");
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

#[test]
fn init_audit_actor_uses_non_blank_user() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret_key = dir.path().join("controller.secret");

    run_init_with_user(&database, &secret_key, Some("alice"));

    assert_eq!(latest_actor(&database), "alice");
}
