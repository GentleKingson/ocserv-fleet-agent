use ocfleet_cli::backup::{
    apply_restore, create_backup, list_backups, plan_restore, verify_backup,
};
use ocfleet_cli::identity::load_or_create_secret_key;
use ocfleet_cli::store::{CURRENT_SCHEMA_VERSION, Store};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[test]
#[cfg(unix)]
fn backup_create_list_verify_and_detect_corruption() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret = dir.path().join("controller.secret");
    let backup_dir = dir.path().join("backups");
    fs::create_dir(&backup_dir).expect("create backup dir");
    fs::set_permissions(&backup_dir, fs::Permissions::from_mode(0o700)).expect("chmod backup dir");
    let controller_key = load_or_create_secret_key(&secret, true).expect("create identity");
    drop(Store::open(&database).expect("create database"));
    rusqlite::Connection::open(&database)
        .expect("open database")
        .execute_batch(
            "CREATE TABLE backup_probe(value TEXT); INSERT INTO backup_probe VALUES ('durable');",
        )
        .expect("seed backup probe");

    let manifest = create_backup(&database, &secret, &backup_dir, None).expect("create backup");
    assert_eq!(manifest.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(
        manifest.expected_controller_endpoint_id,
        controller_key.public().to_string()
    );
    let manifest_path = backup_dir.join(format!("{}.manifest.json", manifest.backup_id));
    let verification = verify_backup(&manifest_path).expect("verify backup");
    assert!(verification.checksum_ok);
    assert!(verification.integrity_ok);
    assert!(!verification.signature_present);
    assert_eq!(
        list_backups(&backup_dir).expect("list backups"),
        vec![manifest.clone()]
    );

    let database_path = backup_dir.join(&manifest.database_file);
    let mut bytes = fs::read(&database_path).expect("read backup");
    let last = bytes.last_mut().expect("non-empty backup");
    *last ^= 0xff;
    fs::write(&database_path, bytes).expect("corrupt backup");
    assert!(
        verify_backup(&manifest_path)
            .expect_err("corruption must fail")
            .to_string()
            .contains("checksum")
    );
}

#[test]
#[cfg(unix)]
fn backup_optional_signature_is_verified_and_manifest_rejects_tampering() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret = dir.path().join("controller.secret");
    let signing_key = dir.path().join("backup-signing.pk8");
    let backup_dir = dir.path().join("backups");
    fs::create_dir(&backup_dir).expect("create backup dir");
    fs::set_permissions(&backup_dir, fs::Permissions::from_mode(0o700)).expect("chmod backup dir");
    load_or_create_secret_key(&secret, true).expect("create identity");
    drop(Store::open(&database).expect("create database"));
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate signing key");
    fs::write(&signing_key, key.as_ref()).expect("write signing key");
    fs::set_permissions(&signing_key, fs::Permissions::from_mode(0o600))
        .expect("chmod signing key");

    let manifest = create_backup(&database, &secret, &backup_dir, Some(&signing_key))
        .expect("create signed backup");
    let manifest_path = backup_dir.join(format!("{}.manifest.json", manifest.backup_id));
    let verification = verify_backup(&manifest_path).expect("verify signed backup");
    assert_eq!(verification.signature_ok, Some(true));

    let text = fs::read_to_string(&manifest_path).expect("read manifest");
    fs::write(
        &manifest_path,
        text.replace(
            "\"application_version\":",
            "\"application_version\": \"tampered\", \"ignored\":",
        ),
    )
    .expect("tamper manifest");
    assert!(verify_backup(&manifest_path).is_err());
}

#[test]
#[cfg(unix)]
fn backup_rejects_unsafe_output_directory() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret = dir.path().join("controller.secret");
    let backup_dir = dir.path().join("backups");
    fs::create_dir(&backup_dir).expect("create backup dir");
    fs::set_permissions(&backup_dir, fs::Permissions::from_mode(0o755)).expect("chmod backup dir");
    load_or_create_secret_key(&secret, true).expect("create identity");
    drop(Store::open(&database).expect("create database"));

    assert!(
        create_backup(&database, &secret, &backup_dir, None)
            .expect_err("unsafe directory must fail")
            .to_string()
            .contains("mode 0700")
    );
}

#[test]
#[cfg(unix)]
fn restore_plan_is_read_only_and_apply_runs_a_prebacked_restore_drill() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod temp dir");
    let database = dir.path().join("controller.sqlite");
    let secret = dir.path().join("controller.secret");
    let wrong_secret = dir.path().join("wrong.secret");
    let backup_dir = dir.path().join("backups");
    fs::create_dir(&backup_dir).expect("create backup dir");
    fs::set_permissions(&backup_dir, fs::Permissions::from_mode(0o700)).expect("chmod backup dir");
    load_or_create_secret_key(&secret, true).expect("create identity");
    load_or_create_secret_key(&wrong_secret, true).expect("create wrong identity");
    drop(Store::open(&database).expect("create database"));
    let conn = rusqlite::Connection::open(&database).expect("open database");
    conn.execute_batch(
        "CREATE TABLE restore_probe(value TEXT); INSERT INTO restore_probe VALUES ('backup');",
    )
    .expect("seed backup state");
    drop(conn);
    let manifest = create_backup(&database, &secret, &backup_dir, None).expect("create backup");
    let manifest_path = backup_dir.join(format!("{}.manifest.json", manifest.backup_id));
    let conn = rusqlite::Connection::open(&database).expect("open live database");
    conn.execute("UPDATE restore_probe SET value = 'live'", [])
        .expect("mutate live state");
    drop(conn);
    let before_plan = fs::read(&database).expect("read before plan");

    let plan = plan_restore(&database, &secret, &manifest_path).expect("plan restore");
    assert!(plan.identity_match);
    assert!(plan.target_exists);
    assert!(plan.will_prebackup_existing);
    assert_eq!(fs::read(&database).expect("read after plan"), before_plan);
    assert!(
        !plan_restore(&database, &wrong_secret, &manifest_path)
            .expect("plan mismatch")
            .identity_match
    );
    assert!(apply_restore(&database, &secret, &manifest_path, false).is_err());
    assert!(apply_restore(&database, &wrong_secret, &manifest_path, true).is_err());

    let wal = std::path::PathBuf::from(format!("{}-wal", database.to_string_lossy()));
    let shm = std::path::PathBuf::from(format!("{}-shm", database.to_string_lossy()));
    fs::write(&wal, []).expect("create stale wal");
    fs::write(&shm, []).expect("create stale shm");
    fs::set_permissions(&wal, fs::Permissions::from_mode(0o600)).expect("chmod wal");
    fs::set_permissions(&shm, fs::Permissions::from_mode(0o600)).expect("chmod shm");

    let result = apply_restore(&database, &secret, &manifest_path, true).expect("apply restore");
    assert!(result.identity_match);
    assert!(result.removed_stale_wal);
    assert!(result.removed_stale_shm);
    let value: String = rusqlite::Connection::open(&database)
        .expect("open restored database")
        .query_row("SELECT value FROM restore_probe", [], |row| row.get(0))
        .expect("read restored value");
    assert_eq!(value, "backup");
    assert_eq!(
        rusqlite::Connection::open(&database)
            .expect("open restored audit")
            .query_row(
                "SELECT count(*) FROM controller_audit_log WHERE event = 'controller.restore.apply'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("read restore audit"),
        1
    );
    let prebackup = result.prebackup_manifest.expect("prebackup manifest");
    let prebackup_verification =
        verify_backup(std::path::Path::new(&prebackup)).expect("verify automatic prebackup");
    let prebackup_value: String = rusqlite::Connection::open(
        std::path::Path::new(&prebackup)
            .parent()
            .expect("prebackup parent")
            .join(&prebackup_verification.manifest.database_file),
    )
    .expect("open prebackup")
    .query_row("SELECT value FROM restore_probe", [], |row| row.get(0))
    .expect("read prebackup value");
    assert_eq!(prebackup_value, "live");
}
