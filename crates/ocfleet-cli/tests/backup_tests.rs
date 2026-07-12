use ocfleet_cli::backup::{create_backup, list_backups, verify_backup};
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
