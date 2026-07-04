use ocfleet_agent::identity::{load_or_create_secret_key, secret_key_file_mode_is_private};

#[test]
fn secret_key_is_created_and_reused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("iroh.secret");
    let first = load_or_create_secret_key(&path, false).expect("first key");
    let second = load_or_create_secret_key(&path, false).expect("second key");
    assert_eq!(first.to_bytes(), second.to_bytes());
}

#[cfg(unix)]
#[test]
fn secret_key_file_mode_is_private_after_create() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("iroh.secret");
    load_or_create_secret_key(&path, true).expect("key");
    assert!(secret_key_file_mode_is_private(&path).expect("mode check"));
}

#[test]
fn existing_invalid_secret_key_is_rejected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("iroh.secret");
    std::fs::write(&path, "not-base64\n").expect("write bad key");
    assert!(load_or_create_secret_key(&path, false).is_err());
}

#[test]
fn deleting_secret_key_changes_endpoint_identity() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("iroh.secret");
    let first = load_or_create_secret_key(&path, false).expect("first key");
    std::fs::remove_file(&path).expect("remove key");
    let second = load_or_create_secret_key(&path, false).expect("second key");
    assert_ne!(first.public(), second.public());
}
