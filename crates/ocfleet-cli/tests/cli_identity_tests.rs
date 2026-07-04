use ocfleet_cli::identity::{
    IdentityError, load_or_create_secret_key, load_or_create_secret_key_with_status,
};
use std::path::Path;
use std::sync::{Mutex, OnceLock};

fn cwd_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct CurrentDirGuard {
    original: std::path::PathBuf,
}

impl CurrentDirGuard {
    fn enter(path: &Path) -> Self {
        let original = std::env::current_dir().expect("current dir");
        std::env::set_current_dir(path).expect("set current dir");
        Self { original }
    }
}

impl Drop for CurrentDirGuard {
    fn drop(&mut self) {
        std::env::set_current_dir(&self.original).expect("restore current dir");
    }
}

#[test]
fn load_or_create_secret_key_supports_single_file_relative_path() {
    let _guard = cwd_lock().lock().expect("cwd lock");
    let dir = tempfile::tempdir().expect("temp dir");
    let _cwd = CurrentDirGuard::enter(dir.path());
    let path = Path::new("controller.secret");

    let first = load_or_create_secret_key(path, false).expect("create relative key");
    let second = load_or_create_secret_key(path, false).expect("reuse relative key");

    assert_eq!(first.to_bytes(), second.to_bytes());
    assert!(dir.path().join(path).is_file());
}

#[test]
fn load_or_create_secret_key_with_status_reports_actual_creation() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("controller.secret");

    let first =
        load_or_create_secret_key_with_status(&path, false).expect("create key with status");
    let second =
        load_or_create_secret_key_with_status(&path, false).expect("reuse key with status");

    assert!(first.created);
    assert!(!second.created);
    assert_eq!(first.secret_key.to_bytes(), second.secret_key.to_bytes());
}

#[cfg(unix)]
#[test]
fn controller_secret_key_rejects_existing_group_or_world_accessible_file() {
    use base64::Engine;
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("controller.secret");
    let key = iroh::SecretKey::generate();
    let encoded = base64::engine::general_purpose::STANDARD.encode(key.to_bytes());
    std::fs::write(&path, format!("{encoded}\n")).expect("write key");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

    let err = load_or_create_secret_key(&path, false).expect_err("unsafe key should fail");

    assert!(matches!(err, IdentityError::InvalidPermissions));
}

#[cfg(unix)]
#[test]
fn controller_secret_key_rejects_final_path_symlink() {
    let dir = tempfile::tempdir().expect("temp dir");
    let real_path = dir.path().join("real.secret");
    let link_path = dir.path().join("controller.secret");
    load_or_create_secret_key(&real_path, false).expect("create real key");
    std::os::unix::fs::symlink(&real_path, &link_path).expect("symlink");

    let err = load_or_create_secret_key(&link_path, false).expect_err("symlink should fail");

    assert!(matches!(err, IdentityError::InvalidPermissions));
}

#[cfg(unix)]
#[test]
fn controller_secret_key_creates_nested_parent_directories_private_under_permissive_umask() {
    use std::os::unix::fs::PermissionsExt;

    struct UmaskGuard(libc::mode_t);

    impl Drop for UmaskGuard {
        fn drop(&mut self) {
            unsafe {
                libc::umask(self.0);
            }
        }
    }

    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir
        .path()
        .join("state")
        .join("keys")
        .join("controller.secret");
    let old_umask = unsafe { libc::umask(0) };
    let _guard = UmaskGuard(old_umask);

    load_or_create_secret_key(&path, false).expect("create nested key");

    for component in [
        dir.path().join("state"),
        dir.path().join("state").join("keys"),
    ] {
        let mode = std::fs::metadata(&component)
            .expect("directory metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }
}
