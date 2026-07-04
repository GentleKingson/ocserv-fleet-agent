use ocfleet_cli::identity::{
    load_or_create_secret_key, load_or_create_secret_key_with_status,
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
