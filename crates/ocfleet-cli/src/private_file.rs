#[cfg(unix)]
use std::fs;
use std::fs::File;
use std::io;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum PrivateFileError {
    #[error("private file io error: {0}")]
    Io(#[from] io::Error),
    #[error("private file parent directory does not exist")]
    MissingParent,
    #[error("private file parent directory permissions are unsafe")]
    UnsafeParent,
    #[error("private file permissions are unsafe")]
    UnsafeFile,
    #[error("private file protection is unsupported on this platform")]
    UnsupportedPlatform,
}

pub fn open_private_create_new(path: &Path) -> Result<File, PrivateFileError> {
    open_private_create_new_impl(path)
}

pub fn open_existing_private_read(path: &Path) -> Result<File, PrivateFileError> {
    open_existing_private_read_impl(path)
}

pub fn validate_existing_private_file(path: &Path) -> Result<(), PrivateFileError> {
    let _file = open_existing_private_read(path)?;
    Ok(())
}

#[cfg(unix)]
fn open_private_create_new_impl(path: &Path) -> Result<File, PrivateFileError> {
    use std::os::unix::fs::OpenOptionsExt;

    ensure_private_parent(path)?;
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    validate_private_file_handle(&file)?;
    Ok(file)
}

#[cfg(unix)]
fn open_existing_private_read_impl(path: &Path) -> Result<File, PrivateFileError> {
    use std::os::unix::fs::OpenOptionsExt;

    validate_parent_for_existing_file(path)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    validate_private_file_handle(&file)?;
    Ok(file)
}

#[cfg(unix)]
pub fn ensure_private_parent(path: &Path) -> Result<(), PrivateFileError> {
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return ensure_private_directory(Path::new("."));
    };
    ensure_private_directory(parent)
}

#[cfg(unix)]
fn ensure_private_directory(directory: &Path) -> Result<(), PrivateFileError> {
    let mut missing = Vec::new();
    let mut cursor = directory.to_path_buf();
    while !cursor.exists() {
        missing.push(cursor.clone());
        cursor = cursor
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
    }

    validate_private_parent(&cursor)?;
    for component in missing.iter().rev() {
        create_private_directory(component)?;
        validate_private_parent(component)?;
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_directory(directory: &Path) -> Result<(), PrivateFileError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(directory) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(PrivateFileError::Io(err)),
    }
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(unix)]
fn validate_parent_for_existing_file(path: &Path) -> Result<(), PrivateFileError> {
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return validate_private_parent(Path::new("."));
    };
    if !parent.exists() {
        return Err(PrivateFileError::MissingParent);
    }
    validate_private_parent(parent)
}

#[cfg(unix)]
fn validate_private_parent(parent: &Path) -> Result<(), PrivateFileError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(parent)?;
    let current_euid = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != current_euid || metadata.mode() & 0o022 != 0 {
        return Err(PrivateFileError::UnsafeParent);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_file_handle(file: &File) -> Result<(), PrivateFileError> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;

    let mut stat = MaybeUninit::<libc::stat>::uninit();
    let result = unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(PrivateFileError::Io(io::Error::last_os_error()));
    }
    let stat = unsafe { stat.assume_init() };
    let current_euid = unsafe { libc::geteuid() };
    let file_type = stat.st_mode & libc::S_IFMT;
    if file_type != libc::S_IFREG || stat.st_uid != current_euid || stat.st_mode & 0o077 != 0 {
        return Err(PrivateFileError::UnsafeFile);
    }
    Ok(())
}

#[cfg(not(unix))]
fn open_private_create_new_impl(path: &Path) -> Result<File, PrivateFileError> {
    let _ = path;
    Err(PrivateFileError::UnsupportedPlatform)
}

#[cfg(not(unix))]
fn open_existing_private_read_impl(path: &Path) -> Result<File, PrivateFileError> {
    let _ = path;
    Err(PrivateFileError::UnsupportedPlatform)
}
