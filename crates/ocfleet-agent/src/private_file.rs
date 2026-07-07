use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

pub fn open_private_append(path: &Path) -> io::Result<File> {
    open_private_append_impl(path)
}

pub fn open_private_create_new(path: &Path) -> io::Result<File> {
    open_private_create_new_impl(path)
}

pub fn open_existing_private_read(path: &Path) -> io::Result<File> {
    open_existing_private_read_impl(path)
}

pub fn write_private_replace(path: &Path, payload: &[u8]) -> io::Result<()> {
    write_private_replace_impl(path, payload)
}

#[cfg(unix)]
fn open_private_append_impl(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    ensure_private_parent(path)?;
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    validate_private_file_handle(&file)?;
    Ok(file)
}

#[cfg(unix)]
fn open_private_create_new_impl(path: &Path) -> io::Result<File> {
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
fn open_existing_private_read_impl(path: &Path) -> io::Result<File> {
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
fn write_private_replace_impl(path: &Path, payload: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    ensure_private_parent(path)?;
    match open_existing_private_read(path) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing file name"))?
        .to_string_lossy();

    let mut last_error = None;
    for attempt in 0..100 {
        let tmp_path = parent.join(format!(".{file_name}.tmp-{}-{attempt}", std::process::id()));
        let mut file = match fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp_path)
        {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                last_error = Some(err);
                continue;
            }
            Err(err) => return Err(err),
        };
        let result = (|| {
            validate_private_file_handle(&file)?;
            file.write_all(payload)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&tmp_path, path)?;
            if let Ok(directory) = File::open(parent) {
                let _ = directory.sync_all();
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }
        return result;
    }

    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate private replacement temp file",
        )
    }))
}

#[cfg(unix)]
fn ensure_private_parent(path: &Path) -> io::Result<()> {
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(());
    };
    ensure_private_directory(parent)
}

#[cfg(unix)]
fn ensure_private_directory(directory: &Path) -> io::Result<()> {
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
fn create_private_directory(directory: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(directory) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(err),
    }
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(unix)]
fn validate_private_parent(parent: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(parent)?;
    let current_euid = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != current_euid || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe private parent permissions",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_parent_for_existing_file(path: &Path) -> io::Result<()> {
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(());
    };
    if !parent.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "missing private parent directory",
        ));
    }
    validate_private_parent(parent)
}

#[cfg(unix)]
fn validate_private_file_handle(file: &File) -> io::Result<()> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;

    let mut stat = MaybeUninit::<libc::stat>::uninit();
    let result = unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    let current_euid = unsafe { libc::geteuid() };
    let file_type = stat.st_mode & libc::S_IFMT;
    if file_type != libc::S_IFREG || stat.st_uid != current_euid || stat.st_mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe private file permissions",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn open_private_append_impl(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    fs::OpenOptions::new().create(true).append(true).open(path)
}

#[cfg(not(unix))]
fn open_private_create_new_impl(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(not(unix))]
fn open_existing_private_read_impl(path: &Path) -> io::Result<File> {
    fs::OpenOptions::new().read(true).open(path)
}

#[cfg(not(unix))]
fn write_private_replace_impl(path: &Path, payload: &[u8]) -> io::Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    file.write_all(payload)?;
    file.sync_all()?;
    Ok(())
}
