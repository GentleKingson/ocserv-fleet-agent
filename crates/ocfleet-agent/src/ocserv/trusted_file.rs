use std::path::Path;

use ocfleet_protocol::error::ErrorCode;

use crate::ocserv::OcservReadonlyError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PermissionPolicy {
    Private,
    TrustedReadable,
}

pub(crate) fn read_bounded_trusted_file(
    path: &Path,
    max_bytes: u64,
    permission_policy: PermissionPolicy,
    unavailable_message: &'static str,
    unsafe_message: &'static str,
    too_large_message: &'static str,
) -> Result<Vec<u8>, OcservReadonlyError> {
    read_bounded_trusted_file_impl(
        path,
        max_bytes,
        permission_policy,
        unavailable_message,
        unsafe_message,
        too_large_message,
    )
}

#[cfg(unix)]
fn read_bounded_trusted_file_impl(
    path: &Path,
    max_bytes: u64,
    permission_policy: PermissionPolicy,
    unavailable_message: &'static str,
    unsafe_message: &'static str,
    too_large_message: &'static str,
) -> Result<Vec<u8>, OcservReadonlyError> {
    use std::io::Read;
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| {
            OcservReadonlyError::new(ErrorCode::OcservProviderUnavailable, unavailable_message)
        })?;

    let mut stat = MaybeUninit::<libc::stat>::uninit();
    let result = unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(OcservReadonlyError::new(
            ErrorCode::OcservProviderUnavailable,
            unavailable_message,
        ));
    }
    let stat = unsafe { stat.assume_init() };
    if !trusted_file_metadata(&stat, permission_policy) {
        return Err(OcservReadonlyError::new(
            ErrorCode::OcservProviderUnsafeSource,
            unsafe_message,
        ));
    }
    if stat.st_size < 0 || stat.st_size as u64 > max_bytes {
        return Err(OcservReadonlyError::new(
            ErrorCode::OcservOutputBoundExceeded,
            too_large_message,
        ));
    }

    let mut bytes = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            OcservReadonlyError::new(ErrorCode::OcservProviderUnavailable, unavailable_message)
        })?;
    if bytes.len() as u64 > max_bytes {
        return Err(OcservReadonlyError::new(
            ErrorCode::OcservOutputBoundExceeded,
            too_large_message,
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn trusted_file_metadata(stat: &libc::stat, permission_policy: PermissionPolicy) -> bool {
    let current_euid = unsafe { libc::geteuid() };
    let file_type = stat.st_mode & libc::S_IFMT;
    let unsafe_mode_bits = match permission_policy {
        PermissionPolicy::Private => 0o077,
        PermissionPolicy::TrustedReadable => 0o022,
    };
    file_type == libc::S_IFREG
        && (stat.st_uid == 0 || stat.st_uid == current_euid)
        && stat.st_nlink == 1
        && stat.st_mode & unsafe_mode_bits == 0
}

#[cfg(not(unix))]
fn read_bounded_trusted_file_impl(
    _path: &Path,
    _max_bytes: u64,
    _permission_policy: PermissionPolicy,
    _unavailable_message: &'static str,
    unsafe_message: &'static str,
    _too_large_message: &'static str,
) -> Result<Vec<u8>, OcservReadonlyError> {
    Err(OcservReadonlyError::new(
        ErrorCode::OcservProviderUnsafeSource,
        unsafe_message,
    ))
}
