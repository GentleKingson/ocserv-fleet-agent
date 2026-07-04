use base64::Engine;
use iroh::SecretKey;
use std::io;
use std::io::{Read, Write};
use std::path::Path;

use crate::private_file;

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("secret key io error: {0}")]
    Io(#[from] io::Error),
    #[error("secret key file must decode to 32 bytes")]
    InvalidLength,
    #[error("secret key permissions must be 0600 in production mode")]
    InvalidPermissions,
    #[error("secret key parent directory does not exist")]
    MissingParent,
}

pub fn load_or_create_secret_key(
    path: &Path,
    _production_mode: bool,
) -> Result<SecretKey, IdentityError> {
    match load_secret_key(path, true) {
        Ok(key) => return Ok(key),
        Err(IdentityError::Io(err)) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    let key = SecretKey::generate();
    let encoded = base64::engine::general_purpose::STANDARD.encode(key.to_bytes());
    match write_new_secret_key(path, &encoded) {
        Ok(()) => Ok(key),
        Err(IdentityError::Io(err)) if err.kind() == io::ErrorKind::AlreadyExists => {
            load_secret_key(path, true)
        }
        Err(err) => Err(err),
    }
}

fn load_secret_key(path: &Path, _production_mode: bool) -> Result<SecretKey, IdentityError> {
    let mut file = private_file::open_existing_private_read(path).map_err(map_private_io)?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|_| IdentityError::InvalidLength)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| IdentityError::InvalidLength)?;
    Ok(SecretKey::from_bytes(&bytes))
}

fn write_new_secret_key(path: &Path, encoded: &str) -> Result<(), IdentityError> {
    let mut file = private_file::open_private_create_new(path).map_err(map_private_io)?;
    file.write_all(encoded.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
pub fn secret_key_file_mode_is_private(path: &Path) -> Result<bool, IdentityError> {
    Ok(private_file::open_existing_private_read(path).is_ok())
}

#[cfg(not(unix))]
pub fn secret_key_file_mode_is_private(_path: &Path) -> Result<bool, IdentityError> {
    Ok(true)
}

fn map_private_io(err: io::Error) -> IdentityError {
    if err.kind() == io::ErrorKind::PermissionDenied || err.raw_os_error() == Some(libc::ELOOP) {
        IdentityError::InvalidPermissions
    } else {
        IdentityError::Io(err)
    }
}
