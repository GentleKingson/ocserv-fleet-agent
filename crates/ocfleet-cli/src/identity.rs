use base64::Engine;
use iroh::SecretKey;
use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;

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
    production_mode: bool,
) -> Result<SecretKey, IdentityError> {
    match load_secret_key(path, production_mode) {
        Ok(key) => return Ok(key),
        Err(IdentityError::Io(err)) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    let parent = path.parent().ok_or(IdentityError::MissingParent)?;
    fs::create_dir_all(parent)?;

    let key = SecretKey::generate();
    let encoded = base64::engine::general_purpose::STANDARD.encode(key.to_bytes());
    match write_new_secret_key(path, &encoded) {
        Ok(()) => Ok(key),
        Err(IdentityError::Io(err)) if err.kind() == io::ErrorKind::AlreadyExists => {
            load_secret_key(path, production_mode)
        }
        Err(err) => Err(err),
    }
}

fn load_secret_key(path: &Path, production_mode: bool) -> Result<SecretKey, IdentityError> {
    if production_mode && !secret_key_file_mode_is_private(path)? {
        return Err(IdentityError::InvalidPermissions);
    }

    let text = fs::read_to_string(path)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|_| IdentityError::InvalidLength)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| IdentityError::InvalidLength)?;
    Ok(SecretKey::from_bytes(&bytes))
}

fn write_new_secret_key(path: &Path, encoded: &str) -> Result<(), IdentityError> {
    let mut file = open_new_secret_file(path)?;
    file.write_all(encoded.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn open_new_secret_file(path: &Path) -> Result<fs::File, IdentityError> {
    use std::os::unix::fs::OpenOptionsExt;

    Ok(fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}

#[cfg(not(unix))]
fn open_new_secret_file(path: &Path) -> Result<fs::File, IdentityError> {
    Ok(fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?)
}

#[cfg(unix)]
pub fn secret_key_file_mode_is_private(path: &Path) -> Result<bool, IdentityError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    Ok(mode == 0o600)
}

#[cfg(not(unix))]
pub fn secret_key_file_mode_is_private(_path: &Path) -> Result<bool, IdentityError> {
    Ok(true)
}
