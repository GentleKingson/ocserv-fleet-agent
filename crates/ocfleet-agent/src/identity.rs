use base64::Engine;
use iroh::SecretKey;
use std::fs;
use std::io;
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
    if path.exists() {
        if production_mode && !secret_key_file_mode_is_private(path)? {
            return Err(IdentityError::InvalidPermissions);
        }

        let text = fs::read_to_string(path)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(text.trim())
            .map_err(|_| IdentityError::InvalidLength)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| IdentityError::InvalidLength)?;
        return Ok(SecretKey::from_bytes(&bytes));
    }

    let parent = path.parent().ok_or(IdentityError::MissingParent)?;
    fs::create_dir_all(parent)?;

    let key = SecretKey::generate();
    let encoded = base64::engine::general_purpose::STANDARD.encode(key.to_bytes());
    fs::write(path, format!("{encoded}\n"))?;
    set_private_file_mode(path)?;

    Ok(key)
}

#[cfg(unix)]
fn set_private_file_mode(path: &Path) -> Result<(), IdentityError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file_mode(_path: &Path) -> Result<(), IdentityError> {
    Ok(())
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
