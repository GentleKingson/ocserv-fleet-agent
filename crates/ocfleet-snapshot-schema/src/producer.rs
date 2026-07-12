use crate::{SnapshotDocument, ValidationError, validate};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum ProducerError {
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error("snapshot output path is unsafe")]
    UnsafePath,
    #[error("snapshot output failed")]
    Io(#[from] std::io::Error),
    #[error("snapshot serialization failed")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct SnapshotProducer {
    output: PathBuf,
}

impl SnapshotProducer {
    pub fn new(output: impl Into<PathBuf>) -> Result<Self, ProducerError> {
        let producer = Self {
            output: output.into(),
        };
        validate_output_path(&producer.output)?;
        Ok(producer)
    }
    pub fn publish(&self, document: &SnapshotDocument) -> Result<(), ProducerError> {
        validate(document)?;
        validate_output_path(&self.output)?;
        let payload = serde_json::to_vec_pretty(document)?;
        let parent = self.output.parent().ok_or(ProducerError::UnsafePath)?;
        let temp = parent.join(format!(".ocfleet-snapshot-{}.tmp", Uuid::new_v4()));
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temp)?;
            file.write_all(&payload)?;
            file.sync_all()?;
            fs::rename(&temp, &self.output)?;
            sync_parent(parent)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}

fn validate_output_path(path: &Path) -> Result<(), ProducerError> {
    if !path.is_absolute() {
        return Err(ProducerError::UnsafePath);
    }
    let parent = path.parent().ok_or(ProducerError::UnsafePath)?;
    let meta = fs::symlink_metadata(parent).map_err(|_| ProducerError::UnsafePath)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(ProducerError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err(ProducerError::UnsafePath);
        }
    }
    if let Ok(meta) = fs::symlink_metadata(path) {
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err(ProducerError::UnsafePath);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.nlink() != 1 {
                return Err(ProducerError::UnsafePath);
            }
        }
    }
    Ok(())
}
fn sync_parent(parent: &Path) -> Result<(), std::io::Error> {
    OpenOptions::new().read(true).open(parent)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SCHEMA_VERSION_V2;
    use ocfleet_protocol::ocserv::{
        OcservCollectorStatus, OcservServiceEnabledState, OcservServiceState,
    };
    fn doc() -> SnapshotDocument {
        SnapshotDocument {
            schema_version: SCHEMA_VERSION_V2.into(),
            collected_at: "2026-07-12T00:00:00Z".into(),
            collector_status: OcservCollectorStatus::Ok,
            service_state: OcservServiceState::Running,
            enabled_state: OcservServiceEnabledState::Enabled,
            version: None,
            session_total: Some(1),
            auth_failure_count_rolling: None,
            connection_failure_count_rolling: None,
            cert_min_days_remaining: None,
            config_fingerprint_short: None,
        }
    }
    #[test]
    fn private_atomic_publish_and_unsafe_paths() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = dir.path().join("snapshot.json");
        SnapshotProducer::new(&path)
            .unwrap()
            .publish(&doc())
            .unwrap();
        crate::validate_file(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(SnapshotProducer::new("relative.json").is_err());
    }
}
