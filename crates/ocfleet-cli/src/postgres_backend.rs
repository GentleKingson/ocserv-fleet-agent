use std::fmt;
use std::path::PathBuf;

use crate::backend::BackendKind;

/// Compile-time scaffold only. No Postgres connection, migration, import, or
/// write path exists in this release.
#[derive(Clone, PartialEq, Eq)]
pub enum PostgresConnectionSource {
    Environment { variable: String },
    PrivateConfigFile { path: PathBuf },
}

impl PostgresConnectionSource {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Environment { variable }
                if variable == "OCFLEET_POSTGRES_URL"
                    || variable == "OCFLEET_TEST_POSTGRES_URL" =>
            {
                Ok(())
            }
            Self::PrivateConfigFile { path } if path.is_absolute() => Ok(()),
            Self::Environment { .. } => Err("unsupported Postgres environment variable"),
            Self::PrivateConfigFile { .. } => Err("Postgres private config path must be absolute"),
        }
    }

    pub const fn backend_kind(&self) -> BackendKind {
        BackendKind::PostgresPlanned
    }
}

impl fmt::Debug for PostgresConnectionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Environment { variable } => {
                let display = match variable.as_str() {
                    "OCFLEET_POSTGRES_URL" | "OCFLEET_TEST_POSTGRES_URL" => variable.as_str(),
                    _ => "<redacted-invalid>",
                };
                f.debug_struct("Environment")
                    .field("variable", &display)
                    .finish()
            }
            Self::PrivateConfigFile { .. } => f
                .debug_struct("PrivateConfigFile")
                .field("path", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("Postgres backend is scaffolding only; no runtime connection path is implemented")]
pub struct PostgresBackendUnavailable;

pub fn connect(source: &PostgresConnectionSource) -> Result<(), PostgresBackendUnavailable> {
    let _ = source;
    Err(PostgresBackendUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaffold_never_logs_private_config_path_or_connects() {
        let source = PostgresConnectionSource::PrivateConfigFile {
            path: PathBuf::from("/run/secrets/ocfleet-postgres.toml"),
        };
        assert!(source.validate().is_ok());
        let debug = format!("{source:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("/run/secrets"));
        assert_eq!(connect(&source), Err(PostgresBackendUnavailable));
    }

    #[test]
    fn invalid_environment_source_is_redacted_before_validation() {
        let source = PostgresConnectionSource::Environment {
            variable: "postgres://operator:secret@db.example/ocfleet".to_string(),
        };
        assert!(source.validate().is_err());
        let debug = format!("{source:?}");
        assert!(debug.contains("<redacted-invalid>"));
        assert!(!debug.contains("operator"));
        assert!(!debug.contains("secret"));
    }
}
