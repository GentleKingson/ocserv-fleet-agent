use std::path::Path;

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("{field} must be {min}-{max} characters and contain only {pattern}")]
    InvalidSafeString {
        field: &'static str,
        min: usize,
        max: usize,
        pattern: &'static str,
    },
    #[error("service_name contains unsupported characters")]
    InvalidServiceName,
    #[error("{field} must not be empty")]
    EmptyPath { field: &'static str },
    #[error("{field} must be non-empty and contain no ASCII whitespace")]
    InvalidEndpointId { field: &'static str },
    #[error("controller role must be viewer")]
    InvalidControllerRole,
    #[error("{field} must be greater than zero")]
    NonPositiveNumber { field: &'static str },
}

fn validate_safe(
    value: &str,
    field: &'static str,
    min: usize,
    max: usize,
) -> Result<(), ValidationError> {
    let ok_len = value.len() >= min && value.len() <= max;
    let ok_chars = value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok_len && ok_chars {
        Ok(())
    } else {
        Err(ValidationError::InvalidSafeString {
            field,
            min,
            max,
            pattern: "[a-zA-Z0-9._-]",
        })
    }
}

pub fn validate_node_id(value: &str) -> Result<(), ValidationError> {
    validate_safe(value, "node_id", 1, 64)
}

pub fn validate_region(value: &str) -> Result<(), ValidationError> {
    validate_safe(value, "region", 1, 32)
}

pub fn validate_role(value: &str) -> Result<(), ValidationError> {
    if value == "ocserv" {
        Ok(())
    } else {
        Err(ValidationError::InvalidSafeString {
            field: "role",
            min: 6,
            max: 6,
            pattern: "ocserv",
        })
    }
}

pub fn validate_service_name(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > 128 {
        return Err(ValidationError::InvalidServiceName);
    }
    let ok = value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@'));
    if ok {
        Ok(())
    } else {
        Err(ValidationError::InvalidServiceName)
    }
}

pub fn validate_non_empty_path(
    path: &Path,
    field: &'static str,
) -> Result<(), ValidationError> {
    if path.as_os_str().is_empty() {
        Err(ValidationError::EmptyPath { field })
    } else {
        Ok(())
    }
}

pub fn validate_controller_endpoint_id(value: &str) -> Result<(), ValidationError> {
    if !value.is_empty() && !value.bytes().any(|b| b.is_ascii_whitespace()) {
        Ok(())
    } else {
        Err(ValidationError::InvalidEndpointId {
            field: "controller endpoint_id",
        })
    }
}

pub fn validate_controller_role(value: &str) -> Result<(), ValidationError> {
    if value == "viewer" {
        Ok(())
    } else {
        Err(ValidationError::InvalidControllerRole)
    }
}

pub fn validate_positive_i64(
    value: i64,
    field: &'static str,
) -> Result<(), ValidationError> {
    if value > 0 {
        Ok(())
    } else {
        Err(ValidationError::NonPositiveNumber { field })
    }
}

pub fn validate_positive_u64(
    value: u64,
    field: &'static str,
) -> Result<(), ValidationError> {
    if value > 0 {
        Ok(())
    } else {
        Err(ValidationError::NonPositiveNumber { field })
    }
}

pub fn validate_positive_usize(
    value: usize,
    field: &'static str,
) -> Result<(), ValidationError> {
    if value > 0 {
        Ok(())
    } else {
        Err(ValidationError::NonPositiveNumber { field })
    }
}
