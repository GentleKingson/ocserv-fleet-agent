use serde_json::Value;
use std::str::FromStr;
use std::sync::{OnceLock, RwLock};

const MAX_ACTOR_LEN: usize = 128;
const MAX_REASON_LEN: usize = 256;
const MAX_DESCRIPTION_LEN: usize = 256;
const MAX_AGENT_VERSION_LEN: usize = 64;
const MAX_AGENT_PUBLIC_KEY_LEN: usize = 256;
const MAX_FINGERPRINT_LEN: usize = 128;
const MAX_HOSTNAME_LEN: usize = 253;
const MAX_SELECTOR_LEN: usize = 128;
const MAX_LABEL_ENTRIES: usize = 32;
const MAX_LABEL_KEY_LEN: usize = 64;
const MAX_LABEL_VALUE_LEN: usize = 128;

static PROCESS_ACTOR: OnceLock<RwLock<Option<String>>> = OnceLock::new();

fn process_actor_cell() -> &'static RwLock<Option<String>> {
    PROCESS_ACTOR.get_or_init(|| RwLock::new(None))
}

pub fn configure_process_actor(explicit_actor: Option<&str>) -> Result<String, String> {
    let actor = resolve_process_actor(explicit_actor)?;
    *process_actor_cell()
        .write()
        .expect("process actor lock poisoned") = Some(actor.clone());
    Ok(actor)
}

pub fn resolve_process_actor(explicit_actor: Option<&str>) -> Result<String, String> {
    if let Some(actor) = explicit_actor {
        return normalize_actor(actor).map_err(|err| format!("--actor {err}"));
    }
    if let Ok(actor) = std::env::var("OCFLEET_ACTOR") {
        return normalize_actor(&actor).map_err(|err| format!("OCFLEET_ACTOR {err}"));
    }
    Ok(local_user_actor())
}

pub fn local_actor() -> String {
    if let Some(actor) = process_actor_cell()
        .read()
        .expect("process actor lock poisoned")
        .clone()
    {
        return actor;
    }
    local_user_actor()
}

fn local_user_actor() -> String {
    match std::env::var("USER") {
        Ok(actor) => normalize_actor(&actor).unwrap_or_else(|_| "local-cli".to_string()),
        _ => "local-cli".to_string(),
    }
}

pub fn validate_actor(value: &str) -> Result<(), String> {
    validate_printable_text(value, "actor", MAX_ACTOR_LEN)
}

fn normalize_actor(value: &str) -> Result<String, String> {
    validate_actor(value)?;
    Ok(value.trim().to_string())
}

pub fn validate_reason(value: &str) -> Result<(), String> {
    validate_printable_text(value, "reason", MAX_REASON_LEN)
}

pub fn validate_description(value: &str) -> Result<(), String> {
    validate_printable_text(value, "description", MAX_DESCRIPTION_LEN)
}

pub fn validate_agent_version(value: &str) -> Result<(), String> {
    validate_printable_text(value, "agent_version", MAX_AGENT_VERSION_LEN)
}

pub fn validate_agent_public_key(value: &str) -> Result<(), String> {
    validate_printable_text(value, "agent_public_key", MAX_AGENT_PUBLIC_KEY_LEN)?;
    validate_no_ascii_whitespace(value.trim(), "agent_public_key")
}

pub fn validate_agent_fingerprint(value: &str) -> Result<(), String> {
    validate_printable_text(value, "fingerprint", MAX_FINGERPRINT_LEN)?;
    validate_no_ascii_whitespace(value.trim(), "fingerprint")
}

pub fn validate_selector(value: &str) -> Result<(), String> {
    validate_printable_text(value, "selector", MAX_SELECTOR_LEN)
}

pub fn validate_hostname(value: &str) -> Result<(), String> {
    validate_printable_text(value, "hostname", MAX_HOSTNAME_LEN)?;
    let hostname = value.trim();
    if hostname.starts_with('.') || hostname.ends_with('.') {
        return Err("hostname must not start or end with '.'".to_string());
    }
    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("hostname labels must be 1-63 characters".to_string());
        }
        let bytes = label.as_bytes();
        if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
            return Err("hostname labels must not start or end with '-'".to_string());
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return Err(
                "hostname labels may contain only ASCII letters, digits, and '-'".to_string(),
            );
        }
    }
    Ok(())
}

pub fn validate_endpoint_id(value: &str) -> Result<String, String> {
    let endpoint_id = value.trim();
    if endpoint_id.is_empty() {
        return Err("endpoint_id must not be empty".to_string());
    }
    iroh::EndpointId::from_str(endpoint_id)
        .map(|parsed| parsed.to_string())
        .map_err(|_| "endpoint_id must be a canonical iroh EndpointID".to_string())
}

pub fn validate_label_json(value: &Value, field: &'static str) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{field} must be a JSON object"))?;
    if object.len() > MAX_LABEL_ENTRIES {
        return Err(format!(
            "{field} must contain at most {MAX_LABEL_ENTRIES} entries"
        ));
    }
    for (key, value) in object {
        validate_label_key(key, field)?;
        match value {
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
            Value::String(text) => validate_printable_text(text, field, MAX_LABEL_VALUE_LEN)?,
            Value::Array(_) | Value::Object(_) => {
                return Err(format!("{field} values must be scalar"));
            }
        }
    }
    Ok(())
}

fn validate_label_key(value: &str, field: &'static str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_LABEL_KEY_LEN {
        return Err(format!(
            "{field} keys must be 1-{MAX_LABEL_KEY_LEN} characters"
        ));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(format!(
            "{field} keys may contain only ASCII letters, digits, '.', '_', and '-'"
        ));
    }
    Ok(())
}

fn validate_printable_text(value: &str, field: &'static str, max_len: usize) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if trimmed.len() > max_len {
        return Err(format!("{field} must be at most {max_len} bytes"));
    }
    if !trimmed
        .bytes()
        .all(|b| b == b' ' || (b.is_ascii_graphic() && b != 0x7f))
    {
        return Err(format!("{field} must contain only printable ASCII"));
    }
    Ok(())
}

fn validate_no_ascii_whitespace(value: &str, field: &'static str) -> Result<(), String> {
    if value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        Err(format!("{field} must not contain ASCII whitespace"))
    } else {
        Ok(())
    }
}
