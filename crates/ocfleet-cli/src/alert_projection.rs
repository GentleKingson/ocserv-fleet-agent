use ocfleet_protocol::method::{
    OCSERV_CERT_EXPIRY, OCSERV_CONFIG_FINGERPRINT, OCSERV_SERVICE_SUMMARY, OCSERV_SESSIONS_SUMMARY,
    OCSERV_VERSION, PROBE_CONTROLLER_PING, PROBE_PATH_ECHO,
};
use serde_json::{Map, Value};

const MAX_ALERT_METHODS: usize = 8;
const MAX_SUMMARY_STRING_BYTES: usize = 128;

pub fn methods_from_detail(detail: &Value) -> Vec<String> {
    detail
        .get("methods")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|method| is_allowed_alert_method(method))
        .take(MAX_ALERT_METHODS)
        .map(str::to_string)
        .collect()
}

pub fn summary_from_detail(detail: &Value) -> Value {
    detail
        .get("summary")
        .map(project_summary)
        .unwrap_or_else(|| Value::Object(Map::new()))
}

pub fn project_summary(value: &Value) -> Value {
    let Value::Object(map) = value else {
        return Value::Object(Map::new());
    };
    let mut output = Map::new();
    for (key, value) in map {
        if let Some(value) = project_summary_field(key, value) {
            output.insert(key.clone(), value);
        }
    }
    Value::Object(output)
}

fn project_summary_field(key: &str, value: &Value) -> Option<Value> {
    match key {
        "freshness_seconds" | "consecutive_failures" => value
            .as_u64()
            .filter(|value| *value <= u32::MAX.into())
            .map(Value::from),
        "days_remaining" => value
            .as_i64()
            .filter(|value| (-365_000..=365_000).contains(value))
            .map(Value::from),
        "endpoint_id" => value
            .as_str()
            .and_then(|value| crate::input_validation::validate_endpoint_id(value).ok())
            .map(Value::String),
        "status" | "last_error_code" | "endpoint_status" | "result_class" => value
            .as_str()
            .filter(|value| is_bounded_safe_token(value))
            .map(|value| Value::String(value.to_string())),
        _ => None,
    }
}

fn is_allowed_alert_method(method: &str) -> bool {
    matches!(
        method,
        PROBE_CONTROLLER_PING
            | PROBE_PATH_ECHO
            | OCSERV_SERVICE_SUMMARY
            | OCSERV_VERSION
            | OCSERV_SESSIONS_SUMMARY
            | OCSERV_CERT_EXPIRY
            | OCSERV_CONFIG_FINGERPRINT
    )
}

fn is_bounded_safe_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SUMMARY_STRING_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn projections_drop_unrecognized_methods_and_unbounded_summary_values() {
        let detail = json!({
            "methods": [PROBE_CONTROLLER_PING, "shell.exec", "/etc/secret"],
            "summary": {
                "status": "stale",
                "last_error_code": "RPC_TIMEOUT",
                "result_class": "x".repeat(MAX_SUMMARY_STRING_BYTES + 1),
                "path": "/etc/ocserv.conf",
                "nested": {"username": "alice"}
            }
        });

        assert_eq!(methods_from_detail(&detail), vec![PROBE_CONTROLLER_PING]);
        assert_eq!(
            summary_from_detail(&detail),
            json!({"status": "stale", "last_error_code": "RPC_TIMEOUT"})
        );
    }
}
