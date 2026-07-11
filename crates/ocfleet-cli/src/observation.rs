use anyhow::{Context, bail};
use ocfleet_config::validation::validate_node_id;
use serde_json::{Map, Value, json};

use crate::args::ObservationCommand;
use crate::input_validation::validate_selector;
use crate::storage_payloads::ObservationSummaryPayloadV1;
use crate::store::{ProbeObservationRecord, Store};

pub const MAX_OBSERVATION_QUERY_LIMIT: u64 = 1_000;

pub fn run_observation_command(store: &Store, command: ObservationCommand) -> anyhow::Result<()> {
    match command {
        ObservationCommand::List {
            node,
            method,
            limit,
            json,
        } => run_observation_list(store, node.as_deref(), method.as_deref(), limit, json),
        ObservationCommand::Show {
            observation_id,
            json,
        } => run_observation_show(store, &observation_id, json),
    }
}

fn run_observation_list(
    store: &Store,
    node: Option<&str>,
    method: Option<&str>,
    limit: u64,
    json_output: bool,
) -> anyhow::Result<()> {
    let limit = validate_limit(limit)?;
    if let Some(node) = node {
        validate_node_id(node)?;
    }
    if let Some(method) = method {
        validate_method_filter(method)?;
    }
    let observations = store.list_probe_observations_filtered(node, method, limit)?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "limit": limit,
                "node_filter": node,
                "method_filter": method,
                "observation_count": observations.len(),
                "observations": observations.iter().map(observation_to_json).collect::<Vec<_>>(),
            }))?
        );
    } else {
        println!("limit={limit}");
        println!("node_filter={}", node.unwrap_or("<all>"));
        println!("method_filter={}", method.unwrap_or("<all>"));
        println!("observation_count={}", observations.len());
        for observation in &observations {
            print_observation_human(observation)?;
        }
    }
    Ok(())
}

fn run_observation_show(
    store: &Store,
    observation_id: &str,
    json_output: bool,
) -> anyhow::Result<()> {
    validate_observation_id(observation_id)?;
    let observation = store
        .get_probe_observation(observation_id)?
        .with_context(|| format!("observation not found: {observation_id}"))?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "observation": observation_to_json(&observation),
            }))?
        );
    } else {
        print_observation_human(&observation)?;
    }
    Ok(())
}

fn print_observation_human(observation: &ProbeObservationRecord) -> anyhow::Result<()> {
    println!(
        "observation_id={} run_id={} node_id={} endpoint_id={} method={} ok={} error_code={} duration_ms={} observed_at={} expires_at={} result_class={} summary_json={}",
        observation.observation_id,
        observation.run_id.as_deref().unwrap_or("<none>"),
        observation.node_id.as_deref().unwrap_or("<none>"),
        observation.endpoint_id.as_deref().unwrap_or("<none>"),
        observation.method,
        option_bool(observation.ok),
        observation.error_code.as_deref().unwrap_or("<none>"),
        option_u64(observation.duration_ms),
        observation.observed_at,
        observation.expires_at.as_deref().unwrap_or("<none>"),
        observation.result_class,
        serde_json::to_string(&safe_observation_summary(&observation.summary_json))?,
    );
    Ok(())
}

pub fn observation_to_json(observation: &ProbeObservationRecord) -> Value {
    json!({
        "observation_id": observation.observation_id,
        "run_id": observation.run_id,
        "node_id": observation.node_id,
        "endpoint_id": observation.endpoint_id,
        "method": observation.method,
        "ok": observation.ok,
        "error_code": observation.error_code,
        "duration_ms": observation.duration_ms,
        "observed_at": observation.observed_at,
        "expires_at": observation.expires_at,
        "result_class": observation.result_class,
        "summary": safe_observation_summary(&observation.summary_json),
    })
}

pub fn safe_observation_summary(value: &Value) -> Value {
    if let Ok(payload) = ObservationSummaryPayloadV1::from_value(value) {
        return payload.public_summary();
    }
    let mut budget = ProjectionBudget {
        entries_remaining: 256,
        string_bytes_remaining: 4_096,
    };
    safe_observation_summary_inner(value, 0, &mut budget)
}

struct ProjectionBudget {
    entries_remaining: usize,
    string_bytes_remaining: usize,
}

fn safe_observation_summary_inner(
    value: &Value,
    depth: usize,
    budget: &mut ProjectionBudget,
) -> Value {
    if depth >= 8 {
        return Value::String("<redacted>".to_string());
    }
    match value {
        Value::Object(map) => {
            if budget.entries_remaining == 0 {
                return Value::String("<redacted>".to_string());
            }
            let mut output = Map::new();
            let members = map
                .iter()
                .filter(|(key, _)| key.len() <= 64 && !forbidden_summary_key(key))
                .take(budget.entries_remaining)
                .collect::<Vec<_>>();
            // Reserve sibling keys before projecting child containers so one
            // attacker-controlled branch cannot make later scalar fields vanish.
            budget.entries_remaining -= members.len();
            for (key, value) in members {
                output.insert(
                    key.clone(),
                    safe_observation_summary_inner(value, depth + 1, budget),
                );
            }
            Value::Object(output)
        }
        Value::Array(values) => {
            if budget.entries_remaining == 0 {
                return Value::String("<redacted>".to_string());
            }
            let mut output = Vec::new();
            let take = values.len().min(budget.entries_remaining);
            budget.entries_remaining -= take;
            for value in values.iter().take(take) {
                output.push(safe_observation_summary_inner(value, depth + 1, budget));
            }
            Value::Array(output)
        }
        Value::String(value) => {
            if value.len() > 256
                || value.len() > budget.string_bytes_remaining
                || value
                    .bytes()
                    .any(|byte| !byte.is_ascii() || byte.is_ascii_control())
                || forbidden_summary_value(value)
            {
                Value::String("<redacted>".to_string())
            } else {
                budget.string_bytes_remaining -= value.len();
                Value::String(value.clone())
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => value.clone(),
    }
}

fn validate_limit(limit: u64) -> anyhow::Result<u64> {
    if limit == 0 || limit > MAX_OBSERVATION_QUERY_LIMIT {
        bail!("--limit must be between 1 and {MAX_OBSERVATION_QUERY_LIMIT}");
    }
    Ok(limit)
}

fn validate_method_filter(method: &str) -> anyhow::Result<()> {
    validate_selector(method).map_err(anyhow::Error::msg)
}

fn validate_observation_id(value: &str) -> anyhow::Result<()> {
    let valid = value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
    if value.is_empty() || value.len() > 128 || !valid {
        bail!("observation_id must be a safe identifier");
    }
    Ok(())
}

fn forbidden_summary_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "raw",
        "stdout",
        "stderr",
        "body",
        "username",
        "client_ip",
        "client-ip",
        "session_id",
        "session-id",
        "subject",
        "issuer",
        "serial",
        "san",
        "certificate_pem",
        "private_key",
        "config_content",
    ]
    .iter()
    .any(|marker| key.contains(marker))
}

fn forbidden_summary_value(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    [
        "/etc/",
        "/var/log",
        "systemctl",
        "journalctl",
        "occtl",
        "username",
        "client_ip",
        "session_id",
        "-----begin certificate-----",
        "-----begin private key-----",
    ]
    .iter()
    .any(|marker| value.contains(marker))
}

fn option_bool(value: Option<bool>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "<none>".to_string())
}

fn option_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "<none>".to_string())
}
