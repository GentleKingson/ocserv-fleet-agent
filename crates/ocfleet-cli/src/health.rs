use anyhow::Context;
use ocfleet_config::validation::validate_node_id;
use ocfleet_protocol::enrollment::EndpointStatus;
use ocfleet_protocol::method::{
    OCSERV_CERT_EXPIRY, OCSERV_CONFIG_FINGERPRINT, OCSERV_SERVICE_SUMMARY, OCSERV_SESSIONS_SUMMARY,
    OCSERV_VERSION, PROBE_CONTROLLER_PING,
};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::args::HealthCommand;
use crate::audit::AuditEvent;
use crate::input_validation::local_actor;
use crate::store::{HealthSnapshotRecord, NodeRecord, ProbeObservationRecord, Store};

const STALE_THRESHOLD_SECONDS: u64 = 24 * 60 * 60;
const OBSERVATION_READ_LIMIT: u64 = 1_000;

pub fn run_health_command(store: &Store, command: HealthCommand) -> anyhow::Result<()> {
    match command {
        HealthCommand::Summary { json } => run_health_summary(store, json),
        HealthCommand::Node { node_id, json } => run_health_node(store, &node_id, json),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HealthStatus {
    Healthy,
    Degraded,
    Unreachable,
    Stale,
    Disabled,
    Unknown,
}

impl HealthStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unreachable => "unreachable",
            Self::Stale => "stale",
            Self::Disabled => "disabled",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Default, Clone)]
struct HealthCounts {
    total: usize,
    healthy: usize,
    degraded: usize,
    unreachable: usize,
    stale: usize,
    disabled: usize,
    unknown: usize,
}

impl HealthCounts {
    fn record(&mut self, status: HealthStatus) {
        self.total += 1;
        match status {
            HealthStatus::Healthy => self.healthy += 1,
            HealthStatus::Degraded => self.degraded += 1,
            HealthStatus::Unreachable => self.unreachable += 1,
            HealthStatus::Stale => self.stale += 1,
            HealthStatus::Disabled => self.disabled += 1,
            HealthStatus::Unknown => self.unknown += 1,
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "total": self.total,
            "healthy": self.healthy,
            "degraded": self.degraded,
            "unreachable": self.unreachable,
            "stale": self.stale,
            "disabled": self.disabled,
            "unknown": self.unknown,
        })
    }
}

#[derive(Debug, Clone)]
struct NodeHealth {
    node_id: String,
    endpoint_id: String,
    endpoint_status: Option<String>,
    region: String,
    role: String,
    status: HealthStatus,
    freshness_seconds: Option<u64>,
    last_success_at: Option<String>,
    last_failure_at: Option<String>,
    last_error_code: Option<String>,
    degraded_methods: Vec<String>,
}

impl NodeHealth {
    fn to_json(&self) -> Value {
        json!({
            "node_id": self.node_id,
            "endpoint_id": self.endpoint_id,
            "endpoint_status": self.endpoint_status,
            "region": self.region,
            "role": self.role,
            "status": self.status.as_str(),
            "freshness_seconds": self.freshness_seconds,
            "last_success_at": self.last_success_at,
            "last_failure_at": self.last_failure_at,
            "last_error_code": self.last_error_code,
            "degraded_methods": self.degraded_methods,
        })
    }
}

fn run_health_summary(store: &Store, json_output: bool) -> anyhow::Result<()> {
    let generated_at = now_rfc3339();
    let nodes = store.list_nodes()?;
    let mut rows = Vec::with_capacity(nodes.len());
    for node in &nodes {
        let row = compute_node_health(store, node, &generated_at)?;
        upsert_health_snapshot(store, &row, &generated_at)?;
        rows.push(row);
    }
    let counts = health_counts(&rows);
    write_health_audit(store, "health.summary", &counts)?;
    print_health_output(&generated_at, &counts, &rows, json_output)?;
    Ok(())
}

fn run_health_node(store: &Store, node_id: &str, json_output: bool) -> anyhow::Result<()> {
    validate_node_id(node_id)?;
    let generated_at = now_rfc3339();
    let node = store
        .get_node(node_id)?
        .with_context(|| format!("node not found: {node_id}"))?;
    let row = compute_node_health(store, &node, &generated_at)?;
    upsert_health_snapshot(store, &row, &generated_at)?;
    let rows = vec![row];
    let counts = health_counts(&rows);
    write_health_audit(store, "health.node", &counts)?;
    print_health_output(&generated_at, &counts, &rows, json_output)?;
    Ok(())
}

fn compute_node_health(
    store: &Store,
    node: &NodeRecord,
    generated_at: &str,
) -> anyhow::Result<NodeHealth> {
    let endpoint_status = store
        .get_endpoint_trust(&node.endpoint_id)?
        .map(|endpoint| endpoint.status);
    let endpoint_error_code = inactive_endpoint_error_code(endpoint_status);
    let observations =
        store.list_probe_observations(Some(&node.node_id), OBSERVATION_READ_LIMIT)?;
    let freshness_seconds = latest_observation(&observations)
        .and_then(|observation| freshness_seconds(generated_at, &observation.observed_at));
    let last_success_at = latest_with_ok(&observations, true).map(|record| record.observed_at);
    let last_failure = latest_with_ok(&observations, false);
    let last_failure_at = last_failure
        .as_ref()
        .map(|record| record.observed_at.clone());
    let last_error_code = endpoint_error_code.map(ToOwned::to_owned).or_else(|| {
        last_failure
            .as_ref()
            .and_then(|record| record.error_code.clone())
    });
    let degraded_methods = degraded_methods(&observations);

    let status = if !node.enabled {
        HealthStatus::Disabled
    } else if endpoint_error_code.is_some() {
        HealthStatus::Unreachable
    } else if observations.is_empty() {
        HealthStatus::Unknown
    } else if latest_is_stale_or_expired(generated_at, &observations) {
        HealthStatus::Stale
    } else if latest_controller_ping_is_unreachable(&observations) {
        HealthStatus::Unreachable
    } else if !degraded_methods.is_empty() || latest_controller_ping_failed(&observations) {
        HealthStatus::Degraded
    } else {
        HealthStatus::Healthy
    };

    Ok(NodeHealth {
        node_id: node.node_id.clone(),
        endpoint_id: node.endpoint_id.clone(),
        endpoint_status: endpoint_status.map(|status| status.as_str().to_string()),
        region: node.region.clone(),
        role: node.role.clone(),
        status,
        freshness_seconds,
        last_success_at,
        last_failure_at,
        last_error_code,
        degraded_methods,
    })
}

fn latest_observation(observations: &[ProbeObservationRecord]) -> Option<&ProbeObservationRecord> {
    observations
        .iter()
        .max_by(|left, right| left.observed_at.cmp(&right.observed_at))
}

fn inactive_endpoint_error_code(status: Option<EndpointStatus>) -> Option<&'static str> {
    match status {
        None => Some("ENDPOINT_TRUST_MISSING"),
        Some(EndpointStatus::Active) => None,
        Some(EndpointStatus::Revoked) => Some("ENDPOINT_REVOKED"),
        Some(EndpointStatus::Quarantined) => Some("ENDPOINT_QUARANTINED"),
        Some(EndpointStatus::Rotated) => Some("ENDPOINT_ROTATED"),
    }
}

fn latest_with_ok(
    observations: &[ProbeObservationRecord],
    ok: bool,
) -> Option<ProbeObservationRecord> {
    observations
        .iter()
        .filter(|record| record.ok == Some(ok))
        .max_by(|left, right| left.observed_at.cmp(&right.observed_at))
        .cloned()
}

fn latest_for_method<'a>(
    observations: &'a [ProbeObservationRecord],
    method: &str,
) -> Option<&'a ProbeObservationRecord> {
    observations
        .iter()
        .filter(|record| record.method == method)
        .max_by(|left, right| left.observed_at.cmp(&right.observed_at))
}

fn latest_is_stale_or_expired(generated_at: &str, observations: &[ProbeObservationRecord]) -> bool {
    let Some(latest) = latest_observation(observations) else {
        return false;
    };
    if latest
        .expires_at
        .as_ref()
        .is_some_and(|expires_at| timestamp_before(expires_at, generated_at).unwrap_or(true))
    {
        return true;
    }
    freshness_seconds(generated_at, &latest.observed_at)
        .is_none_or(|freshness| freshness > STALE_THRESHOLD_SECONDS)
}

fn latest_controller_ping_is_unreachable(observations: &[ProbeObservationRecord]) -> bool {
    latest_for_method(observations, PROBE_CONTROLLER_PING).is_some_and(|record| {
        record.ok == Some(false)
            && record
                .error_code
                .as_deref()
                .is_some_and(is_unreachable_error_code)
    })
}

fn latest_controller_ping_failed(observations: &[ProbeObservationRecord]) -> bool {
    latest_for_method(observations, PROBE_CONTROLLER_PING)
        .is_some_and(|record| record.ok == Some(false))
}

fn is_unreachable_error_code(code: &str) -> bool {
    matches!(
        code,
        "CONNECT_FAILED"
            | "RPC_TIMEOUT"
            | "ENDPOINT_NOT_ALLOWED"
            | "ENDPOINT_MISMATCH"
            | "RESPONSE_TOO_LARGE"
            | "FRAME_READ_FAILED"
            | "NODE_NOT_FOUND"
            | "NODE_DISABLED"
            | "ENDPOINT_REVOKED"
            | "ENDPOINT_QUARANTINED"
            | "ENDPOINT_ROTATED"
            | "ENDPOINT_TRUST_MISSING"
    )
}

fn degraded_methods(observations: &[ProbeObservationRecord]) -> Vec<String> {
    let mut methods = Vec::new();
    for method in [
        OCSERV_SERVICE_SUMMARY,
        OCSERV_VERSION,
        OCSERV_SESSIONS_SUMMARY,
        OCSERV_CONFIG_FINGERPRINT,
        OCSERV_CERT_EXPIRY,
    ] {
        if let Some(record) = latest_for_method(observations, method) {
            if record.ok == Some(false) || cert_observation_warns(record) {
                methods.push(method.to_string());
            }
            for degraded in degraded_methods_from_summary(&record.summary_json) {
                if !methods.contains(&degraded) {
                    methods.push(degraded);
                }
            }
        }
    }
    methods.sort();
    methods.dedup();
    methods
}

fn degraded_methods_from_summary(summary: &Value) -> Vec<String> {
    summary
        .get("degraded_methods")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect()
}

fn cert_observation_warns(record: &ProbeObservationRecord) -> bool {
    if record.method != OCSERV_CERT_EXPIRY {
        return false;
    }
    if status_is_cert_warning(record.summary_json.get("status").and_then(Value::as_str)) {
        return true;
    }
    record
        .summary_json
        .get("certs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|cert| status_is_cert_warning(cert.get("status").and_then(Value::as_str)))
}

fn status_is_cert_warning(status: Option<&str>) -> bool {
    matches!(
        status,
        Some("expiring_soon" | "expired" | "warning" | "critical")
    )
}

fn freshness_seconds(generated_at: &str, observed_at: &str) -> Option<u64> {
    let generated_at = OffsetDateTime::parse(generated_at, &Rfc3339).ok()?;
    let observed_at = OffsetDateTime::parse(observed_at, &Rfc3339).ok()?;
    if observed_at > generated_at {
        return Some(0);
    }
    u64::try_from((generated_at - observed_at).whole_seconds()).ok()
}

fn timestamp_before(left: &str, right: &str) -> anyhow::Result<bool> {
    let left = OffsetDateTime::parse(left, &Rfc3339)?;
    let right = OffsetDateTime::parse(right, &Rfc3339)?;
    Ok(left < right)
}

fn health_counts(rows: &[NodeHealth]) -> HealthCounts {
    let mut counts = HealthCounts::default();
    for row in rows {
        counts.record(row.status);
    }
    counts
}

fn upsert_health_snapshot(
    store: &Store,
    row: &NodeHealth,
    generated_at: &str,
) -> anyhow::Result<()> {
    store.upsert_health_snapshot(&HealthSnapshotRecord {
        node_id: row.node_id.clone(),
        endpoint_id: Some(row.endpoint_id.clone()),
        computed_at: generated_at.to_string(),
        status: row.status.as_str().to_string(),
        freshness_seconds: row.freshness_seconds,
        last_success_at: row.last_success_at.clone(),
        last_failure_at: row.last_failure_at.clone(),
        last_error_code: row.last_error_code.clone(),
        degraded_methods_json: json!(row.degraded_methods),
        summary_json: json!({
            "region": row.region,
            "role": row.role,
            "status": row.status.as_str(),
            "endpoint_status": row.endpoint_status,
        }),
    })?;
    Ok(())
}

fn print_health_output(
    generated_at: &str,
    counts: &HealthCounts,
    rows: &[NodeHealth],
    json_output: bool,
) -> anyhow::Result<()> {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "generated_at": generated_at,
                "summary": counts.to_json(),
                "nodes": rows.iter().map(NodeHealth::to_json).collect::<Vec<_>>(),
            }))?
        );
    } else {
        println!("generated_at={generated_at}");
        println!(
            "total={} healthy={} degraded={} unreachable={} stale={} disabled={} unknown={}",
            counts.total,
            counts.healthy,
            counts.degraded,
            counts.unreachable,
            counts.stale,
            counts.disabled,
            counts.unknown
        );
        for row in rows {
            println!(
                "node_id={} endpoint_id={} endpoint_status={} region={} role={} status={} freshness_seconds={} last_success_at={} last_failure_at={} last_error_code={} degraded_methods={}",
                row.node_id,
                row.endpoint_id,
                row.endpoint_status.as_deref().unwrap_or("<none>"),
                row.region,
                row.role,
                row.status.as_str(),
                option_u64(row.freshness_seconds),
                row.last_success_at.as_deref().unwrap_or("<none>"),
                row.last_failure_at.as_deref().unwrap_or("<none>"),
                row.last_error_code.as_deref().unwrap_or("<none>"),
                if row.degraded_methods.is_empty() {
                    "<none>".to_string()
                } else {
                    row.degraded_methods.join(",")
                },
            );
        }
    }
    Ok(())
}

fn write_health_audit(
    store: &Store,
    event_name: &str,
    counts: &HealthCounts,
) -> anyhow::Result<()> {
    let mut event = AuditEvent::new(local_actor(), event_name);
    event.ok = Some(true);
    event.detail_json = json!({
        "node_count": counts.total,
        "status_counts": counts.to_json(),
    });
    store.insert_audit(&event)?;
    Ok(())
}

fn option_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "<none>".to_string())
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("RFC3339 formatting succeeds")
}
