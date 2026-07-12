use crate::readonly_store::ControllerMetricsSnapshot;

pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetricDescriptor {
    pub name: &'static str,
    pub help: &'static str,
    pub metric_type: &'static str,
    pub label_name: Option<&'static str>,
    pub label_values: &'static [&'static str],
}

pub const CONTROLLER_CATALOG: &[MetricDescriptor] = &[
    descriptor(
        "ocfleet_controller_scheduler_jobs_due",
        "Enabled scheduler jobs currently due.",
        "gauge",
    ),
    descriptor(
        "ocfleet_controller_scheduler_claims_active",
        "Scheduler claims with an unexpired lease.",
        "gauge",
    ),
    labeled(
        "ocfleet_controller_scheduler_runs_total",
        "Persisted scheduler runs by fixed result.",
        "counter",
        "result",
        &["running", "succeeded", "failed", "skipped"],
    ),
    labeled(
        "ocfleet_controller_health_nodes",
        "Controller health snapshots by fixed status.",
        "gauge",
        "status",
        &["healthy", "degraded", "unreachable", "unknown"],
    ),
    labeled(
        "ocfleet_controller_alerts",
        "Persisted alerts by fixed state.",
        "gauge",
        "state",
        &["open", "silenced", "resolved"],
    ),
    labeled(
        "ocfleet_controller_delivery_attempts_total",
        "Persisted delivery attempts by fixed result.",
        "counter",
        "result",
        &["succeeded", "failed"],
    ),
    labeled(
        "ocfleet_controller_delivery_queue",
        "Delivery queue rows by fixed state.",
        "gauge",
        "state",
        &["pending", "claimed", "retry", "dead_letter", "succeeded"],
    ),
    labeled(
        "ocfleet_controller_rpc_calls_total",
        "Completed controller RPC audits by fixed result.",
        "counter",
        "result",
        &["succeeded", "failed"],
    ),
    descriptor(
        "ocfleet_controller_observations_total",
        "Persisted probe observations.",
        "counter",
    ),
    descriptor(
        "ocfleet_controller_observation_freshness_seconds",
        "Age of the newest persisted observation.",
        "gauge",
    ),
    descriptor(
        "ocfleet_controller_sqlite_bytes",
        "Controller SQLite main database size.",
        "gauge",
    ),
    labeled(
        "ocfleet_controller_audit_exports_total",
        "Audit export attempts by fixed result.",
        "counter",
        "result",
        &["succeeded", "failed"],
    ),
];

const fn descriptor(
    name: &'static str,
    help: &'static str,
    metric_type: &'static str,
) -> MetricDescriptor {
    MetricDescriptor {
        name,
        help,
        metric_type,
        label_name: None,
        label_values: &[],
    }
}

const fn labeled(
    name: &'static str,
    help: &'static str,
    metric_type: &'static str,
    label_name: &'static str,
    label_values: &'static [&'static str],
) -> MetricDescriptor {
    MetricDescriptor {
        name,
        help,
        metric_type,
        label_name: Some(label_name),
        label_values,
    }
}

pub fn render_controller(snapshot: &ControllerMetricsSnapshot) -> String {
    let mut output = String::with_capacity(4_096);
    scalar(
        &mut output,
        &CONTROLLER_CATALOG[0],
        snapshot.scheduler_jobs_due,
    );
    scalar(
        &mut output,
        &CONTROLLER_CATALOG[1],
        snapshot.scheduler_claims_active,
    );
    family(
        &mut output,
        &CONTROLLER_CATALOG[2],
        &snapshot.scheduler_runs,
    );
    family(&mut output, &CONTROLLER_CATALOG[3], &snapshot.health_nodes);
    family(&mut output, &CONTROLLER_CATALOG[4], &snapshot.alerts);
    family(
        &mut output,
        &CONTROLLER_CATALOG[5],
        &snapshot.delivery_attempts,
    );
    family(
        &mut output,
        &CONTROLLER_CATALOG[6],
        &snapshot.delivery_queue,
    );
    family(&mut output, &CONTROLLER_CATALOG[7], &snapshot.rpc_calls);
    scalar(
        &mut output,
        &CONTROLLER_CATALOG[8],
        snapshot.observations_total,
    );
    scalar(
        &mut output,
        &CONTROLLER_CATALOG[9],
        snapshot.observation_freshness_seconds,
    );
    scalar(&mut output, &CONTROLLER_CATALOG[10], snapshot.sqlite_bytes);
    family(
        &mut output,
        &CONTROLLER_CATALOG[11],
        &snapshot.audit_exports,
    );
    output
}

fn metadata(output: &mut String, descriptor: &MetricDescriptor) {
    output.push_str("# HELP ");
    output.push_str(descriptor.name);
    output.push(' ');
    output.push_str(descriptor.help);
    output.push('\n');
    output.push_str("# TYPE ");
    output.push_str(descriptor.name);
    output.push(' ');
    output.push_str(descriptor.metric_type);
    output.push('\n');
}

fn scalar(output: &mut String, descriptor: &MetricDescriptor, value: u64) {
    metadata(output, descriptor);
    output.push_str(descriptor.name);
    output.push(' ');
    output.push_str(&value.to_string());
    output.push('\n');
}

fn family<const N: usize>(output: &mut String, descriptor: &MetricDescriptor, values: &[u64; N]) {
    debug_assert_eq!(descriptor.label_values.len(), N);
    metadata(output, descriptor);
    let label_name = descriptor.label_name.expect("family has fixed label");
    for (label_value, value) in descriptor.label_values.iter().zip(values) {
        output.push_str(descriptor.name);
        output.push('{');
        output.push_str(label_name);
        output.push_str("=\"");
        output.push_str(label_value);
        output.push_str("\"} ");
        output.push_str(&value.to_string());
        output.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_only_fixed_low_cardinality_labels() {
        let forbidden = [
            "user",
            "username",
            "ip",
            "address",
            "session",
            "request",
            "endpoint",
            "node",
            "token",
            "cookie",
            "secret",
            "certificate",
            "path",
        ];
        for descriptor in CONTROLLER_CATALOG {
            assert!(descriptor.name.starts_with("ocfleet_controller_"));
            assert!(matches!(descriptor.metric_type, "counter" | "gauge"));
            assert!(descriptor.label_values.len() <= 5);
            let label = descriptor.label_name.unwrap_or("");
            for fragment in forbidden {
                assert!(!label.contains(fragment), "forbidden label {label}");
            }
            for value in descriptor.label_values {
                assert!(value.len() <= 32);
                assert!(
                    value
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
                );
            }
        }
    }

    #[test]
    fn renderer_emits_bounded_prometheus_text_without_identity_values() {
        let snapshot = ControllerMetricsSnapshot {
            scheduler_jobs_due: 1,
            scheduler_claims_active: 2,
            scheduler_runs: [3, 4, 5, 6],
            health_nodes: [7, 8, 9, 10],
            alerts: [11, 12, 13],
            delivery_attempts: [14, 15],
            delivery_queue: [16, 17, 18, 19, 20],
            rpc_calls: [21, 22],
            observations_total: 23,
            observation_freshness_seconds: 24,
            sqlite_bytes: 25,
            audit_exports: [26, 27],
        };
        let text = render_controller(&snapshot);
        assert!(text.contains("ocfleet_controller_health_nodes{status=\"healthy\"} 7"));
        assert!(text.contains("ocfleet_controller_rpc_calls_total{result=\"failed\"} 22"));
        assert!(text.len() < 8_192);
        for forbidden in [
            "node_id",
            "endpoint_id",
            "request_id",
            "session_id",
            "client_ip",
        ] {
            assert!(!text.contains(forbidden));
        }
    }
}
