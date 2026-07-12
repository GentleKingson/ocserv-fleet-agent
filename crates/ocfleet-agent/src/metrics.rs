use std::sync::atomic::{AtomicU64, Ordering};

use crate::audit::AuditMetricsSnapshot;
use ocfleet_protocol::error::ErrorCode;

pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

#[derive(Debug, Default)]
pub struct AgentMetrics {
    handshake_active: AtomicU64,
    handshake_rejected: AtomicU64,
    connection_active: AtomicU64,
    connection_rejected: AtomicU64,
    stream_active: AtomicU64,
    stream_rejected: AtomicU64,
    rpc_succeeded: AtomicU64,
    rpc_failed: AtomicU64,
    rpc_duration_ms_sum: AtomicU64,
    rpc_duration_count: AtomicU64,
    rpc_code_success: AtomicU64,
    rpc_code_validation: AtomicU64,
    rpc_code_authorization: AtomicU64,
    rpc_code_resource: AtomicU64,
    rpc_code_timeout: AtomicU64,
    rpc_code_dependency: AtomicU64,
    rpc_code_internal: AtomicU64,
    nonce_replay_rejected: AtomicU64,
    nonce_resource_rejected: AtomicU64,
}

impl AgentMetrics {
    pub fn admission_started(&self, resource: Resource) {
        resource.active(self).fetch_add(1, Ordering::Relaxed);
    }

    pub fn admission_finished(&self, resource: Resource) {
        resource.active(self).fetch_sub(1, Ordering::Relaxed);
    }

    pub fn admission_rejected(&self, resource: Resource) {
        resource.rejected(self).fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rpc(&self, error: Option<&ErrorCode>, duration_ms: u64) {
        if error.is_none() {
            self.rpc_succeeded.fetch_add(1, Ordering::Relaxed);
        } else {
            self.rpc_failed.fetch_add(1, Ordering::Relaxed);
        }
        rpc_code_counter(self, error).fetch_add(1, Ordering::Relaxed);
        self.rpc_duration_ms_sum
            .fetch_add(duration_ms, Ordering::Relaxed);
        self.rpc_duration_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn nonce_rejected(&self, resource_exhausted: bool) {
        if resource_exhausted {
            self.nonce_resource_rejected.fetch_add(1, Ordering::Relaxed);
        } else {
            self.nonce_replay_rejected.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn render(&self, nonce_cache_size: u64, audit: &AuditMetricsSnapshot) -> String {
        let mut output = String::with_capacity(4_096);
        family(
            &mut output,
            "ocfleet_agent_handshakes",
            "Current and rejected handshakes.",
            "gauge",
            &[
                ("active", self.handshake_active.load(Ordering::Relaxed)),
                ("rejected", self.handshake_rejected.load(Ordering::Relaxed)),
            ],
        );
        family(
            &mut output,
            "ocfleet_agent_rpc_results_total",
            "RPC calls by fixed result-code class.",
            "counter",
            &[
                ("success", self.rpc_code_success.load(Ordering::Relaxed)),
                (
                    "validation",
                    self.rpc_code_validation.load(Ordering::Relaxed),
                ),
                (
                    "authorization",
                    self.rpc_code_authorization.load(Ordering::Relaxed),
                ),
                ("resource", self.rpc_code_resource.load(Ordering::Relaxed)),
                ("timeout", self.rpc_code_timeout.load(Ordering::Relaxed)),
                (
                    "dependency",
                    self.rpc_code_dependency.load(Ordering::Relaxed),
                ),
                ("internal", self.rpc_code_internal.load(Ordering::Relaxed)),
            ],
        );
        family(
            &mut output,
            "ocfleet_agent_connections",
            "Current and rejected connections.",
            "gauge",
            &[
                ("active", self.connection_active.load(Ordering::Relaxed)),
                ("rejected", self.connection_rejected.load(Ordering::Relaxed)),
            ],
        );
        family(
            &mut output,
            "ocfleet_agent_streams",
            "Current and rejected streams.",
            "gauge",
            &[
                ("active", self.stream_active.load(Ordering::Relaxed)),
                ("rejected", self.stream_rejected.load(Ordering::Relaxed)),
            ],
        );
        family(
            &mut output,
            "ocfleet_agent_rpc_calls_total",
            "RPC calls by fixed result.",
            "counter",
            &[
                ("succeeded", self.rpc_succeeded.load(Ordering::Relaxed)),
                ("failed", self.rpc_failed.load(Ordering::Relaxed)),
            ],
        );
        scalar(
            &mut output,
            "ocfleet_agent_rpc_duration_milliseconds_sum",
            "Cumulative RPC duration in milliseconds.",
            "counter",
            self.rpc_duration_ms_sum.load(Ordering::Relaxed),
        );
        scalar(
            &mut output,
            "ocfleet_agent_rpc_duration_milliseconds_count",
            "Number of RPC duration observations.",
            "counter",
            self.rpc_duration_count.load(Ordering::Relaxed),
        );
        scalar(
            &mut output,
            "ocfleet_agent_nonce_cache_size",
            "Current live nonce count.",
            "gauge",
            nonce_cache_size,
        );
        family(
            &mut output,
            "ocfleet_agent_nonce_rejections_total",
            "Nonce rejections by fixed reason.",
            "counter",
            &[
                ("replay", self.nonce_replay_rejected.load(Ordering::Relaxed)),
                (
                    "resource_exhausted",
                    self.nonce_resource_rejected.load(Ordering::Relaxed),
                ),
            ],
        );
        scalar(
            &mut output,
            "ocfleet_agent_audit_queue_events",
            "Audit events currently queued for durable replay.",
            "gauge",
            audit.audit_queued,
        );
        scalar(
            &mut output,
            "ocfleet_agent_audit_dropped_total",
            "Audit events dropped after bounded spool exhaustion.",
            "counter",
            audit.audit_dropped,
        );
        scalar(
            &mut output,
            "ocfleet_agent_audit_replayed_total",
            "Audit events replayed from the durable spool.",
            "counter",
            audit.audit_replayed,
        );
        scalar(
            &mut output,
            "ocfleet_agent_audit_write_failures_total",
            "Audit primary or spool flush failures.",
            "counter",
            audit.audit_flush_failures,
        );
        scalar(
            &mut output,
            "ocfleet_agent_audit_oldest_age_seconds",
            "Age of the oldest queued audit event.",
            "gauge",
            audit.audit_oldest_age_seconds.unwrap_or(0),
        );
        output
    }
}

fn rpc_code_counter<'a>(metrics: &'a AgentMetrics, error: Option<&ErrorCode>) -> &'a AtomicU64 {
    match error {
        None => &metrics.rpc_code_success,
        Some(
            ErrorCode::FrameTooLarge
            | ErrorCode::FrameReadFailed
            | ErrorCode::InvalidJson
            | ErrorCode::InvalidVersion
            | ErrorCode::InvalidRequestId
            | ErrorCode::InvalidTimestamp
            | ErrorCode::RequestExpired
            | ErrorCode::ClockSkewExceeded
            | ErrorCode::InvalidNonce
            | ErrorCode::ReplayedNonce
            | ErrorCode::InvalidDeadline
            | ErrorCode::ParamsInvalid
            | ErrorCode::UnsupportedAuthScheme
            | ErrorCode::ResponseTooLarge
            | ErrorCode::InvalidResponse
            | ErrorCode::MethodNotFound,
        ) => &metrics.rpc_code_validation,
        Some(
            ErrorCode::EndpointNotAllowed
            | ErrorCode::EndpointMismatch
            | ErrorCode::NodeNotFound
            | ErrorCode::NodeDisabled
            | ErrorCode::MethodNotAllowed,
        ) => &metrics.rpc_code_authorization,
        Some(ErrorCode::ResourceExhausted | ErrorCode::SqliteBusyTimeout) => {
            &metrics.rpc_code_resource
        }
        Some(ErrorCode::RpcTimeout) => &metrics.rpc_code_timeout,
        Some(
            ErrorCode::ConnectFailed
            | ErrorCode::SqliteError
            | ErrorCode::SchemaMigrationFailed
            | ErrorCode::SchemaVersionUnsupported
            | ErrorCode::ConfigLoadFailed
            | ErrorCode::SecretKeyLoadFailed
            | ErrorCode::SecretKeyPermissionInvalid
            | ErrorCode::OcservReadonlyDisabled
            | ErrorCode::OcservProviderUnavailable
            | ErrorCode::OcservProviderInvalidData
            | ErrorCode::OcservProviderUnsafeSource
            | ErrorCode::OcservOutputBoundExceeded
            | ErrorCode::OcservUnsupportedField,
        ) => &metrics.rpc_code_dependency,
        Some(ErrorCode::AuditWriteFailed | ErrorCode::InternalError) => &metrics.rpc_code_internal,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resource {
    Handshake,
    Connection,
    Stream,
}

impl Resource {
    fn active(self, metrics: &AgentMetrics) -> &AtomicU64 {
        match self {
            Self::Handshake => &metrics.handshake_active,
            Self::Connection => &metrics.connection_active,
            Self::Stream => &metrics.stream_active,
        }
    }

    fn rejected(self, metrics: &AgentMetrics) -> &AtomicU64 {
        match self {
            Self::Handshake => &metrics.handshake_rejected,
            Self::Connection => &metrics.connection_rejected,
            Self::Stream => &metrics.stream_rejected,
        }
    }
}

fn metadata(output: &mut String, name: &str, help: &str, metric_type: &str) {
    output.push_str("# HELP ");
    output.push_str(name);
    output.push(' ');
    output.push_str(help);
    output.push('\n');
    output.push_str("# TYPE ");
    output.push_str(name);
    output.push(' ');
    output.push_str(metric_type);
    output.push('\n');
}

fn scalar(output: &mut String, name: &str, help: &str, metric_type: &str, value: u64) {
    metadata(output, name, help, metric_type);
    output.push_str(name);
    output.push(' ');
    output.push_str(&value.to_string());
    output.push('\n');
}

fn family(output: &mut String, name: &str, help: &str, metric_type: &str, values: &[(&str, u64)]) {
    metadata(output, name, help, metric_type);
    for (state, value) in values {
        output.push_str(name);
        output.push_str("{state=\"");
        output.push_str(state);
        output.push_str("\"} ");
        output.push_str(&value.to_string());
        output.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renderer_has_only_fixed_labels_and_no_identity_dimensions() {
        let metrics = AgentMetrics::default();
        metrics.admission_started(Resource::Connection);
        metrics.admission_rejected(Resource::Stream);
        metrics.record_rpc(Some(&ErrorCode::ResourceExhausted), 17);
        metrics.nonce_rejected(true);
        let text = metrics.render(
            3,
            &AuditMetricsSnapshot {
                audit_queued: 1,
                audit_dropped: 2,
                audit_replayed: 3,
                audit_flush_failures: 4,
                audit_oldest_age_seconds: Some(5),
            },
        );
        assert!(text.contains("ocfleet_agent_connections{state=\"active\"} 1"));
        assert!(text.contains("ocfleet_agent_rpc_calls_total{state=\"failed\"} 1"));
        assert!(text.len() < 8_192);
        for forbidden in [
            "node_id",
            "endpoint_id",
            "request_id",
            "session_id",
            "client_ip",
            "token",
            "cookie",
            "path",
        ] {
            assert!(!text.contains(forbidden));
        }
    }
}
