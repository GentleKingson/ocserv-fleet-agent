use ocfleet_config::validation::{validate_node_id, validate_region, validate_role};
use ocfleet_protocol::method::{
    OCSERV_CERT_EXPIRY, OCSERV_CONFIG_FINGERPRINT, OCSERV_SERVICE_SUMMARY, OCSERV_SESSIONS_SUMMARY,
    OCSERV_VERSION, PROBE_CONTROLLER_PING, PROBE_PATH_ECHO,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::input_validation::{validate_description, validate_reason};

pub const SCHEDULER_SELECTOR_SCHEMA_V1: &str = "ocfleet.scheduler.selector.v1";
pub const SCHEDULER_PAIR_SCHEMA_V1: &str = "ocfleet.scheduler.pair.v1";
pub const HEALTH_DEGRADED_METHODS_SCHEMA_V1: &str = "ocfleet.health.degraded-methods.v1";
pub const HEALTH_SUMMARY_SCHEMA_V1: &str = "ocfleet.health.summary.v1";
pub const OBSERVATION_SUMMARY_SCHEMA_V1: &str = "ocfleet.observation.summary.v1";
pub const RUN_SUMMARY_SCHEMA_V1: &str = "ocfleet.run.summary.v1";
pub const TRUST_BUNDLE_SCHEMA_V1: &str = "ocfleet.trust.bundle.v1";
pub const ALERT_DETAIL_SCHEMA_V1: &str = "ocfleet.alert.detail.v1";
pub const ALERT_HOST_ALLOW_SCHEMA_V1: &str = "ocfleet.alert.host-allow.v1";

const HEALTH_DEGRADED_METHODS: [&str; 5] = [
    "ocserv.cert.expiry",
    "ocserv.config.fingerprint",
    "ocserv.service.summary",
    "ocserv.sessions.summary",
    "ocserv.version",
];

pub fn validate_scheduler_payload_relationship(
    kind: &str,
    selector: &SchedulerSelectorPayloadV1,
    pair: Option<&SchedulerPairPayloadV1>,
) -> Result<(), String> {
    if kind == "path-probe" {
        if selector.selector != "explicit-pair" || pair.is_none() {
            return Err("path-probe job requires an explicit typed pair".to_string());
        }
    } else if selector.selector == "explicit-pair" || pair.is_some() {
        return Err("non-path job cannot use an explicit pair".to_string());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthDegradedMethodsPayloadV1 {
    pub schema: String,
    pub methods: Vec<String>,
}

impl HealthDegradedMethodsPayloadV1 {
    pub fn new(mut methods: Vec<String>) -> Result<Self, String> {
        methods.sort();
        methods.dedup();
        let payload = Self {
            schema: HEALTH_DEGRADED_METHODS_SCHEMA_V1.to_string(),
            methods,
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn from_value(value: &Value) -> Result<Self, String> {
        let payload: Self = serde_json::from_value(value.clone())
            .map_err(|_| "health degraded-methods payload is not closed v1 data".to_string())?;
        payload.validate()?;
        Ok(payload)
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("health degraded-methods payload serializes")
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != HEALTH_DEGRADED_METHODS_SCHEMA_V1 {
            return Err("health degraded-methods payload schema is unsupported".to_string());
        }
        if self.methods.len() > HEALTH_DEGRADED_METHODS.len() {
            return Err("health degraded-methods payload has too many methods".to_string());
        }
        if self.methods.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err("health degraded methods must be sorted and unique".to_string());
        }
        if self
            .methods
            .iter()
            .any(|method| !HEALTH_DEGRADED_METHODS.contains(&method.as_str()))
        {
            return Err(
                "health degraded-methods payload contains an unsupported method".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthSummaryPayloadV1 {
    pub schema: String,
    pub region: Option<String>,
    pub role: Option<String>,
    pub status: String,
    pub endpoint_status: Option<String>,
    pub consecutive_failures: Option<u64>,
}

impl HealthSummaryPayloadV1 {
    pub fn new(
        region: Option<String>,
        role: Option<String>,
        status: String,
        endpoint_status: Option<String>,
        consecutive_failures: Option<u64>,
    ) -> Result<Self, String> {
        let payload = Self {
            schema: HEALTH_SUMMARY_SCHEMA_V1.to_string(),
            region,
            role,
            status,
            endpoint_status,
            consecutive_failures,
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn from_value(value: &Value) -> Result<Self, String> {
        let payload: Self = serde_json::from_value(value.clone())
            .map_err(|_| "health summary payload is not closed v1 data".to_string())?;
        payload.validate()?;
        Ok(payload)
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("health summary payload serializes")
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != HEALTH_SUMMARY_SCHEMA_V1 {
            return Err("health summary payload schema is unsupported".to_string());
        }
        self.region
            .as_deref()
            .map(validate_region)
            .transpose()
            .map_err(|error| error.to_string())?;
        self.role
            .as_deref()
            .map(validate_role)
            .transpose()
            .map_err(|error| error.to_string())?;
        if !matches!(
            self.status.as_str(),
            "healthy" | "degraded" | "unreachable" | "stale" | "disabled" | "unknown"
        ) {
            return Err("health summary status is unsupported".to_string());
        }
        if self.endpoint_status.as_deref().is_some_and(|status| {
            !matches!(status, "active" | "revoked" | "quarantined" | "rotated")
        }) {
            return Err("health summary endpoint status is unsupported".to_string());
        }
        if self.consecutive_failures.is_some_and(|count| count > 1_000) {
            return Err("health summary consecutive failures exceeds 1000".to_string());
        }
        Ok(())
    }
}

pub fn validate_health_payload_relationship(
    status: &str,
    summary: &HealthSummaryPayloadV1,
) -> Result<(), String> {
    if summary.status != status {
        return Err("health summary status does not match snapshot status".to_string());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunSummaryPayloadV1 {
    pub schema: String,
    pub result_class: String,
    pub job_id: Option<String>,
    pub kind: Option<String>,
    pub status: String,
    pub triggered_by: String,
    pub observations: Option<u64>,
    pub failed_observations: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct LegacyRunSummaryV1 {
    result_class: Option<String>,
    job_id: Option<String>,
    kind: Option<String>,
    status: Option<String>,
    triggered_by: Option<String>,
    observations: Option<u64>,
    failed_observations: Option<u64>,
    started: Option<bool>,
}

impl RunSummaryPayloadV1 {
    pub fn new(
        job_id: Option<String>,
        kind: Option<String>,
        status: String,
        triggered_by: String,
        observations: Option<u64>,
        failed_observations: Option<u64>,
    ) -> Result<Self, String> {
        let payload = Self {
            schema: RUN_SUMMARY_SCHEMA_V1.to_string(),
            result_class: "scheduler_summary".to_string(),
            job_id,
            kind,
            status,
            triggered_by,
            observations,
            failed_observations,
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn from_legacy(
        job_id: Option<&str>,
        kind_hint: Option<&str>,
        status: &str,
        triggered_by: &str,
        value: &Value,
    ) -> Result<Self, String> {
        let legacy: LegacyRunSummaryV1 = serde_json::from_value(value.clone())
            .map_err(|_| "run summary contains unsupported fields or values".to_string())?;
        if legacy
            .result_class
            .as_deref()
            .is_some_and(|result_class| result_class != "scheduler_summary")
        {
            return Err("run summary result class is inconsistent".to_string());
        }
        if legacy.job_id.is_some() && legacy.job_id.as_deref() != job_id {
            return Err("run summary job ID is inconsistent".to_string());
        }
        if legacy
            .status
            .as_deref()
            .is_some_and(|stored| stored != status)
        {
            return Err("run summary status is inconsistent".to_string());
        }
        if legacy
            .triggered_by
            .as_deref()
            .is_some_and(|stored| stored != triggered_by)
        {
            return Err("run summary trigger is inconsistent".to_string());
        }
        if legacy
            .started
            .is_some_and(|started| !started || status != "running")
        {
            return Err("legacy run summary started marker is inconsistent".to_string());
        }
        if let (Some(kind), Some(hint)) = (legacy.kind.as_deref(), kind_hint)
            && kind != hint
        {
            return Err("run summary job kind is inconsistent".to_string());
        }
        Self::new(
            job_id.map(ToOwned::to_owned),
            legacy.kind.or_else(|| kind_hint.map(ToOwned::to_owned)),
            status.to_string(),
            triggered_by.to_string(),
            legacy.observations,
            legacy.failed_observations,
        )
    }

    pub fn from_value(value: &Value) -> Result<Self, String> {
        let payload: Self = serde_json::from_value(value.clone())
            .map_err(|_| "run summary payload is not closed v1 data".to_string())?;
        payload.validate()?;
        Ok(payload)
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("run summary payload serializes")
    }

    pub fn public_summary(&self) -> Value {
        let mut value = serde_json::json!({
            "result_class": self.result_class,
            "job_id": self.job_id,
            "kind": self.kind,
            "status": self.status,
            "triggered_by": self.triggered_by,
            "observations": self.observations,
            "failed_observations": self.failed_observations,
        });
        value
            .as_object_mut()
            .expect("run public summary is an object")
            .retain(|_, value| !value.is_null());
        value
    }

    pub fn validate_relationship(
        &self,
        job_id: Option<&str>,
        kind: Option<&str>,
        status: &str,
        triggered_by: &str,
    ) -> Result<(), String> {
        if self.job_id.as_deref() != job_id
            || self.kind.as_deref() != kind
            || self.status != status
            || self.triggered_by != triggered_by
        {
            return Err(
                "run summary does not match relational job, kind, status, or trigger".to_string(),
            );
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != RUN_SUMMARY_SCHEMA_V1 {
            return Err("run summary payload schema is unsupported".to_string());
        }
        if self.result_class != "scheduler_summary" {
            return Err("run summary result class is unsupported".to_string());
        }
        if let Some(job_id) = &self.job_id {
            validate_fixed_id(job_id, 128, "run summary job ID")?;
        }
        if self.kind.as_deref().is_some_and(|kind| {
            !matches!(
                kind,
                "controller-ping"
                    | "ocserv-status"
                    | "ocserv-cert"
                    | "ocserv-sessions"
                    | "path-probe"
            )
        }) {
            return Err("run summary job kind is unsupported".to_string());
        }
        if !matches!(
            self.status.as_str(),
            "running" | "succeeded" | "failed" | "skipped"
        ) {
            return Err("run summary status is unsupported".to_string());
        }
        if !matches!(self.triggered_by.as_str(), "manual" | "scheduler.run.once") {
            return Err("run summary trigger is unsupported".to_string());
        }
        if self
            .observations
            .is_some_and(|observations| observations > 1_000_000)
            || self
                .failed_observations
                .is_some_and(|observations| observations > 1_000_000)
        {
            return Err("run summary observation count exceeds limit".to_string());
        }
        if let (Some(observations), Some(failed)) = (self.observations, self.failed_observations)
            && failed > observations
        {
            return Err("run summary failed count exceeds observation count".to_string());
        }
        if self.failed_observations.is_some() && self.observations.is_none() {
            return Err("run summary failed count requires an observation count".to_string());
        }
        if self.status == "running"
            && (self.observations.is_some() || self.failed_observations.is_some())
        {
            return Err("running run summary cannot contain terminal counts".to_string());
        }
        Ok(())
    }
}

fn validate_fixed_id(value: &str, max_len: usize, field: &str) -> Result<(), String> {
    if !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        Ok(())
    } else {
        Err(format!(
            "{field} must be 1-{max_len} chars and contain only [a-zA-Z0-9._:-]"
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustBundlePayloadV1 {
    pub schema: String,
    pub endpoint_id: String,
    pub generation: u64,
    pub status: String,
    pub trusted_controllers: Vec<String>,
    pub trusted_peers: Vec<String>,
    pub authorized_path_probes: Vec<(String, String)>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct LegacyTrustBundleV1 {
    endpoint_id: Option<String>,
    generation: Option<u64>,
    status: Option<String>,
    trusted_controllers: Vec<String>,
    trusted_peers: Vec<String>,
    authorized_path_probes: Vec<(String, String)>,
}

impl TrustBundlePayloadV1 {
    pub fn new(
        endpoint_id: String,
        generation: u64,
        status: String,
        trusted_controllers: Vec<String>,
        trusted_peers: Vec<String>,
        authorized_path_probes: Vec<(String, String)>,
    ) -> Result<Self, String> {
        let payload = Self {
            schema: TRUST_BUNDLE_SCHEMA_V1.to_string(),
            endpoint_id,
            generation,
            status,
            trusted_controllers,
            trusted_peers,
            authorized_path_probes,
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn from_legacy(
        endpoint_id: &str,
        generation: u64,
        status: &str,
        value: &Value,
    ) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "legacy trust bundle must be an object".to_string())?;
        if !object.is_empty()
            && (object.len() != 6
                || [
                    "endpoint_id",
                    "generation",
                    "status",
                    "trusted_controllers",
                    "trusted_peers",
                    "authorized_path_probes",
                ]
                .iter()
                .any(|field| !object.contains_key(*field)))
        {
            return Err("legacy trust bundle must be empty or complete".to_string());
        }
        let legacy: LegacyTrustBundleV1 = serde_json::from_value(value.clone())
            .map_err(|_| "trust bundle contains unsupported fields or values".to_string())?;
        if legacy
            .endpoint_id
            .as_deref()
            .is_some_and(|stored| stored != endpoint_id)
            || legacy.generation.is_some_and(|stored| stored != generation)
            || legacy
                .status
                .as_deref()
                .is_some_and(|stored| stored != status)
        {
            return Err("legacy trust bundle is inconsistent with endpoint state".to_string());
        }
        Self::new(
            endpoint_id.to_string(),
            generation,
            status.to_string(),
            legacy.trusted_controllers,
            legacy.trusted_peers,
            legacy.authorized_path_probes,
        )
    }

    pub fn from_value(value: &Value) -> Result<Self, String> {
        let payload: Self = serde_json::from_value(value.clone())
            .map_err(|_| "trust bundle payload is not closed v1 data".to_string())?;
        payload.validate()?;
        Ok(payload)
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("trust bundle payload serializes")
    }

    pub fn public_bundle(&self) -> Value {
        serde_json::json!({
            "endpoint_id": self.endpoint_id,
            "generation": self.generation,
            "status": self.status,
            "trusted_controllers": self.trusted_controllers,
            "trusted_peers": self.trusted_peers,
            "authorized_path_probes": self.authorized_path_probes,
        })
    }

    pub fn validate_relationship(
        &self,
        endpoint_id: &str,
        generation: u64,
        status: &str,
    ) -> Result<(), String> {
        if self.endpoint_id != endpoint_id || self.generation != generation || self.status != status
        {
            return Err(
                "trust bundle does not match relational endpoint, generation, or status"
                    .to_string(),
            );
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != TRUST_BUNDLE_SCHEMA_V1 {
            return Err("trust bundle payload schema is unsupported".to_string());
        }
        validate_fixed_id(&self.endpoint_id, 128, "trust bundle endpoint ID")?;
        if self.generation == 0 || self.generation > i64::MAX as u64 {
            return Err("trust bundle generation is out of range".to_string());
        }
        if !matches!(
            self.status.as_str(),
            "active" | "rotated" | "revoked" | "quarantined"
        ) {
            return Err("trust bundle status is unsupported".to_string());
        }
        validate_trust_id_list(&self.trusted_controllers, "trusted controller")?;
        validate_trust_id_list(&self.trusted_peers, "trusted peer")?;
        if self.authorized_path_probes.len() > 1_024 {
            return Err("trust bundle has too many authorized path probes".to_string());
        }
        let mut pairs = std::collections::BTreeSet::new();
        for (source, target) in &self.authorized_path_probes {
            validate_fixed_id(source, 128, "authorized path source")?;
            validate_fixed_id(target, 128, "authorized path target")?;
            if source == target {
                return Err("authorized path probe requires distinct endpoints".to_string());
            }
            if !pairs.insert((source, target)) {
                return Err("trust bundle authorized path probes must be unique".to_string());
            }
        }
        Ok(())
    }
}

fn validate_trust_id_list(values: &[String], field: &str) -> Result<(), String> {
    if values.len() > 1_024 {
        return Err(format!("trust bundle has too many {field} entries"));
    }
    let mut unique = std::collections::BTreeSet::new();
    for value in values {
        validate_fixed_id(value, 128, field)?;
        if !unique.insert(value) {
            return Err(format!("trust bundle {field} entries must be unique"));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertDetailPayloadV1 {
    pub schema: String,
    pub methods: Vec<String>,
    pub summary: AlertSummaryFieldsV1,
    pub silenced_until: Option<String>,
    pub silence_reason: Option<String>,
    pub resolve_reason: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AlertSummaryFieldsV1 {
    pub freshness_seconds: Option<u64>,
    pub consecutive_failures: Option<u64>,
    pub days_remaining: Option<i64>,
    pub endpoint_id: Option<String>,
    pub status: Option<String>,
    pub last_error_code: Option<String>,
    pub endpoint_status: Option<String>,
    pub result_class: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct LegacyAlertDetailV1 {
    methods: Vec<String>,
    summary: Option<AlertSummaryFieldsV1>,
    silenced_until: Option<String>,
    silence_reason: Option<String>,
    resolve_reason: Option<String>,
    freshness_seconds: Option<u64>,
    consecutive_failures: Option<u64>,
    days_remaining: Option<i64>,
    endpoint_id: Option<String>,
    status: Option<String>,
    last_error_code: Option<String>,
    endpoint_status: Option<String>,
    result_class: Option<String>,
}

impl AlertDetailPayloadV1 {
    pub fn new(
        methods: Vec<String>,
        summary: AlertSummaryFieldsV1,
        silenced_until: Option<String>,
        silence_reason: Option<String>,
        resolve_reason: Option<String>,
    ) -> Result<Self, String> {
        let payload = Self {
            schema: ALERT_DETAIL_SCHEMA_V1.to_string(),
            methods,
            summary,
            silenced_until,
            silence_reason,
            resolve_reason,
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn from_legacy(value: &Value) -> Result<Self, String> {
        let legacy: LegacyAlertDetailV1 = serde_json::from_value(value.clone())
            .map_err(|_| "alert detail contains unsupported fields or values".to_string())?;
        let mut summary = legacy.summary.unwrap_or_default();
        merge_alert_summary_field(
            &mut summary.freshness_seconds,
            legacy.freshness_seconds,
            "freshness_seconds",
        )?;
        merge_alert_summary_field(
            &mut summary.consecutive_failures,
            legacy.consecutive_failures,
            "consecutive_failures",
        )?;
        merge_alert_summary_field(
            &mut summary.days_remaining,
            legacy.days_remaining,
            "days_remaining",
        )?;
        merge_alert_summary_field(&mut summary.endpoint_id, legacy.endpoint_id, "endpoint_id")?;
        merge_alert_summary_field(&mut summary.status, legacy.status, "status")?;
        merge_alert_summary_field(
            &mut summary.last_error_code,
            legacy.last_error_code,
            "last_error_code",
        )?;
        merge_alert_summary_field(
            &mut summary.endpoint_status,
            legacy.endpoint_status,
            "endpoint_status",
        )?;
        merge_alert_summary_field(
            &mut summary.result_class,
            legacy.result_class,
            "result_class",
        )?;
        Self::new(
            legacy.methods,
            summary,
            legacy.silenced_until,
            legacy.silence_reason,
            legacy.resolve_reason,
        )
    }

    pub fn from_value(value: &Value) -> Result<Self, String> {
        let payload: Self = serde_json::from_value(value.clone())
            .map_err(|_| "alert detail payload is not closed v1 data".to_string())?;
        payload.validate()?;
        Ok(payload)
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("alert detail payload serializes")
    }

    pub fn public_detail(&self) -> Value {
        let mut summary = serde_json::to_value(&self.summary).expect("alert summary serializes");
        summary
            .as_object_mut()
            .expect("alert summary is an object")
            .retain(|_, value| !value.is_null());
        let mut detail = serde_json::json!({
            "methods": self.methods,
            "summary": summary,
            "silenced_until": self.silenced_until,
            "silence_reason": self.silence_reason,
            "resolve_reason": self.resolve_reason,
        });
        detail
            .as_object_mut()
            .expect("alert detail is an object")
            .retain(|_, value| !value.is_null());
        detail
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != ALERT_DETAIL_SCHEMA_V1 {
            return Err("alert detail payload schema is unsupported".to_string());
        }
        if self.methods.len() > 8 {
            return Err("alert detail has too many methods".to_string());
        }
        let mut methods = std::collections::BTreeSet::new();
        for method in &self.methods {
            if !matches!(
                method.as_str(),
                PROBE_CONTROLLER_PING
                    | PROBE_PATH_ECHO
                    | OCSERV_SERVICE_SUMMARY
                    | OCSERV_VERSION
                    | OCSERV_SESSIONS_SUMMARY
                    | OCSERV_CERT_EXPIRY
                    | OCSERV_CONFIG_FINGERPRINT
            ) {
                return Err("alert detail contains an unsupported method".to_string());
            }
            if !methods.insert(method) {
                return Err("alert detail methods must be unique".to_string());
            }
        }
        self.summary.validate()?;
        if let Some(until) = &self.silenced_until
            && (until.len() > 64 || OffsetDateTime::parse(until, &Rfc3339).is_err())
        {
            return Err("alert silence deadline must be bounded RFC3339".to_string());
        }
        self.silence_reason
            .as_deref()
            .map(validate_reason)
            .transpose()?;
        self.resolve_reason
            .as_deref()
            .map(validate_reason)
            .transpose()?;
        crate::store::validate_low_sensitive_json(&self.to_value(), "alert detail payload")
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

impl AlertSummaryFieldsV1 {
    fn validate(&self) -> Result<(), String> {
        if self
            .freshness_seconds
            .is_some_and(|value| value > u32::MAX.into())
            || self
                .consecutive_failures
                .is_some_and(|value| value > u32::MAX.into())
        {
            return Err("alert summary count is out of range".to_string());
        }
        if self
            .days_remaining
            .is_some_and(|value| !(-365_000..=365_000).contains(&value))
        {
            return Err("alert summary days remaining is out of range".to_string());
        }
        if let Some(endpoint_id) = &self.endpoint_id {
            validate_fixed_id(endpoint_id, 128, "alert summary endpoint ID")?;
        }
        if self.status.as_deref().is_some_and(|status| {
            !matches!(
                status,
                "healthy"
                    | "degraded"
                    | "unreachable"
                    | "stale"
                    | "disabled"
                    | "unknown"
                    | "ok"
                    | "warning"
                    | "critical"
                    | "expired"
                    | "expiring_soon"
                    | "unreadable"
                    | "valid"
                    | "invalid"
                    | "unavailable"
            )
        }) {
            return Err("alert summary status is unsupported".to_string());
        }
        if let Some(error_code) = &self.last_error_code {
            validate_fixed_id(error_code, 128, "alert summary error code")?;
        }
        if self.endpoint_status.as_deref().is_some_and(|status| {
            !matches!(status, "active" | "rotated" | "revoked" | "quarantined")
        }) {
            return Err("alert summary endpoint status is unsupported".to_string());
        }
        if self.result_class.as_deref().is_some_and(|result_class| {
            !matches!(
                result_class,
                "controller_rpc_summary" | "low_sensitive_summary" | "scheduler_summary"
            )
        }) {
            return Err("alert summary result class is unsupported".to_string());
        }
        Ok(())
    }
}

fn merge_alert_summary_field<T>(
    nested: &mut Option<T>,
    legacy: Option<T>,
    field: &str,
) -> Result<(), String> {
    if nested.is_some() && legacy.is_some() {
        return Err(format!("alert detail has duplicate {field}"));
    }
    if legacy.is_some() {
        *nested = legacy;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertHostAllowPayloadV1 {
    pub schema: String,
    pub hosts: Vec<String>,
}

impl AlertHostAllowPayloadV1 {
    pub fn new(hosts: Vec<String>) -> Result<Self, String> {
        let normalized = crate::alert_webhook::normalize_host_allow(&hosts)
            .map_err(|_| "alert host allowlist contains invalid hosts".to_string())?;
        let payload = Self {
            schema: ALERT_HOST_ALLOW_SCHEMA_V1.to_string(),
            hosts: normalized,
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn from_legacy(value: &Value) -> Result<Self, String> {
        let hosts: Vec<String> = serde_json::from_value(value.clone())
            .map_err(|_| "legacy alert host allowlist is not a string array".to_string())?;
        Self::new(hosts)
    }

    pub fn from_value(value: &Value) -> Result<Self, String> {
        let payload: Self = serde_json::from_value(value.clone())
            .map_err(|_| "alert host allowlist payload is not closed v1 data".to_string())?;
        payload.validate()?;
        Ok(payload)
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("alert host allowlist payload serializes")
    }

    pub fn validate_relationship(&self, endpoint_host: &str) -> Result<(), String> {
        if !self.hosts.iter().any(|host| host == endpoint_host) {
            return Err("alert endpoint host is absent from its allowlist".to_string());
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != ALERT_HOST_ALLOW_SCHEMA_V1 {
            return Err("alert host allowlist payload schema is unsupported".to_string());
        }
        let normalized = crate::alert_webhook::normalize_host_allow(&self.hosts)
            .map_err(|_| "alert host allowlist contains invalid hosts".to_string())?;
        if normalized != self.hosts {
            return Err("alert host allowlist payload is not canonical".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSummaryPayloadV1 {
    pub schema: String,
    pub result_class: String,
    pub method: String,
    pub fields: ObservationSummaryFieldsV1,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ObservationSummaryFieldsV1 {
    pub message: Option<String>,
    pub node_id: Option<String>,
    pub agent_version: Option<String>,
    pub time_utc: Option<String>,
    pub region: Option<String>,
    pub role: Option<String>,
    pub current_time_utc: Option<String>,
    pub agent_endpoint_id: Option<String>,
    pub probe: Option<String>,
    pub ok: Option<bool>,
    pub source_agent_endpoint_id: Option<String>,
    pub target_agent_endpoint_id: Option<String>,
    pub root_request_id: Option<String>,
    pub peer_request_id: Option<String>,
    pub target_error_code: Option<String>,
    pub service_state: Option<String>,
    pub service_enabled: Option<String>,
    pub collector_status: Option<String>,
    pub last_snapshot_at: Option<String>,
    pub auth_failure_count_rolling: Option<u64>,
    pub connection_failure_count_rolling: Option<u64>,
    pub cert_min_days_remaining: Option<i64>,
    pub config_fingerprint_short: Option<String>,
    pub version: Option<String>,
    pub status: Option<String>,
    pub sessions_total: Option<u64>,
    pub sessions_status: Option<String>,
    pub cert_count: Option<u64>,
    pub days_remaining: Option<i64>,
    pub config_fingerprint_algorithm: Option<String>,
    pub config_fingerprint_status: Option<String>,
    pub config_fingerprint_prefix: Option<String>,
    pub request_id: Option<String>,
    pub target_node_id: Option<String>,
    pub target_endpoint_id: Option<String>,
    pub job_id: Option<String>,
    pub kind: Option<String>,
    pub skipped_tasks: Option<u64>,
    pub error_code: Option<String>,
    pub selector_class: Option<String>,
    pub reason_code: Option<String>,
    pub endpoint_trust_state: Option<String>,
    pub endpoint_status: Option<String>,
    pub source_node_id: Option<String>,
    pub source_endpoint_id: Option<String>,
    pub degraded_methods: Option<Vec<String>>,
}

impl ObservationSummaryPayloadV1 {
    pub fn from_legacy(method: &str, result_class: &str, value: &Value) -> Result<Self, String> {
        let mut fields = value.clone();
        let object = fields
            .as_object_mut()
            .ok_or_else(|| "observation summary must be an object".to_string())?;
        if let Some(embedded) = object.remove("result_class")
            && embedded.as_str() != Some(result_class)
        {
            return Err("observation summary result class is inconsistent".to_string());
        }
        let fields: ObservationSummaryFieldsV1 = serde_json::from_value(fields)
            .map_err(|_| "observation summary contains unsupported fields or values".to_string())?;
        let payload = Self {
            schema: OBSERVATION_SUMMARY_SCHEMA_V1.to_string(),
            result_class: result_class.to_string(),
            method: method.to_string(),
            fields,
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn from_value(value: &Value) -> Result<Self, String> {
        let payload: Self = serde_json::from_value(value.clone())
            .map_err(|_| "observation summary payload is not closed v1 data".to_string())?;
        payload.validate()?;
        Ok(payload)
    }

    pub fn to_value(&self) -> Value {
        let mut fields = serde_json::to_value(&self.fields).expect("observation fields serialize");
        fields
            .as_object_mut()
            .expect("observation fields are an object")
            .retain(|_, value| !value.is_null());
        serde_json::json!({
            "schema": self.schema,
            "result_class": self.result_class,
            "method": self.method,
            "fields": fields,
        })
    }

    pub fn public_summary(&self) -> Value {
        let mut value = serde_json::to_value(&self.fields).expect("observation fields serialize");
        let object = value
            .as_object_mut()
            .expect("observation fields are an object");
        object.retain(|_, value| !value.is_null());
        object.insert(
            "result_class".to_string(),
            Value::String(self.result_class.clone()),
        );
        value
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != OBSERVATION_SUMMARY_SCHEMA_V1 {
            return Err("observation summary payload schema is unsupported".to_string());
        }
        if !matches!(
            self.method.as_str(),
            "probe.controller.ping"
                | "probe.path.echo"
                | "ocserv.service.summary"
                | "ocserv.version"
                | "ocserv.sessions.summary"
                | "ocserv.cert.expiry"
                | "ocserv.config.fingerprint"
        ) {
            return Err("observation summary method is unsupported".to_string());
        }
        if !matches!(
            self.result_class.as_str(),
            "controller_rpc_summary" | "low_sensitive_summary" | "scheduler_summary"
        ) {
            return Err("observation summary result class is unsupported".to_string());
        }
        let fields = serde_json::to_value(&self.fields)
            .map_err(|error| format!("observation summary fields cannot serialize: {error}"))?;
        crate::store::validate_low_sensitive_json(&fields, "observation summary fields")
            .map_err(|error| error.to_string())?;
        if let Some(methods) = &self.fields.degraded_methods {
            HealthDegradedMethodsPayloadV1::new(methods.clone())?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerSelectorPayloadV1 {
    pub schema: String,
    pub selector: String,
    pub name: Option<String>,
}

impl SchedulerSelectorPayloadV1 {
    pub fn new(selector: String, name: Option<String>) -> Result<Self, String> {
        let payload = Self {
            schema: SCHEDULER_SELECTOR_SCHEMA_V1.to_string(),
            selector,
            name,
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn from_value(value: &Value) -> Result<Self, String> {
        let payload: Self = serde_json::from_value(value.clone())
            .map_err(|_| "scheduler selector payload is not closed v1 data".to_string())?;
        payload.validate()?;
        Ok(payload)
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("scheduler selector payload serializes")
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != SCHEDULER_SELECTOR_SCHEMA_V1 {
            return Err("scheduler selector payload schema is unsupported".to_string());
        }
        if self.selector == "explicit-pair" {
            // Pair identity is validated by SchedulerPairPayloadV1.
        } else if let Some(role) = self.selector.strip_prefix("role=") {
            validate_role(role).map_err(|error| error.to_string())?;
        } else if let Some(node_id) = self.selector.strip_prefix("node_id=") {
            validate_node_id(node_id).map_err(|error| error.to_string())?;
        } else {
            return Err(
                "scheduler selector must use role=<role>, node_id=<node-id>, or explicit-pair"
                    .to_string(),
            );
        }
        if let Some(name) = &self.name {
            validate_description(name)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerPairPayloadV1 {
    pub schema: String,
    pub source_node_id: String,
    pub target_node_id: String,
}

impl SchedulerPairPayloadV1 {
    pub fn new(source_node_id: String, target_node_id: String) -> Result<Self, String> {
        let payload = Self {
            schema: SCHEDULER_PAIR_SCHEMA_V1.to_string(),
            source_node_id,
            target_node_id,
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn from_value(value: &Value) -> Result<Self, String> {
        let payload: Self = serde_json::from_value(value.clone())
            .map_err(|_| "scheduler pair payload is not closed v1 data".to_string())?;
        payload.validate()?;
        Ok(payload)
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("scheduler pair payload serializes")
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != SCHEDULER_PAIR_SCHEMA_V1 {
            return Err("scheduler pair payload schema is unsupported".to_string());
        }
        validate_node_id(&self.source_node_id).map_err(|error| error.to_string())?;
        validate_node_id(&self.target_node_id).map_err(|error| error.to_string())?;
        if self.source_node_id == self.target_node_id {
            return Err("scheduler pair payload requires distinct nodes".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        ALERT_DETAIL_SCHEMA_V1, ALERT_HOST_ALLOW_SCHEMA_V1, AlertDetailPayloadV1,
        AlertHostAllowPayloadV1, HEALTH_DEGRADED_METHODS_SCHEMA_V1, HEALTH_SUMMARY_SCHEMA_V1,
        HealthDegradedMethodsPayloadV1, HealthSummaryPayloadV1, OBSERVATION_SUMMARY_SCHEMA_V1,
        ObservationSummaryPayloadV1, RUN_SUMMARY_SCHEMA_V1, RunSummaryPayloadV1,
        SCHEDULER_PAIR_SCHEMA_V1, SCHEDULER_SELECTOR_SCHEMA_V1, SchedulerPairPayloadV1,
        SchedulerSelectorPayloadV1, TRUST_BUNDLE_SCHEMA_V1, TrustBundlePayloadV1,
        validate_health_payload_relationship, validate_scheduler_payload_relationship,
    };

    #[test]
    fn scheduler_payloads_are_closed_versioned_and_bounded() {
        let selector = SchedulerSelectorPayloadV1::new(
            "node_id=hk-ocserv-01".to_string(),
            Some("primary".to_string()),
        )
        .expect("valid selector");
        assert_eq!(selector.schema, SCHEDULER_SELECTOR_SCHEMA_V1);
        assert_eq!(
            SchedulerSelectorPayloadV1::from_value(&selector.to_value()).expect("round trip"),
            selector
        );
        let pair =
            SchedulerPairPayloadV1::new("hk-ocserv-01".to_string(), "sg-ocserv-01".to_string())
                .expect("valid pair");
        assert_eq!(pair.schema, SCHEDULER_PAIR_SCHEMA_V1);
        assert_eq!(
            SchedulerPairPayloadV1::from_value(&pair.to_value()).expect("round trip"),
            pair
        );

        for contaminated in [
            json!({
                "schema": SCHEDULER_SELECTOR_SCHEMA_V1,
                "selector": "role=ocserv",
                "name": null,
                "token": "secret"
            }),
            json!({
                "schema": SCHEDULER_SELECTOR_SCHEMA_V1,
                "selector": "role=ocserv",
                "name": null,
                "client_address": "10.0.0.2"
            }),
            json!({
                "schema": SCHEDULER_SELECTOR_SCHEMA_V1,
                "selector": "role=ocserv",
                "name": null,
                "nested": {"raw": "value"}
            }),
            json!({
                "schema": SCHEDULER_SELECTOR_SCHEMA_V1,
                "selector": "role=ocserv",
                "name": null,
                "method": "shell.exec"
            }),
        ] {
            assert!(SchedulerSelectorPayloadV1::from_value(&contaminated).is_err());
        }
        assert!(
            SchedulerSelectorPayloadV1::from_value(&json!({
                "schema": "ocfleet.scheduler.selector.v2",
                "selector": "role=ocserv",
                "name": null
            }))
            .is_err()
        );
        assert!(SchedulerSelectorPayloadV1::new("role=/etc/passwd".to_string(), None).is_err());
        assert!(
            SchedulerSelectorPayloadV1::new("role=ocserv".to_string(), Some("x".repeat(257)))
                .is_err()
        );
        assert!(
            SchedulerPairPayloadV1::from_value(&json!({
                "schema": SCHEDULER_PAIR_SCHEMA_V1,
                "source_node_id": "source",
                "target_node_id": "target",
                "authorization": "Bearer secret"
            }))
            .is_err()
        );
        assert!(SchedulerPairPayloadV1::new("same".to_string(), "same".to_string()).is_err());
        assert!(validate_scheduler_payload_relationship("path-probe", &selector, None).is_err());
        assert!(
            validate_scheduler_payload_relationship("controller-ping", &selector, Some(&pair))
                .is_err()
        );
    }

    #[test]
    fn health_payloads_are_closed_versioned_and_bounded() {
        let methods = HealthDegradedMethodsPayloadV1::new(vec![
            "ocserv.version".to_string(),
            "ocserv.cert.expiry".to_string(),
            "ocserv.version".to_string(),
        ])
        .expect("valid methods");
        assert_eq!(methods.schema, HEALTH_DEGRADED_METHODS_SCHEMA_V1);
        assert_eq!(
            methods.methods,
            vec!["ocserv.cert.expiry", "ocserv.version"]
        );
        assert_eq!(
            HealthDegradedMethodsPayloadV1::from_value(&methods.to_value())
                .expect("methods round trip"),
            methods
        );

        let summary = HealthSummaryPayloadV1::new(
            Some("hk".to_string()),
            Some("ocserv".to_string()),
            "degraded".to_string(),
            Some("active".to_string()),
            Some(2),
        )
        .expect("valid summary");
        assert_eq!(summary.schema, HEALTH_SUMMARY_SCHEMA_V1);
        assert_eq!(
            HealthSummaryPayloadV1::from_value(&summary.to_value()).expect("summary round trip"),
            summary
        );
        validate_health_payload_relationship("degraded", &summary).expect("matching status");

        assert!(
            HealthDegradedMethodsPayloadV1::from_value(&json!({
                "schema": HEALTH_DEGRADED_METHODS_SCHEMA_V1,
                "methods": ["ocserv.version"],
                "client_address": "10.0.0.2"
            }))
            .is_err()
        );
        assert!(
            HealthDegradedMethodsPayloadV1::from_value(&json!({
                "schema": HEALTH_DEGRADED_METHODS_SCHEMA_V1,
                "methods": ["shell.exec"]
            }))
            .is_err()
        );
        assert!(
            HealthSummaryPayloadV1::from_value(&json!({
                "schema": HEALTH_SUMMARY_SCHEMA_V1,
                "region": "hk",
                "role": "ocserv",
                "status": "healthy",
                "endpoint_status": "active",
                "consecutive_failures": 0,
                "token": "secret"
            }))
            .is_err()
        );
        assert!(
            HealthSummaryPayloadV1::new(
                Some("hk".to_string()),
                Some("ocserv".to_string()),
                "healthy".to_string(),
                None,
                Some(1_001),
            )
            .is_err()
        );
        assert!(validate_health_payload_relationship("healthy", &summary).is_err());
    }

    #[test]
    fn observation_summary_payload_is_closed_versioned_and_relationally_bound() {
        let payload = ObservationSummaryPayloadV1::from_legacy(
            "ocserv.cert.expiry",
            "low_sensitive_summary",
            &json!({
                "result_class": "low_sensitive_summary",
                "days_remaining": 12,
                "status": "ok"
            }),
        )
        .expect("valid observation summary");
        assert_eq!(payload.schema, OBSERVATION_SUMMARY_SCHEMA_V1);
        assert_eq!(
            ObservationSummaryPayloadV1::from_value(&payload.to_value()).expect("round trip"),
            payload
        );
        assert_eq!(payload.public_summary()["days_remaining"], 12);
        assert!(
            ObservationSummaryPayloadV1::from_legacy(
                "probe.controller.ping",
                "controller_rpc_summary",
                &json!({"client_address": "10.0.0.2"}),
            )
            .is_err()
        );
        assert!(
            ObservationSummaryPayloadV1::from_legacy(
                "probe.controller.ping",
                "future_summary",
                &json!({}),
            )
            .is_err()
        );
        let mut contaminated = payload.to_value();
        contaminated["fields"]["token"] = json!("secret");
        assert!(ObservationSummaryPayloadV1::from_value(&contaminated).is_err());
    }

    #[test]
    fn run_summary_payload_is_closed_versioned_and_relationally_bound() {
        let payload = RunSummaryPayloadV1::from_legacy(
            Some("job-a"),
            Some("controller-ping"),
            "succeeded",
            "scheduler.run.once",
            &json!({
                "result_class": "scheduler_summary",
                "observations": 4,
                "failed_observations": 1
            }),
        )
        .expect("valid run summary");
        assert_eq!(payload.schema, RUN_SUMMARY_SCHEMA_V1);
        assert_eq!(payload.kind.as_deref(), Some("controller-ping"));
        assert_eq!(
            RunSummaryPayloadV1::from_value(&payload.to_value()).expect("round trip"),
            payload
        );
        payload
            .validate_relationship(
                Some("job-a"),
                Some("controller-ping"),
                "succeeded",
                "scheduler.run.once",
            )
            .expect("matching relationship");
        assert_eq!(payload.public_summary()["observations"], 4);

        let mut contaminated = payload.to_value();
        contaminated["token"] = json!("secret");
        assert!(RunSummaryPayloadV1::from_value(&contaminated).is_err());
        assert!(
            RunSummaryPayloadV1::from_legacy(
                Some("job-a"),
                Some("controller-ping"),
                "succeeded",
                "scheduler.run.once",
                &json!({"client_address": "10.0.0.2"}),
            )
            .is_err()
        );
        assert!(
            RunSummaryPayloadV1::new(
                None,
                None,
                "succeeded".to_string(),
                "manual".to_string(),
                Some(1),
                Some(2),
            )
            .is_err()
        );
        assert!(
            payload
                .validate_relationship(
                    Some("job-b"),
                    Some("controller-ping"),
                    "succeeded",
                    "scheduler.run.once",
                )
                .is_err()
        );
    }

    #[test]
    fn trust_bundle_payload_is_closed_versioned_bounded_and_relationally_bound() {
        let payload = TrustBundlePayloadV1::from_legacy(
            "endpoint-a",
            2,
            "active",
            &json!({
                "endpoint_id": "endpoint-a",
                "generation": 2,
                "status": "active",
                "trusted_controllers": ["controller-a"],
                "trusted_peers": ["peer-a"],
                "authorized_path_probes": [["endpoint-a", "peer-a"]]
            }),
        )
        .expect("valid trust bundle");
        assert_eq!(payload.schema, TRUST_BUNDLE_SCHEMA_V1);
        assert_eq!(
            TrustBundlePayloadV1::from_value(&payload.to_value()).expect("round trip"),
            payload
        );
        payload
            .validate_relationship("endpoint-a", 2, "active")
            .expect("matching relationship");
        assert_eq!(payload.public_bundle()["trusted_peers"], json!(["peer-a"]));

        let mut contaminated = payload.to_value();
        contaminated["token"] = json!("secret");
        assert!(TrustBundlePayloadV1::from_value(&contaminated).is_err());
        assert!(
            TrustBundlePayloadV1::from_legacy(
                "endpoint-a",
                2,
                "active",
                &json!({"client_address": "10.0.0.2"}),
            )
            .is_err()
        );
        assert!(
            TrustBundlePayloadV1::new(
                "endpoint-a".to_string(),
                2,
                "active".to_string(),
                vec!["duplicate".to_string(), "duplicate".to_string()],
                Vec::new(),
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            payload
                .validate_relationship("endpoint-a", 3, "active")
                .is_err()
        );
    }

    #[test]
    fn alert_detail_payload_is_closed_versioned_and_bounded() {
        let payload = AlertDetailPayloadV1::from_legacy(&json!({
            "methods": ["ocserv.cert.expiry"],
            "days_remaining": 12,
            "status": "warning",
            "silenced_until": "2026-07-12T00:00:00Z",
            "silence_reason": "maintenance"
        }))
        .expect("valid alert detail");
        assert_eq!(payload.schema, ALERT_DETAIL_SCHEMA_V1);
        assert_eq!(
            AlertDetailPayloadV1::from_value(&payload.to_value()).expect("round trip"),
            payload
        );
        assert_eq!(payload.public_detail()["summary"]["days_remaining"], 12);

        let mut contaminated = payload.to_value();
        contaminated["token"] = json!("secret");
        assert!(AlertDetailPayloadV1::from_value(&contaminated).is_err());
        assert!(
            AlertDetailPayloadV1::from_legacy(&json!({
                "methods": ["shell.exec"],
                "summary": {}
            }))
            .is_err()
        );
        assert!(
            AlertDetailPayloadV1::from_legacy(&json!({
                "summary": {"status": "stale"},
                "status": "stale"
            }))
            .is_err()
        );
        assert!(
            AlertDetailPayloadV1::from_legacy(&json!({
                "methods": [],
                "summary": {},
                "client_address": "10.0.0.2"
            }))
            .is_err()
        );
    }

    #[test]
    fn alert_host_allow_payload_is_closed_versioned_and_canonical() {
        let payload = AlertHostAllowPayloadV1::from_legacy(&json!([
            "alerts.example.com.",
            "93.184.216.34",
            "ALERTS.EXAMPLE.COM"
        ]))
        .expect("valid legacy host allowlist");
        assert_eq!(payload.schema, ALERT_HOST_ALLOW_SCHEMA_V1);
        assert_eq!(payload.hosts, vec!["93.184.216.34", "alerts.example.com"]);
        payload
            .validate_relationship("alerts.example.com")
            .expect("endpoint host is allowed");
        assert_eq!(
            AlertHostAllowPayloadV1::from_value(&payload.to_value()).expect("round trip"),
            payload
        );

        let mut contaminated = payload.to_value();
        contaminated["client_address"] = json!("10.0.0.2");
        assert!(AlertHostAllowPayloadV1::from_value(&contaminated).is_err());
        assert!(
            AlertHostAllowPayloadV1::from_value(&json!({
                "schema": ALERT_HOST_ALLOW_SCHEMA_V1,
                "hosts": ["alerts.example.com", "93.184.216.34"]
            }))
            .is_err()
        );
        assert!(AlertHostAllowPayloadV1::from_legacy(&json!(["localhost"])).is_err());
    }
}
