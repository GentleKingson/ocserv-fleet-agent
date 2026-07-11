use ocfleet_config::validation::{validate_node_id, validate_region, validate_role};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::input_validation::validate_description;

pub const SCHEDULER_SELECTOR_SCHEMA_V1: &str = "ocfleet.scheduler.selector.v1";
pub const SCHEDULER_PAIR_SCHEMA_V1: &str = "ocfleet.scheduler.pair.v1";
pub const HEALTH_DEGRADED_METHODS_SCHEMA_V1: &str = "ocfleet.health.degraded-methods.v1";
pub const HEALTH_SUMMARY_SCHEMA_V1: &str = "ocfleet.health.summary.v1";
pub const OBSERVATION_SUMMARY_SCHEMA_V1: &str = "ocfleet.observation.summary.v1";

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
        HEALTH_DEGRADED_METHODS_SCHEMA_V1, HEALTH_SUMMARY_SCHEMA_V1,
        HealthDegradedMethodsPayloadV1, HealthSummaryPayloadV1, OBSERVATION_SUMMARY_SCHEMA_V1,
        ObservationSummaryPayloadV1, SCHEDULER_PAIR_SCHEMA_V1, SCHEDULER_SELECTOR_SCHEMA_V1,
        SchedulerPairPayloadV1, SchedulerSelectorPayloadV1, validate_health_payload_relationship,
        validate_scheduler_payload_relationship,
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
}
