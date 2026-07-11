use ocfleet_config::validation::{validate_node_id, validate_role};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::input_validation::validate_description;

pub const SCHEDULER_SELECTOR_SCHEMA_V1: &str = "ocfleet.scheduler.selector.v1";
pub const SCHEDULER_PAIR_SCHEMA_V1: &str = "ocfleet.scheduler.pair.v1";

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
        SCHEDULER_PAIR_SCHEMA_V1, SCHEDULER_SELECTOR_SCHEMA_V1, SchedulerPairPayloadV1,
        SchedulerSelectorPayloadV1, validate_scheduler_payload_relationship,
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
}
