use ocfleet_protocol::ocserv::{
    OcservCollectorStatus, OcservServiceEnabledState, OcservServiceState,
};
use ocfleet_snapshot_schema::producer::SnapshotProducer;
use ocfleet_snapshot_schema::{SCHEMA_VERSION_V2, SnapshotDocument};
use std::path::PathBuf;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: minimal-producer /absolute/private/snapshot.json")?;
    let snapshot = SnapshotDocument {
        schema_version: SCHEMA_VERSION_V2.to_string(),
        collected_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
        collector_status: OcservCollectorStatus::Ok,
        service_state: OcservServiceState::Running,
        enabled_state: OcservServiceEnabledState::Enabled,
        version: None,
        session_total: Some(0),
        auth_failure_count_rolling: None,
        connection_failure_count_rolling: None,
        cert_min_days_remaining: None,
        config_fingerprint_short: None,
    };
    SnapshotProducer::new(output)?.publish(&snapshot)?;
    Ok(())
}
