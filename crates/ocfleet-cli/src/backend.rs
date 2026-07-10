use crate::audit::AuditEvent;
use crate::store::{
    AlertEventRecord, ApprovalInput, AuditRecord, EndpointTrustRecord, HealthPolicyRecord,
    HealthSnapshotRecord, NodeInsert, NodeRecord, ObservabilityJobRecord, ObservabilityRunRecord,
    ProbeObservationRecord, SchedulerOutcomeWrite, SchedulerRunFinish, SchedulerRunStart, Store,
    StoreError,
};

pub const MAX_STORE_READER_ROWS: u64 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendKind {
    Sqlite,
    PostgresPlanned,
}

/// Backend-neutral read contract. Every history query carries an explicit cap.
pub trait StoreReader {
    type Error;

    fn backend_kind(&self) -> BackendKind;
    fn read_nodes(&self, limit: u64) -> Result<Vec<NodeRecord>, Self::Error>;
    fn read_node(&self, node_id: &str) -> Result<Option<NodeRecord>, Self::Error>;
    fn read_jobs(&self, limit: u64) -> Result<Vec<ObservabilityJobRecord>, Self::Error>;
    fn read_runs(&self, limit: u64) -> Result<Vec<ObservabilityRunRecord>, Self::Error>;
    fn read_observations(
        &self,
        node_id: Option<&str>,
        method: Option<&str>,
        limit: u64,
    ) -> Result<Vec<ProbeObservationRecord>, Self::Error>;
    fn read_health_snapshots(&self, limit: u64) -> Result<Vec<HealthSnapshotRecord>, Self::Error>;
    fn read_alerts(&self, limit: u64) -> Result<Vec<AlertEventRecord>, Self::Error>;
    fn read_audit_window(
        &self,
        from: &str,
        to: &str,
        limit: usize,
    ) -> Result<Vec<AuditRecord>, Self::Error>;
}

/// Mutations exposed here already take an actor and write their audit row in
/// the same SQLite transaction. Legacy call sites that do not yet meet that
/// contract intentionally remain outside this trait.
pub trait StoreWriter {
    type Error;

    fn write_node_add(&self, node: &NodeInsert, actor: &str) -> Result<(), Self::Error>;
    fn write_node_enable(&self, node_id: &str, actor: &str) -> Result<(), Self::Error>;
    fn write_node_disable(&self, node_id: &str, actor: &str) -> Result<(), Self::Error>;
    fn write_node_remove(&self, node_id: &str, actor: &str) -> Result<(), Self::Error>;
    fn write_scheduler_job_add(
        &self,
        job: &ObservabilityJobRecord,
        actor: &str,
    ) -> Result<(), Self::Error>;
    fn write_scheduler_job_enable(&self, job_id: &str, actor: &str) -> Result<(), Self::Error>;
    fn write_scheduler_job_disable(&self, job_id: &str, actor: &str) -> Result<(), Self::Error>;
    fn write_scheduler_run_start(
        &self,
        start: &SchedulerRunStart,
        actor: &str,
    ) -> Result<(), Self::Error>;
    fn write_scheduler_outcome(
        &self,
        outcome: &SchedulerOutcomeWrite,
        actor: &str,
    ) -> Result<(), Self::Error>;
    fn write_scheduler_run_finish(
        &self,
        finish: &SchedulerRunFinish,
        actor: &str,
    ) -> Result<(), Self::Error>;
    fn write_health_policy(
        &self,
        policy: &HealthPolicyRecord,
        actor: &str,
    ) -> Result<(), Self::Error>;
    fn write_enrollment_approval(
        &self,
        approval: &ApprovalInput,
    ) -> Result<crate::store::JoinRequestRecord, Self::Error>;
    fn write_endpoint_rotation(
        &self,
        old_endpoint_id: &str,
        new_endpoint_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<EndpointTrustRecord, Self::Error>;
    fn write_endpoint_revocation(
        &self,
        endpoint_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<EndpointTrustRecord, Self::Error>;
    fn write_endpoint_quarantine(
        &self,
        endpoint_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<EndpointTrustRecord, Self::Error>;
}

pub trait MigrationManager {
    type Error;

    fn schema_version(&self) -> Result<i64, Self::Error>;
    fn migration_backend(&self) -> BackendKind;
}

pub trait AuditWriter {
    type Error;

    fn append_audit(&self, event: &AuditEvent) -> Result<(), Self::Error>;
}

impl StoreReader for Store {
    type Error = StoreError;

    fn backend_kind(&self) -> BackendKind {
        BackendKind::Sqlite
    }

    fn read_nodes(&self, limit: u64) -> Result<Vec<NodeRecord>, Self::Error> {
        checked_limit(limit)?;
        Store::list_nodes_limited(self, limit)
    }

    fn read_node(&self, node_id: &str) -> Result<Option<NodeRecord>, Self::Error> {
        Store::get_node(self, node_id)
    }

    fn read_jobs(&self, limit: u64) -> Result<Vec<ObservabilityJobRecord>, Self::Error> {
        checked_limit(limit)?;
        let rows = Store::list_observability_jobs_limited(self, limit)?;
        for row in &rows {
            crate::store::validate_low_sensitive_json(&row.selector_json, "job selector")?;
            if let Some(pair) = &row.pair_selector_json {
                crate::store::validate_low_sensitive_json(pair, "job pair selector")?;
            }
        }
        Ok(rows)
    }

    fn read_runs(&self, limit: u64) -> Result<Vec<ObservabilityRunRecord>, Self::Error> {
        checked_limit(limit)?;
        let rows = Store::list_observability_runs(self, limit)?;
        for row in &rows {
            crate::store::validate_low_sensitive_json(&row.summary_json, "run summary")?;
        }
        Ok(rows)
    }

    fn read_observations(
        &self,
        node_id: Option<&str>,
        method: Option<&str>,
        limit: u64,
    ) -> Result<Vec<ProbeObservationRecord>, Self::Error> {
        checked_limit(limit)?;
        let rows = Store::list_probe_observations_filtered(self, node_id, method, limit)?;
        for row in &rows {
            crate::store::validate_low_sensitive_json(&row.summary_json, "observation summary")?;
        }
        Ok(rows)
    }

    fn read_health_snapshots(&self, limit: u64) -> Result<Vec<HealthSnapshotRecord>, Self::Error> {
        checked_limit(limit)?;
        let rows = Store::list_health_snapshots_limited(self, limit)?;
        for row in &rows {
            crate::store::validate_low_sensitive_json(
                &row.degraded_methods_json,
                "health degraded methods",
            )?;
            crate::store::validate_low_sensitive_json(&row.summary_json, "health summary")?;
        }
        Ok(rows)
    }

    fn read_alerts(&self, limit: u64) -> Result<Vec<AlertEventRecord>, Self::Error> {
        checked_limit(limit)?;
        let rows = Store::list_alert_events_limited(self, limit)?;
        for row in &rows {
            crate::store::validate_low_sensitive_json(&row.detail_json, "alert detail")?;
        }
        Ok(rows)
    }

    fn read_audit_window(
        &self,
        from: &str,
        to: &str,
        limit: usize,
    ) -> Result<Vec<AuditRecord>, Self::Error> {
        if limit == 0 || limit > MAX_STORE_READER_ROWS as usize {
            return Err(invalid_limit());
        }
        let rows = Store::list_audit_window(self, from, to, limit)?;
        for row in &rows {
            crate::store::validate_low_sensitive_json(&row.detail_json, "audit detail")?;
        }
        Ok(rows)
    }
}

impl StoreWriter for Store {
    type Error = StoreError;

    fn write_node_add(&self, node: &NodeInsert, actor: &str) -> Result<(), Self::Error> {
        Store::add_node(self, node, actor)
    }

    fn write_node_enable(&self, node_id: &str, actor: &str) -> Result<(), Self::Error> {
        Store::enable_node(self, node_id, actor)
    }

    fn write_node_disable(&self, node_id: &str, actor: &str) -> Result<(), Self::Error> {
        Store::disable_node(self, node_id, actor)
    }

    fn write_node_remove(&self, node_id: &str, actor: &str) -> Result<(), Self::Error> {
        Store::remove_node(self, node_id, actor)
    }

    fn write_scheduler_job_add(
        &self,
        job: &ObservabilityJobRecord,
        actor: &str,
    ) -> Result<(), Self::Error> {
        Store::insert_observability_job(self, job, actor)
    }

    fn write_scheduler_job_enable(&self, job_id: &str, actor: &str) -> Result<(), Self::Error> {
        Store::set_observability_job_enabled(self, job_id, true, actor)
    }

    fn write_scheduler_job_disable(&self, job_id: &str, actor: &str) -> Result<(), Self::Error> {
        Store::set_observability_job_enabled(self, job_id, false, actor)
    }

    fn write_scheduler_run_start(
        &self,
        start: &SchedulerRunStart,
        actor: &str,
    ) -> Result<(), Self::Error> {
        Store::write_scheduler_run_start(self, start, actor)
    }

    fn write_scheduler_outcome(
        &self,
        outcome: &SchedulerOutcomeWrite,
        actor: &str,
    ) -> Result<(), Self::Error> {
        Store::write_scheduler_outcome(self, outcome, actor)
    }

    fn write_scheduler_run_finish(
        &self,
        finish: &SchedulerRunFinish,
        actor: &str,
    ) -> Result<(), Self::Error> {
        Store::write_scheduler_run_finish(self, finish, actor)
    }

    fn write_health_policy(
        &self,
        policy: &HealthPolicyRecord,
        actor: &str,
    ) -> Result<(), Self::Error> {
        Store::set_health_policy(self, policy, actor)
    }

    fn write_enrollment_approval(
        &self,
        approval: &ApprovalInput,
    ) -> Result<crate::store::JoinRequestRecord, Self::Error> {
        Store::approve_join_request(self, approval)
    }

    fn write_endpoint_rotation(
        &self,
        old_endpoint_id: &str,
        new_endpoint_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<EndpointTrustRecord, Self::Error> {
        Store::rotate_endpoint(self, old_endpoint_id, new_endpoint_id, actor, reason)
    }

    fn write_endpoint_revocation(
        &self,
        endpoint_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<EndpointTrustRecord, Self::Error> {
        Store::revoke_endpoint(self, endpoint_id, actor, reason)
    }

    fn write_endpoint_quarantine(
        &self,
        endpoint_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<EndpointTrustRecord, Self::Error> {
        Store::quarantine_endpoint(self, endpoint_id, actor, reason)
    }
}

impl MigrationManager for Store {
    type Error = StoreError;

    fn schema_version(&self) -> Result<i64, Self::Error> {
        Store::current_schema_version(self)
    }

    fn migration_backend(&self) -> BackendKind {
        BackendKind::Sqlite
    }
}

impl AuditWriter for Store {
    type Error = StoreError;

    fn append_audit(&self, event: &AuditEvent) -> Result<(), Self::Error> {
        Store::insert_audit(self, event)
    }
}

fn checked_limit(limit: u64) -> Result<usize, StoreError> {
    if limit == 0 || limit > MAX_STORE_READER_ROWS {
        return Err(invalid_limit());
    }
    usize::try_from(limit).map_err(|_| invalid_limit())
}

fn invalid_limit() -> StoreError {
    StoreError::InvalidInput(format!(
        "store reader limit must be between 1 and {MAX_STORE_READER_ROWS}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use serde_json::json;

    #[test]
    fn sqlite_reader_rejects_unbounded_queries() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Store::open(&dir.path().join("controller.sqlite")).expect("open store");
        assert!(StoreReader::read_nodes(&store, 0).is_err());
        assert!(StoreReader::read_alerts(&store, MAX_STORE_READER_ROWS + 1).is_err());
    }

    #[test]
    fn sqlite_migration_contract_reports_current_backend() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Store::open(&dir.path().join("controller.sqlite")).expect("open store");
        assert_eq!(
            MigrationManager::schema_version(&store).expect("schema version"),
            crate::store::CURRENT_SCHEMA_VERSION
        );
        assert_eq!(
            MigrationManager::migration_backend(&store),
            BackendKind::Sqlite
        );
    }

    #[test]
    fn generic_audit_writer_rejects_unbounded_or_unsafe_fields() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Store::open(&dir.path().join("controller.sqlite")).expect("open store");

        let mut event = AuditEvent::new("operator", "backend.test");
        event.ts = "/etc/passwd".to_string();
        assert!(AuditWriter::append_audit(&store, &event).is_err());

        event = AuditEvent::new("operator", "backend.test");
        event.duration_ms = Some(u64::MAX);
        assert!(AuditWriter::append_audit(&store, &event).is_err());

        event = AuditEvent::new("operator", "backend.test");
        event.detail_json = serde_json::json!({"secret": "hunter2"});
        assert!(AuditWriter::append_audit(&store, &event).is_err());
        assert_eq!(store.audit_count().expect("audit count"), 0);
    }

    #[test]
    fn sqlite_reader_fails_closed_on_legacy_contaminated_json() {
        let dir = tempfile::tempdir().expect("temp dir");
        let database = dir.path().join("controller.sqlite");
        let store = Store::open(&database).expect("open store");
        store
            .insert_probe_observation(&crate::store::ProbeObservationInsert {
                observation_id: "obs-legacy".to_string(),
                run_id: None,
                node_id: None,
                endpoint_id: None,
                method: "probe.controller.ping".to_string(),
                ok: Some(true),
                error_code: None,
                duration_ms: Some(1),
                observed_at: "2026-07-09T00:00:00Z".to_string(),
                expires_at: None,
                result_class: "controller_rpc_summary".to_string(),
                summary_json: json!({"message": "pong"}),
            })
            .expect("insert safe observation");
        Connection::open(&database)
            .expect("open legacy fixture connection")
            .execute(
                "UPDATE probe_observations SET summary_json = ?1 WHERE observation_id = ?2",
                [
                    json!({"client_address": "10.0.0.2"}).to_string(),
                    "obs-legacy".to_string(),
                ],
            )
            .expect("inject legacy contamination");

        assert!(StoreReader::read_observations(&store, None, None, 10).is_err());
    }
}
