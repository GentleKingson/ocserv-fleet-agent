use std::path::{Path, PathBuf};

use ocfleet_cli::store::{
    AlertEventRecord, AuditRecord, HealthSnapshotRecord, NodeRecord, ObservabilityJobRecord,
    ObservabilityRunRecord, ProbeObservationRecord,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, params, types::Type};
use serde_json::Value;

#[derive(Clone)]
pub struct ReadOnlyStore {
    database: PathBuf,
}

#[derive(Debug, Clone)]
pub struct NodeHealthRecord {
    pub node: NodeRecord,
    pub snapshot: Option<HealthSnapshotRecord>,
}

impl ReadOnlyStore {
    pub fn new(database: PathBuf) -> Self {
        Self { database }
    }

    pub fn check_readable(&self) -> rusqlite::Result<()> {
        let conn = self.open_conn()?;
        let _: i64 = conn.query_row("SELECT count(*) FROM schema_migrations", [], |row| {
            row.get(0)
        })?;
        Ok(())
    }

    pub fn list_node_health(&self, limit: u64) -> rusqlite::Result<Vec<NodeHealthRecord>> {
        let limit = u64_to_i64(limit, "limit")?;
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT n.node_id, n.endpoint_id, n.name, n.region, n.role, n.enabled,
                    h.node_id, h.endpoint_id, h.computed_at, h.status, h.freshness_seconds,
                    h.last_success_at, h.last_failure_at, h.last_error_code,
                    h.degraded_methods_json, h.summary_json
             FROM nodes n
             LEFT JOIN health_snapshots h ON h.node_id = n.node_id
             ORDER BY n.node_id
             LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], node_health_from_row)?;
        rows.collect()
    }

    pub fn get_node_health(&self, node_id: &str) -> rusqlite::Result<Option<NodeHealthRecord>> {
        let conn = self.open_conn()?;
        conn.query_row(
            "SELECT n.node_id, n.endpoint_id, n.name, n.region, n.role, n.enabled,
                    h.node_id, h.endpoint_id, h.computed_at, h.status, h.freshness_seconds,
                    h.last_success_at, h.last_failure_at, h.last_error_code,
                    h.degraded_methods_json, h.summary_json
             FROM nodes n
             LEFT JOIN health_snapshots h ON h.node_id = n.node_id
             WHERE n.node_id = ?1",
            [node_id],
            node_health_from_row,
        )
        .optional()
    }

    pub fn list_jobs(&self, limit: u64) -> rusqlite::Result<Vec<ObservabilityJobRecord>> {
        let limit = u64_to_i64(limit, "limit")?;
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT job_id, kind, selector_json, pair_selector_json, interval_seconds,
                    jitter_seconds, timeout_ms, enabled, next_run_at, last_run_at,
                    created_at, updated_at
             FROM observability_jobs
             ORDER BY job_id
             LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], observability_job_from_row)?;
        rows.collect()
    }

    pub fn get_job(&self, job_id: &str) -> rusqlite::Result<Option<ObservabilityJobRecord>> {
        let conn = self.open_conn()?;
        conn.query_row(
            "SELECT job_id, kind, selector_json, pair_selector_json, interval_seconds,
                    jitter_seconds, timeout_ms, enabled, next_run_at, last_run_at,
                    created_at, updated_at
             FROM observability_jobs
             WHERE job_id = ?1",
            [job_id],
            observability_job_from_row,
        )
        .optional()
    }

    pub fn list_runs(
        &self,
        limit: u64,
        job_id: Option<&str>,
        status: Option<&str>,
    ) -> rusqlite::Result<Vec<ObservabilityRunRecord>> {
        let limit = u64_to_i64(limit, "limit")?;
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT r.run_id, r.job_id, r.started_at, r.finished_at, r.status,
                    r.triggered_by, r.summary_json,
                    COUNT(o.observation_id) AS observation_count,
                    COALESCE(SUM(CASE WHEN o.ok = 0 THEN 1 ELSE 0 END), 0)
                      AS failed_observation_count
             FROM observability_runs r
             LEFT JOIN probe_observations o ON o.run_id = r.run_id
             WHERE (?1 IS NULL OR r.job_id = ?1)
               AND (?2 IS NULL OR r.status = ?2)
             GROUP BY r.run_id, r.job_id, r.started_at, r.finished_at, r.status,
                      r.triggered_by, r.summary_json
             ORDER BY r.started_at DESC, r.run_id DESC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![job_id, status, limit], observability_run_from_row)?;
        rows.collect()
    }

    pub fn get_run(&self, run_id: &str) -> rusqlite::Result<Option<ObservabilityRunRecord>> {
        let conn = self.open_conn()?;
        conn.query_row(
            "SELECT r.run_id, r.job_id, r.started_at, r.finished_at, r.status,
                    r.triggered_by, r.summary_json,
                    COUNT(o.observation_id) AS observation_count,
                    COALESCE(SUM(CASE WHEN o.ok = 0 THEN 1 ELSE 0 END), 0)
                      AS failed_observation_count
             FROM observability_runs r
             LEFT JOIN probe_observations o ON o.run_id = r.run_id
             WHERE r.run_id = ?1
             GROUP BY r.run_id, r.job_id, r.started_at, r.finished_at, r.status,
                      r.triggered_by, r.summary_json",
            [run_id],
            observability_run_from_row,
        )
        .optional()
    }

    pub fn list_observations(
        &self,
        limit: u64,
        node_id: Option<&str>,
        method: Option<&str>,
    ) -> rusqlite::Result<Vec<ProbeObservationRecord>> {
        let limit = u64_to_i64(limit, "limit")?;
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT observation_id, run_id, node_id, endpoint_id, method, ok, error_code,
                    duration_ms, observed_at, expires_at, result_class, summary_json
             FROM probe_observations
             WHERE (?1 IS NULL OR node_id = ?1)
               AND (?2 IS NULL OR method = ?2)
             ORDER BY observed_at DESC, observation_id DESC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![node_id, method, limit], probe_observation_from_row)?;
        rows.collect()
    }

    pub fn get_observation(
        &self,
        observation_id: &str,
    ) -> rusqlite::Result<Option<ProbeObservationRecord>> {
        let conn = self.open_conn()?;
        conn.query_row(
            "SELECT observation_id, run_id, node_id, endpoint_id, method, ok, error_code,
                    duration_ms, observed_at, expires_at, result_class, summary_json
             FROM probe_observations
             WHERE observation_id = ?1",
            [observation_id],
            probe_observation_from_row,
        )
        .optional()
    }

    pub fn list_alerts(
        &self,
        limit: u64,
        state: Option<&str>,
        severity: Option<&str>,
        node_id: Option<&str>,
    ) -> rusqlite::Result<Vec<AlertEventRecord>> {
        let limit = u64_to_i64(limit, "limit")?;
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT alert_id, dedupe_key, node_id, severity, state, reason_code,
                    first_seen_at, last_seen_at, last_sent_at, resolved_at, detail_json
             FROM alert_events
             WHERE (?1 IS NULL OR state = ?1)
               AND (?2 IS NULL OR severity = ?2)
               AND (?3 IS NULL OR node_id = ?3)
             ORDER BY last_seen_at DESC, alert_id
             LIMIT ?4",
        )?;
        let rows = stmt.query_map(
            params![state, severity, node_id, limit],
            alert_event_from_row,
        )?;
        rows.collect()
    }

    pub fn get_alert(&self, lookup: &str) -> rusqlite::Result<Option<AlertEventRecord>> {
        let conn = self.open_conn()?;
        conn.query_row(
            "SELECT alert_id, dedupe_key, node_id, severity, state, reason_code,
                    first_seen_at, last_seen_at, last_sent_at, resolved_at, detail_json
             FROM alert_events
             WHERE alert_id = ?1 OR dedupe_key = ?1
             ORDER BY last_seen_at DESC, alert_id
             LIMIT 1",
            [lookup],
            alert_event_from_row,
        )
        .optional()
    }

    pub fn list_audit_window(
        &self,
        from: &str,
        to: &str,
        limit: u64,
    ) -> rusqlite::Result<Vec<AuditRecord>> {
        let limit = u64_to_i64(limit, "limit")?;
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, ts, actor, event, node_id, endpoint_id, method, request_id,
                    params_hash, ok, error_code, duration_ms, detail_json
             FROM controller_audit_log
             WHERE ts >= ?1 AND ts < ?2
             ORDER BY ts ASC, id ASC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![from, to, limit], audit_record_from_row)?;
        rows.collect()
    }

    fn open_conn(&self) -> rusqlite::Result<Connection> {
        open_read_only_connection(&self.database)
    }
}

fn open_read_only_connection(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.pragma_update(None, "busy_timeout", 5_000)?;
    conn.pragma_update(None, "query_only", "ON")?;
    Ok(conn)
}

fn node_health_from_row(row: &Row<'_>) -> rusqlite::Result<NodeHealthRecord> {
    let node = NodeRecord {
        node_id: row.get(0)?,
        endpoint_id: row.get(1)?,
        name: row.get(2)?,
        region: row.get(3)?,
        role: row.get(4)?,
        enabled: i64_to_bool(row.get(5)?, 5)?,
    };
    let snapshot_node_id: Option<String> = row.get(6)?;
    let snapshot = snapshot_node_id
        .map(|node_id| {
            let degraded_methods_json: String = row.get(14)?;
            let summary_json: String = row.get(15)?;
            let freshness_seconds: Option<i64> = row.get(10)?;
            Ok::<HealthSnapshotRecord, rusqlite::Error>(HealthSnapshotRecord {
                node_id,
                endpoint_id: row.get(7)?,
                computed_at: row.get(8)?,
                status: row.get(9)?,
                freshness_seconds: freshness_seconds.and_then(|value| u64::try_from(value).ok()),
                last_success_at: row.get(11)?,
                last_failure_at: row.get(12)?,
                last_error_code: row.get(13)?,
                degraded_methods_json: parse_json_column(&degraded_methods_json, 14)?,
                summary_json: parse_json_column(&summary_json, 15)?,
            })
        })
        .transpose()?;
    Ok(NodeHealthRecord { node, snapshot })
}

fn observability_job_from_row(row: &Row<'_>) -> rusqlite::Result<ObservabilityJobRecord> {
    let selector_json: String = row.get(2)?;
    let pair_selector_json: Option<String> = row.get(3)?;
    Ok(ObservabilityJobRecord {
        job_id: row.get(0)?,
        kind: row.get(1)?,
        selector_json: parse_json_column(&selector_json, 2)?,
        pair_selector_json: pair_selector_json
            .as_deref()
            .map(|value| parse_json_column(value, 3))
            .transpose()?,
        interval_seconds: i64_to_u64(row.get(4)?, 4)?,
        jitter_seconds: i64_to_u64(row.get(5)?, 5)?,
        timeout_ms: i64_to_u64(row.get(6)?, 6)?,
        enabled: i64_to_bool(row.get(7)?, 7)?,
        next_run_at: row.get(8)?,
        last_run_at: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

fn observability_run_from_row(row: &Row<'_>) -> rusqlite::Result<ObservabilityRunRecord> {
    let summary_json: String = row.get(6)?;
    Ok(ObservabilityRunRecord {
        run_id: row.get(0)?,
        job_id: row.get(1)?,
        started_at: row.get(2)?,
        finished_at: row.get(3)?,
        status: row.get(4)?,
        triggered_by: row.get(5)?,
        summary_json: parse_json_column(&summary_json, 6)?,
        observation_count: i64_to_u64(row.get(7)?, 7)?,
        failed_observation_count: i64_to_u64(row.get(8)?, 8)?,
    })
}

fn probe_observation_from_row(row: &Row<'_>) -> rusqlite::Result<ProbeObservationRecord> {
    let ok: Option<i64> = row.get(5)?;
    let duration_ms: Option<i64> = row.get(7)?;
    let summary_json: String = row.get(11)?;
    Ok(ProbeObservationRecord {
        observation_id: row.get(0)?,
        run_id: row.get(1)?,
        node_id: row.get(2)?,
        endpoint_id: row.get(3)?,
        method: row.get(4)?,
        ok: ok.map(|value| i64_to_bool(value, 5)).transpose()?,
        error_code: row.get(6)?,
        duration_ms: duration_ms.and_then(|value| u64::try_from(value).ok()),
        observed_at: row.get(8)?,
        expires_at: row.get(9)?,
        result_class: row.get(10)?,
        summary_json: parse_json_column(&summary_json, 11)?,
    })
}

fn alert_event_from_row(row: &Row<'_>) -> rusqlite::Result<AlertEventRecord> {
    let detail_json: String = row.get(10)?;
    Ok(AlertEventRecord {
        alert_id: row.get(0)?,
        dedupe_key: row.get(1)?,
        node_id: row.get(2)?,
        severity: row.get(3)?,
        state: row.get(4)?,
        reason_code: row.get(5)?,
        first_seen_at: row.get(6)?,
        last_seen_at: row.get(7)?,
        last_sent_at: row.get(8)?,
        resolved_at: row.get(9)?,
        detail_json: parse_json_column(&detail_json, 10)?,
    })
}

fn audit_record_from_row(row: &Row<'_>) -> rusqlite::Result<AuditRecord> {
    let ok: Option<i64> = row.get(9)?;
    let duration_ms: Option<i64> = row.get(11)?;
    let detail_json: Option<String> = row.get(12)?;
    Ok(AuditRecord {
        id: row.get(0)?,
        ts: row.get(1)?,
        actor: row.get(2)?,
        event: row.get(3)?,
        node_id: row.get(4)?,
        endpoint_id: row.get(5)?,
        method: row.get(6)?,
        request_id: row.get(7)?,
        params_hash: row.get(8)?,
        ok: ok.map(|value| i64_to_bool(value, 9)).transpose()?,
        error_code: row.get(10)?,
        duration_ms: duration_ms.and_then(|value| u64::try_from(value).ok()),
        detail_json: detail_json
            .as_deref()
            .map(|value| parse_json_column(value, 12))
            .transpose()?
            .unwrap_or(Value::Null),
    })
}

fn parse_json_column(value: &str, column: usize) -> rusqlite::Result<Value> {
    serde_json::from_str(value)
        .map_err(|err| rusqlite::Error::FromSqlConversionFailure(column, Type::Text, Box::new(err)))
}

fn i64_to_bool(value: i64, column: usize) -> rusqlite::Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            column,
            Type::Integer,
            format!("invalid bool integer: {value}").into(),
        )),
    }
}

fn i64_to_u64(value: i64, column: usize) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(column, Type::Integer, Box::new(err))
    })
}

fn u64_to_i64(value: u64, name: &'static str) -> rusqlite::Result<i64> {
    i64::try_from(value).map_err(|err| {
        rusqlite::Error::ToSqlConversionFailure(format!("{name} is too large: {err}").into())
    })
}
