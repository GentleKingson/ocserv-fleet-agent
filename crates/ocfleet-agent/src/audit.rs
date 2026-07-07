use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
    mpsc::{self, RecvTimeoutError, SyncSender, TrySendError},
};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::private_file;

const DEFAULT_AUDIT_QUEUE_CAPACITY: usize = 1024;
const DEFAULT_AUDIT_SPOOL_MAX_EVENTS: usize = 10_000;
const AUDIT_SPOOL_FLUSH_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAuditEvent {
    pub event_id: String,
    pub ts: String,
    pub event: String,
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_target_endpoint_id: Option<String>,
    pub remote_endpoint_id: Option<String>,
    pub method: Option<String>,
    pub params_hash: Option<String>,
    pub nonce_hash: Option<String>,
    pub allowed: Option<bool>,
    pub ok: Option<bool>,
    pub error_code: Option<String>,
    pub duration_ms: Option<u64>,
    pub response_bytes: Option<usize>,
    pub stage: Option<String>,
    pub reason: Option<String>,
    pub suppressed_count: Option<u64>,
    pub limit_key: Option<String>,
    pub resource: Option<String>,
}

impl AgentAuditEvent {
    pub fn new(event: impl Into<String>) -> Self {
        Self {
            event_id: Uuid::new_v4().to_string(),
            ts: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .expect("RFC3339 formatting succeeds"),
            event: event.into(),
            request_id: None,
            root_request_id: None,
            peer_request_id: None,
            path_target_endpoint_id: None,
            remote_endpoint_id: None,
            method: None,
            params_hash: None,
            nonce_hash: None,
            allowed: None,
            ok: None,
            error_code: None,
            duration_ms: None,
            response_bytes: None,
            stage: None,
            reason: None,
            suppressed_count: None,
            limit_key: None,
            resource: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct JsonlAuditWriter {
    sender: SyncSender<AuditCommand>,
    queue_capacity: usize,
    durability: Arc<AuditDurability>,
}

#[derive(Debug)]
struct AuditCommand {
    event: AgentAuditEvent,
    ack: oneshot::Sender<io::Result<()>>,
}

trait AuditStorage: Send + Sync + 'static {
    fn write_event(&self, event: &AgentAuditEvent) -> io::Result<()>;

    fn contains_event_id(&self, event_id: &str) -> io::Result<bool> {
        let _ = event_id;
        Ok(false)
    }
}

#[derive(Debug)]
struct FileAuditStorage {
    path: PathBuf,
}

impl AuditStorage for FileAuditStorage {
    fn write_event(&self, event: &AgentAuditEvent) -> io::Result<()> {
        let mut file = private_file::open_private_append(&self.path)?;
        serde_json::to_writer(&mut file, event).map_err(io::Error::other)?;
        file.write_all(b"\n")?;
        Ok(())
    }

    fn contains_event_id(&self, event_id: &str) -> io::Result<bool> {
        match private_file::open_existing_private_read(&self.path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                for line in reader.lines() {
                    let line = line?;
                    let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
                        continue;
                    };
                    if value.get("event_id").and_then(serde_json::Value::as_str) == Some(event_id) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(err),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditMetricsSnapshot {
    pub audit_queued: u64,
    pub audit_dropped: u64,
    pub audit_replayed: u64,
    pub audit_flush_failures: u64,
    pub audit_oldest_age_seconds: Option<u64>,
}

#[derive(Debug, Default)]
struct AuditMetrics {
    queued: AtomicU64,
    dropped: AtomicU64,
    replayed: AtomicU64,
    flush_failures: AtomicU64,
}

impl AuditMetrics {
    fn snapshot(&self, oldest_age_seconds: Option<u64>) -> AuditMetricsSnapshot {
        AuditMetricsSnapshot {
            audit_queued: self.queued.load(Ordering::Relaxed),
            audit_dropped: self.dropped.load(Ordering::Relaxed),
            audit_replayed: self.replayed.load(Ordering::Relaxed),
            audit_flush_failures: self.flush_failures.load(Ordering::Relaxed),
            audit_oldest_age_seconds: oldest_age_seconds,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpoolRecord {
    queued_at: String,
    event: AgentAuditEvent,
}

struct AuditDurability {
    primary: Arc<dyn AuditStorage>,
    spool_path: PathBuf,
    metrics_path: Option<PathBuf>,
    spool_max_events: usize,
    metrics: AuditMetrics,
}

impl std::fmt::Debug for AuditDurability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditDurability")
            .field("spool_path", &self.spool_path)
            .field("metrics_path", &self.metrics_path)
            .field("spool_max_events", &self.spool_max_events)
            .finish_non_exhaustive()
    }
}

impl AuditDurability {
    fn new(
        primary: Arc<dyn AuditStorage>,
        spool_path: PathBuf,
        metrics_path: Option<PathBuf>,
        spool_max_events: usize,
    ) -> Self {
        assert!(
            spool_max_events > 0,
            "audit spool max events must be positive"
        );
        Self {
            primary,
            spool_path,
            metrics_path,
            spool_max_events,
            metrics: AuditMetrics::default(),
        }
    }

    fn write_event(&self, event: &AgentAuditEvent) -> io::Result<()> {
        let _ = self.flush_spool();
        match self.primary.write_event(event) {
            Ok(()) => {
                self.write_metrics_snapshot();
                Ok(())
            }
            Err(primary_err) => self.enqueue_spool(event, primary_err),
        }
    }

    fn enqueue_spool(&self, event: &AgentAuditEvent, primary_err: io::Error) -> io::Result<()> {
        let current_events = self.spool_event_count()?;
        if current_events >= self.spool_max_events {
            self.metrics.dropped.fetch_add(1, Ordering::Relaxed);
            self.write_metrics_snapshot();
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!(
                    "agent audit sink unavailable and spool is full; capacity={}; primary_error={primary_err}",
                    self.spool_max_events
                ),
            ));
        }

        let record = SpoolRecord {
            queued_at: now_rfc3339_for_audit(),
            event: event.clone(),
        };
        let mut file = private_file::open_private_append(&self.spool_path)?;
        serde_json::to_writer(&mut file, &record).map_err(io::Error::other)?;
        file.write_all(b"\n")?;
        self.metrics.queued.fetch_add(1, Ordering::Relaxed);
        self.write_metrics_snapshot();
        Ok(())
    }

    fn flush_spool(&self) -> io::Result<()> {
        let records = self.read_spool_records()?;
        if records.is_empty() {
            self.write_metrics_snapshot();
            return Ok(());
        }

        let mut remaining = Vec::new();
        for (index, record) in records.iter().enumerate() {
            match self.primary.contains_event_id(&record.event.event_id) {
                Ok(true) => {}
                Ok(false) => match self.primary.write_event(&record.event) {
                    Ok(()) => {
                        self.metrics.replayed.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(err) => {
                        remaining.extend_from_slice(&records[index..]);
                        self.rewrite_spool(&remaining)?;
                        self.metrics.flush_failures.fetch_add(1, Ordering::Relaxed);
                        self.write_metrics_snapshot();
                        return Err(err);
                    }
                },
                Err(err) => {
                    remaining.extend_from_slice(&records[index..]);
                    self.rewrite_spool(&remaining)?;
                    self.metrics.flush_failures.fetch_add(1, Ordering::Relaxed);
                    self.write_metrics_snapshot();
                    return Err(err);
                }
            }
        }

        self.rewrite_spool(&[])?;
        self.write_metrics_snapshot();
        Ok(())
    }

    fn snapshot(&self) -> AuditMetricsSnapshot {
        self.metrics
            .snapshot(self.oldest_spool_age_seconds().ok().flatten())
    }

    fn write_metrics_snapshot(&self) {
        let Some(metrics_path) = &self.metrics_path else {
            return;
        };
        let Ok(payload) = serde_json::to_vec_pretty(&self.snapshot()) else {
            return;
        };
        if let Err(err) = private_file::write_private_replace(metrics_path, &payload) {
            tracing::warn!(error = %err, "failed to write audit metrics snapshot");
        }
    }

    fn spool_event_count(&self) -> io::Result<usize> {
        Ok(self.read_spool_records()?.len())
    }

    fn oldest_spool_age_seconds(&self) -> io::Result<Option<u64>> {
        let records = self.read_spool_records()?;
        let Some(oldest) = records.first() else {
            return Ok(None);
        };
        let queued_at = OffsetDateTime::parse(
            &oldest.queued_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(io::Error::other)?;
        let age = (OffsetDateTime::now_utc() - queued_at)
            .whole_seconds()
            .max(0) as u64;
        Ok(Some(age))
    }

    fn read_spool_records(&self) -> io::Result<Vec<SpoolRecord>> {
        match private_file::open_existing_private_read(&self.spool_path) {
            Ok(file) => {
                let mut records = Vec::new();
                for line in BufReader::new(file).lines() {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<SpoolRecord>(&line) {
                        Ok(record) => records.push(record),
                        Err(err) => {
                            self.metrics.dropped.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(error = %err, "dropped malformed audit spool record");
                        }
                    }
                }
                Ok(records)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(err) => Err(err),
        }
    }

    fn rewrite_spool(&self, records: &[SpoolRecord]) -> io::Result<()> {
        let mut payload = Vec::new();
        for record in records {
            serde_json::to_writer(&mut payload, record).map_err(io::Error::other)?;
            payload.write_all(b"\n")?;
        }
        private_file::write_private_replace(&self.spool_path, &payload)
    }
}

impl JsonlAuditWriter {
    pub fn new(path: PathBuf) -> Self {
        Self::with_queue_capacity(path, DEFAULT_AUDIT_QUEUE_CAPACITY)
    }

    pub fn with_queue_capacity(path: PathBuf, queue_capacity: usize) -> Self {
        let spool_path = default_spool_path_for(&path);
        Self::with_durability(
            path,
            queue_capacity,
            spool_path,
            None,
            DEFAULT_AUDIT_SPOOL_MAX_EVENTS,
        )
    }

    pub fn with_durability(
        path: PathBuf,
        queue_capacity: usize,
        spool_path: PathBuf,
        metrics_path: Option<PathBuf>,
        spool_max_events: usize,
    ) -> Self {
        Self::with_storage(
            queue_capacity,
            Arc::new(FileAuditStorage { path }) as Arc<dyn AuditStorage>,
            spool_path,
            metrics_path,
            spool_max_events,
        )
    }

    pub fn metrics_snapshot(&self) -> AuditMetricsSnapshot {
        self.durability.snapshot()
    }

    pub fn default_spool_path(path: &Path) -> PathBuf {
        default_spool_path_for(path)
    }

    pub fn default_metrics_path(path: &Path) -> PathBuf {
        append_path_suffix(path, ".metrics.json")
    }

    pub async fn write_async(&self, event: &AgentAuditEvent) -> io::Result<()> {
        let ack = self.enqueue(event)?;
        ack.await.unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "agent audit writer stopped before acknowledging event",
            ))
        })
    }

    pub fn write(&self, event: &AgentAuditEvent) -> io::Result<()> {
        let ack = self.enqueue(event)?;
        ack.blocking_recv().unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "agent audit writer stopped before acknowledging event",
            ))
        })
    }

    fn enqueue(&self, event: &AgentAuditEvent) -> io::Result<oneshot::Receiver<io::Result<()>>> {
        let (ack, ack_rx) = oneshot::channel();
        let command = AuditCommand {
            event: event.clone(),
            ack,
        };
        match self.sender.try_send(command) {
            Ok(()) => Ok(ack_rx),
            Err(TrySendError::Full(_)) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!(
                    "agent audit queue is full; capacity={}",
                    self.queue_capacity
                ),
            )),
            Err(TrySendError::Disconnected(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "agent audit writer is stopped",
            )),
        }
    }

    fn with_storage(
        queue_capacity: usize,
        storage: Arc<dyn AuditStorage>,
        spool_path: PathBuf,
        metrics_path: Option<PathBuf>,
        spool_max_events: usize,
    ) -> Self {
        assert!(queue_capacity > 0, "audit queue capacity must be positive");
        let (sender, receiver) = mpsc::sync_channel::<AuditCommand>(queue_capacity);
        let durability = Arc::new(AuditDurability::new(
            storage,
            spool_path,
            metrics_path,
            spool_max_events,
        ));
        durability.write_metrics_snapshot();
        let worker_durability = durability.clone();
        std::thread::Builder::new()
            .name("ocfleet-agent-audit-writer".to_string())
            .spawn(move || {
                loop {
                    match receiver.recv_timeout(AUDIT_SPOOL_FLUSH_INTERVAL) {
                        Ok(command) => {
                            let result = worker_durability.write_event(&command.event);
                            let _ = command.ack.send(result);
                        }
                        Err(RecvTimeoutError::Timeout) => {
                            let _ = worker_durability.flush_spool();
                        }
                        Err(RecvTimeoutError::Disconnected) => {
                            let _ = worker_durability.flush_spool();
                            break;
                        }
                    }
                }
            })
            .expect("spawn audit writer thread");
        Self {
            sender,
            queue_capacity,
            durability,
        }
    }

    #[cfg(test)]
    fn with_storage_for_test(queue_capacity: usize, storage: Arc<dyn AuditStorage>) -> Self {
        Self::with_storage(
            queue_capacity,
            storage,
            std::env::temp_dir().join(format!("ocfleet-test-{}.spool.jsonl", Uuid::new_v4())),
            None,
            DEFAULT_AUDIT_SPOOL_MAX_EVENTS,
        )
    }

    #[cfg(test)]
    fn with_durability_for_test(
        path: PathBuf,
        spool_path: PathBuf,
        metrics_path: Option<PathBuf>,
        queue_capacity: usize,
        spool_max_events: usize,
    ) -> Self {
        Self::with_durability(
            path,
            queue_capacity,
            spool_path,
            metrics_path,
            spool_max_events,
        )
    }

    #[cfg(test)]
    fn flush_replay_for_test(&self) -> io::Result<()> {
        self.durability.flush_spool()
    }
}

fn default_spool_path_for(path: &Path) -> PathBuf {
    append_path_suffix(path, ".spool.jsonl")
}

fn append_path_suffix(path: &Path, suffix: &str) -> PathBuf {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return PathBuf::from(format!("audit{suffix}"));
    };
    path.with_file_name(format!("{file_name}{suffix}"))
}

fn now_rfc3339_for_audit() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("RFC3339 formatting succeeds")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn async_write_yields_while_dedicated_writer_is_slow() {
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let storage = Arc::new(SlowAuditStorage {
            started_tx,
            release_rx: std::sync::Mutex::new(release_rx),
            writes: AtomicUsize::new(0),
        });
        let writer = JsonlAuditWriter::with_storage_for_test(1, storage.clone());
        let event = AgentAuditEvent::new("request.completed");

        let write_task = tokio::spawn({
            let writer = writer.clone();
            async move { writer.write_async(&event).await }
        });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("writer thread started slow write");

        let progress = tokio::time::timeout(Duration::from_millis(50), async {
            tokio::task::yield_now().await;
            "advanced"
        })
        .await
        .expect("runtime advanced while audit writer was blocked");

        assert_eq!(progress, "advanced");
        release_tx.send(()).expect("release slow writer");
        write_task
            .await
            .expect("write task joined")
            .expect("audit write succeeded");
        assert_eq!(storage.writes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn phase_three_correlation_fields_are_optional_and_low_sensitive() {
        let base = AgentAuditEvent::new("rpc_request");
        let base_json = serde_json::to_value(&base).expect("base audit json");
        assert!(base_json.get("root_request_id").is_none());
        assert!(base_json.get("peer_request_id").is_none());
        assert!(base_json.get("path_target_endpoint_id").is_none());

        let mut path = AgentAuditEvent::new("rpc_request");
        path.root_request_id = Some("00000000-0000-4000-8000-000000000001".to_string());
        path.peer_request_id = Some("00000000-0000-4000-8000-000000000002".to_string());
        path.path_target_endpoint_id = Some("target-endpoint".to_string());
        let path_json = serde_json::to_value(&path).expect("path audit json");

        assert_eq!(
            path_json["root_request_id"],
            "00000000-0000-4000-8000-000000000001"
        );
        assert_eq!(
            path_json["peer_request_id"],
            "00000000-0000-4000-8000-000000000002"
        );
        assert_eq!(path_json["path_target_endpoint_id"], "target-endpoint");
        for forbidden in [
            "host",
            "port",
            "endpoint_addr",
            "route",
            "relay_url",
            "mesh_hint",
            "payload",
        ] {
            assert!(
                path_json.get(forbidden).is_none(),
                "audit must not serialize {forbidden}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn async_write_returns_queue_full_instead_of_growing_without_bound() {
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let storage = Arc::new(SlowAuditStorage {
            started_tx,
            release_rx: std::sync::Mutex::new(release_rx),
            writes: AtomicUsize::new(0),
        });
        let writer = JsonlAuditWriter::with_storage_for_test(1, storage);
        let first = AgentAuditEvent::new("first");
        let second = AgentAuditEvent::new("second");
        let third = AgentAuditEvent::new("third");

        let first_ack = writer.enqueue(&first).expect("enqueue first event");
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("writer thread consumed first event");

        let second_ack = writer.enqueue(&second).expect("enqueue second event");

        let err = writer
            .write_async(&third)
            .await
            .expect_err("bounded queue rejects overflow");
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);

        release_tx.send(()).expect("release first slow writer");
        release_tx.send(()).expect("release queued slow writer");
        first_ack
            .await
            .expect("first ack received")
            .expect("first write succeeds");
        second_ack
            .await
            .expect("second ack received")
            .expect("second write succeeds");
    }

    #[tokio::test]
    async fn async_write_returns_error_when_primary_and_spool_both_fail() {
        let dir = tempfile::tempdir().expect("temp dir");
        let bad_spool_path = dir.path().join("spool-is-directory");
        std::fs::create_dir(&bad_spool_path).expect("bad spool directory");
        let writer = JsonlAuditWriter::with_storage(
            1,
            Arc::new(FailingAuditStorage),
            bad_spool_path,
            None,
            1,
        );

        let err = writer
            .write_async(&AgentAuditEvent::new("request.completed"))
            .await
            .expect_err("undurable audit failure is returned");

        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::IsADirectory
            ),
            "unexpected error kind: {err:?}"
        );
    }

    #[tokio::test]
    async fn async_write_spools_when_primary_audit_sink_is_unavailable() {
        let dir = tempfile::tempdir().expect("temp dir");
        let primary_path = dir.path().join("agent-audit.jsonl");
        std::fs::create_dir(&primary_path).expect("primary path is unavailable as a file");
        let spool_path = dir.path().join("agent-audit.spool.jsonl");
        let writer = JsonlAuditWriter::with_durability_for_test(
            primary_path.clone(),
            spool_path.clone(),
            None,
            8,
            10,
        );

        let event = AgentAuditEvent::new("request.completed");
        let event_id = event.event_id.clone();
        writer
            .write_async(&event)
            .await
            .expect("fallback spool makes the audit durable");

        let spool_text = std::fs::read_to_string(&spool_path).expect("spool file");
        assert!(spool_text.contains(&event_id));
        let metrics = writer.metrics_snapshot();
        assert_eq!(metrics.audit_queued, 1);
        assert_eq!(metrics.audit_dropped, 0);
        assert_eq!(metrics.audit_replayed, 0);
    }

    #[tokio::test]
    async fn async_write_replays_spooled_events_after_primary_recovers() {
        let dir = tempfile::tempdir().expect("temp dir");
        let primary_path = dir.path().join("agent-audit.jsonl");
        std::fs::create_dir(&primary_path).expect("primary path is unavailable as a file");
        let spool_path = dir.path().join("agent-audit.spool.jsonl");
        let writer = JsonlAuditWriter::with_durability_for_test(
            primary_path.clone(),
            spool_path.clone(),
            None,
            8,
            10,
        );

        let first = AgentAuditEvent::new("first");
        let first_id = first.event_id.clone();
        writer
            .write_async(&first)
            .await
            .expect("first event spooled");

        std::fs::remove_dir(&primary_path).expect("primary path can recover");
        let second = AgentAuditEvent::new("second");
        let second_id = second.event_id.clone();
        writer
            .write_async(&second)
            .await
            .expect("second event written after replay");

        let primary_text = std::fs::read_to_string(&primary_path).expect("primary audit file");
        assert!(primary_text.contains(&first_id));
        assert!(primary_text.contains(&second_id));
        assert_eq!(primary_text.matches(&first_id).count(), 1);
        assert_eq!(primary_text.matches(&second_id).count(), 1);

        let metrics = writer.metrics_snapshot();
        assert_eq!(metrics.audit_queued, 1);
        assert_eq!(metrics.audit_dropped, 0);
        assert_eq!(metrics.audit_replayed, 1);
    }

    #[tokio::test]
    async fn async_write_reports_spool_capacity_drops_without_silent_loss() {
        let dir = tempfile::tempdir().expect("temp dir");
        let primary_path = dir.path().join("agent-audit.jsonl");
        std::fs::create_dir(&primary_path).expect("primary path is unavailable as a file");
        let spool_path = dir.path().join("agent-audit.spool.jsonl");
        let writer = JsonlAuditWriter::with_durability_for_test(
            primary_path,
            spool_path.clone(),
            None,
            8,
            1,
        );

        writer
            .write_async(&AgentAuditEvent::new("first"))
            .await
            .expect("first event spooled");
        let err = writer
            .write_async(&AgentAuditEvent::new("second"))
            .await
            .expect_err("full spool returns backpressure");

        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(
            std::fs::read_to_string(&spool_path)
                .expect("spool")
                .lines()
                .count(),
            1
        );
        let metrics = writer.metrics_snapshot();
        assert_eq!(metrics.audit_queued, 1);
        assert_eq!(metrics.audit_dropped, 1);
    }

    #[tokio::test]
    async fn async_write_skips_duplicate_spooled_event_ids_during_replay() {
        let dir = tempfile::tempdir().expect("temp dir");
        let primary_path = dir.path().join("agent-audit.jsonl");
        let spool_path = dir.path().join("agent-audit.spool.jsonl");
        let writer = JsonlAuditWriter::with_durability_for_test(
            primary_path.clone(),
            spool_path.clone(),
            None,
            8,
            10,
        );

        let already_written = AgentAuditEvent::new("already-written");
        let event_id = already_written.event_id.clone();
        writer
            .write_async(&already_written)
            .await
            .expect("write primary event");
        append_spool_record_for_test(&spool_path, &already_written);

        writer
            .flush_replay_for_test()
            .expect("duplicate replay is treated as durable");

        let primary_text = std::fs::read_to_string(&primary_path).expect("primary audit file");
        assert_eq!(primary_text.matches(&event_id).count(), 1);
        assert_eq!(
            std::fs::read_to_string(&spool_path)
                .unwrap_or_default()
                .lines()
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn async_write_exposes_metrics_snapshot_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let primary_path = dir.path().join("agent-audit.jsonl");
        let spool_path = dir.path().join("agent-audit.spool.jsonl");
        let metrics_path = dir.path().join("agent-audit.metrics.json");
        let writer = JsonlAuditWriter::with_durability_for_test(
            primary_path,
            spool_path,
            Some(metrics_path.clone()),
            8,
            10,
        );

        writer
            .write_async(&AgentAuditEvent::new("request.completed"))
            .await
            .expect("write primary audit");

        let metrics_text = std::fs::read_to_string(metrics_path).expect("metrics file");
        let metrics: AuditMetricsSnapshot =
            serde_json::from_str(&metrics_text).expect("metrics json");
        assert_eq!(metrics.audit_queued, 0);
        assert_eq!(metrics.audit_dropped, 0);
        assert_eq!(metrics.audit_replayed, 0);
        assert_eq!(metrics.audit_flush_failures, 0);
        assert_eq!(metrics.audit_oldest_age_seconds, None);
    }

    fn append_spool_record_for_test(path: &Path, event: &AgentAuditEvent) {
        let record = SpoolRecord {
            queued_at: now_rfc3339_for_audit(),
            event: event.clone(),
        };
        let mut file = private_file::open_private_append(path).expect("open test spool");
        serde_json::to_writer(&mut file, &record).expect("write spool record");
        file.write_all(b"\n").expect("spool newline");
    }

    struct SlowAuditStorage {
        started_tx: mpsc::Sender<()>,
        release_rx: std::sync::Mutex<mpsc::Receiver<()>>,
        writes: AtomicUsize,
    }

    impl AuditStorage for SlowAuditStorage {
        fn write_event(&self, _event: &AgentAuditEvent) -> io::Result<()> {
            self.started_tx.send(()).expect("send started");
            let _ = self
                .release_rx
                .lock()
                .expect("release lock")
                .recv_timeout(Duration::from_secs(5));
            self.writes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct FailingAuditStorage;

    impl AuditStorage for FailingAuditStorage {
        fn write_event(&self, _event: &AgentAuditEvent) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe path /tmp/agent-audit.jsonl",
            ))
        }
    }
}
