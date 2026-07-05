use serde::Serialize;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{
    Arc,
    mpsc::{self, SyncSender, TrySendError},
};
use time::OffsetDateTime;
use tokio::sync::oneshot;

use crate::private_file;

const DEFAULT_AUDIT_QUEUE_CAPACITY: usize = 1024;

#[derive(Debug, Clone, Serialize)]
pub struct AgentAuditEvent {
    pub ts: String,
    pub event: String,
    pub request_id: Option<String>,
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
            ts: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .expect("RFC3339 formatting succeeds"),
            event: event.into(),
            request_id: None,
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
}

#[derive(Debug)]
struct AuditCommand {
    event: AgentAuditEvent,
    ack: oneshot::Sender<io::Result<()>>,
}

trait AuditStorage: Send + Sync + 'static {
    fn write_event(&self, event: &AgentAuditEvent) -> io::Result<()>;
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
}

impl JsonlAuditWriter {
    pub fn new(path: PathBuf) -> Self {
        Self::with_queue_capacity(path, DEFAULT_AUDIT_QUEUE_CAPACITY)
    }

    pub fn with_queue_capacity(path: PathBuf, queue_capacity: usize) -> Self {
        Self::with_storage(
            queue_capacity,
            Arc::new(FileAuditStorage { path }) as Arc<dyn AuditStorage>,
        )
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

    fn with_storage(queue_capacity: usize, storage: Arc<dyn AuditStorage>) -> Self {
        assert!(queue_capacity > 0, "audit queue capacity must be positive");
        let (sender, receiver) = mpsc::sync_channel::<AuditCommand>(queue_capacity);
        std::thread::Builder::new()
            .name("ocfleet-agent-audit-writer".to_string())
            .spawn(move || {
                while let Ok(command) = receiver.recv() {
                    let result = storage.write_event(&command.event);
                    let _ = command.ack.send(result);
                }
            })
            .expect("spawn audit writer thread");
        Self {
            sender,
            queue_capacity,
        }
    }

    #[cfg(test)]
    fn with_storage_for_test(queue_capacity: usize, storage: Arc<dyn AuditStorage>) -> Self {
        Self::with_storage(queue_capacity, storage)
    }
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
    async fn async_write_returns_storage_errors_to_caller() {
        let writer = JsonlAuditWriter::with_storage_for_test(1, Arc::new(FailingAuditStorage));

        let err = writer
            .write_async(&AgentAuditEvent::new("request.completed"))
            .await
            .expect_err("storage failure is returned");

        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
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
