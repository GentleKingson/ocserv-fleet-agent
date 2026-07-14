//! Explicit, default-off Postgres-wrapped SQLite snapshot backend.
//!
//! This experimental format stores the complete, already versioned SQLite
//! state as one checksummed Postgres value. It preserves the existing Store
//! contract while providing durable snapshot replacement and fencing, but it
//! is not a native relational Postgres data layer or a concurrent-write scale
//! architecture.

use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::time::Instant;

use postgres::config::Host;
use postgres::{Config, NoTls, Transaction};
use r2d2::{Pool, PooledConnection};
use r2d2_postgres::PostgresConnectionManager;
use rusqlite::backup::Backup;
use rusqlite::{Connection, OpenFlags};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tempfile::{NamedTempFile, TempDir};

use crate::audit::AuditEvent;
use crate::backend::{
    AuditWriter, BackendKind, MAX_STORE_READER_ROWS, MigrationManager, StoreReader, StoreWriter,
};
use crate::private_file;
use crate::store::{
    AlertDeliveryAttemptWrite, AlertDeliveryFinalizeWrite, AlertDeliveryQueueClaim,
    AlertDeliveryQueueEnqueue, AlertDeliveryQueueOutcome, AlertEvaluationWrite, AlertEventRecord,
    AlertStateTransition, AlertWebhookHookRecord, ApprovalInput, AuditRecord,
    CURRENT_SCHEMA_VERSION, EndpointTrustRecord, EnrollmentTokenInsert, EnrollmentTokenRecord,
    HealthEvaluationFailure, HealthEvaluationFinish, HealthEvaluationStart, HealthPolicyRecord,
    HealthRollupWrite, HealthSnapshotRecord, HealthSnapshotWrite, JoinRequestInsert,
    JoinRequestRecord, LegacyEnrollmentClaimInput, NodeInsert, NodeMaintenanceWindow,
    NodeMetadataRecord, NodeRecord, ObservabilityJobRecord, ObservabilityRunRecord,
    ProbeObservationRecord, RetentionApplyInput, RetentionApplyResult, RetentionPolicyRecord,
    SchedulerJobClaim, SchedulerMaintenanceWindow, SchedulerOutcomeWrite, SchedulerRunFinish,
    SchedulerRunStart, Store, StoreError,
};
use crate::version_governance::CapabilitySnapshot;

const MIGRATION_LOCK_ID: i64 = 0x4f43464c454554;
const FORMAT_VERSION: i32 = 1;
const BACKEND_SCHEMA_VERSION: i32 = 3;
const IMPORT_INDEX_SCHEMA_VERSION: i32 = 2;
const DEFAULT_POOL_SIZE: u32 = 8;
const MAX_DSN_BYTES: usize = 8_192;
const MAX_STATE_IMAGE_BYTES: u64 = 512 * 1024 * 1024;
pub const RECOMMENDED_STATE_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_VERIFICATION_ROWS_PER_TABLE: u64 = 1_000_000;
const BACKUP_PAGES_PER_STEP: i32 = 128;

#[derive(Clone, PartialEq, Eq)]
pub enum PostgresConnectionSource {
    Environment { variable: String },
    PrivateConfigFile { path: PathBuf },
}

impl PostgresConnectionSource {
    pub fn validate(&self) -> Result<(), PostgresError> {
        match self {
            Self::Environment { variable }
                if matches!(
                    variable.as_str(),
                    "OCFLEET_POSTGRES_URL" | "OCFLEET_TEST_POSTGRES_URL"
                ) =>
            {
                Ok(())
            }
            Self::Environment { .. } => Err(PostgresError::Configuration(
                "unsupported Postgres environment variable",
            )),
            Self::PrivateConfigFile { path } if path.is_absolute() => Ok(()),
            Self::PrivateConfigFile { .. } => Err(PostgresError::Configuration(
                "Postgres private config path must be absolute",
            )),
        }
    }

    fn load(&self) -> Result<PrivatePostgresConfig, PostgresError> {
        self.validate()?;
        match self {
            Self::Environment { variable } => {
                let dsn = std::env::var(variable).map_err(|_| {
                    PostgresError::Configuration("Postgres DSN environment variable is not set")
                })?;
                validate_dsn(&dsn)?;
                Ok(PrivatePostgresConfig {
                    dsn,
                    pool_size: DEFAULT_POOL_SIZE,
                })
            }
            Self::PrivateConfigFile { path } => {
                let file = private_file::open_existing_private_read(path)?;
                let mut text = String::new();
                file.take((MAX_DSN_BYTES + 1) as u64)
                    .read_to_string(&mut text)?;
                if text.len() > MAX_DSN_BYTES {
                    return Err(PostgresError::Configuration("Postgres config is too large"));
                }
                let config: PrivatePostgresConfig = toml::from_str(&text)
                    .map_err(|_| PostgresError::Configuration("Postgres config is invalid"))?;
                validate_dsn(&config.dsn)?;
                if config.pool_size == 0 || config.pool_size > 64 {
                    return Err(PostgresError::Configuration(
                        "Postgres pool_size must be between 1 and 64",
                    ));
                }
                Ok(config)
            }
        }
    }

    pub const fn backend_kind(&self) -> BackendKind {
        BackendKind::PostgresSnapshot
    }
}

impl fmt::Debug for PostgresConnectionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Environment { variable } => f
                .debug_struct("Environment")
                .field(
                    "variable",
                    &if matches!(
                        variable.as_str(),
                        "OCFLEET_POSTGRES_URL" | "OCFLEET_TEST_POSTGRES_URL"
                    ) {
                        variable.as_str()
                    } else {
                        "<redacted-invalid>"
                    },
                )
                .finish(),
            Self::PrivateConfigFile { .. } => f
                .debug_struct("PrivateConfigFile")
                .field("path", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivatePostgresConfig {
    dsn: String,
    #[serde(default = "default_pool_size")]
    pool_size: u32,
}

fn default_pool_size() -> u32 {
    DEFAULT_POOL_SIZE
}

#[derive(Debug, thiserror::Error)]
pub enum PostgresError {
    #[error("Postgres configuration error: {0}")]
    Configuration(&'static str),
    #[error("Postgres connection or query failed")]
    Database(#[source] postgres::Error),
    #[error("Postgres connection pool failed")]
    Pool(#[source] r2d2::Error),
    #[error("Postgres state checksum verification failed")]
    Checksum,
    #[error("Postgres state format {0} is unsupported")]
    UnsupportedFormat(i32),
    #[error("Postgres imported state is invalid: {0}")]
    InvalidState(String),
    #[error("Postgres StoreWriter requires a current controller lease")]
    FenceRequired,
    #[error("Postgres controller lease is stale")]
    StaleFence,
    #[error("private Postgres configuration could not be read")]
    PrivateConfig(#[source] crate::private_file::PrivateFileError),
    #[error("Postgres backend local staging failed")]
    Io(#[source] std::io::Error),
    #[error("store operation failed: {0}")]
    Store(#[source] StoreError),
    #[error("Postgres backend SQLite snapshot failed")]
    Sqlite(#[source] rusqlite::Error),
}

impl From<postgres::Error> for PostgresError {
    fn from(value: postgres::Error) -> Self {
        Self::Database(value)
    }
}
impl From<r2d2::Error> for PostgresError {
    fn from(value: r2d2::Error) -> Self {
        Self::Pool(value)
    }
}
impl From<crate::private_file::PrivateFileError> for PostgresError {
    fn from(value: crate::private_file::PrivateFileError) -> Self {
        Self::PrivateConfig(value)
    }
}
impl From<std::io::Error> for PostgresError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<StoreError> for PostgresError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}
impl From<rusqlite::Error> for PostgresError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

#[derive(Default)]
struct SnapshotMetrics {
    state_image_bytes: AtomicU64,
    read_operations: AtomicU64,
    failed_read_operations: AtomicU64,
    write_operations: AtomicU64,
    failed_write_operations: AtomicU64,
    last_download_us: AtomicU64,
    last_read_total_us: AtomicU64,
    last_write_total_us: AtomicU64,
    last_write_owned_image_bytes: AtomicU64,
    last_materialize_us: AtomicU64,
    last_upload_commit_us: AtomicU64,
    last_advisory_lock_wait_us: AtomicU64,
    last_lease_remaining_ms: AtomicU64,
}

impl SnapshotMetrics {
    fn snapshot(&self) -> PostgresSnapshotRuntimeMetrics {
        PostgresSnapshotRuntimeMetrics {
            state_image_bytes: self.state_image_bytes.load(Ordering::Relaxed),
            read_operations: self.read_operations.load(Ordering::Relaxed),
            failed_read_operations: self.failed_read_operations.load(Ordering::Relaxed),
            write_operations: self.write_operations.load(Ordering::Relaxed),
            failed_write_operations: self.failed_write_operations.load(Ordering::Relaxed),
            last_download_us: self.last_download_us.load(Ordering::Relaxed),
            last_read_total_us: self.last_read_total_us.load(Ordering::Relaxed),
            last_write_total_us: self.last_write_total_us.load(Ordering::Relaxed),
            last_write_owned_image_bytes: self.last_write_owned_image_bytes.load(Ordering::Relaxed),
            last_materialize_us: self.last_materialize_us.load(Ordering::Relaxed),
            last_upload_commit_us: self.last_upload_commit_us.load(Ordering::Relaxed),
            last_advisory_lock_wait_us: self.last_advisory_lock_wait_us.load(Ordering::Relaxed),
            last_lease_remaining_ms: self.last_lease_remaining_ms.load(Ordering::Relaxed),
        }
    }
}

pub struct PostgresSnapshotStore {
    pool: Pool<PostgresConnectionManager<NoTls>>,
    write_fence: Option<ControllerLease>,
    metrics: Arc<SnapshotMetrics>,
}

impl fmt::Debug for PostgresSnapshotStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresSnapshotStore")
            .field("pool", &"<redacted>")
            .field("write_fence", &self.write_fence)
            .finish()
    }
}

pub fn connect(source: &PostgresConnectionSource) -> Result<PostgresSnapshotStore, PostgresError> {
    let private = source.load()?;
    let config = Config::from_str(&private.dsn)
        .map_err(|_| PostgresError::Configuration("Postgres DSN is invalid"))?;
    validate_transport(&config)?;
    let manager = PostgresConnectionManager::new(config, NoTls);
    let pool = Pool::builder().max_size(private.pool_size).build(manager)?;
    let store = PostgresSnapshotStore {
        pool,
        write_fence: None,
        metrics: Arc::new(SnapshotMetrics::default()),
    };
    store.migrate()?;
    Ok(store)
}

impl PostgresSnapshotStore {
    pub fn migrate(&self) -> Result<(), PostgresError> {
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK_ID])?;
        tx.batch_execute(
            "CREATE TABLE IF NOT EXISTS ocfleet_backend_migrations (
               version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now());
             CREATE TABLE IF NOT EXISTS ocfleet_runtime_state (
               singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
               format_version INTEGER NOT NULL,
               sqlite_schema_version BIGINT NOT NULL,
               state_revision BIGINT NOT NULL DEFAULT 1,
               state_sha256 TEXT NOT NULL CHECK (length(state_sha256) = 64),
               state_bytes BYTEA NOT NULL,
               updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
             CREATE TABLE IF NOT EXISTS ocfleet_imports (
               import_id UUID PRIMARY KEY, source_sha256 TEXT NOT NULL,
               source_size BIGINT NOT NULL, verified BOOLEAN NOT NULL DEFAULT FALSE,
               created_at TIMESTAMPTZ NOT NULL DEFAULT now(), completed_at TIMESTAMPTZ);
             CREATE TABLE IF NOT EXISTS ocfleet_controller_leases (
               lease_name TEXT PRIMARY KEY, owner_id TEXT NOT NULL,
               fencing_token BIGINT NOT NULL CHECK (fencing_token > 0),
               lease_until TIMESTAMPTZ NOT NULL,
               updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
             CREATE INDEX IF NOT EXISTS idx_ocfleet_imports_created ON ocfleet_imports(created_at);"
        )?;
        tx.execute(
            "INSERT INTO ocfleet_backend_migrations(version) VALUES ($1) ON CONFLICT DO NOTHING",
            &[&FORMAT_VERSION],
        )?;
        tx.batch_execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_ocfleet_imports_source
               ON ocfleet_imports(source_sha256, source_size);",
        )?;
        tx.execute(
            "INSERT INTO ocfleet_backend_migrations(version) VALUES ($1) ON CONFLICT DO NOTHING",
            &[&IMPORT_INDEX_SCHEMA_VERSION],
        )?;
        let revision_migration_pending = tx
            .query_opt(
                "SELECT 1 FROM ocfleet_backend_migrations WHERE version=$1",
                &[&BACKEND_SCHEMA_VERSION],
            )?
            .is_none();
        if revision_migration_pending {
            tx.batch_execute(
                "ALTER TABLE ocfleet_runtime_state
                   ADD COLUMN IF NOT EXISTS state_revision BIGINT NOT NULL DEFAULT 1;
                 ALTER TABLE ocfleet_runtime_state
                   DROP CONSTRAINT IF EXISTS ocfleet_runtime_state_revision_positive;
                 ALTER TABLE ocfleet_runtime_state
                   ADD CONSTRAINT ocfleet_runtime_state_revision_positive
                   CHECK (state_revision > 0);",
            )?;
            tx.execute(
                "INSERT INTO ocfleet_backend_migrations(version) VALUES ($1)",
                &[&BACKEND_SCHEMA_VERSION],
            )?;
        }
        if tx
            .query_opt(
                "SELECT 1 FROM ocfleet_runtime_state WHERE singleton = TRUE",
                &[],
            )?
            .is_none()
        {
            let image = empty_sqlite_image()?;
            insert_state(&mut tx, &image)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn doctor(&self) -> Result<PostgresDoctor, PostgresError> {
        let started = Instant::now();
        let mut conn = self.connection()?;
        check_state_size(&mut conn)?;
        let download_started = Instant::now();
        let row = conn.query_one(
            "SELECT format_version, sqlite_schema_version, state_revision,
                    state_sha256, state_bytes,
                    to_char(updated_at AT TIME ZONE 'UTC',
                            'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                    octet_length(state_bytes)::BIGINT
             FROM ocfleet_runtime_state WHERE singleton = TRUE",
            &[],
        )?;
        let download_us = elapsed_us(download_started);
        let image: Vec<u8> = row.get(4);
        let checksum: String = row.get(3);
        let schema_version: i64 = row.get(1);
        let state_revision = positive_u64(row.get(2), "state revision")?;
        let state_size = positive_u64(row.get(6), "state image size")?;
        let checksum_valid = sha256(&image) == checksum;
        let materialize_started = Instant::now();
        if checksum_valid {
            let (image_schema_version, _) = verify_image(&image)?;
            if image_schema_version != schema_version {
                return Err(PostgresError::InvalidState(
                    "stored schema metadata does not match the SQLite image".into(),
                ));
            }
        }
        let materialize_us = elapsed_us(materialize_started);
        self.metrics
            .state_image_bytes
            .store(state_size, Ordering::Relaxed);
        Ok(PostgresDoctor {
            backend_kind: "postgres-wrapped-sqlite-snapshot",
            experimental: true,
            connected: true,
            backend_schema_version: conn
                .query_one("SELECT max(version) FROM ocfleet_backend_migrations", &[])?
                .get::<_, Option<i32>>(0)
                .unwrap_or_default(),
            format_version: row.get(0),
            schema_version,
            state_revision,
            state_updated_at: row.get(5),
            state_sha256: checksum,
            state_size,
            recommended_state_image_bytes: RECOMMENDED_STATE_IMAGE_BYTES,
            hard_state_image_limit_bytes: MAX_STATE_IMAGE_BYTES,
            above_recommended_state_size: state_size > RECOMMENDED_STATE_IMAGE_BYTES,
            read_consistency: "snapshot-at-query-start; no cross-request read-after-write guarantee",
            checksum_valid,
            pool_max_size: self.pool.max_size(),
            doctor_download_us: download_us,
            doctor_materialize_us: materialize_us,
            doctor_total_us: elapsed_us(started),
            runtime_metrics: self.runtime_metrics(),
        })
    }

    pub fn import_sqlite(&self, path: &Path, dry_run: bool) -> Result<ImportReport, PostgresError> {
        let total_started = Instant::now();
        let snapshot_started = Instant::now();
        let (image, schema_version, counts) = snapshot_sqlite(path)?;
        let snapshot_us = elapsed_us(snapshot_started);
        let source_sha256 = sha256(&image);
        let (
            already_current,
            advisory_lock_wait_us,
            upload_commit_us,
            lease_remaining_ms,
            state_revision,
        ) = if !dry_run {
            self.metrics
                .write_operations
                .fetch_add(1, Ordering::Relaxed);
            self.metrics
                .last_write_owned_image_bytes
                .store(image.len() as u64, Ordering::Relaxed);
            let write_started = Instant::now();
            let outcome = (|| {
                let mut conn = self.connection()?;
                let mut tx = conn.transaction()?;
                let lock_started = Instant::now();
                tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK_ID])?;
                let advisory_lock_wait_us = elapsed_us(lock_started);
                let lease_remaining_ms = self.lock_write_fence(&mut tx)?;
                let row = tx.query_one(
                    "SELECT state_sha256, state_revision
                         FROM ocfleet_runtime_state
                         WHERE singleton = TRUE FOR UPDATE",
                    &[],
                )?;
                let current_sha256: String = row.get(0);
                let current_revision = positive_u64(row.get(1), "state revision")?;
                let already_current = current_sha256 == source_sha256;
                let upload_started = Instant::now();
                let state_revision = if already_current {
                    current_revision
                } else {
                    insert_state(&mut tx, &image)?
                };
                let import_id = uuid::Uuid::new_v4().to_string();
                tx.execute(
                    "INSERT INTO ocfleet_imports
                           (import_id, source_sha256, source_size, verified, completed_at)
                         VALUES ($1::text::uuid, $2, $3, TRUE, clock_timestamp())
                         ON CONFLICT(source_sha256, source_size) DO UPDATE SET
                           verified = TRUE,
                           completed_at = COALESCE(ocfleet_imports.completed_at,
                                                   clock_timestamp())",
                    &[&import_id, &source_sha256, &(image.len() as i64)],
                )?;
                self.recheck_write_fence(&mut tx)?;
                tx.commit()?;
                Ok((
                    already_current,
                    state_revision,
                    advisory_lock_wait_us,
                    elapsed_us(upload_started),
                    lease_remaining_ms,
                ))
            })();
            self.metrics
                .last_write_total_us
                .store(elapsed_us(write_started), Ordering::Relaxed);
            let (already_current, state_revision, lock_us, upload_us, lease_ms) = match outcome {
                Ok(values) => values,
                Err(error) => {
                    self.metrics
                        .failed_write_operations
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(error);
                }
            };
            self.metrics
                .last_advisory_lock_wait_us
                .store(lock_us, Ordering::Relaxed);
            self.metrics
                .last_upload_commit_us
                .store(upload_us, Ordering::Relaxed);
            self.metrics
                .last_lease_remaining_ms
                .store(lease_ms, Ordering::Relaxed);
            self.metrics
                .state_image_bytes
                .store(image.len() as u64, Ordering::Relaxed);
            (
                already_current,
                lock_us,
                upload_us,
                lease_ms,
                Some(state_revision),
            )
        } else {
            let mut conn = self.connection()?;
            (
                load_state(&mut conn).map(|state| sha256(&state) == source_sha256)?,
                0,
                0,
                0,
                None,
            )
        };
        Ok(ImportReport {
            dry_run,
            already_current,
            source_sha256,
            source_size: image.len() as u64,
            recommended_state_image_bytes: RECOMMENDED_STATE_IMAGE_BYTES,
            above_recommended_state_size: image.len() as u64 > RECOMMENDED_STATE_IMAGE_BYTES,
            schema_version,
            counts_verified: counts,
            state_revision,
            snapshot_us,
            advisory_lock_wait_us,
            upload_commit_us,
            lease_remaining_ms,
            total_us: elapsed_us(total_started),
        })
    }

    pub fn export_sqlite(&self, path: &Path) -> Result<ExportReport, PostgresError> {
        let total_started = Instant::now();
        let mut conn = self.connection()?;
        let download_started = Instant::now();
        let image = load_state(&mut conn)?;
        let download_us = elapsed_us(download_started);
        let verify_started = Instant::now();
        let (schema_version, counts_verified) = verify_image(&image)?;
        let materialize_verify_us = elapsed_us(verify_started);
        let state_sha256 = sha256(&image);
        let mut output = private_file::open_private_create_new_strict(path)?;
        output.write_all(&image)?;
        output.flush()?;
        output.sync_all()?;
        Ok(ExportReport {
            state_sha256,
            state_size: image.len() as u64,
            recommended_state_image_bytes: RECOMMENDED_STATE_IMAGE_BYTES,
            above_recommended_state_size: image.len() as u64 > RECOMMENDED_STATE_IMAGE_BYTES,
            schema_version,
            counts_verified,
            download_us,
            materialize_verify_us,
            total_us: elapsed_us(total_started),
        })
    }

    /// Acquires or renews a bounded distributed lease. Every successful new
    /// ownership epoch increments the fencing token; stale holders therefore
    /// cannot commit through a fenced writer after failover.
    pub fn acquire_lease(
        &self,
        name: &str,
        owner_id: &str,
        ttl_seconds: u32,
    ) -> Result<Option<ControllerLease>, PostgresError> {
        validate_lease(name, owner_id, ttl_seconds)?;
        let mut conn = self.connection()?;
        let row = conn.query_opt(
            "INSERT INTO ocfleet_controller_leases(lease_name, owner_id, fencing_token, lease_until)
             VALUES($1,$2,1,now() + make_interval(secs => $3))
             ON CONFLICT(lease_name) DO UPDATE SET
               owner_id = EXCLUDED.owner_id,
               fencing_token = CASE WHEN ocfleet_controller_leases.owner_id = EXCLUDED.owner_id AND ocfleet_controller_leases.lease_until > now() THEN ocfleet_controller_leases.fencing_token ELSE ocfleet_controller_leases.fencing_token + 1 END,
               lease_until = EXCLUDED.lease_until, updated_at = now()
             WHERE ocfleet_controller_leases.lease_until <= now() OR ocfleet_controller_leases.owner_id = EXCLUDED.owner_id
             RETURNING owner_id, fencing_token, extract(epoch from lease_until)::BIGINT",
            &[&name, &owner_id, &(ttl_seconds as f64)],
        )?;
        Ok(row.map(|row| ControllerLease {
            name: name.into(),
            owner_id: row.get(0),
            fencing_token: row.get::<_, i64>(1) as u64,
            lease_until_unix: row.get(2),
        }))
    }

    pub fn verify_fence(&self, lease: &ControllerLease) -> Result<bool, PostgresError> {
        let mut conn = self.connection()?;
        Ok(conn.query_opt(
            "SELECT 1 FROM ocfleet_controller_leases WHERE lease_name=$1 AND owner_id=$2 AND fencing_token=$3 AND lease_until > clock_timestamp()",
            &[&lease.name, &lease.owner_id, &(lease.fencing_token as i64)],
        )?.is_some())
    }

    /// Returns a writer view whose lease is revalidated while holding the same
    /// Postgres transaction that replaces controller state.
    pub fn fenced(&self, lease: ControllerLease) -> Result<Self, PostgresError> {
        validate_lease(&lease.name, &lease.owner_id, 1)?;
        if lease.fencing_token == 0 {
            return Err(PostgresError::StaleFence);
        }
        Ok(Self {
            pool: self.pool.clone(),
            write_fence: Some(lease),
            metrics: Arc::clone(&self.metrics),
        })
    }

    pub fn runtime_metrics(&self) -> PostgresSnapshotRuntimeMetrics {
        self.metrics.snapshot()
    }

    fn connection(
        &self,
    ) -> Result<PooledConnection<PostgresConnectionManager<NoTls>>, PostgresError> {
        Ok(self.pool.get()?)
    }

    fn with_store<T>(
        &self,
        callback: impl FnOnce(&Store) -> Result<T, StoreError>,
    ) -> Result<T, PostgresError> {
        self.metrics.read_operations.fetch_add(1, Ordering::Relaxed);
        let total_started = Instant::now();
        let outcome = (|| {
            let mut conn = self.connection()?;
            let download_started = Instant::now();
            let image = load_state(&mut conn)?;
            self.metrics
                .last_download_us
                .store(elapsed_us(download_started), Ordering::Relaxed);
            self.metrics
                .state_image_bytes
                .store(image.len() as u64, Ordering::Relaxed);
            let materialize_started = Instant::now();
            let (_temp, store) = materialize(&image)?;
            self.metrics
                .last_materialize_us
                .store(elapsed_us(materialize_started), Ordering::Relaxed);
            Ok(callback(&store)?)
        })();
        self.metrics
            .last_read_total_us
            .store(elapsed_us(total_started), Ordering::Relaxed);
        if outcome.is_err() {
            self.metrics
                .failed_read_operations
                .fetch_add(1, Ordering::Relaxed);
        }
        outcome
    }

    fn with_write<T>(
        &self,
        callback: impl FnOnce(&Store) -> Result<T, StoreError>,
    ) -> Result<T, PostgresError> {
        self.metrics
            .write_operations
            .fetch_add(1, Ordering::Relaxed);
        let total_started = Instant::now();
        let outcome = (|| {
            let mut conn = self.connection()?;
            let mut tx = conn.transaction()?;
            let lock_started = Instant::now();
            tx.query_one(
                "SELECT pg_advisory_xact_lock($1)",
                &[&(MIGRATION_LOCK_ID + 1)],
            )?;
            self.metrics
                .last_advisory_lock_wait_us
                .store(elapsed_us(lock_started), Ordering::Relaxed);
            let lease_remaining_ms = self.lock_write_fence(&mut tx)?;
            self.metrics
                .last_lease_remaining_ms
                .store(lease_remaining_ms, Ordering::Relaxed);
            let state_size = tx
                .query_one(
                    "SELECT octet_length(state_bytes)::BIGINT FROM ocfleet_runtime_state WHERE singleton = TRUE",
                    &[],
                )?
                .get::<_, i64>(0);
            if state_size < 0 || state_size as u64 > MAX_STATE_IMAGE_BYTES {
                return Err(PostgresError::InvalidState(
                    "stored state image exceeds the configured limit".into(),
                ));
            }
            let download_started = Instant::now();
            let row = tx.query_one("SELECT format_version, state_sha256, state_bytes FROM ocfleet_runtime_state WHERE singleton = TRUE FOR UPDATE", &[])?;
            self.metrics
                .last_download_us
                .store(elapsed_us(download_started), Ordering::Relaxed);
            let format: i32 = row.get(0);
            if format != FORMAT_VERSION {
                return Err(PostgresError::UnsupportedFormat(format));
            }
            let checksum: String = row.get(1);
            let image: Vec<u8> = row.get(2);
            self.metrics
                .state_image_bytes
                .store(image.len() as u64, Ordering::Relaxed);
            if sha256(&image) != checksum {
                return Err(PostgresError::Checksum);
            }
            let materialize_started = Instant::now();
            let (temp, store) = materialize(&image)?;
            self.metrics
                .last_materialize_us
                .store(elapsed_us(materialize_started), Ordering::Relaxed);
            let result = callback(&store)?;
            drop(store);
            if std::fs::metadata(temp.path())?.len() > MAX_STATE_IMAGE_BYTES {
                return Err(PostgresError::InvalidState(
                    "updated state image exceeds the configured limit".into(),
                ));
            }
            let updated = std::fs::read(temp.path())?;
            self.metrics.last_write_owned_image_bytes.store(
                (image.len() as u64).saturating_add(updated.len() as u64),
                Ordering::Relaxed,
            );
            let upload_started = Instant::now();
            insert_state(&mut tx, &updated)?;
            self.recheck_write_fence(&mut tx)?;
            tx.commit()?;
            self.metrics
                .last_upload_commit_us
                .store(elapsed_us(upload_started), Ordering::Relaxed);
            self.metrics
                .state_image_bytes
                .store(updated.len() as u64, Ordering::Relaxed);
            Ok(result)
        })();
        self.metrics
            .last_write_total_us
            .store(elapsed_us(total_started), Ordering::Relaxed);
        if outcome.is_err() {
            self.metrics
                .failed_write_operations
                .fetch_add(1, Ordering::Relaxed);
        }
        outcome
    }

    fn lock_write_fence(&self, tx: &mut Transaction<'_>) -> Result<u64, PostgresError> {
        let fence = self
            .write_fence
            .as_ref()
            .ok_or(PostgresError::FenceRequired)?;
        let remaining = tx
            .query_opt(
                "SELECT floor(extract(epoch FROM (lease_until - clock_timestamp())) * 1000)::BIGINT
                 FROM ocfleet_controller_leases
                 WHERE lease_name=$1 AND owner_id=$2 AND fencing_token=$3
                 FOR SHARE",
                &[&fence.name, &fence.owner_id, &(fence.fencing_token as i64)],
            )?
            .ok_or(PostgresError::StaleFence)?
            .get::<_, i64>(0);
        if remaining <= 0 {
            return Err(PostgresError::StaleFence);
        }
        positive_u64(remaining, "lease remaining time")
    }

    fn recheck_write_fence(&self, tx: &mut Transaction<'_>) -> Result<(), PostgresError> {
        let fence = self
            .write_fence
            .as_ref()
            .ok_or(PostgresError::FenceRequired)?;
        let valid = tx
            .query_opt(
                "SELECT 1 FROM ocfleet_controller_leases
                 WHERE lease_name=$1 AND owner_id=$2 AND fencing_token=$3
                   AND lease_until > clock_timestamp()",
                &[&fence.name, &fence.owner_id, &(fence.fencing_token as i64)],
            )?
            .is_some();
        if !valid {
            return Err(PostgresError::StaleFence);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PostgresDoctor {
    pub backend_kind: &'static str,
    pub experimental: bool,
    pub connected: bool,
    pub backend_schema_version: i32,
    pub format_version: i32,
    pub schema_version: i64,
    pub state_revision: u64,
    pub state_updated_at: String,
    pub state_sha256: String,
    pub state_size: u64,
    pub recommended_state_image_bytes: u64,
    pub hard_state_image_limit_bytes: u64,
    pub above_recommended_state_size: bool,
    pub read_consistency: &'static str,
    pub checksum_valid: bool,
    pub pool_max_size: u32,
    pub doctor_download_us: u64,
    pub doctor_materialize_us: u64,
    pub doctor_total_us: u64,
    pub runtime_metrics: PostgresSnapshotRuntimeMetrics,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct PostgresSnapshotRuntimeMetrics {
    pub state_image_bytes: u64,
    pub read_operations: u64,
    pub failed_read_operations: u64,
    pub write_operations: u64,
    pub failed_write_operations: u64,
    pub last_download_us: u64,
    pub last_read_total_us: u64,
    pub last_write_total_us: u64,
    /// Sum of snapshot `Vec` lengths owned at the write high-water point.
    /// This excludes allocator, Postgres driver, and SQLite process overhead.
    pub last_write_owned_image_bytes: u64,
    pub last_materialize_us: u64,
    pub last_upload_commit_us: u64,
    pub last_advisory_lock_wait_us: u64,
    pub last_lease_remaining_ms: u64,
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct ImportReport {
    pub dry_run: bool,
    pub already_current: bool,
    pub source_sha256: String,
    pub source_size: u64,
    pub recommended_state_image_bytes: u64,
    pub above_recommended_state_size: bool,
    pub schema_version: i64,
    pub counts_verified: u64,
    pub state_revision: Option<u64>,
    pub snapshot_us: u64,
    pub advisory_lock_wait_us: u64,
    pub upload_commit_us: u64,
    pub lease_remaining_ms: u64,
    pub total_us: u64,
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExportReport {
    pub state_sha256: String,
    pub state_size: u64,
    pub recommended_state_image_bytes: u64,
    pub above_recommended_state_size: bool,
    pub schema_version: i64,
    pub counts_verified: u64,
    pub download_us: u64,
    pub materialize_verify_us: u64,
    pub total_us: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ControllerLease {
    pub name: String,
    pub owner_id: String,
    pub fencing_token: u64,
    pub lease_until_unix: i64,
}

impl StoreReader for PostgresSnapshotStore {
    type Error = PostgresError;
    fn backend_kind(&self) -> BackendKind {
        BackendKind::PostgresSnapshot
    }
    fn read_nodes(&self, limit: u64) -> Result<Vec<NodeRecord>, Self::Error> {
        checked_limit(limit)?;
        self.with_store(|s| s.list_nodes_limited(limit))
    }
    fn read_node(&self, id: &str) -> Result<Option<NodeRecord>, Self::Error> {
        self.with_store(|s| s.get_node(id))
    }
    fn read_jobs(&self, limit: u64) -> Result<Vec<ObservabilityJobRecord>, Self::Error> {
        checked_limit(limit)?;
        self.with_store(|s| <Store as StoreReader>::read_jobs(s, limit))
    }
    fn read_runs(&self, limit: u64) -> Result<Vec<ObservabilityRunRecord>, Self::Error> {
        checked_limit(limit)?;
        self.with_store(|s| <Store as StoreReader>::read_runs(s, limit))
    }
    fn read_observations(
        &self,
        node: Option<&str>,
        method: Option<&str>,
        limit: u64,
    ) -> Result<Vec<ProbeObservationRecord>, Self::Error> {
        checked_limit(limit)?;
        self.with_store(|s| <Store as StoreReader>::read_observations(s, node, method, limit))
    }
    fn read_health_snapshots(&self, limit: u64) -> Result<Vec<HealthSnapshotRecord>, Self::Error> {
        checked_limit(limit)?;
        self.with_store(|s| <Store as StoreReader>::read_health_snapshots(s, limit))
    }
    fn read_alerts(&self, limit: u64) -> Result<Vec<AlertEventRecord>, Self::Error> {
        checked_limit(limit)?;
        self.with_store(|s| <Store as StoreReader>::read_alerts(s, limit))
    }
    fn read_audit_window(
        &self,
        from: &str,
        to: &str,
        limit: usize,
    ) -> Result<Vec<AuditRecord>, Self::Error> {
        if limit == 0 || limit > MAX_STORE_READER_ROWS as usize {
            return Err(PostgresError::InvalidState(
                "query limit is out of bounds".into(),
            ));
        }
        self.with_store(|s| <Store as StoreReader>::read_audit_window(s, from, to, limit))
    }
}

macro_rules! forward_write {
    ($name:ident($($arg:ident : $ty:ty),*) -> $ret:ty => $method:ident) => {
        fn $name(&self, $($arg: $ty),*) -> Result<$ret, Self::Error> {
            self.with_write(|store| store.$method($($arg),*))
        }
    };
}

impl StoreWriter for PostgresSnapshotStore {
    type Error = PostgresError;
    forward_write!(write_node_add(node: &NodeInsert, actor: &str) -> () => add_node);
    forward_write!(write_node_enable(node_id: &str, actor: &str) -> () => enable_node);
    forward_write!(write_node_disable(node_id: &str, actor: &str) -> () => disable_node);
    forward_write!(write_node_remove(node_id: &str, actor: &str) -> () => remove_node);
    forward_write!(write_node_metadata(metadata: &NodeMetadataRecord, actor: &str) -> () => set_node_metadata);
    forward_write!(write_node_maintenance_set(window: &NodeMaintenanceWindow, actor: &str) -> () => set_node_maintenance);
    forward_write!(write_node_maintenance_clear(node_id: &str, actor: &str) -> bool => clear_node_maintenance);
    fn write_node_capability_snapshot(
        &self,
        snapshot: &CapabilitySnapshot,
        audit: &AuditEvent,
    ) -> Result<(), Self::Error> {
        self.with_write(|store| store.upsert_node_capability_snapshot_with_audit(snapshot, audit))
    }
    forward_write!(write_scheduler_job_add(job: &ObservabilityJobRecord, actor: &str) -> () => insert_observability_job);
    fn write_scheduler_job_enable(&self, job_id: &str, actor: &str) -> Result<(), Self::Error> {
        self.with_write(|s| s.set_observability_job_enabled(job_id, true, actor))
    }
    fn write_scheduler_job_disable(&self, job_id: &str, actor: &str) -> Result<(), Self::Error> {
        self.with_write(|s| s.set_observability_job_enabled(job_id, false, actor))
    }
    forward_write!(write_scheduler_maintenance_set(window: &SchedulerMaintenanceWindow, actor: &str) -> () => set_scheduler_maintenance);
    forward_write!(write_scheduler_maintenance_clear(cleared_at: &str, actor: &str) -> bool => clear_scheduler_maintenance);
    forward_write!(write_scheduler_claim_next_due(owner_id: &str, now: &str, lease_seconds: u64, actor: &str) -> Option<SchedulerJobClaim> => claim_next_due_scheduler_job);
    forward_write!(write_scheduler_claim(job_id: &str, owner_id: &str, now: &str, lease_seconds: u64, actor: &str) -> Option<SchedulerJobClaim> => claim_scheduler_job);
    forward_write!(write_scheduler_claim_due(job_id: &str, owner_id: &str, now: &str, lease_seconds: u64, actor: &str) -> Option<SchedulerJobClaim> => claim_due_scheduler_job);
    forward_write!(write_scheduler_claim_renew(claim: &SchedulerJobClaim, now: &str, lease_seconds: u64, actor: &str) -> SchedulerJobClaim => renew_scheduler_job_claim);
    forward_write!(write_scheduler_claim_release(claim: &SchedulerJobClaim, released_at: &str, actor: &str) -> () => release_scheduler_job_claim);
    forward_write!(write_scheduler_run_start(start: &SchedulerRunStart, actor: &str) -> () => write_scheduler_run_start);
    forward_write!(write_scheduler_claimed_run_start(start: &SchedulerRunStart, claim: &SchedulerJobClaim, actor: &str) -> () => write_scheduler_claimed_run_start);
    forward_write!(write_scheduler_outcome(outcome: &SchedulerOutcomeWrite, actor: &str) -> () => write_scheduler_outcome);
    forward_write!(write_scheduler_run_finish(finish: &SchedulerRunFinish, actor: &str) -> () => write_scheduler_run_finish);
    forward_write!(write_health_policy(policy: &HealthPolicyRecord, actor: &str) -> () => set_health_policy);
    forward_write!(write_health_snapshots(write: &HealthSnapshotWrite, actor: &str) -> () => write_health_snapshots);
    forward_write!(write_health_evaluation_start(start: &HealthEvaluationStart, actor: &str) -> () => write_health_evaluation_start);
    forward_write!(write_health_evaluation_finish(finish: &HealthEvaluationFinish, actor: &str) -> () => write_health_evaluation_finish);
    forward_write!(write_health_evaluation_failure(failure: &HealthEvaluationFailure, actor: &str) -> () => write_health_evaluation_failure);
    forward_write!(write_health_evaluation_recovery(cutoff: &str, recovered_at: &str, actor: &str) -> usize => write_health_evaluation_recovery);
    forward_write!(write_health_rollups(write: &HealthRollupWrite, actor: &str) -> () => write_health_rollups);
    forward_write!(write_alert_evaluation(write: &AlertEvaluationWrite, actor: &str) -> () => write_alert_evaluation);
    forward_write!(write_alert_state_transition(write: &AlertStateTransition, actor: &str) -> () => write_alert_state_transition);
    forward_write!(write_alert_webhook_hook_create(hook: &AlertWebhookHookRecord, actor: &str) -> () => write_alert_webhook_hook_create);
    forward_write!(write_alert_webhook_hook_enabled(hook_id: &str, enabled: bool, updated_at: &str, actor: &str) -> bool => write_alert_webhook_hook_enabled);
    forward_write!(write_alert_delivery_attempt(write: &AlertDeliveryAttemptWrite, actor: &str) -> () => write_alert_delivery_attempt);
    forward_write!(write_alert_delivery_queue_enqueue(enqueue: &AlertDeliveryQueueEnqueue, actor: &str) -> () => write_alert_delivery_queue_enqueue);
    forward_write!(write_alert_delivery_queue_claim_next(owner_id: &str, now: &str, lease_seconds: u64, actor: &str) -> Option<AlertDeliveryQueueClaim> => write_alert_delivery_queue_claim_next);
    forward_write!(write_alert_delivery_queue_renew(claim: &AlertDeliveryQueueClaim, now: &str, lease_seconds: u64, actor: &str) -> AlertDeliveryQueueClaim => write_alert_delivery_queue_renew);
    forward_write!(write_alert_delivery_queue_outcome(outcome: &AlertDeliveryQueueOutcome, actor: &str) -> () => write_alert_delivery_queue_outcome);
    forward_write!(write_alert_delivery_queue_defer(claim: &AlertDeliveryQueueClaim, deferred_at: &str, next_attempt_at: &str, actor: &str) -> () => write_alert_delivery_queue_defer);
    forward_write!(write_alert_delivery_finalize(write: &AlertDeliveryFinalizeWrite, actor: &str) -> () => write_alert_delivery_finalize);
    forward_write!(write_retention_policy(policy: &RetentionPolicyRecord, actor: &str) -> RetentionPolicyRecord => set_retention_policy);
    forward_write!(write_retention_apply(input: &RetentionApplyInput, actor: &str) -> RetentionApplyResult => apply_retention);
    forward_write!(write_enrollment_token_create(token: &EnrollmentTokenInsert, actor: &str) -> EnrollmentTokenRecord => create_enrollment_token);
    forward_write!(write_enrollment_token_revoke(token_id: &str, actor: &str, reason: &str) -> EnrollmentTokenRecord => revoke_enrollment_token);
    forward_write!(write_enrollment_request_submit(request: &JoinRequestInsert, actor: &str) -> JoinRequestRecord => submit_join_request);
    forward_write!(write_enrollment_request_reject(request_id: &str, actor: &str, reason: &str) -> JoinRequestRecord => reject_join_request);
    forward_write!(write_enrollment_approval(approval: &ApprovalInput, actor: &str) -> JoinRequestRecord => approve_join_request);
    forward_write!(write_legacy_enrollment_claim(claim: &LegacyEnrollmentClaimInput, actor: &str) -> JoinRequestRecord => claim_legacy_enrollment);
    forward_write!(write_endpoint_rotation(old_endpoint_id: &str, new_endpoint_id: &str, actor: &str, reason: &str) -> EndpointTrustRecord => rotate_endpoint);
    forward_write!(write_endpoint_revocation(endpoint_id: &str, actor: &str, reason: &str) -> EndpointTrustRecord => revoke_endpoint);
    forward_write!(write_endpoint_quarantine(endpoint_id: &str, actor: &str, reason: &str) -> EndpointTrustRecord => quarantine_endpoint);
}

impl MigrationManager for PostgresSnapshotStore {
    type Error = PostgresError;
    fn schema_version(&self) -> Result<i64, Self::Error> {
        Ok(self.doctor()?.schema_version)
    }
    fn migration_backend(&self) -> BackendKind {
        BackendKind::PostgresSnapshot
    }
}

impl AuditWriter for PostgresSnapshotStore {
    type Error = PostgresError;
    fn append_audit(&self, event: &AuditEvent) -> Result<(), Self::Error> {
        self.with_write(|store| store.insert_audit(event))
    }
}

fn validate_dsn(dsn: &str) -> Result<(), PostgresError> {
    if dsn.is_empty()
        || dsn.len() > MAX_DSN_BYTES
        || !(dsn.starts_with("postgres://") || dsn.starts_with("postgresql://"))
    {
        return Err(PostgresError::Configuration(
            "Postgres DSN must be a bounded postgres URL",
        ));
    }
    Ok(())
}

fn validate_transport(config: &Config) -> Result<(), PostgresError> {
    let local_only = config.get_hosts().iter().all(|host| match host {
        Host::Tcp(host) => matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1"),
        #[cfg(unix)]
        Host::Unix(_) => true,
    });
    if !local_only {
        return Err(PostgresError::Configuration(
            "NoTls Postgres connections are restricted to Unix sockets or loopback",
        ));
    }
    Ok(())
}
fn validate_lease(name: &str, owner: &str, ttl: u32) -> Result<(), PostgresError> {
    let valid = |value: &str| {
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
    };
    if !valid(name) || !valid(owner) || !(1..=300).contains(&ttl) {
        return Err(PostgresError::InvalidState(
            "lease name, owner, or TTL is invalid".into(),
        ));
    }
    Ok(())
}
fn checked_limit(limit: u64) -> Result<(), PostgresError> {
    if limit == 0 || limit > MAX_STORE_READER_ROWS {
        Err(PostgresError::InvalidState(
            "query limit is out of bounds".into(),
        ))
    } else {
        Ok(())
    }
}
fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

fn positive_u64(value: i64, label: &str) -> Result<u64, PostgresError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            PostgresError::InvalidState(format!("{label} is outside the supported range"))
        })
}

fn empty_sqlite_image() -> Result<Vec<u8>, PostgresError> {
    let directory = private_tempdir()?;
    let path = directory.path().join("state.sqlite3");
    let store = Store::open(&path)?;
    drop(store);
    Ok(std::fs::read(path)?)
}

fn load_state(conn: &mut postgres::Client) -> Result<Vec<u8>, PostgresError> {
    check_state_size(conn)?;
    let row = conn.query_one("SELECT format_version, state_sha256, state_bytes FROM ocfleet_runtime_state WHERE singleton = TRUE", &[])?;
    let format: i32 = row.get(0);
    if format != FORMAT_VERSION {
        return Err(PostgresError::UnsupportedFormat(format));
    }
    let checksum: String = row.get(1);
    let image: Vec<u8> = row.get(2);
    if sha256(&image) != checksum {
        return Err(PostgresError::Checksum);
    }
    Ok(image)
}

fn insert_state(tx: &mut Transaction<'_>, image: &[u8]) -> Result<u64, PostgresError> {
    if image.len() as u64 > MAX_STATE_IMAGE_BYTES {
        return Err(PostgresError::InvalidState(
            "state image exceeds the configured limit".into(),
        ));
    }
    let (schema, _) = verify_image(image)?;
    let checksum = sha256(image);
    let revision = tx
        .query_one(
            "INSERT INTO ocfleet_runtime_state
               (singleton, format_version, sqlite_schema_version, state_revision,
                state_sha256, state_bytes, updated_at)
             VALUES(TRUE,$1,$2,1,$3,$4,clock_timestamp())
             ON CONFLICT(singleton) DO UPDATE SET
               format_version=EXCLUDED.format_version,
               sqlite_schema_version=EXCLUDED.sqlite_schema_version,
               state_revision=ocfleet_runtime_state.state_revision + 1,
               state_sha256=EXCLUDED.state_sha256,
               state_bytes=EXCLUDED.state_bytes,
               updated_at=clock_timestamp()
             RETURNING state_revision",
            &[&FORMAT_VERSION, &schema, &checksum, &image],
        )?
        .get::<_, i64>(0);
    positive_u64(revision, "state revision")
}

fn check_state_size(conn: &mut postgres::Client) -> Result<u64, PostgresError> {
    let row = conn.query_one(
        "SELECT octet_length(state_bytes)::BIGINT FROM ocfleet_runtime_state WHERE singleton = TRUE",
        &[],
    )?;
    let size = row.get::<_, i64>(0);
    if size < 0 || size as u64 > MAX_STATE_IMAGE_BYTES {
        return Err(PostgresError::InvalidState(
            "stored state image exceeds the configured limit".into(),
        ));
    }
    Ok(size as u64)
}

struct PrivateTempFile {
    _directory: TempDir,
    file: NamedTempFile,
}

impl PrivateTempFile {
    fn new() -> Result<Self, std::io::Error> {
        let directory = private_tempdir()?;
        let file = NamedTempFile::new_in(directory.path())?;
        Ok(Self {
            _directory: directory,
            file,
        })
    }

    fn path(&self) -> &Path {
        self.file.path()
    }
}

impl Write for PrivateTempFile {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.file.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

fn private_tempdir() -> Result<TempDir, std::io::Error> {
    let directory = tempfile::Builder::new()
        .prefix("ocfleet-postgres-state-")
        .tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(directory)
}

fn materialize(image: &[u8]) -> Result<(PrivateTempFile, Store), PostgresError> {
    let temp = stage_image(image)?;
    verify_staged_image(temp.path())?;
    let store = Store::open(temp.path())?;
    Ok((temp, store))
}

fn verify_image(image: &[u8]) -> Result<(i64, u64), PostgresError> {
    if image.len() < 16 || &image[..16] != b"SQLite format 3\0" {
        return Err(PostgresError::InvalidState(
            "source is not a SQLite database".into(),
        ));
    }
    let temp = stage_image(image)?;
    verify_staged_image(temp.path())
}

fn stage_image(image: &[u8]) -> Result<PrivateTempFile, PostgresError> {
    if image.len() as u64 > MAX_STATE_IMAGE_BYTES {
        return Err(PostgresError::InvalidState(
            "state image exceeds the configured limit".into(),
        ));
    }
    let mut temp = PrivateTempFile::new()?;
    temp.write_all(image)?;
    temp.flush()?;
    Ok(temp)
}

fn verify_staged_image(path: &Path) -> Result<(i64, u64), PostgresError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.pragma_update(None, "query_only", "ON")?;
    connection.pragma_update(None, "busy_timeout", 5_000)?;

    let integrity: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(PostgresError::InvalidState(
            "SQLite quick_check failed".into(),
        ));
    }
    let (migration_count, minimum_schema, schema): (i64, Option<i64>, Option<i64>) = connection
        .query_row(
            "SELECT COUNT(*), MIN(version), MAX(version) FROM schema_migrations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    let schema = schema.unwrap_or_default();
    if schema != CURRENT_SCHEMA_VERSION {
        return Err(PostgresError::InvalidState(format!(
            "source schema {schema} does not match required schema {CURRENT_SCHEMA_VERSION}"
        )));
    }
    if minimum_schema != Some(1) || migration_count != CURRENT_SCHEMA_VERSION {
        return Err(PostgresError::InvalidState(
            "source schema migration history is incomplete".into(),
        ));
    }
    let mut counts = 0_u64;
    for table in ["nodes", "observability_jobs", "alert_events"] {
        let count = bounded_table_count(&connection, table)?;
        counts = counts.checked_add(count).ok_or_else(|| {
            PostgresError::InvalidState("verified row count exceeds the supported range".into())
        })?;
    }
    Ok((schema, counts))
}

fn bounded_table_count(connection: &Connection, table: &str) -> Result<u64, PostgresError> {
    let sql = format!("SELECT COUNT(*) FROM (SELECT 1 FROM {table} LIMIT ?1)");
    let count: i64 = connection.query_row(
        &sql,
        [i64::try_from(MAX_VERIFICATION_ROWS_PER_TABLE + 1).expect("bounded row limit")],
        |row| row.get(0),
    )?;
    if count < 0 || count as u64 > MAX_VERIFICATION_ROWS_PER_TABLE {
        return Err(PostgresError::InvalidState(format!(
            "SQLite table {table} exceeds the verification row limit"
        )));
    }
    Ok(count as u64)
}

fn snapshot_sqlite(path: &Path) -> Result<(Vec<u8>, i64, u64), PostgresError> {
    validate_sqlite_source(path)?;
    let source = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    source.pragma_update(None, "query_only", "ON")?;
    source.pragma_update(None, "busy_timeout", 5_000)?;
    let page_count: i64 = source.query_row("PRAGMA page_count", [], |row| row.get(0))?;
    let page_size: i64 = source.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    let logical_size = page_count.checked_mul(page_size).ok_or_else(|| {
        PostgresError::InvalidState("SQLite import size is outside the supported range".into())
    })?;
    if logical_size < 0 || logical_size as u64 > MAX_STATE_IMAGE_BYTES {
        return Err(PostgresError::InvalidState(
            "SQLite import exceeds the state image limit".into(),
        ));
    }

    let snapshot = PrivateTempFile::new()?;
    let mut destination = Connection::open(snapshot.path())?;
    {
        let backup = Backup::new(&source, &mut destination)?;
        backup.run_to_completion(BACKUP_PAGES_PER_STEP, Duration::from_millis(10), None)?;
    }
    drop(destination);
    drop(source);
    validate_sqlite_source(path)?;

    let size = std::fs::metadata(snapshot.path())?.len();
    if size > MAX_STATE_IMAGE_BYTES {
        return Err(PostgresError::InvalidState(
            "SQLite import exceeds the state image limit".into(),
        ));
    }
    let (schema_version, counts) = verify_staged_image(snapshot.path())?;
    let file = std::fs::File::open(snapshot.path())?;
    let mut image = Vec::with_capacity(size as usize);
    file.take(MAX_STATE_IMAGE_BYTES + 1)
        .read_to_end(&mut image)?;
    if image.len() as u64 > MAX_STATE_IMAGE_BYTES {
        return Err(PostgresError::InvalidState(
            "SQLite import exceeds the state image limit".into(),
        ));
    }
    if image.len() < 16 || &image[..16] != b"SQLite format 3\0" {
        return Err(PostgresError::InvalidState(
            "source is not a SQLite database".into(),
        ));
    }
    Ok((image, schema_version, counts))
}

fn validate_sqlite_source(path: &Path) -> Result<(), PostgresError> {
    let invalid_source = || {
        PostgresError::InvalidState(
            "SQLite source and sidecars must be private regular files".into(),
        )
    };
    private_file::validate_existing_private_file(path).map_err(|_| invalid_source())?;
    for sidecar in sqlite_sidecar_paths(path) {
        match std::fs::symlink_metadata(&sidecar) {
            Ok(_) => private_file::validate_existing_private_file(&sidecar)
                .map_err(|_| invalid_source())?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn sqlite_sidecar_paths(path: &Path) -> [PathBuf; 2] {
    let mut wal = path.as_os_str().to_os_string();
    wal.push("-wal");
    let mut shm = path.as_os_str().to_os_string();
    shm.push("-shm");
    [PathBuf::from(wal), PathBuf::from(shm)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::NodeInsert;
    #[test]
    fn connection_sources_never_debug_dsn_or_path() {
        let env = PostgresConnectionSource::Environment {
            variable: "postgres://user:secret@host/db".into(),
        };
        assert!(env.validate().is_err());
        let debug = format!("{env:?}");
        assert!(!debug.contains("secret"));
        let file = PostgresConnectionSource::PrivateConfigFile {
            path: PathBuf::from("/run/secrets/postgres.toml"),
        };
        assert!(!format!("{file:?}").contains("/run/secrets"));
    }

    #[test]
    fn no_tls_transport_rejects_remote_hosts() {
        let remote = Config::from_str("postgresql://db.example.test/ocfleet").expect("config");
        assert!(validate_transport(&remote).is_err());
        let loopback = Config::from_str("postgresql://127.0.0.1/ocfleet").expect("config");
        assert!(validate_transport(&loopback).is_ok());
    }

    #[test]
    fn snapshot_includes_committed_active_wal_records() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("active.sqlite3");
        let store = Store::open(&path).expect("store");
        store
            .add_node(
                &NodeInsert {
                    node_id: "node-active-wal".into(),
                    endpoint_id: iroh::SecretKey::generate().public().to_string(),
                    name: "node-active-wal".into(),
                    region: "test".into(),
                    role: "ocserv".into(),
                },
                "operator",
            )
            .expect("commit node");
        let [wal, _] = sqlite_sidecar_paths(&path);
        assert!(std::fs::metadata(wal).expect("WAL").len() > 0);

        let (image, _, _) = snapshot_sqlite(&path).expect("online snapshot");
        let snapshot = stage_image(&image).expect("stage snapshot");
        let connection = Connection::open_with_flags(
            snapshot.path(),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("inspect snapshot");
        let present: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM nodes WHERE node_id = 'node-active-wal'",
                [],
                |row| row.get(0),
            )
            .expect("read snapshotted node");
        assert_eq!(present, 1);
        drop(store);
    }

    #[test]
    fn snapshot_rejects_schema_27_without_migrating_source() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("schema-27.sqlite3");
        drop(Store::open(&path).expect("store"));
        let connection = Connection::open(&path).expect("downgrade fixture");
        connection
            .execute_batch(
                "DROP TABLE signed_bundles;
                 DROP TABLE write_operation_audit;
                 DROP TABLE write_operation_attempts;
                 DROP TABLE change_approvals;
                 DROP TABLE change_requests;
                 DELETE FROM schema_migrations WHERE version = 28;",
            )
            .expect("schema 27 fixture");
        drop(connection);

        assert!(matches!(
            snapshot_sqlite(&path),
            Err(PostgresError::InvalidState(_))
        ));
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("inspect source");
        let schema: i64 = connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("schema");
        assert_eq!(schema, 27);
    }
}
