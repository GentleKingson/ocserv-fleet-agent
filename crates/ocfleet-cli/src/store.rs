use rusqlite::{Connection, OptionalExtension, params};
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::audit::AuditEvent;
use crate::private_file::{self, PrivateFileError};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("controller state file permissions are unsafe")]
    UnsafePermissions,
    #[error("node not found: {0}")]
    NodeNotFound(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInsert {
    pub node_id: String,
    pub endpoint_id: String,
    pub name: String,
    pub region: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecord {
    pub node_id: String,
    pub endpoint_id: String,
    pub name: String,
    pub region: String,
    pub role: String,
    pub enabled: bool,
}

pub struct Store {
    conn: Connection,
}

pub struct StoreOpenResult {
    pub store: Store,
    pub created_database: bool,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let _created_database = create_database_file_if_missing(path)?;
        Self::open_existing_or_create(path)
    }

    pub fn open_with_status(path: &Path) -> Result<StoreOpenResult, StoreError> {
        let created_database = create_database_file_if_missing(path)?;
        let store = Self::open_existing_or_create(path)?;
        Ok(StoreOpenResult {
            store,
            created_database,
        })
    }

    fn open_existing_or_create(path: &Path) -> Result<Self, StoreError> {
        validate_database_files(path)?;
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", 5_000)?;

        let store = Self { conn };
        store.migrate()?;
        validate_database_files(path)?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS schema_migrations (
              version INTEGER PRIMARY KEY,
              applied_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS nodes (
              node_id TEXT PRIMARY KEY,
              endpoint_id TEXT NOT NULL UNIQUE,
              name TEXT NOT NULL,
              region TEXT,
              role TEXT NOT NULL DEFAULT 'ocserv',
              enabled INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS controller_audit_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts TEXT NOT NULL,
              actor TEXT NOT NULL,
              event TEXT NOT NULL,
              node_id TEXT,
              endpoint_id TEXT,
              method TEXT,
              request_id TEXT,
              params_hash TEXT,
              ok INTEGER,
              error_code TEXT,
              duration_ms INTEGER,
              detail_json TEXT
            );
            "#,
        )?;
        self.conn.execute(
            "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (1, strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
            [],
        )?;
        Ok(())
    }

    pub fn current_schema_version(&self) -> Result<i64, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT max(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })?)
    }

    pub fn add_node(&self, node: &NodeInsert) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO nodes (node_id, endpoint_id, name, region, role, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
            params![
                node.node_id,
                node.endpoint_id,
                node.name,
                node.region,
                node.role
            ],
        )?;
        Ok(())
    }

    pub fn get_node(&self, node_id: &str) -> Result<Option<NodeRecord>, StoreError> {
        self.conn
            .query_row(
                "SELECT node_id, endpoint_id, name, region, role, enabled FROM nodes WHERE node_id = ?1",
                [node_id],
                node_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn list_nodes(&self) -> Result<Vec<NodeRecord>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT node_id, endpoint_id, name, region, role, enabled FROM nodes ORDER BY node_id",
        )?;
        let rows = stmt.query_map([], node_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn disable_node(&self, node_id: &str) -> Result<(), StoreError> {
        let affected = self.conn.execute(
            "UPDATE nodes SET enabled = 0, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE node_id = ?1",
            [node_id],
        )?;
        if affected == 0 {
            return Err(StoreError::NodeNotFound(node_id.to_string()));
        }
        Ok(())
    }

    pub fn enable_node(&self, node_id: &str) -> Result<(), StoreError> {
        let affected = self.conn.execute(
            "UPDATE nodes SET enabled = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE node_id = ?1",
            [node_id],
        )?;
        if affected == 0 {
            return Err(StoreError::NodeNotFound(node_id.to_string()));
        }
        Ok(())
    }

    pub fn remove_node(&self, node_id: &str) -> Result<(), StoreError> {
        let affected = self
            .conn
            .execute("DELETE FROM nodes WHERE node_id = ?1", [node_id])?;
        if affected == 0 {
            return Err(StoreError::NodeNotFound(node_id.to_string()));
        }
        Ok(())
    }

    pub fn insert_audit(&self, event: &AuditEvent) -> Result<(), StoreError> {
        let ok = event.ok.map(|v| if v { 1_i64 } else { 0_i64 });
        let duration_ms = event.duration_ms.map(|v| v as i64);
        self.conn.execute(
            "INSERT INTO controller_audit_log
             (ts, actor, event, node_id, endpoint_id, method, request_id, params_hash, ok, error_code, duration_ms, detail_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                event.ts,
                event.actor,
                event.event,
                event.node_id,
                event.endpoint_id,
                event.method,
                event.request_id,
                event.params_hash,
                ok,
                event.error_code,
                duration_ms,
                event.detail_json.to_string(),
            ],
        )?;
        Ok(())
    }

    pub fn audit_count(&self) -> Result<i64, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT count(*) FROM controller_audit_log", [], |row| {
                row.get(0)
            })?)
    }
}

fn create_database_file_if_missing(path: &Path) -> Result<bool, StoreError> {
    match private_file::open_private_create_new(path) {
        Ok(_) => Ok(true),
        Err(PrivateFileError::Io(err)) if err.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(map_private_file_error(err)),
    }
}

fn validate_database_files(path: &Path) -> Result<(), StoreError> {
    private_file::validate_existing_private_file(path).map_err(map_private_file_error)?;
    for sidecar in sqlite_sidecar_paths(path) {
        match std::fs::symlink_metadata(&sidecar) {
            Ok(_) => {
                private_file::validate_existing_private_file(&sidecar)
                    .map_err(map_private_file_error)?;
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(StoreError::Io(err)),
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

fn map_private_file_error(err: PrivateFileError) -> StoreError {
    match err {
        PrivateFileError::Io(err) => StoreError::Io(err),
        PrivateFileError::MissingParent
        | PrivateFileError::UnsafeParent
        | PrivateFileError::UnsafeFile => StoreError::UnsafePermissions,
    }
}

fn node_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<NodeRecord> {
    Ok(NodeRecord {
        node_id: row.get(0)?,
        endpoint_id: row.get(1)?,
        name: row.get(2)?,
        region: row.get(3)?,
        role: row.get(4)?,
        enabled: row.get::<_, i64>(5)? == 1,
    })
}
