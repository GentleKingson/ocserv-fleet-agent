use iroh::EndpointId;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::identity::load_secret_key;
use crate::private_file;
use crate::store::CURRENT_SCHEMA_VERSION;

pub const DOCTOR_EXIT_OK: i32 = 0;
pub const DOCTOR_EXIT_UNHEALTHY: i32 = 1;
pub const DOCTOR_EXIT_USAGE: i32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorStatus {
    Ok,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Ok,
    Warning,
    Error,
}

impl CheckStatus {
    pub fn is_error(self) -> bool {
        self == Self::Error
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    pub id: String,
    pub status: CheckStatus,
    pub message: String,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub status: DoctorStatus,
    pub exit_code: i32,
    pub schema_version_expected: i64,
    pub schema_version_actual: Option<i64>,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone)]
pub struct DoctorOptions {
    pub database: PathBuf,
    pub secret_key: PathBuf,
}

#[derive(Debug, Clone)]
struct RegistryNode {
    node_id: String,
    endpoint_id: String,
    name: String,
    region: Option<String>,
    role: String,
}

pub fn run_doctor(options: &DoctorOptions) -> DoctorReport {
    let mut checks = Vec::new();
    check_directory(
        "controller_db.parent",
        options.database.parent(),
        &mut checks,
    );
    check_directory(
        "secret_key.parent",
        options.secret_key.parent(),
        &mut checks,
    );
    check_secret_key(options, &mut checks);

    let mut schema_version_actual = None;
    if !options.database.exists() {
        checks.push(error(
            "controller_db.exists",
            "controller database does not exist",
            json!({"path": options.database.display().to_string()}),
        ));
    } else {
        checks.push(ok(
            "controller_db.exists",
            "controller database exists",
            json!({"path": options.database.display().to_string()}),
        ));
        match private_file::validate_existing_private_file(&options.database) {
            Ok(()) => checks.push(ok(
                "controller_db.permissions",
                "controller database permissions are private",
                json!({"path": options.database.display().to_string()}),
            )),
            Err(err) => checks.push(error(
                "controller_db.permissions",
                "controller database permissions are unsafe or unreadable",
                json!({"path": options.database.display().to_string(), "error": err.to_string()}),
            )),
        }

        match open_read_only_database(&options.database) {
            Ok(conn) => {
                checks.push(ok(
                    "controller_db.open_readonly",
                    "controller database opened read-only",
                    json!({"path": options.database.display().to_string()}),
                ));
                schema_version_actual = check_schema(&conn, &mut checks);
                check_registry(&conn, &mut checks);
            }
            Err(err) => checks.push(error(
                "controller_db.open_readonly",
                "controller database could not be opened read-only",
                json!({"path": options.database.display().to_string(), "error": err.to_string()}),
            )),
        }
    }

    let status = report_status(&checks);
    let exit_code = if status == DoctorStatus::Error {
        DOCTOR_EXIT_UNHEALTHY
    } else {
        DOCTOR_EXIT_OK
    };
    DoctorReport {
        status,
        exit_code,
        schema_version_expected: CURRENT_SCHEMA_VERSION,
        schema_version_actual,
        checks,
    }
}

pub fn format_human(report: &DoctorReport) -> String {
    let mut output = String::new();
    output.push_str(&format!("ocfleet doctor: {:?}\n", report.status).to_lowercase());
    output.push_str(&format!(
        "schema_version_expected={} schema_version_actual={}\n",
        report.schema_version_expected,
        report
            .schema_version_actual
            .map(|value| value.to_string())
            .unwrap_or_else(|| "<unknown>".to_string())
    ));
    for check in &report.checks {
        output.push_str(
            &format!("[{:?}] {}: {}\n", check.status, check.id, check.message).to_lowercase(),
        );
    }
    output.push_str(&format!("exit_code={}\n", report.exit_code));
    output
}

fn open_read_only_database(path: &Path) -> rusqlite::Result<Connection> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
}

fn check_schema(conn: &Connection, checks: &mut Vec<DoctorCheck>) -> Option<i64> {
    for table in ["schema_migrations", "nodes", "controller_audit_log"] {
        match table_exists(conn, table) {
            Ok(true) => checks.push(ok(
                "controller_db.required_table",
                format!("required table exists: {table}"),
                json!({"table": table}),
            )),
            Ok(false) => checks.push(error(
                "controller_db.required_table",
                format!("required table is missing: {table}"),
                json!({"table": table}),
            )),
            Err(err) => checks.push(error(
                "controller_db.required_table",
                format!("failed to inspect required table: {table}"),
                json!({"table": table, "error": err.to_string()}),
            )),
        }
    }

    let version = conn
        .query_row("SELECT max(version) FROM schema_migrations", [], |row| {
            row.get::<_, Option<i64>>(0)
        })
        .optional();
    let version = match version {
        Ok(Some(Some(version))) => Some(version),
        Ok(Some(None)) | Ok(None) => None,
        Err(err) => {
            checks.push(error(
                "controller_db.schema_version",
                "failed to read schema version",
                json!({"error": err.to_string()}),
            ));
            return None;
        }
    };

    match version {
        Some(CURRENT_SCHEMA_VERSION) => checks.push(ok(
            "controller_db.schema_version",
            "schema version matches this program",
            json!({"actual": CURRENT_SCHEMA_VERSION, "expected": CURRENT_SCHEMA_VERSION}),
        )),
        Some(actual) => checks.push(error(
            "controller_db.schema_version",
            "schema version does not match this program",
            json!({"actual": actual, "expected": CURRENT_SCHEMA_VERSION}),
        )),
        None => checks.push(error(
            "controller_db.schema_version",
            "schema version is missing",
            json!({"expected": CURRENT_SCHEMA_VERSION}),
        )),
    }

    match conn.query_row(
        "SELECT count(*) FROM schema_migrations WHERE version > ?1",
        [CURRENT_SCHEMA_VERSION],
        |row| row.get::<_, i64>(0),
    ) {
        Ok(0) => checks.push(ok(
            "controller_db.migrations",
            "no unknown future migrations are present",
            json!({}),
        )),
        Ok(count) => checks.push(error(
            "controller_db.migrations",
            "unknown future migrations are present",
            json!({"count": count, "current_program_schema": CURRENT_SCHEMA_VERSION}),
        )),
        Err(err) => checks.push(error(
            "controller_db.migrations",
            "failed to inspect migration state",
            json!({"error": err.to_string()}),
        )),
    }

    version
}

fn check_registry(conn: &Connection, checks: &mut Vec<DoctorCheck>) {
    let nodes = match load_registry_nodes(conn) {
        Ok(nodes) => nodes,
        Err(err) => {
            checks.push(error(
                "registry.load",
                "failed to read node registry",
                json!({"error": err.to_string()}),
            ));
            return;
        }
    };

    let mut endpoint_counts = BTreeMap::<String, usize>::new();
    let mut node_ids = BTreeSet::new();
    let mut endpoint_to_node = HashMap::new();
    let mut node_to_endpoint = HashMap::new();
    let mut missing_fields = Vec::new();
    let mut invalid_endpoint_ids = Vec::new();

    for node in &nodes {
        *endpoint_counts.entry(node.endpoint_id.clone()).or_default() += 1;
        node_ids.insert(node.node_id.clone());
        endpoint_to_node.insert(node.endpoint_id.clone(), node.node_id.clone());
        node_to_endpoint.insert(node.node_id.clone(), node.endpoint_id.clone());

        for (field, value) in [
            ("node_id", Some(node.node_id.as_str())),
            ("endpoint_id", Some(node.endpoint_id.as_str())),
            ("name", Some(node.name.as_str())),
            ("region", node.region.as_deref()),
            ("role", Some(node.role.as_str())),
        ] {
            if value.is_none_or(|value| value.trim().is_empty()) {
                missing_fields.push(json!({"node_id": node.node_id, "field": field}));
            }
        }

        if EndpointId::from_str(&node.endpoint_id).is_err() {
            invalid_endpoint_ids.push(json!({
                "node_id": node.node_id,
                "endpoint_id": node.endpoint_id,
            }));
        }
    }

    let duplicates = endpoint_counts
        .iter()
        .filter(|(_, count)| **count > 1)
        .map(|(endpoint_id, count)| json!({"endpoint_id": endpoint_id, "count": count}))
        .collect::<Vec<_>>();
    if duplicates.is_empty() {
        checks.push(ok(
            "registry.endpoint_id.unique",
            "registry EndpointIDs are unique",
            json!({"node_count": nodes.len()}),
        ));
    } else {
        checks.push(error(
            "registry.endpoint_id.unique",
            "duplicate registry EndpointIDs found",
            json!({"duplicates": duplicates}),
        ));
    }

    if missing_fields.is_empty() {
        checks.push(ok(
            "registry.required_fields",
            "registry nodes have required fields",
            json!({"node_count": nodes.len()}),
        ));
    } else {
        checks.push(error(
            "registry.required_fields",
            "registry nodes are missing required fields",
            json!({"missing_fields": missing_fields}),
        ));
    }

    if invalid_endpoint_ids.is_empty() {
        checks.push(ok(
            "registry.endpoint_id.parse",
            "registry EndpointIDs parse as iroh EndpointIDs",
            json!({"node_count": nodes.len()}),
        ));
    } else {
        checks.push(error(
            "registry.endpoint_id.parse",
            "registry contains invalid EndpointIDs",
            json!({"invalid_endpoint_ids": invalid_endpoint_ids}),
        ));
    }

    check_endpoint_trust_coverage(conn, checks, nodes.len());
    check_endpoint_trust_bindings(conn, checks);
    check_audit_relationship_references(
        conn,
        checks,
        &node_ids,
        &endpoint_to_node,
        &node_to_endpoint,
    );
}

fn check_endpoint_trust_coverage(
    conn: &Connection,
    checks: &mut Vec<DoctorCheck>,
    node_count: usize,
) {
    let missing_count = conn.query_row(
        "SELECT count(*)
         FROM nodes AS node
         WHERE NOT EXISTS (
           SELECT 1
           FROM endpoint_trust AS trust
           WHERE trust.endpoint_id = node.endpoint_id
         )",
        [],
        |row| row.get::<_, i64>(0),
    );

    match missing_count {
        Ok(0) => checks.push(ok(
            "registry.endpoint_trust.coverage",
            "every registry EndpointID has endpoint trust state",
            json!({"node_count": node_count}),
        )),
        Ok(missing_count) => checks.push(error(
            "registry.endpoint_trust.coverage",
            "registry EndpointIDs are missing endpoint trust state",
            json!({"node_count": node_count, "missing_count": missing_count}),
        )),
        Err(err) => checks.push(error(
            "registry.endpoint_trust.coverage",
            "failed to inspect endpoint trust coverage",
            json!({"error": err.to_string()}),
        )),
    }
}

fn check_endpoint_trust_bindings(conn: &Connection, checks: &mut Vec<DoctorCheck>) {
    let counts = conn.query_row(
        "SELECT
           (SELECT count(*)
              FROM endpoint_trust AS trust
             WHERE trust.status = 'active'
               AND (trust.node_id IS NULL OR trim(trust.node_id) = '')),
           (SELECT count(*)
              FROM endpoint_trust AS trust
             WHERE trust.status = 'active'
               AND trust.node_id IS NOT NULL
               AND trim(trust.node_id) <> ''
               AND NOT EXISTS (
                 SELECT 1 FROM nodes AS node WHERE node.node_id = trust.node_id
               )),
           (SELECT count(*)
              FROM nodes AS node
              JOIN endpoint_trust AS trust ON trust.endpoint_id = node.endpoint_id
             WHERE trust.node_id IS NULL OR trust.node_id <> node.node_id),
           (SELECT count(*)
              FROM nodes AS node
              JOIN endpoint_trust AS trust ON trust.endpoint_id = node.endpoint_id
             WHERE node.enabled = 1
               AND trust.status <> 'active'),
           (SELECT count(*)
              FROM endpoint_trust AS trust
              JOIN nodes AS node ON node.node_id = trust.node_id
             WHERE trust.status = 'active'
               AND trust.endpoint_id <> node.endpoint_id)",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        },
    );

    match counts {
        Ok((0, 0, 0, 0, 0)) => checks.push(ok(
            "registry.endpoint_trust.bindings",
            "active endpoint trust bindings match the node registry",
            endpoint_trust_binding_details(0, 0, 0, 0, 0),
        )),
        Ok((
            active_unbound,
            active_orphan,
            current_binding_mismatch,
            inactive_current,
            active_extra_for_node,
        )) => checks.push(error(
            "registry.endpoint_trust.bindings",
            "endpoint trust bindings are inconsistent with the node registry",
            endpoint_trust_binding_details(
                active_unbound,
                active_orphan,
                current_binding_mismatch,
                inactive_current,
                active_extra_for_node,
            ),
        )),
        Err(err) => checks.push(error(
            "registry.endpoint_trust.bindings",
            "failed to inspect endpoint trust bindings",
            json!({"error": err.to_string()}),
        )),
    }
}

fn endpoint_trust_binding_details(
    active_unbound: i64,
    active_orphan: i64,
    current_binding_mismatch: i64,
    inactive_current: i64,
    active_extra_for_node: i64,
) -> Value {
    json!({
        "active_unbound": active_unbound,
        "active_orphan": active_orphan,
        "current_binding_mismatch": current_binding_mismatch,
        "inactive_current": inactive_current,
        "active_extra_for_node": active_extra_for_node,
    })
}

fn check_audit_relationship_references(
    conn: &Connection,
    checks: &mut Vec<DoctorCheck>,
    node_ids: &BTreeSet<String>,
    endpoint_to_node: &HashMap<String, String>,
    node_to_endpoint: &HashMap<String, String>,
) {
    let rows = match load_recent_audit_detail_json(conn) {
        Ok(rows) => rows,
        Err(err) => {
            checks.push(warning(
                "registry.peer_relationships",
                "could not inspect recent path relationship audit records",
                json!({"error": err.to_string()}),
            ));
            return;
        }
    };

    let mut unknown = Vec::new();
    let mut inconsistent = Vec::new();
    for (audit_id, detail) in rows {
        let Some(object) = detail.as_object() else {
            continue;
        };

        for field in ["source_node_id", "target_node_id"] {
            if let Some(value) = object.get(field).and_then(Value::as_str)
                && !node_ids.contains(value)
            {
                unknown.push(json!({"audit_id": audit_id, "field": field, "node_id": value}));
            }
        }
        for field in ["source_endpoint_id", "target_endpoint_id"] {
            if let Some(value) = object.get(field).and_then(Value::as_str)
                && !endpoint_to_node.contains_key(value)
            {
                unknown.push(json!({"audit_id": audit_id, "field": field, "endpoint_id": value}));
            }
        }
        for (node_field, endpoint_field) in [
            ("source_node_id", "source_endpoint_id"),
            ("target_node_id", "target_endpoint_id"),
        ] {
            let node_id = object.get(node_field).and_then(Value::as_str);
            let endpoint_id = object.get(endpoint_field).and_then(Value::as_str);
            if let (Some(node_id), Some(endpoint_id)) = (node_id, endpoint_id)
                && let Some(expected) = node_to_endpoint.get(node_id)
                && expected != endpoint_id
            {
                inconsistent.push(json!({
                    "audit_id": audit_id,
                    "node_id": node_id,
                    "endpoint_id": endpoint_id,
                    "expected_endpoint_id": expected,
                }));
            }
        }
    }

    if unknown.is_empty() && inconsistent.is_empty() {
        checks.push(ok(
            "registry.peer_relationships",
            "recent path relationship audit references match the registry",
            json!({"records_checked": "recent"}),
        ));
    } else {
        checks.push(error(
            "registry.peer_relationships",
            "unknown or inconsistent peer relationship references found",
            json!({"unknown": unknown, "inconsistent": inconsistent}),
        ));
    }
}

fn check_secret_key(options: &DoctorOptions, checks: &mut Vec<DoctorCheck>) {
    if !options.secret_key.exists() {
        checks.push(error(
            "secret_key.exists",
            "controller SecretKey does not exist",
            json!({"path": options.secret_key.display().to_string()}),
        ));
        return;
    }
    checks.push(ok(
        "secret_key.exists",
        "controller SecretKey exists",
        json!({"path": options.secret_key.display().to_string()}),
    ));

    match load_secret_key(&options.secret_key, false) {
        Ok(secret_key) => checks.push(ok(
            "secret_key.read",
            "controller SecretKey is readable and valid",
            json!({
                "path": options.secret_key.display().to_string(),
                "controller_endpoint_id": secret_key.public().to_string(),
            }),
        )),
        Err(err) => checks.push(error(
            "secret_key.read",
            "controller SecretKey is unreadable, invalid, or has unsafe permissions",
            json!({"path": options.secret_key.display().to_string(), "error": err.to_string()}),
        )),
    }
}

fn check_directory(id: &str, path: Option<&std::path::Path>, checks: &mut Vec<DoctorCheck>) {
    let path = path.filter(|path| !path.as_os_str().is_empty());
    let Some(path) = path else {
        checks.push(ok(id, "current directory is used", json!({"path": "."})));
        return;
    };
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            if directory_permissions_reasonable(&metadata) {
                checks.push(ok(
                    id,
                    "directory exists with reasonable permissions",
                    json!({"path": path.display().to_string()}),
                ));
            } else {
                checks.push(error(
                    id,
                    "directory permissions are too broad or owner is unexpected",
                    json!({"path": path.display().to_string()}),
                ));
            }
        }
        Ok(_) => checks.push(error(
            id,
            "path exists but is not a directory",
            json!({"path": path.display().to_string()}),
        )),
        Err(err) => checks.push(error(
            id,
            "directory does not exist or is unreadable",
            json!({"path": path.display().to_string(), "error": err.to_string()}),
        )),
    }
}

#[cfg(unix)]
fn directory_permissions_reasonable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    let current_euid = unsafe { libc::geteuid() };
    metadata.uid() == current_euid && metadata.mode() & 0o022 == 0
}

#[cfg(not(unix))]
fn directory_permissions_reasonable(_metadata: &std::fs::Metadata) -> bool {
    true
}

fn table_exists(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1",
        [table],
        |_| Ok(()),
    )
    .optional()
    .map(|value| value.is_some())
}

fn load_registry_nodes(conn: &Connection) -> rusqlite::Result<Vec<RegistryNode>> {
    let mut stmt = conn
        .prepare("SELECT node_id, endpoint_id, name, region, role FROM nodes ORDER BY node_id")?;
    let rows = stmt.query_map([], |row| {
        Ok(RegistryNode {
            node_id: row.get(0)?,
            endpoint_id: row.get(1)?,
            name: row.get(2)?,
            region: row.get(3)?,
            role: row.get(4)?,
        })
    })?;
    rows.collect()
}

fn load_recent_audit_detail_json(conn: &Connection) -> rusqlite::Result<Vec<(i64, Value)>> {
    let mut stmt = conn.prepare(
        "SELECT id, detail_json FROM controller_audit_log
         WHERE detail_json IS NOT NULL
         ORDER BY id DESC
         LIMIT 500",
    )?;
    let rows = stmt.query_map([], |row| {
        let id = row.get::<_, i64>(0)?;
        let text = row.get::<_, String>(1)?;
        let value = serde_json::from_str(&text).unwrap_or_else(|_| json!({}));
        Ok((id, value))
    })?;
    rows.collect()
}

fn report_status(checks: &[DoctorCheck]) -> DoctorStatus {
    if checks
        .iter()
        .any(|check| check.status == CheckStatus::Error)
    {
        DoctorStatus::Error
    } else if checks
        .iter()
        .any(|check| check.status == CheckStatus::Warning)
    {
        DoctorStatus::Warning
    } else {
        DoctorStatus::Ok
    }
}

fn ok(id: impl Into<String>, message: impl Into<String>, details: Value) -> DoctorCheck {
    DoctorCheck {
        id: id.into(),
        status: CheckStatus::Ok,
        message: message.into(),
        details,
    }
}

fn warning(id: impl Into<String>, message: impl Into<String>, details: Value) -> DoctorCheck {
    DoctorCheck {
        id: id.into(),
        status: CheckStatus::Warning,
        message: message.into(),
        details,
    }
}

fn error(id: impl Into<String>, message: impl Into<String>, details: Value) -> DoctorCheck {
    DoctorCheck {
        id: id.into(),
        status: CheckStatus::Error,
        message: message.into(),
        details,
    }
}
