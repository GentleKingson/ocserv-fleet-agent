use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ocfleet_protocol::constants::PROTOCOL_VERSION;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::CLI_VERSION;
use crate::args::BackupCommand;
use crate::identity::load_secret_key;
use crate::migrations::{read_schema_version, run_sqlite_backup, sha256_file_hex};
use crate::private_file;
use crate::store::CURRENT_SCHEMA_VERSION;

const MANIFEST_SCHEMA: &str = "ocfleet.controller_backup.v1";
const SIGNATURE_SCHEMA: &str = "ocfleet.controller_backup.signature.v1";
const MAX_MANIFEST_BYTES: usize = 32 * 1024;
const MAX_SIGNING_KEY_BYTES: usize = 16 * 1024;
const MAX_BACKUPS_LISTED: usize = 1_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupManifest {
    pub manifest_schema: String,
    pub backup_id: String,
    pub database_file: String,
    pub database_sha256: String,
    pub database_bytes: u64,
    pub schema_version: i64,
    pub application_version: String,
    pub protocol_version: u32,
    pub created_at: String,
    pub expected_controller_endpoint_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupSignature {
    signature_schema: String,
    algorithm: String,
    signed_file: String,
    content_sha256: String,
    public_key: String,
    signature: String,
    signed_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupVerification {
    pub manifest: BackupManifest,
    pub integrity_ok: bool,
    pub checksum_ok: bool,
    pub signature_present: bool,
    pub signature_ok: Option<bool>,
}

pub fn run_backup_command(
    database: &Path,
    secret_key: &Path,
    command: BackupCommand,
) -> anyhow::Result<()> {
    match command {
        BackupCommand::Create {
            output_dir,
            sign_with_key_file,
            json,
        } => {
            let manifest = create_backup(
                database,
                secret_key,
                &output_dir,
                sign_with_key_file.as_deref(),
            )?;
            print_manifest(&manifest, json)
        }
        BackupCommand::List { backup_dir, json } => {
            let manifests = list_backups(&backup_dir)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "backup_count": manifests.len(),
                        "backups": manifests,
                    }))?
                );
            } else {
                println!("backup_count={}", manifests.len());
                for manifest in manifests {
                    println!(
                        "backup_id={} created_at={} schema_version={} database_file={} endpoint_id={}",
                        manifest.backup_id,
                        manifest.created_at,
                        manifest.schema_version,
                        manifest.database_file,
                        manifest.expected_controller_endpoint_id,
                    );
                }
            }
            Ok(())
        }
        BackupCommand::Verify { manifest, json } => {
            let verification = verify_backup(&manifest)?;
            print_verification(&verification, json)
        }
        BackupCommand::Inspect { manifest, json } => {
            let manifest = read_manifest(&manifest)?;
            print_manifest(&manifest, json)
        }
    }
}

pub fn create_backup(
    database: &Path,
    secret_key_path: &Path,
    output_dir: &Path,
    signing_key_path: Option<&Path>,
) -> anyhow::Result<BackupManifest> {
    private_file::validate_existing_private_directory_strict(output_dir)
        .context("backup output directory must be owned, non-symlink, and mode 0700")?;
    private_file::validate_existing_private_file(database)
        .context("controller database must be a private regular file")?;
    let secret_key = load_secret_key(secret_key_path, true)
        .context("failed to load controller identity for backup binding")?;
    let source = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .context("failed to open controller database for online backup")?;
    let source_schema = read_schema_version(&source)?;
    if source_schema != CURRENT_SCHEMA_VERSION {
        bail!(
            "controller database schema must be current version {CURRENT_SCHEMA_VERSION}, got {source_schema}"
        );
    }

    let created_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let backup_id = format!("backup-{}", Uuid::new_v4().simple());
    let database_file = format!("{backup_id}.sqlite");
    let database_path = output_dir.join(&database_file);
    let manifest_path = output_dir.join(format!("{backup_id}.manifest.json"));
    let checksum_path = output_dir.join(format!("{backup_id}.sqlite.sha256"));
    let result = (|| -> anyhow::Result<BackupManifest> {
        let database_handle = private_file::open_private_create_new_strict(&database_path)?;
        database_handle.sync_all()?;
        drop(database_handle);
        run_sqlite_backup(&source, &database_path)?;
        validate_sqlite_integrity(&database_path)?;
        let database_sha256 = sha256_file_hex(&database_path)?;
        let database_bytes = fs::metadata(&database_path)?.len();
        let manifest = BackupManifest {
            manifest_schema: MANIFEST_SCHEMA.to_string(),
            backup_id: backup_id.clone(),
            database_file: database_file.clone(),
            database_sha256: database_sha256.clone(),
            database_bytes,
            schema_version: source_schema,
            application_version: CLI_VERSION.to_string(),
            protocol_version: PROTOCOL_VERSION,
            created_at,
            expected_controller_endpoint_id: secret_key.public().to_string(),
        };
        validate_manifest(&manifest)?;
        let mut checksum_file = private_file::open_private_create_new_strict(&checksum_path)?;
        writeln!(checksum_file, "{database_sha256}  {database_file}")?;
        checksum_file.sync_all()?;
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        let mut manifest_file = private_file::open_private_create_new_strict(&manifest_path)?;
        manifest_file.write_all(&manifest_bytes)?;
        manifest_file.write_all(b"\n")?;
        manifest_file.sync_all()?;
        drop(manifest_file);
        if let Some(key_path) = signing_key_path {
            write_signature(&manifest_path, key_path)?;
        }
        sync_directory(output_dir)?;
        Ok(manifest)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&manifest_path);
        let _ = fs::remove_file(signature_path(&manifest_path));
        let _ = fs::remove_file(&checksum_path);
        let _ = fs::remove_file(&database_path);
    }
    result
}

pub fn list_backups(directory: &Path) -> anyhow::Result<Vec<BackupManifest>> {
    private_file::validate_existing_private_directory_strict(directory)
        .context("backup directory must be owned, non-symlink, and mode 0700")?;
    let mut paths = fs::read_dir(directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("backup-") && name.ends_with(".manifest.json"))
        })
        .collect::<Vec<_>>();
    paths.sort();
    if paths.len() > MAX_BACKUPS_LISTED {
        bail!("backup directory contains more than {MAX_BACKUPS_LISTED} manifests");
    }
    let mut manifests = paths
        .iter()
        .map(|path| read_manifest(path))
        .collect::<anyhow::Result<Vec<_>>>()?;
    manifests.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| left.backup_id.cmp(&right.backup_id))
    });
    Ok(manifests)
}

pub fn verify_backup(manifest_path: &Path) -> anyhow::Result<BackupVerification> {
    let manifest_bytes = read_private_bounded(manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest: BackupManifest =
        serde_json::from_slice(&manifest_bytes).context("backup manifest is invalid")?;
    validate_manifest(&manifest)?;
    let parent = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    private_file::validate_existing_private_directory_strict(parent)
        .context("backup directory must be owned, non-symlink, and mode 0700")?;
    let database_path = parent.join(&manifest.database_file);
    private_file::validate_existing_private_file(&database_path)
        .context("backup database is not private")?;
    let actual_bytes = fs::metadata(&database_path)?.len();
    if actual_bytes != manifest.database_bytes {
        bail!("backup database size does not match manifest");
    }
    let checksum_ok = sha256_file_hex(&database_path)? == manifest.database_sha256;
    if !checksum_ok {
        bail!("backup database checksum does not match manifest");
    }
    validate_sqlite_integrity(&database_path)?;
    let backup = Connection::open_with_flags(&database_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let schema = read_schema_version(&backup)?;
    if schema != manifest.schema_version {
        bail!("backup database schema does not match manifest");
    }
    let signature_path = signature_path(manifest_path);
    let signature_present = signature_path.exists();
    let signature_ok = if signature_present {
        verify_signature(manifest_path, &manifest_bytes, &signature_path)?;
        Some(true)
    } else {
        None
    };
    Ok(BackupVerification {
        manifest,
        integrity_ok: true,
        checksum_ok,
        signature_present,
        signature_ok,
    })
}

fn read_manifest(path: &Path) -> anyhow::Result<BackupManifest> {
    let bytes = read_private_bounded(path, MAX_MANIFEST_BYTES)?;
    let manifest: BackupManifest =
        serde_json::from_slice(&bytes).context("backup manifest is invalid")?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn validate_manifest(manifest: &BackupManifest) -> anyhow::Result<()> {
    if manifest.manifest_schema != MANIFEST_SCHEMA {
        bail!("unsupported backup manifest schema");
    }
    if !manifest.backup_id.starts_with("backup-")
        || manifest.backup_id.len() != 39
        || !manifest.backup_id[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("backup manifest id is invalid");
    }
    if manifest.database_file != format!("{}.sqlite", manifest.backup_id) {
        bail!("backup manifest database file is invalid");
    }
    if manifest.database_sha256.len() != 64
        || !manifest
            .database_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("backup manifest checksum is invalid");
    }
    if manifest.database_bytes == 0 || manifest.database_bytes > 1024 * 1024 * 1024 * 1024 {
        bail!("backup manifest database size is invalid");
    }
    if manifest.schema_version <= 0 || manifest.schema_version > CURRENT_SCHEMA_VERSION {
        bail!("backup manifest schema version is unsupported");
    }
    if manifest.application_version.is_empty() || manifest.application_version.len() > 64 {
        bail!("backup manifest application version is invalid");
    }
    if manifest.protocol_version != PROTOCOL_VERSION {
        bail!("backup manifest protocol version is unsupported");
    }
    OffsetDateTime::parse(&manifest.created_at, &Rfc3339)
        .context("backup manifest created_at is invalid")?;
    if manifest.expected_controller_endpoint_id.is_empty()
        || manifest.expected_controller_endpoint_id.len() > 128
        || manifest
            .expected_controller_endpoint_id
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        bail!("backup manifest controller EndpointID is invalid");
    }
    Ok(())
}

fn validate_sqlite_integrity(path: &Path) -> anyhow::Result<()> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let integrity: String =
        connection.pragma_query_value(None, "integrity_check", |row| row.get(0))?;
    if integrity != "ok" {
        bail!("backup database integrity check failed");
    }
    Ok(())
}

fn write_signature(manifest_path: &Path, key_path: &Path) -> anyhow::Result<()> {
    let key_bytes = read_private_bounded(key_path, MAX_SIGNING_KEY_BYTES)?;
    let key_pair = Ed25519KeyPair::from_pkcs8(&key_bytes)
        .map_err(|_| anyhow::anyhow!("invalid Ed25519 PKCS#8 signing key"))?;
    let manifest_bytes = read_private_bounded(manifest_path, MAX_MANIFEST_BYTES)?;
    let signature = key_pair.sign(&manifest_bytes);
    let signed_file = manifest_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("backup manifest filename is invalid")?;
    let sidecar = BackupSignature {
        signature_schema: SIGNATURE_SCHEMA.to_string(),
        algorithm: "Ed25519".to_string(),
        signed_file: signed_file.to_string(),
        content_sha256: sha256_bytes(&manifest_bytes),
        public_key: BASE64.encode(key_pair.public_key().as_ref()),
        signature: BASE64.encode(signature.as_ref()),
        signed_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
    };
    let path = signature_path(manifest_path);
    let mut file = private_file::open_private_create_new_strict(&path)?;
    serde_json::to_writer_pretty(&mut file, &sidecar)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn verify_signature(
    manifest_path: &Path,
    manifest_bytes: &[u8],
    signature_path: &Path,
) -> anyhow::Result<()> {
    let bytes = read_private_bounded(signature_path, MAX_MANIFEST_BYTES)?;
    let sidecar: BackupSignature =
        serde_json::from_slice(&bytes).context("backup signature sidecar is invalid")?;
    let expected_file = manifest_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("backup manifest filename is invalid")?;
    if sidecar.signature_schema != SIGNATURE_SCHEMA
        || sidecar.algorithm != "Ed25519"
        || sidecar.signed_file != expected_file
        || sidecar.content_sha256 != sha256_bytes(manifest_bytes)
    {
        bail!("backup signature metadata does not match manifest");
    }
    OffsetDateTime::parse(&sidecar.signed_at, &Rfc3339)
        .context("backup signature timestamp is invalid")?;
    let public_key = BASE64
        .decode(sidecar.public_key)
        .context("backup signature public key is invalid")?;
    let signature = BASE64
        .decode(sidecar.signature)
        .context("backup signature is invalid")?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(manifest_bytes, &signature)
        .map_err(|_| anyhow::anyhow!("backup signature verification failed"))
}

fn read_private_bounded(path: &Path, max_bytes: usize) -> anyhow::Result<Vec<u8>> {
    let file = private_file::open_existing_private_read(path)?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(max_bytes + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        bail!("private backup artifact exceeds size limit");
    }
    Ok(bytes)
}

fn signature_path(manifest_path: &Path) -> PathBuf {
    manifest_path.with_extension("json.sig")
}

fn sha256_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> anyhow::Result<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn print_manifest(manifest: &BackupManifest, json_output: bool) -> anyhow::Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(manifest)?);
    } else {
        println!("backup_id={}", manifest.backup_id);
        println!("database_file={}", manifest.database_file);
        println!("database_sha256={}", manifest.database_sha256);
        println!("database_bytes={}", manifest.database_bytes);
        println!("schema_version={}", manifest.schema_version);
        println!("application_version={}", manifest.application_version);
        println!("protocol_version={}", manifest.protocol_version);
        println!("created_at={}", manifest.created_at);
        println!(
            "expected_controller_endpoint_id={}",
            manifest.expected_controller_endpoint_id
        );
    }
    Ok(())
}

fn print_verification(verification: &BackupVerification, json_output: bool) -> anyhow::Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(verification)?);
    } else {
        println!("backup_id={}", verification.manifest.backup_id);
        println!("checksum_ok={}", verification.checksum_ok);
        println!("integrity_ok={}", verification.integrity_ok);
        println!("signature_present={}", verification.signature_present);
        println!(
            "signature_ok={}",
            verification
                .signature_ok
                .map(|value| value.to_string())
                .unwrap_or_else(|| "not-present".to_string())
        );
    }
    Ok(())
}
