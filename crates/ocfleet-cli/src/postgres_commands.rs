use anyhow::{Context, bail};

use crate::args::PostgresCommand;
use crate::postgres_backend::{PostgresConnectionSource, connect};

const WRITER_LEASE: &str = "controller-writer";

pub fn run_postgres_command(command: PostgresCommand) -> anyhow::Result<()> {
    match command {
        PostgresCommand::Doctor { config, json } => {
            let store = connect(&PostgresConnectionSource::PrivateConfigFile { path: config })?;
            let report = store.doctor()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("connected={}", report.connected);
                println!("backend_schema_version={}", report.backend_schema_version);
                println!("format_version={}", report.format_version);
                println!("schema_version={}", report.schema_version);
                println!("checksum_valid={}", report.checksum_valid);
                println!("pool_max_size={}", report.pool_max_size);
                println!("backup_method=encrypted-pg-dump");
                println!("restore_validation=separate-database-first");
            }
            if !report.checksum_valid {
                bail!("Postgres state checksum verification failed");
            }
        }
        PostgresCommand::Import {
            config,
            source,
            dry_run,
            lease_owner,
            lease_ttl_seconds,
            json,
        } => {
            let store = connect(&PostgresConnectionSource::PrivateConfigFile { path: config })?;
            let report = if dry_run {
                store.import_sqlite(&source, true)?
            } else {
                let owner = lease_owner
                    .as_deref()
                    .context("--lease-owner is required unless --dry-run is used")?;
                let lease = store
                    .acquire_lease(WRITER_LEASE, owner, lease_ttl_seconds)?
                    .context("Postgres controller writer lease is held by another replica")?;
                store.fenced(lease)?.import_sqlite(&source, false)?
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("dry_run={}", report.dry_run);
                println!("already_current={}", report.already_current);
                println!("source_sha256={}", report.source_sha256);
                println!("source_size={}", report.source_size);
                println!("schema_version={}", report.schema_version);
                println!("counts_verified={}", report.counts_verified);
            }
        }
        PostgresCommand::Export {
            config,
            output,
            json,
        } => {
            let store = connect(&PostgresConnectionSource::PrivateConfigFile { path: config })?;
            let report = store.export_sqlite(&output)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("state_sha256={}", report.state_sha256);
                println!("state_size={}", report.state_size);
                println!("schema_version={}", report.schema_version);
                println!("counts_verified={}", report.counts_verified);
            }
        }
    }
    Ok(())
}
