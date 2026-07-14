use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Parser;
use ocfleet_cli::args::RedactionMode;

use crate::auth::{AuthToken, Authenticator};
use crate::cursor_keys::CursorKeyring;

pub const DEFAULT_LISTEN: &str = "127.0.0.1:8080";
pub const DEFAULT_MAX_LIMIT: u64 = 1_000;
pub const ABSOLUTE_MAX_LIMIT: u64 = 10_000;

#[derive(Debug, Parser)]
#[command(name = "ocfleet-api")]
#[command(version)]
#[command(about = "Experimental read-only ocfleet observation API")]
pub struct ApiCli {
    #[arg(long, default_value = "controller.sqlite")]
    pub database: PathBuf,
    #[arg(long)]
    pub read_only: bool,
    #[arg(long, default_value = DEFAULT_LISTEN)]
    pub listen: SocketAddr,
    #[arg(long, default_value_t = DEFAULT_MAX_LIMIT)]
    pub max_limit: u64,
    #[arg(long, value_enum, default_value_t = RedactionMode::Default)]
    pub redact: RedactionMode,
    #[arg(long, value_name = "PATH")]
    pub auth_token_file: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub auth_config_file: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub cursor_key_file: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct ApiConfig {
    pub database: PathBuf,
    pub listen: SocketAddr,
    pub max_limit: u64,
    pub redact: RedactionMode,
    pub authenticator: Authenticator,
    pub cursor_keys: CursorKeyring,
}

impl ApiConfig {
    pub fn from_cli(cli: ApiCli) -> anyhow::Result<Self> {
        if !cli.read_only {
            bail!(
                "--read-only is required; ocfleet-api refuses to start without explicit read-only mode"
            );
        }
        if cli.max_limit == 0 || cli.max_limit > ABSOLUTE_MAX_LIMIT {
            bail!("--max-limit must be between 1 and {ABSOLUTE_MAX_LIMIT}");
        }
        let auth_token = cli
            .auth_token_file
            .as_deref()
            .map(AuthToken::from_private_file)
            .transpose()
            .context("failed to load --auth-token-file")?;
        let authenticator = Authenticator::load(auth_token, cli.auth_config_file.as_deref())
            .context("failed to load authentication configuration")?;
        if !cli.listen.ip().is_loopback() && !authenticator.enabled() {
            bail!(
                "--auth-token-file or a remote method in --auth-config-file is required when --listen is not loopback"
            );
        }
        if !cli.listen.ip().is_loopback() && authenticator.mtls_proxy_enabled() {
            bail!(
                "mTLS forwarded identity headers require a loopback listener behind a trusted TLS proxy"
            );
        }
        let cursor_key_file = cli
            .cursor_key_file
            .as_deref()
            .context("--cursor-key-file is required for stable signed /api/v1 cursors")?;
        let cursor_keys = CursorKeyring::from_private_file(cursor_key_file)
            .context("failed to load --cursor-key-file")?;
        Ok(Self {
            database: cli.database,
            listen: cli.listen,
            max_limit: cli.max_limit,
            redact: cli.redact,
            authenticator,
            cursor_keys,
        })
    }

    pub fn auth_enabled(&self) -> bool {
        self.authenticator.enabled()
    }
}
