use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "ocfleet")]
#[command(version)]
#[command(about = "Read-only ocserv fleet controller")]
pub struct Cli {
    #[arg(long, default_value = "controller.sqlite")]
    pub database: PathBuf,
    #[arg(long, default_value = "controller.secret")]
    pub secret_key: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Init,
    Doctor {
        #[arg(long)]
        json: bool,
    },
    Ping {
        node_id: String,
    },
    Probe {
        #[command(subcommand)]
        command: ProbeCommand,
    },
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    Enroll {
        #[command(subcommand)]
        command: EnrollCommand,
    },
    Endpoint {
        #[command(subcommand)]
        command: EndpointCommand,
    },
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },
    Ocserv {
        #[command(subcommand)]
        command: OcservCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum ProbeCommand {
    Ping {
        node_id: String,
    },
    Path {
        source_node_id: String,
        target_node_id: String,
    },
    Summary {
        source_node_id: String,
        target_node_id: String,
    },
    Topology,
    History {
        node_id: Option<String>,
    },
    Observe {
        source_node_id: String,
        target_node_id: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum NodeCommand {
    Info {
        node_id: String,
    },
    Add {
        node_id: String,
        #[arg(long)]
        endpoint_id: String,
        #[arg(long)]
        region: String,
        #[arg(long, default_value = "ocserv")]
        role: String,
    },
    List,
    Disable {
        node_id: String,
    },
    Enable {
        node_id: String,
    },
    Remove {
        node_id: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum EnrollCommand {
    Token {
        #[command(subcommand)]
        command: EnrollTokenCommand,
    },
    Request {
        #[command(subcommand)]
        command: EnrollRequestCommand,
    },
    Approve {
        join_request_id: String,
        #[arg(long)]
        endpoint_id: String,
        #[arg(long)]
        reason: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum EnrollTokenCommand {
    Create {
        #[arg(long, default_value = "24h")]
        ttl: String,
        #[arg(long, default_value_t = 1)]
        max_uses: u32,
        #[arg(long)]
        description: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum EnrollRequestCommand {
    Create {
        #[arg(long)]
        token: String,
        #[arg(long)]
        agent_public_key: String,
        #[arg(long)]
        fingerprint: String,
        #[arg(long)]
        requested_endpoint_id: Option<String>,
        #[arg(long)]
        hostname: String,
        #[arg(long)]
        agent_version: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum EndpointCommand {
    Rotate {
        old_endpoint_id: String,
        #[arg(long)]
        new_endpoint_id: String,
        #[arg(long)]
        reason: String,
    },
    Revoke {
        endpoint_id: String,
        #[arg(long)]
        reason: String,
    },
    Quarantine {
        endpoint_id: String,
        #[arg(long)]
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TrustDiffFormat {
    Human,
    Json,
}

#[derive(Debug, Subcommand)]
pub enum TrustCommand {
    Diff {
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long, value_enum, default_value = "human")]
        format: TrustDiffFormat,
        #[arg(long)]
        strict: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum OcservCommand {
    Status {
        node: String,
        #[arg(long)]
        json: bool,
    },
    Cert {
        node: String,
        #[arg(long)]
        json: bool,
    },
    Sessions {
        #[command(subcommand)]
        command: OcservSessionsCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum OcservSessionsCommand {
    Summary {
        node: String,
        #[arg(long)]
        json: bool,
    },
}
