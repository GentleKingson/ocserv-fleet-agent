use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "ocfleet")]
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
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum NodeCommand {
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
