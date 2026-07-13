use clap::Parser;
use ocfleet_snapshot_schema::{MACHINE_SCHEMA, validate_file};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ocfleet-snapshot-validator",
    about = "Validate a closed local OCFleet aggregate snapshot"
)]
struct Cli {
    #[arg(value_name = "SNAPSHOT")]
    snapshot: Option<PathBuf>,
    #[arg(long)]
    print_schema: bool,
    #[arg(long)]
    json: bool,
}
fn main() {
    let cli = Cli::parse();
    if cli.print_schema {
        println!("{MACHINE_SCHEMA}");
        return;
    }
    let Some(path) = cli.snapshot else {
        eprintln!("snapshot path is required");
        std::process::exit(2)
    };
    match validate_file(&path) {
        Ok(doc) => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({"valid":true,"schema_version":doc.schema_version})
                );
            } else {
                println!("valid schema_version={}", doc.schema_version);
            }
        }
        Err(error) => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({"valid":false,"error_code":"INVALID_SNAPSHOT"})
                );
            } else {
                eprintln!("invalid snapshot: {error}");
            }
            std::process::exit(1)
        }
    }
}
