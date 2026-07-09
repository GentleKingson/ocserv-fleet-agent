pub mod alerts;
pub mod args;
pub mod audit;
pub mod controller_rpc;
pub mod doctor;
pub mod health;
pub mod identity;
pub mod input_validation;
pub(crate) mod migrations;
pub mod ocserv_output;
pub mod private_file;
pub mod rpc_client;
pub mod scheduler;
pub mod store;

pub const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");
