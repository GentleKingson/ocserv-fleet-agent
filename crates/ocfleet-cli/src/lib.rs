pub mod args;
pub mod audit;
pub mod doctor;
pub mod identity;
pub mod private_file;
pub mod rpc_client;
pub mod store;

pub const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");
