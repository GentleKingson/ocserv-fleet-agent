pub mod alert_delivery;
pub mod alert_projection;
pub mod alert_webhook;
pub mod alerts;
pub mod args;
pub mod audit;
pub mod audit_export;
pub mod backend;
pub mod controller_rpc;
pub mod doctor;
pub mod duration_args;
pub mod governance;
pub mod health;
pub mod identity;
pub mod input_validation;
pub(crate) mod migrations;
pub mod observation;
pub mod ocserv_output;
#[cfg(feature = "postgres-backend")]
pub mod postgres_backend;
pub mod private_file;
pub mod retention;
pub mod rpc_client;
pub mod scheduler;
pub mod store;
pub mod trust_policy;

pub const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");
