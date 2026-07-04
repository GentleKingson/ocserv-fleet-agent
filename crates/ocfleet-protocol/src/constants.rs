pub const PROTOCOL_VERSION: u32 = 1;
pub const DEFAULT_ALPN: &str = "/com.github.gentlekingson.ocfleet.mgmt/1";
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 65_536;
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 2_097_152;
pub const DEFAULT_CLOCK_SKEW_SECONDS: i64 = 60;
pub const DEFAULT_DEADLINE_MS: u64 = 5_000;
pub const DEFAULT_MAX_DEADLINE_MS: u64 = 10_000;
pub const DEFAULT_MAX_RPC_TIMEOUT_MS: u64 = 5_000;
