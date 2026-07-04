use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use iroh::endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks, Side, presets};
use iroh::{Endpoint, EndpointId, RelayMode, SecretKey};
use ocfleet_config::agent::AgentConfig;

use crate::audit::{AgentAuditEvent, JsonlAuditWriter};
use crate::nonce::NonceCache;

#[derive(Debug)]
pub struct AgentServerState {
    pub config: AgentConfig,
    pub audit: JsonlAuditWriter,
    pub nonce_cache: Arc<Mutex<NonceCache>>,
    pub agent_endpoint_id: String,
}

#[derive(Debug, Clone)]
pub struct AllowlistHook {
    allowed: HashSet<EndpointId>,
    audit: JsonlAuditWriter,
}

impl AllowlistHook {
    pub fn new(allowed: HashSet<EndpointId>, audit: JsonlAuditWriter) -> Self {
        Self { allowed, audit }
    }
}

impl EndpointHooks for AllowlistHook {
    async fn after_handshake(&self, conn: &Connection) -> AfterHandshakeOutcome {
        if conn.side() != Side::Server {
            return AfterHandshakeOutcome::Accept;
        }

        let remote_endpoint_id = conn.remote_id();
        if self.allowed.contains(&remote_endpoint_id) {
            return AfterHandshakeOutcome::Accept;
        }

        let alpn = String::from_utf8_lossy(conn.alpn());
        let reason = format!("endpoint not allowed for ALPN {alpn}");
        let mut event = AgentAuditEvent::new("rpc_rejected");
        event.remote_endpoint_id = Some(remote_endpoint_id.to_string());
        event.stage = Some("endpoint_allowlist".to_string());
        event.allowed = Some(false);
        event.error_code = Some("ENDPOINT_NOT_ALLOWED".to_string());
        event.reason = Some(reason.clone());
        if let Err(err) = self.audit.write(&event) {
            tracing::warn!(error = %err, "failed to write endpoint allowlist rejection audit event");
        }

        AfterHandshakeOutcome::Reject {
            error_code: 403u32.into(),
            reason: reason.into_bytes(),
        }
    }
}

pub async fn bind_agent_endpoint(
    config: &AgentConfig,
    secret_key: SecretKey,
    audit: JsonlAuditWriter,
) -> Result<Endpoint> {
    agent_endpoint_builder(config, secret_key, audit)?
        .bind()
        .await
        .context("failed to bind agent iroh endpoint")
}

pub async fn bind_agent_endpoint_local_only(
    config: &AgentConfig,
    secret_key: SecretKey,
    audit: JsonlAuditWriter,
) -> Result<Endpoint> {
    agent_endpoint_builder(config, secret_key, audit)?
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .context("failed to configure local-only agent endpoint bind address")?
        .bind()
        .await
        .context("failed to bind local-only agent iroh endpoint")
}

pub fn parse_endpoint_id(value: &str) -> Result<EndpointId> {
    EndpointId::from_str(value).context("invalid endpoint id")
}

fn agent_endpoint_builder(
    config: &AgentConfig,
    secret_key: SecretKey,
    audit: JsonlAuditWriter,
) -> Result<iroh::endpoint::Builder> {
    let allowed = config
        .security
        .controllers
        .iter()
        .map(|controller| {
            parse_endpoint_id(&controller.endpoint_id).with_context(|| {
                format!(
                    "invalid allowed controller endpoint id: {}",
                    controller.endpoint_id
                )
            })
        })
        .collect::<Result<HashSet<_>>>()?;

    Ok(Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(vec![config.iroh.alpn.as_bytes().to_vec()])
        .hooks(AllowlistHook::new(allowed, audit)))
}
