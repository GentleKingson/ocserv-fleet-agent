use anyhow::{Context, bail};
use reqwest::Url;
use reqwest::blocking::Client;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, USER_AGENT};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use crate::alert_delivery::{MAX_JSONL_PAYLOAD_BYTES, alert_delivery_payload_for_hook};
use crate::private_file;
use crate::store::{AlertEventRecord, AlertWebhookHookRecord};

pub const DEFAULT_WEBHOOK_TIMEOUT_MS: u64 = 3_000;
pub const MIN_WEBHOOK_TIMEOUT_MS: u64 = 1_000;
pub const MAX_WEBHOOK_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_WEBHOOK_MAX_ATTEMPTS: u64 = 3;
pub const MAX_WEBHOOK_ATTEMPTS: u64 = 5;
pub const MAX_WEBHOOK_RESPONSE_BYTES: usize = 4 * 1024;
pub const MAX_HMAC_SECRET_BYTES: usize = 4 * 1024;
pub const MIN_HMAC_SECRET_BYTES: usize = 16;
const MAX_WEBHOOK_PATH_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedWebhookEndpoint {
    pub url: String,
    pub redacted_url: String,
    pub host: String,
    pub host_allow: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct WebhookHttpRequest {
    pub url: String,
    pub timeout_ms: u64,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookHttpResponse {
    pub status_code: u16,
    pub status_class: String,
    pub response_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookHttpFailure {
    pub error_code: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookHttpResult {
    Completed(WebhookHttpResponse),
    Failed(WebhookHttpFailure),
}

pub trait WebhookSender {
    fn send(&self, request: &WebhookHttpRequest) -> WebhookHttpResult;
}

#[derive(Debug, Clone)]
pub struct ReqwestWebhookSender;

impl ReqwestWebhookSender {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self)
    }
}

impl WebhookSender for ReqwestWebhookSender {
    fn send(&self, request: &WebhookHttpRequest) -> WebhookHttpResult {
        let client = match pinned_https_client(&request.url) {
            Ok(client) => client,
            Err(error_code) => return WebhookHttpResult::Failed(WebhookHttpFailure { error_code }),
        };
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static("ocfleet-alert-webhook/0.1"),
        );
        for (name, value) in &request.headers {
            let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
                return WebhookHttpResult::Failed(WebhookHttpFailure {
                    error_code: "WEBHOOK_HEADER_INVALID",
                });
            };
            let Ok(value) = HeaderValue::from_str(value) else {
                return WebhookHttpResult::Failed(WebhookHttpFailure {
                    error_code: "WEBHOOK_HEADER_INVALID",
                });
            };
            headers.insert(name, value);
        }

        let response = client
            .post(&request.url)
            .timeout(Duration::from_millis(request.timeout_ms))
            .headers(headers)
            .body(request.body.clone())
            .send();
        let mut response = match response {
            Ok(response) => response,
            Err(err) => {
                return WebhookHttpResult::Failed(WebhookHttpFailure {
                    error_code: if err.is_timeout() {
                        "WEBHOOK_TIMEOUT"
                    } else {
                        "WEBHOOK_REQUEST_FAILED"
                    },
                });
            }
        };
        let status_code = response.status().as_u16();
        let status_class = http_status_class(status_code).to_string();
        let mut body = Vec::new();
        let read_result = response
            .by_ref()
            .take(u64::try_from(MAX_WEBHOOK_RESPONSE_BYTES + 1).unwrap_or(u64::MAX))
            .read_to_end(&mut body);
        if read_result.is_err() {
            return WebhookHttpResult::Failed(WebhookHttpFailure {
                error_code: "WEBHOOK_RESPONSE_READ_FAILED",
            });
        }
        if body.len() > MAX_WEBHOOK_RESPONSE_BYTES {
            return WebhookHttpResult::Failed(WebhookHttpFailure {
                error_code: "WEBHOOK_RESPONSE_TOO_LARGE",
            });
        }
        WebhookHttpResult::Completed(WebhookHttpResponse {
            status_code,
            status_class,
            response_bytes: body.len(),
        })
    }
}

pub fn validate_webhook_endpoint(
    url: &str,
    host_allow: &[String],
) -> anyhow::Result<ValidatedWebhookEndpoint> {
    let url = Url::parse(url).context("webhook URL is invalid")?;
    if url.scheme() != "https" {
        bail!("webhook URL must use https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("webhook URL must not contain userinfo");
    }
    if url.fragment().is_some() {
        bail!("webhook URL must not contain a fragment");
    }
    if url.query().is_some() {
        bail!("webhook URL must not contain a query; store secrets only in the private HMAC file");
    }
    let path = url.path();
    if path.len() > MAX_WEBHOOK_PATH_BYTES
        || !path.bytes().all(|byte| {
            byte == b'/'
                || byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-' | b'~')
        })
    {
        bail!("webhook URL path must be a bounded non-secret path");
    }
    if !matches!(path, "/" | "/alerts" | "/webhook" | "/ocfleet/alerts") {
        bail!("webhook URL path is not in the fixed low-sensitive path catalog");
    }
    let host = url
        .host_str()
        .context("webhook URL must include a host")?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") {
        bail!("webhook URL host is forbidden");
    }
    let normalized_allow = normalize_host_allow(host_allow)?;
    if !normalized_allow.iter().any(|allowed| allowed == &host) {
        bail!("webhook URL host is not in the host allowlist");
    }
    validate_resolved_host(&host, url.port_or_known_default().unwrap_or(443))?;
    Ok(ValidatedWebhookEndpoint {
        url: url.to_string(),
        redacted_url: redact_webhook_url(&url, &host),
        host,
        host_allow: normalized_allow,
    })
}

pub fn normalize_host_allow(host_allow: &[String]) -> anyhow::Result<Vec<String>> {
    if host_allow.is_empty() || host_allow.len() > 16 {
        bail!("webhook host allowlist must contain 1-16 hosts");
    }
    let mut output = Vec::new();
    for host in host_allow {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty()
            || host.len() > 253
            || host.contains('/')
            || host.contains(':')
            || host.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            bail!("webhook host allow entry is invalid");
        }
        if host == "localhost" || host.ends_with(".localhost") || is_metadata_hostname(&host) {
            bail!("webhook host allow entry is forbidden");
        }
        output.push(host);
    }
    output.sort();
    output.dedup();
    Ok(output)
}

pub fn read_hmac_secret_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    let file = private_file::open_existing_private_read(path)
        .with_context(|| "failed to read webhook HMAC secret file")?;
    let mut secret = Vec::new();
    file.take(u64::try_from(MAX_HMAC_SECRET_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut secret)
        .with_context(|| "failed to read webhook HMAC secret file")?;
    if secret.len() > MAX_HMAC_SECRET_BYTES {
        bail!("webhook HMAC secret is too large");
    }
    while matches!(secret.last(), Some(b'\n' | b'\r')) {
        secret.pop();
    }
    if secret.len() < MIN_HMAC_SECRET_BYTES {
        bail!("webhook HMAC secret is too short");
    }
    Ok(secret)
}

pub fn hmac_key_id(secret: &[u8]) -> String {
    hex_lower(&Sha256::digest(secret))[..16].to_string()
}

pub fn build_webhook_request(
    hook: &AlertWebhookHookRecord,
    alert: &AlertEventRecord,
    secret: &[u8],
    timestamp: &str,
    delivery_id: &str,
) -> anyhow::Result<WebhookHttpRequest> {
    validate_webhook_endpoint(&hook.endpoint_url, &hook.host_allow)?;
    let payload = alert_delivery_payload_for_hook(alert, "webhook");
    let body = webhook_payload_bytes(&payload)?;
    let signature = webhook_signature(secret, timestamp, delivery_id, &body);
    Ok(WebhookHttpRequest {
        url: hook.endpoint_url.clone(),
        timeout_ms: hook.timeout_ms,
        headers: vec![
            (
                "X-Ocfleet-Signature".to_string(),
                format!("sha256={signature}"),
            ),
            ("X-Ocfleet-Timestamp".to_string(), timestamp.to_string()),
            ("X-Ocfleet-Delivery-Id".to_string(), delivery_id.to_string()),
            ("X-Ocfleet-Hook-Id".to_string(), hook.hook_id.clone()),
            (
                "X-Ocfleet-Hmac-Key-Id".to_string(),
                hook.hmac_key_id.clone(),
            ),
        ],
        body,
    })
}

pub fn webhook_payload_bytes(payload: &Value) -> anyhow::Result<Vec<u8>> {
    let body = serde_json::to_vec(payload)?;
    if body.len() > MAX_JSONL_PAYLOAD_BYTES {
        bail!("alert delivery payload exceeds limit");
    }
    Ok(body)
}

pub fn webhook_signature(secret: &[u8], timestamp: &str, delivery_id: &str, body: &[u8]) -> String {
    let mut signed = Vec::with_capacity(timestamp.len() + delivery_id.len() + body.len() + 2);
    signed.extend_from_slice(timestamp.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(delivery_id.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(body);
    hmac_sha256_hex(secret, &signed)
}

pub fn http_status_class(status: u16) -> &'static str {
    match status {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "unknown",
    }
}

pub fn webhook_error_for_status(status: u16) -> Option<&'static str> {
    match status {
        200..=299 => None,
        300..=399 => Some("WEBHOOK_REDIRECT_FORBIDDEN"),
        400..=499 => Some("WEBHOOK_HTTP_4XX"),
        500..=599 => Some("WEBHOOK_HTTP_5XX"),
        _ => Some("WEBHOOK_HTTP_STATUS_INVALID"),
    }
}

pub fn is_retryable_webhook_error(error_code: &str) -> bool {
    matches!(
        error_code,
        "WEBHOOK_TIMEOUT"
            | "WEBHOOK_REQUEST_FAILED"
            | "WEBHOOK_RESPONSE_READ_FAILED"
            | "WEBHOOK_RESPONSE_TOO_LARGE"
            | "WEBHOOK_HTTP_5XX"
    )
}

fn validate_resolved_host(host: &str, port: u16) -> anyhow::Result<()> {
    let _ = resolve_public_addresses(host, port)?;
    Ok(())
}

fn pinned_https_client(url: &str) -> Result<Client, &'static str> {
    let url = Url::parse(url).map_err(|_| "WEBHOOK_URL_INVALID")?;
    if url.scheme() != "https" {
        return Err("WEBHOOK_SCHEME_FORBIDDEN");
    }
    let host = url
        .host_str()
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
        .ok_or("WEBHOOK_HOST_MISSING")?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addresses =
        resolve_public_addresses(&host, port).map_err(|_| "WEBHOOK_RESOLVED_IP_FORBIDDEN")?;
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("ocfleet-alert-webhook/0.1")
        .resolve_to_addrs(&host, &addresses)
        .build()
        .map_err(|_| "WEBHOOK_CLIENT_BUILD_FAILED")
}

fn resolve_public_addresses(host: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
    if is_metadata_hostname(host) {
        bail!("webhook URL host is forbidden");
    }
    let addresses = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        (host, port)
            .to_socket_addrs()
            .with_context(|| "webhook host DNS resolution failed")?
            .collect::<Vec<_>>()
    };
    if addresses.is_empty() {
        bail!("webhook host DNS resolution returned no addresses");
    }
    for address in &addresses {
        if is_forbidden_ip(address.ip()) {
            bail!("webhook resolved IP is forbidden");
        }
    }
    Ok(addresses)
}

fn is_metadata_hostname(host: &str) -> bool {
    matches!(
        host,
        "metadata.google.internal"
            | "metadata"
            | "169.254.169.254"
            | "100.100.100.200"
            | "metadata.azure.internal"
    )
}

fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip == Ipv4Addr::BROADCAST
                || ip == Ipv4Addr::new(169, 254, 169, 254)
                || is_ipv4_shared_address(ip)
                || is_ipv4_non_public_special_use(ip)
        }
        IpAddr::V6(ip) => {
            ip.to_ipv4_mapped()
                .is_some_and(|mapped| is_forbidden_ip(IpAddr::V4(mapped)))
                || ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || is_ipv6_documentation(ip)
        }
    }
}

fn is_ipv4_shared_address(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn is_ipv4_non_public_special_use(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 0
        || octets[0] >= 240
        || (octets[0] == 198 && (18..=19).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
}

fn is_ipv6_documentation(ip: std::net::Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

fn redact_webhook_url(url: &Url, host: &str) -> String {
    let mut authority = host.to_string();
    if let Some(port) = url.port() {
        authority.push(':');
        authority.push_str(&port.to_string());
    }
    format!("https://{authority}/<redacted>")
}

fn hmac_sha256_hex(secret: &[u8], message: &[u8]) -> String {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0_u8; BLOCK_SIZE];
    if secret.len() > BLOCK_SIZE {
        let digest = Sha256::digest(secret);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..secret.len()].copy_from_slice(secret);
    }
    let mut ipad = [0x36_u8; BLOCK_SIZE];
    let mut opad = [0x5c_u8; BLOCK_SIZE];
    for index in 0..BLOCK_SIZE {
        ipad[index] ^= key_block[index];
        opad[index] ^= key_block[index];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    hex_lower(&outer.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}
