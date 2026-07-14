use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, bail};
use axum::http::HeaderMap;
use base64::Engine as _;
use ocfleet_cli::private_file;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MIN_TOKEN_BYTES: usize = 32;
const MAX_AUTH_CONFIG_BYTES: usize = 256 * 1024;
const MAX_AUTH_ENTRIES: usize = 256;
const MAX_JWT_SEGMENT_BYTES: usize = 12 * 1024;
const MTLS_VERIFIED_HEADER: &str = "x-ocfleet-mtls-verified";
const MTLS_SUBJECT_HEADER: &str = "x-ocfleet-mtls-subject";

static AUTH_MISSING_TOTAL: AtomicU64 = AtomicU64::new(0);
static AUTH_INVALID_TOTAL: AtomicU64 = AtomicU64::new(0);
static AUTH_EXPIRED_TOTAL: AtomicU64 = AtomicU64::new(0);
static AUTH_FORBIDDEN_TOTAL: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Viewer,
    Operator,
    SecurityAdmin,
    ChangeApprover,
    Auditor,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::SecurityAdmin => "security-admin",
            Self::ChangeApprover => "change-approver",
            Self::Auditor => "auditor",
        }
    }

    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "viewer" => Ok(Self::Viewer),
            "operator" => Ok(Self::Operator),
            "security-admin" => Ok(Self::SecurityAdmin),
            "change-approver" => Ok(Self::ChangeApprover),
            "auditor" => Ok(Self::Auditor),
            _ => bail!("unknown RBAC role"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    FleetRead,
    AuditRead,
    MetricsRead,
    HealthRead,
    ControlledWriteCreate,
    ControlledWriteApprove,
    SecurityAdmin,
}

impl Role {
    pub const fn permits(self, permission: Permission) -> bool {
        matches!(
            (self, permission),
            (
                Self::Viewer | Self::Operator | Self::SecurityAdmin,
                Permission::FleetRead
                    | Permission::AuditRead
                    | Permission::MetricsRead
                    | Permission::HealthRead,
            ) | (
                Self::Auditor,
                Permission::AuditRead | Permission::HealthRead
            ) | (
                Self::Operator | Self::SecurityAdmin,
                Permission::ControlledWriteCreate
            ) | (
                Self::ChangeApprover | Self::SecurityAdmin,
                Permission::ControlledWriteApprove
            ) | (Self::SecurityAdmin, Permission::SecurityAdmin)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthenticationMethod {
    LocalDevelopment,
    LegacyBearer,
    Oidc,
    Mtls,
    ServiceAccount,
    BreakGlass,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Principal {
    principal_id: String,
    roles: BTreeSet<Role>,
    method: AuthenticationMethod,
    authenticated: bool,
}

impl fmt::Debug for Principal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Principal")
            .field("principal_id", &"<redacted>")
            .field("roles", &self.roles)
            .field("method", &self.method)
            .field("authenticated", &self.authenticated)
            .finish()
    }
}

impl Principal {
    pub fn local_viewer() -> Self {
        Self::new(
            "local-development",
            [Role::Viewer],
            AuthenticationMethod::LocalDevelopment,
            false,
        )
    }

    fn authenticated_viewer() -> Self {
        Self::new(
            "legacy-bearer",
            [Role::Viewer],
            AuthenticationMethod::LegacyBearer,
            true,
        )
    }

    fn new(
        principal_id: impl Into<String>,
        roles: impl IntoIterator<Item = Role>,
        method: AuthenticationMethod,
        authenticated: bool,
    ) -> Self {
        Self {
            principal_id: principal_id.into(),
            roles: roles.into_iter().collect(),
            method,
            authenticated,
        }
    }

    pub fn actor(&self) -> &str {
        &self.principal_id
    }

    pub fn role(&self) -> Role {
        self.roles.iter().copied().next().unwrap_or(Role::Viewer)
    }

    pub fn roles(&self) -> impl Iterator<Item = Role> + '_ {
        self.roles.iter().copied()
    }

    pub fn authentication_method(&self) -> AuthenticationMethod {
        self.method
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    pub fn permits(&self, permission: Permission) -> bool {
        self.roles.iter().any(|role| role.permits(permission))
    }
}

#[derive(Clone)]
pub struct AuthToken {
    digest: [u8; 32],
}

impl fmt::Debug for AuthToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthToken")
            .field("digest", &"<redacted>")
            .finish()
    }
}

impl AuthToken {
    pub fn from_private_file(path: &Path) -> anyhow::Result<Self> {
        let raw = read_private_text(path, MAX_TOKEN_BYTES, "auth token")?;
        Self::from_token_text(&raw)
    }

    pub fn from_token_text(raw: &str) -> anyhow::Result<Self> {
        let token = raw.trim_end_matches(['\r', '\n']);
        validate_token(token)?;
        Ok(Self {
            digest: digest(token.as_bytes()),
        })
    }

    pub fn authenticate_headers(&self, headers: &HeaderMap) -> Option<Principal> {
        let token = bearer_token(headers)?;
        constant_time_eq(&self.digest, &digest(token.as_bytes()))
            .then(Principal::authenticated_viewer)
    }
}

#[derive(Clone)]
pub struct Authenticator {
    legacy_bearer: Option<AuthToken>,
    config: AuthConfig,
}

impl fmt::Debug for Authenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Authenticator")
            .field("legacy_bearer", &self.legacy_bearer.is_some())
            .field("local_development", &self.config.local_development)
            .field("service_account_count", &self.config.service_accounts.len())
            .field("oidc_enabled", &self.config.oidc.is_some())
            .field("mtls_subject_count", &self.config.mtls_subjects.len())
            .field("break_glass_enabled", &self.config.break_glass.is_some())
            .finish()
    }
}

impl Authenticator {
    pub fn load(
        legacy_bearer: Option<AuthToken>,
        config_path: Option<&Path>,
    ) -> anyhow::Result<Self> {
        let config = config_path
            .map(AuthConfig::from_private_file)
            .transpose()?
            .unwrap_or_else(|| AuthConfig {
                local_development: legacy_bearer.is_none(),
                ..AuthConfig::default()
            });
        if config.local_development && (legacy_bearer.is_some() || config.has_remote_method()) {
            bail!("local development auth cannot be combined with remote authentication");
        }
        Ok(Self {
            legacy_bearer,
            config,
        })
    }

    pub fn enabled(&self) -> bool {
        self.legacy_bearer.is_some() || self.config.has_remote_method()
    }

    pub fn mtls_proxy_enabled(&self) -> bool {
        !self.config.mtls_subjects.is_empty()
    }

    pub fn authenticate(&self, headers: &HeaderMap) -> Result<Principal, AuthFailure> {
        if let Some(token) = bearer_token(headers) {
            if validate_token(token).is_err() {
                return Err(AuthFailure::Invalid);
            }
            if let Some(legacy) = &self.legacy_bearer
                && constant_time_eq(&legacy.digest, &digest(token.as_bytes()))
            {
                return Ok(Principal::authenticated_viewer());
            }
            let token_digest = digest(token.as_bytes());
            let now = OffsetDateTime::now_utc();
            for account in &self.config.service_accounts {
                if constant_time_eq(&account.token_digest, &token_digest) {
                    return account.principal(now, AuthenticationMethod::ServiceAccount);
                }
            }
            if let Some(account) = &self.config.break_glass
                && constant_time_eq(&account.token_digest, &token_digest)
            {
                tracing::warn!("break-glass authentication used");
                return account.principal(now, AuthenticationMethod::BreakGlass);
            }
            if token.matches('.').count() == 2
                && let Some(oidc) = &self.config.oidc
            {
                return oidc.authenticate(token);
            }
            return Err(AuthFailure::Invalid);
        }

        if headers
            .get(MTLS_VERIFIED_HEADER)
            .and_then(|value| value.to_str().ok())
            == Some("SUCCESS")
        {
            let subject = headers
                .get(MTLS_SUBJECT_HEADER)
                .and_then(|value| value.to_str().ok())
                .ok_or(AuthFailure::Invalid)?;
            let identity = self
                .config
                .mtls_subjects
                .get(subject)
                .ok_or(AuthFailure::Invalid)?;
            return Ok(identity.principal(AuthenticationMethod::Mtls));
        }

        if self.config.local_development {
            Ok(Principal::local_viewer())
        } else {
            Err(AuthFailure::Missing)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    Missing,
    Invalid,
    Expired,
}

impl AuthFailure {
    pub fn record(self) {
        let counter = match self {
            Self::Missing => &AUTH_MISSING_TOTAL,
            Self::Invalid => &AUTH_INVALID_TOTAL,
            Self::Expired => &AUTH_EXPIRED_TOTAL,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(reason = ?self, "API authentication failed");
    }
}

pub fn record_forbidden() {
    AUTH_FORBIDDEN_TOTAL.fetch_add(1, Ordering::Relaxed);
    tracing::warn!("API authorization failed");
}

pub fn auth_failure_counts() -> [u64; 4] {
    [
        AUTH_MISSING_TOTAL.load(Ordering::Relaxed),
        AUTH_INVALID_TOTAL.load(Ordering::Relaxed),
        AUTH_EXPIRED_TOTAL.load(Ordering::Relaxed),
        AUTH_FORBIDDEN_TOTAL.load(Ordering::Relaxed),
    ]
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct AuthConfigFile {
    local_development: bool,
    service_accounts: Vec<ServiceAccountFile>,
    oidc: Option<OidcFile>,
    mtls_subjects: Vec<MtlsIdentityFile>,
    break_glass: Option<BreakGlassFile>,
}

#[derive(Clone, Default)]
struct AuthConfig {
    local_development: bool,
    service_accounts: Vec<ServiceAccount>,
    oidc: Option<OidcVerifier>,
    mtls_subjects: BTreeMap<String, MtlsIdentity>,
    break_glass: Option<ServiceAccount>,
}

impl AuthConfig {
    fn from_private_file(path: &Path) -> anyhow::Result<Self> {
        let text = read_private_text(path, MAX_AUTH_CONFIG_BYTES, "auth config")?;
        let file: AuthConfigFile =
            toml::from_str(&text).map_err(|_| anyhow::anyhow!("auth config is invalid"))?;
        if file.service_accounts.len() > MAX_AUTH_ENTRIES
            || file.mtls_subjects.len() > MAX_AUTH_ENTRIES
        {
            bail!("auth config contains too many identities");
        }
        let service_accounts = file
            .service_accounts
            .into_iter()
            .map(ServiceAccount::try_from)
            .collect::<anyhow::Result<Vec<_>>>()?;
        let break_glass = file
            .break_glass
            .map(|entry| {
                if !entry.enabled {
                    bail!("break-glass identity must be explicitly enabled");
                }
                let account = ServiceAccount::try_from(entry.account)?;
                if !account.roles.contains(&Role::SecurityAdmin) {
                    bail!("break-glass identity must include security-admin");
                }
                let now = OffsetDateTime::now_utc();
                if account.expires_at <= now || account.expires_at > now + time::Duration::hours(1)
                {
                    bail!("break-glass expiry must be within one hour");
                }
                Ok(account)
            })
            .transpose()?;
        let mut mtls_subjects = BTreeMap::new();
        for entry in file.mtls_subjects {
            let subject = validate_identity_text(&entry.subject, "mTLS subject")?;
            let identity = MtlsIdentity::try_from(entry)?;
            if mtls_subjects.insert(subject, identity).is_some() {
                bail!("auth config contains a duplicate mTLS subject");
            }
        }
        Ok(Self {
            local_development: file.local_development,
            service_accounts,
            oidc: file.oidc.map(OidcVerifier::try_from).transpose()?,
            mtls_subjects,
            break_glass,
        })
    }

    fn has_remote_method(&self) -> bool {
        !self.service_accounts.is_empty()
            || self.oidc.is_some()
            || !self.mtls_subjects.is_empty()
            || self.break_glass.is_some()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceAccountFile {
    principal_id: String,
    token_sha256: String,
    expires_at: String,
    roles: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BreakGlassFile {
    enabled: bool,
    #[serde(flatten)]
    account: ServiceAccountFile,
}

#[derive(Clone)]
struct ServiceAccount {
    principal_id: String,
    token_digest: [u8; 32],
    expires_at: OffsetDateTime,
    roles: BTreeSet<Role>,
}

impl TryFrom<ServiceAccountFile> for ServiceAccount {
    type Error = anyhow::Error;

    fn try_from(value: ServiceAccountFile) -> Result<Self, Self::Error> {
        Ok(Self {
            principal_id: validate_identity_text(&value.principal_id, "principal_id")?,
            token_digest: parse_sha256(&value.token_sha256)?,
            expires_at: OffsetDateTime::parse(&value.expires_at, &Rfc3339)
                .context("service-account expiry must be RFC3339")?,
            roles: parse_roles(value.roles)?,
        })
    }
}

impl ServiceAccount {
    fn principal(
        &self,
        now: OffsetDateTime,
        method: AuthenticationMethod,
    ) -> Result<Principal, AuthFailure> {
        if self.expires_at <= now {
            return Err(AuthFailure::Expired);
        }
        Ok(Principal::new(
            self.principal_id.clone(),
            self.roles.iter().copied(),
            method,
            true,
        ))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MtlsIdentityFile {
    subject: String,
    principal_id: String,
    roles: Vec<String>,
}

#[derive(Clone)]
struct MtlsIdentity {
    principal_id: String,
    roles: BTreeSet<Role>,
}

impl TryFrom<MtlsIdentityFile> for MtlsIdentity {
    type Error = anyhow::Error;

    fn try_from(value: MtlsIdentityFile) -> Result<Self, Self::Error> {
        Ok(Self {
            principal_id: validate_identity_text(&value.principal_id, "principal_id")?,
            roles: parse_roles(value.roles)?,
        })
    }
}

impl MtlsIdentity {
    fn principal(&self, method: AuthenticationMethod) -> Principal {
        Principal::new(
            self.principal_id.clone(),
            self.roles.iter().copied(),
            method,
            true,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OidcFile {
    issuer: String,
    audience: String,
    #[serde(default = "default_groups_claim")]
    groups_claim: String,
    #[serde(default)]
    keys: Vec<OidcKeyFile>,
    #[serde(default)]
    jwks_file: Option<std::path::PathBuf>,
    role_mappings: Vec<RoleMappingFile>,
}

fn default_groups_claim() -> String {
    "groups".into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OidcKeyFile {
    kid: String,
    algorithm: String,
    public_key_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JwksFile {
    keys: Vec<JwkFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JwkFile {
    kty: String,
    crv: String,
    alg: String,
    #[serde(rename = "use")]
    key_use: String,
    kid: String,
    x: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleMappingFile {
    group: String,
    role: String,
}

#[derive(Clone)]
struct OidcVerifier {
    issuer: String,
    audience: String,
    groups_claim: String,
    keys: BTreeMap<String, [u8; 32]>,
    mappings: BTreeMap<String, BTreeSet<Role>>,
}

impl TryFrom<OidcFile> for OidcVerifier {
    type Error = anyhow::Error;

    fn try_from(mut value: OidcFile) -> Result<Self, Self::Error> {
        let issuer = validate_identity_text(&value.issuer, "OIDC issuer")?;
        let audience = validate_identity_text(&value.audience, "OIDC audience")?;
        let groups_claim = validate_identity_text(&value.groups_claim, "OIDC groups claim")?;
        if let Some(path) = value.jwks_file.take() {
            if !path.is_absolute() {
                bail!("OIDC jwks_file must be absolute");
            }
            let text = read_private_text(&path, MAX_AUTH_CONFIG_BYTES, "OIDC JWKS cache")?;
            let jwks: JwksFile = serde_json::from_str(&text)
                .map_err(|_| anyhow::anyhow!("OIDC JWKS cache is invalid"))?;
            for key in jwks.keys {
                if key.kty != "OKP"
                    || key.crv != "Ed25519"
                    || key.alg != "EdDSA"
                    || key.key_use != "sig"
                {
                    bail!("OIDC JWKS key must be an Ed25519 signing key");
                }
                value.keys.push(OidcKeyFile {
                    kid: key.kid,
                    algorithm: key.alg,
                    public_key_base64url: key.x,
                });
            }
        }
        if value.keys.is_empty() || value.keys.len() > MAX_AUTH_ENTRIES {
            bail!("OIDC must configure 1-256 JWKS keys");
        }
        let mut keys = BTreeMap::new();
        for key in value.keys {
            if key.algorithm != "EdDSA" {
                bail!("OIDC key algorithm must be EdDSA");
            }
            let kid = validate_identity_text(&key.kid, "OIDC key id")?;
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(key.public_key_base64url)
                .context("OIDC Ed25519 key is invalid")?;
            let public_key: [u8; 32] = decoded
                .try_into()
                .map_err(|_| anyhow::anyhow!("OIDC Ed25519 key must be 32 bytes"))?;
            if keys.insert(kid, public_key).is_some() {
                bail!("OIDC key id is duplicated");
            }
        }
        let mut mappings: BTreeMap<String, BTreeSet<Role>> = BTreeMap::new();
        for mapping in value.role_mappings {
            let group = validate_identity_text(&mapping.group, "OIDC group")?;
            mappings
                .entry(group)
                .or_default()
                .insert(Role::parse(&mapping.role)?);
        }
        Ok(Self {
            issuer,
            audience,
            groups_claim,
            keys,
            mappings,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JwtHeader {
    alg: String,
    kid: String,
    #[serde(default)]
    typ: Option<String>,
}

#[derive(Deserialize)]
struct JwtClaims {
    iss: String,
    aud: Audience,
    sub: String,
    exp: i64,
    #[serde(default)]
    nbf: Option<i64>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
        }
    }
}

impl OidcVerifier {
    fn authenticate(&self, token: &str) -> Result<Principal, AuthFailure> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(AuthFailure::Invalid);
        }
        let mut segments = token.split('.');
        let header_segment = segments.next().ok_or(AuthFailure::Invalid)?;
        let claims_segment = segments.next().ok_or(AuthFailure::Invalid)?;
        let signature_segment = segments.next().ok_or(AuthFailure::Invalid)?;
        if segments.next().is_some()
            || header_segment.len() > MAX_JWT_SEGMENT_BYTES
            || claims_segment.len() > MAX_JWT_SEGMENT_BYTES
            || signature_segment.len() > MAX_JWT_SEGMENT_BYTES
        {
            return Err(AuthFailure::Invalid);
        }
        let header: JwtHeader = decode_jwt_json(header_segment)?;
        if header.alg != "EdDSA" || header.typ.as_deref().is_some_and(|typ| typ != "JWT") {
            return Err(AuthFailure::Invalid);
        }
        let public_key = self.keys.get(&header.kid).ok_or(AuthFailure::Invalid)?;
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature_segment)
            .map_err(|_| AuthFailure::Invalid)?;
        let signing_input = format!("{header_segment}.{claims_segment}");
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| AuthFailure::Invalid)?;
        let claims: JwtClaims = decode_jwt_json(claims_segment)?;
        if claims.iss != self.issuer || !claims.aud.contains(&self.audience) {
            return Err(AuthFailure::Invalid);
        }
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if claims.exp <= now {
            return Err(AuthFailure::Expired);
        }
        if claims.nbf.is_some_and(|not_before| not_before > now) {
            return Err(AuthFailure::Invalid);
        }
        let subject = validate_identity_text(&claims.sub, "OIDC subject")
            .map_err(|_| AuthFailure::Invalid)?;
        let groups = claims
            .extra
            .get(&self.groups_claim)
            .and_then(Value::as_array)
            .ok_or(AuthFailure::Invalid)?;
        if groups.len() > MAX_AUTH_ENTRIES {
            return Err(AuthFailure::Invalid);
        }
        let mut roles = BTreeSet::new();
        for group in groups {
            let group = group.as_str().ok_or(AuthFailure::Invalid)?;
            if let Some(mapped) = self.mappings.get(group) {
                roles.extend(mapped);
            }
        }
        if roles.is_empty() {
            return Err(AuthFailure::Invalid);
        }
        Ok(Principal::new(
            subject,
            roles,
            AuthenticationMethod::Oidc,
            true,
        ))
    }
}

fn decode_jwt_json<T: for<'de> Deserialize<'de>>(segment: &str) -> Result<T, AuthFailure> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| AuthFailure::Invalid)?;
    serde_json::from_slice(&decoded).map_err(|_| AuthFailure::Invalid)
}

fn parse_roles(values: Vec<String>) -> anyhow::Result<BTreeSet<Role>> {
    if values.is_empty() || values.len() > 5 {
        bail!("identity must have 1-5 roles");
    }
    values
        .into_iter()
        .map(|value| Role::parse(&value))
        .collect()
}

fn parse_sha256(value: &str) -> anyhow::Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("token_sha256 must be lowercase SHA-256 hex");
    }
    let mut output = [0_u8; 32];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .context("token_sha256 is invalid")?;
    }
    Ok(output)
}

fn validate_identity_text(value: &str, field: &str) -> anyhow::Result<String> {
    if value.trim().is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| !byte.is_ascii() || byte.is_ascii_control())
    {
        bail!("{field} is invalid");
    }
    Ok(value.to_string())
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn validate_token(token: &str) -> anyhow::Result<()> {
    let len = token.len();
    if !(MIN_TOKEN_BYTES..=MAX_TOKEN_BYTES).contains(&len) {
        bail!("auth token must be between {MIN_TOKEN_BYTES} and {MAX_TOKEN_BYTES} bytes");
    }
    if token
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        bail!("auth token must not contain whitespace or control characters");
    }
    Ok(())
}

fn read_private_text(path: &Path, limit: usize, label: &str) -> anyhow::Result<String> {
    let file = private_file::open_existing_private_read(path)?;
    let mut limited = file.take((limit + 1) as u64);
    let mut raw = String::new();
    limited.read_to_string(&mut raw)?;
    if raw.len() > limit {
        bail!("{label} file is too large");
    }
    Ok(raw)
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::json;

    #[test]
    fn rejects_short_tokens() {
        assert!(AuthToken::from_token_text("short").is_err());
    }

    #[test]
    fn accepts_trailing_newline() {
        let token =
            AuthToken::from_token_text("abcdefghijklmnopqrstuvwxyz123456\n").expect("valid token");
        let headers = bearer_headers("abcdefghijklmnopqrstuvwxyz123456");
        let principal = token.authenticate_headers(&headers).expect("principal");
        assert_eq!(principal.role(), Role::Viewer);
        assert!(principal.is_authenticated());
    }

    #[test]
    fn role_permission_matrix_is_default_deny() {
        assert!(Role::Viewer.permits(Permission::FleetRead));
        assert!(!Role::Viewer.permits(Permission::ControlledWriteCreate));
        assert!(Role::Operator.permits(Permission::ControlledWriteCreate));
        assert!(!Role::Operator.permits(Permission::ControlledWriteApprove));
        assert!(Role::ChangeApprover.permits(Permission::ControlledWriteApprove));
        assert!(!Role::ChangeApprover.permits(Permission::FleetRead));
        assert!(Role::Auditor.permits(Permission::AuditRead));
        assert!(!Role::Auditor.permits(Permission::MetricsRead));
        assert!(Role::SecurityAdmin.permits(Permission::SecurityAdmin));
    }

    #[test]
    fn break_glass_is_expiring_explicit_and_debug_redacted() {
        let raw = "break-glass-emergency-token-123456789";
        let account = ServiceAccount {
            principal_id: "break-glass:incident-1".into(),
            token_digest: digest(raw.as_bytes()),
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(30),
            roles: [Role::SecurityAdmin].into_iter().collect(),
        };
        let authenticator = Authenticator {
            legacy_bearer: None,
            config: AuthConfig {
                break_glass: Some(account),
                ..AuthConfig::default()
            },
        };
        let principal = authenticator
            .authenticate(&bearer_headers(raw))
            .expect("break glass");
        assert_eq!(
            principal.authentication_method(),
            AuthenticationMethod::BreakGlass
        );
        assert!(principal.permits(Permission::SecurityAdmin));
        let debug = format!("{authenticator:?} {principal:?}");
        assert!(!debug.contains(raw));
        assert!(!debug.contains("incident-1"));

        let expired = Authenticator {
            legacy_bearer: None,
            config: AuthConfig {
                break_glass: Some(ServiceAccount {
                    expires_at: OffsetDateTime::now_utc() - time::Duration::seconds(1),
                    ..authenticator.config.break_glass.expect("account")
                }),
                ..AuthConfig::default()
            },
        };
        assert_eq!(
            expired.authenticate(&bearer_headers(raw)),
            Err(AuthFailure::Expired)
        );
    }

    #[test]
    fn static_dotted_tokens_are_checked_before_oidc() {
        let key = generate_key();
        let oidc = OidcVerifier::try_from(OidcFile {
            issuer: "https://issuer.example".into(),
            audience: "ocfleet-api".into(),
            groups_claim: "groups".into(),
            keys: vec![key_file("current", &key)],
            jwks_file: None,
            role_mappings: vec![RoleMappingFile {
                group: "fleet-operators".into(),
                role: "operator".into(),
            }],
        })
        .expect("verifier");
        let service_token = "service-account-token.with.two-dots-1234567890";
        let break_glass_token = "break-glass-token.with.two-dots-1234567890";
        assert_eq!(service_token.matches('.').count(), 2);
        assert_eq!(break_glass_token.matches('.').count(), 2);
        let expires_at = OffsetDateTime::now_utc() + time::Duration::minutes(30);
        let authenticator = Authenticator {
            legacy_bearer: None,
            config: AuthConfig {
                service_accounts: vec![ServiceAccount {
                    principal_id: "service:automation".into(),
                    token_digest: digest(service_token.as_bytes()),
                    expires_at,
                    roles: [Role::Operator].into_iter().collect(),
                }],
                oidc: Some(oidc),
                break_glass: Some(ServiceAccount {
                    principal_id: "break-glass:incident-2".into(),
                    token_digest: digest(break_glass_token.as_bytes()),
                    expires_at,
                    roles: [Role::SecurityAdmin].into_iter().collect(),
                }),
                ..AuthConfig::default()
            },
        };

        let service = authenticator
            .authenticate(&bearer_headers(service_token))
            .expect("dotted service-account token");
        assert_eq!(
            service.authentication_method(),
            AuthenticationMethod::ServiceAccount
        );
        let break_glass = authenticator
            .authenticate(&bearer_headers(break_glass_token))
            .expect("dotted break-glass token");
        assert_eq!(
            break_glass.authentication_method(),
            AuthenticationMethod::BreakGlass
        );
    }

    #[test]
    fn oidc_checks_signature_issuer_audience_time_rotation_and_mapping() {
        let first = generate_key();
        let second = generate_key();
        let verifier = OidcVerifier::try_from(OidcFile {
            issuer: "https://issuer.example".into(),
            audience: "ocfleet-api".into(),
            groups_claim: "groups".into(),
            keys: vec![key_file("old", &first), key_file("current", &second)],
            jwks_file: None,
            role_mappings: vec![RoleMappingFile {
                group: "fleet-operators".into(),
                role: "operator".into(),
            }],
        })
        .expect("verifier");
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = json!({
            "iss": "https://issuer.example",
            "aud": "ocfleet-api",
            "sub": "alice@example.com",
            "exp": now + 300,
            "nbf": now - 1,
            "groups": ["fleet-operators"]
        });
        for (kid, key) in [("old", &first), ("current", &second)] {
            let principal = verifier
                .authenticate(&jwt(kid, key, &claims))
                .expect("rotated key accepted");
            assert_eq!(principal.actor(), "alice@example.com");
            assert!(principal.permits(Permission::ControlledWriteCreate));
        }
        let mut wrong = claims.clone();
        wrong["aud"] = Value::String("other-api".into());
        assert!(
            verifier
                .authenticate(&jwt("current", &second, &wrong))
                .is_err()
        );
        let mut expired = claims;
        expired["exp"] = Value::from(now - 1);
        assert_eq!(
            verifier.authenticate(&jwt("current", &second, &expired)),
            Err(AuthFailure::Expired)
        );
        let forged = jwt("current", &first, &expired);
        assert_eq!(verifier.authenticate(&forged), Err(AuthFailure::Invalid));
    }

    fn generate_key() -> Ed25519KeyPair {
        let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate key");
        Ed25519KeyPair::from_pkcs8(key.as_ref()).expect("parse key")
    }

    fn key_file(kid: &str, key: &Ed25519KeyPair) -> OidcKeyFile {
        OidcKeyFile {
            kid: kid.into(),
            algorithm: "EdDSA".into(),
            public_key_base64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(key.public_key().as_ref()),
        }
    }

    fn jwt(kid: &str, key: &Ed25519KeyPair, claims: &Value) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({"alg":"EdDSA","kid":kid,"typ":"JWT"})).unwrap());
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(claims).unwrap());
        let input = format!("{header}.{claims}");
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(key.sign(input.as_bytes()).as_ref());
        format!("{input}.{signature}")
    }

    fn bearer_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().expect("header"),
        );
        headers
    }
}
