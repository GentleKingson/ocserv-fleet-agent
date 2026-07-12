use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ocfleet_config::validation::{
    canonicalize_controller_endpoint_id, canonicalize_node_endpoint_id,
    canonicalize_path_probe_endpoint_id, canonicalize_peer_endpoint_id, validate_controller_role,
    validate_node_id, validate_region, validate_role,
};
use ocfleet_protocol::enrollment::EndpointStatus;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::str::FromStr;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::args::TrustPolicyDiffFormat;
use crate::input_validation::{
    validate_actor, validate_agent_version, validate_label_json, validate_metadata_value,
};
use crate::private_file;
use crate::store::{EndpointTrustRecord, NodeRecord, Store};

const MAX_POLICY_BYTES: u64 = 256 * 1024;
const MAX_POLICY_NODES: usize = 2_048;
const MAX_POLICY_CONTROLLERS: usize = 128;
const MAX_POLICY_PEERS: usize = 4_096;
const MAX_POLICY_PATH_PROBES: usize = 4_096;
const MAX_DIFF_ITEMS: usize = 512;
const MAX_SIGNATURE_BYTES: u64 = 16 * 1024;
const MAX_SIGNING_KEY_BYTES: u64 = 16 * 1024;
const MAX_PLAN_BYTES: u64 = 512 * 1024;
const MAX_HISTORY_BYTES: u64 = 1024 * 1024;
const MAX_HISTORY_ENTRIES: usize = 256;
const POLICY_SIGNATURE_SCHEMA: &str = "ocfleet.trust_policy.signature.v1";
const POLICY_PUBLIC_KEY_SCHEMA: &str = "ocfleet.trust_policy.public_key.v1";
const POLICY_PLAN_SCHEMA: &str = "ocfleet.trust_policy.plan.v1";
const POLICY_APPROVAL_SCHEMA: &str = "ocfleet.trust_policy.approval.v1";
const POLICY_HISTORY_SCHEMA: &str = "ocfleet.trust_policy.history.v1";

pub fn run_trust_policy_validate(
    file: &Path,
    json: bool,
    signature: Option<&Path>,
    public_key: Option<&Path>,
) -> anyhow::Result<()> {
    let (policy, report) = load_and_validate_policy(file)?;
    validate_signature_args(signature, public_key)?;
    if let (Some(signature), Some(public_key)) = (signature, public_key) {
        verify_policy_signature(&policy, &report, signature, public_key)?;
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_validation_human(file, &report);
    }
    Ok(())
}

pub fn run_trust_policy_diff(
    store: &Store,
    file: &Path,
    json: bool,
    format: TrustPolicyDiffFormat,
    output: Option<&Path>,
) -> anyhow::Result<()> {
    let (policy, report) = load_and_validate_policy(file)?;
    let diff = compute_policy_diff(store, policy, report)?;
    let format = if json {
        TrustPolicyDiffFormat::Json
    } else {
        format
    };
    match format {
        TrustPolicyDiffFormat::Human => {
            if output.is_some() {
                bail!("--output is supported only with --format markdown");
            }
            print_diff_human(file, &diff);
        }
        TrustPolicyDiffFormat::Json => {
            if output.is_some() {
                bail!("--output is supported only with --format markdown");
            }
            println!("{}", serde_json::to_string_pretty(&diff)?);
        }
        TrustPolicyDiffFormat::Markdown => {
            let markdown = format_diff_markdown(file, &diff);
            if let Some(path) = output {
                let mut file = private_file::open_private_create_new_strict(path)
                    .with_context(|| "failed to create private markdown output")?;
                file.write_all(markdown.as_bytes())
                    .with_context(|| "failed to write markdown output")?;
                file.sync_all()
                    .with_context(|| "failed to sync markdown output")?;
            } else {
                print!("{markdown}");
            }
        }
    }
    Ok(())
}

pub fn run_trust_policy_sign(
    file: &Path,
    key_file: &Path,
    key_id: &str,
    output: &Path,
    public_key_output: &Path,
    json: bool,
) -> anyhow::Result<()> {
    validate_metadata_label("key_id", key_id)?;
    let (policy, report) = load_and_validate_policy(file)?;
    require_explicit_revision(&policy)?;
    let key_bytes = read_private_bounded(key_file, MAX_SIGNING_KEY_BYTES, "signing key")?;
    let key_pair = Ed25519KeyPair::from_pkcs8(&key_bytes)
        .map_err(|_| anyhow::anyhow!("invalid Ed25519 PKCS#8 policy signing key"))?;
    let signature = key_pair.sign(&policy_signature_payload(
        &report.policy_revision,
        &report.policy_sha256,
    ));
    let signature_file = PolicySignatureFile {
        schema: POLICY_SIGNATURE_SCHEMA.to_string(),
        algorithm: "ed25519".to_string(),
        key_id: key_id.to_string(),
        policy_revision: report.policy_revision.clone(),
        policy_sha256: report.policy_sha256.clone(),
        signature: BASE64.encode(signature.as_ref()),
    };
    let public_key_file = PolicyPublicKeyFile {
        schema: POLICY_PUBLIC_KEY_SCHEMA.to_string(),
        algorithm: "ed25519".to_string(),
        key_id: key_id.to_string(),
        public_key: BASE64.encode(key_pair.public_key().as_ref()),
    };
    write_private_json(public_key_output, &public_key_file, "policy public key")?;
    write_private_json(output, &signature_file, "policy signature")?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "signed",
                "policy_revision": report.policy_revision,
                "policy_sha256": report.policy_sha256,
                "key_id": key_id,
                "public_key_sha256": sha256_hex(key_pair.public_key().as_ref()),
            }))?
        );
    } else {
        println!("status=signed");
        println!("policy_revision={}", report.policy_revision);
        println!("policy_sha256={}", report.policy_sha256);
        println!("key_id={key_id}");
    }
    Ok(())
}

pub fn run_trust_policy_plan(
    store: &Store,
    file: &Path,
    signature: &Path,
    public_key: &Path,
    output: &Path,
    markdown_output: Option<&Path>,
    json: bool,
) -> anyhow::Result<()> {
    let (policy, report) = load_and_validate_policy(file)?;
    require_explicit_revision(&policy)?;
    let verified = verify_policy_signature(&policy, &report, signature, public_key)?;
    let policy_revision = report.policy_revision.clone();
    let policy_sha256 = report.policy_sha256.clone();
    let diff = compute_policy_diff(store, policy, report)?;
    let drift_active = diff.total_diff_count > 0;
    let severity = if diff.diffs.iter().any(|change| change.severity == "high") {
        "critical"
    } else if drift_active {
        "warning"
    } else {
        "none"
    };
    let plan = TrustPolicyPlan {
        schema: POLICY_PLAN_SCHEMA.to_string(),
        mode: "review-only".to_string(),
        policy_revision,
        policy_sha256,
        signature_key_id: verified.key_id,
        signature_public_key_sha256: verified.public_key_sha256,
        change_count: diff.diff_count,
        total_change_count: diff.total_diff_count,
        truncated: diff.truncated,
        changes: diff
            .diffs
            .into_iter()
            .map(TrustPolicyPlanChange::from)
            .collect(),
        drift_alert: TrustPolicyDriftAlert {
            active: drift_active,
            reason_code: "TRUST_POLICY_DRIFT".to_string(),
            severity: severity.to_string(),
            total_change_count: diff.total_diff_count,
        },
    };
    write_private_json(output, &plan, "policy plan")?;
    if let Some(path) = markdown_output {
        write_private_text(
            path,
            &format_plan_markdown(file, &plan),
            "policy markdown report",
        )?;
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        println!("status=planned");
        println!("mode={}", plan.mode);
        println!("policy_revision={}", plan.policy_revision);
        println!("policy_sha256={}", plan.policy_sha256);
        println!("change_count={}", plan.change_count);
        println!("total_change_count={}", plan.total_change_count);
        println!("truncated={}", plan.truncated);
        println!("drift_alert={}", plan.drift_alert.active);
    }
    Ok(())
}

pub fn run_trust_policy_approve(
    plan_path: &Path,
    key_file: &Path,
    key_id: &str,
    approver: &str,
    output: &Path,
    json: bool,
) -> anyhow::Result<()> {
    validate_metadata_label("key_id", key_id)?;
    validate_actor(approver).map_err(anyhow::Error::msg)?;
    let plan: TrustPolicyPlan =
        read_artifact_json_bounded(plan_path, MAX_PLAN_BYTES, "policy plan")?;
    validate_plan(&plan)?;
    let key_bytes = read_private_bounded(key_file, MAX_SIGNING_KEY_BYTES, "approval key")?;
    let key_pair = Ed25519KeyPair::from_pkcs8(&key_bytes)
        .map_err(|_| anyhow::anyhow!("invalid Ed25519 PKCS#8 approval signing key"))?;
    let approved_at = now_rfc3339();
    let plan_sha256 = sha256_hex(&serde_json::to_vec(&plan)?);
    let payload = approval_signature_payload(
        &plan.policy_revision,
        &plan_sha256,
        approver,
        &approved_at,
        key_id,
    );
    let approval = TrustPolicyApproval {
        schema: POLICY_APPROVAL_SCHEMA.to_string(),
        policy_revision: plan.policy_revision,
        plan_sha256,
        approver: approver.to_string(),
        approved_at,
        key_id: key_id.to_string(),
        public_key: BASE64.encode(key_pair.public_key().as_ref()),
        signature: BASE64.encode(key_pair.sign(&payload).as_ref()),
    };
    write_private_json(output, &approval, "policy approval")?;
    if json {
        println!("{}", serde_json::to_string_pretty(&approval)?);
    } else {
        println!("status=approved");
        println!("policy_revision={}", approval.policy_revision);
        println!("plan_sha256={}", approval.plan_sha256);
        println!("approver={}", approval.approver);
        println!("key_id={}", approval.key_id);
    }
    Ok(())
}

pub fn run_trust_policy_history_record(
    plan_path: &Path,
    approval_path: Option<&Path>,
    history_path: &Path,
    json: bool,
) -> anyhow::Result<()> {
    let plan: TrustPolicyPlan =
        read_artifact_json_bounded(plan_path, MAX_PLAN_BYTES, "policy plan")?;
    validate_plan(&plan)?;
    let entries = read_history_entries(history_path, true)?;
    if entries
        .iter()
        .any(|entry| entry.policy_revision == plan.policy_revision)
    {
        bail!("policy revision is already present in history");
    }
    if entries.len() >= MAX_HISTORY_ENTRIES {
        bail!("policy history exceeds the bounded limit of {MAX_HISTORY_ENTRIES} entries");
    }
    let approval = approval_path
        .map(|path| {
            read_artifact_json_bounded::<TrustPolicyApproval>(
                path,
                MAX_SIGNATURE_BYTES,
                "policy approval",
            )
        })
        .transpose()?;
    if let Some(approval) = &approval {
        validate_approval(approval, &plan)?;
    }
    let entry = TrustPolicyHistoryEntry {
        schema: POLICY_HISTORY_SCHEMA.to_string(),
        policy_revision: plan.policy_revision.clone(),
        policy_sha256: plan.policy_sha256.clone(),
        plan_sha256: sha256_hex(&serde_json::to_vec(&plan)?),
        total_change_count: plan.total_change_count,
        drift_active: plan.drift_alert.active,
        approved_by: approval.as_ref().map(|value| value.approver.clone()),
        approval_key_id: approval.as_ref().map(|value| value.key_id.clone()),
        approval_sha256: approval
            .as_ref()
            .map(|value| serde_json::to_vec(value).map(|bytes| sha256_hex(&bytes)))
            .transpose()?,
        recorded_at: now_rfc3339(),
    };
    let mut file = private_file::open_private_append_create(history_path)
        .context("failed to open private policy history")?;
    serde_json::to_writer(&mut file, &entry).context("failed to serialize policy history")?;
    file.write_all(b"\n")
        .context("failed to append policy history")?;
    file.sync_all().context("failed to sync policy history")?;
    if json {
        println!("{}", serde_json::to_string_pretty(&entry)?);
    } else {
        println!("status=recorded");
        println!("policy_revision={}", entry.policy_revision);
        println!("plan_sha256={}", entry.plan_sha256);
    }
    Ok(())
}

pub fn run_trust_policy_history_list(history_path: &Path, json: bool) -> anyhow::Result<()> {
    let mut entries = read_history_entries(history_path, false)?;
    entries.sort_by(|left, right| {
        (left.recorded_at.as_str(), left.policy_revision.as_str())
            .cmp(&(right.recorded_at.as_str(), right.policy_revision.as_str()))
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        for entry in entries {
            println!(
                "revision={} recorded_at={} drift_active={} total_change_count={} plan_sha256={}",
                entry.policy_revision,
                entry.recorded_at,
                entry.drift_active,
                entry.total_change_count,
                entry.plan_sha256
            );
        }
    }
    Ok(())
}

struct VerifiedPolicySignature {
    key_id: String,
    public_key_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustPolicyDocument {
    version: u32,
    #[serde(default)]
    metadata: Option<PolicyMetadata>,
    #[serde(default)]
    nodes: Vec<PolicyNode>,
    #[serde(default)]
    controllers: Vec<PolicyController>,
    #[serde(default)]
    peers: Vec<PolicyPeer>,
    #[serde(default)]
    path_probes: Vec<PolicyPathProbe>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyMetadata {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    revision: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyNode {
    node_id: String,
    endpoint_id: String,
    region: String,
    role: String,
    lifecycle: String,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    environment: Option<String>,
    #[serde(default)]
    site: Option<String>,
    #[serde(default)]
    owner_team: Option<String>,
    #[serde(default)]
    service_tier: Option<String>,
    #[serde(default)]
    labels: Option<BTreeMap<String, String>>,
    #[serde(default)]
    expected_agent_version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyController {
    endpoint_id: String,
    role: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyPeer {
    source_node_id: String,
    peer_node_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyPathProbe {
    source_node_id: String,
    target_node_id: String,
    #[serde(default)]
    enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
struct TrustPolicyValidationReport {
    generated_at: String,
    status: &'static str,
    schema_version: u32,
    policy_revision: String,
    policy_sha256: String,
    node_count: usize,
    controller_count: usize,
    peer_count: usize,
    path_probe_count: usize,
    warning_count: usize,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct TrustPolicyDiffReport {
    generated_at: String,
    status: &'static str,
    validated: TrustPolicyValidationReport,
    diff_count: usize,
    total_diff_count: usize,
    truncated: bool,
    diffs: Vec<TrustPolicyDiff>,
}

#[derive(Debug, Serialize)]
struct TrustPolicyDiff {
    code: &'static str,
    severity: &'static str,
    node_id: Option<String>,
    endpoint_id: Option<String>,
    field: Option<&'static str>,
    desired: Option<String>,
    current: Option<String>,
    message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TrustPolicyPlanChange {
    code: String,
    severity: String,
    node_id: Option<String>,
    endpoint_id: Option<String>,
    field: Option<String>,
    desired: Option<String>,
    current: Option<String>,
    message: String,
}

impl From<TrustPolicyDiff> for TrustPolicyPlanChange {
    fn from(diff: TrustPolicyDiff) -> Self {
        Self {
            code: diff.code.to_string(),
            severity: diff.severity.to_string(),
            node_id: diff.node_id,
            endpoint_id: diff.endpoint_id,
            field: diff.field.map(str::to_string),
            desired: diff.desired,
            current: diff.current,
            message: diff.message,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicySignatureFile {
    schema: String,
    algorithm: String,
    key_id: String,
    policy_revision: String,
    policy_sha256: String,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyPublicKeyFile {
    schema: String,
    algorithm: String,
    key_id: String,
    public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TrustPolicyPlan {
    schema: String,
    mode: String,
    policy_revision: String,
    policy_sha256: String,
    signature_key_id: String,
    signature_public_key_sha256: String,
    change_count: usize,
    total_change_count: usize,
    truncated: bool,
    changes: Vec<TrustPolicyPlanChange>,
    drift_alert: TrustPolicyDriftAlert,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TrustPolicyDriftAlert {
    active: bool,
    reason_code: String,
    severity: String,
    total_change_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustPolicyApproval {
    schema: String,
    policy_revision: String,
    plan_sha256: String,
    approver: String,
    approved_at: String,
    key_id: String,
    public_key: String,
    signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TrustPolicyHistoryEntry {
    schema: String,
    policy_revision: String,
    policy_sha256: String,
    plan_sha256: String,
    total_change_count: usize,
    drift_active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approved_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approval_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approval_sha256: Option<String>,
    recorded_at: String,
}

#[derive(Debug, Deserialize)]
struct StoredTrustBundleProjection {
    #[serde(default)]
    trusted_controllers: Vec<String>,
    #[serde(default)]
    trusted_peers: Vec<String>,
    #[serde(default)]
    authorized_path_probes: Vec<(String, String)>,
}

fn load_and_validate_policy(
    path: &Path,
) -> anyhow::Result<(TrustPolicyDocument, TrustPolicyValidationReport)> {
    let raw = read_bounded_policy(path)?;
    let mut policy = parse_policy(path, &raw)?;
    canonicalize_policy(&mut policy)?;
    let report = validate_policy(&policy)?;
    Ok((policy, report))
}

fn read_bounded_policy(path: &Path) -> anyhow::Result<String> {
    let file = fs::File::open(path).context("failed to open trust policy file")?;
    let metadata = file
        .metadata()
        .context("failed to inspect trust policy file")?;
    if !metadata.is_file() {
        bail!("trust policy input must be a regular file");
    }
    if metadata.len() > MAX_POLICY_BYTES {
        bail!("trust policy file exceeds {MAX_POLICY_BYTES} bytes");
    }
    let mut raw = String::new();
    file.take(MAX_POLICY_BYTES + 1)
        .read_to_string(&mut raw)
        .context("failed to read trust policy file")?;
    if raw.len() as u64 > MAX_POLICY_BYTES {
        bail!("trust policy file exceeds {MAX_POLICY_BYTES} bytes");
    }
    Ok(raw)
}

fn parse_policy(path: &Path, raw: &str) -> anyhow::Result<TrustPolicyDocument> {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase);
    match extension.as_deref() {
        Some("toml") | None => {
            toml::from_str(raw).map_err(|_| anyhow::anyhow!("failed to parse TOML trust policy"))
        }
        Some("yaml") | Some("yml") => serde_yaml_ng::from_str(raw)
            .map_err(|_| anyhow::anyhow!("failed to parse YAML trust policy")),
        Some(_) => bail!("unsupported trust policy extension; use .toml, .yaml, or .yml"),
    }
}

fn canonicalize_policy(policy: &mut TrustPolicyDocument) -> anyhow::Result<()> {
    for node in &mut policy.nodes {
        node.endpoint_id = canonicalize_node_endpoint_id(&node.endpoint_id)?;
    }
    for controller in &mut policy.controllers {
        controller.endpoint_id = canonicalize_controller_endpoint_id(&controller.endpoint_id)?;
    }
    policy.nodes.sort_by(|left, right| {
        (left.node_id.as_str(), left.endpoint_id.as_str())
            .cmp(&(right.node_id.as_str(), right.endpoint_id.as_str()))
    });
    policy.controllers.sort_by(|left, right| {
        (left.endpoint_id.as_str(), left.role.as_str())
            .cmp(&(right.endpoint_id.as_str(), right.role.as_str()))
    });
    policy.peers.sort_by(|left, right| {
        (left.source_node_id.as_str(), left.peer_node_id.as_str())
            .cmp(&(right.source_node_id.as_str(), right.peer_node_id.as_str()))
    });
    policy.path_probes.sort_by(|left, right| {
        (left.source_node_id.as_str(), left.target_node_id.as_str())
            .cmp(&(right.source_node_id.as_str(), right.target_node_id.as_str()))
    });
    Ok(())
}

fn validate_policy(policy: &TrustPolicyDocument) -> anyhow::Result<TrustPolicyValidationReport> {
    if policy.version != 1 {
        bail!("trust policy version must be 1");
    }
    validate_collection_len("nodes", policy.nodes.len(), MAX_POLICY_NODES)?;
    validate_collection_len(
        "controllers",
        policy.controllers.len(),
        MAX_POLICY_CONTROLLERS,
    )?;
    validate_collection_len("peers", policy.peers.len(), MAX_POLICY_PEERS)?;
    validate_collection_len(
        "path_probes",
        policy.path_probes.len(),
        MAX_POLICY_PATH_PROBES,
    )?;
    if let Some(metadata) = &policy.metadata {
        if let Some(name) = metadata.name.as_deref() {
            validate_metadata_label("metadata.name", name)?;
        }
        if let Some(revision) = metadata.revision.as_deref() {
            validate_metadata_label("metadata.revision", revision)?;
        }
    }

    let mut node_ids = BTreeSet::new();
    let mut endpoint_ids = BTreeSet::new();
    for node in &policy.nodes {
        validate_node_id(&node.node_id)?;
        validate_region(&node.region)?;
        validate_role(&node.role)?;
        for (field, value) in [
            ("environment", node.environment.as_deref()),
            ("site", node.site.as_deref()),
            ("owner_team", node.owner_team.as_deref()),
            ("service_tier", node.service_tier.as_deref()),
        ] {
            if let Some(value) = value {
                validate_metadata_value(value, field).map_err(anyhow::Error::msg)?;
            }
        }
        if let Some(labels) = &node.labels {
            validate_label_json(&serde_json::to_value(labels)?, "node labels")
                .map_err(anyhow::Error::msg)?;
        }
        if let Some(version) = &node.expected_agent_version {
            validate_agent_version(version).map_err(anyhow::Error::msg)?;
        }
        let endpoint_id = canonicalize_node_endpoint_id(&node.endpoint_id)?;
        let lifecycle = EndpointStatus::from_str(&node.lifecycle).map_err(|_| {
            anyhow::anyhow!("node lifecycle must be active, rotated, revoked, or quarantined")
        })?;
        if lifecycle != EndpointStatus::Active && node.enabled.unwrap_or(true) {
            bail!(
                "node {} must set enabled=false when lifecycle={}",
                node.node_id,
                lifecycle.as_str()
            );
        }
        if !node_ids.insert(node.node_id.as_str()) {
            bail!("duplicate node_id in trust policy: {}", node.node_id);
        }
        if !endpoint_ids.insert(endpoint_id) {
            bail!(
                "duplicate endpoint_id in trust policy nodes: {}",
                node.endpoint_id
            );
        }
    }

    let policy_node_ids = policy
        .nodes
        .iter()
        .map(|node| node.node_id.as_str())
        .collect::<BTreeSet<_>>();
    let operational_node_ids = policy
        .nodes
        .iter()
        .filter(|node| {
            node.lifecycle == EndpointStatus::Active.as_str() && node.enabled.unwrap_or(true)
        })
        .map(|node| node.node_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut controller_endpoint_ids = BTreeSet::new();
    for controller in &policy.controllers {
        validate_controller_role(&controller.role)?;
        let endpoint_id = canonicalize_controller_endpoint_id(&controller.endpoint_id)?;
        if endpoint_ids.contains(&endpoint_id) {
            bail!("controller endpoint_id must not also be a node endpoint_id");
        }
        if !controller_endpoint_ids.insert(endpoint_id) {
            bail!(
                "duplicate controller endpoint_id in trust policy: {}",
                controller.endpoint_id
            );
        }
    }

    let mut peer_pairs = BTreeSet::new();
    for peer in &policy.peers {
        validate_node_reference(
            &policy_node_ids,
            &peer.source_node_id,
            "peer source_node_id",
        )?;
        validate_node_reference(&policy_node_ids, &peer.peer_node_id, "peer peer_node_id")?;
        if peer.source_node_id == peer.peer_node_id {
            bail!("peer entries must use distinct source_node_id and peer_node_id");
        }
        if !operational_node_ids.contains(peer.source_node_id.as_str())
            || !operational_node_ids.contains(peer.peer_node_id.as_str())
        {
            bail!("peer entries may reference only active enabled policy nodes");
        }
        if !peer_pairs.insert((peer.source_node_id.as_str(), peer.peer_node_id.as_str())) {
            bail!(
                "duplicate peer pair in trust policy: {} -> {}",
                peer.source_node_id,
                peer.peer_node_id
            );
        }
    }

    let mut path_probe_pairs = BTreeSet::new();
    for probe in &policy.path_probes {
        validate_node_reference(
            &policy_node_ids,
            &probe.source_node_id,
            "path probe source_node_id",
        )?;
        validate_node_reference(
            &policy_node_ids,
            &probe.target_node_id,
            "path probe target_node_id",
        )?;
        if probe.source_node_id == probe.target_node_id {
            bail!("path_probes require an explicit distinct source/target pair");
        }
        let pair = (probe.source_node_id.as_str(), probe.target_node_id.as_str());
        if !path_probe_pairs.insert(pair) {
            bail!(
                "duplicate path_probe pair in trust policy: {} -> {}",
                probe.source_node_id,
                probe.target_node_id
            );
        }
        if !peer_pairs.contains(&pair) {
            bail!(
                "path_probe pair {} -> {} requires a matching explicit peer entry",
                probe.source_node_id,
                probe.target_node_id
            );
        }
        if probe.enabled.unwrap_or(true) && controller_endpoint_ids.is_empty() {
            bail!("enabled path_probe entries require at least one explicit controller");
        }
    }

    let mut warnings = Vec::new();
    if policy.nodes.is_empty() {
        warnings
            .push("policy contains no nodes; diff will only report controller extras".to_string());
    }
    let disabled_path_probe_count = policy
        .path_probes
        .iter()
        .filter(|probe| probe.enabled == Some(false))
        .count();
    if disabled_path_probe_count > 0 {
        warnings.push(format!(
            "{disabled_path_probe_count} path_probe entries are disabled and are not authorization changes"
        ));
    }
    let policy_sha256 = sha256_hex(&canonical_policy_bytes(policy)?);
    let policy_revision = policy
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.revision.clone())
        .unwrap_or_else(|| format!("sha256-{policy_sha256}"));
    Ok(TrustPolicyValidationReport {
        generated_at: now_rfc3339(),
        status: "ok",
        schema_version: policy.version,
        policy_revision,
        policy_sha256,
        node_count: policy.nodes.len(),
        controller_count: policy.controllers.len(),
        peer_count: policy.peers.len(),
        path_probe_count: policy.path_probes.len(),
        warning_count: warnings.len(),
        warnings,
    })
}

fn canonical_policy_bytes(policy: &TrustPolicyDocument) -> anyhow::Result<Vec<u8>> {
    serde_json::to_vec(policy).context("failed to canonicalize trust policy")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn require_explicit_revision(policy: &TrustPolicyDocument) -> anyhow::Result<&str> {
    policy
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.revision.as_deref())
        .ok_or_else(|| anyhow::anyhow!("signed policy review requires metadata.revision"))
}

fn validate_signature_args(
    signature: Option<&Path>,
    public_key: Option<&Path>,
) -> anyhow::Result<()> {
    if signature.is_some() != public_key.is_some() {
        bail!("--signature and --public-key must be provided together");
    }
    Ok(())
}

fn policy_signature_payload(revision: &str, policy_sha256: &str) -> Vec<u8> {
    format!("{POLICY_SIGNATURE_SCHEMA}\n{revision}\n{policy_sha256}\n").into_bytes()
}

fn approval_signature_payload(
    revision: &str,
    plan_sha256: &str,
    approver: &str,
    approved_at: &str,
    key_id: &str,
) -> Vec<u8> {
    format!(
        "{POLICY_APPROVAL_SCHEMA}\n{revision}\n{plan_sha256}\n{approver}\n{approved_at}\n{key_id}\n"
    )
    .into_bytes()
}

fn verify_policy_signature(
    policy: &TrustPolicyDocument,
    report: &TrustPolicyValidationReport,
    signature_path: &Path,
    public_key_path: &Path,
) -> anyhow::Result<VerifiedPolicySignature> {
    require_explicit_revision(policy)?;
    let signature: PolicySignatureFile =
        read_artifact_json_bounded(signature_path, MAX_SIGNATURE_BYTES, "policy signature")?;
    let public_key: PolicyPublicKeyFile =
        read_artifact_json_bounded(public_key_path, MAX_SIGNATURE_BYTES, "policy public key")?;
    if signature.schema != POLICY_SIGNATURE_SCHEMA
        || public_key.schema != POLICY_PUBLIC_KEY_SCHEMA
        || signature.algorithm != "ed25519"
        || public_key.algorithm != "ed25519"
        || signature.key_id != public_key.key_id
        || signature.policy_revision != report.policy_revision
        || signature.policy_sha256 != report.policy_sha256
    {
        bail!("policy signature metadata does not match the validated policy");
    }
    validate_metadata_label("signature key_id", &signature.key_id)?;
    let public_key_bytes = BASE64
        .decode(&public_key.public_key)
        .map_err(|_| anyhow::anyhow!("policy public key is invalid"))?;
    let signature_bytes = BASE64
        .decode(&signature.signature)
        .map_err(|_| anyhow::anyhow!("policy signature is invalid"))?;
    if public_key_bytes.len() != 32 || signature_bytes.len() != 64 {
        bail!("policy signature is invalid");
    }
    UnparsedPublicKey::new(&ED25519, &public_key_bytes)
        .verify(
            &policy_signature_payload(&report.policy_revision, &report.policy_sha256),
            &signature_bytes,
        )
        .map_err(|_| anyhow::anyhow!("policy signature verification failed"))?;
    Ok(VerifiedPolicySignature {
        key_id: signature.key_id,
        public_key_sha256: sha256_hex(&public_key_bytes),
    })
}

fn read_private_bounded(
    path: &Path,
    max_bytes: u64,
    label: &'static str,
) -> anyhow::Result<Vec<u8>> {
    let file = private_file::open_existing_private_read(path)
        .with_context(|| format!("failed to open private {label}"))?;
    let len = file
        .metadata()
        .with_context(|| format!("failed to inspect {label}"))?
        .len();
    if len > max_bytes {
        bail!("{label} exceeds the bounded size limit");
    }
    let mut bytes = Vec::with_capacity(len as usize);
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {label}"))?;
    if bytes.len() as u64 > max_bytes {
        bail!("{label} exceeds the bounded size limit");
    }
    Ok(bytes)
}

fn read_artifact_json_bounded<T: for<'de> Deserialize<'de>>(
    path: &Path,
    max_bytes: u64,
    label: &'static str,
) -> anyhow::Result<T> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .with_context(|| format!("failed to open {label}"))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("failed to inspect {label}"))?;
        let current_euid = unsafe { libc::geteuid() };
        if !metadata.is_file()
            || metadata.uid() != current_euid
            || metadata.nlink() != 1
            || metadata.mode() & 0o022 != 0
        {
            bail!("{label} permissions are unsafe");
        }
        file
    };
    #[cfg(not(unix))]
    let file = fs::File::open(path).with_context(|| format!("failed to open {label}"))?;

    let len = file
        .metadata()
        .with_context(|| format!("failed to inspect {label}"))?
        .len();
    if len > max_bytes {
        bail!("{label} exceeds the bounded size limit");
    }
    let mut bytes = Vec::with_capacity(len as usize);
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {label}"))?;
    if bytes.len() as u64 > max_bytes {
        bail!("{label} exceeds the bounded size limit");
    }
    serde_json::from_slice(&bytes).with_context(|| format!("{label} is invalid"))
}

fn write_private_json<T: Serialize>(
    path: &Path,
    value: &T,
    label: &'static str,
) -> anyhow::Result<()> {
    let text = serde_json::to_string_pretty(value)? + "\n";
    write_private_text(path, &text, label)
}

fn write_private_text(path: &Path, text: &str, label: &'static str) -> anyhow::Result<()> {
    let mut file = private_file::open_private_create_new_strict(path)
        .with_context(|| format!("failed to create private {label}"))?;
    file.write_all(text.as_bytes())
        .with_context(|| format!("failed to write {label}"))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {label}"))?;
    Ok(())
}

fn validate_plan(plan: &TrustPolicyPlan) -> anyhow::Result<()> {
    if plan.schema != POLICY_PLAN_SCHEMA || plan.mode != "review-only" {
        bail!("policy plan schema is invalid");
    }
    validate_metadata_label("policy_revision", &plan.policy_revision)?;
    if !is_sha256_hex(&plan.policy_sha256)
        || !is_sha256_hex(&plan.signature_public_key_sha256)
        || plan.changes.len() > MAX_DIFF_ITEMS
        || plan.change_count != plan.changes.len()
        || plan.change_count > plan.total_change_count
        || plan.truncated != (plan.total_change_count > plan.change_count)
        || plan.drift_alert.total_change_count != plan.total_change_count
        || plan.drift_alert.active != (plan.total_change_count > 0)
        || plan.drift_alert.reason_code != "TRUST_POLICY_DRIFT"
        || !matches!(
            plan.drift_alert.severity.as_str(),
            "none" | "warning" | "critical"
        )
    {
        bail!("policy plan is invalid");
    }
    validate_metadata_label("signature_key_id", &plan.signature_key_id)?;
    Ok(())
}

fn validate_approval(approval: &TrustPolicyApproval, plan: &TrustPolicyPlan) -> anyhow::Result<()> {
    let expected_plan_sha256 = sha256_hex(&serde_json::to_vec(plan)?);
    if approval.schema != POLICY_APPROVAL_SCHEMA
        || approval.policy_revision != plan.policy_revision
        || approval.plan_sha256 != expected_plan_sha256
    {
        bail!("policy approval does not match the review plan");
    }
    validate_metadata_label("approval key_id", &approval.key_id)?;
    validate_actor(&approval.approver).map_err(anyhow::Error::msg)?;
    OffsetDateTime::parse(&approval.approved_at, &Rfc3339)
        .context("policy approval timestamp is invalid")?;
    let public_key = BASE64
        .decode(&approval.public_key)
        .map_err(|_| anyhow::anyhow!("policy approval public key is invalid"))?;
    let signature = BASE64
        .decode(&approval.signature)
        .map_err(|_| anyhow::anyhow!("policy approval signature is invalid"))?;
    if public_key.len() != 32 || signature.len() != 64 {
        bail!("policy approval signature is invalid");
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(
            &approval_signature_payload(
                &approval.policy_revision,
                &approval.plan_sha256,
                &approval.approver,
                &approval.approved_at,
                &approval.key_id,
            ),
            &signature,
        )
        .map_err(|_| anyhow::anyhow!("policy approval signature verification failed"))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn read_history_entries(
    path: &Path,
    allow_missing: bool,
) -> anyhow::Result<Vec<TrustPolicyHistoryEntry>> {
    if !path.exists() && allow_missing {
        return Ok(Vec::new());
    }
    let bytes = read_private_bounded(path, MAX_HISTORY_BYTES, "policy history")?;
    let text = std::str::from_utf8(&bytes).context("policy history is not UTF-8")?;
    let mut entries = Vec::new();
    let mut revisions = BTreeSet::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if entries.len() >= MAX_HISTORY_ENTRIES {
            bail!("policy history exceeds the bounded limit of {MAX_HISTORY_ENTRIES} entries");
        }
        let entry: TrustPolicyHistoryEntry =
            serde_json::from_str(line).context("policy history entry is invalid")?;
        if entry.schema != POLICY_HISTORY_SCHEMA
            || !is_sha256_hex(&entry.policy_sha256)
            || !is_sha256_hex(&entry.plan_sha256)
            || entry.approved_by.is_some() != entry.approval_key_id.is_some()
            || entry.approved_by.is_some() != entry.approval_sha256.is_some()
            || entry
                .approval_sha256
                .as_deref()
                .is_some_and(|hash| !is_sha256_hex(hash))
            || !revisions.insert(entry.policy_revision.clone())
        {
            bail!("policy history entry is invalid");
        }
        validate_metadata_label("history policy_revision", &entry.policy_revision)?;
        if let Some(approver) = &entry.approved_by {
            validate_actor(approver).map_err(anyhow::Error::msg)?;
        }
        if let Some(key_id) = &entry.approval_key_id {
            validate_metadata_label("history approval_key_id", key_id)?;
        }
        OffsetDateTime::parse(&entry.recorded_at, &Rfc3339)
            .context("policy history timestamp is invalid")?;
        entries.push(entry);
    }
    Ok(entries)
}

fn validate_collection_len(field: &'static str, len: usize, max: usize) -> anyhow::Result<()> {
    if len > max {
        bail!("trust policy {field} exceeds the bounded limit of {max}");
    }
    Ok(())
}

fn validate_metadata_label(field: &'static str, value: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("{field} must be 1-64 characters from [a-zA-Z0-9._-]");
    }
    Ok(())
}

fn validate_node_reference(
    node_ids: &BTreeSet<&str>,
    node_id: &str,
    field: &'static str,
) -> anyhow::Result<()> {
    validate_node_id(node_id)?;
    if !node_ids.contains(node_id) {
        bail!("{field} references unknown policy node_id: {node_id}");
    }
    Ok(())
}

fn compute_policy_diff(
    store: &Store,
    policy: TrustPolicyDocument,
    report: TrustPolicyValidationReport,
) -> anyhow::Result<TrustPolicyDiffReport> {
    let nodes = store.list_nodes()?;
    let endpoints = store
        .trust_snapshot(None)
        .map_err(|_| anyhow::anyhow!("controller trust bundle projection is invalid"))?
        .endpoints;
    let node_map = nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let endpoint_map = endpoints
        .iter()
        .map(|endpoint| (endpoint.endpoint_id.as_str(), endpoint))
        .collect::<BTreeMap<_, _>>();
    let policy_node_map = policy
        .nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let policy_endpoint_ids = policy
        .nodes
        .iter()
        .map(|node| canonicalize_node_endpoint_id(&node.endpoint_id))
        .collect::<Result<BTreeSet<_>, _>>()?;

    let mut diffs = Vec::new();
    for policy_node in &policy.nodes {
        match node_map.get(policy_node.node_id.as_str()) {
            Some(current) => {
                compare_node(policy_node, current, &mut diffs)?;
                compare_node_metadata(
                    policy_node,
                    store.get_node_metadata(&policy_node.node_id)?.as_ref(),
                    &mut diffs,
                )?;
            }
            None => diffs.push(TrustPolicyDiff {
                code: "NODE_MISSING_FROM_CONTROLLER",
                severity: "medium",
                node_id: Some(policy_node.node_id.clone()),
                endpoint_id: Some(policy_node.endpoint_id.clone()),
                field: None,
                desired: Some("present".to_string()),
                current: Some("absent".to_string()),
                message: "policy node is not present in the controller registry".to_string(),
            }),
        }
        match endpoint_map.get(policy_node.endpoint_id.as_str()) {
            Some(endpoint) => compare_endpoint(policy_node, endpoint, &mut diffs)?,
            None => diffs.push(TrustPolicyDiff {
                code: "ENDPOINT_MISSING_FROM_CONTROLLER",
                severity: "medium",
                node_id: Some(policy_node.node_id.clone()),
                endpoint_id: Some(policy_node.endpoint_id.clone()),
                field: Some("lifecycle"),
                desired: Some(policy_node.lifecycle.clone()),
                current: Some("absent".to_string()),
                message: "policy endpoint is not present in endpoint trust state".to_string(),
            }),
        }
    }
    for current in &nodes {
        if !policy_node_map.contains_key(current.node_id.as_str()) {
            diffs.push(TrustPolicyDiff {
                code: "NODE_EXTRA_IN_CONTROLLER",
                severity: "low",
                node_id: Some(current.node_id.clone()),
                endpoint_id: Some(current.endpoint_id.clone()),
                field: None,
                desired: Some("absent".to_string()),
                current: Some("present".to_string()),
                message: "controller registry contains a node not declared in policy".to_string(),
            });
        }
    }
    for endpoint in &endpoints {
        if !policy_endpoint_ids.contains(&endpoint.endpoint_id) {
            diffs.push(TrustPolicyDiff {
                code: "ENDPOINT_EXTRA_IN_CONTROLLER",
                severity: "low",
                node_id: endpoint.node_id.clone(),
                endpoint_id: Some(endpoint.endpoint_id.clone()),
                field: None,
                desired: Some("absent".to_string()),
                current: Some(endpoint.status.as_str().to_string()),
                message: "controller trust state contains an endpoint not declared in policy"
                    .to_string(),
            });
        }
    }
    compare_trust_bundle_allowlists(&policy, &endpoint_map, &mut diffs)?;

    diffs.sort_by(|left, right| {
        (
            left.code,
            left.node_id.as_deref(),
            left.endpoint_id.as_deref(),
            left.field,
            left.desired.as_deref(),
            left.current.as_deref(),
        )
            .cmp(&(
                right.code,
                right.node_id.as_deref(),
                right.endpoint_id.as_deref(),
                right.field,
                right.desired.as_deref(),
                right.current.as_deref(),
            ))
    });
    let total_diff_count = diffs.len();
    let truncated = total_diff_count > MAX_DIFF_ITEMS;
    diffs.truncate(MAX_DIFF_ITEMS);
    Ok(TrustPolicyDiffReport {
        generated_at: now_rfc3339(),
        status: "ok",
        validated: report,
        diff_count: diffs.len(),
        total_diff_count,
        truncated,
        diffs,
    })
}

fn compare_trust_bundle_allowlists(
    policy: &TrustPolicyDocument,
    endpoint_map: &BTreeMap<&str, &EndpointTrustRecord>,
    diffs: &mut Vec<TrustPolicyDiff>,
) -> anyhow::Result<()> {
    let policy_nodes = policy
        .nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let desired_controllers = policy
        .controllers
        .iter()
        .map(|controller| controller.endpoint_id.clone())
        .collect::<BTreeSet<_>>();

    for node in &policy.nodes {
        let Some(endpoint) = endpoint_map.get(node.endpoint_id.as_str()) else {
            continue;
        };
        let stored: StoredTrustBundleProjection =
            serde_json::from_value(endpoint.trust_bundle_json.clone())
                .map_err(|_| anyhow::anyhow!("controller trust bundle projection is invalid"))?;
        let actual_controllers = canonicalize_stored_controller_ids(&stored.trusted_controllers)?;
        let actual_peers = canonicalize_stored_peer_ids(&stored.trusted_peers)?;
        let actual_path_probes = canonicalize_stored_path_probes(&stored.authorized_path_probes)?;
        let operational =
            node.lifecycle == EndpointStatus::Active.as_str() && node.enabled.unwrap_or(true);

        let expected_controllers = if operational {
            desired_controllers.clone()
        } else {
            BTreeSet::new()
        };
        add_set_diffs(
            diffs,
            node,
            "trusted_controllers",
            "CONTROLLER_ALLOWLIST_MISSING",
            "CONTROLLER_ALLOWLIST_UNEXPECTED",
            "controller allowlist differs from review policy",
            &expected_controllers,
            &actual_controllers,
        );

        let expected_peers = if operational {
            policy
                .peers
                .iter()
                .filter(|peer| peer.source_node_id == node.node_id)
                .filter_map(|peer| policy_nodes.get(peer.peer_node_id.as_str()))
                .map(|peer| peer.endpoint_id.clone())
                .collect::<BTreeSet<_>>()
        } else {
            BTreeSet::new()
        };
        add_set_diffs(
            diffs,
            node,
            "trusted_peers",
            "PEER_ALLOWLIST_MISSING",
            "PEER_ALLOWLIST_UNEXPECTED",
            "peer allowlist differs from review policy",
            &expected_peers,
            &actual_peers,
        );

        let expected_path_probes = if operational {
            policy
                .path_probes
                .iter()
                .filter(|probe| {
                    probe.source_node_id == node.node_id && probe.enabled.unwrap_or(true)
                })
                .filter_map(|probe| policy_nodes.get(probe.target_node_id.as_str()))
                .flat_map(|target| {
                    desired_controllers
                        .iter()
                        .map(move |controller| format!("{controller}->{}", target.endpoint_id))
                })
                .collect::<BTreeSet<_>>()
        } else {
            BTreeSet::new()
        };
        add_set_diffs(
            diffs,
            node,
            "authorized_path_probes",
            "PATH_PROBE_MISSING",
            "PATH_PROBE_UNEXPECTED",
            "path-probe allowlist differs from explicit review policy",
            &expected_path_probes,
            &actual_path_probes,
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn add_set_diffs(
    diffs: &mut Vec<TrustPolicyDiff>,
    node: &PolicyNode,
    field: &'static str,
    missing_code: &'static str,
    unexpected_code: &'static str,
    message: &'static str,
    desired: &BTreeSet<String>,
    current: &BTreeSet<String>,
) {
    for value in desired.difference(current) {
        diffs.push(TrustPolicyDiff {
            code: missing_code,
            severity: "high",
            node_id: Some(node.node_id.clone()),
            endpoint_id: Some(node.endpoint_id.clone()),
            field: Some(field),
            desired: Some(value.clone()),
            current: Some("absent".to_string()),
            message: message.to_string(),
        });
    }
    for value in current.difference(desired) {
        diffs.push(TrustPolicyDiff {
            code: unexpected_code,
            severity: "high",
            node_id: Some(node.node_id.clone()),
            endpoint_id: Some(node.endpoint_id.clone()),
            field: Some(field),
            desired: Some("absent".to_string()),
            current: Some(value.clone()),
            message: message.to_string(),
        });
    }
}

fn canonicalize_stored_controller_ids(values: &[String]) -> anyhow::Result<BTreeSet<String>> {
    canonicalize_stored_ids(values, "trusted controller", |value| {
        canonicalize_controller_endpoint_id(value)
    })
}

fn canonicalize_stored_peer_ids(values: &[String]) -> anyhow::Result<BTreeSet<String>> {
    canonicalize_stored_ids(values, "trusted peer", |value| {
        canonicalize_peer_endpoint_id(value)
    })
}

fn canonicalize_stored_ids<F, E>(
    values: &[String],
    field: &'static str,
    canonicalize: F,
) -> anyhow::Result<BTreeSet<String>>
where
    F: Fn(&str) -> Result<String, E>,
    E: std::error::Error + Send + Sync + 'static,
{
    let mut canonical = BTreeSet::new();
    for value in values {
        let value = canonicalize(value)
            .map_err(anyhow::Error::new)
            .with_context(|| format!("stored {field} EndpointID is invalid"))?;
        if !canonical.insert(value) {
            bail!("stored {field} allowlist contains a duplicate EndpointID");
        }
    }
    Ok(canonical)
}

fn canonicalize_stored_path_probes(
    values: &[(String, String)],
) -> anyhow::Result<BTreeSet<String>> {
    let mut canonical = BTreeSet::new();
    for (controller, target) in values {
        let controller = canonicalize_controller_endpoint_id(controller)
            .context("stored path-probe controller EndpointID is invalid")?;
        let target = canonicalize_path_probe_endpoint_id(target)
            .context("stored path-probe target EndpointID is invalid")?;
        if !canonical.insert(format!("{controller}->{target}")) {
            bail!("stored path-probe allowlist contains a duplicate pair");
        }
    }
    Ok(canonical)
}

fn compare_node(
    policy: &PolicyNode,
    current: &NodeRecord,
    diffs: &mut Vec<TrustPolicyDiff>,
) -> anyhow::Result<()> {
    compare_field(
        diffs,
        "NODE_ENDPOINT_MISMATCH",
        &policy.node_id,
        Some(&policy.endpoint_id),
        "endpoint_id",
        &policy.endpoint_id,
        &current.endpoint_id,
    );
    compare_field(
        diffs,
        "NODE_REGION_MISMATCH",
        &policy.node_id,
        Some(&policy.endpoint_id),
        "region",
        &policy.region,
        &current.region,
    );
    compare_field(
        diffs,
        "NODE_ROLE_MISMATCH",
        &policy.node_id,
        Some(&policy.endpoint_id),
        "role",
        &policy.role,
        &current.role,
    );
    if let Some(enabled) = policy.enabled {
        compare_field(
            diffs,
            "NODE_ENABLED_MISMATCH",
            &policy.node_id,
            Some(&policy.endpoint_id),
            "enabled",
            &enabled.to_string(),
            &current.enabled.to_string(),
        );
    }
    Ok(())
}

fn compare_node_metadata(
    policy: &PolicyNode,
    current: Option<&crate::store::NodeMetadataRecord>,
    diffs: &mut Vec<TrustPolicyDiff>,
) -> anyhow::Result<()> {
    let current_value = |field: &str| -> Option<String> {
        current.map(|metadata| match field {
            "environment" => metadata.environment.clone(),
            "site" => metadata.site.clone(),
            "owner_team" => metadata.owner_team.clone(),
            "service_tier" => metadata.service_tier.clone(),
            "expected_agent_version" => metadata
                .expected_agent_version
                .clone()
                .unwrap_or_else(|| "<unset>".to_string()),
            _ => "<unset>".to_string(),
        })
    };
    for (field, desired) in [
        ("environment", policy.environment.as_ref()),
        ("site", policy.site.as_ref()),
        ("owner_team", policy.owner_team.as_ref()),
        ("service_tier", policy.service_tier.as_ref()),
        (
            "expected_agent_version",
            policy.expected_agent_version.as_ref(),
        ),
    ] {
        if let Some(desired) = desired {
            compare_metadata_field(
                diffs,
                "NODE_METADATA_MISMATCH",
                &policy.node_id,
                Some(&policy.endpoint_id),
                field,
                desired,
                &current_value(field).unwrap_or_else(|| "<unset>".to_string()),
            );
        }
    }
    if let Some(labels) = &policy.labels {
        let desired = serde_json::to_string(labels)?;
        let current = current
            .map(|metadata| serde_json::to_string(&metadata.labels_json))
            .transpose()?
            .unwrap_or_else(|| "<unset>".to_string());
        compare_metadata_field(
            diffs,
            "NODE_METADATA_MISMATCH",
            &policy.node_id,
            Some(&policy.endpoint_id),
            "labels",
            &desired,
            &current,
        );
    }
    Ok(())
}

fn compare_metadata_field(
    diffs: &mut Vec<TrustPolicyDiff>,
    code: &'static str,
    node_id: &str,
    endpoint_id: Option<&str>,
    field: &'static str,
    desired: &str,
    current: &str,
) {
    let before = diffs.len();
    compare_field(diffs, code, node_id, endpoint_id, field, desired, current);
    if diffs.len() > before {
        let diff = diffs.last_mut().expect("new metadata diff exists");
        diff.severity = "low";
        diff.message = format!("controller advisory {field} differs from policy");
    }
}

fn compare_endpoint(
    policy: &PolicyNode,
    current: &EndpointTrustRecord,
    diffs: &mut Vec<TrustPolicyDiff>,
) -> anyhow::Result<()> {
    let desired = EndpointStatus::from_str(&policy.lifecycle).map_err(anyhow::Error::msg)?;
    if current.status != desired {
        diffs.push(TrustPolicyDiff {
            code: "ENDPOINT_LIFECYCLE_MISMATCH",
            severity: "high",
            node_id: Some(policy.node_id.clone()),
            endpoint_id: Some(current.endpoint_id.clone()),
            field: Some("lifecycle"),
            desired: Some(desired.as_str().to_string()),
            current: Some(current.status.as_str().to_string()),
            message: "controller endpoint lifecycle differs from policy".to_string(),
        });
    }
    Ok(())
}

fn compare_field(
    diffs: &mut Vec<TrustPolicyDiff>,
    code: &'static str,
    node_id: &str,
    endpoint_id: Option<&str>,
    field: &'static str,
    desired: &str,
    current: &str,
) {
    if desired == current {
        return;
    }
    diffs.push(TrustPolicyDiff {
        code,
        severity: "medium",
        node_id: Some(node_id.to_string()),
        endpoint_id: endpoint_id.map(ToOwned::to_owned),
        field: Some(field),
        desired: Some(desired.to_string()),
        current: Some(current.to_string()),
        message: format!("controller {field} differs from policy"),
    });
}

fn print_validation_human(path: &Path, report: &TrustPolicyValidationReport) {
    println!("trust_policy={}", policy_source_label(path));
    println!("status={}", report.status);
    println!("schema_version={}", report.schema_version);
    println!("policy_revision={}", report.policy_revision);
    println!("policy_sha256={}", report.policy_sha256);
    println!("node_count={}", report.node_count);
    println!("controller_count={}", report.controller_count);
    println!("peer_count={}", report.peer_count);
    println!("path_probe_count={}", report.path_probe_count);
    println!("warning_count={}", report.warning_count);
    for warning in &report.warnings {
        println!("warning={warning}");
    }
}

fn print_diff_human(path: &Path, report: &TrustPolicyDiffReport) {
    println!("trust_policy={}", policy_source_label(path));
    println!("status={}", report.status);
    println!("diff_count={}", report.diff_count);
    println!("total_diff_count={}", report.total_diff_count);
    println!("truncated={}", report.truncated);
    for diff in &report.diffs {
        println!(
            "diff code={} severity={} node_id={} endpoint_id={} field={} desired={} current={} message={}",
            diff.code,
            diff.severity,
            diff.node_id.as_deref().unwrap_or("<none>"),
            diff.endpoint_id.as_deref().unwrap_or("<none>"),
            diff.field.unwrap_or("<none>"),
            diff.desired.as_deref().unwrap_or("<none>"),
            diff.current.as_deref().unwrap_or("<none>"),
            diff.message
        );
    }
}

fn format_diff_markdown(path: &Path, report: &TrustPolicyDiffReport) -> String {
    let mut output = String::new();
    output.push_str("# Trust Policy Diff\n\n");
    output.push_str(&format!(
        "- policy: `{}`\n",
        escape_markdown(&policy_source_label(path))
    ));
    output.push_str("- mode: `review-only`\n");
    output.push_str(&format!("- generated_at: `{}`\n", report.generated_at));
    output.push_str(&format!("- status: `{}`\n", report.status));
    output.push_str(&format!("- diff_count: `{}`\n", report.diff_count));
    output.push_str(&format!(
        "- total_diff_count: `{}`\n",
        report.total_diff_count
    ));
    output.push_str(&format!("- truncated: `{}`\n\n", report.truncated));
    output.push_str("| Severity | Code | Node | Endpoint | Field | Desired | Current |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
    if report.diffs.is_empty() {
        output.push_str("| info | NO_DIFF | none | none | none | none | none |\n");
        return output;
    }
    for diff in &report.diffs {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            escape_markdown(diff.severity),
            escape_markdown(diff.code),
            escape_markdown(diff.node_id.as_deref().unwrap_or("none")),
            escape_markdown(diff.endpoint_id.as_deref().unwrap_or("none")),
            escape_markdown(diff.field.unwrap_or("none")),
            escape_markdown(diff.desired.as_deref().unwrap_or("none")),
            escape_markdown(diff.current.as_deref().unwrap_or("none")),
        ));
    }
    output
}

fn format_plan_markdown(path: &Path, plan: &TrustPolicyPlan) -> String {
    let mut output = String::new();
    output.push_str("# Trust Policy Review Plan\n\n");
    output.push_str(&format!(
        "- policy: `{}`\n",
        escape_markdown(&policy_source_label(path))
    ));
    output.push_str("- mode: `review-only`\n");
    output.push_str(&format!(
        "- policy_revision: `{}`\n",
        escape_markdown(&plan.policy_revision)
    ));
    output.push_str(&format!("- policy_sha256: `{}`\n", plan.policy_sha256));
    output.push_str(&format!(
        "- signature_key_id: `{}`\n",
        escape_markdown(&plan.signature_key_id)
    ));
    output.push_str(&format!("- change_count: `{}`\n", plan.change_count));
    output.push_str(&format!(
        "- total_change_count: `{}`\n",
        plan.total_change_count
    ));
    output.push_str(&format!("- truncated: `{}`\n", plan.truncated));
    output.push_str(&format!(
        "- drift_alert: `{}` (`{}`)\n\n",
        plan.drift_alert.active, plan.drift_alert.severity
    ));
    output.push_str("| Severity | Code | Node | Endpoint | Field | Desired | Current |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
    if plan.changes.is_empty() {
        output.push_str("| info | NO_DIFF | none | none | none | none | none |\n");
        return output;
    }
    for change in &plan.changes {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            escape_markdown(&change.severity),
            escape_markdown(&change.code),
            escape_markdown(change.node_id.as_deref().unwrap_or("none")),
            escape_markdown(change.endpoint_id.as_deref().unwrap_or("none")),
            escape_markdown(change.field.as_deref().unwrap_or("none")),
            escape_markdown(change.desired.as_deref().unwrap_or("none")),
            escape_markdown(change.current.as_deref().unwrap_or("none")),
        ));
    }
    output
}

fn policy_source_label(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .chars()
        .take(128)
        .map(|character| {
            if character.is_ascii_graphic() && character != '=' {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn escape_markdown(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars().take(256) {
        match ch {
            '|' => escaped.push_str("\\|"),
            '\n' | '\r' => escaped.push(' '),
            '`' => escaped.push('\''),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("RFC3339 formatting succeeds")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn metadata_policy_diff_is_advisory_and_field_bounded() {
        let policy = PolicyNode {
            node_id: "node-a".to_string(),
            endpoint_id: "endpoint-a".to_string(),
            region: "us-east".to_string(),
            role: "ocserv".to_string(),
            lifecycle: "active".to_string(),
            enabled: Some(true),
            environment: Some("prod".to_string()),
            site: Some("iad-1".to_string()),
            owner_team: Some("network".to_string()),
            service_tier: Some("tier-1".to_string()),
            labels: Some(BTreeMap::from([("color".to_string(), "blue".to_string())])),
            expected_agent_version: Some("0.4.0".to_string()),
        };
        let current = crate::store::NodeMetadataRecord {
            node_id: "node-a".to_string(),
            environment: "staging".to_string(),
            site: "iad-1".to_string(),
            owner_team: "network".to_string(),
            service_tier: "tier-1".to_string(),
            labels_json: json!({"color":"green"}),
            expected_agent_version: Some("0.3.0".to_string()),
            updated_at: "2026-07-12T00:00:00Z".to_string(),
        };
        let mut diffs = Vec::new();
        compare_node_metadata(&policy, Some(&current), &mut diffs).expect("diff");
        assert_eq!(diffs.len(), 3);
        assert!(diffs.iter().all(|diff| diff.severity == "low"));
        assert!(
            diffs
                .iter()
                .all(|diff| diff.code == "NODE_METADATA_MISMATCH")
        );
    }
}
