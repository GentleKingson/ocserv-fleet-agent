use anyhow::{Context, bail};
use ocfleet_config::validation::{
    canonicalize_controller_endpoint_id, canonicalize_node_endpoint_id,
    canonicalize_path_probe_endpoint_id, canonicalize_peer_endpoint_id, validate_controller_role,
    validate_node_id, validate_region, validate_role,
};
use ocfleet_protocol::enrollment::EndpointStatus;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::str::FromStr;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::args::TrustPolicyDiffFormat;
use crate::private_file;
use crate::store::{EndpointTrustRecord, NodeRecord, Store};

const MAX_POLICY_BYTES: u64 = 256 * 1024;
const MAX_POLICY_NODES: usize = 2_048;
const MAX_POLICY_CONTROLLERS: usize = 128;
const MAX_POLICY_PEERS: usize = 4_096;
const MAX_POLICY_PATH_PROBES: usize = 4_096;
const MAX_DIFF_ITEMS: usize = 512;

pub fn run_trust_policy_validate(file: &Path, json: bool) -> anyhow::Result<()> {
    let (_, report) = load_and_validate_policy(file)?;
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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyMetadata {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    revision: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyNode {
    node_id: String,
    endpoint_id: String,
    region: String,
    role: String,
    lifecycle: String,
    #[serde(default)]
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyController {
    endpoint_id: String,
    role: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyPeer {
    source_node_id: String,
    peer_node_id: String,
}

#[derive(Debug, Deserialize)]
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
    Ok(TrustPolicyValidationReport {
        generated_at: now_rfc3339(),
        status: "ok",
        schema_version: policy.version,
        node_count: policy.nodes.len(),
        controller_count: policy.controllers.len(),
        peer_count: policy.peers.len(),
        path_probe_count: policy.path_probes.len(),
        warning_count: warnings.len(),
        warnings,
    })
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
            Some(current) => compare_node(policy_node, current, &mut diffs)?,
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
