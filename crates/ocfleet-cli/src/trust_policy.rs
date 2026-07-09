use anyhow::{Context, bail};
use ocfleet_config::validation::{
    canonicalize_controller_endpoint_id, canonicalize_node_endpoint_id, validate_controller_role,
    validate_node_id, validate_region, validate_role,
};
use ocfleet_protocol::enrollment::EndpointStatus;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::str::FromStr;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::args::TrustPolicyCommand;
use crate::store::{EndpointTrustRecord, NodeRecord, Store};

pub fn run_trust_policy_command(store: &Store, command: TrustPolicyCommand) -> anyhow::Result<()> {
    match command {
        TrustPolicyCommand::Validate { file, json } => {
            let (_, report) = load_and_validate_policy(&file)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_validation_human(&file, &report);
            }
            Ok(())
        }
        TrustPolicyCommand::Diff { file, json } => {
            let (policy, report) = load_and_validate_policy(&file)?;
            let diff = compute_policy_diff(store, policy, report)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&diff)?);
            } else {
                print_diff_human(&file, &diff);
            }
            Ok(())
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustPolicyDocument {
    version: u32,
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

fn load_and_validate_policy(
    path: &Path,
) -> anyhow::Result<(TrustPolicyDocument, TrustPolicyValidationReport)> {
    let raw = fs::read_to_string(path).with_context(|| "failed to read trust policy file")?;
    let policy = parse_policy(path, &raw)?;
    let report = validate_policy(&policy)?;
    Ok((policy, report))
}

fn parse_policy(path: &Path, raw: &str) -> anyhow::Result<TrustPolicyDocument> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("toml") | None => toml::from_str(raw).context("failed to parse TOML trust policy"),
        Some("yaml") | Some("yml") => bail!(
            "YAML trust policy schema is documented, but this build implements TOML parsing only"
        ),
        Some(other) => bail!("unsupported trust policy extension: {other}; use .toml"),
    }
}

fn validate_policy(policy: &TrustPolicyDocument) -> anyhow::Result<TrustPolicyValidationReport> {
    if policy.version != 1 {
        bail!("trust policy version must be 1");
    }
    let mut node_ids = BTreeSet::new();
    let mut endpoint_ids = BTreeSet::new();
    for node in &policy.nodes {
        validate_node_id(&node.node_id)?;
        validate_region(&node.region)?;
        validate_role(&node.role)?;
        let endpoint_id = canonicalize_node_endpoint_id(&node.endpoint_id)?;
        let lifecycle = EndpointStatus::from_str(&node.lifecycle)
            .map_err(|err| anyhow::anyhow!("node {} lifecycle {err}", node.node_id))?;
        if lifecycle == EndpointStatus::Rotated && node.enabled.unwrap_or(true) {
            bail!(
                "node {} must not be enabled with lifecycle=rotated",
                node.node_id
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
    for controller in &policy.controllers {
        validate_controller_role(&controller.role)?;
        canonicalize_controller_endpoint_id(&controller.endpoint_id)?;
    }
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
    }
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
    let endpoints = store.trust_snapshot(None)?.endpoints;
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

    Ok(TrustPolicyDiffReport {
        generated_at: now_rfc3339(),
        status: "ok",
        validated: report,
        diff_count: diffs.len(),
        diffs,
    })
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
    println!("trust_policy={}", path.display());
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
    println!("trust_policy={}", path.display());
    println!("status={}", report.status);
    println!("diff_count={}", report.diff_count);
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

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("RFC3339 formatting succeeds")
}
