use std::path::Path;

use anyhow::Context;
use serde::Serialize;
use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::args::ChangeCommand;
use crate::controlled_writes::{
    ApprovalDecision, ChangeAuditRecord, ChangeRequestRecord, ControlledWritePolicy,
    TrustedIntentKeyring, UnsignedChangeIntent, read_private_signature,
};
use crate::store::Store;

pub fn run_change_command(
    store: &Store,
    actor: &str,
    command: ChangeCommand,
) -> anyhow::Result<()> {
    match command {
        ChangeCommand::Digest { intent, json } => {
            let intent = UnsignedChangeIntent::from_private_file(&intent)?;
            let digest = intent.digest(actor, &now_rfc3339()?)?;
            if json {
                print_json(&json!({
                    "schema": "ocfleet.controlled-write-digest.v1",
                    "request_id": intent.request_id,
                    "payload_sha256": digest,
                }))?;
            } else {
                println!("payload_sha256={digest}");
            }
        }
        ChangeCommand::Create {
            intent,
            trusted_keyring,
            key_id,
            signature_file,
            json,
        } => {
            let intent = UnsignedChangeIntent::from_private_file(&intent)?;
            let signature = read_private_signature(&signature_file)?;
            let keyring = TrustedIntentKeyring::from_private_file(&trusted_keyring)?;
            let request = intent.build_request(actor, &key_id, signature)?;
            let record = store.create_change_request(&request, &keyring, &now_rfc3339()?)?;
            print_record(&record, json)?;
        }
        ChangeCommand::List { limit, json } => {
            let records = store.list_change_requests(limit)?;
            if json {
                print_json(&json!({
                    "schema": "ocfleet.change-request-list.v1",
                    "count": records.len(),
                    "requests": records,
                }))?;
            } else {
                for record in records {
                    print_record_human(&record);
                }
            }
        }
        ChangeCommand::Show { request_id, json } => {
            let record = store
                .get_change_request(&request_id)?
                .context("change request not found")?;
            print_record(&record, json)?;
        }
        ChangeCommand::DryRun {
            request_id,
            policy_file,
            json,
        } => {
            let current = store
                .get_change_request(&request_id)?
                .context("change request not found")?;
            let policy = load_policy(policy_file.as_deref())?;
            let record = store.record_change_dry_run(
                &request_id,
                actor,
                true,
                policy.allows(&current.operation_kind),
                &now_rfc3339()?,
            )?;
            print_record(&record, json)?;
        }
        ChangeCommand::Approve {
            request_id,
            approval_id,
            role,
            reason,
            expires_at,
            json,
        } => {
            let record = store.approve_change(
                &request_id,
                &ApprovalDecision {
                    approval_id,
                    approver: actor.to_string(),
                    role: role.as_str().into(),
                    reason,
                    expires_at,
                },
                &now_rfc3339()?,
            )?;
            print_record(&record, json)?;
        }
        ChangeCommand::Reject {
            request_id,
            approval_id,
            role,
            reason,
            expires_at,
            json,
        } => {
            let record = store.reject_change(
                &request_id,
                &ApprovalDecision {
                    approval_id,
                    approver: actor.to_string(),
                    role: role.as_str().into(),
                    reason,
                    expires_at,
                },
                &now_rfc3339()?,
            )?;
            print_record(&record, json)?;
        }
        ChangeCommand::Cancel { request_id, json } => {
            let record = store.cancel_change(&request_id, actor, &now_rfc3339()?)?;
            print_record(&record, json)?;
        }
        ChangeCommand::Audit {
            request_id,
            limit,
            json,
        } => {
            let records = store.list_change_audit(&request_id, limit)?;
            print_audit(&request_id, &records, json)?;
        }
    }
    Ok(())
}

fn load_policy(path: Option<&Path>) -> anyhow::Result<ControlledWritePolicy> {
    path.map(ControlledWritePolicy::from_private_file)
        .transpose()
        .map(|policy| policy.unwrap_or_default())
        .map_err(anyhow::Error::from)
}

fn print_record(record: &ChangeRequestRecord, json: bool) -> anyhow::Result<()> {
    if json {
        print_json(&json!({
            "schema": "ocfleet.change-request.v1",
            "request": record,
            "dispatch_available": false,
        }))?;
    } else {
        print_record_human(record);
        println!("dispatch_available=false");
    }
    Ok(())
}

fn print_record_human(record: &ChangeRequestRecord) {
    println!(
        "request_id={} operation_id={} operation_kind={} endpoint_id={} actor={} state={} expires_at={}",
        record.request_id,
        record.operation_id,
        record.operation_kind,
        record.endpoint_id,
        record.actor,
        record.state.as_str(),
        record.expires_at,
    );
}

fn print_audit(request_id: &str, records: &[ChangeAuditRecord], json: bool) -> anyhow::Result<()> {
    if json {
        print_json(&json!({
            "schema": "ocfleet.change-audit.v1",
            "request_id": request_id,
            "count": records.len(),
            "events": records,
        }))?;
    } else {
        for record in records {
            let ok = record
                .ok
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unset".into());
            println!(
                "id={} ts={} operation_kind={} actor={} from={} to={} ok={} error_code={}",
                record.id,
                record.timestamp,
                record.operation_kind,
                record.actor,
                record.state_from.as_deref().unwrap_or("none"),
                record.state_to,
                ok,
                record.error_code.as_deref().unwrap_or("none"),
            );
        }
    }
    Ok(())
}

fn print_json(value: &impl Serialize) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn now_rfc3339() -> anyhow::Result<String> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(anyhow::Error::from)
}
