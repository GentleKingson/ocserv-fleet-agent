use clap::{CommandFactory, Parser};
use ocfleet_cli::args::{
    AlertCommand, AlertHookCommand, AlertSeverity, AlertState, AuditCommand, AuditExportFormat,
    Cli, Command, EndpointCommand, EnrollCommand, EnrollRequestCommand, EnrollTokenCommand,
    HealthCommand, HealthPolicyCommand, HealthSnapshotCommand, NodeCommand, ObservationCommand,
    OcservCommand, OcservSessionsCommand, ProbeCommand, RedactionMode, RetentionCommand,
    RetentionScope, ScheduleCommand, ScheduleJobCommand, ScheduleJobKind, ScheduleRunCommand,
    TrustCommand, TrustDiffFormat, TrustPolicyDiffFormat,
};
use std::path::PathBuf;

#[test]
fn exposes_controller_version_flag() {
    let err = Cli::command()
        .try_get_matches_from(["ocfleet", "--version"])
        .expect_err("version flag exits before command parsing");

    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
    assert!(err.to_string().contains("ocfleet"));
}

#[test]
fn parses_global_defaults_and_init_command() {
    let cli = Cli::parse_from(["ocfleet", "init"]);

    assert_eq!(cli.database, PathBuf::from("controller.sqlite"));
    assert_eq!(cli.secret_key, PathBuf::from("controller.secret"));
    assert_eq!(cli.actor, None);
    assert!(matches!(cli.command, Command::Init));
}

#[test]
fn parses_global_actor_flag() {
    let cli = Cli::parse_from(["ocfleet", "--actor", "alice@example.test", "init"]);

    assert_eq!(cli.actor.as_deref(), Some("alice@example.test"));
    assert!(matches!(cli.command, Command::Init));
}

#[test]
fn parses_node_add_with_default_ocserv_role() {
    let cli = Cli::parse_from([
        "ocfleet",
        "--database",
        "state/controller.sqlite",
        "--secret-key",
        "state/controller.secret",
        "node",
        "add",
        "hk-ocserv-01",
        "--endpoint-id",
        "endpoint-one",
        "--region",
        "hk",
    ]);

    assert_eq!(cli.database, PathBuf::from("state/controller.sqlite"));
    assert_eq!(cli.secret_key, PathBuf::from("state/controller.secret"));

    let Command::Node {
        command:
            NodeCommand::Add {
                node_id,
                endpoint_id,
                region,
                role,
            },
    } = cli.command
    else {
        panic!("expected node add command");
    };

    assert_eq!(node_id, "hk-ocserv-01");
    assert_eq!(endpoint_id, "endpoint-one");
    assert_eq!(region, "hk");
    assert_eq!(role, "ocserv");
}

#[test]
fn parses_node_remove_yes_flag() {
    let cli = Cli::parse_from(["ocfleet", "node", "remove", "hk-ocserv-01", "--yes"]);

    let Command::Node {
        command: NodeCommand::Remove { node_id, yes },
    } = cli.command
    else {
        panic!("expected node remove command");
    };

    assert_eq!(node_id, "hk-ocserv-01");
    assert!(yes);
}

#[test]
fn parses_top_level_ping_command() {
    let cli = Cli::parse_from(["ocfleet", "ping", "hk-ocserv-01"]);

    let Command::Ping { node_id } = cli.command else {
        panic!("expected ping command");
    };

    assert_eq!(node_id, "hk-ocserv-01");
}

#[test]
fn parses_doctor_human_and_json_modes() {
    let cli = Cli::parse_from(["ocfleet", "doctor"]);
    let Command::Doctor { json } = cli.command else {
        panic!("expected doctor command");
    };
    assert!(!json);

    let cli = Cli::parse_from(["ocfleet", "doctor", "--json"]);
    let Command::Doctor { json } = cli.command else {
        panic!("expected doctor command");
    };
    assert!(json);
}

#[test]
fn parses_health_policy_commands() {
    let cli = Cli::parse_from(["ocfleet", "health", "policy", "show"]);
    let Command::Health {
        command: HealthCommand::Policy {
            command: HealthPolicyCommand::Show,
        },
    } = cli.command
    else {
        panic!("expected health policy show command");
    };

    let cli = Cli::parse_from([
        "ocfleet",
        "health",
        "policy",
        "set",
        "--stale-window",
        "24h",
        "--unreachable-failures",
        "3",
        "--cert-warning-days",
        "30",
        "--cert-critical-days",
        "7",
    ]);
    let Command::Health {
        command:
            HealthCommand::Policy {
                command:
                    HealthPolicyCommand::Set {
                        stale_window,
                        unreachable_failures,
                        cert_warning_days,
                        cert_critical_days,
                    },
            },
    } = cli.command
    else {
        panic!("expected health policy set command");
    };

    assert_eq!(stale_window.as_deref(), Some("24h"));
    assert_eq!(unreachable_failures, Some(3));
    assert_eq!(cert_warning_days, Some(30));
    assert_eq!(cert_critical_days, Some(7));
}

#[test]
fn parses_alert_deliver_command() {
    let cli = Cli::parse_from([
        "ocfleet",
        "alert",
        "deliver",
        "--hook",
        "jsonl_file:state/alerts.jsonl",
        "--limit",
        "25",
        "--dry-run",
    ]);

    let Command::Alert {
        command:
            AlertCommand::Deliver {
                hook,
                limit,
                dry_run,
                hmac_secret_file,
            },
    } = cli.command
    else {
        panic!("expected alert deliver command");
    };

    assert_eq!(hook, "jsonl_file:state/alerts.jsonl");
    assert_eq!(limit, 25);
    assert!(dry_run);
    assert!(hmac_secret_file.is_none());
}

#[test]
fn parses_alert_webhook_hook_commands() {
    let cli = Cli::parse_from([
        "ocfleet",
        "alert",
        "hook",
        "add-webhook",
        "--name",
        "ops",
        "--url",
        "https://alerts.example.com/ocfleet",
        "--hmac-secret-file",
        "state/webhook.secret",
        "--host-allow",
        "alerts.example.com",
        "--max-attempts",
        "2",
        "--timeout-ms",
        "1500",
    ]);
    let Command::Alert {
        command:
            AlertCommand::Hook {
                command:
                    AlertHookCommand::AddWebhook {
                        name,
                        url,
                        hmac_secret_file,
                        host_allow,
                        max_attempts,
                        timeout_ms,
                    },
            },
    } = cli.command
    else {
        panic!("expected alert hook add-webhook command");
    };
    assert_eq!(name, "ops");
    assert_eq!(url, "https://alerts.example.com/ocfleet");
    assert_eq!(hmac_secret_file, PathBuf::from("state/webhook.secret"));
    assert_eq!(host_allow, vec!["alerts.example.com".to_string()]);
    assert_eq!(max_attempts, 2);
    assert_eq!(timeout_ms, 1500);

    let cli = Cli::parse_from(["ocfleet", "alert", "hook", "list", "--json"]);
    let Command::Alert {
        command:
            AlertCommand::Hook {
                command: AlertHookCommand::List { json },
            },
    } = cli.command
    else {
        panic!("expected alert hook list command");
    };
    assert!(json);

    let cli = Cli::parse_from([
        "ocfleet",
        "alert",
        "hook",
        "test",
        "webhook-1",
        "--dry-run",
        "--hmac-secret-file",
        "state/webhook.secret",
    ]);
    let Command::Alert {
        command:
            AlertCommand::Hook {
                command:
                    AlertHookCommand::Test {
                        hook_id,
                        dry_run,
                        hmac_secret_file,
                    },
            },
    } = cli.command
    else {
        panic!("expected alert hook test command");
    };
    assert_eq!(hook_id, "webhook-1");
    assert!(dry_run);
    assert_eq!(
        hmac_secret_file,
        Some(PathBuf::from("state/webhook.secret"))
    );
}

#[test]
fn parses_alert_list_filters() {
    let cli = Cli::parse_from([
        "ocfleet",
        "alert",
        "list",
        "--state",
        "open",
        "--severity",
        "critical",
        "--node",
        "hk-ocserv-01",
        "--json",
    ]);

    let Command::Alert {
        command:
            AlertCommand::List {
                state,
                severity,
                node,
                json,
            },
    } = cli.command
    else {
        panic!("expected alert list command");
    };

    assert_eq!(state, Some(AlertState::Open));
    assert_eq!(severity, Some(AlertSeverity::Critical));
    assert_eq!(node.as_deref(), Some("hk-ocserv-01"));
    assert!(json);
}

#[test]
fn parses_retention_apply_report_options() {
    let cli = Cli::parse_from([
        "ocfleet",
        "retention",
        "apply",
        "--dry-run",
        "--scope",
        "observations",
        "--before",
        "2026-07-01T00:00:00Z",
        "--limit",
        "25",
        "--batch-size",
        "10",
        "--json",
    ]);

    let Command::Retention {
        command:
            RetentionCommand::Apply {
                dry_run,
                scope,
                before,
                limit,
                json,
                batch_size,
            },
    } = cli.command
    else {
        panic!("expected retention apply command");
    };

    assert!(dry_run);
    assert_eq!(scope, Some(RetentionScope::Observations));
    assert_eq!(before.as_deref(), Some("2026-07-01T00:00:00Z"));
    assert_eq!(limit, Some(25));
    assert_eq!(batch_size, 10);
    assert!(json);
}

#[test]
fn parses_retention_explain_command() {
    let cli = Cli::parse_from([
        "ocfleet",
        "retention",
        "explain",
        "--scope",
        "alert-events",
        "--json",
    ]);

    let Command::Retention {
        command: RetentionCommand::Explain { scope, json },
    } = cli.command
    else {
        panic!("expected retention explain command");
    };

    assert_eq!(scope, RetentionScope::AlertEvents);
    assert!(json);
}

#[test]
fn parses_scheduler_operability_commands() {
    let cli = Cli::parse_from([
        "ocfleet",
        "schedule",
        "job",
        "add",
        "--name",
        "HK ping",
        "--kind",
        "controller-ping",
        "--interval",
        "5m",
        "--selector",
        "node_id=hk-ocserv-01",
    ]);
    let Command::Schedule {
        command:
            ScheduleCommand::Job {
                command:
                    ScheduleJobCommand::Add {
                        name,
                        kind,
                        interval,
                        selector,
                        source_node_id,
                        target_node_id,
                    },
            },
    } = cli.command
    else {
        panic!("expected schedule job add command");
    };
    assert_eq!(name.as_deref(), Some("HK ping"));
    assert_eq!(kind, ScheduleJobKind::ControllerPing);
    assert_eq!(interval, "5m");
    assert_eq!(selector.as_deref(), Some("node_id=hk-ocserv-01"));
    assert_eq!(source_node_id, None);
    assert_eq!(target_node_id, None);

    let cli = Cli::parse_from(["ocfleet", "schedule", "job", "list", "--json"]);
    assert!(matches!(
        cli.command,
        Command::Schedule {
            command: ScheduleCommand::Job {
                command: ScheduleJobCommand::List { json: true }
            }
        }
    ));

    let cli = Cli::parse_from(["ocfleet", "schedule", "job", "show", "job-1", "--json"]);
    assert!(matches!(
        cli.command,
        Command::Schedule {
            command: ScheduleCommand::Job {
                command: ScheduleJobCommand::Show {
                    job_id,
                    json: true
                }
            }
        } if job_id == "job-1"
    ));

    let cli = Cli::parse_from(["ocfleet", "schedule", "job", "validate", "job-1", "--json"]);
    assert!(matches!(
        cli.command,
        Command::Schedule {
            command: ScheduleCommand::Job {
                command: ScheduleJobCommand::Validate {
                    job_id,
                    json: true
                }
            }
        } if job_id == "job-1"
    ));
}

#[test]
fn parses_schedule_run_query_and_targeted_once_commands() {
    let cli = Cli::parse_from([
        "ocfleet",
        "schedule",
        "run",
        "--once",
        "--job-id",
        "job-1",
        "--max-concurrency",
        "4",
        "--json",
    ]);
    let Command::Schedule {
        command:
            ScheduleCommand::Run {
                command,
                once,
                job_id,
                max_concurrency,
                json,
            },
    } = cli.command
    else {
        panic!("expected schedule run command");
    };
    assert!(command.is_none());
    assert!(once);
    assert_eq!(job_id.as_deref(), Some("job-1"));
    assert_eq!(max_concurrency, 4);
    assert!(json);

    let cli = Cli::parse_from([
        "ocfleet", "schedule", "run", "list", "--limit", "25", "--json",
    ]);
    assert!(matches!(
        cli.command,
        Command::Schedule {
            command: ScheduleCommand::Run {
                command: Some(ScheduleRunCommand::List {
                    limit: 25,
                    json: true
                }),
                ..
            }
        }
    ));

    let cli = Cli::parse_from(["ocfleet", "schedule", "run", "show", "run-1", "--json"]);
    assert!(matches!(
        cli.command,
        Command::Schedule {
            command: ScheduleCommand::Run {
                command: Some(ScheduleRunCommand::Show {
                    run_id,
                    json: true
                }),
                ..
            }
        } if run_id == "run-1"
    ));
}

#[test]
fn parses_observation_and_health_snapshot_queries() {
    let cli = Cli::parse_from([
        "ocfleet",
        "observation",
        "list",
        "--node",
        "hk-ocserv-01",
        "--method",
        "probe.controller.ping",
        "--limit",
        "25",
        "--json",
    ]);
    let Command::Observation {
        command:
            ObservationCommand::List {
                node,
                method,
                limit,
                json,
            },
    } = cli.command
    else {
        panic!("expected observation list command");
    };
    assert_eq!(node.as_deref(), Some("hk-ocserv-01"));
    assert_eq!(method.as_deref(), Some("probe.controller.ping"));
    assert_eq!(limit, 25);
    assert!(json);

    let cli = Cli::parse_from(["ocfleet", "observation", "show", "obs-1", "--json"]);
    assert!(matches!(
        cli.command,
        Command::Observation {
            command: ObservationCommand::Show {
                observation_id,
                json: true
            }
        } if observation_id == "obs-1"
    ));

    let cli = Cli::parse_from([
        "ocfleet", "health", "snapshot", "list", "--limit", "25", "--json",
    ]);
    assert!(matches!(
        cli.command,
        Command::Health {
            command: HealthCommand::Snapshot {
                command: HealthSnapshotCommand::List {
                    limit: 25,
                    json: true
                }
            }
        }
    ));
}

#[test]
fn parses_audit_export_command() {
    let cli = Cli::parse_from([
        "ocfleet",
        "audit",
        "export",
        "--from",
        "2026-07-01T00:00:00Z",
        "--to",
        "2026-07-02T00:00:00Z",
        "--format",
        "jsonl",
        "--output",
        "state/audit.jsonl",
        "--redact",
        "strict",
        "--include-checksum",
        "--sign-with-key-file",
        "state/audit-signing-key.pk8",
        "--max-rows",
        "500",
    ]);

    let Command::Audit {
        command:
            AuditCommand::Export {
                from,
                to,
                format,
                output,
                redact,
                include_checksum,
                sign_with_key_file,
                max_rows,
            },
    } = cli.command
    else {
        panic!("expected audit export command");
    };

    assert_eq!(from, "2026-07-01T00:00:00Z");
    assert_eq!(to, "2026-07-02T00:00:00Z");
    assert_eq!(format, AuditExportFormat::Jsonl);
    assert_eq!(output, PathBuf::from("state/audit.jsonl"));
    assert_eq!(redact, RedactionMode::Strict);
    assert!(include_checksum);
    assert_eq!(
        sign_with_key_file,
        Some(PathBuf::from("state/audit-signing-key.pk8"))
    );
    assert_eq!(max_rows, 500);
}

#[test]
fn parses_probe_ping_command() {
    let cli = Cli::parse_from(["ocfleet", "probe", "ping", "hk-ocserv-01"]);

    let Command::Probe {
        command: ProbeCommand::Ping { node_id },
    } = cli.command
    else {
        panic!("expected probe ping command");
    };

    assert_eq!(node_id, "hk-ocserv-01");
}

#[test]
fn parses_probe_path_command() {
    let cli = Cli::parse_from(["ocfleet", "probe", "path", "source-01", "target-01"]);

    let Command::Probe {
        command:
            ProbeCommand::Path {
                source_node_id,
                target_node_id,
            },
    } = cli.command
    else {
        panic!("expected probe path command");
    };

    assert_eq!(source_node_id, "source-01");
    assert_eq!(target_node_id, "target-01");
}

#[test]
fn parses_probe_summary_command() {
    let cli = Cli::parse_from(["ocfleet", "probe", "summary", "source-01", "target-01"]);

    let Command::Probe {
        command:
            ProbeCommand::Summary {
                source_node_id,
                target_node_id,
            },
    } = cli.command
    else {
        panic!("expected probe summary command");
    };

    assert_eq!(source_node_id, "source-01");
    assert_eq!(target_node_id, "target-01");
}

#[test]
fn probe_summary_rejects_address_flags() {
    let err = Cli::try_parse_from([
        "ocfleet",
        "probe",
        "summary",
        "source-01",
        "target-01",
        "--host",
        "127.0.0.1",
    ])
    .expect_err("probe summary must not accept host flags");

    assert!(err.to_string().contains("unexpected argument"));
}

#[test]
fn parses_probe_topology_command() {
    let cli = Cli::parse_from(["ocfleet", "probe", "topology"]);

    let Command::Probe {
        command: ProbeCommand::Topology,
    } = cli.command
    else {
        panic!("expected probe topology command");
    };
}

#[test]
fn probe_topology_rejects_address_flags() {
    let err = Cli::try_parse_from(["ocfleet", "probe", "topology", "--host", "127.0.0.1"])
        .expect_err("probe topology must not accept host flags");

    assert!(err.to_string().contains("unexpected argument"));
}

#[test]
fn parses_probe_history_command_without_filter() {
    let cli = Cli::parse_from(["ocfleet", "probe", "history"]);

    let Command::Probe {
        command: ProbeCommand::History { node_id, .. },
    } = cli.command
    else {
        panic!("expected probe history command");
    };

    assert_eq!(node_id, None);
}

#[test]
fn parses_probe_history_command_with_node_filter() {
    let cli = Cli::parse_from(["ocfleet", "probe", "history", "source-node"]);

    let Command::Probe {
        command: ProbeCommand::History { node_id, .. },
    } = cli.command
    else {
        panic!("expected probe history command");
    };

    assert_eq!(node_id.as_deref(), Some("source-node"));
}

#[test]
fn probe_history_rejects_address_flags() {
    let err = Cli::try_parse_from(["ocfleet", "probe", "history", "--host", "127.0.0.1"])
        .expect_err("probe history must not accept host flags");

    assert!(err.to_string().contains("unexpected argument"));
}

#[test]
fn parses_probe_observe_command() {
    let cli = Cli::parse_from(["ocfleet", "probe", "observe", "source-node", "target-node"]);

    let Command::Probe {
        command:
            ProbeCommand::Observe {
                source_node_id,
                target_node_id,
            },
    } = cli.command
    else {
        panic!("expected probe observe command");
    };

    assert_eq!(source_node_id, "source-node");
    assert_eq!(target_node_id, "target-node");
}

#[test]
fn probe_observe_rejects_address_flags() {
    let err = Cli::try_parse_from([
        "ocfleet",
        "probe",
        "observe",
        "source-node",
        "target-node",
        "--port",
        "443",
    ])
    .expect_err("probe observe must not accept port flags");

    assert!(err.to_string().contains("unexpected argument"));
}

#[test]
fn parses_enroll_token_create_defaults_and_overrides() {
    let cli = Cli::parse_from([
        "ocfleet",
        "enroll",
        "token",
        "create",
        "--ttl",
        "12h",
        "--max-uses",
        "3",
        "--description",
        "prod node onboarding",
    ]);

    let Command::Enroll {
        command:
            EnrollCommand::Token {
                command:
                    EnrollTokenCommand::Create {
                        ttl,
                        max_uses,
                        description,
                    },
            },
    } = cli.command
    else {
        panic!("expected enroll token create command");
    };

    assert_eq!(ttl, "12h");
    assert_eq!(max_uses, 3);
    assert_eq!(description.as_deref(), Some("prod node onboarding"));
}

#[test]
fn parses_enroll_approve_command() {
    let cli = Cli::parse_from([
        "ocfleet",
        "enroll",
        "approve",
        "join-123",
        "--endpoint-id",
        "endpoint-approved",
        "--node-id",
        "hk-ocserv-01",
        "--region",
        "hk",
        "--reason",
        "ticket-123",
    ]);

    let Command::Enroll {
        command:
            EnrollCommand::Approve {
                join_request_id,
                endpoint_id,
                node_id,
                region,
                role,
                reason,
            },
    } = cli.command
    else {
        panic!("expected enroll approve command");
    };

    assert_eq!(join_request_id, "join-123");
    assert_eq!(endpoint_id, "endpoint-approved");
    assert_eq!(node_id, "hk-ocserv-01");
    assert_eq!(region, "hk");
    assert_eq!(role, "ocserv");
    assert_eq!(reason, "ticket-123");
}

#[test]
fn parses_enroll_claim_command_with_explicit_role() {
    let cli = Cli::parse_from([
        "ocfleet",
        "enroll",
        "claim",
        "join-legacy",
        "--endpoint-id",
        "endpoint-approved",
        "--node-id",
        "edge-proxy-01",
        "--region",
        "sg",
        "--role",
        "ocserv",
        "--reason",
        "legacy repair",
    ]);

    let Command::Enroll {
        command:
            EnrollCommand::Claim {
                join_request_id,
                endpoint_id,
                node_id,
                region,
                role,
                reason,
            },
    } = cli.command
    else {
        panic!("expected enroll claim command");
    };

    assert_eq!(join_request_id, "join-legacy");
    assert_eq!(endpoint_id, "endpoint-approved");
    assert_eq!(node_id, "edge-proxy-01");
    assert_eq!(region, "sg");
    assert_eq!(role, "ocserv");
    assert_eq!(reason, "legacy repair");
}

#[test]
fn enrollment_binding_commands_require_node_and_region() {
    for command in ["approve", "claim"] {
        let err = Cli::try_parse_from([
            "ocfleet",
            "enroll",
            command,
            "join-123",
            "--endpoint-id",
            "endpoint-approved",
            "--reason",
            "ticket-123",
        ])
        .expect_err("node and region are required");

        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        let message = err.to_string();
        assert!(message.contains("--node-id"));
        assert!(message.contains("--region"));
    }
}

#[test]
fn parses_enroll_request_create_command() {
    let cli = Cli::parse_from([
        "ocfleet",
        "enroll",
        "request",
        "create",
        "--token",
        "secret-token",
        "--agent-public-key",
        "agent-public-key",
        "--fingerprint",
        "agent-fingerprint",
        "--requested-endpoint-id",
        "requested-endpoint",
        "--hostname",
        "hk-ocserv-01",
        "--agent-version",
        "0.1.0",
    ]);

    let Command::Enroll {
        command:
            EnrollCommand::Request {
                command:
                    EnrollRequestCommand::Create {
                        token,
                        token_file,
                        token_stdin,
                        agent_public_key,
                        fingerprint,
                        requested_endpoint_id,
                        hostname,
                        agent_version,
                    },
            },
    } = cli.command
    else {
        panic!("expected enroll request create command");
    };

    assert_eq!(token.as_deref(), Some("secret-token"));
    assert_eq!(token_file, None);
    assert!(!token_stdin);
    assert_eq!(agent_public_key, "agent-public-key");
    assert_eq!(fingerprint, "agent-fingerprint");
    assert_eq!(requested_endpoint_id.as_deref(), Some("requested-endpoint"));
    assert_eq!(hostname, "hk-ocserv-01");
    assert_eq!(agent_version, "0.1.0");
}

#[test]
fn parses_enroll_request_create_token_file_and_stdin_sources() {
    let cli = Cli::parse_from([
        "ocfleet",
        "enroll",
        "request",
        "create",
        "--token-file",
        "/run/secrets/ocfleet-token",
        "--agent-public-key",
        "agent-public-key",
        "--fingerprint",
        "agent-fingerprint",
        "--hostname",
        "hk-ocserv-01",
        "--agent-version",
        "0.1.0",
    ]);

    let Command::Enroll {
        command:
            EnrollCommand::Request {
                command:
                    EnrollRequestCommand::Create {
                        token,
                        token_file,
                        token_stdin,
                        ..
                    },
            },
    } = cli.command
    else {
        panic!("expected enroll request create command");
    };

    assert_eq!(token, None);
    assert_eq!(
        token_file.as_deref(),
        Some(std::path::Path::new("/run/secrets/ocfleet-token"))
    );
    assert!(!token_stdin);

    let cli = Cli::parse_from([
        "ocfleet",
        "enroll",
        "request",
        "create",
        "--token-stdin",
        "--agent-public-key",
        "agent-public-key",
        "--fingerprint",
        "agent-fingerprint",
        "--hostname",
        "hk-ocserv-01",
        "--agent-version",
        "0.1.0",
    ]);

    let Command::Enroll {
        command:
            EnrollCommand::Request {
                command:
                    EnrollRequestCommand::Create {
                        token,
                        token_file,
                        token_stdin,
                        ..
                    },
            },
    } = cli.command
    else {
        panic!("expected enroll request create command");
    };

    assert_eq!(token, None);
    assert_eq!(token_file, None);
    assert!(token_stdin);
}

#[test]
fn enroll_request_create_rejects_address_flags() {
    let err = Cli::try_parse_from([
        "ocfleet",
        "enroll",
        "request",
        "create",
        "--token",
        "secret-token",
        "--agent-public-key",
        "agent-public-key",
        "--fingerprint",
        "agent-fingerprint",
        "--hostname",
        "hk-ocserv-01",
        "--agent-version",
        "0.1.0",
        "--host",
        "127.0.0.1",
    ])
    .expect_err("enroll request create must not accept host flags");

    assert!(err.to_string().contains("unexpected argument"));
}

#[test]
fn parses_endpoint_lifecycle_commands() {
    let cli = Cli::parse_from([
        "ocfleet",
        "endpoint",
        "rotate",
        "old-endpoint",
        "--new-endpoint-id",
        "new-endpoint",
        "--reason",
        "rotation",
    ]);
    let Command::Endpoint {
        command:
            EndpointCommand::Rotate {
                old_endpoint_id,
                new_endpoint_id,
                reason,
            },
    } = cli.command
    else {
        panic!("expected endpoint rotate command");
    };
    assert_eq!(old_endpoint_id, "old-endpoint");
    assert_eq!(new_endpoint_id, "new-endpoint");
    assert_eq!(reason, "rotation");

    let cli = Cli::parse_from([
        "ocfleet",
        "endpoint",
        "revoke",
        "endpoint-one",
        "--reason",
        "lost host",
    ]);
    assert!(matches!(
        cli.command,
        Command::Endpoint {
            command: EndpointCommand::Revoke { .. }
        }
    ));

    let cli = Cli::parse_from([
        "ocfleet",
        "endpoint",
        "quarantine",
        "endpoint-one",
        "--reason",
        "suspicious",
    ]);
    assert!(matches!(
        cli.command,
        Command::Endpoint {
            command: EndpointCommand::Quarantine { .. }
        }
    ));
}

#[test]
fn parses_trust_diff_modes() {
    let cli = Cli::parse_from([
        "ocfleet",
        "trust",
        "diff",
        "--endpoint",
        "endpoint-one",
        "--format",
        "json",
        "--strict",
    ]);

    let Command::Trust {
        command:
            TrustCommand::Diff {
                endpoint,
                format,
                strict,
            },
    } = cli.command
    else {
        panic!("expected trust diff command");
    };

    assert_eq!(endpoint.as_deref(), Some("endpoint-one"));
    assert_eq!(format, TrustDiffFormat::Json);
    assert!(strict);
}

#[test]
fn parses_trust_policy_commands() {
    let cli = Cli::parse_from([
        "ocfleet",
        "trust",
        "policy",
        "validate",
        "policy.toml",
        "--json",
    ]);

    let Command::Trust {
        command: TrustCommand::Policy { command },
    } = cli.command
    else {
        panic!("expected trust policy command");
    };

    match command {
        ocfleet_cli::args::TrustPolicyCommand::Validate { file, json } => {
            assert_eq!(file, PathBuf::from("policy.toml"));
            assert!(json);
        }
        _ => panic!("expected trust policy validate command"),
    }

    let cli = Cli::parse_from([
        "ocfleet",
        "trust",
        "policy",
        "diff",
        "policy.toml",
        "--format",
        "markdown",
        "--output",
        "summary.md",
    ]);

    let Command::Trust {
        command: TrustCommand::Policy { command },
    } = cli.command
    else {
        panic!("expected trust policy command");
    };

    match command {
        ocfleet_cli::args::TrustPolicyCommand::Diff {
            file,
            json,
            format,
            output,
        } => {
            assert_eq!(file, PathBuf::from("policy.toml"));
            assert!(!json);
            assert_eq!(format, TrustPolicyDiffFormat::Markdown);
            assert_eq!(output, Some(PathBuf::from("summary.md")));
        }
        _ => panic!("expected trust policy diff command"),
    }
}

#[test]
fn parses_node_info_command() {
    let cli = Cli::parse_from(["ocfleet", "node", "info", "hk-ocserv-01"]);

    let Command::Node {
        command: NodeCommand::Info { node_id },
    } = cli.command
    else {
        panic!("expected node info command");
    };

    assert_eq!(node_id, "hk-ocserv-01");
}

#[test]
fn parses_ocserv_status_command() {
    let cli = Cli::parse_from(["ocfleet", "ocserv", "status", "hk-ocserv-01"]);

    let Command::Ocserv {
        command: OcservCommand::Status { node, json },
    } = cli.command
    else {
        panic!("expected ocserv status command");
    };

    assert_eq!(node, "hk-ocserv-01");
    assert!(!json);
}

#[test]
fn parses_ocserv_cert_command() {
    let cli = Cli::parse_from(["ocfleet", "ocserv", "cert", "hk-ocserv-01", "--json"]);

    let Command::Ocserv {
        command: OcservCommand::Cert { node, json },
    } = cli.command
    else {
        panic!("expected ocserv cert command");
    };

    assert_eq!(node, "hk-ocserv-01");
    assert!(json);
}

#[test]
fn parses_ocserv_sessions_summary_command() {
    let cli = Cli::parse_from(["ocfleet", "ocserv", "sessions", "summary", "hk-ocserv-01"]);

    let Command::Ocserv {
        command:
            OcservCommand::Sessions {
                command: OcservSessionsCommand::Summary { node, json },
            },
    } = cli.command
    else {
        panic!("expected ocserv sessions summary command");
    };

    assert_eq!(node, "hk-ocserv-01");
    assert!(!json);
}

#[test]
fn ocserv_commands_reject_dangerous_selector_flags() {
    for args in [
        vec![
            "ocfleet",
            "ocserv",
            "status",
            "hk-ocserv-01",
            "--host",
            "127.0.0.1",
        ],
        vec![
            "ocfleet",
            "ocserv",
            "status",
            "hk-ocserv-01",
            "--port",
            "443",
        ],
        vec![
            "ocfleet",
            "ocserv",
            "cert",
            "hk-ocserv-01",
            "--path",
            "/etc/ocserv/server.pem",
        ],
        vec![
            "ocfleet",
            "ocserv",
            "sessions",
            "summary",
            "hk-ocserv-01",
            "--command",
            "occtl show users",
        ],
    ] {
        let err = Cli::try_parse_from(args).expect_err("dangerous ocserv selector rejected");
        assert!(err.to_string().contains("unexpected argument"));
    }
}
