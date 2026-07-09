use clap::{CommandFactory, Parser};
use ocfleet_cli::args::{
    AlertCommand, Cli, Command, EndpointCommand, EnrollCommand, EnrollRequestCommand,
    EnrollTokenCommand, HealthCommand, HealthPolicyCommand, NodeCommand, OcservCommand,
    OcservSessionsCommand, ProbeCommand, TrustCommand, TrustDiffFormat,
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
            },
    } = cli.command
    else {
        panic!("expected alert deliver command");
    };

    assert_eq!(hook, "jsonl_file:state/alerts.jsonl");
    assert_eq!(limit, 25);
    assert!(dry_run);
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
        "--reason",
        "ticket-123",
    ]);

    let Command::Enroll {
        command:
            EnrollCommand::Approve {
                join_request_id,
                endpoint_id,
                reason,
            },
    } = cli.command
    else {
        panic!("expected enroll approve command");
    };

    assert_eq!(join_request_id, "join-123");
    assert_eq!(endpoint_id, "endpoint-approved");
    assert_eq!(reason, "ticket-123");
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
