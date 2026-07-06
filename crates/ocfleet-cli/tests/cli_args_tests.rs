use clap::Parser;
use ocfleet_cli::args::{Cli, Command, NodeCommand, ProbeCommand};
use std::path::PathBuf;

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
