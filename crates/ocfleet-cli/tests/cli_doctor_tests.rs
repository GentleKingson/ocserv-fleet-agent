use iroh::SecretKey;
use ocfleet_cli::backend::StoreWriter;
use ocfleet_cli::doctor::{
    CheckStatus, DOCTOR_EXIT_OK, DOCTOR_EXIT_UNHEALTHY, DoctorCheck, DoctorOptions, DoctorReport,
    DoctorStatus, run_doctor,
};
use ocfleet_cli::identity::load_or_create_secret_key_with_status;
use ocfleet_cli::store::{CURRENT_SCHEMA_VERSION, NodeInsert, Store};
use rusqlite::{Connection, params};

#[test]
fn doctor_reports_ok_for_initialized_controller_state() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let secret = dir.path().join("controller.secret");
    let store = Store::open(&db).expect("store opens");
    let node_key = SecretKey::generate();
    store
        .add_node(
            &NodeInsert {
                node_id: "hk-ocserv-01".to_string(),
                endpoint_id: node_key.public().to_string(),
                name: "hk-ocserv-01".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            "doctor-test",
        )
        .expect("insert node");
    load_or_create_secret_key_with_status(&secret, false).expect("controller secret");

    let report = run_doctor(&DoctorOptions {
        database: db,
        secret_key: secret,
    });

    assert_eq!(report.status, DoctorStatus::Ok);
    assert_eq!(report.exit_code, DOCTOR_EXIT_OK);
    assert_eq!(report.schema_version_actual, Some(CURRENT_SCHEMA_VERSION));
    assert!(report.checks.iter().all(|check| !check.status.is_error()));
    let coverage = report
        .checks
        .iter()
        .find(|check| check.id == "registry.endpoint_trust.coverage")
        .expect("endpoint trust coverage check");
    assert_eq!(coverage.status, CheckStatus::Ok);
    assert_eq!(coverage.details["node_count"], 1);
    let bindings = endpoint_trust_bindings(&report);
    assert_eq!(bindings.status, CheckStatus::Ok);
    assert_eq!(
        bindings.details,
        serde_json::json!({
            "active_unbound": 0,
            "active_orphan": 0,
            "current_binding_mismatch": 0,
            "inactive_current": 0,
            "active_extra_for_node": 0,
        })
    );
}

#[test]
fn doctor_does_not_create_missing_database_or_secret() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("missing-controller.sqlite");
    let secret = dir.path().join("missing-controller.secret");

    let report = run_doctor(&DoctorOptions {
        database: db.clone(),
        secret_key: secret.clone(),
    });

    assert_eq!(report.status, DoctorStatus::Error);
    assert_eq!(report.exit_code, DOCTOR_EXIT_UNHEALTHY);
    assert!(!db.exists(), "doctor must not create controller DB");
    assert!(!secret.exists(), "doctor must not create SecretKey");
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.id == "controller_db.exists" && check.status.is_error())
    );
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.id == "secret_key.exists" && check.status.is_error())
    );
}

#[test]
fn doctor_detects_invalid_registry_endpoint_ids() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let secret = dir.path().join("controller.secret");
    let store = Store::open(&db).expect("store opens");
    store
        .add_node(
            &NodeInsert {
                node_id: "hk-ocserv-01".to_string(),
                endpoint_id: "not-an-endpoint-id".to_string(),
                name: "hk-ocserv-01".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            "doctor-test",
        )
        .expect("insert malformed node");
    load_or_create_secret_key_with_status(&secret, false).expect("controller secret");

    let report = run_doctor(&DoctorOptions {
        database: db,
        secret_key: secret,
    });

    assert_eq!(report.status, DoctorStatus::Error);
    assert_eq!(report.exit_code, DOCTOR_EXIT_UNHEALTHY);
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.id == "registry.endpoint_id.parse" && check.status.is_error())
    );
}

#[test]
fn doctor_detects_registry_endpoint_without_trust_state() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let secret = dir.path().join("controller.secret");
    let store = Store::open(&db).expect("store opens");
    let endpoint_id = SecretKey::generate().public().to_string();
    store
        .add_node(
            &NodeInsert {
                node_id: "hk-ocserv-01".to_string(),
                endpoint_id: endpoint_id.clone(),
                name: "hk-ocserv-01".to_string(),
                region: "hk".to_string(),
                role: "ocserv".to_string(),
            },
            "doctor-test",
        )
        .expect("insert node");
    drop(store);
    rusqlite::Connection::open(&db)
        .expect("open database")
        .execute(
            "DELETE FROM endpoint_trust WHERE endpoint_id = ?1",
            [&endpoint_id],
        )
        .expect("delete endpoint trust state");
    load_or_create_secret_key_with_status(&secret, false).expect("controller secret");

    let report = run_doctor(&DoctorOptions {
        database: db,
        secret_key: secret,
    });

    assert_eq!(report.status, DoctorStatus::Error);
    assert_eq!(report.exit_code, DOCTOR_EXIT_UNHEALTHY);
    let coverage = report
        .checks
        .iter()
        .find(|check| check.id == "registry.endpoint_trust.coverage")
        .expect("endpoint trust coverage check");
    assert_eq!(coverage.status, CheckStatus::Error);
    assert_eq!(coverage.details["node_count"], 1);
    assert_eq!(coverage.details["missing_count"], 1);
    assert_eq!(coverage.details.as_object().expect("details").len(), 2);
}

#[test]
fn doctor_reports_aggregate_endpoint_trust_binding_failures_without_identities() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let secret = dir.path().join("controller.secret");
    let store = Store::open(&db).expect("store opens");
    let mismatch_endpoint = add_node(&store, "mismatch-node");
    let inactive_endpoint = add_node(&store, "inactive-node");
    let extra_owner_endpoint = add_node(&store, "extra-owner-node");
    drop(store);

    let active_unbound_endpoint = SecretKey::generate().public().to_string();
    let active_orphan_endpoint = SecretKey::generate().public().to_string();
    let active_extra_endpoint = SecretKey::generate().public().to_string();
    let conn = Connection::open(&db).expect("open database");
    conn.execute(
        "UPDATE endpoint_trust SET node_id = NULL WHERE endpoint_id = ?1",
        [&mismatch_endpoint],
    )
    .expect("make current binding unbound");
    conn.execute(
        "UPDATE endpoint_trust SET status = 'revoked' WHERE endpoint_id = ?1",
        [&inactive_endpoint],
    )
    .expect("make current endpoint inactive");
    insert_endpoint_trust(&conn, &active_unbound_endpoint, None, "active");
    insert_endpoint_trust(
        &conn,
        &active_orphan_endpoint,
        Some("removed-node"),
        "active",
    );
    insert_endpoint_trust(
        &conn,
        &active_extra_endpoint,
        Some("extra-owner-node"),
        "active",
    );
    drop(conn);
    load_or_create_secret_key_with_status(&secret, false).expect("controller secret");

    let report = run_doctor(&DoctorOptions {
        database: db,
        secret_key: secret,
    });

    assert_eq!(report.status, DoctorStatus::Error);
    assert_eq!(report.exit_code, DOCTOR_EXIT_UNHEALTHY);
    let bindings = endpoint_trust_bindings(&report);
    assert_eq!(bindings.status, CheckStatus::Error);
    assert_eq!(
        bindings.details,
        serde_json::json!({
            "active_unbound": 2,
            "active_orphan": 1,
            "current_binding_mismatch": 1,
            "inactive_current": 1,
            "active_extra_for_node": 1,
        })
    );
    assert_eq!(bindings.details.as_object().expect("details").len(), 5);
    let details = bindings.details.to_string();
    for identity in [
        "mismatch-node",
        "inactive-node",
        "extra-owner-node",
        "removed-node",
        mismatch_endpoint.as_str(),
        inactive_endpoint.as_str(),
        extra_owner_endpoint.as_str(),
        active_unbound_endpoint.as_str(),
        active_orphan_endpoint.as_str(),
        active_extra_endpoint.as_str(),
    ] {
        assert!(
            !details.contains(identity),
            "binding details must not expose identity {identity}"
        );
    }
}

#[test]
fn doctor_accepts_historical_inactive_endpoint_trust_tombstones() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let secret = dir.path().join("controller.secret");
    let store = Store::open(&db).expect("store opens");
    drop(store);

    let conn = Connection::open(&db).expect("open database");
    for (index, status) in ["rotated", "revoked", "quarantined"]
        .into_iter()
        .enumerate()
    {
        let endpoint_id = SecretKey::generate().public().to_string();
        insert_endpoint_trust(
            &conn,
            &endpoint_id,
            Some(&format!("historical-node-{index}")),
            status,
        );
    }
    drop(conn);
    load_or_create_secret_key_with_status(&secret, false).expect("controller secret");

    let report = run_doctor(&DoctorOptions {
        database: db,
        secret_key: secret,
    });

    assert_eq!(report.status, DoctorStatus::Ok);
    assert_eq!(report.exit_code, DOCTOR_EXIT_OK);
    let bindings = endpoint_trust_bindings(&report);
    assert_eq!(bindings.status, CheckStatus::Ok);
    assert_eq!(
        bindings.details,
        serde_json::json!({
            "active_unbound": 0,
            "active_orphan": 0,
            "current_binding_mismatch": 0,
            "inactive_current": 0,
            "active_extra_for_node": 0,
        })
    );
}

#[test]
fn doctor_accepts_disabled_node_with_inactive_current_trust() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let secret = dir.path().join("controller.secret");
    let store = Store::open(&db).expect("store opens");
    let endpoint_id = add_node(&store, "quarantined-node");
    StoreWriter::write_endpoint_quarantine(&store, &endpoint_id, "doctor-test", "investigation")
        .expect("quarantine endpoint");
    load_or_create_secret_key_with_status(&secret, false).expect("controller secret");

    let report = run_doctor(&DoctorOptions {
        database: db,
        secret_key: secret,
    });

    assert_eq!(report.status, DoctorStatus::Ok);
    assert_eq!(report.exit_code, DOCTOR_EXIT_OK);
    let bindings = endpoint_trust_bindings(&report);
    assert_eq!(bindings.status, CheckStatus::Ok);
    assert_eq!(bindings.details["inactive_current"], 0);
}

fn endpoint_trust_bindings(report: &DoctorReport) -> &DoctorCheck {
    report
        .checks
        .iter()
        .find(|check| check.id == "registry.endpoint_trust.bindings")
        .expect("endpoint trust bindings check")
}

fn add_node(store: &Store, node_id: &str) -> String {
    let endpoint_id = SecretKey::generate().public().to_string();
    store
        .add_node(
            &NodeInsert {
                node_id: node_id.to_string(),
                endpoint_id: endpoint_id.clone(),
                name: node_id.to_string(),
                region: "test".to_string(),
                role: "ocserv".to_string(),
            },
            "doctor-test",
        )
        .expect("insert node");
    endpoint_id
}

fn insert_endpoint_trust(
    conn: &Connection,
    endpoint_id: &str,
    node_id: Option<&str>,
    status: &str,
) {
    let trust_bundle = serde_json::json!({
        "endpoint_id": endpoint_id,
        "generation": 1,
        "status": status,
        "trusted_controllers": [],
        "trusted_peers": [],
        "authorized_path_probes": [],
    });
    conn.execute(
        "INSERT INTO endpoint_trust
         (endpoint_id, node_id, fingerprint, status, generation, previous_endpoint_id, rotated_to,
          trust_bundle_json, created_at, updated_at)
         VALUES (?1, ?2, NULL, ?3, 1, NULL, NULL, ?4,
                 '2026-07-11T00:00:00Z', '2026-07-11T00:00:00Z')",
        params![endpoint_id, node_id, status, trust_bundle.to_string()],
    )
    .expect("insert endpoint trust fixture");
}
