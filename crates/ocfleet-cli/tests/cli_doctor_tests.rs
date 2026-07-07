use iroh::SecretKey;
use ocfleet_cli::doctor::{
    DOCTOR_EXIT_OK, DOCTOR_EXIT_UNHEALTHY, DoctorOptions, DoctorStatus, run_doctor,
};
use ocfleet_cli::identity::load_or_create_secret_key_with_status;
use ocfleet_cli::store::{NodeInsert, Store};

#[test]
fn doctor_reports_ok_for_initialized_controller_state() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("controller.sqlite");
    let secret = dir.path().join("controller.secret");
    let store = Store::open(&db).expect("store opens");
    let node_key = SecretKey::generate();
    store
        .add_node(&NodeInsert {
            node_id: "hk-ocserv-01".to_string(),
            endpoint_id: node_key.public().to_string(),
            name: "hk-ocserv-01".to_string(),
            region: "hk".to_string(),
            role: "ocserv".to_string(),
        })
        .expect("insert node");
    load_or_create_secret_key_with_status(&secret, false).expect("controller secret");

    let report = run_doctor(&DoctorOptions {
        database: db,
        secret_key: secret,
    });

    assert_eq!(report.status, DoctorStatus::Ok);
    assert_eq!(report.exit_code, DOCTOR_EXIT_OK);
    assert_eq!(report.schema_version_actual, Some(1));
    assert!(report.checks.iter().all(|check| !check.status.is_error()));
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
        .add_node(&NodeInsert {
            node_id: "hk-ocserv-01".to_string(),
            endpoint_id: "not-an-endpoint-id".to_string(),
            name: "hk-ocserv-01".to_string(),
            region: "hk".to_string(),
            role: "ocserv".to_string(),
        })
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
