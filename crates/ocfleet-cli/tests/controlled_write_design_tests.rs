use std::fs;
use std::path::Path;

#[test]
fn controlled_write_design_keeps_required_safety_gates() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let doc = fs::read_to_string(repo.join("docs/controlled-write-operations.md"))
        .expect("controlled write design doc");

    for required in [
        "This phase adds no working",
        "Compile-time feature: `controlled-writes`, default off.",
        "Agent local config: `controlled_writes.enabled = false`, default off.",
        "Audit: required for every state transition.",
        "Dry-run: mandatory for every operation.",
        "write_operation_audit",
        "No raw config body or raw command in RPC.",
        "The controller must never supply local",
        "service units, paths, commands, selectors, scripts, or package names.",
    ] {
        assert!(
            doc.contains(required),
            "controlled write design doc is missing required safety text: {required}"
        );
    }
}
