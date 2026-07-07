#[test]
fn agent_endpoint_builders_do_not_use_public_n0_defaults() {
    let source = include_str!("../src/server.rs");

    assert!(
        !source.contains("presets::N0"),
        "agent endpoint builders must use the private Minimal transport preset, not public N0 defaults"
    );
}
