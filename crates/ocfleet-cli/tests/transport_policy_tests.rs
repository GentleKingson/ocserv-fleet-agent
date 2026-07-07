#[test]
fn controller_endpoint_builders_do_not_use_public_n0_defaults() {
    let source = include_str!("../src/rpc_client.rs");

    assert!(
        !source.contains("presets::N0"),
        "controller endpoint builders must use the private Minimal transport preset, not public N0 defaults"
    );
}
