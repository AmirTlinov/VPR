use vpr_e2e::config::E2eConfig;

#[test]
fn config_defaults_are_safe() {
    let cfg = E2eConfig::default();
    // sensible defaults
    assert_eq!(cfg.server.ssh_port, 22);
    assert_eq!(cfg.server.user, "root");
    assert_eq!(cfg.client.tun_name, "vpr0");
    assert!(cfg.tests.ping);
    assert!(cfg.output.json);
}

#[test]
fn config_can_set_target() {
    let mut cfg = E2eConfig::default();
    cfg.server.host = "127.0.0.1".into();
    assert_eq!(cfg.server.host, "127.0.0.1");
}
