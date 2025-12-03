use bytes::Bytes;
use masque_core::vpn_tunnel::{PacketEncapsulator, TunnelStats, VpnTunnelConfig};
use std::net::Ipv4Addr;

#[test]
fn encapsulator_preserves_payload() {
    let enc = PacketEncapsulator::new();
    let payload = Bytes::from_static(b"hello");
    let out = enc.encapsulate(payload.clone());
    let back = enc.decapsulate(out).unwrap();
    assert_eq!(payload, back);
}

#[test]
fn tunnel_stats_start_zero() {
    let stats = TunnelStats::default();
    assert_eq!(stats.packets_sent, 0);
    assert_eq!(stats.packets_received, 0);
    assert_eq!(stats.bytes_sent, 0);
    assert_eq!(stats.bytes_received, 0);
}

#[test]
fn vpn_tunnel_client_helpers() {
    let cfg = VpnTunnelConfig::client(
        Ipv4Addr::new(10, 0, 0, 2),
        "example.com:443".into(),
        "example.com".into(),
        Ipv4Addr::new(10, 0, 0, 1),
    );
    assert_eq!(cfg.tun.name, "vpr0");
    assert_eq!(cfg.server_name, "example.com");
    assert_eq!(cfg.target_port, 0);
}
