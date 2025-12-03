//! Tests for TUN module helpers
use ipnetwork::IpNetwork;
use masque_core::tun::{RouteRule, RoutingConfig, RoutingPolicy, TunConfig};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn tun_config_client_defaults() {
    let cfg = TunConfig::client(Ipv4Addr::new(10, 8, 0, 2));
    assert_eq!(cfg.address, Ipv4Addr::new(10, 8, 0, 2));
    assert_eq!(cfg.name, "vpr0");
    assert_eq!(cfg.mtu, 1400);
}

#[test]
fn tun_config_server_defaults() {
    let cfg = TunConfig::server(Ipv4Addr::new(10, 8, 0, 1));
    assert_eq!(cfg.address, Ipv4Addr::new(10, 8, 0, 1));
    assert_eq!(cfg.name, "vpr-srv0");
}

#[test]
fn routing_config_ipv4_routes() {
    let cfg = RoutingConfig {
        policy: RoutingPolicy::Split,
        routes: vec![RouteRule {
            destination: IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).unwrap(),
            gateway: None,
            metric: 100,
            table: None,
        }],
        dns_servers: vec![],
        ipv6_enabled: false,
    };
    assert_eq!(cfg.ipv4_routes().len(), 1);
    assert!(cfg.ipv6_routes().is_empty());
}

#[test]
fn routing_config_ipv6_routes() {
    let cfg = RoutingConfig {
        policy: RoutingPolicy::Split,
        routes: vec![RouteRule {
            destination: IpNetwork::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                32,
            )
            .unwrap(),
            gateway: None,
            metric: 100,
            table: None,
        }],
        dns_servers: vec![],
        ipv6_enabled: true,
    };
    assert!(cfg.ipv4_routes().is_empty());
    assert_eq!(cfg.ipv6_routes().len(), 1);
}

#[test]
fn routing_config_validation_split_requires_routes() {
    let cfg = RoutingConfig {
        policy: RoutingPolicy::Split,
        routes: vec![], // Empty routes with Split policy should fail
        dns_servers: vec![],
        ipv6_enabled: false,
    };
    assert!(cfg.validate().is_err());
}

#[test]
fn routing_config_validation_full_allows_empty() {
    let cfg = RoutingConfig {
        policy: RoutingPolicy::Full,
        routes: vec![], // Full policy doesn't require routes
        dns_servers: vec![],
        ipv6_enabled: false,
    };
    assert!(cfg.validate().is_ok());
}

#[test]
fn route_rule_mixed_family_gateway_fails_validation() {
    let cfg = RoutingConfig {
        policy: RoutingPolicy::Split,
        routes: vec![RouteRule {
            destination: IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).unwrap(),
            gateway: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)), // IPv6 gateway for IPv4 dest
            metric: 100,
            table: None,
        }],
        dns_servers: vec![],
        ipv6_enabled: false,
    };
    assert!(cfg.validate().is_err());
}
