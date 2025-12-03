//! Tests for routing policy configuration
//!
//! Note: routing_policy_serde is private. Test only public API.

use ipnetwork::IpNetwork;
use masque_core::tun::{RouteRule, RoutingConfig, RoutingPolicy};
use std::net::IpAddr;

#[test]
fn routing_config_split_requires_routes() {
    let cfg = RoutingConfig {
        policy: RoutingPolicy::Split,
        routes: vec![],
        dns_servers: vec![],
        ipv6_enabled: false,
    };
    assert!(cfg.validate().is_err());
}

#[test]
fn routing_config_gateway_family_mismatch() {
    let cfg = RoutingConfig {
        policy: RoutingPolicy::Split,
        routes: vec![RouteRule {
            destination: "10.0.0.0/24".parse::<IpNetwork>().unwrap(),
            gateway: Some(IpAddr::V6("2001:db8::1".parse().unwrap())),
            metric: 0,
            table: None,
        }],
        dns_servers: vec![],
        ipv6_enabled: false,
    };
    assert!(cfg.validate().is_err());
}

#[test]
fn routing_config_full_allows_no_routes() {
    let cfg = RoutingConfig {
        policy: RoutingPolicy::Full,
        routes: vec![],
        dns_servers: vec!["8.8.8.8".parse().unwrap()],
        ipv6_enabled: false,
    };
    assert!(cfg.validate().is_ok());
}

#[test]
fn routing_policy_variants_exist() {
    // Verify all policy variants are available
    let _full = RoutingPolicy::Full;
    let _split = RoutingPolicy::Split;
    let _bypass = RoutingPolicy::Bypass;
}
