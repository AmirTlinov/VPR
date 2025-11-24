//! Tests for DNS configuration and protection

use anyhow::Result;
use masque_core::tun::{DnsProtection, RoutingConfig, RoutingPolicy};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn test_routing_config_validation_full_tunnel() -> Result<()> {
    let config = RoutingConfig {
        policy: RoutingPolicy::Full,
        routes: vec![],
        dns_servers: vec![],
        ipv6_enabled: false,
    };

    // Full tunnel doesn't require routes
    assert!(config.validate().is_ok());
    Ok(())
}

#[test]
fn test_routing_config_validation_split_tunnel_requires_routes() {
    let config = RoutingConfig {
        policy: RoutingPolicy::Split,
        routes: vec![],
        dns_servers: vec![],
        ipv6_enabled: false,
    };

    // Split tunnel requires at least one route
    assert!(config.validate().is_err());
}

#[test]
fn test_routing_config_ipv6_routes() -> Result<()> {
    use masque_core::tun::RouteRule;

    let config = RoutingConfig {
        policy: RoutingPolicy::Split,
        routes: vec![
            RouteRule {
                destination: "192.168.1.0/24".parse()?,
                gateway: Some(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1))),
                metric: 0,
                table: None,
            },
            RouteRule {
                destination: "2001:db8::/32".parse()?,
                gateway: Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
                metric: 0,
                table: None,
            },
        ],
        dns_servers: vec![],
        ipv6_enabled: true,
    };

    assert!(config.validate().is_ok());
    assert!(config.has_ipv6_routes());
    assert_eq!(config.ipv6_routes().len(), 1);
    assert_eq!(config.ipv4_routes().len(), 1);
    Ok(())
}

#[test]
fn test_routing_config_gateway_mismatch() {
    use masque_core::tun::RouteRule;

    let config = RoutingConfig {
        policy: RoutingPolicy::Split,
        routes: vec![RouteRule {
            destination: "192.168.1.0/24".parse().unwrap(),
            gateway: Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
            metric: 0,
            table: None,
        }],
        dns_servers: vec![],
        ipv6_enabled: false,
    };

    // IPv4 destination with IPv6 gateway should fail validation
    assert!(config.validate().is_err());
}

#[test]
fn test_dns_protection_creation() {
    let dns = DnsProtection::new();
    assert!(!dns.is_active());
}

#[test]
fn test_routing_config_dns_servers() -> Result<()> {
    let config = RoutingConfig {
        policy: RoutingPolicy::Full,
        routes: vec![],
        dns_servers: vec![
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 0x8888)),
        ],
        ipv6_enabled: true,
    };

    assert!(config.validate().is_ok());
    assert_eq!(config.dns_servers.len(), 3);
    Ok(())
}
