//! Integration tests for routing and NAT functionality
//!
//! These tests verify that routing and NAT masquerading work correctly.
//! Note: These tests require root privileges or network namespace setup.

use anyhow::Result;
use ipnetwork::IpNetwork;
use masque_core::tun::{
    add_route_rule, restore_routing, restore_split_tunnel, setup_ipv6_nat, setup_ipv6_routing,
    setup_nat_with_config, setup_policy_routing, setup_routing, setup_split_tunnel, teardown_nat,
    NatConfig, RouteRule, RoutingState,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore] // Requires root or network namespace
async fn test_nat_setup_teardown() -> Result<()> {
    // Check if we have required permissions
    if std::env::var("VPR_TEST_ROOT").is_err() {
        eprintln!("Skipping NAT test - requires VPR_TEST_ROOT=1 or root");
        return Ok(());
    }

    let tun_name = "vpr_test_nat";
    let outbound_iface = get_default_interface()?;

    let mut state = RoutingState::new();
    let nat_config = NatConfig {
        outbound_iface: outbound_iface.clone(),
        masquerade_ipv4: true,
        masquerade_ipv6: false,
        preserve_source: false,
    };

    // Setup NAT with config
    setup_nat_with_config(tun_name, &nat_config, &mut state)?;

    // Verify NAT rules exist
    let has_nat = check_nat_rule_exists(tun_name)?;
    assert!(has_nat, "NAT rule should exist after setup");

    // Teardown NAT
    teardown_nat(&mut state)?;

    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore] // Requires root or network namespace
async fn test_routing_setup_restore() -> Result<()> {
    if std::env::var("VPR_TEST_ROOT").is_err() {
        eprintln!("Skipping routing test - requires VPR_TEST_ROOT=1 or root");
        return Ok(());
    }

    let tun_name = "vpr_test_route";
    let gateway = Ipv4Addr::new(10, 8, 0, 1);

    // Setup routing
    setup_routing(tun_name, gateway)?;

    // Verify route exists
    let has_route = check_route_exists(&gateway)?;
    assert!(has_route, "Route should exist after setup");

    // Restore routing
    restore_routing(tun_name, gateway)?;

    // Verify route removed
    let route_still_exists = check_route_exists(&gateway)?;
    assert!(!route_still_exists, "Route should be removed after restore");

    Ok(())
}

#[cfg(target_os = "linux")]
fn get_default_interface() -> Result<String> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()?;

    let stdout = String::from_utf8(output.stdout)?;
    for line in stdout.lines() {
        if line.contains("dev") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            for (i, part) in parts.iter().enumerate() {
                if *part == "dev" && i + 1 < parts.len() {
                    return Ok(parts[i + 1].to_string());
                }
            }
        }
    }

    anyhow::bail!("could not determine default interface")
}

#[cfg(target_os = "linux")]
fn check_nat_rule_exists(tun_name: &str) -> Result<bool> {
    let output = Command::new("iptables")
        .args(["-t", "nat", "-L", "-n", "-v"])
        .output()?;

    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout.contains(tun_name))
}

#[cfg(target_os = "linux")]
fn check_route_exists(gateway: &Ipv4Addr) -> Result<bool> {
    let output = Command::new("ip").args(["route", "show"]).output()?;

    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout.contains(&gateway.to_string()))
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore] // Requires root or network namespace
async fn test_split_tunnel_setup_restore() -> Result<()> {
    if std::env::var("VPR_TEST_ROOT").is_err() {
        eprintln!("Skipping split tunnel test - requires VPR_TEST_ROOT=1 or root");
        return Ok(());
    }

    let tun_name = "vpr_test_split";
    let gateway = IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1));
    let mut state = RoutingState::new();

    // Create test routes
    let routes = vec![
        RouteRule {
            destination: "192.168.1.0/24".parse()?,
            gateway: Some(gateway),
            metric: 0,
            table: None,
        },
        RouteRule {
            destination: "10.0.0.0/8".parse()?,
            gateway: Some(gateway),
            metric: 0,
            table: None,
        },
    ];

    // Setup split tunnel
    setup_split_tunnel(tun_name, gateway, &routes, &mut state)?;

    // Verify routes exist
    for route in &routes {
        let has_route = check_route_exists_network(&route.destination)?;
        assert!(has_route, "Route should exist for {}", route.destination);
    }

    // Restore split tunnel
    restore_split_tunnel(&mut state)?;

    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore] // Requires root or network namespace
async fn test_split_tunnel_multiple_routes() -> Result<()> {
    if std::env::var("VPR_TEST_ROOT").is_err() {
        eprintln!("Skipping split tunnel multiple routes test - requires VPR_TEST_ROOT=1 or root");
        return Ok(());
    }

    let tun_name = "vpr_test_split_multi";
    let gateway = IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1));
    let mut state = RoutingState::new();

    // Create multiple routes with different metrics
    let routes = vec![
        RouteRule {
            destination: "172.16.0.0/12".parse()?,
            gateway: Some(gateway),
            metric: 100,
            table: None,
        },
        RouteRule {
            destination: "192.168.0.0/16".parse()?,
            gateway: Some(gateway),
            metric: 200,
            table: Some(100),
        },
    ];

    setup_split_tunnel(tun_name, gateway, &routes, &mut state)?;

    // Verify all routes were added
    assert_eq!(state.route_count(), 2);

    restore_split_tunnel(&mut state)?;

    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore] // Requires root or network namespace
async fn test_policy_routing_setup() -> Result<()> {
    if std::env::var("VPR_TEST_ROOT").is_err() {
        eprintln!("Skipping policy routing test - requires VPR_TEST_ROOT=1 or root");
        return Ok(());
    }

    let tun_name = "vpr_test_policy";
    let gateway = IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1));
    let mut state = RoutingState::new();

    let routes = vec![RouteRule {
        destination: "203.0.113.0/24".parse()?,
        gateway: Some(gateway),
        metric: 0,
        table: Some(100),
    }];

    setup_policy_routing(tun_name, gateway, &routes, &mut state)?;

    // Verify policy rule was added
    assert!(state.has_policy_rules());

    restore_split_tunnel(&mut state)?;

    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore] // Requires root or network namespace
async fn test_nat_teardown() -> Result<()> {
    if std::env::var("VPR_TEST_ROOT").is_err() {
        eprintln!("Skipping NAT teardown test - requires VPR_TEST_ROOT=1 or root");
        return Ok(());
    }

    let tun_name = "vpr_test_nat_teardown";
    let outbound_iface = get_default_interface()?;
    let mut state = RoutingState::new();

    let nat_config = NatConfig {
        outbound_iface: outbound_iface.clone(),
        masquerade_ipv4: true,
        masquerade_ipv6: false,
        preserve_source: false,
    };

    setup_nat_with_config(tun_name, &nat_config, &mut state)?;

    // Verify NAT rules exist
    let has_nat_before = check_nat_rule_exists(tun_name)?;
    assert!(has_nat_before, "NAT rule should exist before teardown");

    // Teardown
    teardown_nat(&mut state)?;

    // State should be cleared
    assert!(!state.has_nat_rules());

    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore] // Requires root or network namespace
async fn test_add_route_rule() -> Result<()> {
    if std::env::var("VPR_TEST_ROOT").is_err() {
        eprintln!("Skipping add route rule test - requires VPR_TEST_ROOT=1 or root");
        return Ok(());
    }

    let tun_name = "vpr_test_add_route";
    let gateway = IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1));
    let mut state = RoutingState::new();

    let rule = RouteRule {
        destination: "198.51.100.0/24".parse()?,
        gateway: Some(gateway),
        metric: 50,
        table: None,
    };

    add_route_rule(tun_name, gateway, &rule, &mut state)?;

    // Verify route was added to state
    assert_eq!(state.route_count(), 1);

    restore_split_tunnel(&mut state)?;

    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore] // Requires root or network namespace
async fn test_ipv6_routing_setup() -> Result<()> {
    if std::env::var("VPR_TEST_ROOT").is_err() {
        eprintln!("Skipping IPv6 routing test - requires VPR_TEST_ROOT=1 or root");
        return Ok(());
    }

    let tun_name = "vpr_test_ipv6_route";
    let gateway_v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let mut state = RoutingState::new();

    let routes = vec![RouteRule {
        destination: "2001:db8::/32".parse()?,
        gateway: Some(IpAddr::V6(gateway_v6)),
        metric: 0,
        table: None,
    }];

    setup_ipv6_routing(tun_name, gateway_v6, &routes, &mut state)?;

    // Verify route was added to state
    assert_eq!(state.route_count(), 1);

    // Restore
    restore_split_tunnel(&mut state)?;

    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore] // Requires root or network namespace
async fn test_ipv6_nat_setup() -> Result<()> {
    if std::env::var("VPR_TEST_ROOT").is_err() {
        eprintln!("Skipping IPv6 NAT test - requires VPR_TEST_ROOT=1 or root");
        return Ok(());
    }

    let tun_name = "vpr_test_ipv6_nat";
    let outbound_iface = get_default_interface()?;
    let mut state = RoutingState::new();

    setup_ipv6_nat(tun_name, &outbound_iface, &mut state)?;

    // Verify IPv6 NAT rules exist
    let has_ipv6_nat = check_ipv6_nat_rule_exists(tun_name)?;
    assert!(has_ipv6_nat, "IPv6 NAT rule should exist after setup");

    // Teardown
    teardown_nat(&mut state)?;

    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore] // Requires root or network namespace
async fn test_routing_config_full_cycle() -> Result<()> {
    if std::env::var("VPR_TEST_ROOT").is_err() {
        eprintln!("Skipping routing config full cycle test - requires VPR_TEST_ROOT=1 or root");
        return Ok(());
    }

    let tun_name = "vpr_test_full_cycle";
    let gateway = IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1));
    let mut state = RoutingState::new();

    // Create routing config with split tunnel
    let routes = vec![
        RouteRule {
            destination: "192.168.1.0/24".parse()?,
            gateway: Some(gateway),
            metric: 0,
            table: None,
        },
        RouteRule {
            destination: "10.0.0.0/8".parse()?,
            gateway: Some(gateway),
            metric: 100,
            table: Some(100),
        },
    ];

    // Setup split tunnel
    setup_split_tunnel(tun_name, gateway, &routes, &mut state)?;

    // Verify all routes were added
    assert_eq!(state.route_count(), 2);

    // Setup policy routing for one route
    let policy_routes = vec![routes[1].clone()];
    setup_policy_routing(tun_name, gateway, &policy_routes, &mut state)?;

    // Verify policy rules were added
    assert!(state.has_policy_rules());

    // Restore everything
    restore_split_tunnel(&mut state)?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn check_route_exists_network(network: &IpNetwork) -> Result<bool> {
    let output = Command::new("ip").args(["route", "show"]).output()?;
    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout.contains(&network.to_string()))
}

#[cfg(target_os = "linux")]
fn check_ipv6_nat_rule_exists(tun_name: &str) -> Result<bool> {
    let output = Command::new("ip6tables")
        .args(["-t", "nat", "-L", "-n", "-v"])
        .output()?;

    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout.contains(tun_name))
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn test_skip_on_non_linux() {
    // Tests are Linux-specific
    assert!(true);
}
