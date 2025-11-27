//! IPv6 routing and NAT for VPN tunnel
//!
//! Provides IPv6-specific routing and NAT configuration.

use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use std::net::{IpAddr, Ipv6Addr};
use std::process::Command;
use tracing::{info, warn};

use super::nat::iptables_rule_exists;
use super::routing::RouteRule;
use super::state::RoutingState;

/// Setup IPv6 routing
pub fn setup_ipv6_routing(
    tun_name: &str,
    gateway_v6: Ipv6Addr,
    routes: &[RouteRule],
    state: &mut RoutingState,
) -> Result<()> {
    // Enable IPv6 forwarding
    std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")
        .context("enabling IPv6 forwarding")?;

    for rule in routes {
        if let IpNetwork::V6(net) = rule.destination {
            let mut args = vec!["-6".to_string(), "route".to_string(), "add".to_string()];
            args.push(net.to_string());

            if let Some(IpAddr::V6(gw_v6)) = rule.gateway {
                args.push("via".to_string());
                args.push(gw_v6.to_string());
            } else {
                args.push("via".to_string());
                args.push(gateway_v6.to_string());
            }

            args.push("dev".to_string());
            args.push(tun_name.to_string());

            if rule.metric > 0 {
                args.push("metric".to_string());
                args.push(rule.metric.to_string());
            }

            if let Some(table) = rule.table {
                args.push("table".to_string());
                args.push(table.to_string());
            }

            let status = Command::new("ip")
                .args(&args)
                .status()
                .context("adding IPv6 route")?;

            if !status.success() {
                warn!(route = %net, "Failed to add IPv6 route");
            } else {
                // Prepare delete args
                let mut delete_args =
                    vec!["-6".to_string(), "route".to_string(), "del".to_string()];
                delete_args.push(net.to_string());
                if let Some(IpAddr::V6(gw_v6)) = rule.gateway {
                    delete_args.push("via".to_string());
                    delete_args.push(gw_v6.to_string());
                } else {
                    delete_args.push("via".to_string());
                    delete_args.push(gateway_v6.to_string());
                }
                delete_args.push("dev".to_string());
                delete_args.push(tun_name.to_string());
                if let Some(table) = rule.table {
                    delete_args.push("table".to_string());
                    delete_args.push(table.to_string());
                }

                state.add_route(rule.destination, delete_args);
            }
        }
    }

    info!(
        tun = %tun_name,
        gateway_v6 = %gateway_v6,
        route_count = routes.len(),
        "IPv6 routing configured"
    );
    Ok(())
}

/// Setup IPv6 NAT masquerading
pub fn setup_ipv6_nat(
    tun_name: &str,
    outbound_iface: &str,
    state: &mut RoutingState,
) -> Result<()> {
    // Enable IPv6 forwarding
    std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")
        .context("enabling IPv6 forwarding")?;

    // IPv6 NAT - check if rule exists (suppresses "Bad rule" stderr)
    let nat_exists = iptables_rule_exists(
        "ip6tables",
        &[
            "-t",
            "nat",
            "-C",
            "POSTROUTING",
            "-o",
            outbound_iface,
            "-j",
            "MASQUERADE",
        ],
    );

    if !nat_exists {
        let status = Command::new("ip6tables")
            .args([
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                outbound_iface,
                "-j",
                "MASQUERADE",
            ])
            .status()
            .context("setting up IPv6 NAT")?;

        if status.success() {
            let delete_args = vec![
                "-t".to_string(),
                "nat".to_string(),
                "-D".to_string(),
                "POSTROUTING".to_string(),
                "-o".to_string(),
                outbound_iface.to_string(),
                "-j".to_string(),
                "MASQUERADE".to_string(),
            ];
            state.add_nat_rule(delete_args);
        }
    }

    // Forward rules - check if rule exists (suppresses "Bad rule" stderr)
    let forward_exists = iptables_rule_exists(
        "ip6tables",
        &[
            "-C",
            "FORWARD",
            "-i",
            tun_name,
            "-o",
            outbound_iface,
            "-j",
            "ACCEPT",
        ],
    );

    if !forward_exists {
        let status = Command::new("ip6tables")
            .args([
                "-A",
                "FORWARD",
                "-i",
                tun_name,
                "-o",
                outbound_iface,
                "-j",
                "ACCEPT",
            ])
            .status()
            .context("allowing IPv6 forward from TUN")?;

        if status.success() {
            let delete_args = vec![
                "-D".to_string(),
                "FORWARD".to_string(),
                "-i".to_string(),
                tun_name.to_string(),
                "-o".to_string(),
                outbound_iface.to_string(),
                "-j".to_string(),
                "ACCEPT".to_string(),
            ];
            state.add_nat_rule(delete_args);
        }
    }

    // Established connections - check if rule exists (suppresses "Bad rule" stderr)
    let established_exists = iptables_rule_exists(
        "ip6tables",
        &[
            "-C",
            "FORWARD",
            "-i",
            outbound_iface,
            "-o",
            tun_name,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
    );

    if !established_exists {
        let status = Command::new("ip6tables")
            .args([
                "-A",
                "FORWARD",
                "-i",
                outbound_iface,
                "-o",
                tun_name,
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ])
            .status()
            .context("allowing IPv6 established connections")?;

        if status.success() {
            let delete_args = vec![
                "-D".to_string(),
                "FORWARD".to_string(),
                "-i".to_string(),
                outbound_iface.to_string(),
                "-o".to_string(),
                tun_name.to_string(),
                "-m".to_string(),
                "state".to_string(),
                "--state".to_string(),
                "RELATED,ESTABLISHED".to_string(),
                "-j".to_string(),
                "ACCEPT".to_string(),
            ];
            state.add_nat_rule(delete_args);
        }
    }

    info!(
        tun = %tun_name,
        outbound = %outbound_iface,
        "IPv6 NAT masquerading configured"
    );
    Ok(())
}
