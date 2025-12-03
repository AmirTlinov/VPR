//! Split tunnel routing for VPN
//!
//! Provides split tunnel configuration and policy-based routing.

use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::process::Command;
use tracing::{info, warn};

use super::routing::RouteRule;
use super::state::RoutingState;

/// Setup split tunnel routing
/// Adds routes only for specified networks and saves original routes for restoration
pub fn setup_split_tunnel(
    tun_name: &str,
    gateway: IpAddr,
    routes: &[RouteRule],
    state: &mut RoutingState,
) -> Result<()> {
    for rule in routes {
        add_route_rule(tun_name, gateway, rule, state)?;
    }

    info!(
        tun = %tun_name,
        route_count = routes.len(),
        "Split tunnel configured"
    );
    Ok(())
}

/// Restore split tunnel - removes added routes
pub fn restore_split_tunnel(state: &mut RoutingState) -> Result<()> {
    let mut errors = Vec::new();

    // Remove all added routes
    for (destination, delete_args) in state.routes() {
        let status = Command::new("ip").args(delete_args).status();

        if let Ok(s) = status {
            if !s.success() {
                errors.push(format!("Failed to remove route for {}", destination));
            }
        }
    }

    // Remove all policy rules
    for (_priority, delete_args) in state.policy_rules() {
        let status = Command::new("ip").args(delete_args).status();

        if let Ok(s) = status {
            if !s.success() {
                errors.push("Failed to remove policy rule".to_string());
            }
        }
    }

    state.clear_routes();
    state.clear_policy_rules();

    if !errors.is_empty() {
        warn!(errors = ?errors, "Some routes failed to restore");
    } else {
        info!("Split tunnel restored");
    }

    Ok(())
}

/// Add a specific route rule
pub fn add_route_rule(
    tun_name: &str,
    gateway: IpAddr,
    rule: &RouteRule,
    state: &mut RoutingState,
) -> Result<()> {
    let mut args = vec!["route".to_string(), "add".to_string()];

    // Add destination network
    args.push(rule.destination.to_string());

    // Add gateway if specified
    if let Some(gw) = rule.gateway {
        args.push("via".to_string());
        args.push(gw.to_string());
    } else {
        args.push("via".to_string());
        args.push(gateway.to_string());
    }

    args.push("dev".to_string());
    args.push(tun_name.to_string());

    // Add metric if specified
    if rule.metric > 0 {
        args.push("metric".to_string());
        args.push(rule.metric.to_string());
    }

    // Add table if specified
    if let Some(table) = rule.table {
        args.push("table".to_string());
        args.push(table.to_string());
    }

    let status = Command::new("ip")
        .args(&args)
        .status()
        .context("adding route rule")?;

    if !status.success() {
        warn!(route = ?rule.destination, "Failed to add route (may already exist)");
    } else {
        // Prepare delete args for cleanup
        let mut delete_args = vec!["route".to_string(), "del".to_string()];
        delete_args.push(rule.destination.to_string());
        if let Some(gw) = rule.gateway {
            delete_args.push("via".to_string());
            delete_args.push(gw.to_string());
        } else {
            delete_args.push("via".to_string());
            delete_args.push(gateway.to_string());
        }
        delete_args.push("dev".to_string());
        delete_args.push(tun_name.to_string());
        if let Some(table) = rule.table {
            delete_args.push("table".to_string());
            delete_args.push(table.to_string());
        }

        state.add_route(rule.destination, delete_args);
    }

    Ok(())
}

/// Setup policy-based routing
pub fn setup_policy_routing(
    tun_name: &str,
    gateway: IpAddr,
    rules: &[RouteRule],
    state: &mut RoutingState,
) -> Result<()> {
    for (priority, rule) in rules.iter().enumerate() {
        let prio = (priority as u32 + 1000) * 10; // Start from 10000
        add_policy_rule(tun_name, gateway, rule, prio, state)?;
    }

    info!(
        tun = %tun_name,
        rule_count = rules.len(),
        "Policy-based routing configured"
    );
    Ok(())
}

/// Add a policy rule
pub fn add_policy_rule(
    tun_name: &str,
    gateway: IpAddr,
    rule: &RouteRule,
    priority: u32,
    state: &mut RoutingState,
) -> Result<()> {
    let mut args = vec!["rule".to_string(), "add".to_string()];

    // Add priority
    args.push("priority".to_string());
    args.push(priority.to_string());

    // Add source-based routing if destination is a network
    match rule.destination {
        IpNetwork::V4(net) => {
            args.push("from".to_string());
            args.push(net.to_string());
        }
        IpNetwork::V6(net) => {
            args.push("from".to_string());
            args.push(net.to_string());
        }
    }

    // Add table
    let table = rule.table.unwrap_or(100); // Default custom table
    args.push("table".to_string());
    args.push(table.to_string());

    let status = Command::new("ip")
        .args(&args)
        .status()
        .context("adding policy rule")?;

    if !status.success() {
        warn!(
            priority = priority,
            "Failed to add policy rule (may already exist)"
        );
    } else {
        // Prepare delete args
        let mut delete_args = vec!["rule".to_string(), "del".to_string()];
        delete_args.push("priority".to_string());
        delete_args.push(priority.to_string());
        match rule.destination {
            IpNetwork::V4(net) => {
                delete_args.push("from".to_string());
                delete_args.push(net.to_string());
            }
            IpNetwork::V6(net) => {
                delete_args.push("from".to_string());
                delete_args.push(net.to_string());
            }
        }
        delete_args.push("table".to_string());
        delete_args.push(table.to_string());

        state.add_policy_rule(priority, delete_args);
    }

    // Add route in the custom table
    let mut route_args = vec!["route".to_string(), "add".to_string()];
    route_args.push(rule.destination.to_string());
    route_args.push("via".to_string());
    route_args.push(rule.gateway.unwrap_or(gateway).to_string());
    route_args.push("dev".to_string());
    route_args.push(tun_name.to_string());
    route_args.push("table".to_string());
    route_args.push(table.to_string());

    if rule.metric > 0 {
        route_args.push("metric".to_string());
        route_args.push(rule.metric.to_string());
    }

    let status = Command::new("ip")
        .args(&route_args)
        .status()
        .context("adding route in policy table")?;

    if !status.success() {
        warn!("Failed to add route in policy table");
    }

    Ok(())
}
