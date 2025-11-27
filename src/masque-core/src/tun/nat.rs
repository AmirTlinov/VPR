//! NAT configuration and management for VPN tunnel
//!
//! Provides NAT masquerading and IP forwarding functionality.

use anyhow::{Context, Result};
use std::process::{Command, Stdio};
use tracing::{info, warn};

use super::state::RoutingState;

/// NAT configuration
#[derive(Debug, Clone)]
pub struct NatConfig {
    /// Outbound interface name
    pub outbound_iface: String,
    /// Enable IPv4 masquerading
    pub masquerade_ipv4: bool,
    /// Enable IPv6 masquerading
    pub masquerade_ipv6: bool,
    /// Preserve source address
    pub preserve_source: bool,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            outbound_iface: String::new(),
            masquerade_ipv4: true,
            masquerade_ipv6: false,
            preserve_source: false,
        }
    }
}

/// Enable IP forwarding (for server mode)
pub fn enable_ip_forwarding() -> Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").context("enabling IP forwarding")?;
    info!("IP forwarding enabled");
    Ok(())
}

/// Setup NAT masquerading (for server mode)
pub fn setup_nat(tun_name: &str, outbound_iface: &str) -> Result<()> {
    // Enable masquerading for outbound traffic
    let status = Command::new("iptables")
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
        .context("setting up NAT")?;

    if !status.success() {
        warn!("iptables NAT setup may have failed");
    }

    // Allow forwarding from TUN to outbound
    let status = Command::new("iptables")
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
        .context("allowing forward from TUN")?;

    if !status.success() {
        warn!("iptables forward rule may have failed");
    }

    // Allow established connections back
    let status = Command::new("iptables")
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
        .context("allowing established connections")?;

    if !status.success() {
        warn!("iptables established rule may have failed");
    }

    info!(
        tun = %tun_name,
        outbound = %outbound_iface,
        "NAT masquerading configured"
    );
    Ok(())
}

/// Check if an iptables rule exists (suppresses "Bad rule" stderr output)
pub(crate) fn iptables_rule_exists(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Setup NAT with configuration (advanced)
pub fn setup_nat_with_config(
    tun_name: &str,
    config: &NatConfig,
    state: &mut RoutingState,
) -> Result<()> {
    if config.masquerade_ipv4 {
        setup_ipv4_nat(tun_name, config, state)?;
    }

    if config.masquerade_ipv6 {
        super::ipv6::setup_ipv6_nat(tun_name, &config.outbound_iface, state)?;
    }

    info!(
        tun = %tun_name,
        outbound = %config.outbound_iface,
        ipv4 = config.masquerade_ipv4,
        ipv6 = config.masquerade_ipv6,
        "NAT masquerading configured with config"
    );
    Ok(())
}

/// Setup IPv4 NAT rules
fn setup_ipv4_nat(tun_name: &str, config: &NatConfig, state: &mut RoutingState) -> Result<()> {
    // IPv4 NAT - check if rule exists (suppresses "Bad rule" stderr)
    let nat_exists = iptables_rule_exists(
        "iptables",
        &[
            "-t",
            "nat",
            "-C",
            "POSTROUTING",
            "-o",
            &config.outbound_iface,
            "-j",
            "MASQUERADE",
        ],
    );

    if !nat_exists {
        let add_status = Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                &config.outbound_iface,
                "-j",
                "MASQUERADE",
            ])
            .status()
            .context("setting up IPv4 NAT")?;

        if add_status.success() {
            let delete_args = vec![
                "-t".to_string(),
                "nat".to_string(),
                "-D".to_string(),
                "POSTROUTING".to_string(),
                "-o".to_string(),
                config.outbound_iface.clone(),
                "-j".to_string(),
                "MASQUERADE".to_string(),
            ];
            state.add_nat_rule(delete_args);
        }
    }

    // Forward rules - check if rule exists (suppresses "Bad rule" stderr)
    let forward_exists = iptables_rule_exists(
        "iptables",
        &[
            "-C",
            "FORWARD",
            "-i",
            tun_name,
            "-o",
            &config.outbound_iface,
            "-j",
            "ACCEPT",
        ],
    );

    if !forward_exists {
        let add_status = Command::new("iptables")
            .args([
                "-A",
                "FORWARD",
                "-i",
                tun_name,
                "-o",
                &config.outbound_iface,
                "-j",
                "ACCEPT",
            ])
            .status()
            .context("allowing forward from TUN")?;

        if add_status.success() {
            let delete_args = vec![
                "-D".to_string(),
                "FORWARD".to_string(),
                "-i".to_string(),
                tun_name.to_string(),
                "-o".to_string(),
                config.outbound_iface.clone(),
                "-j".to_string(),
                "ACCEPT".to_string(),
            ];
            state.add_nat_rule(delete_args);
        }
    }

    // Established connections - check if rule exists (suppresses "Bad rule" stderr)
    let established_exists = iptables_rule_exists(
        "iptables",
        &[
            "-C",
            "FORWARD",
            "-i",
            &config.outbound_iface,
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
        let add_status = Command::new("iptables")
            .args([
                "-A",
                "FORWARD",
                "-i",
                &config.outbound_iface,
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
            .context("allowing established connections")?;

        if add_status.success() {
            let delete_args = vec![
                "-D".to_string(),
                "FORWARD".to_string(),
                "-i".to_string(),
                config.outbound_iface.clone(),
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

    Ok(())
}

/// Teardown NAT - remove all added NAT rules
pub fn teardown_nat(state: &mut RoutingState) -> Result<()> {
    let mut errors = Vec::new();

    for delete_args in state.nat_rules() {
        // Determine if it's ip6tables or iptables
        let cmd = if delete_args.iter().any(|a| a == "-6") {
            "ip6tables"
        } else {
            // Check for "-t nat" pattern to determine if it's iptables
            // Default to iptables if pattern not found
            "iptables"
        };

        let status = Command::new(cmd).args(delete_args).status();

        if let Ok(s) = status {
            if !s.success() {
                errors.push(format!("Failed to remove NAT rule: {:?}", delete_args));
            }
        }
    }

    state.clear_nat_rules();

    if !errors.is_empty() {
        warn!(errors = ?errors, "Some NAT rules failed to remove");
    } else {
        info!("NAT teardown complete");
    }

    Ok(())
}
