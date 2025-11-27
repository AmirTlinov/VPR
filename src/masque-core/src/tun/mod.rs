//! TUN device and routing management for VPN tunnel
//!
//! Provides async TUN device creation, IP packet handling, routing configuration,
//! NAT, and DNS protection.

mod device;
mod dns;
pub mod ipv6;
pub mod nat;
mod packet;
pub mod routing;
pub mod split_tunnel;
pub mod state;

// Re-export main types
pub use device::{TunConfig, TunDevice, TunReader, TunWriter};
pub use dns::DnsProtection;
pub use ipv6::{setup_ipv6_nat, setup_ipv6_routing};
pub use nat::{enable_ip_forwarding, setup_nat, setup_nat_with_config, teardown_nat, NatConfig};
pub use packet::{IpAddress, IpPacketInfo, IpVersion};
pub use routing::{RouteRule, RoutingConfig, RoutingPolicy};
pub use split_tunnel::{
    add_policy_rule, add_route_rule, restore_split_tunnel, setup_policy_routing, setup_split_tunnel,
};
pub use state::RoutingState;

use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use tracing::{debug, info, warn};

/// Get current default gateway and interface from routing table
fn get_default_gateway() -> Option<(String, String)> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Parse: "default via 192.168.1.1 dev eth0 ..."
    let parts: Vec<&str> = stdout.split_whitespace().collect();
    let via_idx = parts.iter().position(|&p| p == "via")?;
    let dev_idx = parts.iter().position(|&p| p == "dev")?;
    
    let gateway = parts.get(via_idx + 1)?.to_string();
    let interface = parts.get(dev_idx + 1)?.to_string();
    
    Some((gateway, interface))
}

/// Setup routing to send traffic through TUN device.
/// 
/// IMPORTANT: Adds a host route to the VPN server through the original gateway
/// to prevent routing loop (VPN traffic going into the tunnel itself).
pub fn setup_routing(tun_name: &str, gateway: Ipv4Addr, server_ip: IpAddr) -> Result<(Option<String>, Option<String>)> {
    // Step 1: Get original default gateway BEFORE changing anything
    let original_gateway = get_default_gateway();
    
    if let Some((orig_gw, orig_iface)) = &original_gateway {
        info!(
            gateway = %orig_gw,
            interface = %orig_iface,
            "Captured original default gateway"
        );
        
        // Step 2: Add host route to VPN server through original gateway
        // This ensures QUIC traffic to server bypasses the VPN tunnel
        let server_str = server_ip.to_string();
        let host_route_status = Command::new("ip")
            .args([
                "route",
                "add",
                &server_str,
                "via",
                orig_gw,
                "dev",
                orig_iface,
            ])
            .status()
            .context("adding host route to VPN server")?;

        if host_route_status.success() {
            info!(server = %server_ip, gateway = %orig_gw, "Host route to VPN server added");
        } else {
            // May already exist or route already covers it
            debug!(server = %server_ip, "Host route addition returned non-zero (may already exist)");
        }
    } else {
        warn!("Could not determine original default gateway - VPN may break connectivity");
    }

    // Step 3: Add default route through TUN
    let gateway_str = gateway.to_string();
    let status = Command::new("ip")
        .args([
            "route",
            "add",
            "default",
            "via",
            &gateway_str,
            "dev",
            tun_name,
        ])
        .status()
        .context("adding default route")?;

    if !status.success() {
        warn!("failed to add default route (may already exist)");
    }

    info!(tun = %tun_name, gateway = %gateway, "routing configured");
    
    Ok(original_gateway.map_or((None, None), |(gw, iface)| (Some(gw), Some(iface))))
}

/// Restore routing after VPN disconnect.
/// 
/// Removes the default route through TUN and the host route to VPN server.
pub fn restore_routing(tun_name: &str, gateway: Ipv4Addr, server_ip: Option<IpAddr>) -> Result<()> {
    // Remove default route through TUN
    let gateway_str = gateway.to_string();
    let status = Command::new("ip")
        .args([
            "route",
            "del",
            "default",
            "via",
            &gateway_str,
            "dev",
            tun_name,
        ])
        .status();

    if let Ok(s) = status {
        if s.success() {
            info!(tun = %tun_name, gateway = %gateway, "default route removed");
        } else {
            debug!("failed to remove default route (may not exist)");
        }
    }

    // Remove host route to VPN server
    if let Some(server) = server_ip {
        let server_str = server.to_string();
        let host_status = Command::new("ip")
            .args(["route", "del", &server_str])
            .status();

        if let Ok(s) = host_status {
            if s.success() {
                info!(server = %server, "host route to VPN server removed");
            } else {
                debug!(server = %server, "failed to remove host route (may not exist)");
            }
        }
    }

    info!(tun = %tun_name, "routing restored");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netmask_to_cidr() {
        use device::netmask_to_cidr;
        assert_eq!(netmask_to_cidr(&Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(netmask_to_cidr(&Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(netmask_to_cidr(&Ipv4Addr::new(255, 0, 0, 0)), 8);
        assert_eq!(netmask_to_cidr(&Ipv4Addr::new(255, 255, 255, 255)), 32);
    }

    #[test]
    fn test_parse_ip_packet() {
        // Minimal IPv4 header (20 bytes)
        let packet = [
            0x45, 0x00, // Version + IHL, DSCP + ECN
            0x00, 0x28, // Total length (40 bytes)
            0x00, 0x00, 0x00, 0x00, // ID, Flags, Fragment offset
            0x40, 0x06, // TTL (64), Protocol (TCP)
            0x00, 0x00, // Header checksum
            0x0A, 0x00, 0x00, 0x01, // Source: 10.0.0.1
            0x08, 0x08, 0x08, 0x08, // Dest: 8.8.8.8
        ];

        let info = IpPacketInfo::parse(&packet).unwrap();
        assert_eq!(info.version, IpVersion::V4);
        assert_eq!(info.header_len, 20);
        assert_eq!(info.total_len, 40);
        assert_eq!(info.protocol, 6); // TCP
        assert_eq!(info.src_addr.as_ipv4(), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(info.dst_addr.as_ipv4(), Some(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(info.protocol_name(), "TCP");
    }

    #[test]
    fn test_tun_config_defaults() {
        let config = TunConfig::default();
        assert_eq!(config.address, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(config.mtu, 1500);
    }

    #[test]
    fn test_tun_config_client() {
        let config = TunConfig::client(Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(config.name, "vpr0");
        assert_eq!(config.address, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(config.mtu, 1400);
    }
}
