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
pub use nat::{enable_ip_forwarding, setup_nat, setup_nat_with_config, teardown_nat, NatConfig};
pub use packet::{IpAddress, IpPacketInfo, IpVersion};
pub use routing::{RouteRule, RoutingConfig, RoutingPolicy};
pub use split_tunnel::{
    add_policy_rule, add_route_rule, restore_split_tunnel, setup_policy_routing,
    setup_split_tunnel,
};
pub use state::RoutingState;
pub use ipv6::{setup_ipv6_nat, setup_ipv6_routing};

use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::process::Command;
use tracing::{info, warn};

/// Setup routing to send traffic through TUN device
pub fn setup_routing(tun_name: &str, gateway: Ipv4Addr) -> Result<()> {
    // Add default route through TUN
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
    Ok(())
}

/// Restore routing after VPN disconnect
pub fn restore_routing(tun_name: &str, gateway: Ipv4Addr) -> Result<()> {
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

    // Игнорируем ошибки, так как маршрут может уже не существовать
    if let Ok(s) = status {
        if s.success() {
            info!(tun = %tun_name, gateway = %gateway, "routing restored");
        } else {
            warn!("failed to remove default route (may not exist)");
        }
    }

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
