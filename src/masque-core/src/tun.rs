//! TUN device management for VPN tunnel
//!
//! Provides async TUN device creation and IP packet handling.

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use std::net::Ipv4Addr;
use std::process::Command;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio_tun::{Tun, TunBuilder};
use tracing::{info, warn};

/// Configuration for TUN device
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Device name (empty for kernel-assigned)
    pub name: String,
    /// Local IP address for the TUN interface
    pub address: Ipv4Addr,
    /// Netmask for the TUN interface
    pub netmask: Ipv4Addr,
    /// MTU (default 1500)
    pub mtu: u16,
    /// Destination address (point-to-point)
    pub destination: Option<Ipv4Addr>,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            address: Ipv4Addr::new(10, 0, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: 1500,
            destination: None,
        }
    }
}

impl TunConfig {
    /// Create client-side TUN config
    pub fn client(address: Ipv4Addr) -> Self {
        Self {
            name: "vpr0".into(),
            address,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: 1400, // Leave room for encapsulation
            destination: None,
        }
    }

    /// Create server-side TUN config
    pub fn server(address: Ipv4Addr) -> Self {
        Self {
            name: "vpr-srv0".into(),
            address,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: 1400,
            destination: None,
        }
    }
}

/// TUN device wrapper with async I/O
pub struct TunDevice {
    name: String,
    tun: Tun,
    config: TunConfig,
}

impl TunDevice {
    /// Create and configure a new TUN device
    pub async fn create(config: TunConfig) -> Result<Self> {
        let mut builder = TunBuilder::new();

        // Set name (empty = kernel assigns)
        if !config.name.is_empty() {
            builder = builder.name(&config.name);
        }

        // Configure address and netmask
        builder = builder
            .address(config.address)
            .netmask(config.netmask)
            .mtu(config.mtu as i32)
            .up();

        // Build the TUN device (TUN mode by default, no packet_info by default)
        let tun = builder.try_build().context("creating TUN device")?;

        let name = tun.name().to_string();
        info!(
            name = %name,
            address = %config.address,
            netmask = %config.netmask,
            mtu = config.mtu,
            "TUN device created and configured"
        );

        Ok(Self { name, tun, config })
    }

    /// Get device name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get device configuration
    pub fn config(&self) -> &TunConfig {
        &self.config
    }

    /// Split into read and write halves
    pub fn split(self) -> (TunReader, TunWriter) {
        let (read, write) = tokio::io::split(self.tun);
        (
            TunReader {
                inner: read,
                mtu: self.config.mtu,
            },
            TunWriter { inner: write },
        )
    }

    /// Read a single IP packet
    pub async fn read_packet(&mut self) -> Result<Bytes> {
        let mut buf = vec![0u8; self.config.mtu as usize + 4];
        let n = self.tun.read(&mut buf).await?;
        if n == 0 {
            bail!("TUN device closed");
        }
        Ok(Bytes::copy_from_slice(&buf[..n]))
    }

    /// Write a single IP packet
    pub async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.tun.write_all(packet).await?;
        Ok(())
    }
}

/// Read half of TUN device
pub struct TunReader {
    inner: ReadHalf<Tun>,
    mtu: u16,
}

impl TunReader {
    /// Read a single IP packet
    pub async fn read_packet(&mut self) -> Result<Bytes> {
        let mut buf = vec![0u8; self.mtu as usize + 4];
        let n = self.inner.read(&mut buf).await?;
        if n == 0 {
            bail!("TUN device closed");
        }
        Ok(Bytes::copy_from_slice(&buf[..n]))
    }
}

/// Write half of TUN device
pub struct TunWriter {
    inner: WriteHalf<Tun>,
}

impl TunWriter {
    /// Write a single IP packet
    pub async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.inner.write_all(packet).await?;
        Ok(())
    }
}

/// Configure TUN device IP address using ip command
fn configure_tun_address(name: &str, config: &TunConfig) -> Result<()> {
    // Set IP address
    let addr_cidr = format!("{}/{}", config.address, netmask_to_cidr(&config.netmask));
    let status = Command::new("ip")
        .args(["addr", "add", &addr_cidr, "dev", name])
        .status()
        .context("running ip addr add")?;

    if !status.success() {
        warn!(
            name = %name,
            addr = %addr_cidr,
            "ip addr add failed (may already be configured)"
        );
    }

    // Bring interface up (should already be up from TunBuilder, but ensure)
    let status = Command::new("ip")
        .args(["link", "set", name, "up"])
        .status()
        .context("running ip link set up")?;

    if !status.success() {
        bail!("failed to bring up interface {}", name);
    }

    info!(
        name = %name,
        address = %config.address,
        netmask = %config.netmask,
        "TUN device configured"
    );

    Ok(())
}

/// Convert netmask to CIDR prefix length
fn netmask_to_cidr(netmask: &Ipv4Addr) -> u8 {
    let bits = u32::from_be_bytes(netmask.octets());
    bits.count_ones() as u8
}

/// Parse IP packet header to extract basic info
#[derive(Debug, Clone)]
pub struct IpPacketInfo {
    pub version: u8,
    pub header_len: u8,
    pub total_len: u16,
    pub protocol: u8,
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
}

impl IpPacketInfo {
    /// Parse IPv4 packet header
    pub fn parse(packet: &[u8]) -> Result<Self> {
        if packet.len() < 20 {
            bail!("packet too short for IPv4 header");
        }

        let version = packet[0] >> 4;
        if version != 4 {
            bail!("not an IPv4 packet (version={})", version);
        }

        let header_len = (packet[0] & 0x0F) * 4;
        let total_len = u16::from_be_bytes([packet[2], packet[3]]);
        let protocol = packet[9];
        let src_addr = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst_addr = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

        Ok(Self {
            version,
            header_len,
            total_len,
            protocol,
            src_addr,
            dst_addr,
        })
    }

    /// Get protocol name
    pub fn protocol_name(&self) -> &'static str {
        match self.protocol {
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            _ => "OTHER",
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netmask_to_cidr() {
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
        assert_eq!(info.version, 4);
        assert_eq!(info.header_len, 20);
        assert_eq!(info.total_len, 40);
        assert_eq!(info.protocol, 6); // TCP
        assert_eq!(info.src_addr, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(info.dst_addr, Ipv4Addr::new(8, 8, 8, 8));
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
