//! TUN device management for VPN tunnel
//!
//! Provides TUN device creation, configuration, and async I/O.

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use std::net::{Ipv4Addr, Ipv6Addr};
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
    /// IPv6 address (optional)
    pub address_v6: Option<Ipv6Addr>,
    /// IPv6 prefix length (optional)
    pub prefix_len_v6: Option<u8>,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            address: Ipv4Addr::new(10, 0, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: 1500,
            destination: None,
            address_v6: None,
            prefix_len_v6: None,
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
            address_v6: None,
            prefix_len_v6: None,
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
            address_v6: None,
            prefix_len_v6: None,
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
#[allow(dead_code)]
pub(crate) fn configure_tun_address(name: &str, config: &TunConfig) -> Result<()> {
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
#[allow(dead_code)]
pub(crate) fn netmask_to_cidr(netmask: &Ipv4Addr) -> u8 {
    let bits = u32::from_be_bytes(netmask.octets());
    bits.count_ones() as u8
}
