//! IP packet parsing for VPN tunnel
//!
//! Provides IP packet header parsing for both IPv4 and IPv6.

use anyhow::{bail, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IP version enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

/// Generic IP address enum for both IPv4 and IPv6
#[derive(Debug, Clone, Copy)]
pub enum IpAddress {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl std::fmt::Display for IpAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpAddress::V4(addr) => write!(f, "{}", addr),
            IpAddress::V6(addr) => write!(f, "{}", addr),
        }
    }
}

impl IpAddress {
    /// Try to convert to IPv4 address
    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        match self {
            IpAddress::V4(addr) => Some(*addr),
            IpAddress::V6(_) => None,
        }
    }

    /// Try to convert to IPv6 address
    pub fn as_ipv6(&self) -> Option<Ipv6Addr> {
        match self {
            IpAddress::V4(_) => None,
            IpAddress::V6(addr) => Some(*addr),
        }
    }

    /// Convert to generic IpAddr
    pub fn to_ip_addr(&self) -> IpAddr {
        match self {
            IpAddress::V4(addr) => IpAddr::V4(*addr),
            IpAddress::V6(addr) => IpAddr::V6(*addr),
        }
    }
}

/// Parse IP packet header to extract basic info (supports both IPv4 and IPv6)
#[derive(Debug, Clone)]
pub struct IpPacketInfo {
    pub version: IpVersion,
    pub header_len: u8,
    pub total_len: u16,
    pub protocol: u8,
    pub src_addr: IpAddress,
    pub dst_addr: IpAddress,
}

impl IpPacketInfo {
    /// Parse IP packet header (IPv4 or IPv6)
    pub fn parse(packet: &[u8]) -> Result<Self> {
        if packet.is_empty() {
            bail!("empty packet");
        }

        let version = packet[0] >> 4;
        match version {
            4 => Self::parse_ipv4(packet),
            6 => Self::parse_ipv6(packet),
            _ => bail!("unknown IP version: {}", version),
        }
    }

    /// Parse IPv4 packet header
    fn parse_ipv4(packet: &[u8]) -> Result<Self> {
        if packet.len() < 20 {
            bail!("packet too short for IPv4 header");
        }

        let header_len = (packet[0] & 0x0F) * 4;
        let total_len = u16::from_be_bytes([packet[2], packet[3]]);
        let protocol = packet[9];
        let src_addr = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst_addr = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

        Ok(Self {
            version: IpVersion::V4,
            header_len,
            total_len,
            protocol,
            src_addr: IpAddress::V4(src_addr),
            dst_addr: IpAddress::V4(dst_addr),
        })
    }

    /// Parse IPv6 packet header
    fn parse_ipv6(packet: &[u8]) -> Result<Self> {
        // IPv6 header is always 40 bytes (without extension headers)
        if packet.len() < 40 {
            bail!("packet too short for IPv6 header");
        }

        // IPv6 header layout:
        // 0-3: version (4 bits), traffic class (8 bits), flow label (20 bits)
        // 4-5: payload length
        // 6: next header (protocol)
        // 7: hop limit
        // 8-23: source address (128 bits)
        // 24-39: destination address (128 bits)

        let payload_len = u16::from_be_bytes([packet[4], packet[5]]);
        let next_header = packet[6];
        // Total length = header (40) + payload
        let total_len = 40u16.saturating_add(payload_len);

        let src_octets: [u8; 16] = packet[8..24].try_into().unwrap();
        let dst_octets: [u8; 16] = packet[24..40].try_into().unwrap();

        let src_addr = Ipv6Addr::from(src_octets);
        let dst_addr = Ipv6Addr::from(dst_octets);

        Ok(Self {
            version: IpVersion::V6,
            header_len: 40, // IPv6 fixed header is always 40 bytes
            total_len,
            protocol: next_header,
            src_addr: IpAddress::V6(src_addr),
            dst_addr: IpAddress::V6(dst_addr),
        })
    }

    /// Check if this is an IPv4 packet
    pub fn is_ipv4(&self) -> bool {
        self.version == IpVersion::V4
    }

    /// Check if this is an IPv6 packet
    pub fn is_ipv6(&self) -> bool {
        self.version == IpVersion::V6
    }

    /// Get protocol name
    pub fn protocol_name(&self) -> &'static str {
        match (self.version, self.protocol) {
            // IPv4 protocols
            (IpVersion::V4, 1) => "ICMP",
            (IpVersion::V4, 6) => "TCP",
            (IpVersion::V4, 17) => "UDP",
            // IPv6 protocols (next header values)
            (IpVersion::V6, 6) => "TCP",
            (IpVersion::V6, 17) => "UDP",
            (IpVersion::V6, 58) => "ICMPv6",
            (IpVersion::V6, 0) => "HOP-BY-HOP",
            (IpVersion::V6, 43) => "ROUTING",
            (IpVersion::V6, 44) => "FRAGMENT",
            (IpVersion::V6, 60) => "DESTINATION",
            (IpVersion::V6, 59) => "NO-NEXT",
            _ => "OTHER",
        }
    }
}
