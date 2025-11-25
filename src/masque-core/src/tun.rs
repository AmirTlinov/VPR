//! TUN device management for VPN tunnel
//!
//! Provides async TUN device creation and IP packet handling.

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use ipnetwork::IpNetwork;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::{Command, Stdio};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio_tun::{Tun, TunBuilder};
use tracing::{info, warn};

/// Routing policy for VPN tunnel
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingPolicy {
    /// Full tunnel - весь трафик через VPN
    Full,
    /// Split tunnel - только указанные сети через VPN
    Split,
    /// Bypass tunnel - указанные сети обходят VPN
    Bypass,
}

/// Route rule for routing configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RouteRule {
    /// Целевая сеть (CIDR notation as string)
    #[serde(with = "ipnetwork_serde")]
    pub destination: IpNetwork,
    /// Шлюз (опционально)
    pub gateway: Option<IpAddr>,
    /// Метрика маршрута
    pub metric: u32,
    /// Routing table ID (опционально)
    pub table: Option<u32>,
}

/// Routing configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RoutingConfig {
    /// Routing policy
    #[serde(with = "routing_policy_serde")]
    pub policy: RoutingPolicy,
    /// Список правил маршрутизации
    pub routes: Vec<RouteRule>,
    /// DNS серверы
    pub dns_servers: Vec<IpAddr>,
    /// Включена ли поддержка IPv6
    pub ipv6_enabled: bool,
}

impl RoutingConfig {
    /// Validate routing configuration
    pub fn validate(&self) -> Result<()> {
        // Validate policy and routes consistency
        match self.policy {
            RoutingPolicy::Split | RoutingPolicy::Bypass => {
                if self.routes.is_empty() {
                    bail!(
                        "Routing policy {:?} requires at least one route",
                        self.policy
                    );
                }
            }
            RoutingPolicy::Full => {
                // Full tunnel doesn't require routes, but if provided, they should be valid
            }
        }

        // Validate routes
        for (idx, route) in self.routes.iter().enumerate() {
            // Check if gateway matches network family
            if let Some(gateway) = route.gateway {
                match (route.destination, gateway) {
                    (IpNetwork::V4(_), IpAddr::V6(_)) => {
                        bail!("Route {}: IPv4 destination with IPv6 gateway", idx);
                    }
                    (IpNetwork::V6(_), IpAddr::V4(_)) => {
                        bail!("Route {}: IPv6 destination with IPv4 gateway", idx);
                    }
                    _ => {}
                }
            }
        }

        // Validate DNS servers
        for dns in &self.dns_servers {
            match dns {
                IpAddr::V4(_) | IpAddr::V6(_) => {} // Valid
            }
        }

        Ok(())
    }

    /// Check if configuration has IPv6 routes
    pub fn has_ipv6_routes(&self) -> bool {
        self.routes
            .iter()
            .any(|r| matches!(r.destination, IpNetwork::V6(_)))
    }

    /// Get IPv6 routes
    pub fn ipv6_routes(&self) -> Vec<&RouteRule> {
        self.routes
            .iter()
            .filter(|r| matches!(r.destination, IpNetwork::V6(_)))
            .collect()
    }

    /// Get IPv4 routes
    pub fn ipv4_routes(&self) -> Vec<&RouteRule> {
        self.routes
            .iter()
            .filter(|r| matches!(r.destination, IpNetwork::V4(_)))
            .collect()
    }
}

// Serde helpers for IpNetwork
mod ipnetwork_serde {
    use ipnetwork::IpNetwork;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(network: &IpNetwork, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        network.to_string().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<IpNetwork, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// Serde helpers for RoutingPolicy
mod routing_policy_serde {
    use super::RoutingPolicy;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(policy: &RoutingPolicy, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match policy {
            RoutingPolicy::Full => "full".serialize(serializer),
            RoutingPolicy::Split => "split".serialize(serializer),
            RoutingPolicy::Bypass => "bypass".serialize(serializer),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<RoutingPolicy, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "full" => Ok(RoutingPolicy::Full),
            "split" => Ok(RoutingPolicy::Split),
            "bypass" => Ok(RoutingPolicy::Bypass),
            _ => Err(serde::de::Error::custom(format!(
                "Unknown routing policy: {}",
                s
            ))),
        }
    }
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            policy: RoutingPolicy::Full,
            routes: vec![],
            dns_servers: vec![],
            ipv6_enabled: false,
        }
    }
}

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
#[allow(dead_code)]
fn netmask_to_cidr(netmask: &Ipv4Addr) -> u8 {
    let bits = u32::from_be_bytes(netmask.octets());
    bits.count_ones() as u8
}

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
fn iptables_rule_exists(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// State for tracking added routes and NAT rules for cleanup
#[derive(Debug, Clone, Default)]
pub struct RoutingState {
    /// Added routes (destination -> command args for deletion)
    routes: Vec<(IpNetwork, Vec<String>)>,
    /// Added policy rules (priority -> command args for deletion)
    policy_rules: Vec<(u32, Vec<String>)>,
    /// NAT rules added (for cleanup)
    nat_rules: Vec<Vec<String>>,
}

impl RoutingState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_route(&mut self, destination: IpNetwork, delete_args: Vec<String>) {
        self.routes.push((destination, delete_args));
    }

    pub fn add_policy_rule(&mut self, priority: u32, delete_args: Vec<String>) {
        self.policy_rules.push((priority, delete_args));
    }

    pub fn add_nat_rule(&mut self, delete_args: Vec<String>) {
        self.nat_rules.push(delete_args);
    }

    /// Get number of routes
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Get number of policy rules
    pub fn policy_rule_count(&self) -> usize {
        self.policy_rules.len()
    }

    /// Get number of NAT rules
    pub fn nat_rule_count(&self) -> usize {
        self.nat_rules.len()
    }

    /// Check if has any routes
    pub fn has_routes(&self) -> bool {
        !self.routes.is_empty()
    }

    /// Check if has any policy rules
    pub fn has_policy_rules(&self) -> bool {
        !self.policy_rules.is_empty()
    }

    /// Check if has any NAT rules
    pub fn has_nat_rules(&self) -> bool {
        !self.nat_rules.is_empty()
    }
}

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
    for (destination, delete_args) in &state.routes {
        let status = Command::new("ip").args(delete_args).status();

        if let Ok(s) = status {
            if !s.success() {
                errors.push(format!("Failed to remove route for {}", destination));
            }
        }
    }

    // Remove all policy rules
    for (_priority, delete_args) in &state.policy_rules {
        let status = Command::new("ip").args(delete_args).status();

        if let Ok(s) = status {
            if !s.success() {
                errors.push("Failed to remove policy rule".to_string());
            }
        }
    }

    state.routes.clear();
    state.policy_rules.clear();

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

    // Add fwmark if needed (can be extended)
    // For now, we use source-based routing

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

/// Setup NAT masquerading with improved configuration
pub fn setup_nat_with_config(
    tun_name: &str,
    config: &NatConfig,
    state: &mut RoutingState,
) -> Result<()> {
    if config.masquerade_ipv4 {
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
    }

    if config.masquerade_ipv6 {
        setup_ipv6_nat(tun_name, &config.outbound_iface, state)?;
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

/// Teardown NAT - remove all added NAT rules
pub fn teardown_nat(state: &mut RoutingState) -> Result<()> {
    let mut errors = Vec::new();

    for delete_args in &state.nat_rules {
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

    state.nat_rules.clear();

    if !errors.is_empty() {
        warn!(errors = ?errors, "Some NAT rules failed to remove");
    } else {
        info!("NAT teardown complete");
    }

    Ok(())
}

/// DNS leak protection configuration
pub struct DnsProtection {
    /// Original resolv.conf backup
    backup_path: Option<std::path::PathBuf>,
    /// Whether protection is active
    active: bool,
}

impl DnsProtection {
    /// Create new DNS protection instance
    pub fn new() -> Self {
        Self {
            backup_path: None,
            active: false,
        }
    }

    /// Enable DNS leak protection with specified DNS servers
    pub fn enable(&mut self, dns_servers: &[IpAddr]) -> Result<()> {
        if self.active {
            return Ok(());
        }

        let resolv_path = std::path::Path::new("/etc/resolv.conf");
        let backup_path = std::path::PathBuf::from("/tmp/vpr-resolv.conf.bak");

        // Check if we have write permissions (typically requires root)
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(meta) = resolv_path.metadata() {
                // Check if we're root (uid 0) or owner
                // SAFETY: libc::geteuid() is a safe POSIX system call that returns the effective
                // user ID of the calling process. It has no side effects, takes no parameters,
                // and cannot fail. The returned uid_t is a simple integer value.
                let euid = unsafe { libc::geteuid() };
                let file_uid = meta.uid();
                if euid != 0 && euid != file_uid {
                    bail!(
                        "DNS protection requires root privileges (euid={}, file owner={})",
                        euid,
                        file_uid
                    );
                }
            }
        }

        // Backup original resolv.conf
        if resolv_path.exists() {
            std::fs::copy(resolv_path, &backup_path).context("backing up resolv.conf")?;
            self.backup_path = Some(backup_path);
        }

        // Write new resolv.conf with VPN DNS servers
        let mut content = String::from("# VPR VPN DNS configuration\n");
        for dns in dns_servers {
            content.push_str(&format!("nameserver {}\n", dns));
        }

        std::fs::write(resolv_path, &content).context("writing resolv.conf")?;

        self.active = true;
        info!(dns_servers = ?dns_servers, "DNS leak protection enabled");
        Ok(())
    }

    /// Restore original DNS configuration
    pub fn disable(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }

        let resolv_path = std::path::Path::new("/etc/resolv.conf");

        if let Some(backup) = &self.backup_path {
            if backup.exists() {
                std::fs::copy(backup, resolv_path).context("restoring resolv.conf")?;
                let _ = std::fs::remove_file(backup);
            }
        }

        self.active = false;
        self.backup_path = None;
        info!("DNS leak protection disabled, original config restored");
        Ok(())
    }

    /// Check if DNS protection is active
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Default for DnsProtection {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DnsProtection {
    fn drop(&mut self) {
        if self.active {
            if let Err(e) = self.disable() {
                warn!(%e, "Failed to restore DNS on drop");
            }
        }
    }
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
