//! CLI argument definitions for VPN server.

use clap::Parser;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

/// VPR VPN Server CLI arguments
#[derive(Parser, Debug)]
#[command(name = "vpn-server", version, about = "VPR VPN server with TUN tunnel")]
pub struct Args {
    /// QUIC bind address
    #[arg(long, default_value = "0.0.0.0:4433")]
    pub bind: SocketAddr,

    /// TUN device name
    #[arg(long, default_value = "vpr-srv0")]
    pub tun_name: String,

    /// Server TUN IP address (gateway for clients)
    #[arg(long, default_value = "10.9.0.1")]
    pub tun_addr: Ipv4Addr,

    /// TUN netmask
    #[arg(long, default_value = "255.255.255.0")]
    pub tun_netmask: Ipv4Addr,

    /// DNS servers to push to clients (comma-separated). Defaults to public resolvers if empty.
    #[arg(long, value_delimiter = ',')]
    pub dns_servers: Vec<IpAddr>,

    /// MTU for TUN device
    #[arg(long, default_value = "1400")]
    pub mtu: u16,

    /// Start of client IP pool
    #[arg(long, default_value = "10.9.0.2")]
    pub pool_start: Ipv4Addr,

    /// End of client IP pool
    #[arg(long, default_value = "10.9.0.254")]
    pub pool_end: Ipv4Addr,

    /// Padding strategy: none|bucket|rand-bucket|mtu
    #[arg(long, default_value = "rand-bucket")]
    pub padding_strategy: String,

    /// Maximum jitter for padded sends (microseconds). 0 disables jitter.
    #[arg(long, default_value = "5000")]
    pub padding_max_jitter_us: u64,

    /// Minimum padded packet size (bytes)
    #[arg(long, default_value = "32")]
    pub padding_min_size: usize,

    /// Override MTU for padding (defaults to TUN MTU)
    #[arg(long)]
    pub padding_mtu: Option<u16>,

    /// Cover traffic base rate (pps)
    #[arg(long, default_value = "8.0")]
    pub cover_traffic_rate: f64,

    /// Cover traffic pattern: https|h3|webrtc|idle
    #[arg(long, default_value = "https")]
    pub cover_traffic_pattern: String,

    /// Probe protection: PoW difficulty (leading zero bytes)
    #[arg(long, default_value = "2")]
    pub probe_difficulty: u8,

    /// Probe protection: max failed attempts before ban
    #[arg(long, default_value = "3")]
    pub probe_max_failed_attempts: u32,

    /// Probe protection: ban duration seconds
    #[arg(long, default_value = "300")]
    pub probe_ban_seconds: u64,

    /// Probe protection: min handshake time ms (too fast -> suspicious)
    #[arg(long, default_value = "50")]
    pub probe_min_handshake_ms: u64,

    /// Probe protection: max handshake time ms (too slow -> blocked)
    #[arg(long, default_value = "10000")]
    pub probe_max_handshake_ms: u64,

    /// Write probe metrics to this path in Prometheus text format
    #[arg(long)]
    pub probe_metrics_path: Option<PathBuf>,

    /// Interval for probe metrics export (seconds)
    #[arg(long, default_value = "30")]
    pub probe_metrics_interval: u64,

    /// Directory containing Noise keys
    #[arg(long, default_value = ".")]
    pub noise_dir: PathBuf,

    /// Noise key name
    #[arg(long, default_value = "server")]
    pub noise_name: String,

    /// TLS certificate file (PEM)
    #[arg(long)]
    pub cert: PathBuf,

    /// TLS private key file (PEM)
    #[arg(long)]
    pub key: PathBuf,

    /// Outbound interface for NAT (e.g., eth0)
    #[arg(long)]
    pub outbound_iface: Option<String>,

    /// Enable IP forwarding
    #[arg(long, default_value_t = true)]
    pub enable_forwarding: bool,

    /// Idle timeout in seconds
    #[arg(long, default_value = "300")]
    pub idle_timeout: u64,

    /// Session rekey time limit (seconds)
    #[arg(long, default_value = "60")]
    pub session_rekey_seconds: u64,

    /// Session rekey data limit (bytes)
    #[arg(long, default_value = "1073741824")]
    pub session_rekey_bytes: u64,

    /// Enable IPv6 support
    #[arg(long)]
    pub ipv6: bool,

    /// Enable IPv6 NAT masquerading
    #[arg(long)]
    pub ipv6_nat: bool,

    /// Routing policy: full|split|bypass
    #[arg(long, default_value = "full")]
    pub routing_policy: String,

    /// Routes to push to clients (CIDR notation, comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub routes: Vec<String>,

    /// TLS fingerprint profile to mimic (chrome, firefox, safari, random)
    #[arg(long, default_value = "chrome")]
    pub tls_profile: String,

    /// Canary TLS profile (chrome|firefox|safari|random|custom)
    #[arg(long, default_value = "safari")]
    pub tls_canary_profile: String,

    /// Percent of connections using canary profile
    #[arg(long, default_value = "5")]
    pub tls_canary_percent: f64,

    /// Seed for canary selection (0 = random)
    #[arg(long, default_value_t = 0)]
    pub tls_canary_seed: u64,

    /// GREASE mode: random|deterministic
    #[arg(long, default_value = "random")]
    pub tls_grease_mode: String,

    /// GREASE seed used when deterministic mode is selected
    #[arg(long, default_value_t = 0)]
    pub tls_grease_seed: u64,

    /// Export JA3/JA3S/JA4 metrics to Prometheus text file
    #[arg(long)]
    pub tls_fp_metrics_path: Option<PathBuf>,

    /// Run tls-fp-sync.py on startup to refresh fingerprint profiles
    #[arg(long)]
    pub tls_fp_sync: bool,

    /// Path to tls-fp-sync log file
    #[arg(long, default_value = "logs/tls-fp-sync.log")]
    pub tls_fp_sync_log: PathBuf,
}
