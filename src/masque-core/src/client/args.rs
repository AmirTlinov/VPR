//! CLI argument definitions for VPN client.

use clap::Parser;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "vpn-client", about = "VPR VPN client with TUN tunnel")]
pub struct Args {
    /// Server address (host:port)
    #[arg(long, default_value = "127.0.0.1:4433")]
    pub server: String,

    /// TLS/QUIC server name
    #[arg(long, default_value = "localhost")]
    pub server_name: String,

    /// TUN device name (empty = kernel assigns)
    #[arg(long, default_value = "vpr0")]
    pub tun_name: String,

    /// Local TUN IP address
    #[arg(long, default_value = "10.9.0.2")]
    pub tun_addr: Ipv4Addr,

    /// TUN netmask
    #[arg(long, default_value = "255.255.255.0")]
    pub tun_netmask: Ipv4Addr,

    /// MTU for TUN device (leave room for encapsulation)
    #[arg(long, default_value = "1400")]
    pub mtu: u16,

    /// Gateway IP for routing (server's TUN address)
    #[arg(long, default_value = "10.9.0.1")]
    pub gateway: Ipv4Addr,

    /// Configure default route through VPN
    #[arg(long)]
    pub set_default_route: bool,

    /// Directory containing Noise keys
    #[arg(long, default_value = ".")]
    pub noise_dir: PathBuf,

    /// Noise key name (will load {name}.noise.key)
    #[arg(long, default_value = "client")]
    pub noise_name: String,

    /// Server's public key file
    #[arg(long)]
    pub server_pub: PathBuf,

    /// Path to custom CA certificate file (PEM format)
    #[arg(long)]
    pub ca_cert: Option<PathBuf>,

    /// Skip TLS certificate verification (INSECURE - NEVER use in production!)
    ///
    /// WARNING: This flag disables TLS certificate verification, making the connection
    /// vulnerable to man-in-the-middle attacks. Only use for development/testing.
    #[arg(long)]
    pub insecure: bool,

    /// Idle timeout in seconds
    #[arg(long, default_value = "30")]
    pub idle_timeout: u64,

    /// Session rekey time limit (seconds)
    #[arg(long, default_value = "60")]
    pub session_rekey_seconds: u64,

    /// Session rekey data limit (bytes)
    #[arg(long, default_value = "1073741824")]
    pub session_rekey_bytes: u64,

    /// Enable DNS leak protection (overwrites /etc/resolv.conf)
    #[arg(long)]
    pub dns_protection: bool,

    /// Custom DNS servers to use with DNS protection (IPv4/IPv6, comma-separated)
    /// If not specified, uses DNS servers from VPN config
    #[arg(long, value_delimiter = ',')]
    pub dns_servers: Vec<IpAddr>,

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

    /// Export JA3/JA3S/JA4 metrics to Prometheus text file
    #[arg(long)]
    pub tls_fp_metrics_path: Option<PathBuf>,

    /// Run tls-fp-sync.py on startup (client side validation)
    #[arg(long)]
    pub tls_fp_sync: bool,

    /// Path to tls-fp-sync log file
    #[arg(long, default_value = "logs/tls-fp-sync.log")]
    pub tls_fp_sync_log: PathBuf,

    /// GREASE mode: random|deterministic
    #[arg(long, default_value = "random")]
    pub tls_grease_mode: String,

    /// GREASE seed when deterministic mode is selected
    #[arg(long, default_value_t = 0)]
    pub tls_grease_seed: u64,

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

    /// Enable split tunnel mode (only specified routes through VPN)
    #[arg(long)]
    pub split_tunnel: bool,

    /// Add route (CIDR notation, can be specified multiple times)
    #[arg(long, value_delimiter = ',')]
    pub route: Vec<String>,

    /// Enable policy-based routing
    #[arg(long)]
    pub policy_routing: bool,

    /// Enable IPv6 support
    #[arg(long)]
    pub ipv6: bool,

    /// Repair network configuration after crash (restore DNS, routes, cleanup TUN)
    #[arg(long)]
    pub repair: bool,

    /// Skip automatic network repair on startup (enabled by default)
    #[arg(long)]
    pub no_auto_repair: bool,

    /// Run diagnostics before connecting
    #[arg(long)]
    pub diagnose: bool,

    /// Automatically apply fixes
    #[arg(long)]
    pub auto_fix: bool,

    /// Fix consent level (auto/semi-auto/manual)
    #[arg(long, default_value = "semi-auto")]
    pub fix_consent: String,

    /// Dry run (show what would be fixed without applying)
    #[arg(long)]
    pub dry_run: bool,

    /// SSH host for server diagnostics
    #[arg(long)]
    pub ssh_host: Option<String>,

    /// SSH port
    #[arg(long, default_value = "22")]
    pub ssh_port: u16,

    /// SSH user
    #[arg(long, default_value = "root")]
    pub ssh_user: String,

    /// SSH password (DEPRECATED - use SSH keys for security)
    #[arg(long)]
    pub ssh_password: Option<String>,

    /// SSH private key path (recommended over password)
    #[arg(long)]
    pub ssh_key: Option<PathBuf>,
}
