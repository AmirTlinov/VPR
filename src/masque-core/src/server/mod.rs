//! VPN Server module - decomposed components for vpn-server binary.
//!
//! This module provides reusable server components:
//! - CLI argument parsing
//! - IP pool management
//! - Client session state
//! - TLS/QUIC configuration
//! - TUN device tasks

pub mod args;
pub mod builders;
pub mod ip_pool;
pub mod metrics;
pub mod state;
pub mod suspicion;
pub mod tls;
pub mod tun_tasks;

pub use args::Args;
pub use builders::{build_padder, build_probe_protector, resolve_dns_servers};
pub use ip_pool::IpPool;
pub use metrics::probe_metrics_task;
pub use state::{ClientSession, ServerState, SessionInfo};
pub use suspicion::SuspicionTracker;
pub use tls::{build_server_config, build_tls_fingerprint, load_certs, load_key};
pub use tun_tasks::{tun_reader_task, tun_writer_task};

/// Session timeout for reconnection (5 minutes)
pub const SESSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Default DNS servers pushed to clients when none specified
pub const DEFAULT_DNS_SERVERS: [std::net::IpAddr; 2] = [
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
];

/// VPR protocol version byte
pub const VPR_PROTOCOL_VERSION: u8 = 0x01;

/// Convert IPv4 address to IPv6 using ULA prefix fd09::/64
/// Maps 10.9.0.x -> fd09::10:9:0:x
pub fn ipv4_to_ipv6(ipv4: std::net::Ipv4Addr) -> std::net::Ipv6Addr {
    let octets = ipv4.octets();
    std::net::Ipv6Addr::new(
        0xfd09,
        0,
        0,
        0,
        u16::from(octets[0]),
        u16::from(octets[1]),
        u16::from(octets[2]),
        u16::from(octets[3]),
    )
}

/// Generate cryptographically secure session ID
pub fn generate_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let random: u64 = crate::rng::random_u64();
    format!("{:x}{:016x}", timestamp, random)
}

/// Try to detect the default outbound interface from system routing table
pub fn detect_default_iface() -> Option<String> {
    use std::process::Command;
    if let Ok(output) = Command::new("ip").args(["route", "show", "default"]).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let mut parts = line.split_whitespace();
                while let Some(tok) = parts.next() {
                    if tok == "dev" {
                        if let Some(iface) = parts.next() {
                            return Some(iface.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}
