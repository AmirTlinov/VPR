//! Builder functions for server components.

use super::{Args, DEFAULT_DNS_SERVERS};
use crate::padding::{Padder, PaddingConfig, PaddingStrategy};
use crate::probe_protection::{ProbeProtectionConfig, ProbeProtector};
use crate::vpn_common::parse_padding_strategy;
use std::net::IpAddr;
use std::time::Duration;

/// Build a Padder from CLI arguments
pub fn build_padder(args: &Args) -> Padder {
    let strategy = parse_padding_strategy(&args.padding_strategy);
    let mtu = args.padding_mtu.unwrap_or(args.mtu) as usize;

    let config = PaddingConfig {
        strategy,
        mtu,
        jitter_enabled: args.padding_max_jitter_us > 0,
        max_jitter_us: args.padding_max_jitter_us,
        min_packet_size: args.padding_min_size,
        adaptive: true,
        high_strategy: PaddingStrategy::Mtu,
        medium_strategy: PaddingStrategy::Bucket,
        low_strategy: PaddingStrategy::RandomBucket,
        high_threshold: 60,
        medium_threshold: 20,
        hysteresis: 5,
    };

    Padder::new(config)
}

/// Build a ProbeProtector from CLI arguments
pub fn build_probe_protector(args: &Args) -> ProbeProtector {
    let config = ProbeProtectionConfig {
        challenge_enabled: true,
        challenge_difficulty: args.probe_difficulty,
        ban_duration: Duration::from_secs(args.probe_ban_seconds),
        max_failed_attempts: args.probe_max_failed_attempts,
        timing_analysis: true,
        min_handshake_time: Duration::from_millis(args.probe_min_handshake_ms),
        max_handshake_time: Duration::from_millis(args.probe_max_handshake_ms),
    };

    ProbeProtector::new(config)
}

/// Resolve DNS servers from CLI arguments, using defaults if none specified
pub fn resolve_dns_servers(args: &Args) -> Vec<IpAddr> {
    if args.dns_servers.is_empty() {
        DEFAULT_DNS_SERVERS.to_vec()
    } else {
        args.dns_servers.clone()
    }
}
