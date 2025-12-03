//! Builder functions for client components.

use super::Args;
use crate::padding::{Padder, PaddingConfig, PaddingStrategy};
use crate::vpn_common::parse_padding_strategy;
use crate::vpn_config::VpnConfig;

/// Build a Padder from CLI arguments only (before server config is received)
pub fn build_padder_cli(args: &Args, fallback_mtu: u16) -> Padder {
    let strategy = parse_padding_strategy(&args.padding_strategy);
    let mtu = args.padding_mtu.unwrap_or(fallback_mtu) as usize;

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

/// Build a Padder merging CLI arguments with server-provided VpnConfig
pub fn build_padder_from_config(args: &Args, config: &VpnConfig) -> Padder {
    // Prefer server-provided padding params to stay in sync
    let strategy = config
        .padding_strategy
        .as_deref()
        .map(parse_padding_strategy)
        .unwrap_or_else(|| parse_padding_strategy(&args.padding_strategy));

    let max_jitter_us = config
        .padding_max_jitter_us
        .unwrap_or(args.padding_max_jitter_us);

    let min_size = config.padding_min_size.unwrap_or(args.padding_min_size);

    let mtu = config
        .padding_mtu
        .unwrap_or_else(|| args.padding_mtu.unwrap_or(config.mtu)) as usize;

    let config = PaddingConfig {
        strategy,
        mtu,
        jitter_enabled: max_jitter_us > 0,
        max_jitter_us,
        min_packet_size: min_size,
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
