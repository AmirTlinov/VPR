//! Common utilities for VPN client and server
//!
//! Provides shared functionality for padding, cover traffic, and TLS fingerprinting.

use crate::cover_traffic::{CoverTrafficConfig, TrafficPattern};
use crate::padding::{Padder, PaddingConfig, PaddingStrategy};
use crate::tls_fingerprint::{GreaseMode, TlsProfile};
use std::time::Duration;

/// Parse GREASE mode from string
pub fn parse_grease_mode(mode: &str, seed: u64) -> GreaseMode {
    match mode.to_ascii_lowercase().as_str() {
        "deterministic" | "det" | "fixed" => GreaseMode::Deterministic(seed),
        _ => GreaseMode::Random,
    }
}

/// Get preferred TLS 1.3 cipher from profile
pub fn preferred_tls13_cipher(profile: &TlsProfile) -> u16 {
    profile
        .cipher_suites()
        .into_iter()
        .find(|c| (*c & 0xff00) == 0x1300)
        .or_else(|| profile.cipher_suites().first().copied())
        .unwrap_or(0x1301)
}

/// Parse padding strategy from string
pub fn parse_padding_strategy(name: &str) -> PaddingStrategy {
    match name.to_ascii_lowercase().as_str() {
        "none" => PaddingStrategy::None,
        "bucket" => PaddingStrategy::Bucket,
        "mtu" => PaddingStrategy::Mtu,
        "rand-bucket" | "random-bucket" | "random" => PaddingStrategy::RandomBucket,
        other => {
            tracing::warn!(strategy = %other, "Unknown padding strategy, using rand-bucket");
            PaddingStrategy::RandomBucket
        }
    }
}

/// Parse cover traffic pattern from string
pub fn parse_cover_pattern(name: &str) -> TrafficPattern {
    match name.to_ascii_lowercase().as_str() {
        "https" => TrafficPattern::HttpsBurst,
        "h3" => TrafficPattern::H3Multiplex,
        "webrtc" => TrafficPattern::WebRtcCbr,
        "idle" => TrafficPattern::Idle,
        _ => TrafficPattern::HttpsBurst,
    }
}

/// Build cover traffic configuration
pub fn build_cover_config(rate: f64, pattern: &str, mtu: usize) -> CoverTrafficConfig {
    CoverTrafficConfig {
        pattern: parse_cover_pattern(pattern),
        base_rate_pps: rate,
        rate_jitter: 0.35,
        min_packet_size: 64,
        max_packet_size: mtu.saturating_sub(40).max(64),
        adaptive: true,
        min_interval: Duration::from_millis(5),
    }
}

/// Convert padding strategy to byte for protocol
pub fn padding_strategy_to_byte(strategy: PaddingStrategy) -> u8 {
    match strategy {
        PaddingStrategy::None => 0,
        PaddingStrategy::Bucket => 1,
        PaddingStrategy::RandomBucket => 2,
        PaddingStrategy::Mtu => 3,
    }
}

/// Serialize padding schedule to bytes for protocol
pub fn padding_schedule_bytes(padder: &Padder) -> Vec<u8> {
    let cfg = padder.config();
    let mut out = Vec::with_capacity(15);
    out.push(padding_strategy_to_byte(cfg.strategy));
    out.extend_from_slice(&cfg.max_jitter_us.to_be_bytes());
    out.extend_from_slice(&(cfg.min_packet_size as u32).to_be_bytes());
    out.extend_from_slice(&(cfg.mtu as u16).to_be_bytes());
    out
}

/// Serialize padding schedule from raw values (for server)
pub fn padding_schedule_bytes_raw(
    strategy: &str,
    max_jitter_us: u64,
    min_size: usize,
    mtu: u16,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(15);
    out.push(padding_strategy_to_byte(parse_padding_strategy(strategy)));
    out.extend_from_slice(&max_jitter_us.to_be_bytes());
    out.extend_from_slice(&(min_size as u32).to_be_bytes());
    out.extend_from_slice(&mtu.to_be_bytes());
    out
}

/// Common padding config builder parameters
#[derive(Debug, Clone)]
pub struct PaddingParams {
    pub strategy: String,
    pub mtu: usize,
    pub max_jitter_us: u64,
    pub min_size: usize,
}

/// Build padder from common parameters
pub fn build_padder(params: &PaddingParams) -> Padder {
    let strategy = parse_padding_strategy(&params.strategy);

    let config = PaddingConfig {
        strategy,
        mtu: params.mtu,
        jitter_enabled: params.max_jitter_us > 0,
        max_jitter_us: params.max_jitter_us,
        min_packet_size: params.min_size,
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

#[cfg(unix)]
/// Setup shutdown signal handler for graceful termination
/// Returns a receiver that completes when SIGTERM or SIGINT is received
pub fn setup_shutdown_signal() -> tokio::sync::oneshot::Receiver<()> {
    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("Received SIGTERM - initiating graceful shutdown");
            }
            _ = sigint.recv() => {
                tracing::info!("Received SIGINT (Ctrl+C) - initiating graceful shutdown");
            }
        }

        let _ = tx.send(());
    });

    rx
}

#[cfg(not(unix))]
/// Setup shutdown signal handler for graceful termination (Windows)
pub fn setup_shutdown_signal() -> tokio::sync::oneshot::Receiver<()> {
    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Ctrl+C handler");
        tracing::info!("Received Ctrl+C - initiating graceful shutdown");
        let _ = tx.send(());
    });

    rx
}
