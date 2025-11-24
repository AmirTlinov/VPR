//! Cover Traffic Generation
//!
//! Generates fake traffic to obscure real communication patterns.
//! Uses trace-driven patterns that mimic HTTPS/H3/WebRTC traffic.

use rand::rngs::OsRng;
use rand::Rng;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, trace};

/// Cover traffic pattern type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficPattern {
    /// HTTPS-like burst pattern (request-response)
    HttpsBurst,
    /// HTTP/3 multiplexed stream pattern
    H3Multiplex,
    /// WebRTC-like constant bitrate with jitter
    WebRtcCbr,
    /// Idle pattern (minimal keepalive)
    Idle,
    /// Custom pattern
    Custom,
}

impl Default for TrafficPattern {
    fn default() -> Self {
        Self::HttpsBurst
    }
}

/// Cover traffic configuration
#[derive(Debug, Clone)]
pub struct CoverTrafficConfig {
    /// Traffic pattern to mimic
    pub pattern: TrafficPattern,
    /// Base packet rate (packets per second)
    pub base_rate_pps: f64,
    /// Rate jitter factor (0.0 - 1.0)
    pub rate_jitter: f64,
    /// Minimum packet size
    pub min_packet_size: usize,
    /// Maximum packet size
    pub max_packet_size: usize,
    /// Enable adaptive rate based on real traffic
    pub adaptive: bool,
    /// Minimum interval between cover packets
    pub min_interval: Duration,
}

impl Default for CoverTrafficConfig {
    fn default() -> Self {
        Self {
            pattern: TrafficPattern::HttpsBurst,
            base_rate_pps: 10.0, // 10 packets per second
            rate_jitter: 0.3,    // 30% jitter
            min_packet_size: 64,
            max_packet_size: 1200,
            adaptive: true,
            min_interval: Duration::from_millis(10),
        }
    }
}

impl CoverTrafficConfig {
    /// Create config for HTTPS-like traffic
    pub fn https() -> Self {
        Self {
            pattern: TrafficPattern::HttpsBurst,
            base_rate_pps: 5.0,
            rate_jitter: 0.5,
            min_packet_size: 40,
            max_packet_size: 1400,
            adaptive: true,
            min_interval: Duration::from_millis(20),
        }
    }

    /// Create config for WebRTC-like traffic
    pub fn webrtc() -> Self {
        Self {
            pattern: TrafficPattern::WebRtcCbr,
            base_rate_pps: 50.0, // ~50 pps for audio
            rate_jitter: 0.1,
            min_packet_size: 80,
            max_packet_size: 200,
            adaptive: false,
            min_interval: Duration::from_millis(10),
        }
    }

    /// Create minimal idle config
    pub fn idle() -> Self {
        Self {
            pattern: TrafficPattern::Idle,
            base_rate_pps: 0.5, // ~1 packet per 2 seconds
            rate_jitter: 0.2,
            min_packet_size: 32,
            max_packet_size: 64,
            adaptive: false,
            min_interval: Duration::from_secs(1),
        }
    }
}

/// Cover traffic generator
pub struct CoverTrafficGenerator {
    config: CoverTrafficConfig,
    last_packet_time: Instant,
    real_traffic_rate: f64,
    packets_sent: u64,
}

impl CoverTrafficGenerator {
    /// Create new generator with config
    pub fn new(config: CoverTrafficConfig) -> Self {
        Self {
            config,
            last_packet_time: Instant::now(),
            real_traffic_rate: 0.0,
            packets_sent: 0,
        }
    }

    /// Update real traffic rate for adaptive mode
    pub fn update_real_traffic_rate(&mut self, rate_pps: f64) {
        self.real_traffic_rate = rate_pps;
    }

    /// Calculate effective cover rate based on pattern and real traffic
    fn effective_rate(&self) -> f64 {
        let base = self.config.base_rate_pps;

        if self.config.adaptive {
            // Reduce cover traffic when real traffic is high
            let reduction = (self.real_traffic_rate / 100.0).min(0.8);
            base * (1.0 - reduction)
        } else {
            base
        }
    }

    /// Calculate next packet delay with jitter
    pub fn next_delay(&self) -> Duration {
        let rate = self.effective_rate();
        if rate <= 0.0 {
            return Duration::from_secs(60); // Very long delay if rate is 0
        }

        let base_interval_ms = 1000.0 / rate;

        // Apply jitter
        let jitter_range = base_interval_ms * self.config.rate_jitter;
        let jitter = OsRng.gen_range(-jitter_range..=jitter_range);
        let interval_ms =
            (base_interval_ms + jitter).max(self.config.min_interval.as_millis() as f64);

        Duration::from_millis(interval_ms as u64)
    }

    /// Generate a cover packet
    pub fn generate_packet(&mut self) -> CoverPacket {
        self.packets_sent += 1;
        self.last_packet_time = Instant::now();

        let size = match self.config.pattern {
            TrafficPattern::HttpsBurst => self.generate_https_size(),
            TrafficPattern::H3Multiplex => self.generate_h3_size(),
            TrafficPattern::WebRtcCbr => self.generate_webrtc_size(),
            TrafficPattern::Idle => self.config.min_packet_size,
            TrafficPattern::Custom => {
                OsRng.gen_range(self.config.min_packet_size..=self.config.max_packet_size)
            }
        };

        let mut data = vec![0u8; size];
        OsRng.fill(&mut data[..]);

        // Add cover traffic marker in first byte (for debugging)
        data[0] = 0xCC; // Cover traffic marker

        CoverPacket {
            data,
            generated_at: Instant::now(),
        }
    }

    /// Generate HTTPS-like packet size (bimodal distribution)
    fn generate_https_size(&self) -> usize {
        let min = self.config.min_packet_size;
        let max = self.config.max_packet_size;

        // Bimodal: small ACKs or large data
        if OsRng.gen_bool(0.6) {
            // Small packet (ACK-like)
            OsRng.gen_range(min..min.max(120).min(max))
        } else {
            // Large packet (data)
            OsRng.gen_range((max / 2).max(min)..max)
        }
    }

    /// Generate HTTP/3 packet size
    fn generate_h3_size(&self) -> usize {
        let min = self.config.min_packet_size;
        let max = self.config.max_packet_size;

        // More uniform distribution with some clustering
        let cluster = OsRng.gen_range(0..4);
        let (low, high) = match cluster {
            0 => (min, (min + 60).min(max)),                   // Headers/control
            1 => ((min + 60).min(max), (min + 200).min(max)),  // Small data
            2 => ((max / 3).max(min), (max * 2 / 3).min(max)), // Medium data
            _ => ((max * 2 / 3).max(min), max),                // Large data
        };
        OsRng.gen_range(low..=high)
    }

    /// Generate WebRTC packet size (fairly constant)
    fn generate_webrtc_size(&self) -> usize {
        let min = self.config.min_packet_size;
        let max = self.config.max_packet_size;

        // Audio-like: centered around (min+max)/2 with small variation
        let center = ((min + max) / 2) as i32;
        let range = ((max - min) / 4) as i32;
        let variation = OsRng.gen_range(-range..=range);
        (center + variation).max(min as i32).min(max as i32) as usize
    }

    /// Get statistics
    pub fn stats(&self) -> CoverTrafficStats {
        CoverTrafficStats {
            packets_sent: self.packets_sent,
            effective_rate: self.effective_rate(),
            real_traffic_rate: self.real_traffic_rate,
        }
    }
}

/// Cover packet data
#[derive(Debug, Clone)]
pub struct CoverPacket {
    pub data: Vec<u8>,
    pub generated_at: Instant,
}

impl CoverPacket {
    /// Check if this is a cover packet (by marker)
    pub fn is_cover_packet(data: &[u8]) -> bool {
        !data.is_empty() && data[0] == 0xCC
    }
}

/// Cover traffic statistics
#[derive(Debug, Clone, Copy)]
pub struct CoverTrafficStats {
    pub packets_sent: u64,
    pub effective_rate: f64,
    pub real_traffic_rate: f64,
}

/// Async cover traffic sender task
pub async fn cover_traffic_task(
    mut generator: CoverTrafficGenerator,
    tx: mpsc::Sender<CoverPacket>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    debug!(pattern = ?generator.config.pattern, "Cover traffic task started");

    loop {
        let delay = generator.next_delay();

        tokio::select! {
            _ = tokio::time::sleep(delay) => {
                let packet = generator.generate_packet();
                trace!(size = packet.data.len(), "Generated cover packet");

                if tx.send(packet).await.is_err() {
                    debug!("Cover traffic channel closed");
                    break;
                }
            }
            _ = shutdown.recv() => {
                debug!("Cover traffic task shutting down");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CoverTrafficConfig::default();
        assert!(config.base_rate_pps > 0.0);
        assert!(config.min_packet_size < config.max_packet_size);
    }

    #[test]
    fn test_https_config() {
        let config = CoverTrafficConfig::https();
        assert_eq!(config.pattern, TrafficPattern::HttpsBurst);
    }

    #[test]
    fn test_webrtc_config() {
        let config = CoverTrafficConfig::webrtc();
        assert_eq!(config.pattern, TrafficPattern::WebRtcCbr);
        assert!(config.base_rate_pps >= 30.0); // Higher rate for audio
    }

    #[test]
    fn test_generate_packet() {
        let mut gen = CoverTrafficGenerator::new(CoverTrafficConfig::default());
        let packet = gen.generate_packet();

        assert!(!packet.data.is_empty());
        assert!(CoverPacket::is_cover_packet(&packet.data));
    }

    #[test]
    fn test_packet_sizes_in_range() {
        let config = CoverTrafficConfig {
            min_packet_size: 50,
            max_packet_size: 500,
            ..Default::default()
        };
        let mut gen = CoverTrafficGenerator::new(config.clone());

        for _ in 0..100 {
            let packet = gen.generate_packet();
            assert!(packet.data.len() >= config.min_packet_size);
            assert!(packet.data.len() <= config.max_packet_size);
        }
    }

    #[test]
    fn test_next_delay_positive() {
        let gen = CoverTrafficGenerator::new(CoverTrafficConfig::default());
        let delay = gen.next_delay();
        assert!(delay > Duration::ZERO);
    }

    #[test]
    fn test_adaptive_rate_reduction() {
        let mut gen = CoverTrafficGenerator::new(CoverTrafficConfig {
            adaptive: true,
            base_rate_pps: 100.0,
            ..Default::default()
        });

        let rate_no_traffic = gen.effective_rate();

        gen.update_real_traffic_rate(50.0);
        let rate_with_traffic = gen.effective_rate();

        assert!(rate_with_traffic < rate_no_traffic);
    }

    #[test]
    fn test_stats() {
        let mut gen = CoverTrafficGenerator::new(CoverTrafficConfig::default());
        assert_eq!(gen.stats().packets_sent, 0);

        gen.generate_packet();
        assert_eq!(gen.stats().packets_sent, 1);
    }

    #[test]
    fn test_idle_pattern_low_rate() {
        let gen = CoverTrafficGenerator::new(CoverTrafficConfig::idle());
        let delay = gen.next_delay();

        // Idle should have long delays (at least 500ms base)
        assert!(delay >= Duration::from_millis(500));
    }
}
