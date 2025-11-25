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

        // NOTE: No marker byte - cover traffic must be indistinguishable
        // from real encrypted traffic to resist traffic analysis

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
    /// Get packet size
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if packet is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
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

        assert!(!packet.is_empty());
        assert!(packet.len() >= gen.config.min_packet_size);
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

    #[test]
    fn test_traffic_pattern_default() {
        let pattern = TrafficPattern::default();
        assert_eq!(pattern, TrafficPattern::HttpsBurst);
    }

    #[test]
    fn test_traffic_pattern_equality() {
        assert_eq!(TrafficPattern::HttpsBurst, TrafficPattern::HttpsBurst);
        assert_eq!(TrafficPattern::H3Multiplex, TrafficPattern::H3Multiplex);
        assert_eq!(TrafficPattern::WebRtcCbr, TrafficPattern::WebRtcCbr);
        assert_eq!(TrafficPattern::Idle, TrafficPattern::Idle);
        assert_eq!(TrafficPattern::Custom, TrafficPattern::Custom);
        assert_ne!(TrafficPattern::HttpsBurst, TrafficPattern::Idle);
    }

    #[test]
    fn test_traffic_pattern_clone() {
        let pattern = TrafficPattern::H3Multiplex;
        let cloned = pattern;
        assert_eq!(pattern, cloned);
    }

    #[test]
    fn test_traffic_pattern_debug() {
        let pattern = TrafficPattern::WebRtcCbr;
        let debug_str = format!("{:?}", pattern);
        assert!(debug_str.contains("WebRtcCbr"));
    }

    #[test]
    fn test_cover_traffic_config_clone() {
        let config = CoverTrafficConfig::https();
        let cloned = config.clone();
        assert_eq!(cloned.pattern, TrafficPattern::HttpsBurst);
        assert_eq!(cloned.base_rate_pps, config.base_rate_pps);
    }

    #[test]
    fn test_cover_traffic_config_debug() {
        let config = CoverTrafficConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("CoverTrafficConfig"));
    }

    #[test]
    fn test_idle_config() {
        let config = CoverTrafficConfig::idle();
        assert_eq!(config.pattern, TrafficPattern::Idle);
        assert!(config.base_rate_pps < 1.0); // Very low rate
        assert!(!config.adaptive);
    }

    #[test]
    fn test_cover_packet_len() {
        let packet = CoverPacket {
            data: vec![1, 2, 3, 4, 5],
            generated_at: Instant::now(),
        };
        assert_eq!(packet.len(), 5);
    }

    #[test]
    fn test_cover_packet_is_empty() {
        let empty_packet = CoverPacket {
            data: vec![],
            generated_at: Instant::now(),
        };
        assert!(empty_packet.is_empty());

        let non_empty = CoverPacket {
            data: vec![1],
            generated_at: Instant::now(),
        };
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn test_cover_packet_clone() {
        let packet = CoverPacket {
            data: vec![10, 20, 30],
            generated_at: Instant::now(),
        };
        let cloned = packet.clone();
        assert_eq!(packet.data, cloned.data);
    }

    #[test]
    fn test_cover_packet_debug() {
        let packet = CoverPacket {
            data: vec![1, 2],
            generated_at: Instant::now(),
        };
        let debug_str = format!("{:?}", packet);
        assert!(debug_str.contains("CoverPacket"));
    }

    #[test]
    fn test_cover_traffic_stats_clone() {
        let stats = CoverTrafficStats {
            packets_sent: 100,
            effective_rate: 10.0,
            real_traffic_rate: 5.0,
        };
        let cloned = stats;
        assert_eq!(cloned.packets_sent, 100);
    }

    #[test]
    fn test_cover_traffic_stats_debug() {
        let stats = CoverTrafficStats {
            packets_sent: 42,
            effective_rate: 15.0,
            real_traffic_rate: 7.0,
        };
        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("CoverTrafficStats"));
        assert!(debug_str.contains("42"));
    }

    #[test]
    fn test_h3_multiplex_pattern() {
        let config = CoverTrafficConfig {
            pattern: TrafficPattern::H3Multiplex,
            min_packet_size: 40,
            max_packet_size: 1200,
            ..Default::default()
        };
        let mut gen = CoverTrafficGenerator::new(config);

        for _ in 0..50 {
            let packet = gen.generate_packet();
            assert!(packet.len() >= 40);
            assert!(packet.len() <= 1200);
        }
    }

    #[test]
    fn test_custom_pattern() {
        let config = CoverTrafficConfig {
            pattern: TrafficPattern::Custom,
            min_packet_size: 100,
            max_packet_size: 200,
            ..Default::default()
        };
        let mut gen = CoverTrafficGenerator::new(config);

        for _ in 0..50 {
            let packet = gen.generate_packet();
            assert!(packet.len() >= 100);
            assert!(packet.len() <= 200);
        }
    }

    #[test]
    fn test_webrtc_pattern_generation() {
        let config = CoverTrafficConfig::webrtc();
        let mut gen = CoverTrafficGenerator::new(config.clone());

        // WebRTC packets should be relatively uniform in size
        let mut sizes = Vec::new();
        for _ in 0..100 {
            let packet = gen.generate_packet();
            sizes.push(packet.len());
        }

        // Check variance is relatively low (centered distribution)
        let avg: f64 = sizes.iter().map(|&s| s as f64).sum::<f64>() / sizes.len() as f64;
        let expected_center = (config.min_packet_size + config.max_packet_size) as f64 / 2.0;
        assert!((avg - expected_center).abs() < 30.0);
    }

    #[test]
    fn test_effective_rate_non_adaptive() {
        let config = CoverTrafficConfig {
            adaptive: false,
            base_rate_pps: 50.0,
            ..Default::default()
        };
        let mut gen = CoverTrafficGenerator::new(config);

        let rate1 = gen.effective_rate();
        gen.update_real_traffic_rate(100.0);
        let rate2 = gen.effective_rate();

        // Non-adaptive: rate should not change
        assert_eq!(rate1, rate2);
        assert_eq!(rate1, 50.0);
    }

    #[test]
    fn test_effective_rate_adaptive_high_traffic() {
        let config = CoverTrafficConfig {
            adaptive: true,
            base_rate_pps: 100.0,
            ..Default::default()
        };
        let mut gen = CoverTrafficGenerator::new(config);

        // reduction = (real_traffic / 100).min(0.8)
        // For 50 pps: reduction = 0.5, rate = 100 * 0.5 = 50
        gen.update_real_traffic_rate(50.0);
        let rate = gen.effective_rate();

        // With moderate real traffic, cover rate should be reduced but not to minimum
        assert!(rate < 100.0);
        assert!(rate >= 45.0); // Should be around 50
    }

    #[test]
    fn test_next_delay_zero_rate() {
        let config = CoverTrafficConfig {
            base_rate_pps: 0.0,
            ..Default::default()
        };
        let gen = CoverTrafficGenerator::new(config);
        let delay = gen.next_delay();

        // Zero rate should give very long delay
        assert!(delay >= Duration::from_secs(30));
    }

    #[test]
    fn test_next_delay_respects_min_interval() {
        let config = CoverTrafficConfig {
            base_rate_pps: 10000.0, // Very high rate
            rate_jitter: 0.0,       // No jitter
            min_interval: Duration::from_millis(50),
            ..Default::default()
        };
        let gen = CoverTrafficGenerator::new(config);

        // Even with high rate, delay should respect min_interval
        for _ in 0..10 {
            let delay = gen.next_delay();
            assert!(delay >= Duration::from_millis(50));
        }
    }

    #[test]
    fn test_packets_sent_counter() {
        let mut gen = CoverTrafficGenerator::new(CoverTrafficConfig::default());

        assert_eq!(gen.stats().packets_sent, 0);

        gen.generate_packet();
        gen.generate_packet();
        gen.generate_packet();

        assert_eq!(gen.stats().packets_sent, 3);
    }

    #[test]
    fn test_stats_real_traffic_rate() {
        let mut gen = CoverTrafficGenerator::new(CoverTrafficConfig::default());

        assert_eq!(gen.stats().real_traffic_rate, 0.0);

        gen.update_real_traffic_rate(42.5);
        assert_eq!(gen.stats().real_traffic_rate, 42.5);
    }

    #[tokio::test]
    async fn test_cover_traffic_task_shutdown() {
        use tokio::sync::broadcast;

        let gen = CoverTrafficGenerator::new(CoverTrafficConfig {
            base_rate_pps: 100.0, // Fast rate for test
            ..Default::default()
        });

        let (tx, mut rx) = mpsc::channel(10);
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let task = tokio::spawn(cover_traffic_task(gen, tx, shutdown_rx));

        // Should receive at least one packet before shutdown
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .ok();

        // Send shutdown
        let _ = shutdown_tx.send(());

        // Task should complete
        tokio::time::timeout(Duration::from_millis(500), task)
            .await
            .expect("task should complete after shutdown")
            .expect("task should not panic");
    }

    #[tokio::test]
    async fn test_cover_traffic_task_channel_close() {
        use tokio::sync::broadcast;

        let gen = CoverTrafficGenerator::new(CoverTrafficConfig {
            base_rate_pps: 1000.0, // Very fast for test
            ..Default::default()
        });

        let (tx, rx) = mpsc::channel(1);
        let (_shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

        let task = tokio::spawn(cover_traffic_task(gen, tx, shutdown_rx));

        // Drop receiver to close channel
        drop(rx);

        // Task should complete when channel closes
        tokio::time::timeout(Duration::from_millis(500), task)
            .await
            .expect("task should complete when channel closes")
            .expect("task should not panic");
    }

    #[test]
    fn test_https_size_bimodal() {
        let config = CoverTrafficConfig::https();
        let mut gen = CoverTrafficGenerator::new(config.clone());

        let mut small_count = 0;
        let mut large_count = 0;

        for _ in 0..200 {
            let packet = gen.generate_packet();
            if packet.len() < 150 {
                small_count += 1;
            } else {
                large_count += 1;
            }
        }

        // Should have mix of small and large packets (bimodal)
        assert!(small_count > 50);
        assert!(large_count > 30);
    }
}
