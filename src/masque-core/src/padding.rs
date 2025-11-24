//! Adaptive Padding for Traffic Analysis Resistance
//!
//! Implements packet padding to obscure traffic patterns and resist DPI.
//! Uses bucket-based padding with jittered timing to mimic natural traffic.

use rand::rngs::OsRng;
use rand::Rng;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

/// Padding bucket sizes (bytes)
pub const BUCKET_SMALL: usize = 32;
pub const BUCKET_MEDIUM: usize = 64;
pub const BUCKET_LARGE: usize = 256;
pub const BUCKET_JUMBO: usize = 1024;

/// All available bucket sizes in ascending order
pub const BUCKETS: [usize; 4] = [BUCKET_SMALL, BUCKET_MEDIUM, BUCKET_LARGE, BUCKET_JUMBO];

/// Maximum padding overhead (percentage)
pub const MAX_PADDING_OVERHEAD: f32 = 0.25;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspicionBucket {
    Low,
    Medium,
    High,
}

/// Padding strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingStrategy {
    /// No padding (insecure, for testing only)
    None,
    /// Pad to fixed bucket sizes
    Bucket,
    /// Pad to random size within bucket range
    RandomBucket,
    /// Pad to MTU size (maximum obfuscation)
    Mtu,
}

impl Default for PaddingStrategy {
    fn default() -> Self {
        Self::RandomBucket
    }
}

/// Padding configuration
#[derive(Debug, Clone)]
pub struct PaddingConfig {
    /// Padding strategy
    pub strategy: PaddingStrategy,
    /// MTU for MTU-based padding
    pub mtu: usize,
    /// Enable timing jitter
    pub jitter_enabled: bool,
    /// Maximum jitter delay (microseconds)
    pub max_jitter_us: u64,
    /// Minimum packet size (will always pad to at least this)
    pub min_packet_size: usize,
    /// Enable adaptive strategy switch by suspicion bucket
    pub adaptive: bool,
    /// High bucket = strategy applied when suspicion >= high_threshold
    pub high_strategy: PaddingStrategy,
    /// Medium bucket = strategy applied when suspicion in [mid, high)
    pub medium_strategy: PaddingStrategy,
    /// Low bucket = strategy applied when suspicion < mid_threshold
    pub low_strategy: PaddingStrategy,
    /// Upper threshold for medium (inclusive), >= this → high bucket
    pub high_threshold: u8,
    /// Upper threshold for low (inclusive), >= this → medium bucket
    pub medium_threshold: u8,
    /// Hysteresis margin to reduce flapping
    pub hysteresis: u8,
}

impl Default for PaddingConfig {
    fn default() -> Self {
        Self {
            strategy: PaddingStrategy::RandomBucket,
            mtu: 1400,
            jitter_enabled: true,
            max_jitter_us: 5000, // 5ms max jitter
            min_packet_size: BUCKET_SMALL,
            adaptive: false,
            high_strategy: PaddingStrategy::Mtu,
            medium_strategy: PaddingStrategy::Bucket,
            low_strategy: PaddingStrategy::RandomBucket,
            high_threshold: 60,
            medium_threshold: 20,
            hysteresis: 5,
        }
    }
}

/// Packet padder
pub struct Padder {
    config: PaddingConfig,
    suspicion_bucket: AtomicU8, // stores SuspicionBucket as u8
}

impl Padder {
    /// Expose config for synchronization/telemetry
    pub fn config(&self) -> &PaddingConfig {
        &self.config
    }

    /// Create new padder with config
    pub fn new(config: PaddingConfig) -> Self {
        let initial_bucket = SuspicionBucket::Low as u8;
        Self {
            config,
            suspicion_bucket: AtomicU8::new(initial_bucket),
        }
    }

    /// Create padder with default config
    pub fn default_config() -> Self {
        Self::new(PaddingConfig::default())
    }

    /// Calculate padded size for a packet
    pub fn padded_size(&self, original_size: usize) -> usize {
        let strategy = self.effective_strategy();
        match strategy {
            PaddingStrategy::None => original_size,
            PaddingStrategy::Bucket => self.bucket_size(original_size),
            PaddingStrategy::RandomBucket => self.random_bucket_size(original_size),
            PaddingStrategy::Mtu => self.config.mtu,
        }
    }

    /// Pad packet to calculated size
    pub fn pad(&self, data: &[u8]) -> Vec<u8> {
        let target_size = self.padded_size(data.len());
        let mut padded = Vec::with_capacity(target_size);

        // Original data
        padded.extend_from_slice(data);

        // Padding bytes (random to avoid pattern detection)
        if padded.len() < target_size {
            let padding_len = target_size - padded.len();
            let mut padding = vec![0u8; padding_len];
            OsRng.fill(&mut padding[..]);
            padded.extend_from_slice(&padding);
        }

        padded
    }

    /// Pad packet in-place (for pre-allocated buffers)
    pub fn pad_in_place(&self, data: &mut Vec<u8>) {
        let target_size = self.padded_size(data.len());
        if data.len() < target_size {
            let padding_len = target_size - data.len();
            data.reserve(padding_len);
            let mut padding = vec![0u8; padding_len];
            OsRng.fill(&mut padding[..]);
            data.extend_from_slice(&padding);
        }
    }

    /// Get jitter delay if enabled
    pub fn jitter_delay(&self) -> Option<Duration> {
        if !self.config.jitter_enabled || self.config.max_jitter_us == 0 {
            return None;
        }

        let jitter_us = OsRng.gen_range(0..=self.config.max_jitter_us);
        Some(Duration::from_micros(jitter_us))
    }

    /// Update suspicion bucket with hysteresis to avoid flapping
    pub fn update_suspicion(&self, score: f64) {
        if !self.config.adaptive {
            return;
        }
        let score = score.clamp(0.0, 100.0) as u8;
        let current = self.suspicion_bucket.load(Ordering::Relaxed);
        let current_enum = match current {
            0 => SuspicionBucket::Low,
            1 => SuspicionBucket::Medium,
            _ => SuspicionBucket::High,
        };

        let next = match current_enum {
            SuspicionBucket::Low => {
                if score >= self.config.medium_threshold + self.config.hysteresis {
                    SuspicionBucket::Medium
                } else {
                    SuspicionBucket::Low
                }
            }
            SuspicionBucket::Medium => {
                if score >= self.config.high_threshold + self.config.hysteresis {
                    SuspicionBucket::High
                } else if score + self.config.hysteresis < self.config.medium_threshold {
                    SuspicionBucket::Low
                } else {
                    SuspicionBucket::Medium
                }
            }
            SuspicionBucket::High => {
                if score + self.config.hysteresis < self.config.high_threshold {
                    SuspicionBucket::Medium
                } else {
                    SuspicionBucket::High
                }
            }
        };
        self.suspicion_bucket.store(next as u8, Ordering::Relaxed);
    }

    pub fn suspicion_bucket(&self) -> SuspicionBucket {
        match self.suspicion_bucket.load(Ordering::Relaxed) {
            0 => SuspicionBucket::Low,
            1 => SuspicionBucket::Medium,
            _ => SuspicionBucket::High,
        }
    }

    fn effective_strategy(&self) -> PaddingStrategy {
        if !self.config.adaptive {
            return self.config.strategy;
        }
        match self.suspicion_bucket() {
            SuspicionBucket::Low => self.config.low_strategy,
            SuspicionBucket::Medium => self.config.medium_strategy,
            SuspicionBucket::High => self.config.high_strategy,
        }
    }

    /// Find bucket size for given data size
    fn bucket_size(&self, size: usize) -> usize {
        // Ensure minimum size
        let size = size.max(self.config.min_packet_size);

        // Find smallest bucket that fits
        for &bucket in &BUCKETS {
            if size <= bucket {
                return bucket;
            }
        }

        // For sizes larger than largest bucket, round up to MTU
        self.config
            .mtu
            .min(size + (BUCKET_LARGE - (size % BUCKET_LARGE)))
    }

    /// Random size within appropriate bucket range
    fn random_bucket_size(&self, size: usize) -> usize {
        let bucket = self.bucket_size(size);

        // Find the next bucket for upper bound
        let next_bucket = BUCKETS
            .iter()
            .find(|&&b| b > bucket)
            .copied()
            .unwrap_or(self.config.mtu);

        // Random size between bucket and next_bucket - 1
        if next_bucket > bucket {
            OsRng.gen_range(bucket..next_bucket)
        } else {
            bucket
        }
    }
}

impl Default for Padder {
    fn default() -> Self {
        Self::default_config()
    }
}

/// Calculate padding overhead for a set of packets
pub fn calculate_overhead(original_sizes: &[usize], padded_sizes: &[usize]) -> f32 {
    if original_sizes.is_empty() {
        return 0.0;
    }

    let original_total: usize = original_sizes.iter().sum();
    let padded_total: usize = padded_sizes.iter().sum();

    if original_total == 0 {
        return 0.0;
    }

    (padded_total - original_total) as f32 / original_total as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_sizes() {
        let padder = Padder::default_config();

        // Small packets go to small bucket
        assert!(padder.padded_size(10) >= BUCKET_SMALL);

        // Medium packets
        assert!(padder.padded_size(50) >= BUCKET_MEDIUM);

        // Large packets
        assert!(padder.padded_size(200) >= BUCKET_LARGE);
    }

    #[test]
    fn test_no_padding_strategy() {
        let padder = Padder::new(PaddingConfig {
            strategy: PaddingStrategy::None,
            ..Default::default()
        });

        assert_eq!(padder.padded_size(100), 100);
    }

    #[test]
    fn test_mtu_padding_strategy() {
        let padder = Padder::new(PaddingConfig {
            strategy: PaddingStrategy::Mtu,
            mtu: 1400,
            ..Default::default()
        });

        assert_eq!(padder.padded_size(100), 1400);
        assert_eq!(padder.padded_size(1000), 1400);
    }

    #[test]
    fn test_pad_creates_correct_size() {
        let padder = Padder::new(PaddingConfig {
            strategy: PaddingStrategy::Bucket,
            ..Default::default()
        });

        let data = vec![1, 2, 3, 4, 5];
        let padded = padder.pad(&data);

        assert!(padded.len() >= BUCKET_SMALL);
        assert_eq!(&padded[..5], &data[..]);
    }

    #[test]
    fn test_pad_in_place() {
        let padder = Padder::new(PaddingConfig {
            strategy: PaddingStrategy::Bucket,
            ..Default::default()
        });

        let mut data = vec![1, 2, 3, 4, 5];
        let original = data.clone();
        padder.pad_in_place(&mut data);

        assert!(data.len() >= BUCKET_SMALL);
        assert_eq!(&data[..5], &original[..]);
    }

    #[test]
    fn test_jitter_delay() {
        let padder = Padder::new(PaddingConfig {
            jitter_enabled: true,
            max_jitter_us: 1000,
            ..Default::default()
        });

        // Should return Some with jitter enabled
        let delay = padder.jitter_delay();
        assert!(delay.is_some());
        assert!(delay.unwrap() <= Duration::from_micros(1000));
    }

    #[test]
    fn test_jitter_disabled() {
        let padder = Padder::new(PaddingConfig {
            jitter_enabled: false,
            ..Default::default()
        });

        assert!(padder.jitter_delay().is_none());
    }

    #[test]
    fn test_calculate_overhead() {
        let original = vec![100, 200, 300];
        let padded = vec![128, 256, 512];

        let overhead = calculate_overhead(&original, &padded);

        // (896 - 600) / 600 = 0.493...
        assert!(overhead > 0.4 && overhead < 0.6);
    }

    #[test]
    fn test_random_bucket_varies() {
        let padder = Padder::new(PaddingConfig {
            strategy: PaddingStrategy::RandomBucket,
            ..Default::default()
        });

        // Multiple calls should sometimes produce different sizes
        let sizes: Vec<usize> = (0..100).map(|_| padder.padded_size(50)).collect();
        let unique_sizes: std::collections::HashSet<_> = sizes.iter().collect();

        // Should have some variation (not guaranteed but very likely)
        assert!(
            unique_sizes.len() > 1,
            "Random bucket should produce varied sizes"
        );
    }

    #[test]
    fn adaptive_switches_buckets_with_hysteresis() {
        let padder = Padder::new(PaddingConfig {
            adaptive: true,
            low_strategy: PaddingStrategy::RandomBucket,
            medium_strategy: PaddingStrategy::Bucket,
            high_strategy: PaddingStrategy::Mtu,
            medium_threshold: 20,
            high_threshold: 60,
            hysteresis: 5,
            ..Default::default()
        });

        padder.update_suspicion(10.0);
        assert_eq!(padder.suspicion_bucket(), SuspicionBucket::Low);
        padder.update_suspicion(25.0);
        assert_eq!(padder.suspicion_bucket(), SuspicionBucket::Medium);
        padder.update_suspicion(90.0);
        assert_eq!(padder.suspicion_bucket(), SuspicionBucket::High);
        padder.update_suspicion(58.0);
        assert_eq!(padder.suspicion_bucket(), SuspicionBucket::High);
        padder.update_suspicion(40.0);
        assert_eq!(padder.suspicion_bucket(), SuspicionBucket::Medium);
    }
}
