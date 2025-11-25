//! Cover traffic generation with profile-realistic patterns
//!
//! Generates cover packets that mimic the statistical properties of target
//! traffic profiles to evade deep packet inspection.
//!
//! # Security Considerations
//!
//! Cover traffic must be indistinguishable from legitimate traffic:
//! - Packet sizes follow profile distribution (not uniform/zeros)
//! - Timing patterns match profile characteristics
//! - Payload entropy matches expected content type

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::profiles::ProfileStats;
use crate::TrafficProfile;

/// Cover traffic generator with profile-aware packet synthesis
#[derive(Debug)]
pub struct CoverGenerator {
    /// Target profile for cover traffic
    profile: TrafficProfile,
    /// Cached profile statistics
    stats: ProfileStats,
    /// Seeded RNG for deterministic testing (optional)
    rng: StdRng,
    /// Sequence counter for pattern variation
    sequence: u64,
    /// Session-unique SSRC (randomized per session to avoid fingerprinting)
    session_ssrc: u32,
    /// Session-unique game packet type (randomized to avoid fingerprinting)
    game_packet_type: u8,
}

impl CoverGenerator {
    /// Create new cover generator for given profile
    pub fn new(profile: TrafficProfile) -> Self {
        Self::with_seed(profile, None)
    }

    /// Create cover generator with optional seed for reproducibility
    pub fn with_seed(profile: TrafficProfile, seed: Option<u64>) -> Self {
        let mut rng = match seed {
            Some(s) => StdRng::seed_from_u64(s),
            None => StdRng::from_entropy(),
        };

        // Generate session-unique identifiers to avoid fingerprinting
        let session_ssrc: u32 = rng.gen();
        let game_packet_type: u8 = rng.gen_range(0x01..=0x7F); // Valid game packet types

        Self {
            profile,
            stats: ProfileStats::for_profile(profile),
            rng,
            sequence: 0,
            session_ssrc,
            game_packet_type,
        }
    }

    /// Generate a cover packet mimicking target profile
    ///
    /// Returns packet with:
    /// - Size sampled from profile distribution
    /// - Payload with appropriate entropy (not zeros!)
    pub fn generate(&mut self) -> Vec<u8> {
        let size = self.sample_size();
        let mut packet = vec![0u8; size];

        // Fill with profile-appropriate content
        self.fill_payload(&mut packet);
        self.sequence = self.sequence.wrapping_add(1);

        packet
    }

    /// Generate cover packet with specific minimum size
    pub fn generate_min_size(&mut self, min_size: usize) -> Vec<u8> {
        let base_size = self.sample_size();
        let size = base_size.max(min_size);
        let mut packet = vec![0u8; size];

        self.fill_payload(&mut packet);
        self.sequence = self.sequence.wrapping_add(1);

        packet
    }

    /// Sample packet size from profile distribution
    fn sample_size(&mut self) -> usize {
        // Use mixture model: 70% common sizes, 30% gaussian around mean
        if self.rng.gen_bool(0.7) {
            // Pick from common sizes with weighted probability
            self.sample_common_size()
        } else {
            // Gaussian around profile mean
            self.sample_gaussian_size()
        }
    }

    /// Sample from common sizes with realistic weights
    fn sample_common_size(&mut self) -> usize {
        let sizes = self.stats.common_sizes;
        if sizes.is_empty() {
            return 64; // Fallback
        }

        // Weight smaller sizes more heavily (typical for acks/control)
        let weights: Vec<f32> = sizes
            .iter()
            .enumerate()
            .map(|(i, _)| 1.0 / (i as f32 + 1.0))
            .collect();

        let total: f32 = weights.iter().sum();
        let mut r = self.rng.gen::<f32>() * total;

        for (i, w) in weights.iter().enumerate() {
            r -= w;
            if r <= 0.0 {
                return sizes[i];
            }
        }

        sizes[sizes.len() - 1]
    }

    /// Sample size from gaussian distribution around profile mean
    fn sample_gaussian_size(&mut self) -> usize {
        // Box-Muller transform for gaussian
        let u1: f32 = self.rng.gen();
        let u2: f32 = self.rng.gen();

        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f32::consts::PI * u2).cos();
        let size = self.stats.mean_size + z * self.stats.size_std;

        // Clamp to valid range
        size.clamp(32.0, 1500.0) as usize
    }

    /// Fill payload with profile-appropriate content
    ///
    /// Different profiles have different payload characteristics:
    /// - Streaming (YouTube/Netflix): High entropy (encrypted video)
    /// - Gaming: Mixed entropy (game state + encrypted)
    /// - Browsing: Variable (HTML/images/encrypted)
    /// - Zoom: High entropy (encrypted audio/video)
    fn fill_payload(&mut self, packet: &mut [u8]) {
        match self.profile {
            TrafficProfile::YouTube | TrafficProfile::Netflix => {
                // Encrypted video stream: high entropy throughout
                self.fill_high_entropy(packet);
            }
            TrafficProfile::Zoom => {
                // RTP-like: small header + encrypted payload
                self.fill_rtp_like(packet);
            }
            TrafficProfile::Gaming => {
                // Game packets: structured header + variable payload
                self.fill_game_like(packet);
            }
            TrafficProfile::Browsing => {
                // Web traffic: TLS records with high entropy
                self.fill_tls_like(packet);
            }
        }
    }

    /// High entropy fill (encrypted stream)
    fn fill_high_entropy(&mut self, packet: &mut [u8]) {
        self.rng.fill(packet);
    }

    /// RTP-like structure for video calls
    ///
    /// # Security: SSRC is randomized per session to avoid fingerprinting
    fn fill_rtp_like(&mut self, packet: &mut [u8]) {
        if packet.len() < 12 {
            self.rng.fill(packet);
            return;
        }

        // RTP header (12 bytes)
        packet[0] = 0x80; // Version 2
        packet[1] = 0x60 | (self.rng.gen::<u8>() & 0x1F); // PT with marker

        // Sequence number (incrementing with random offset to avoid pattern)
        let seq = (self.sequence.wrapping_add(self.session_ssrc as u64) & 0xFFFF) as u16;
        packet[2..4].copy_from_slice(&seq.to_be_bytes());

        // Timestamp (incrementing with jitter)
        let jitter: u32 = self.rng.gen_range(0..16);
        let ts = (self.sequence * 160 + jitter as u64) as u32;
        packet[4..8].copy_from_slice(&ts.to_be_bytes());

        // SSRC (session-unique, randomized at construction)
        packet[8..12].copy_from_slice(&self.session_ssrc.to_be_bytes());

        // Encrypted payload
        self.rng.fill(&mut packet[12..]);
    }

    /// Game packet structure
    ///
    /// # Security: All values randomized per-session to avoid fingerprinting
    fn fill_game_like(&mut self, packet: &mut [u8]) {
        if packet.len() < 8 {
            self.rng.fill(packet);
            return;
        }

        // Randomized game header (no fixed patterns)
        packet[0] = self.game_packet_type; // Session-unique packet type
        packet[1] = self.rng.gen(); // Randomized flags

        // Tick number with session-unique offset and jitter
        let tick_base = self.session_ssrc.wrapping_add(self.sequence as u32 * 16);
        let jitter: u32 = self.rng.gen_range(0..8);
        let tick = tick_base.wrapping_add(jitter);
        packet[2..6].copy_from_slice(&tick.to_be_bytes());

        // Payload size with random variation
        let payload_len = (packet.len() - 8) as u16;
        packet[6..8].copy_from_slice(&payload_len.to_be_bytes());

        // Fully randomized payload (no deterministic patterns)
        self.rng.fill(&mut packet[8..]);
    }

    /// TLS record structure for web traffic
    fn fill_tls_like(&mut self, packet: &mut [u8]) {
        if packet.len() < 5 {
            self.rng.fill(packet);
            return;
        }

        // TLS Application Data record header
        packet[0] = 0x17; // Application Data
        packet[1] = 0x03; // TLS 1.2
        packet[2] = 0x03;

        // Record length
        let len = (packet.len() - 5) as u16;
        packet[3..5].copy_from_slice(&len.to_be_bytes());

        // Encrypted payload (high entropy)
        self.rng.fill(&mut packet[5..]);
    }

    /// Get suggested delay until next cover packet (ms)
    pub fn suggested_delay_ms(&mut self) -> f32 {
        // Sample from profile delay distribution
        let u1: f32 = self.rng.gen();
        let u2: f32 = self.rng.gen();

        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f32::consts::PI * u2).cos();
        let delay_log = self.stats.mean_delay_log + z * self.stats.delay_std;

        // Convert from log scale and clamp
        (delay_log.exp() - 1.0).clamp(1.0, 1000.0)
    }

    /// Check if we should inject cover traffic now
    ///
    /// Based on profile burstiness and recent activity
    pub fn should_inject(&mut self, packets_since_last_cover: u32, idle_ms: f32) -> bool {
        let (min_burst, max_burst) = self.stats.burst_lengths;

        // Inject if we've been idle too long
        let idle_threshold = self.stats.mean_delay_log.exp() * 3.0;
        if idle_ms > idle_threshold {
            return true;
        }

        // Inject based on burst pattern
        if packets_since_last_cover >= max_burst as u32 {
            return true;
        }

        // Random injection within burst
        if packets_since_last_cover >= min_burst as u32 {
            return self.rng.gen_bool(0.3);
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cover_generation_not_zeros() {
        let mut gen = CoverGenerator::with_seed(TrafficProfile::YouTube, Some(42));

        for _ in 0..100 {
            let packet = gen.generate();

            // Packet should not be all zeros
            assert!(
                !packet.iter().all(|&b| b == 0),
                "Cover packet should not be all zeros"
            );

            // Should have reasonable size
            assert!(packet.len() >= 32 && packet.len() <= 1500);
        }
    }

    #[test]
    fn test_cover_deterministic_with_seed() {
        let mut gen1 = CoverGenerator::with_seed(TrafficProfile::Gaming, Some(12345));
        let mut gen2 = CoverGenerator::with_seed(TrafficProfile::Gaming, Some(12345));

        for _ in 0..10 {
            let p1 = gen1.generate();
            let p2 = gen2.generate();
            assert_eq!(p1, p2, "Same seed should produce same packets");
        }
    }

    #[test]
    fn test_cover_size_distribution() {
        let mut gen = CoverGenerator::with_seed(TrafficProfile::YouTube, Some(42));
        let mut sizes: Vec<usize> = Vec::new();

        for _ in 0..1000 {
            sizes.push(gen.generate().len());
        }

        let mean: f32 = sizes.iter().sum::<usize>() as f32 / sizes.len() as f32;
        let youtube_stats = ProfileStats::for_profile(TrafficProfile::YouTube);

        // Mean should be within 2 std devs of profile mean
        let tolerance = youtube_stats.size_std * 2.0;
        assert!(
            (mean - youtube_stats.mean_size).abs() < tolerance,
            "Mean size {} should be close to profile mean {}",
            mean,
            youtube_stats.mean_size
        );
    }

    #[test]
    fn test_rtp_like_structure() {
        let mut gen = CoverGenerator::with_seed(TrafficProfile::Zoom, Some(42));

        let packet = gen.generate_min_size(100);

        // Should have RTP header
        assert_eq!(packet[0] & 0xC0, 0x80, "RTP version should be 2");
    }

    #[test]
    fn test_tls_like_structure() {
        let mut gen = CoverGenerator::with_seed(TrafficProfile::Browsing, Some(42));

        let packet = gen.generate_min_size(100);

        // Should have TLS record header
        assert_eq!(packet[0], 0x17, "Should be TLS Application Data");
        assert_eq!(packet[1], 0x03, "Should be TLS 1.x");
    }

    #[test]
    fn test_injection_decision() {
        let mut gen = CoverGenerator::with_seed(TrafficProfile::Gaming, Some(42));

        // Should inject after many packets
        assert!(gen.should_inject(100, 0.0));

        // Should inject after long idle
        assert!(gen.should_inject(0, 10000.0));
    }
}
