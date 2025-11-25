//! Packet feature extraction for traffic morphing
//!
//! Extracts features from network packets that are used by the AI model
//! to make morphing decisions.

use std::collections::VecDeque;
use std::time::Instant;

/// Maximum context window size
/// NOTE: Flagship model uses 32, legacy uses 16. Default to 32 for new deployments.
pub const CONTEXT_WINDOW_SIZE: usize = 32;

/// Legacy context window size for backward compatibility
pub const CONTEXT_WINDOW_SIZE_LEGACY: usize = 16;

/// Direction of packet flow
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Outbound = 0,
    Inbound = 1,
}

/// Features extracted from a single packet
#[derive(Debug, Clone)]
pub struct PacketFeatures {
    /// Packet size in bytes (normalized: size / 1500.0)
    pub size_normalized: f32,
    /// Raw packet size
    pub size_raw: usize,
    /// Inter-packet delay from previous packet (log-scaled ms)
    pub delay_log_ms: f32,
    /// Direction of packet
    pub direction: Direction,
    /// Position in current burst (0-15, clamped)
    pub burst_position: u8,
    /// Timestamp when packet was observed
    pub timestamp: Instant,
}

impl PacketFeatures {
    /// Create features from raw packet data
    pub fn from_packet(
        packet: &[u8],
        direction: Direction,
        prev_timestamp: Option<Instant>,
    ) -> Self {
        let now = Instant::now();
        let size_raw = packet.len();

        // Normalize size (typical MTU is 1500)
        let size_normalized = (size_raw as f32 / 1500.0).min(1.0);

        // Calculate inter-packet delay (log scale for better distribution)
        let delay_log_ms = prev_timestamp
            .map(|prev| {
                let delay_ms = now.duration_since(prev).as_secs_f32() * 1000.0;
                (delay_ms + 1.0).ln() // log(delay + 1) to handle 0
            })
            .unwrap_or(0.0);

        Self {
            size_normalized,
            size_raw,
            delay_log_ms,
            direction,
            burst_position: 0, // Updated by context
            timestamp: now,
        }
    }

    /// Convert to model input tensor (1D array)
    pub fn to_tensor(&self) -> [f32; 4] {
        [
            self.size_normalized,
            self.delay_log_ms,
            self.direction as u8 as f32,
            self.burst_position as f32 / 15.0, // Normalize to 0-1
        ]
    }
}

/// Rolling context window of recent packets
#[derive(Debug)]
pub struct PacketContext {
    /// Recent packet features
    packets: VecDeque<PacketFeatures>,
    /// Current burst counter (reset on direction change or large delay)
    burst_counter: u8,
    /// Last packet direction
    last_direction: Option<Direction>,
    /// Threshold for burst detection (ms)
    burst_threshold_ms: f32,
}

impl Default for PacketContext {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketContext {
    /// Create new empty context with default burst threshold
    pub fn new() -> Self {
        Self::with_burst_threshold(50.0)
    }

    /// Create context with custom burst threshold
    ///
    /// # Arguments
    /// * `burst_threshold_ms` - Time gap (ms) that defines a new burst.
    ///   Lower values detect smaller gaps as burst boundaries.
    pub fn with_burst_threshold(burst_threshold_ms: f32) -> Self {
        Self {
            packets: VecDeque::with_capacity(CONTEXT_WINDOW_SIZE),
            burst_counter: 0,
            last_direction: None,
            burst_threshold_ms,
        }
    }

    /// Add packet to context, return features with updated burst position
    pub fn add_packet(&mut self, packet: &[u8], direction: Direction) -> PacketFeatures {
        let prev_timestamp = self.packets.back().map(|p| p.timestamp);
        let mut features = PacketFeatures::from_packet(packet, direction, prev_timestamp);

        // Detect burst boundaries
        let is_new_burst = self.last_direction != Some(direction)
            || features.delay_log_ms > (self.burst_threshold_ms + 1.0).ln();

        if is_new_burst {
            self.burst_counter = 0;
        } else {
            self.burst_counter = self.burst_counter.saturating_add(1).min(15);
        }

        features.burst_position = self.burst_counter;
        self.last_direction = Some(direction);

        // Add to window, remove oldest if full
        if self.packets.len() >= CONTEXT_WINDOW_SIZE {
            self.packets.pop_front();
        }
        self.packets.push_back(features.clone());

        features
    }

    /// Get context as 2D tensor for model input
    /// Shape: [CONTEXT_WINDOW_SIZE, 4]
    pub fn to_tensor(&self) -> Vec<f32> {
        let mut tensor = vec![0.0f32; CONTEXT_WINDOW_SIZE * 4];

        for (i, pkt) in self.packets.iter().enumerate() {
            let offset = i * 4;
            let features = pkt.to_tensor();
            tensor[offset..offset + 4].copy_from_slice(&features);
        }

        tensor
    }

    /// Get number of packets in context
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Check if context is empty
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// Clear context (e.g., on connection reset)
    pub fn clear(&mut self) {
        self.packets.clear();
        self.burst_counter = 0;
        self.last_direction = None;
    }

    /// Calculate traffic statistics for profile matching
    pub fn stats(&self) -> TrafficStats {
        if self.packets.is_empty() {
            return TrafficStats::default();
        }

        let sizes: Vec<f32> = self.packets.iter().map(|p| p.size_raw as f32).collect();
        let delays: Vec<f32> = self.packets.iter().map(|p| p.delay_log_ms).collect();

        let mean_size = sizes.iter().sum::<f32>() / sizes.len() as f32;
        let mean_delay = delays.iter().sum::<f32>() / delays.len() as f32;

        let size_variance =
            sizes.iter().map(|s| (s - mean_size).powi(2)).sum::<f32>() / sizes.len() as f32;
        let delay_variance =
            delays.iter().map(|d| (d - mean_delay).powi(2)).sum::<f32>() / delays.len() as f32;

        let outbound_ratio = self
            .packets
            .iter()
            .filter(|p| p.direction == Direction::Outbound)
            .count() as f32
            / self.packets.len() as f32;

        TrafficStats {
            mean_size,
            size_std: size_variance.sqrt(),
            mean_delay_log: mean_delay,
            delay_std: delay_variance.sqrt(),
            outbound_ratio,
            packet_count: self.packets.len(),
        }
    }
}

/// Traffic statistics for profile matching
#[derive(Debug, Clone, Default)]
pub struct TrafficStats {
    pub mean_size: f32,
    pub size_std: f32,
    pub mean_delay_log: f32,
    pub delay_std: f32,
    pub outbound_ratio: f32,
    pub packet_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_features() {
        let packet = vec![0u8; 1000];
        let features = PacketFeatures::from_packet(&packet, Direction::Outbound, None);

        assert!((features.size_normalized - 0.6667).abs() < 0.01);
        assert_eq!(features.size_raw, 1000);
        assert_eq!(features.direction, Direction::Outbound);
    }

    #[test]
    fn test_context_window() {
        let mut ctx = PacketContext::new();

        // Add less than window size packets
        for i in 0..20 {
            let packet = vec![0u8; 100 + i * 10];
            ctx.add_packet(&packet, Direction::Outbound);
        }

        assert_eq!(ctx.len(), 20);
    }

    #[test]
    fn test_burst_detection() {
        let mut ctx = PacketContext::new();

        // Quick succession = same burst
        let p1 = ctx.add_packet(&[0u8; 100], Direction::Outbound);
        let p2 = ctx.add_packet(&[0u8; 100], Direction::Outbound);

        assert_eq!(p1.burst_position, 0);
        // p2 might be 0 or 1 depending on timing
        assert!(p2.burst_position <= 1);

        // Direction change = new burst
        let p3 = ctx.add_packet(&[0u8; 100], Direction::Inbound);
        assert_eq!(p3.burst_position, 0);
    }

    #[test]
    fn test_constants() {
        assert_eq!(CONTEXT_WINDOW_SIZE, 32);
        assert_eq!(CONTEXT_WINDOW_SIZE_LEGACY, 16);
    }

    #[test]
    fn test_direction_values() {
        assert_eq!(Direction::Outbound as u8, 0);
        assert_eq!(Direction::Inbound as u8, 1);
    }

    #[test]
    fn test_direction_clone_copy() {
        let dir = Direction::Outbound;
        let cloned = dir.clone();
        let copied = dir;
        assert_eq!(dir, cloned);
        assert_eq!(dir, copied);
    }

    #[test]
    fn test_direction_debug() {
        let dir = Direction::Inbound;
        let debug = format!("{:?}", dir);
        assert!(debug.contains("Inbound"));
    }

    #[test]
    fn test_packet_features_clone() {
        let packet = vec![0u8; 500];
        let features = PacketFeatures::from_packet(&packet, Direction::Inbound, None);
        let cloned = features.clone();
        assert_eq!(features.size_raw, cloned.size_raw);
        assert_eq!(features.direction, cloned.direction);
    }

    #[test]
    fn test_packet_features_debug() {
        let packet = vec![0u8; 100];
        let features = PacketFeatures::from_packet(&packet, Direction::Outbound, None);
        let debug = format!("{:?}", features);
        assert!(debug.contains("PacketFeatures"));
        assert!(debug.contains("size_raw: 100"));
    }

    #[test]
    fn test_packet_features_to_tensor() {
        let packet = vec![0u8; 750]; // 750/1500 = 0.5
        let mut features = PacketFeatures::from_packet(&packet, Direction::Outbound, None);
        features.burst_position = 8; // 8/15 ≈ 0.533

        let tensor = features.to_tensor();
        assert_eq!(tensor.len(), 4);
        assert!((tensor[0] - 0.5).abs() < 0.01); // size_normalized
        assert_eq!(tensor[2], 0.0); // direction (Outbound = 0)
        assert!((tensor[3] - 8.0 / 15.0).abs() < 0.01); // burst_position normalized
    }

    #[test]
    fn test_packet_features_max_size_clamped() {
        let packet = vec![0u8; 2000]; // > 1500, should clamp to 1.0
        let features = PacketFeatures::from_packet(&packet, Direction::Outbound, None);
        assert_eq!(features.size_normalized, 1.0);
        assert_eq!(features.size_raw, 2000);
    }

    #[test]
    fn test_packet_context_default() {
        let ctx = PacketContext::default();
        assert!(ctx.is_empty());
        assert_eq!(ctx.len(), 0);
    }

    #[test]
    fn test_packet_context_with_burst_threshold() {
        let ctx = PacketContext::with_burst_threshold(100.0);
        assert!(ctx.is_empty());
    }

    #[test]
    fn test_packet_context_clear() {
        let mut ctx = PacketContext::new();
        ctx.add_packet(&[0u8; 100], Direction::Outbound);
        ctx.add_packet(&[0u8; 200], Direction::Inbound);
        assert_eq!(ctx.len(), 2);

        ctx.clear();
        assert!(ctx.is_empty());
        assert_eq!(ctx.len(), 0);
    }

    #[test]
    fn test_packet_context_to_tensor() {
        let mut ctx = PacketContext::new();
        ctx.add_packet(&[0u8; 100], Direction::Outbound);
        ctx.add_packet(&[0u8; 200], Direction::Inbound);

        let tensor = ctx.to_tensor();
        assert_eq!(tensor.len(), CONTEXT_WINDOW_SIZE * 4);

        // First packet features at offset 0
        assert!(tensor[0] > 0.0); // size_normalized
                                  // Second packet at offset 4
        assert!(tensor[4] > 0.0);
        // Rest should be zeros
        assert_eq!(tensor[8], 0.0);
    }

    #[test]
    fn test_packet_context_fills_window() {
        let mut ctx = PacketContext::new();

        // Add more than window size
        for i in 0..40 {
            ctx.add_packet(&vec![0u8; 100 + i], Direction::Outbound);
        }

        // Should cap at CONTEXT_WINDOW_SIZE
        assert_eq!(ctx.len(), CONTEXT_WINDOW_SIZE);
    }

    #[test]
    fn test_packet_context_debug() {
        let ctx = PacketContext::new();
        let debug = format!("{:?}", ctx);
        assert!(debug.contains("PacketContext"));
    }

    #[test]
    fn test_traffic_stats_default() {
        let stats = TrafficStats::default();
        assert_eq!(stats.mean_size, 0.0);
        assert_eq!(stats.size_std, 0.0);
        assert_eq!(stats.mean_delay_log, 0.0);
        assert_eq!(stats.delay_std, 0.0);
        assert_eq!(stats.outbound_ratio, 0.0);
        assert_eq!(stats.packet_count, 0);
    }

    #[test]
    fn test_traffic_stats_clone() {
        let stats = TrafficStats {
            mean_size: 500.0,
            size_std: 100.0,
            mean_delay_log: 2.5,
            delay_std: 0.5,
            outbound_ratio: 0.7,
            packet_count: 10,
        };
        let cloned = stats.clone();
        assert_eq!(stats.mean_size, cloned.mean_size);
        assert_eq!(stats.packet_count, cloned.packet_count);
    }

    #[test]
    fn test_traffic_stats_debug() {
        let stats = TrafficStats::default();
        let debug = format!("{:?}", stats);
        assert!(debug.contains("TrafficStats"));
    }

    #[test]
    fn test_packet_context_stats_empty() {
        let ctx = PacketContext::new();
        let stats = ctx.stats();
        assert_eq!(stats.packet_count, 0);
        assert_eq!(stats.mean_size, 0.0);
    }

    #[test]
    fn test_packet_context_stats_with_data() {
        let mut ctx = PacketContext::new();
        ctx.add_packet(&[0u8; 100], Direction::Outbound);
        ctx.add_packet(&[0u8; 200], Direction::Outbound);
        ctx.add_packet(&[0u8; 300], Direction::Inbound);

        let stats = ctx.stats();
        assert_eq!(stats.packet_count, 3);
        assert!((stats.mean_size - 200.0).abs() < 0.01); // (100+200+300)/3 = 200
        assert!(stats.outbound_ratio > 0.6); // 2/3 ≈ 0.667
        assert!(stats.outbound_ratio < 0.7);
    }

    #[test]
    fn test_packet_context_stats_variance() {
        let mut ctx = PacketContext::new();
        // Add identical packets - variance should be 0
        for _ in 0..5 {
            ctx.add_packet(&[0u8; 100], Direction::Outbound);
        }

        let stats = ctx.stats();
        assert!(stats.size_std < 0.01); // Should be essentially 0
    }

    #[test]
    fn test_packet_features_with_prev_timestamp() {
        let packet1 = vec![0u8; 100];
        let features1 = PacketFeatures::from_packet(&packet1, Direction::Outbound, None);
        let ts = features1.timestamp;

        // Small delay
        std::thread::sleep(std::time::Duration::from_millis(1));

        let packet2 = vec![0u8; 200];
        let features2 = PacketFeatures::from_packet(&packet2, Direction::Inbound, Some(ts));

        // delay_log_ms should be > 0 when there's a previous timestamp
        assert!(features2.delay_log_ms > 0.0);
    }

    #[test]
    fn test_burst_counter_saturation() {
        let mut ctx = PacketContext::with_burst_threshold(1000.0); // High threshold, no burst breaks

        // Add many packets quickly - burst_position should saturate at 15
        for _ in 0..20 {
            let features = ctx.add_packet(&[0u8; 100], Direction::Outbound);
            assert!(features.burst_position <= 15);
        }
    }
}
