//! Packet feature extraction for traffic morphing
//!
//! Extracts features from network packets that are used by the AI model
//! to make morphing decisions.

use std::collections::VecDeque;
use std::time::Instant;

/// Maximum context window size
pub const CONTEXT_WINDOW_SIZE: usize = 16;

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

        // Add more than window size packets
        for i in 0..20 {
            let packet = vec![0u8; 100 + i * 10];
            ctx.add_packet(&packet, Direction::Outbound);
        }

        assert_eq!(ctx.len(), CONTEXT_WINDOW_SIZE);
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
}
