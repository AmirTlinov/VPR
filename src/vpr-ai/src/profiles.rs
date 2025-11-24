//! Traffic profile definitions for morphing targets
//!
//! Each profile defines the statistical characteristics of a legitimate
//! traffic pattern that we want to emulate.

use crate::TrafficProfile;

/// Statistical profile of a traffic type
#[derive(Debug, Clone)]
pub struct ProfileStats {
    /// Profile name
    pub name: TrafficProfile,
    /// Target mean packet size
    pub mean_size: f32,
    /// Target packet size standard deviation
    pub size_std: f32,
    /// Target mean inter-packet delay (log ms)
    pub mean_delay_log: f32,
    /// Target delay standard deviation
    pub delay_std: f32,
    /// Typical outbound/total ratio
    pub outbound_ratio: f32,
    /// Common packet sizes (for bucket padding)
    pub common_sizes: &'static [usize],
    /// Typical burst lengths
    pub burst_lengths: (usize, usize), // (min, max)
}

impl ProfileStats {
    /// Get profile stats for a given profile type
    pub fn for_profile(profile: TrafficProfile) -> Self {
        match profile {
            TrafficProfile::YouTube => YOUTUBE_PROFILE,
            TrafficProfile::Zoom => ZOOM_PROFILE,
            TrafficProfile::Gaming => GAMING_PROFILE,
            TrafficProfile::Browsing => BROWSING_PROFILE,
            TrafficProfile::Netflix => NETFLIX_PROFILE,
        }
    }

    /// Calculate how much padding to add to match this profile
    pub fn suggested_padding(&self, current_size: usize) -> usize {
        // Find nearest common size that's >= current
        for &target in self.common_sizes {
            if target >= current_size {
                return target - current_size;
            }
        }
        // If larger than all common sizes, pad to nearest 64 bytes
        let aligned = (current_size + 63) & !63;
        aligned - current_size
    }

    /// Calculate suggested delay adjustment
    pub fn suggested_delay_ms(&self, current_delay_log: f32) -> f32 {
        // If current delay is too low, add some delay
        if current_delay_log < self.mean_delay_log - self.delay_std {
            let target = self.mean_delay_log - self.delay_std * 0.5;
            let target_ms = target.exp() - 1.0;
            let current_ms = current_delay_log.exp() - 1.0;
            (target_ms - current_ms).max(0.0)
        } else {
            0.0
        }
    }
}

/// YouTube 4K streaming profile
/// Characteristics: Large packets, bursty downloads, small acks
pub const YOUTUBE_PROFILE: ProfileStats = ProfileStats {
    name: TrafficProfile::YouTube,
    mean_size: 1100.0,
    size_std: 400.0,
    mean_delay_log: 2.5,  // ~11ms average
    delay_std: 1.5,
    outbound_ratio: 0.15, // Mostly inbound (video data)
    common_sizes: &[64, 128, 576, 1200, 1400, 1500],
    burst_lengths: (5, 30),
};

/// Zoom video call profile
/// Characteristics: Bidirectional, regular intervals, medium packets
pub const ZOOM_PROFILE: ProfileStats = ProfileStats {
    name: TrafficProfile::Zoom,
    mean_size: 800.0,
    size_std: 300.0,
    mean_delay_log: 2.0,  // ~6ms average (for 30fps video)
    delay_std: 0.8,
    outbound_ratio: 0.45, // Nearly symmetric
    common_sizes: &[64, 200, 400, 800, 1200],
    burst_lengths: (2, 8),
};

/// Online gaming (FPS) profile
/// Characteristics: Small packets, very low latency, regular
pub const GAMING_PROFILE: ProfileStats = ProfileStats {
    name: TrafficProfile::Gaming,
    mean_size: 150.0,
    size_std: 80.0,
    mean_delay_log: 1.5,  // ~3.5ms average (high tick rate)
    delay_std: 0.5,
    outbound_ratio: 0.50, // Symmetric
    common_sizes: &[32, 64, 128, 256, 512],
    burst_lengths: (1, 4),
};

/// Web browsing profile
/// Characteristics: Bursty, variable sizes, long pauses
pub const BROWSING_PROFILE: ProfileStats = ProfileStats {
    name: TrafficProfile::Browsing,
    mean_size: 600.0,
    size_std: 500.0,
    mean_delay_log: 3.5,  // ~32ms average (includes think time)
    delay_std: 2.0,
    outbound_ratio: 0.25, // Mostly downloads
    common_sizes: &[64, 256, 512, 1024, 1400, 1500],
    burst_lengths: (3, 20),
};

/// Netflix streaming profile
/// Similar to YouTube but with different packet patterns
pub const NETFLIX_PROFILE: ProfileStats = ProfileStats {
    name: TrafficProfile::Netflix,
    mean_size: 1200.0,
    size_std: 350.0,
    mean_delay_log: 2.3,  // ~9ms average
    delay_std: 1.2,
    outbound_ratio: 0.10, // Almost all inbound
    common_sizes: &[64, 576, 1200, 1400, 1500],
    burst_lengths: (10, 50),
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_padding() {
        let youtube = ProfileStats::for_profile(TrafficProfile::YouTube);

        assert_eq!(youtube.suggested_padding(50), 14);   // -> 64
        assert_eq!(youtube.suggested_padding(64), 0);    // already aligned
        assert_eq!(youtube.suggested_padding(100), 28);  // -> 128
        assert_eq!(youtube.suggested_padding(1400), 0);  // exactly on boundary
    }

    #[test]
    fn test_profile_delay() {
        let gaming = ProfileStats::for_profile(TrafficProfile::Gaming);

        // Very fast packet should be delayed
        let delay = gaming.suggested_delay_ms(0.5);
        assert!(delay > 0.0);

        // Normal speed packet should not be delayed
        let delay = gaming.suggested_delay_ms(1.5);
        assert_eq!(delay, 0.0);
    }
}
