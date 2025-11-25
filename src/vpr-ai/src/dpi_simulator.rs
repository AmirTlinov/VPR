//! Aggressive DPI Simulator for E2E testing of traffic morphing.
//!
//! Simulates a paranoid ISP that blocks VPN traffic at the slightest suspicion.
//! Uses multiple detection techniques based on real-world DPI systems.

use std::collections::VecDeque;

/// Detection result from DPI analysis
#[derive(Debug, Clone, PartialEq)]
pub enum DpiVerdict {
    /// Traffic looks legitimate
    Pass,
    /// Suspicious but not blocked (warning)
    Suspicious(String),
    /// Blocked - VPN detected
    Blocked(String),
}

/// Paranoid DPI simulator with aggressive detection rules
pub struct ParanoidDpi {
    /// Packet size history for pattern analysis
    size_history: VecDeque<u16>,
    /// Inter-arrival time history (ms)
    timing_history: VecDeque<f64>,
    /// Direction history (-1 inbound, 1 outbound)
    direction_history: VecDeque<i8>,
    /// Consecutive similar sizes (VPN fingerprint)
    consecutive_similar: u32,
    /// Total packets analyzed
    total_packets: u64,
    /// Suspicion score (0-100)
    suspicion_score: f64,
    /// Configuration
    config: DpiConfig,
}

/// DPI detection sensitivity configuration
#[derive(Debug, Clone)]
pub struct DpiConfig {
    /// History window size for pattern analysis
    pub window_size: usize,
    /// Threshold for blocking (suspicion score)
    pub block_threshold: f64,
    /// Threshold for suspicious warning
    pub warn_threshold: f64,
    /// Enable entropy analysis
    pub check_entropy: bool,
    /// Enable timing analysis
    pub check_timing: bool,
    /// Enable size pattern analysis
    pub check_size_patterns: bool,
    /// Enable direction ratio analysis
    pub check_direction_ratio: bool,
    /// Enable burst detection
    pub check_bursts: bool,
}

impl Default for DpiConfig {
    fn default() -> Self {
        Self {
            window_size: 50,
            block_threshold: 60.0,
            warn_threshold: 35.0,
            check_entropy: true,
            check_timing: true,
            check_size_patterns: true,
            check_direction_ratio: true,
            check_bursts: true,
        }
    }
}

impl DpiConfig {
    /// Maximum paranoia - blocks at slightest suspicion
    pub fn paranoid() -> Self {
        Self {
            window_size: 30,
            block_threshold: 25.0, // Very low threshold
            warn_threshold: 10.0,
            check_entropy: true,
            check_timing: true,
            check_size_patterns: true,
            check_direction_ratio: true,
            check_bursts: true,
        }
    }

    /// China-style DPI (very aggressive)
    pub fn china_gfw() -> Self {
        Self {
            window_size: 20,
            block_threshold: 30.0,
            warn_threshold: 15.0,
            check_entropy: true,
            check_timing: true,
            check_size_patterns: true,
            check_direction_ratio: true,
            check_bursts: true,
        }
    }

    /// Russia-style DPI (Roskomnadzor)
    pub fn russia_rkn() -> Self {
        Self {
            window_size: 40,
            block_threshold: 40.0,
            warn_threshold: 20.0,
            check_entropy: true,
            check_timing: true,
            check_size_patterns: true,
            check_direction_ratio: false, // Less sophisticated
            check_bursts: true,
        }
    }

    /// Iran-style DPI
    pub fn iran() -> Self {
        Self {
            window_size: 25,
            block_threshold: 35.0,
            warn_threshold: 18.0,
            check_entropy: true,
            check_timing: true,
            check_size_patterns: true,
            check_direction_ratio: true,
            check_bursts: true,
        }
    }
}

impl ParanoidDpi {
    pub fn new(config: DpiConfig) -> Self {
        Self {
            size_history: VecDeque::with_capacity(config.window_size),
            timing_history: VecDeque::with_capacity(config.window_size),
            direction_history: VecDeque::with_capacity(config.window_size),
            consecutive_similar: 0,
            total_packets: 0,
            suspicion_score: 0.0,
            config,
        }
    }

    /// Analyze a packet and return DPI verdict
    pub fn analyze_packet(&mut self, size: u16, delay_ms: f64, direction: i8) -> DpiVerdict {
        self.total_packets += 1;

        // Update histories
        if self.size_history.len() >= self.config.window_size {
            self.size_history.pop_front();
            self.timing_history.pop_front();
            self.direction_history.pop_front();
        }
        self.size_history.push_back(size);
        self.timing_history.push_back(delay_ms);
        self.direction_history.push_back(direction);

        // Reset suspicion with decay
        self.suspicion_score *= 0.95;

        // Run all detection checks
        let mut reasons = Vec::new();

        if self.config.check_size_patterns {
            if let Some(reason) = self.check_size_patterns(size) {
                reasons.push(reason);
            }
        }

        if self.config.check_timing {
            if let Some(reason) = self.check_timing_patterns(delay_ms) {
                reasons.push(reason);
            }
        }

        if self.config.check_direction_ratio {
            if let Some(reason) = self.check_direction_ratio() {
                reasons.push(reason);
            }
        }

        if self.config.check_entropy {
            if let Some(reason) = self.check_size_entropy() {
                reasons.push(reason);
            }
        }

        if self.config.check_bursts {
            if let Some(reason) = self.check_burst_patterns() {
                reasons.push(reason);
            }
        }

        // Additional VPN-specific checks
        if let Some(reason) = self.check_mtu_signatures(size) {
            reasons.push(reason);
        }

        if let Some(reason) = self.check_keepalive_patterns(size, delay_ms) {
            reasons.push(reason);
        }

        // Determine verdict
        if self.suspicion_score >= self.config.block_threshold {
            DpiVerdict::Blocked(format!(
                "VPN detected (score: {:.1}): {}",
                self.suspicion_score,
                reasons.join(", ")
            ))
        } else if self.suspicion_score >= self.config.warn_threshold {
            DpiVerdict::Suspicious(format!(
                "Suspicious traffic (score: {:.1}): {}",
                self.suspicion_score,
                reasons.join(", ")
            ))
        } else {
            DpiVerdict::Pass
        }
    }

    /// Check for VPN-like size patterns
    fn check_size_patterns(&mut self, size: u16) -> Option<String> {
        // Check for consecutive similar sizes (VPN fingerprint)
        if let Some(&last_size) = self.size_history.iter().rev().nth(1) {
            let diff = (size as i32 - last_size as i32).unsigned_abs();
            if diff < 10 {
                self.consecutive_similar += 1;
                if self.consecutive_similar > 5 {
                    self.suspicion_score += 8.0;
                    return Some("consecutive similar sizes".into());
                }
            } else {
                self.consecutive_similar = 0;
            }
        }

        // Check for fixed-size patterns (common in VPN protocols)
        let common_vpn_sizes = [64, 128, 256, 512, 1024, 1280, 1400, 1420, 1440, 1460];
        if common_vpn_sizes.contains(&(size as usize)) {
            self.suspicion_score += 3.0;
            return Some(format!("common VPN packet size: {}", size));
        }

        // Check for MTU-aligned sizes
        if size == 1500 || size == 1492 || size == 1472 {
            self.suspicion_score += 5.0;
            return Some("MTU-aligned packet".into());
        }

        None
    }

    /// Check for VPN-like timing patterns
    fn check_timing_patterns(&mut self, delay_ms: f64) -> Option<String> {
        if self.timing_history.len() < 5 {
            return None;
        }

        // Calculate timing variance
        let mean: f64 = self.timing_history.iter().sum::<f64>() / self.timing_history.len() as f64;
        let variance: f64 = self
            .timing_history
            .iter()
            .map(|&t| (t - mean).powi(2))
            .sum::<f64>()
            / self.timing_history.len() as f64;
        let std_dev = variance.sqrt();

        // Very regular timing is suspicious (VPN keepalive)
        if std_dev < 2.0 && mean > 10.0 {
            self.suspicion_score += 12.0;
            return Some(format!("regular timing (std_dev: {:.2}ms)", std_dev));
        }

        // Very low latency bursts (tunnel traffic)
        if delay_ms < 1.0 && self.timing_history.iter().filter(|&&t| t < 1.0).count() > 3 {
            self.suspicion_score += 6.0;
            return Some("rapid packet bursts".into());
        }

        // Check for periodic patterns (keepalive)
        if self.timing_history.len() >= 10 {
            let diffs: Vec<f64> = self
                .timing_history
                .iter()
                .zip(self.timing_history.iter().skip(1))
                .map(|(a, b)| (b - a).abs())
                .collect();

            let mean_diff: f64 = diffs.iter().sum::<f64>() / diffs.len() as f64;
            let periodic = diffs
                .iter()
                .filter(|&&d| (d - mean_diff).abs() < 5.0)
                .count();

            if periodic > diffs.len() * 7 / 10 {
                self.suspicion_score += 15.0;
                return Some("periodic timing pattern".into());
            }
        }

        None
    }

    /// Check direction ratio (VPN typically has more balanced ratio)
    fn check_direction_ratio(&mut self) -> Option<String> {
        if self.direction_history.len() < 20 {
            return None;
        }

        let outbound: usize = self.direction_history.iter().filter(|&&d| d > 0).count();
        let total = self.direction_history.len();
        let ratio = outbound as f64 / total as f64;

        // VPN traffic often has balanced ratio (0.4-0.6)
        // Real browsing is more asymmetric (0.1-0.3 outbound)
        if (0.4..=0.6).contains(&ratio) {
            self.suspicion_score += 8.0;
            return Some(format!("balanced direction ratio: {:.2}", ratio));
        }

        None
    }

    /// Check size entropy (VPN has lower entropy due to padding)
    fn check_size_entropy(&mut self) -> Option<String> {
        if self.size_history.len() < 20 {
            return None;
        }

        // Bucket sizes and calculate entropy
        let mut buckets = [0u32; 16];
        for &size in &self.size_history {
            let bucket = (size / 100).min(15) as usize;
            buckets[bucket] += 1;
        }

        let total = self.size_history.len() as f64;
        let entropy: f64 = buckets
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / total;
                -p * p.log2()
            })
            .sum();

        // Low entropy = more uniform = suspicious
        if entropy < 1.5 {
            self.suspicion_score += 10.0;
            return Some(format!("low size entropy: {:.2}", entropy));
        }

        // Very high entropy with many unique sizes = also suspicious (random padding)
        if entropy > 3.5 {
            self.suspicion_score += 5.0;
            return Some(format!(
                "high size entropy (random padding?): {:.2}",
                entropy
            ));
        }

        None
    }

    /// Check for burst patterns typical of tunneled traffic
    fn check_burst_patterns(&mut self) -> Option<String> {
        if self.timing_history.len() < 10 {
            return None;
        }

        // Count rapid sequences (< 5ms apart)
        let rapid_count = self.timing_history.iter().filter(|&&t| t < 5.0).count();

        let rapid_ratio = rapid_count as f64 / self.timing_history.len() as f64;

        if rapid_ratio > 0.6 {
            self.suspicion_score += 10.0;
            return Some(format!("high burst ratio: {:.1}%", rapid_ratio * 100.0));
        }

        None
    }

    /// Check for MTU-related signatures
    fn check_mtu_signatures(&mut self, size: u16) -> Option<String> {
        // WireGuard-like sizes (148 header + payload)
        #[allow(clippy::incompatible_msrv)]
        if size > 148 && (size - 148).is_multiple_of(16) {
            self.suspicion_score += 4.0;
            return Some("WireGuard-like alignment".into());
        }

        // OpenVPN-like sizes
        #[allow(clippy::incompatible_msrv)]
        if size > 48 && (size - 48).is_multiple_of(16) {
            self.suspicion_score += 3.0;
            return Some("OpenVPN-like alignment".into());
        }

        // IPsec ESP patterns
        #[allow(clippy::incompatible_msrv)]
        if size > 20 && (size - 20).is_multiple_of(8) && size > 100 {
            self.suspicion_score += 2.0;
        }

        None
    }

    /// Check for keepalive patterns
    fn check_keepalive_patterns(&mut self, size: u16, delay_ms: f64) -> Option<String> {
        // Small packets with regular timing = keepalive
        if size < 100 && delay_ms > 1000.0 {
            let small_count = self.size_history.iter().filter(|&&s| s < 100).count();
            if small_count > self.size_history.len() / 3 {
                self.suspicion_score += 7.0;
                return Some("keepalive pattern detected".into());
            }
        }

        None
    }

    /// Get current suspicion score
    pub fn suspicion_score(&self) -> f64 {
        self.suspicion_score
    }

    /// Reset DPI state
    pub fn reset(&mut self) {
        self.size_history.clear();
        self.timing_history.clear();
        self.direction_history.clear();
        self.consecutive_similar = 0;
        self.total_packets = 0;
        self.suspicion_score = 0.0;
    }

    /// Get statistics
    pub fn stats(&self) -> DpiStats {
        DpiStats {
            total_packets: self.total_packets,
            suspicion_score: self.suspicion_score,
            window_fill: self.size_history.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DpiStats {
    pub total_packets: u64,
    pub suspicion_score: f64,
    pub window_fill: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_traffic_passes() {
        let mut dpi = ParanoidDpi::new(DpiConfig::default());

        // Simulate normal HTTPS browsing - variable sizes, asymmetric
        let packets = [
            (200, 50.0, 1),   // request
            (1400, 10.0, -1), // response chunk
            (1400, 5.0, -1),  // response chunk
            (1350, 8.0, -1),  // response chunk
            (64, 100.0, 1),   // ack
            (350, 200.0, 1),  // new request
            (1200, 15.0, -1), // response
            (800, 12.0, -1),  // response
        ];

        let mut blocked = false;
        for (size, delay, dir) in packets {
            if let DpiVerdict::Blocked(_) = dpi.analyze_packet(size, delay, dir) {
                blocked = true;
            }
        }

        assert!(!blocked, "Normal traffic should not be blocked");
    }

    #[test]
    fn test_vpn_like_traffic_detected() {
        let mut dpi = ParanoidDpi::new(DpiConfig::paranoid());

        // Simulate obvious VPN traffic - regular sizes, balanced direction
        for i in 0..30 {
            let size = 1420 + (i % 3) as u16; // Nearly fixed size
            let delay = 20.0 + (i % 2) as f64; // Regular timing
            let dir = if i % 2 == 0 { 1 } else { -1 }; // Balanced

            let verdict = dpi.analyze_packet(size, delay, dir);
            if let DpiVerdict::Blocked(reason) = verdict {
                println!("Blocked at packet {}: {}", i, reason);
                return; // Test passed - VPN detected
            }
        }

        panic!("VPN traffic should have been detected");
    }

    #[test]
    fn test_china_gfw_sensitivity() {
        let mut dpi = ParanoidDpi::new(DpiConfig::china_gfw());

        // Even slightly suspicious traffic should trigger
        let mut warnings = 0;
        let mut blocks = 0;

        for i in 0..50 {
            let size = 1200 + ((i * 17) % 200) as u16;
            let delay = 30.0 + ((i * 7) % 50) as f64;
            let dir = if i % 3 == 0 { 1 } else { -1 };

            match dpi.analyze_packet(size, delay, dir) {
                DpiVerdict::Suspicious(_) => warnings += 1,
                DpiVerdict::Blocked(_) => blocks += 1,
                DpiVerdict::Pass => {}
            }
        }

        println!("GFW test: {} warnings, {} blocks", warnings, blocks);
        assert!(warnings + blocks > 0, "GFW should detect something");
    }
}
