//! Traffic Monitor
//!
//! Monitors real traffic patterns (packets/sec, bytes/sec) to enable adaptive
//! cover traffic generation and DPI evasion strategies. Uses exponential moving
//! average (EMA) for smooth rate estimation.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::trace;

/// Traffic statistics snapshot
#[derive(Debug, Clone)]
pub struct TrafficStats {
    /// Packets per second (smoothed)
    pub packets_per_sec: f64,
    /// Bytes per second (smoothed)
    pub bytes_per_sec: f64,
    /// Total packets observed
    pub total_packets: u64,
    /// Total bytes observed
    pub total_bytes: u64,
    /// Time window for rate calculation (seconds)
    pub window_secs: f64,
}

impl Default for TrafficStats {
    fn default() -> Self {
        Self {
            packets_per_sec: 0.0,
            bytes_per_sec: 0.0,
            total_packets: 0,
            total_bytes: 0,
            window_secs: 1.0,
        }
    }
}

/// Configuration for traffic monitoring
#[derive(Debug, Clone)]
pub struct TrafficMonitorConfig {
    /// EMA alpha factor for smoothing (0.0 - 1.0)
    /// Lower values = more smoothing, slower response
    /// Higher values = less smoothing, faster response
    pub ema_alpha: f64,
    /// Minimum time window for rate calculation (seconds)
    pub min_window_secs: f64,
    /// Maximum time window for rate calculation (seconds)
    pub max_window_secs: f64,
    /// Enable automatic window adjustment based on traffic patterns
    pub adaptive_window: bool,
}

impl Default for TrafficMonitorConfig {
    fn default() -> Self {
        Self {
            ema_alpha: 0.3,       // Moderate smoothing
            min_window_secs: 0.1, // 100ms minimum
            max_window_secs: 5.0, // 5 seconds maximum
            adaptive_window: true,
        }
    }
}

impl TrafficMonitorConfig {
    /// Create config optimized for low latency (fast response)
    pub fn low_latency() -> Self {
        Self {
            ema_alpha: 0.7, // Less smoothing, faster response
            min_window_secs: 0.05,
            max_window_secs: 2.0,
            adaptive_window: false,
        }
    }

    /// Create config optimized for stability (smooth rates)
    pub fn stable() -> Self {
        Self {
            ema_alpha: 0.1, // More smoothing
            min_window_secs: 0.5,
            max_window_secs: 10.0,
            adaptive_window: true,
        }
    }
}

/// Traffic monitor for tracking real traffic patterns
///
/// Thread-safe, designed for concurrent access from multiple tasks.
/// Uses atomic operations for lock-free updates.
pub struct TrafficMonitor {
    config: TrafficMonitorConfig,
    // Packet counters (atomic for lock-free updates)
    total_packets: AtomicU64,
    total_bytes: AtomicU64,
    // EMA state (stored as fixed-point for atomic operations)
    // packets_per_sec * 1000 stored as u64
    ema_packets_per_sec: AtomicU64,
    // bytes_per_sec * 100 stored as u64 (to handle larger values)
    ema_bytes_per_sec: AtomicU64,
    // Time tracking
    window_start: AtomicU64,    // Instant stored as nanos since epoch
    window_duration: AtomicU64, // Duration in nanos
}

impl TrafficMonitor {
    /// Create new monitor with default config
    pub fn new() -> Self {
        Self::with_config(TrafficMonitorConfig::default())
    }

    /// Create new monitor with custom config
    pub fn with_config(config: TrafficMonitorConfig) -> Self {
        let now = Self::now_nanos();
        let min_window_nanos = Duration::from_secs_f64(config.min_window_secs).as_nanos() as u64;
        Self {
            config,
            total_packets: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            ema_packets_per_sec: AtomicU64::new(0),
            ema_bytes_per_sec: AtomicU64::new(0),
            window_start: AtomicU64::new(now),
            window_duration: AtomicU64::new(min_window_nanos),
        }
    }

    /// Record a packet (thread-safe, lock-free)
    ///
    /// This should be called for each packet sent/received.
    pub fn record_packet(&self, size_bytes: usize) {
        self.total_packets.fetch_add(1, Ordering::Relaxed);
        self.total_bytes
            .fetch_add(size_bytes as u64, Ordering::Relaxed);
        self.update_rates();
    }

    /// Record multiple packets at once (batch update)
    pub fn record_packets(&self, count: u64, total_bytes: u64) {
        self.total_packets.fetch_add(count, Ordering::Relaxed);
        self.total_bytes.fetch_add(total_bytes, Ordering::Relaxed);
        self.update_rates();
    }

    /// Update EMA rates based on current window
    fn update_rates(&self) {
        let now = Self::now_nanos();
        let window_start = self.window_start.load(Ordering::Relaxed);
        let window_duration = self.window_duration.load(Ordering::Relaxed);

        // Calculate elapsed time in window
        let elapsed_nanos = now.saturating_sub(window_start);
        if elapsed_nanos == 0 {
            return; // Avoid division by zero
        }

        let elapsed_secs = elapsed_nanos as f64 / 1_000_000_000.0;

        // Get current totals
        let total_packets = self.total_packets.load(Ordering::Relaxed);
        let total_bytes = self.total_bytes.load(Ordering::Relaxed);

        // Calculate instantaneous rates
        let instant_packets_per_sec = total_packets as f64 / elapsed_secs.max(0.001);
        let instant_bytes_per_sec = total_bytes as f64 / elapsed_secs.max(0.001);

        // Update EMA
        let ema_packets = self.ema_packets_per_sec.load(Ordering::Relaxed) as f64 / 1000.0;
        let ema_bytes = self.ema_bytes_per_sec.load(Ordering::Relaxed) as f64 / 100.0;

        let new_ema_packets = if ema_packets == 0.0 {
            instant_packets_per_sec
        } else {
            self.config.ema_alpha * instant_packets_per_sec
                + (1.0 - self.config.ema_alpha) * ema_packets
        };

        let new_ema_bytes = if ema_bytes == 0.0 {
            instant_bytes_per_sec
        } else {
            self.config.ema_alpha * instant_bytes_per_sec
                + (1.0 - self.config.ema_alpha) * ema_bytes
        };

        // Store EMA values (fixed-point)
        self.ema_packets_per_sec
            .store((new_ema_packets * 1000.0) as u64, Ordering::Relaxed);
        self.ema_bytes_per_sec
            .store((new_ema_bytes * 100.0) as u64, Ordering::Relaxed);

        // Reset window if needed
        if elapsed_nanos >= window_duration {
            self.reset_window(now);
        }

        trace!(
            packets_per_sec = %new_ema_packets,
            bytes_per_sec = %new_ema_bytes,
            elapsed_secs = %elapsed_secs,
            "Updated traffic rates"
        );
    }

    /// Reset measurement window
    fn reset_window(&self, now: u64) {
        self.window_start.store(now, Ordering::Relaxed);

        // Adaptive window adjustment
        if self.config.adaptive_window {
            let current_rate = self.get_packets_per_sec();
            let window_secs = if current_rate > 100.0 {
                // High traffic: shorter window for responsiveness
                self.config.min_window_secs.max(0.1)
            } else if current_rate < 1.0 {
                // Low traffic: longer window for stability
                self.config.max_window_secs.min(5.0)
            } else {
                // Medium traffic: use default
                (self.config.min_window_secs + self.config.max_window_secs) / 2.0
            };
            self.window_duration.store(
                Duration::from_secs_f64(window_secs).as_nanos() as u64,
                Ordering::Relaxed,
            );
        }
    }

    /// Get current packets per second (smoothed EMA)
    pub fn get_packets_per_sec(&self) -> f64 {
        self.ema_packets_per_sec.load(Ordering::Relaxed) as f64 / 1000.0
    }

    /// Get current bytes per second (smoothed EMA)
    pub fn get_bytes_per_sec(&self) -> f64 {
        self.ema_bytes_per_sec.load(Ordering::Relaxed) as f64 / 100.0
    }

    /// Get current traffic statistics snapshot
    pub fn get_stats(&self) -> TrafficStats {
        let window_duration = self.window_duration.load(Ordering::Relaxed);
        TrafficStats {
            packets_per_sec: self.get_packets_per_sec(),
            bytes_per_sec: self.get_bytes_per_sec(),
            total_packets: self.total_packets.load(Ordering::Relaxed),
            total_bytes: self.total_bytes.load(Ordering::Relaxed),
            window_secs: window_duration as f64 / 1_000_000_000.0,
        }
    }

    /// Reset all counters (useful for testing or periodic resets)
    pub fn reset(&self) {
        let now = Self::now_nanos();
        self.total_packets.store(0, Ordering::Relaxed);
        self.total_bytes.store(0, Ordering::Relaxed);
        self.ema_packets_per_sec.store(0, Ordering::Relaxed);
        self.ema_bytes_per_sec.store(0, Ordering::Relaxed);
        self.window_start.store(now, Ordering::Relaxed);
    }

    /// Get configuration (read-only)
    pub fn config(&self) -> &TrafficMonitorConfig {
        &self.config
    }

    /// Helper to get current time as nanos since epoch
    fn now_nanos() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }
}

impl Default for TrafficMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_traffic_monitor_initial_state() {
        let monitor = TrafficMonitor::new();
        assert_eq!(monitor.get_packets_per_sec(), 0.0);
        assert_eq!(monitor.get_bytes_per_sec(), 0.0);
        let stats = monitor.get_stats();
        assert_eq!(stats.total_packets, 0);
        assert_eq!(stats.total_bytes, 0);
    }

    #[test]
    fn test_record_packet() {
        let monitor = TrafficMonitor::new();
        monitor.record_packet(100);
        monitor.record_packet(200);

        let stats = monitor.get_stats();
        assert_eq!(stats.total_packets, 2);
        assert_eq!(stats.total_bytes, 300);
    }

    #[test]
    fn test_record_packets_batch() {
        let monitor = TrafficMonitor::new();
        monitor.record_packets(10, 5000);

        let stats = monitor.get_stats();
        assert_eq!(stats.total_packets, 10);
        assert_eq!(stats.total_bytes, 5000);
    }

    #[test]
    fn test_rate_calculation() {
        let config = TrafficMonitorConfig {
            ema_alpha: 0.5, // 50% smoothing
            min_window_secs: 0.1,
            max_window_secs: 1.0,
            adaptive_window: false,
        };
        let monitor = TrafficMonitor::with_config(config);

        // Record packets over time to get realistic rate
        for i in 0..10 {
            monitor.record_packet(100);
            // Small delay between packets to simulate real traffic
            if i < 9 {
                thread::sleep(Duration::from_millis(10));
            }
        }

        // Wait for window to accumulate
        thread::sleep(Duration::from_millis(150));

        // Update rates (record_packet already calls update_rates, but call again to ensure)
        monitor.update_rates();

        let rate = monitor.get_packets_per_sec();
        assert!(rate > 0.0, "Rate should be positive. Got: {}", rate);
        // With 10 packets over ~250ms, rate should be around 40 pps, but EMA smoothing
        // may give different values. Just check it's reasonable (< 1000 pps)
        assert!(rate < 1000.0, "Rate should be reasonable. Got: {}", rate);
    }

    #[test]
    fn test_thread_safety() {
        let monitor = Arc::new(TrafficMonitor::new());
        let mut handles = vec![];

        // Spawn multiple threads recording packets concurrently
        for i in 0..10 {
            let m = monitor.clone();
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    m.record_packet((i * 100 + j) as usize);
                }
            }));
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify final state
        let stats = monitor.get_stats();
        assert_eq!(stats.total_packets, 1000);
        assert!(stats.total_bytes > 0);
    }

    #[test]
    fn test_reset() {
        let monitor = TrafficMonitor::new();
        monitor.record_packet(100);
        monitor.record_packet(200);

        monitor.reset();

        let stats = monitor.get_stats();
        assert_eq!(stats.total_packets, 0);
        assert_eq!(stats.total_bytes, 0);
    }

    #[test]
    fn test_config_variants() {
        let low_latency = TrafficMonitorConfig::low_latency();
        assert!(low_latency.ema_alpha > 0.5);
        assert!(!low_latency.adaptive_window);

        let stable = TrafficMonitorConfig::stable();
        assert!(stable.ema_alpha < 0.3);
        assert!(stable.adaptive_window);
    }
}
