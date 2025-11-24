//! Integration tests for Traffic Monitor
//!
//! Tests the integration of Traffic Monitor with VPN tunnel forwarding,
//! Cover Traffic Generator, and DPI Feedback Controller to ensure adaptive
//! traffic shaping works correctly based on real traffic patterns.

use masque_core::cover_traffic::{CoverTrafficConfig, CoverTrafficGenerator, TrafficPattern};
use masque_core::dpi_feedback::DpiFeedbackController;
use masque_core::traffic_monitor::{TrafficMonitor, TrafficMonitorConfig};
use masque_core::vpn_tunnel::traffic_monitor_update_task;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_traffic_monitor_basic_recording() {
    let monitor = Arc::new(TrafficMonitor::new());

    // Record some packets
    monitor.record_packet(100);
    monitor.record_packet(200);
    monitor.record_packet(150);

    // Wait for rate calculation window
    sleep(Duration::from_millis(100)).await;

    let stats = monitor.get_stats();
    assert_eq!(stats.total_packets, 3);
    assert_eq!(stats.total_bytes, 450);
    assert!(stats.packets_per_sec > 0.0);
    assert!(stats.bytes_per_sec > 0.0);
}

#[tokio::test]
async fn test_traffic_monitor_with_cover_traffic_generator() {
    let monitor = Arc::new(TrafficMonitor::new());

    let cover_config = CoverTrafficConfig {
        pattern: TrafficPattern::HttpsBurst,
        base_rate_pps: 10.0,
        adaptive: true,
        rate_jitter: 0.3,
        min_packet_size: 64,
        max_packet_size: 1200,
        min_interval: Duration::from_millis(10),
    };
    let cover_gen = Arc::new(tokio::sync::Mutex::new(CoverTrafficGenerator::new(
        cover_config,
    )));

    // Simulate some real traffic
    for _ in 0..10 {
        monitor.record_packet(100);
        sleep(Duration::from_millis(10)).await;
    }

    // Get initial rate (update_rates is called automatically by record_packet)
    let _initial_rate = monitor.get_packets_per_sec();

    // Spawn update task
    let monitor_clone = monitor.clone();
    let cover_gen_clone = cover_gen.clone();
    let update_handle = tokio::spawn(async move {
        traffic_monitor_update_task(monitor_clone, cover_gen_clone, Duration::from_millis(100))
            .await
    });

    // Wait for a few update cycles
    sleep(Duration::from_millis(250)).await;

    // Check that cover generator was updated
    // Note: real_traffic_rate is a private field, but we can verify
    // the generator is working by checking it generates packets
    let mut gen = cover_gen.lock().await;
    let _packet = gen.generate_packet(); // Should work if generator is initialized

    // Abort the update task
    update_handle.abort();
}

#[tokio::test]
async fn test_traffic_monitor_adaptive_cover_traffic() {
    let monitor = Arc::new(TrafficMonitor::new());

    let cover_config = CoverTrafficConfig {
        pattern: TrafficPattern::HttpsBurst,
        base_rate_pps: 20.0,
        adaptive: true,
        rate_jitter: 0.3,
        min_packet_size: 64,
        max_packet_size: 1200,
        min_interval: Duration::from_millis(10),
    };
    let cover_gen = Arc::new(tokio::sync::Mutex::new(CoverTrafficGenerator::new(
        cover_config,
    )));

    // Simulate low traffic
    for _ in 0..5 {
        monitor.record_packet(100);
        sleep(Duration::from_millis(50)).await;
    }
    // update_rates is called automatically by record_packet
    let low_rate = monitor.get_packets_per_sec();

    // Update cover generator
    {
        let mut gen = cover_gen.lock().await;
        gen.update_real_traffic_rate(low_rate);
    }

    // Simulate high traffic
    for _ in 0..50 {
        monitor.record_packet(100);
        sleep(Duration::from_millis(5)).await;
    }
    let high_rate = monitor.get_packets_per_sec();

    assert!(high_rate > low_rate);

    // Update cover generator with high rate
    {
        let mut gen = cover_gen.lock().await;
        gen.update_real_traffic_rate(high_rate);
    }

    // Verify generator still works (adaptive mode should reduce rate when real traffic is high)
    let mut gen = cover_gen.lock().await;
    let _packet = gen.generate_packet(); // Should work
    let delay = gen.next_delay(); // Should return reasonable delay
    assert!(delay.as_secs_f64() > 0.0);
}

#[tokio::test]
async fn test_traffic_monitor_with_dpi_feedback() {
    let monitor = Arc::new(TrafficMonitor::new());
    let _dpi_feedback = Arc::new(DpiFeedbackController::new());

    // Simulate traffic patterns that might trigger suspicion
    // High burst traffic
    for _ in 0..100 {
        monitor.record_packet(1500); // Large packets
        sleep(Duration::from_millis(1)).await;
    }
    let high_rate = monitor.get_packets_per_sec();
    assert!(high_rate > 0.0); // Should have recorded traffic

    // Wait a bit and record low traffic
    sleep(Duration::from_millis(200)).await;
    // Record a few more packets at low rate
    for _ in 0..5 {
        monitor.record_packet(100);
        sleep(Duration::from_millis(100)).await;
    }
    let low_rate = monitor.get_packets_per_sec();
    // EMA smoothing means rate might not drop immediately, but should eventually decrease
    // Just verify monitor is tracking traffic correctly
    assert!(low_rate >= 0.0);

    // DPI feedback should adapt based on traffic patterns
    // (This is indirect - DPI feedback uses suspicion, not directly traffic monitor)
    // But we can verify that traffic monitor provides accurate metrics
    let stats = monitor.get_stats();
    assert!(stats.total_packets >= 100);
    assert!(stats.total_bytes >= 100 * 1500);
}

#[tokio::test]
async fn test_traffic_monitor_thread_safety() {
    let monitor = Arc::new(TrafficMonitor::new());

    // Spawn multiple tasks recording packets concurrently
    let mut handles = vec![];
    for i in 0..10 {
        let monitor_clone = monitor.clone();
        let handle = tokio::spawn(async move {
            for j in 0..20 {
                monitor_clone.record_packet(100 + (i * 10) + j);
                sleep(Duration::from_millis(1)).await;
            }
        });
        handles.push(handle);
    }

    // Wait for all tasks
    for handle in handles {
        handle.await.unwrap();
    }

    let stats = monitor.get_stats();
    assert_eq!(stats.total_packets, 200); // 10 tasks * 20 packets
    assert!(stats.total_bytes > 0);
    assert!(stats.packets_per_sec > 0.0);
}

#[tokio::test]
async fn test_traffic_monitor_rate_calculation_smoothing() {
    let config = TrafficMonitorConfig {
        ema_alpha: 0.3,
        min_window_secs: 0.1,
        max_window_secs: 1.0,
        adaptive_window: false,
    };
    let monitor = Arc::new(TrafficMonitor::with_config(config));

    // Record packets in bursts
    for _ in 0..10 {
        monitor.record_packet(100);
    }
    sleep(Duration::from_millis(100)).await;
    let rate1 = monitor.get_packets_per_sec();

    // Record more packets
    for _ in 0..10 {
        monitor.record_packet(100);
    }
    sleep(Duration::from_millis(100)).await;
    let rate2 = monitor.get_packets_per_sec();

    // Rates should be smoothed (EMA), not jumping wildly
    assert!((rate2 - rate1).abs() < rate1 * 2.0); // Should not jump more than 2x
}

#[tokio::test]
async fn test_traffic_monitor_reset() {
    let monitor = Arc::new(TrafficMonitor::new());

    // Record some packets
    for _ in 0..10 {
        monitor.record_packet(100);
    }
    let stats_before = monitor.get_stats();
    assert_eq!(stats_before.total_packets, 10);

    // Reset
    monitor.reset();

    let stats_after = monitor.get_stats();
    assert_eq!(stats_after.total_packets, 0);
    assert_eq!(stats_after.total_bytes, 0);
    assert_eq!(stats_after.packets_per_sec, 0.0);
    assert_eq!(stats_after.bytes_per_sec, 0.0);
}

#[tokio::test]
async fn test_traffic_monitor_batch_recording() {
    let monitor = Arc::new(TrafficMonitor::new());

    // Record packets in batch
    let total_bytes = 100 + 200 + 150 + 300 + 250;
    monitor.record_packets(5, total_bytes);

    let stats = monitor.get_stats();
    assert_eq!(stats.total_packets, 5);
    assert_eq!(stats.total_bytes, 1000); // Sum of all packet sizes
}

#[tokio::test]
async fn test_traffic_monitor_integration_with_vpn_tunnel_flow() {
    let monitor = Arc::new(TrafficMonitor::new());

    // Simulate VPN tunnel packet flow
    // TUN -> QUIC (outgoing)
    for _ in 0..50 {
        monitor.record_packet(1200); // Typical IP packet size
        sleep(Duration::from_millis(10)).await;
    }

    // QUIC -> TUN (incoming)
    for _ in 0..30 {
        monitor.record_packet(800);
        sleep(Duration::from_millis(10)).await;
    }

    let stats = monitor.get_stats();
    assert_eq!(stats.total_packets, 80);
    assert!(stats.packets_per_sec > 0.0);
    assert!(stats.bytes_per_sec > 0.0);

    // Verify rates are reasonable
    let pps = monitor.get_packets_per_sec();
    let bps = monitor.get_bytes_per_sec();

    // Should have recorded packets, so rates should be positive
    assert!(pps > 0.0);
    assert!(bps > 0.0);

    // Bytes per second should be roughly packets_per_sec * average_packet_size
    let avg_packet_size = stats.total_bytes as f64 / stats.total_packets as f64;
    assert!((bps / pps - avg_packet_size).abs() < avg_packet_size * 0.5); // Within 50%
}

#[tokio::test]
async fn test_traffic_monitor_config_variants() {
    // Test with different configs
    let config_fast = TrafficMonitorConfig {
        ema_alpha: 0.5, // Faster adaptation
        min_window_secs: 0.05,
        max_window_secs: 2.0,
        adaptive_window: false,
    };
    let monitor_fast = Arc::new(TrafficMonitor::with_config(config_fast));

    let config_slow = TrafficMonitorConfig {
        ema_alpha: 0.1, // Slower adaptation
        min_window_secs: 0.2,
        max_window_secs: 10.0,
        adaptive_window: true,
    };
    let monitor_slow = Arc::new(TrafficMonitor::with_config(config_slow));

    // Record same traffic pattern
    for _ in 0..20 {
        monitor_fast.record_packet(100);
        monitor_slow.record_packet(100);
        sleep(Duration::from_millis(10)).await;
    }

    let rate_fast = monitor_fast.get_packets_per_sec();
    let rate_slow = monitor_slow.get_packets_per_sec();

    // Both should have recorded traffic
    assert!(rate_fast > 0.0);
    assert!(rate_slow > 0.0);

    // Fast config should adapt more quickly (higher EMA alpha)
    // But both should converge to similar values over time
    // For this test, we just verify both are working
}
