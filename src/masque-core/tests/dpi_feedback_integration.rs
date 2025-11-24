//! Integration tests for DPI Feedback Controller
//!
//! Tests the integration of DPI Feedback with Padder, SuspicionTracker,
//! and VPN tunnel forwarding to ensure adaptive traffic shaping works correctly.

use masque_core::dpi_feedback::{DpiFeedbackConfig, DpiFeedbackController};
use masque_core::padding::{Padder, PaddingConfig, PaddingStrategy, SuspicionBucket};
use masque_core::suspicion::SuspicionTracker;
use masque_core::vpn_tunnel::suspicion_update_task;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

#[test]
fn test_dpi_feedback_with_padder_adaptation() {
    // Create DPI feedback controller with custom thresholds
    let config = DpiFeedbackConfig {
        low_threshold: 20.0,
        medium_threshold: 20.0,
        high_threshold: 70.0,
        hysteresis: 5.0,
        update_interval: Duration::from_secs(1),
        min_cover_multiplier: 0.5,
        max_cover_multiplier: 2.0,
        aggressive_mode_enabled: true,
        aggressive_threshold: 85.0,
    };
    let dpi_feedback = Arc::new(DpiFeedbackController::with_config(config));

    // Create padder with adaptive mode enabled
    let mut padder_config = PaddingConfig::default();
    padder_config.adaptive = true;
    padder_config.low_strategy = PaddingStrategy::RandomBucket;
    padder_config.medium_strategy = PaddingStrategy::Bucket;
    padder_config.high_strategy = PaddingStrategy::Mtu;
    padder_config.medium_threshold = 20;
    padder_config.high_threshold = 70;
    padder_config.hysteresis = 5;
    let padder = Arc::new(Padder::new(padder_config));

    // Test low suspicion -> RandomBucket
    dpi_feedback.update_suspicion(10.0);
    padder.update_suspicion(dpi_feedback.current_suspicion());
    assert_eq!(padder.suspicion_bucket(), SuspicionBucket::Low);
    // Verify padding behavior: RandomBucket should pad to bucket sizes
    let small_packet = vec![0u8; 10];
    let padded_low = padder.padded_size(small_packet.len());
    assert!(padded_low >= padder.config().min_packet_size);
    assert!(padded_low <= padder.config().mtu);

    // Test medium suspicion -> Bucket
    dpi_feedback.update_suspicion(30.0);
    padder.update_suspicion(dpi_feedback.current_suspicion());
    assert_eq!(padder.suspicion_bucket(), SuspicionBucket::Medium);
    // Bucket strategy should pad to fixed bucket sizes
    let padded_medium = padder.padded_size(small_packet.len());
    assert!(padded_medium >= padder.config().min_packet_size);

    // Test high suspicion -> Mtu
    dpi_feedback.update_suspicion(75.0);
    padder.update_suspicion(dpi_feedback.current_suspicion());
    assert_eq!(padder.suspicion_bucket(), SuspicionBucket::High);
    // Mtu strategy should pad to MTU size
    let padded_high = padder.padded_size(small_packet.len());
    assert_eq!(padded_high, padder.config().mtu);
}

#[tokio::test]
async fn test_dpi_feedback_with_suspicion_tracker() {
    let suspicion_tracker = Arc::new(SuspicionTracker::with_half_life(1.0));
    let dpi_feedback = Arc::new(DpiFeedbackController::new());

    // Add suspicion events
    suspicion_tracker.add(30.0);
    suspicion_tracker.add(20.0);

    // Update DPI feedback from tracker
    let score = suspicion_tracker.current();
    dpi_feedback.update_suspicion(score);

    // Verify suspicion score is reflected
    assert!(dpi_feedback.current_suspicion() > 0.0);
    assert!(dpi_feedback.current_suspicion() <= 100.0);

    // Wait for decay
    sleep(Duration::from_millis(1100)).await;

    // Update again after decay
    let decayed_score = suspicion_tracker.current();
    dpi_feedback.update_suspicion(decayed_score);

    // Verify score decreased
    assert!(dpi_feedback.current_suspicion() < score);
}

#[tokio::test]
async fn test_suspicion_update_task() {
    let suspicion_tracker = Arc::new(SuspicionTracker::with_half_life(0.5));
    let config = DpiFeedbackConfig {
        update_interval: Duration::from_millis(100),
        ..Default::default()
    };
    let dpi_feedback = Arc::new(DpiFeedbackController::with_config(config));

    // Add initial suspicion
    suspicion_tracker.add(50.0);

    // Spawn update task
    let tracker_clone = suspicion_tracker.clone();
    let feedback_clone = dpi_feedback.clone();
    let update_handle = tokio::spawn(async move {
        let _ = suspicion_update_task(tracker_clone, feedback_clone).await;
    });

    // Wait for a few update cycles
    sleep(Duration::from_millis(350)).await;

    // Verify DPI feedback was updated
    let score = dpi_feedback.current_suspicion();
    assert!(score > 0.0, "DPI feedback should have been updated");

    // Abort the task (it runs forever)
    update_handle.abort();
    let _ = update_handle.await;
}

#[test]
fn test_dpi_feedback_cover_traffic_adaptation() {
    let dpi_feedback = Arc::new(DpiFeedbackController::new());
    use masque_core::cover_traffic::CoverTrafficConfig;

    let base_config = CoverTrafficConfig {
        base_rate_pps: 10.0,
        ..Default::default()
    };

    // Low suspicion -> lower multiplier
    dpi_feedback.update_suspicion(10.0);
    let low_rate = dpi_feedback.get_cover_traffic_rate(&base_config);
    assert!(low_rate < base_config.base_rate_pps * 1.5);

    // High suspicion -> higher multiplier
    dpi_feedback.update_suspicion(80.0);
    let high_rate = dpi_feedback.get_cover_traffic_rate(&base_config);
    assert!(high_rate > low_rate);
    assert!(high_rate >= base_config.base_rate_pps * 1.5);
}

#[test]
fn test_dpi_feedback_morpher_config_adaptation() {
    let dpi_feedback = Arc::new(DpiFeedbackController::new());

    // Low suspicion -> low padding, low delay
    dpi_feedback.update_suspicion(10.0);
    let low_config = dpi_feedback.get_morpher_config();
    assert!(low_config.max_padding_ratio <= 0.3);
    assert!(low_config.max_delay_ms <= 10.0);

    // High suspicion -> high padding, high delay
    dpi_feedback.update_suspicion(80.0);
    let high_config = dpi_feedback.get_morpher_config();
    // high_suspicion() returns max_padding_ratio: 0.5, which is >= 0.3
    assert!(high_config.max_padding_ratio >= 0.3);
    assert!(high_config.max_delay_ms >= 10.0);
    assert!(high_config.max_padding_ratio >= low_config.max_padding_ratio);
    assert!(high_config.max_delay_ms >= low_config.max_delay_ms);
}

#[test]
fn test_dpi_feedback_hysteresis_prevention() {
    let config = DpiFeedbackConfig {
        low_threshold: 20.0,
        medium_threshold: 20.0,
        high_threshold: 70.0,
        hysteresis: 5.0,
        ..Default::default()
    };
    let dpi_feedback = Arc::new(DpiFeedbackController::with_config(config));

    // Start low
    dpi_feedback.update_suspicion(10.0);
    assert_eq!(dpi_feedback.current_bucket(), SuspicionBucket::Low);

    // Transition to medium (need >= 25 with hysteresis)
    dpi_feedback.update_suspicion(30.0);
    assert_eq!(dpi_feedback.current_bucket(), SuspicionBucket::Medium);

    // Drop slightly below threshold but within hysteresis -> should stay Medium
    dpi_feedback.update_suspicion(18.0);
    assert_eq!(
        dpi_feedback.current_bucket(),
        SuspicionBucket::Medium,
        "Should stay Medium due to hysteresis"
    );

    // Drop well below threshold -> should transition to Low
    dpi_feedback.update_suspicion(10.0);
    assert_eq!(dpi_feedback.current_bucket(), SuspicionBucket::Low);
}

#[test]
fn test_dpi_feedback_aggressive_mode() {
    let config = DpiFeedbackConfig {
        aggressive_mode_enabled: true,
        aggressive_threshold: 85.0,
        ..Default::default()
    };
    let dpi_feedback = Arc::new(DpiFeedbackController::with_config(config));

    // Below aggressive threshold
    dpi_feedback.update_suspicion(80.0);
    let strategy_below = dpi_feedback.get_padding_strategy();
    assert_ne!(strategy_below, PaddingStrategy::Mtu);

    // Above aggressive threshold -> should use aggressive padding
    dpi_feedback.update_suspicion(90.0);
    let strategy_above = dpi_feedback.get_padding_strategy();
    // Aggressive mode should use Mtu strategy
    assert_eq!(strategy_above, PaddingStrategy::Mtu);
}

#[test]
fn test_dpi_feedback_cover_traffic_injection_decision() {
    let dpi_feedback = Arc::new(DpiFeedbackController::new());

    // Low suspicion -> should not inject
    dpi_feedback.update_suspicion(10.0);
    assert!(!dpi_feedback.should_inject_cover_traffic());

    // Medium suspicion -> should inject
    dpi_feedback.update_suspicion(30.0);
    assert!(dpi_feedback.should_inject_cover_traffic());

    // High suspicion -> should inject
    dpi_feedback.update_suspicion(80.0);
    assert!(dpi_feedback.should_inject_cover_traffic());
}

#[tokio::test]
async fn test_dpi_feedback_with_packet_forwarding() {
    use bytes::Bytes;
    use masque_core::padding::Padder;
    use masque_core::vpn_tunnel::PacketEncapsulator;

    let dpi_feedback = Arc::new(DpiFeedbackController::new());
    let padder_config = PaddingConfig {
        adaptive: true,
        low_strategy: PaddingStrategy::RandomBucket,
        medium_strategy: PaddingStrategy::Bucket,
        high_strategy: PaddingStrategy::Mtu,
        medium_threshold: 20,
        high_threshold: 70,
        hysteresis: 5,
        ..Default::default()
    };
    let padder = Arc::new(Padder::new(padder_config));
    let encapsulator = Arc::new(PacketEncapsulator::new());

    // Test packet padding with different suspicion levels
    let test_packet = Bytes::from_static(&[0x45, 0x00, 0x00, 0x28, 0x00, 0x00]);

    // Low suspicion
    dpi_feedback.update_suspicion(10.0);
    padder.update_suspicion(dpi_feedback.current_suspicion());
    assert_eq!(padder.suspicion_bucket(), SuspicionBucket::Low);
    let padded_low = padder.pad(&test_packet);
    let padded_low_len = padded_low.len();
    let _datagram_low = encapsulator.encapsulate(Bytes::from(padded_low));

    // Transition through Medium first (for hysteresis)
    dpi_feedback.update_suspicion(30.0);
    padder.update_suspicion(dpi_feedback.current_suspicion());
    assert_eq!(padder.suspicion_bucket(), SuspicionBucket::Medium);

    // High suspicion
    dpi_feedback.update_suspicion(80.0);
    padder.update_suspicion(dpi_feedback.current_suspicion());
    assert_eq!(
        padder.suspicion_bucket(),
        SuspicionBucket::High,
        "Padder should be in High bucket with suspicion 80.0"
    );
    let padded_high = padder.pad(&test_packet);
    let padded_high_len = padded_high.len();
    let _datagram_high = encapsulator.encapsulate(Bytes::from(padded_high));

    // Verify high suspicion pads to MTU (deterministic)
    assert_eq!(
        padded_high_len,
        padder.config().mtu,
        "High suspicion should pad to MTU size. Got: {}, Expected: {}, bucket: {:?}",
        padded_high_len,
        padder.config().mtu,
        padder.suspicion_bucket()
    );
    // Low suspicion uses RandomBucket (non-deterministic, but should be <= MTU)
    assert!(
        padded_low_len <= padder.config().mtu,
        "Low suspicion should pad to bucket size <= MTU. Got: {}, MTU: {}",
        padded_low_len,
        padder.config().mtu
    );
}

#[test]
fn test_dpi_feedback_thread_safety() {
    use std::sync::Arc;
    use std::thread;

    let dpi_feedback = Arc::new(DpiFeedbackController::new());
    let mut handles = vec![];

    // Spawn multiple threads updating suspicion concurrently
    for i in 0..10 {
        let feedback = dpi_feedback.clone();
        handles.push(thread::spawn(move || {
            for j in 0..100 {
                let score = ((i * 10 + j) % 100) as f64;
                feedback.update_suspicion(score);
                let _ = feedback.current_suspicion();
                let _ = feedback.current_bucket();
            }
        }));
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify final state is valid
    let score = dpi_feedback.current_suspicion();
    assert!(score >= 0.0 && score <= 100.0);
    let bucket = dpi_feedback.current_bucket();
    match bucket {
        SuspicionBucket::Low | SuspicionBucket::Medium | SuspicionBucket::High => {}
    }
}
