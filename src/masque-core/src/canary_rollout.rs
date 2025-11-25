//! Canary Rollout
//!
//! Provides gradual rollout mechanism for manifest rotations and endpoint updates.
//! Supports percentage-based canary deployments with automatic promotion and rollback.

use crate::manifest_rotator::{EndpointConfig, ManifestRotator};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tokio::time::{sleep, Instant};
use tracing::{info, warn};
use vpr_crypto::manifest::{ServerEndpoint, SignedManifest};

/// Canary rollout configuration
#[derive(Debug, Clone)]
pub struct CanaryRolloutConfig {
    /// Initial canary percentage (0-100)
    pub initial_percent: u8,
    /// Increment percentage per stage (0-100)
    pub increment_percent: u8,
    /// Duration to wait between stages
    pub stage_duration: Duration,
    /// Minimum duration to observe canary before promotion
    pub min_observation_duration: Duration,
    /// Maximum duration before forcing full rollout
    pub max_rollout_duration: Duration,
    /// Health check interval during canary
    pub health_check_interval: Duration,
    /// Success threshold (percentage of successful requests)
    pub success_threshold: f64,
    /// Error threshold (percentage of errors before rollback)
    pub error_threshold: f64,
}

impl Default for CanaryRolloutConfig {
    fn default() -> Self {
        Self {
            initial_percent: 10,
            increment_percent: 10,
            stage_duration: Duration::from_secs(300), // 5 minutes
            min_observation_duration: Duration::from_secs(60), // 1 minute
            max_rollout_duration: Duration::from_secs(3600), // 1 hour
            health_check_interval: Duration::from_secs(10),
            success_threshold: 0.95, // 95% success rate
            error_threshold: 0.10,   // 10% error rate triggers rollback
        }
    }
}

/// Canary rollout state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanaryState {
    /// Canary rollout not started
    NotStarted,
    /// Canary rollout in progress
    InProgress {
        /// Current percentage deployed
        current_percent: u8,
        /// Start time
        start_time: SystemTime,
    },
    /// Canary rollout completed successfully
    Completed,
    /// Canary rollout rolled back due to errors
    RolledBack,
}

/// Health metrics for canary evaluation
#[derive(Debug, Clone, Default)]
pub struct HealthMetrics {
    /// Total requests
    pub total_requests: u64,
    /// Successful requests
    pub successful_requests: u64,
    /// Failed requests
    pub failed_requests: u64,
    /// Average latency (milliseconds)
    pub avg_latency_ms: f64,
    /// Error rate
    pub error_rate: f64,
    /// Success rate
    pub success_rate: f64,
}

impl HealthMetrics {
    pub fn update(&mut self, success: bool, latency_ms: f64) {
        self.total_requests += 1;
        if success {
            self.successful_requests += 1;
        } else {
            self.failed_requests += 1;
        }

        // Update average latency (exponential moving average)
        if self.total_requests == 1 {
            self.avg_latency_ms = latency_ms;
        } else {
            self.avg_latency_ms = (self.avg_latency_ms * 0.9) + (latency_ms * 0.1);
        }

        // Calculate rates
        if self.total_requests > 0 {
            self.error_rate = self.failed_requests as f64 / self.total_requests as f64;
            self.success_rate = self.successful_requests as f64 / self.total_requests as f64;
        }
    }

    pub fn is_healthy(&self, config: &CanaryRolloutConfig) -> bool {
        self.success_rate >= config.success_threshold && self.error_rate < config.error_threshold
    }
}

/// Canary Rollout Manager
pub struct CanaryRollout {
    config: CanaryRolloutConfig,
    state: CanaryState,
    metrics: HashMap<String, HealthMetrics>, // Per-endpoint metrics
    start_time: Option<Instant>,
}

impl CanaryRollout {
    /// Create new Canary Rollout manager
    pub fn new(config: CanaryRolloutConfig) -> Self {
        Self {
            config,
            state: CanaryState::NotStarted,
            metrics: HashMap::new(),
            start_time: None,
        }
    }

    /// Start canary rollout
    pub fn start(&mut self) {
        self.state = CanaryState::InProgress {
            current_percent: self.config.initial_percent,
            start_time: SystemTime::now(),
        };
        self.start_time = Some(Instant::now());
        info!(
            "Canary rollout started with {}% initial deployment",
            self.config.initial_percent
        );
    }

    /// Execute canary rollout with manifest rotator
    pub async fn execute(
        &mut self,
        rotator: &ManifestRotator,
        _current_manifest: &SignedManifest,
        new_endpoints: Vec<ServerEndpoint>,
    ) -> Result<SignedManifest> {
        self.start();

        let mut current_percent = self.config.initial_percent;

        loop {
            // Calculate endpoints for current stage
            let num_endpoints = new_endpoints.len();
            let num_canary = (num_endpoints * current_percent as usize / 100).max(1);
            let canary_endpoints: Vec<ServerEndpoint> =
                new_endpoints.iter().take(num_canary).cloned().collect();

            info!(
                "Canary stage: {}% ({} endpoints)",
                current_percent, num_canary
            );

            // Create canary manifest with current percentage of endpoints
            let canary_endpoint_configs: Vec<EndpointConfig> = canary_endpoints
                .iter()
                .map(|ep| EndpointConfig {
                    server: ep.clone(),
                    active: true,
                })
                .collect();

            // Rotate manifest with canary endpoints
            let _canary_manifest = rotator
                .rotate(
                    canary_endpoint_configs,
                    None, // Preserve existing ODoH relays
                    None, // Preserve existing fronting domains
                )
                .await
                .context("creating canary manifest")?;

            // Wait for observation period
            sleep(self.config.min_observation_duration).await;

            // Check health metrics
            let is_healthy = self.check_health().await;

            if !is_healthy {
                warn!("Canary rollout failed health check - rolling back");
                self.state = CanaryState::RolledBack;
                // Rollback would be handled by rotator
                anyhow::bail!("Canary rollout failed health checks");
            }

            // Check if we've reached 100%
            if current_percent >= 100 {
                self.state = CanaryState::Completed;
                info!("Canary rollout completed successfully");
                break;
            }

            // Check if max duration exceeded
            if let Some(start) = self.start_time {
                if start.elapsed() > self.config.max_rollout_duration {
                    warn!("Canary rollout exceeded max duration - forcing completion");
                    self.state = CanaryState::Completed;
                    break;
                }
            }

            // Increment percentage
            current_percent = (current_percent + self.config.increment_percent).min(100);

            // Update state
            self.state = CanaryState::InProgress {
                current_percent,
                start_time: SystemTime::now(),
            };

            // Wait before next stage
            sleep(self.config.stage_duration).await;
        }

        // Final manifest with all endpoints
        // Create final manifest with all endpoints using rotator
        let final_endpoints: Vec<EndpointConfig> = new_endpoints
            .iter()
            .map(|ep| EndpointConfig {
                server: ep.clone(),
                active: true,
            })
            .collect();

        // Rotate to final manifest with all endpoints
        let final_manifest = rotator
            .rotate(
                final_endpoints,
                None, // Use existing ODoH relays
                None, // Use existing fronting domains
            )
            .await
            .context("creating final manifest")?;

        self.state = CanaryState::Completed;
        info!(
            "Canary rollout completed successfully with {} endpoints",
            new_endpoints.len()
        );

        Ok(final_manifest)
    }

    /// Check health of canary deployment
    async fn check_health(&self) -> bool {
        // Aggregate metrics across all endpoints
        let mut total_metrics = HealthMetrics::default();

        for metrics in self.metrics.values() {
            total_metrics.total_requests += metrics.total_requests;
            total_metrics.successful_requests += metrics.successful_requests;
            total_metrics.failed_requests += metrics.failed_requests;
        }

        if total_metrics.total_requests > 0 {
            total_metrics.error_rate =
                total_metrics.failed_requests as f64 / total_metrics.total_requests as f64;
            total_metrics.success_rate =
                total_metrics.successful_requests as f64 / total_metrics.total_requests as f64;
        }

        total_metrics.is_healthy(&self.config)
    }

    /// Record request metric
    pub fn record_request(&mut self, endpoint_id: &str, success: bool, latency_ms: f64) {
        let metrics = self.metrics.entry(endpoint_id.to_string()).or_default();
        metrics.update(success, latency_ms);
    }

    /// Get current state
    pub fn state(&self) -> &CanaryState {
        &self.state
    }

    /// Get metrics for endpoint
    pub fn get_metrics(&self, endpoint_id: &str) -> Option<&HealthMetrics> {
        self.metrics.get(endpoint_id)
    }

    /// Get aggregated metrics
    pub fn get_aggregated_metrics(&self) -> HealthMetrics {
        let mut aggregated = HealthMetrics::default();

        for metrics in self.metrics.values() {
            aggregated.total_requests += metrics.total_requests;
            aggregated.successful_requests += metrics.successful_requests;
            aggregated.failed_requests += metrics.failed_requests;
        }

        if aggregated.total_requests > 0 {
            aggregated.error_rate =
                aggregated.failed_requests as f64 / aggregated.total_requests as f64;
            aggregated.success_rate =
                aggregated.successful_requests as f64 / aggregated.total_requests as f64;
        }

        aggregated
    }

    /// Reset canary rollout
    pub fn reset(&mut self) {
        self.state = CanaryState::NotStarted;
        self.metrics.clear();
        self.start_time = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canary_rollout_config_default() {
        let config = CanaryRolloutConfig::default();
        assert_eq!(config.initial_percent, 10);
        assert_eq!(config.increment_percent, 10);
        assert_eq!(config.success_threshold, 0.95);
        assert_eq!(config.error_threshold, 0.10);
        assert_eq!(config.stage_duration, Duration::from_secs(300));
        assert_eq!(config.min_observation_duration, Duration::from_secs(60));
        assert_eq!(config.max_rollout_duration, Duration::from_secs(3600));
        assert_eq!(config.health_check_interval, Duration::from_secs(10));
    }

    #[test]
    fn test_canary_rollout_config_clone() {
        let config = CanaryRolloutConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.initial_percent, config.initial_percent);
        assert_eq!(cloned.success_threshold, config.success_threshold);
    }

    #[test]
    fn test_health_metrics_default() {
        let metrics = HealthMetrics::default();
        assert_eq!(metrics.total_requests, 0);
        assert_eq!(metrics.successful_requests, 0);
        assert_eq!(metrics.failed_requests, 0);
        assert_eq!(metrics.avg_latency_ms, 0.0);
        assert_eq!(metrics.error_rate, 0.0);
        assert_eq!(metrics.success_rate, 0.0);
    }

    #[test]
    fn test_health_metrics_first_update_sets_latency() {
        let mut metrics = HealthMetrics::default();
        metrics.update(true, 50.0);
        assert_eq!(metrics.avg_latency_ms, 50.0);
        assert_eq!(metrics.total_requests, 1);
    }

    #[test]
    fn test_health_metrics_update() {
        let mut metrics = HealthMetrics::default();
        metrics.update(true, 10.0);
        metrics.update(true, 20.0);
        metrics.update(false, 30.0);

        assert_eq!(metrics.total_requests, 3);
        assert_eq!(metrics.successful_requests, 2);
        assert_eq!(metrics.failed_requests, 1);
        assert!((metrics.error_rate - 1.0 / 3.0).abs() < 0.01);
        assert!((metrics.success_rate - 2.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_health_metrics_latency_ema() {
        let mut metrics = HealthMetrics::default();
        // First update sets latency directly
        metrics.update(true, 100.0);
        assert_eq!(metrics.avg_latency_ms, 100.0);

        // EMA: 0.9 * 100 + 0.1 * 200 = 110
        metrics.update(true, 200.0);
        assert!((metrics.avg_latency_ms - 110.0).abs() < 0.1);
    }

    #[test]
    fn test_health_metrics_is_healthy() {
        let config = CanaryRolloutConfig::default();
        let mut metrics = HealthMetrics::default();

        // Add 100 successful requests
        for _ in 0..100 {
            metrics.update(true, 10.0);
        }

        assert!(metrics.is_healthy(&config));
    }

    #[test]
    fn test_health_metrics_not_healthy_low_success() {
        let config = CanaryRolloutConfig::default();
        let mut metrics = HealthMetrics::default();

        // 90% success is below 95% threshold
        for _ in 0..90 {
            metrics.update(true, 10.0);
        }
        for _ in 0..10 {
            metrics.update(false, 10.0);
        }

        assert!(!metrics.is_healthy(&config));
    }

    #[test]
    fn test_health_metrics_not_healthy_high_error() {
        let mut config = CanaryRolloutConfig::default();
        config.success_threshold = 0.0; // Disable success check
        config.error_threshold = 0.05; // 5% error threshold

        let mut metrics = HealthMetrics::default();
        for _ in 0..90 {
            metrics.update(true, 10.0);
        }
        for _ in 0..10 {
            metrics.update(false, 10.0);
        }

        // 10% error rate > 5% threshold
        assert!(!metrics.is_healthy(&config));
    }

    #[test]
    fn test_health_metrics_clone() {
        let mut metrics = HealthMetrics::default();
        metrics.update(true, 10.0);
        let cloned = metrics.clone();
        assert_eq!(cloned.total_requests, metrics.total_requests);
        assert_eq!(cloned.avg_latency_ms, metrics.avg_latency_ms);
    }

    #[test]
    fn test_canary_state_equality() {
        assert_eq!(CanaryState::NotStarted, CanaryState::NotStarted);
        assert_eq!(CanaryState::Completed, CanaryState::Completed);
        assert_eq!(CanaryState::RolledBack, CanaryState::RolledBack);
        assert_ne!(CanaryState::NotStarted, CanaryState::Completed);
        assert_ne!(CanaryState::Completed, CanaryState::RolledBack);
    }

    #[test]
    fn test_canary_state_in_progress() {
        let state = CanaryState::InProgress {
            current_percent: 50,
            start_time: SystemTime::now(),
        };
        match state {
            CanaryState::InProgress { current_percent, .. } => {
                assert_eq!(current_percent, 50);
            }
            _ => panic!("Expected InProgress"),
        }
    }

    #[test]
    fn test_canary_state_clone() {
        let state = CanaryState::Completed;
        let cloned = state.clone();
        assert_eq!(cloned, CanaryState::Completed);
    }

    #[tokio::test]
    async fn test_canary_rollout_start() {
        let config = CanaryRolloutConfig::default();
        let mut rollout = CanaryRollout::new(config);
        assert_eq!(rollout.state(), &CanaryState::NotStarted);

        rollout.start();
        match rollout.state() {
            CanaryState::InProgress {
                current_percent, ..
            } => {
                assert_eq!(*current_percent, 10);
            }
            _ => panic!("Expected InProgress state"),
        }
    }

    #[test]
    fn test_canary_rollout_record_request() {
        let config = CanaryRolloutConfig::default();
        let mut rollout = CanaryRollout::new(config);

        rollout.record_request("endpoint1", true, 10.0);
        rollout.record_request("endpoint1", true, 20.0);
        rollout.record_request("endpoint1", false, 30.0);

        let metrics = rollout.get_metrics("endpoint1").unwrap();
        assert_eq!(metrics.total_requests, 3);
        assert_eq!(metrics.successful_requests, 2);
        assert_eq!(metrics.failed_requests, 1);
    }

    #[test]
    fn test_canary_rollout_record_multiple_endpoints() {
        let config = CanaryRolloutConfig::default();
        let mut rollout = CanaryRollout::new(config);

        rollout.record_request("endpoint1", true, 10.0);
        rollout.record_request("endpoint2", false, 20.0);
        rollout.record_request("endpoint3", true, 15.0);

        assert!(rollout.get_metrics("endpoint1").is_some());
        assert!(rollout.get_metrics("endpoint2").is_some());
        assert!(rollout.get_metrics("endpoint3").is_some());
        assert!(rollout.get_metrics("nonexistent").is_none());
    }

    #[test]
    fn test_canary_rollout_get_aggregated_metrics() {
        let config = CanaryRolloutConfig::default();
        let mut rollout = CanaryRollout::new(config);

        rollout.record_request("endpoint1", true, 10.0);
        rollout.record_request("endpoint1", true, 10.0);
        rollout.record_request("endpoint2", false, 20.0);

        let aggregated = rollout.get_aggregated_metrics();
        assert_eq!(aggregated.total_requests, 3);
        assert_eq!(aggregated.successful_requests, 2);
        assert_eq!(aggregated.failed_requests, 1);
        assert!((aggregated.success_rate - 2.0 / 3.0).abs() < 0.01);
        assert!((aggregated.error_rate - 1.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_canary_rollout_get_aggregated_metrics_empty() {
        let config = CanaryRolloutConfig::default();
        let rollout = CanaryRollout::new(config);

        let aggregated = rollout.get_aggregated_metrics();
        assert_eq!(aggregated.total_requests, 0);
        assert_eq!(aggregated.error_rate, 0.0);
        assert_eq!(aggregated.success_rate, 0.0);
    }

    #[test]
    fn test_canary_rollout_reset() {
        let config = CanaryRolloutConfig::default();
        let mut rollout = CanaryRollout::new(config);

        rollout.start();
        rollout.record_request("endpoint1", true, 10.0);

        assert_ne!(rollout.state(), &CanaryState::NotStarted);
        assert!(rollout.get_metrics("endpoint1").is_some());

        rollout.reset();

        assert_eq!(rollout.state(), &CanaryState::NotStarted);
        assert!(rollout.get_metrics("endpoint1").is_none());
    }
}
