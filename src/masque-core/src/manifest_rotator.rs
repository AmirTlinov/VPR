//! Manifest Rotator
//!
//! Provides automatic rotation of bootstrap manifests with new endpoints,
//! certificates, and configurations. Supports canary rollouts and rollback.

use crate::stego_rss::{StegoRssConfig, StegoRssEncoder};
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use tokio::fs;
use tracing::info;
use vpr_crypto::keys::SigningKeypair;
use vpr_crypto::manifest::{ManifestPayload, ServerEndpoint, SignedManifest};

/// Manifest rotation strategy
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationStrategy {
    /// Immediate rotation (all endpoints updated at once)
    Immediate,
    /// Canary rotation (gradual rollout)
    Canary {
        /// Percentage of endpoints to update initially (0-100)
        initial_percent: u8,
        /// Time between rollout stages
        stage_interval: Duration,
    },
    /// Scheduled rotation at specific time
    Scheduled {
        /// Target time for rotation
        target_time: SystemTime,
    },
}

/// Endpoint configuration for rotation
#[derive(Debug, Clone)]
pub struct EndpointConfig {
    /// Server endpoint
    pub server: ServerEndpoint,
    /// Whether endpoint is active
    pub active: bool,
}

/// Manifest rotation configuration
pub struct ManifestRotatorConfig {
    /// Signing keypair for manifests
    pub signing_keypair: SigningKeypair,
    /// Output directory for rotated manifests
    pub output_dir: PathBuf,
    /// RSS feed configuration for publishing
    pub rss_config: Option<StegoRssConfig>,
    /// Rotation strategy
    pub rotation_strategy: RotationStrategy,
    /// Current manifest path (for rollback)
    pub current_manifest_path: Option<PathBuf>,
    /// Backup directory for rollback
    pub backup_dir: PathBuf,
    /// Maximum number of backups to keep
    pub max_backups: usize,
}

/// Manifest Rotator
pub struct ManifestRotator {
    config: ManifestRotatorConfig,
    rss_encoder: Option<std::sync::Mutex<StegoRssEncoder>>,
}

impl ManifestRotator {
    /// Create new Manifest Rotator
    pub fn new(config: ManifestRotatorConfig) -> Result<Self> {
        let rss_encoder = config
            .rss_config
            .as_ref()
            .map(|rss_config| std::sync::Mutex::new(StegoRssEncoder::new(rss_config.clone())));

        Ok(Self {
            config,
            rss_encoder,
        })
    }

    /// Rotate manifest with new endpoints
    pub async fn rotate(
        &self,
        new_endpoints: Vec<EndpointConfig>,
        odoh_relays: Option<Vec<String>>,
        fronting_domains: Option<Vec<String>>,
    ) -> Result<SignedManifest> {
        info!(
            "Starting manifest rotation with {} endpoints",
            new_endpoints.len()
        );

        // Load current manifest for reference
        let current_manifest = if let Some(ref path) = self.config.current_manifest_path {
            if path.exists() {
                let data = fs::read(path).await?;
                let manifest: SignedManifest =
                    serde_json::from_slice(&data).context("parsing current manifest")?;
                Some(manifest)
            } else {
                None
            }
        } else {
            None
        };

        // Create backup of current manifest
        if let Some(ref manifest) = current_manifest {
            self.backup_manifest(manifest).await?;
        }

        // Build new manifest payload
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let servers: Vec<ServerEndpoint> = new_endpoints
            .iter()
            .filter(|e| e.active)
            .map(|e| e.server.clone())
            .collect();

        let mut payload = ManifestPayload::new(servers);
        payload.created_at = now;
        payload.odoh_relays = odoh_relays.unwrap_or_default();
        payload.front_domains = fronting_domains.unwrap_or_default();

        // Add rotation metadata in comment
        let rotation_id = format!("{}", now);
        let mut comment = format!("rotation_id={}", rotation_id);
        if let Some(ref current) = current_manifest {
            let current_payload: ManifestPayload = serde_json::from_str(&current.payload)
                .context("parsing current manifest payload")?;
            if let Some(prev_id) = current_payload.comment.split('=').nth(1) {
                comment.push_str(&format!(",previous_rotation_id={}", prev_id));
            }
        }
        payload.comment = comment;

        // Sign manifest
        let signed_manifest = SignedManifest::sign(&payload, &self.config.signing_keypair)?;

        // Save rotated manifest
        let payload: ManifestPayload = serde_json::from_str(&signed_manifest.payload)
            .context("parsing signed manifest payload")?;
        let output_path = self
            .config
            .output_dir
            .join(format!("manifest_{}.json", payload.created_at));
        fs::create_dir_all(&self.config.output_dir).await?;
        fs::write(
            &output_path,
            serde_json::to_string_pretty(&signed_manifest)?,
        )
        .await?;
        info!("Rotated manifest saved to: {:?}", output_path);

        // Publish via RSS if configured
        if let Some(ref encoder) = self.rss_encoder {
            let rss_xml = {
                let mut enc = encoder.lock().unwrap();
                enc.encode_manifest(&signed_manifest)?
            };
            let rss_path = self
                .config
                .output_dir
                .join(format!("manifest_{}.rss", payload.created_at));
            fs::write(&rss_path, rss_xml).await?;
            info!("RSS feed published to: {:?}", rss_path);
        }

        Ok(signed_manifest)
    }

    /// Rollback to previous manifest
    pub async fn rollback(&self) -> Result<SignedManifest> {
        info!("Rolling back to previous manifest");

        // Find latest backup
        let backup_dir = &self.config.backup_dir;
        if !backup_dir.exists() {
            anyhow::bail!("Backup directory does not exist");
        }

        let mut backups = Vec::new();
        let mut entries = fs::read_dir(backup_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                backups.push(path);
            }
        }

        backups.sort();
        backups.reverse(); // Most recent first

        if backups.is_empty() {
            anyhow::bail!("No backup manifests found");
        }

        let backup_path = &backups[0];
        let data = fs::read_to_string(backup_path).await?;
        let manifest: SignedManifest =
            SignedManifest::from_json(&data).context("parsing backup manifest")?;

        // Restore manifest
        if let Some(ref current_path) = self.config.current_manifest_path {
            fs::write(current_path, serde_json::to_string_pretty(&manifest)?).await?;
            info!("Manifest rolled back from: {:?}", backup_path);
        }

        Ok(manifest)
    }

    /// List available backups
    pub async fn list_backups(&self) -> Result<Vec<PathBuf>> {
        let backup_dir = &self.config.backup_dir;
        if !backup_dir.exists() {
            return Ok(Vec::new());
        }

        let mut backups = Vec::new();
        let mut entries = fs::read_dir(backup_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                backups.push(path);
            }
        }

        backups.sort();
        backups.reverse(); // Most recent first
        Ok(backups)
    }

    /// Cleanup old backups
    pub async fn cleanup_backups(&self) -> Result<()> {
        let backups = self.list_backups().await?;

        if backups.len() > self.config.max_backups {
            let to_remove = backups.len() - self.config.max_backups;
            for backup in backups.iter().skip(self.config.max_backups) {
                fs::remove_file(backup).await?;
                info!("Removed old backup: {:?}", backup);
            }
            info!("Cleaned up {} old backups", to_remove);
        }

        Ok(())
    }

    /// Backup current manifest
    async fn backup_manifest(&self, manifest: &SignedManifest) -> Result<()> {
        fs::create_dir_all(&self.config.backup_dir).await?;

        let payload: ManifestPayload =
            serde_json::from_str(&manifest.payload).context("parsing manifest payload")?;
        let backup_path = self
            .config
            .backup_dir
            .join(format!("manifest_backup_{}.json", payload.created_at));

        fs::write(&backup_path, serde_json::to_string_pretty(manifest)?).await?;
        info!("Manifest backed up to: {:?}", backup_path);

        // Cleanup old backups
        self.cleanup_backups().await?;

        Ok(())
    }

    /// Generate rotation plan based on strategy
    pub fn generate_rotation_plan(
        &self,
        _current_endpoints: &[ServerEndpoint],
        new_endpoints: &[EndpointConfig],
    ) -> RotationPlan {
        match &self.config.rotation_strategy {
            RotationStrategy::Immediate => RotationPlan {
                stages: vec![RotationStage {
                    endpoints: new_endpoints
                        .iter()
                        .map(|e| format!("{}:{}", e.server.host, e.server.port))
                        .collect(),
                    delay: Duration::ZERO,
                }],
            },
            RotationStrategy::Canary {
                initial_percent,
                stage_interval,
            } => {
                let initial_count =
                    (new_endpoints.len() * (*initial_percent as usize) / 100).max(1);
                let mut stages = Vec::new();

                // Initial stage
                stages.push(RotationStage {
                    endpoints: new_endpoints
                        .iter()
                        .take(initial_count)
                        .map(|e| format!("{}:{}", e.server.host, e.server.port))
                        .collect(),
                    delay: Duration::ZERO,
                });

                // Remaining stages
                let remaining: Vec<String> = new_endpoints
                    .iter()
                    .skip(initial_count)
                    .map(|e| format!("{}:{}", e.server.host, e.server.port))
                    .collect();

                if !remaining.is_empty() {
                    stages.push(RotationStage {
                        endpoints: remaining,
                        delay: *stage_interval,
                    });
                }

                RotationPlan { stages }
            }
            RotationStrategy::Scheduled { target_time } => {
                let delay = target_time
                    .duration_since(SystemTime::now())
                    .unwrap_or(Duration::ZERO);
                RotationPlan {
                    stages: vec![RotationStage {
                        endpoints: new_endpoints
                            .iter()
                            .map(|e| format!("{}:{}", e.server.host, e.server.port))
                            .collect(),
                        delay,
                    }],
                }
            }
        }
    }
}

/// Rotation plan with stages
#[derive(Debug, Clone)]
pub struct RotationPlan {
    pub stages: Vec<RotationStage>,
}

/// Single rotation stage
#[derive(Debug, Clone)]
pub struct RotationStage {
    pub endpoints: Vec<String>,
    pub delay: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use vpr_crypto::keys::SigningKeypair;
    use vpr_crypto::manifest::ServerEndpoint;

    fn test_endpoint(host: &str, port: u16) -> EndpointConfig {
        EndpointConfig {
            server: ServerEndpoint {
                id: format!("test-{}-{}", host, port),
                host: host.to_string(),
                port,
                noise_pubkey: "test_pubkey".to_string(),
                region: "us-east".to_string(),
                capabilities: vec!["masque".to_string()],
                weight: 100,
                active: true,
            },
            active: true,
        }
    }

    fn test_server_endpoint(host: &str, port: u16) -> ServerEndpoint {
        ServerEndpoint {
            id: format!("test-{}-{}", host, port),
            host: host.to_string(),
            port,
            noise_pubkey: "test_pubkey".to_string(),
            region: "us-east".to_string(),
            capabilities: vec!["masque".to_string()],
            weight: 100,
            active: true,
        }
    }

    #[test]
    fn test_rotation_strategy_immediate() {
        let strategy = RotationStrategy::Immediate;
        assert_eq!(strategy, RotationStrategy::Immediate);
    }

    #[test]
    fn test_rotation_strategy_canary() {
        let strategy = RotationStrategy::Canary {
            initial_percent: 10,
            stage_interval: Duration::from_secs(3600),
        };
        match strategy {
            RotationStrategy::Canary {
                initial_percent,
                stage_interval,
            } => {
                assert_eq!(initial_percent, 10);
                assert_eq!(stage_interval, Duration::from_secs(3600));
            }
            _ => panic!("Expected Canary strategy"),
        }
    }

    #[test]
    fn test_rotation_strategy_scheduled() {
        let target = SystemTime::now() + Duration::from_secs(3600);
        let strategy = RotationStrategy::Scheduled {
            target_time: target,
        };
        match strategy {
            RotationStrategy::Scheduled { target_time } => {
                assert!(target_time > SystemTime::now());
            }
            _ => panic!("Expected Scheduled strategy"),
        }
    }

    #[test]
    fn test_rotation_strategy_debug() {
        let immediate = format!("{:?}", RotationStrategy::Immediate);
        assert!(immediate.contains("Immediate"));

        let canary = format!(
            "{:?}",
            RotationStrategy::Canary {
                initial_percent: 20,
                stage_interval: Duration::from_secs(60),
            }
        );
        assert!(canary.contains("Canary"));
        assert!(canary.contains("20"));

        let scheduled = format!(
            "{:?}",
            RotationStrategy::Scheduled {
                target_time: SystemTime::now(),
            }
        );
        assert!(scheduled.contains("Scheduled"));
    }

    #[test]
    fn test_rotation_strategy_clone() {
        let strategy = RotationStrategy::Canary {
            initial_percent: 15,
            stage_interval: Duration::from_secs(120),
        };
        let cloned = strategy.clone();
        assert_eq!(strategy, cloned);
    }

    #[test]
    fn test_endpoint_config_debug() {
        let config = test_endpoint("example.com", 443);
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("EndpointConfig"));
        assert!(debug_str.contains("example.com"));
    }

    #[test]
    fn test_endpoint_config_clone() {
        let config = test_endpoint("test.com", 8443);
        let cloned = config.clone();
        assert_eq!(cloned.server.host, "test.com");
        assert_eq!(cloned.server.port, 8443);
        assert!(cloned.active);
    }

    #[test]
    fn test_rotation_plan_debug_and_clone() {
        let plan = RotationPlan {
            stages: vec![
                RotationStage {
                    endpoints: vec!["a:1".to_string()],
                    delay: Duration::ZERO,
                },
                RotationStage {
                    endpoints: vec!["b:2".to_string()],
                    delay: Duration::from_secs(60),
                },
            ],
        };

        let debug_str = format!("{:?}", plan);
        assert!(debug_str.contains("RotationPlan"));
        assert!(debug_str.contains("stages"));

        let cloned = plan.clone();
        assert_eq!(cloned.stages.len(), 2);
    }

    #[test]
    fn test_rotation_stage_debug_and_clone() {
        let stage = RotationStage {
            endpoints: vec!["host:443".to_string()],
            delay: Duration::from_secs(30),
        };

        let debug_str = format!("{:?}", stage);
        assert!(debug_str.contains("RotationStage"));
        assert!(debug_str.contains("host:443"));

        let cloned = stage.clone();
        assert_eq!(cloned.endpoints, vec!["host:443".to_string()]);
        assert_eq!(cloned.delay, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn test_manifest_rotator_new() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let keypair = SigningKeypair::generate();

        let config = ManifestRotatorConfig {
            signing_keypair: keypair,
            output_dir: temp_dir.path().to_path_buf(),
            rss_config: None,
            rotation_strategy: RotationStrategy::Immediate,
            current_manifest_path: None,
            backup_dir: temp_dir.path().join("backups"),
            max_backups: 5,
        };

        let rotator = ManifestRotator::new(config);
        assert!(rotator.is_ok());
    }

    #[tokio::test]
    async fn test_list_backups_empty_dir() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let keypair = SigningKeypair::generate();

        let config = ManifestRotatorConfig {
            signing_keypair: keypair,
            output_dir: temp_dir.path().to_path_buf(),
            rss_config: None,
            rotation_strategy: RotationStrategy::Immediate,
            current_manifest_path: None,
            backup_dir: temp_dir.path().join("backups"),
            max_backups: 5,
        };

        let rotator = ManifestRotator::new(config).unwrap();
        let backups = rotator.list_backups().await.unwrap();
        assert!(backups.is_empty());
    }

    #[tokio::test]
    async fn test_list_backups_with_files() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let backup_dir = temp_dir.path().join("backups");
        tokio::fs::create_dir_all(&backup_dir).await.unwrap();

        // Create test backup files
        tokio::fs::write(backup_dir.join("manifest_1.json"), "{}")
            .await
            .unwrap();
        tokio::fs::write(backup_dir.join("manifest_2.json"), "{}")
            .await
            .unwrap();
        tokio::fs::write(backup_dir.join("other.txt"), "not a backup")
            .await
            .unwrap();

        let keypair = SigningKeypair::generate();
        let config = ManifestRotatorConfig {
            signing_keypair: keypair,
            output_dir: temp_dir.path().to_path_buf(),
            rss_config: None,
            rotation_strategy: RotationStrategy::Immediate,
            current_manifest_path: None,
            backup_dir,
            max_backups: 5,
        };

        let rotator = ManifestRotator::new(config).unwrap();
        let backups = rotator.list_backups().await.unwrap();
        assert_eq!(backups.len(), 2); // Only .json files
    }

    #[test]
    fn test_generate_rotation_plan_immediate() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let keypair = SigningKeypair::generate();

        let config = ManifestRotatorConfig {
            signing_keypair: keypair,
            output_dir: temp_dir.path().to_path_buf(),
            rss_config: None,
            rotation_strategy: RotationStrategy::Immediate,
            current_manifest_path: None,
            backup_dir: temp_dir.path().join("backups"),
            max_backups: 5,
        };

        let rotator = ManifestRotator::new(config).unwrap();
        let endpoints = vec![
            test_endpoint("server1.com", 443),
            test_endpoint("server2.com", 8443),
        ];
        let current = vec![test_server_endpoint("old.com", 443)];

        let plan = rotator.generate_rotation_plan(&current, &endpoints);
        assert_eq!(plan.stages.len(), 1);
        assert_eq!(plan.stages[0].endpoints.len(), 2);
        assert_eq!(plan.stages[0].delay, Duration::ZERO);
    }

    #[test]
    fn test_generate_rotation_plan_canary() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let keypair = SigningKeypair::generate();

        let config = ManifestRotatorConfig {
            signing_keypair: keypair,
            output_dir: temp_dir.path().to_path_buf(),
            rss_config: None,
            rotation_strategy: RotationStrategy::Canary {
                initial_percent: 50,
                stage_interval: Duration::from_secs(60),
            },
            current_manifest_path: None,
            backup_dir: temp_dir.path().join("backups"),
            max_backups: 5,
        };

        let rotator = ManifestRotator::new(config).unwrap();
        let endpoints = vec![
            test_endpoint("server1.com", 443),
            test_endpoint("server2.com", 8443),
            test_endpoint("server3.com", 9443),
            test_endpoint("server4.com", 10443),
        ];
        let current = vec![];

        let plan = rotator.generate_rotation_plan(&current, &endpoints);
        assert_eq!(plan.stages.len(), 2);
        assert_eq!(plan.stages[0].endpoints.len(), 2); // 50% of 4
        assert_eq!(plan.stages[0].delay, Duration::ZERO);
        assert_eq!(plan.stages[1].endpoints.len(), 2);
        assert_eq!(plan.stages[1].delay, Duration::from_secs(60));
    }

    #[test]
    fn test_generate_rotation_plan_canary_single_endpoint() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let keypair = SigningKeypair::generate();

        let config = ManifestRotatorConfig {
            signing_keypair: keypair,
            output_dir: temp_dir.path().to_path_buf(),
            rss_config: None,
            rotation_strategy: RotationStrategy::Canary {
                initial_percent: 10,
                stage_interval: Duration::from_secs(30),
            },
            current_manifest_path: None,
            backup_dir: temp_dir.path().join("backups"),
            max_backups: 5,
        };

        let rotator = ManifestRotator::new(config).unwrap();
        let endpoints = vec![test_endpoint("only.com", 443)];
        let current = vec![];

        let plan = rotator.generate_rotation_plan(&current, &endpoints);
        // With 1 endpoint, initial_count.max(1) ensures at least 1
        assert_eq!(plan.stages.len(), 1);
        assert_eq!(plan.stages[0].endpoints.len(), 1);
    }

    #[test]
    fn test_generate_rotation_plan_scheduled() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let keypair = SigningKeypair::generate();
        let target_time = SystemTime::now() + Duration::from_secs(3600);

        let config = ManifestRotatorConfig {
            signing_keypair: keypair,
            output_dir: temp_dir.path().to_path_buf(),
            rss_config: None,
            rotation_strategy: RotationStrategy::Scheduled { target_time },
            current_manifest_path: None,
            backup_dir: temp_dir.path().join("backups"),
            max_backups: 5,
        };

        let rotator = ManifestRotator::new(config).unwrap();
        let endpoints = vec![
            test_endpoint("server1.com", 443),
            test_endpoint("server2.com", 8443),
        ];
        let current = vec![];

        let plan = rotator.generate_rotation_plan(&current, &endpoints);
        assert_eq!(plan.stages.len(), 1);
        assert_eq!(plan.stages[0].endpoints.len(), 2);
        // Delay should be approximately 1 hour (3600 seconds)
        assert!(plan.stages[0].delay > Duration::from_secs(3500));
    }

    #[test]
    fn test_generate_rotation_plan_scheduled_past_time() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let keypair = SigningKeypair::generate();
        // Target time in the past
        let target_time = SystemTime::now() - Duration::from_secs(100);

        let config = ManifestRotatorConfig {
            signing_keypair: keypair,
            output_dir: temp_dir.path().to_path_buf(),
            rss_config: None,
            rotation_strategy: RotationStrategy::Scheduled { target_time },
            current_manifest_path: None,
            backup_dir: temp_dir.path().join("backups"),
            max_backups: 5,
        };

        let rotator = ManifestRotator::new(config).unwrap();
        let endpoints = vec![test_endpoint("server.com", 443)];

        let plan = rotator.generate_rotation_plan(&[], &endpoints);
        // Past time should result in zero delay
        assert_eq!(plan.stages[0].delay, Duration::ZERO);
    }

    #[tokio::test]
    async fn test_rollback_no_backup_dir() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let keypair = SigningKeypair::generate();

        let config = ManifestRotatorConfig {
            signing_keypair: keypair,
            output_dir: temp_dir.path().to_path_buf(),
            rss_config: None,
            rotation_strategy: RotationStrategy::Immediate,
            current_manifest_path: None,
            backup_dir: temp_dir.path().join("nonexistent_backups"),
            max_backups: 5,
        };

        let rotator = ManifestRotator::new(config).unwrap();
        let result = rotator.rollback().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }

    #[tokio::test]
    async fn test_rollback_empty_backups() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let backup_dir = temp_dir.path().join("backups");
        tokio::fs::create_dir_all(&backup_dir).await.unwrap();

        let keypair = SigningKeypair::generate();
        let config = ManifestRotatorConfig {
            signing_keypair: keypair,
            output_dir: temp_dir.path().to_path_buf(),
            rss_config: None,
            rotation_strategy: RotationStrategy::Immediate,
            current_manifest_path: None,
            backup_dir,
            max_backups: 5,
        };

        let rotator = ManifestRotator::new(config).unwrap();
        let result = rotator.rollback().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No backup"));
    }

    #[tokio::test]
    async fn test_cleanup_backups() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let backup_dir = temp_dir.path().join("backups");
        tokio::fs::create_dir_all(&backup_dir).await.unwrap();

        // Create 5 backup files
        for i in 1..=5 {
            tokio::fs::write(backup_dir.join(format!("manifest_{}.json", i)), "{}")
                .await
                .unwrap();
        }

        let keypair = SigningKeypair::generate();
        let config = ManifestRotatorConfig {
            signing_keypair: keypair,
            output_dir: temp_dir.path().to_path_buf(),
            rss_config: None,
            rotation_strategy: RotationStrategy::Immediate,
            current_manifest_path: None,
            backup_dir: backup_dir.clone(),
            max_backups: 3,
        };

        let rotator = ManifestRotator::new(config).unwrap();

        // Before cleanup
        let backups_before = rotator.list_backups().await.unwrap();
        assert_eq!(backups_before.len(), 5);

        // Cleanup
        rotator.cleanup_backups().await.unwrap();

        // After cleanup - should have max_backups (3)
        let backups_after = rotator.list_backups().await.unwrap();
        assert_eq!(backups_after.len(), 3);
    }

    #[tokio::test]
    async fn test_cleanup_backups_under_limit() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let backup_dir = temp_dir.path().join("backups");
        tokio::fs::create_dir_all(&backup_dir).await.unwrap();

        // Create 2 backup files (under limit of 5)
        tokio::fs::write(backup_dir.join("manifest_1.json"), "{}")
            .await
            .unwrap();
        tokio::fs::write(backup_dir.join("manifest_2.json"), "{}")
            .await
            .unwrap();

        let keypair = SigningKeypair::generate();
        let config = ManifestRotatorConfig {
            signing_keypair: keypair,
            output_dir: temp_dir.path().to_path_buf(),
            rss_config: None,
            rotation_strategy: RotationStrategy::Immediate,
            current_manifest_path: None,
            backup_dir,
            max_backups: 5,
        };

        let rotator = ManifestRotator::new(config).unwrap();
        rotator.cleanup_backups().await.unwrap();

        // Should still have 2 (no cleanup needed)
        let backups = rotator.list_backups().await.unwrap();
        assert_eq!(backups.len(), 2);
    }
}
