//! Unit tests for ManifestRotator
//!
//! Tests basic ManifestRotator functionality with current API.

use masque_core::manifest_rotator::{
    EndpointConfig, ManifestRotator, ManifestRotatorConfig, RotationStrategy,
};
use tempfile::TempDir;
use vpr_crypto::keys::SigningKeypair;
use vpr_crypto::manifest::ServerEndpoint;

fn sample_endpoint(id: &str, host: &str) -> EndpointConfig {
    EndpointConfig {
        server: ServerEndpoint::new(
            id,
            host,
            443,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
        active: true,
    }
}

#[test]
fn manifest_rotator_creation() {
    let tmp = TempDir::new().unwrap();
    let signing = SigningKeypair::generate();

    let config = ManifestRotatorConfig {
        signing_keypair: signing,
        output_dir: tmp.path().join("out"),
        rss_config: None,
        rotation_strategy: RotationStrategy::Immediate,
        current_manifest_path: None,
        backup_dir: tmp.path().join("backups"),
        max_backups: 3,
    };

    let rotator = ManifestRotator::new(config);
    assert!(rotator.is_ok(), "ManifestRotator should be creatable");
}

#[test]
fn manifest_rotator_generates_plan() {
    let tmp = TempDir::new().unwrap();
    let signing = SigningKeypair::generate();

    let config = ManifestRotatorConfig {
        signing_keypair: signing,
        output_dir: tmp.path().join("out"),
        rss_config: None,
        rotation_strategy: RotationStrategy::Immediate,
        current_manifest_path: None,
        backup_dir: tmp.path().join("backups"),
        max_backups: 3,
    };

    let rotator = ManifestRotator::new(config).unwrap();
    let endpoints = vec![sample_endpoint("srv-1", "example.com")];

    let plan = rotator.generate_rotation_plan(&[], &endpoints);
    assert!(
        !plan.stages.is_empty(),
        "Plan should have at least one stage"
    );
}

#[tokio::test]
async fn manifest_rotator_rotate_immediate() {
    let tmp = TempDir::new().unwrap();
    let signing = SigningKeypair::generate();

    // Create output directory
    std::fs::create_dir_all(tmp.path().join("out")).unwrap();
    std::fs::create_dir_all(tmp.path().join("backups")).unwrap();

    let config = ManifestRotatorConfig {
        signing_keypair: signing,
        output_dir: tmp.path().join("out"),
        rss_config: None,
        rotation_strategy: RotationStrategy::Immediate,
        current_manifest_path: None,
        backup_dir: tmp.path().join("backups"),
        max_backups: 3,
    };

    let rotator = ManifestRotator::new(config).unwrap();
    let endpoints = vec![sample_endpoint("srv-1", "test.example.com")];

    let result = rotator.rotate(endpoints, None, None).await;
    assert!(
        result.is_ok(),
        "Immediate rotation should succeed: {:?}",
        result.err()
    );

    let manifest = result.unwrap();
    assert!(
        !manifest.payload.is_empty(),
        "Manifest payload should not be empty"
    );
    assert!(
        !manifest.signature.is_empty(),
        "Manifest signature should not be empty"
    );
}
