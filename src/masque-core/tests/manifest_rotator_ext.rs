//! Extended tests for ManifestRotator
//!
//! Tests rotation, backup creation, and scheduled rotation planning.

use std::time::{Duration, SystemTime};

use tempfile::TempDir;
use vpr_crypto::keys::SigningKeypair;
use vpr_crypto::manifest::{ManifestPayload, ServerEndpoint, SignedManifest};

use masque_core::manifest_rotator::{
    EndpointConfig, ManifestRotator, ManifestRotatorConfig, RotationStrategy,
};

fn make_signed_manifest(secret_bytes: &[u8; 32], host: &str, port: u16) -> SignedManifest {
    let key = SigningKeypair::from_secret_bytes(secret_bytes).expect("valid key bytes");
    let payload = ManifestPayload::new(vec![ServerEndpoint::new(
        "id-1",
        host,
        port,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )]);
    SignedManifest::sign(&payload, &key).expect("sign manifest")
}

#[tokio::test]
async fn test_backup_created_on_rotate() {
    let tmp = TempDir::new().unwrap();
    // Use fixed secret bytes so we can recreate the same key
    let secret_bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    // prepare current manifest file
    let current_manifest_path = tmp.path().join("current.json");
    let current = make_signed_manifest(&secret_bytes, "old.example", 443);
    std::fs::write(
        &current_manifest_path,
        serde_json::to_string(&current).unwrap(),
    )
    .unwrap();

    // Create signing keypair for rotator
    let signing = SigningKeypair::from_secret_bytes(&secret_bytes).expect("valid key");

    let config = ManifestRotatorConfig {
        signing_keypair: signing,
        output_dir: tmp.path().join("out"),
        rss_config: None,
        rotation_strategy: RotationStrategy::Immediate,
        current_manifest_path: Some(current_manifest_path.clone()),
        backup_dir: tmp.path().join("backups"),
        max_backups: 2,
    };

    let rotator = ManifestRotator::new(config).unwrap();

    let new_endpoints = vec![EndpointConfig {
        server: ServerEndpoint::new(
            "id-2",
            "new.example",
            443,
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        ),
        active: true,
    }];

    let rotated = rotator
        .rotate(new_endpoints, None, None)
        .await
        .expect("rotate");

    // backup should exist
    let backups: Vec<_> = std::fs::read_dir(tmp.path().join("backups"))
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(backups.len(), 1);

    // rotated manifest payload should match new endpoint
    let payload: ManifestPayload = serde_json::from_str(&rotated.payload).unwrap();
    assert_eq!(payload.servers[0].host, "new.example");
}

#[test]
fn test_generate_rotation_plan_scheduled_delay_nonzero() {
    let signing = SigningKeypair::generate();
    let config = ManifestRotatorConfig {
        signing_keypair: signing,
        output_dir: TempDir::new().unwrap().path().to_path_buf(),
        rss_config: None,
        rotation_strategy: RotationStrategy::Scheduled {
            target_time: SystemTime::now() + Duration::from_secs(30),
        },
        current_manifest_path: None,
        backup_dir: TempDir::new().unwrap().path().to_path_buf(),
        max_backups: 1,
    };

    let rotator = ManifestRotator::new(config).unwrap();
    let endpoints = vec![EndpointConfig {
        server: ServerEndpoint::new(
            "id-1",
            "example.com",
            443,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
        active: true,
    }];

    let plan = rotator.generate_rotation_plan(&[], &endpoints);
    assert_eq!(plan.stages.len(), 1);
    assert!(plan.stages[0].delay > Duration::ZERO);
}
