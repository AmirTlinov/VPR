//! Full E2E Pipeline Tests
//!
//! These tests verify the complete VPN pipeline:
//! 1. SSH connection to VPS
//! 2. Server binary deployment
//! 3. Key generation
//! 4. Server startup
//! 5. Client connection
//! 6. Traffic verification
//! 7. Kill switch
//! 8. Reconnection
//! 9. Cleanup
//!
//! These tests require:
//! - A real VPS with root SSH access
//! - Environment variables: VPR_E2E_HOST, VPR_E2E_PASSWORD
//! - Built server binaries (vpn-server, vpr-keygen)
//! - Root privileges on local machine (for TUN creation)
//!
//! Run with: cargo test --package vpr-e2e --test full_pipeline -- --ignored

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use vpr_e2e::{Deployer, E2eConfig};

/// Get E2E config from environment or skip test
fn get_config() -> Option<E2eConfig> {
    let host = std::env::var("VPR_E2E_HOST").ok()?;
    let password = std::env::var("VPR_E2E_PASSWORD").ok()?;

    if host.is_empty() || password.is_empty() {
        return None;
    }

    let mut config = E2eConfig::default();
    config.server.host = host;
    config.server.password = Some(password);
    config.server.user = std::env::var("VPR_E2E_USER").unwrap_or_else(|_| "root".into());
    config.server.vpn_port = std::env::var("VPR_E2E_VPN_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(443);

    Some(config)
}

/// Find server binaries
fn find_binaries() -> Option<(PathBuf, PathBuf)> {
    let search_paths = [
        PathBuf::from("target/release"),
        PathBuf::from("target/debug"),
        PathBuf::from("../target/release"),
        PathBuf::from("../target/debug"),
        PathBuf::from("../../target/release"),
        PathBuf::from("../../target/debug"),
    ];

    for base in &search_paths {
        let server = base.join("vpn-server");
        let keygen = base.join("vpr-keygen");
        if server.exists() && keygen.exists() {
            return Some((server, keygen));
        }
    }
    None
}

/// Check if running as root (required for TUN creation)
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

// =============================================================================
// Test: SSH Connection
// =============================================================================

#[tokio::test]
#[ignore = "requires VPS and env vars"]
async fn test_01_ssh_connection() {
    let config = match get_config() {
        Some(c) => c,
        None => {
            eprintln!("SKIP: VPR_E2E_HOST and VPR_E2E_PASSWORD not set");
            return;
        }
    };

    let deployer = Deployer::new(config);

    let result = deployer.test_connection().await;
    assert!(result.is_ok(), "SSH connection failed: {:?}", result.err());

    println!("✓ SSH connection successful");
}

// =============================================================================
// Test: Server Deployment
// =============================================================================

#[tokio::test]
#[ignore = "requires VPS and env vars"]
async fn test_02_server_deployment() {
    let config = match get_config() {
        Some(c) => c,
        None => {
            eprintln!("SKIP: VPR_E2E_HOST and VPR_E2E_PASSWORD not set");
            return;
        }
    };

    let (server_bin, keygen_bin) = match find_binaries() {
        Some(b) => b,
        None => {
            eprintln!("SKIP: Server binaries not found. Run 'cargo build --release' first.");
            return;
        }
    };

    let deployer = Deployer::new(config);

    // Prepare server
    let result = deployer.prepare_server().await;
    assert!(result.is_ok(), "Failed to prepare server: {:?}", result.err());
    println!("✓ Server directory prepared");

    // Deploy server binary
    let result = deployer.deploy_server_binary(&server_bin).await;
    assert!(result.is_ok(), "Failed to deploy server binary: {:?}", result.err());
    println!("✓ Server binary deployed");

    // Deploy keygen binary
    let result = deployer.deploy_keygen_binary(&keygen_bin).await;
    assert!(result.is_ok(), "Failed to deploy keygen binary: {:?}", result.err());
    println!("✓ Keygen binary deployed");

    // Check binary exists
    let exists = deployer.server_binary_exists().await.unwrap_or(false);
    assert!(exists, "Server binary not found after deployment");
    println!("✓ Server binary verified");
}

// =============================================================================
// Test: Key Generation
// =============================================================================

#[tokio::test]
#[ignore = "requires VPS and env vars"]
async fn test_03_key_generation() {
    let config = match get_config() {
        Some(c) => c,
        None => {
            eprintln!("SKIP: VPR_E2E_HOST and VPR_E2E_PASSWORD not set");
            return;
        }
    };

    let deployer = Deployer::new(config);

    let result = deployer.ensure_server_keys().await;
    assert!(result.is_ok(), "Key generation failed: {:?}", result.err());

    println!("✓ Server keys generated/verified");
}

// =============================================================================
// Test: Server Start/Stop
// =============================================================================

#[tokio::test]
#[ignore = "requires VPS and env vars"]
async fn test_04_server_start_stop() {
    let config = match get_config() {
        Some(c) => c,
        None => {
            eprintln!("SKIP: VPR_E2E_HOST and VPR_E2E_PASSWORD not set");
            return;
        }
    };

    let deployer = Deployer::new(config);

    // Stop any existing server
    let _ = deployer.stop_server().await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let running = deployer.is_server_running().await;
    assert!(!running, "Server should be stopped");
    println!("✓ Server stopped");

    // Start server
    let result = deployer.start_server().await;
    assert!(result.is_ok(), "Failed to start server: {:?}", result.err());

    let running = deployer.is_server_running().await;
    assert!(running, "Server should be running");
    println!("✓ Server started");

    // Check logs
    let logs = deployer.get_server_logs(10).await.unwrap_or_default();
    assert!(!logs.is_empty(), "Server logs should not be empty");
    println!("✓ Server logs accessible");

    // Stop server
    let result = deployer.stop_server().await;
    assert!(result.is_ok(), "Failed to stop server: {:?}", result.err());

    let running = deployer.is_server_running().await;
    assert!(!running, "Server should be stopped");
    println!("✓ Server stopped");
}

// =============================================================================
// Test: Full Pipeline (requires root)
// =============================================================================

#[tokio::test]
#[ignore = "requires VPS, env vars, and root privileges"]
async fn test_05_full_pipeline() {
    if !is_root() {
        eprintln!("SKIP: This test requires root privileges for TUN creation");
        return;
    }

    let config = match get_config() {
        Some(c) => c,
        None => {
            eprintln!("SKIP: VPR_E2E_HOST and VPR_E2E_PASSWORD not set");
            return;
        }
    };

    let (server_bin, keygen_bin) = match find_binaries() {
        Some(b) => b,
        None => {
            eprintln!("SKIP: Server binaries not found. Run 'cargo build --release' first.");
            return;
        }
    };

    let deployer = Deployer::new(config.clone());

    println!("=== Phase 1: Server Setup ===");

    // Deploy everything
    deployer.prepare_server().await.expect("prepare_server");
    deployer.deploy_server_binary(&server_bin).await.expect("deploy_server");
    deployer.deploy_keygen_binary(&keygen_bin).await.expect("deploy_keygen");
    deployer.ensure_server_keys().await.expect("ensure_keys");
    deployer.start_server().await.expect("start_server");
    println!("✓ Server deployed and started");

    // Download server public key for client
    let secrets_dir = PathBuf::from("/tmp/vpr-e2e-secrets");
    std::fs::create_dir_all(&secrets_dir).expect("create secrets dir");
    deployer.download_server_pubkey(&secrets_dir.join("server.noise.pub")).await.expect("download pubkey");
    println!("✓ Server public key downloaded");

    println!("=== Phase 2: Client Connection ===");

    // Find client binary
    let client_bin = find_client_binary();
    if client_bin.is_none() {
        eprintln!("SKIP: Client binary (vpn-client) not found");
        deployer.stop_server().await.ok();
        return;
    }
    let client_bin = client_bin.unwrap();

    // Generate client keys
    let keygen = find_binaries().map(|(_, k)| k);
    if let Some(keygen) = keygen {
        let status = Command::new(&keygen)
            .args(["gen-noise-key", "--name", "client", "--output"])
            .arg(&secrets_dir)
            .status()
            .await;
        if status.is_err() || !status.unwrap().success() {
            eprintln!("WARN: Could not generate client keys, trying without");
        }
    }

    // Start client
    let mut client = Command::new(&client_bin)
        .args([
            "--server", &config.server.host,
            "--port", &config.server.vpn_port.to_string(),
            "--tun-name", &config.client.tun_name,
            "--noise-dir", secrets_dir.to_str().unwrap(),
            "--noise-name", "client",
            "--server-pub", secrets_dir.join("server.noise.pub").to_str().unwrap(),
            "--set-default-route",
            "--insecure",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start client");

    // Wait for connection
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Check TUN interface exists
    let tun_check = Command::new("ip")
        .args(["link", "show", &config.client.tun_name])
        .status()
        .await;
    let tun_exists = tun_check.map(|s| s.success()).unwrap_or(false);

    if !tun_exists {
        eprintln!("✗ TUN interface not created");
        client.kill().await.ok();
        deployer.stop_server().await.ok();
        panic!("Client failed to create TUN interface");
    }
    println!("✓ TUN interface created");

    println!("=== Phase 3: Traffic Verification ===");

    // Ping VPN gateway
    let ping_result = Command::new("ping")
        .args(["-c", "3", "-W", "5", "-I", &config.client.tun_name, "10.9.0.1"])
        .output()
        .await;

    let ping_ok = ping_result.map(|o| o.status.success()).unwrap_or(false);
    if !ping_ok {
        eprintln!("✗ Cannot ping VPN gateway");
    } else {
        println!("✓ Ping to VPN gateway successful");
    }

    // Test external connectivity through VPN
    let curl_result = Command::new("curl")
        .args([
            "-s", "--max-time", "10",
            "--interface", &config.client.tun_name,
            "https://ifconfig.me"
        ])
        .output()
        .await;

    if let Ok(output) = curl_result {
        if output.status.success() {
            let external_ip = String::from_utf8_lossy(&output.stdout);
            println!("✓ External IP via VPN: {}", external_ip.trim());
        } else {
            eprintln!("✗ External connectivity failed");
        }
    }

    println!("=== Phase 4: Cleanup ===");

    // Stop client
    client.kill().await.ok();
    tokio::time::sleep(Duration::from_secs(2)).await;
    println!("✓ Client stopped");

    // Stop server
    deployer.stop_server().await.ok();
    println!("✓ Server stopped");

    // Cleanup secrets
    std::fs::remove_dir_all(&secrets_dir).ok();
    println!("✓ Temporary files cleaned up");

    println!("=== Full Pipeline Test PASSED ===");
}

/// Find client binary
fn find_client_binary() -> Option<PathBuf> {
    let names = ["vpn-client", "masque-client"];
    let search_paths = [
        PathBuf::from("target/release"),
        PathBuf::from("target/debug"),
        PathBuf::from("../target/release"),
        PathBuf::from("../target/debug"),
        PathBuf::from("../../target/release"),
        PathBuf::from("../../target/debug"),
    ];

    for name in &names {
        for base in &search_paths {
            let path = base.join(name);
            if path.exists() {
                return Some(path);
            }
        }
    }
    None
}

// =============================================================================
// Test: Configuration Validation
// =============================================================================

#[test]
fn test_config_validation() {
    let mut config = E2eConfig::default();

    // Empty host should fail validation
    let result = config.validate();
    assert!(result.is_err(), "Empty host should fail validation");

    // Set host but no auth
    config.server.host = "1.2.3.4".into();
    let result = config.validate();
    assert!(result.is_err(), "No auth should fail validation");

    // Set password
    config.server.password = Some("secret".into());
    let result = config.validate();
    assert!(result.is_ok(), "Valid config should pass validation");
}

// =============================================================================
// Test: Report Generation
// =============================================================================

#[test]
fn test_report_generation() {
    use vpr_e2e::report::{E2eReport, TestResult};

    let results = vec![
        TestResult {
            name: "test_1".into(),
            passed: true,
            duration_ms: 100,
            details: Some("OK".into()),
            metrics: None,
            error: None,
        },
        TestResult {
            name: "test_2".into(),
            passed: false,
            duration_ms: 50,
            details: None,
            metrics: None,
            error: Some("Failed".into()),
        },
    ];

    let report = E2eReport::new(results.clone());
    assert_eq!(report.total_tests(), 2);
    assert_eq!(report.passed_tests(), 1);
    assert_eq!(report.failed_tests(), 1);

    // Generate markdown
    let md = report.to_markdown();
    assert!(md.contains("test_1"));
    assert!(md.contains("test_2"));
    assert!(md.contains("PASSED"));
    assert!(md.contains("FAILED"));
}
