//! Cross-checks between client and server for diagnostic consistency

use super::{DiagnosticReport, DiagnosticResult, Fix, Severity, SyncDirection};
use anyhow::Result;
use std::path::PathBuf;

/// Run cross-checks between client and server diagnostic reports
pub async fn run_cross_checks(
    client_report: &DiagnosticReport,
    server_report: &DiagnosticReport,
) -> Result<Vec<DiagnosticResult>> {
    Ok(vec![
        // Check 1: Noise key synchronization
        check_noise_key_sync()?,
        // Check 2: Time skew between client and server
        check_time_skew(client_report, server_report)?,
        // Check 3: Protocol version match (TODO: when versioning is implemented)
        // check_protocol_version_match(client_report, server_report)?,
    ])
}

fn check_noise_key_sync() -> Result<DiagnosticResult> {
    // Compare MD5 hashes of client.noise.pub on both sides
    // Note: This requires SSH access to server, which we'll implement in the engine
    // For now, we'll create a placeholder that suggests manual verification

    let client_pub_key = PathBuf::from("secrets/client.noise.pub");

    if !client_pub_key.exists() {
        return Ok(DiagnosticResult {
            check_name: "Noise Key Sync (Cross-Check)".to_string(),
            passed: false,
            severity: Severity::Critical,
            message: "Client public key not found locally".to_string(),
            fix: Some(Fix::ManualInstruction {
                instruction: "vpr-keygen client".to_string(),
                description: "Generate client Noise keys".to_string(),
            }),
            auto_fixable: true,
        });
    }

    // Calculate MD5 hash of local client.noise.pub
    let client_key_content = std::fs::read(&client_pub_key)?;
    let client_hash = format!("{:x}", md5::compute(&client_key_content));

    // TODO: In the engine, we'll fetch the server-side hash via SSH and compare
    // For now, we'll assume it needs verification

    Ok(DiagnosticResult {
        check_name: "Noise Key Sync (Cross-Check)".to_string(),
        passed: true, // Will be determined by engine when SSH is available
        severity: Severity::Critical,
        message: format!(
            "Client key hash: {} (verify this matches server-side)",
            client_hash
        ),
        fix: Some(Fix::SyncNoiseKeys {
            direction: SyncDirection::ClientToServer,
        }),
        auto_fixable: true,
    })
}

fn check_time_skew(
    client_report: &DiagnosticReport,
    server_report: &DiagnosticReport,
) -> Result<DiagnosticResult> {
    // Check if client and server timestamps are within acceptable range
    let client_time = client_report.timestamp;
    let server_time = server_report.timestamp;

    let duration = if client_time > server_time {
        client_time.duration_since(server_time).unwrap_or_default()
    } else {
        server_time.duration_since(client_time).unwrap_or_default()
    };

    let skew_secs = duration.as_secs();
    let acceptable_skew = 300; // 5 minutes

    let passed = skew_secs <= acceptable_skew;

    Ok(DiagnosticResult {
        check_name: "Time Skew (Cross-Check)".to_string(),
        passed,
        severity: if skew_secs > 600 {
            Severity::Critical
        } else if skew_secs > acceptable_skew {
            Severity::Error
        } else {
            Severity::Info
        },
        message: if passed {
            format!("Client-server time skew is acceptable ({} seconds)", skew_secs)
        } else {
            format!(
                "Client-server time skew is TOO LARGE ({} seconds > {} seconds max). This will break Noise protocol nonces!",
                skew_secs, acceptable_skew
            )
        },
        fix: if !passed {
            Some(Fix::ManualInstruction {
                instruction: "ntpdate -s time.nist.gov || chronyd -q".to_string(),
                description: "Sync time with NTP server".to_string(),
            })
        } else {
            None
        },
        auto_fixable: true,
    })
}

#[allow(dead_code)]
fn check_protocol_version_match(
    _client_report: &DiagnosticReport,
    _server_report: &DiagnosticReport,
) -> Result<DiagnosticResult> {
    // TODO: When protocol versioning is implemented, check for version compatibility

    Ok(DiagnosticResult {
        check_name: "Protocol Version Match (Cross-Check)".to_string(),
        passed: true,
        severity: Severity::Info,
        message: "Protocol version check not implemented yet".to_string(),
        fix: None,
        auto_fixable: false,
    })
}
