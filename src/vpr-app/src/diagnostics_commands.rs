//! Tauri commands for VPN diagnostics and auto-fix

use masque_core::diagnostics::{
    engine::DiagnosticEngine, fixes::FixResult, ssh_client::SshConfig as CoreSshConfig,
    DiagnosticConfig, DiagnosticContext, DiagnosticResult, FixConsentLevel,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use tokio::sync::Mutex;

/// Diagnostic state for the UI
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiagnosticState {
    pub running: bool,
    pub progress: u8, // 0-100
    pub current_check: Option<String>,
    pub report: Option<SerializableReport>,
}

/// Serializable version of DiagnosticReport for Tauri
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableReport {
    pub overall_health: String,
    pub client_checks: Vec<SerializableCheck>,
    pub server_checks: Vec<SerializableCheck>,
    pub cross_checks: Vec<SerializableCheck>,
    pub fixable_issues: usize,
    pub auto_fixable_issues: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableCheck {
    pub name: String,
    pub passed: bool,
    pub severity: String,
    pub message: String,
    pub has_fix: bool,
    pub auto_fixable: bool,
}

impl From<&DiagnosticResult> for SerializableCheck {
    fn from(result: &DiagnosticResult) -> Self {
        Self {
            name: result.check_name.clone(),
            passed: result.passed,
            severity: format!("{:?}", result.severity),
            message: result.message.clone(),
            has_fix: result.fix.is_some(),
            auto_fixable: result.auto_fixable,
        }
    }
}

impl From<DiagnosticContext> for SerializableReport {
    fn from(ctx: DiagnosticContext) -> Self {
        let client_checks = ctx
            .client_report
            .as_ref()
            .map(|r| r.results.iter().map(SerializableCheck::from).collect())
            .unwrap_or_default();

        let server_checks = ctx
            .server_report
            .as_ref()
            .map(|r| r.results.iter().map(SerializableCheck::from).collect())
            .unwrap_or_default();

        let cross_checks = ctx
            .cross_checks
            .iter()
            .map(SerializableCheck::from)
            .collect();

        let overall_health = ctx
            .client_report
            .as_ref()
            .map(|r| format!("{:?}", r.overall_status))
            .unwrap_or_else(|| "Unknown".to_string());

        let fixable_issues = ctx
            .all_failures()
            .into_iter()
            .filter(|r| r.fix.is_some())
            .count();
        let auto_fixable_issues = ctx
            .all_failures()
            .into_iter()
            .filter(|r| r.auto_fixable && r.fix.is_some())
            .count();

        Self {
            overall_health,
            client_checks,
            server_checks,
            cross_checks,
            fixable_issues,
            auto_fixable_issues,
        }
    }
}

/// SSH configuration for diagnostics
///
/// # Security
/// Password authentication is NOT supported because:
/// - Passwords passed via CLI args are visible in process lists (`ps aux`)
/// - SSH keys provide stronger authentication
/// - Key-based auth enables automation without credential exposure
///
/// Use `ssh-keygen -t ed25519` to generate keys and `ssh-copy-id` to install them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Path to SSH private key (required for authentication)
    pub key_path: String,
}

impl TryFrom<SshConfig> for CoreSshConfig {
    type Error = anyhow::Error;

    fn try_from(config: SshConfig) -> Result<Self, Self::Error> {
        CoreSshConfig::new(
            &config.host,
            config.port,
            &config.user,
            Some(config.key_path.into()),
        )
    }
}

/// Run VPN diagnostics
#[tauri::command]
pub async fn run_diagnostics(
    app: AppHandle,
    server_addr: Option<String>,
    ssh_config: Option<SshConfig>,
) -> Result<SerializableReport, String> {
    tracing::info!("Tauri: Starting diagnostics");

    // Parse server address
    let parsed_server = if let Some(addr) = server_addr {
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() != 2 {
            return Err("Invalid server address format (expected host:port)".to_string());
        }
        let ip: IpAddr = parts[0]
            .parse()
            .map_err(|e| format!("Invalid IP address: {}", e))?;
        let port: u16 = parts[1]
            .parse()
            .map_err(|e| format!("Invalid port: {}", e))?;
        Some((ip, port))
    } else {
        None
    };

    let config = DiagnosticConfig {
        auto_fix: false,
        timeout_secs: 30,
        server_addr: parsed_server,
        privileged: unsafe { libc::geteuid() } == 0,
    };

    let ssh_cfg = match ssh_config {
        Some(cfg) => {
            Some(CoreSshConfig::try_from(cfg).map_err(|e| format!("Invalid SSH config: {}", e))?)
        }
        None => None,
    };
    let engine = DiagnosticEngine::new(config, ssh_cfg);

    // Emit progress events
    let _ = app.emit(
        "diagnostic_progress",
        DiagnosticState {
            running: true,
            progress: 10,
            current_check: Some("Starting diagnostics...".to_string()),
            report: None,
        },
    );

    // Run diagnostics
    let context = engine
        .run_full_diagnostics()
        .await
        .map_err(|e| format!("Diagnostics failed: {}", e))?;

    let report = SerializableReport::from(context);

    let _ = app.emit(
        "diagnostic_progress",
        DiagnosticState {
            running: false,
            progress: 100,
            current_check: None,
            report: Some(report.clone()),
        },
    );

    tracing::info!("Tauri: Diagnostics complete");
    Ok(report)
}

/// Apply auto-fixes with specified consent level
#[tauri::command]
pub async fn apply_auto_fixes(
    app: AppHandle,
    server_addr: Option<String>,
    ssh_config: Option<SshConfig>,
    consent_level: String,
) -> Result<Vec<String>, String> {
    tracing::info!("Tauri: Applying auto-fixes with consent: {}", consent_level);

    let consent = match consent_level.as_str() {
        "auto" => FixConsentLevel::Auto,
        "semi_auto" => FixConsentLevel::SemiAuto,
        "manual" => FixConsentLevel::Manual,
        _ => return Err(format!("Invalid consent level: {}", consent_level)),
    };

    // Parse server address
    let parsed_server = if let Some(addr) = server_addr {
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() != 2 {
            return Err("Invalid server address format".to_string());
        }
        let ip: IpAddr = parts[0].parse().map_err(|e| format!("Invalid IP: {}", e))?;
        let port: u16 = parts[1]
            .parse()
            .map_err(|e| format!("Invalid port: {}", e))?;
        Some((ip, port))
    } else {
        None
    };

    let config = DiagnosticConfig {
        auto_fix: false,
        timeout_secs: 30,
        server_addr: parsed_server,
        privileged: unsafe { libc::geteuid() } == 0,
    };

    let ssh_cfg = match ssh_config {
        Some(cfg) => {
            Some(CoreSshConfig::try_from(cfg).map_err(|e| format!("Invalid SSH config: {}", e))?)
        }
        None => None,
    };
    let engine = DiagnosticEngine::new(config, ssh_cfg);

    // First run diagnostics to get context
    let _ = app.emit(
        "fix_progress",
        "Running diagnostics before fixes...".to_string(),
    );

    let context = engine
        .run_full_diagnostics()
        .await
        .map_err(|e| format!("Diagnostics failed: {}", e))?;

    // Apply fixes
    let _ = app.emit("fix_progress", "Applying fixes...".to_string());

    let results = engine
        .apply_auto_fixes(&context, consent)
        .await
        .map_err(|e| format!("Auto-fix failed: {}", e))?;

    let messages: Vec<String> = results
        .iter()
        .map(|r| match r {
            FixResult::Success(msg) => {
                format!("✅ Success: {}", msg)
            }
            FixResult::Failed(error) => {
                format!("❌ Failed: {}", error)
            }
            FixResult::Skipped(reason) => {
                format!("⏭️  Skipped: {}", reason)
            }
        })
        .collect();

    let _ = app.emit("fix_progress", "Fixes complete".to_string());

    tracing::info!("Tauri: Auto-fixes complete: {} results", messages.len());
    Ok(messages)
}

/// Get current diagnostic state (for UI polling)
#[tauri::command]
pub async fn get_diagnostic_state(
    state: tauri::State<'_, Arc<Mutex<DiagnosticState>>>,
) -> Result<DiagnosticState, String> {
    Ok(state.lock().await.clone())
}

/// Cancel running diagnostics
#[tauri::command]
pub async fn cancel_diagnostics(
    state: tauri::State<'_, Arc<Mutex<DiagnosticState>>>,
) -> Result<(), String> {
    let mut diag_state = state.lock().await;
    diag_state.running = false;
    diag_state.progress = 0;
    diag_state.current_check = None;
    Ok(())
}

// =============================================================================
// Extended Flagship Diagnostics Commands
// =============================================================================

use crate::connection_diagnostics::{
    self, AutoFix, ComprehensiveDiagnosticResult, ConnectionQuality,
    DiagnosticParams, HealthCheckResult, QuicDiagnostic, RetryConfig, RetryState,
    ServerDiagnosticResult, SshConfig as ConnSshConfig,
};
use std::path::PathBuf;

/// Run comprehensive flagship diagnostics (all checks in one call)
///
/// # Security
/// SSH key authentication is required for remote server diagnostics.
/// Password authentication is not supported due to security concerns
/// (passwords visible in process lists).
#[tauri::command]
pub async fn run_comprehensive_diagnostics(
    app: AppHandle,
    server: String,
    port: u16,
    secrets_dir: Option<String>,
    ssh_host: Option<String>,
    ssh_user: Option<String>,
    ssh_key_path: Option<String>,
    ssh_port: Option<u16>,
) -> Result<ComprehensiveDiagnosticResult, String> {
    tracing::info!(
        server = %server,
        port = port,
        "Running comprehensive flagship diagnostics"
    );

    // Emit start event
    let _ = app.emit("comprehensive_diagnostic_start", ());

    // Build diagnostic params
    let secrets_path = secrets_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".silentway/secrets"))
                .unwrap_or_else(|_| PathBuf::from("secrets"))
        });

    let params = DiagnosticParams {
        server: server.clone(),
        port,
        secrets_dir: secrets_path,
        timeout_ms: 10000,
        tun_name: "vpr0".to_string(),
    };

    // Build SSH config if provided (key path required for SSH)
    let ssh_config = if let (Some(host), Some(user), Some(key_path)) = (ssh_host, ssh_user, ssh_key_path) {
        Some(ConnSshConfig {
            host,
            port: ssh_port.unwrap_or(22),
            user,
            key_path: PathBuf::from(key_path),
            known_hosts_path: None,
        })
    } else {
        None
    };

    let client_version = env!("CARGO_PKG_VERSION");

    let result = connection_diagnostics::run_comprehensive_diagnostics(
        &params,
        ssh_config.as_ref(),
        client_version,
    )
    .await;

    // Emit result
    let _ = app.emit("comprehensive_diagnostic_result", &result);

    tracing::info!(
        status = ?result.overall_status,
        duration_ms = result.total_duration_ms,
        "Comprehensive diagnostics complete"
    );

    Ok(result)
}

/// Measure connection quality to server
#[tauri::command]
pub async fn measure_connection_quality(
    server: String,
    samples: Option<usize>,
) -> Result<ConnectionQuality, String> {
    let samples = samples.unwrap_or(5);
    tracing::info!(server = %server, samples = samples, "Measuring connection quality");

    let quality = connection_diagnostics::measure_connection_quality(&server, samples).await;

    tracing::info!(
        rtt_ms = quality.rtt_ms,
        jitter_ms = quality.rtt_jitter_ms,
        loss_percent = quality.packet_loss_percent,
        score = quality.quality_score,
        label = %quality.quality_label,
        "Connection quality measured"
    );

    Ok(quality)
}

/// Run QUIC-specific diagnostics
#[tauri::command]
pub async fn diagnose_quic_connection(
    server: String,
    port: u16,
    timeout_ms: Option<u64>,
) -> Result<QuicDiagnostic, String> {
    let timeout = timeout_ms.unwrap_or(5000);
    tracing::info!(server = %server, port = port, timeout_ms = timeout, "Running QUIC diagnostics");

    let result = connection_diagnostics::diagnose_quic_connection(&server, port, timeout).await;

    tracing::info!(
        initial_handshake_completed = result.initial_handshake.completed,
        quic_version = ?result.quic_version,
        total_time_ms = result.total_time_ms,
        errors = ?result.errors,
        "QUIC diagnostics complete"
    );

    Ok(result)
}

/// Run remote server diagnostics via SSH
///
/// # Security
/// SSH key authentication is required. Password authentication is not supported
/// due to security concerns (passwords visible in process lists via `ps aux`).
#[tauri::command]
pub async fn run_server_diagnostics(
    host: String,
    ssh_port: Option<u16>,
    user: String,
    key_path: String,
    vpn_port: u16,
) -> Result<ServerDiagnosticResult, String> {
    tracing::info!(host = %host, vpn_port = vpn_port, "Running remote server diagnostics");

    let ssh_config = ConnSshConfig {
        host,
        port: ssh_port.unwrap_or(22),
        user,
        key_path: PathBuf::from(key_path),
        known_hosts_path: None,
    };

    let result = connection_diagnostics::run_remote_server_diagnostics(&ssh_config, vpn_port).await;

    tracing::info!(
        vpn_running = result.vpn_server_running,
        listening_port = ?result.vpn_listening_port,
        firewall_open = result.firewall_open,
        errors = ?result.errors,
        "Server diagnostics complete"
    );

    Ok(result)
}

/// Check health endpoint
#[tauri::command]
pub async fn check_health_endpoint(
    server: String,
    port: u16,
    endpoint: Option<String>,
) -> Result<HealthCheckResult, String> {
    let endpoint = endpoint.unwrap_or_else(|| "/health".to_string());
    tracing::info!(server = %server, port = port, endpoint = %endpoint, "Checking health endpoint");

    let result = connection_diagnostics::check_health_endpoint(&server, port, &endpoint).await;

    tracing::info!(
        reachable = result.reachable,
        status_code = ?result.status_code,
        response_time_ms = result.response_time_ms,
        "Health check complete"
    );

    Ok(result)
}

/// Get available auto-fixes for a diagnostic code
#[tauri::command]
pub fn get_available_fixes(code: String) -> Vec<AutoFix> {
    // Parse diagnostic code from string
    let diag_code = match code.as_str() {
        "E101" => connection_diagnostics::DiagnosticCode::E101_MissingServerPubKey,
        "E102" => connection_diagnostics::DiagnosticCode::E102_MissingClientKey,
        "E105" => connection_diagnostics::DiagnosticCode::E105_KeyPermissions,
        "E201" => connection_diagnostics::DiagnosticCode::E201_DnsResolutionFailed,
        "E302" => connection_diagnostics::DiagnosticCode::E302_TunDeviceExists,
        "E304" => connection_diagnostics::DiagnosticCode::E304_FirewallBlocking,
        "E501" => connection_diagnostics::DiagnosticCode::E501_OtherVpnActive,
        _ => return Vec::new(),
    };

    connection_diagnostics::get_available_fixes(diag_code)
}

/// Apply a specific auto-fix
#[tauri::command]
pub async fn apply_specific_fix(fix: AutoFix) -> Result<String, String> {
    tracing::info!(name = %fix.name, command = %fix.command, "Applying fix");

    connection_diagnostics::apply_fix(&fix).await
}

/// Check if an error is retryable
#[tauri::command]
pub fn is_retryable_error(error: String) -> bool {
    RetryState::is_retryable_error(&error)
}

/// Get retry configuration
#[tauri::command]
pub fn get_retry_config() -> RetryConfig {
    RetryConfig::default()
}

/// Calculate next retry delay with exponential backoff
#[tauri::command]
pub fn calculate_retry_state(
    attempt: u32,
    last_error: Option<String>,
    config: Option<RetryConfig>,
) -> RetryState {
    let cfg = config.unwrap_or_default();
    let mut state = RetryState::new(&cfg);
    state.attempt = attempt;

    if let Some(error) = last_error {
        state.record_failure(&error, &cfg);
    }

    state
}

/// Check local certificate validity
#[tauri::command]
pub fn check_local_certificate(cert_path: String) -> connection_diagnostics::LocalCertificateCheck {
    let path = PathBuf::from(cert_path);
    connection_diagnostics::check_local_certificate(&path)
}

// =============================================================================
// Ultimate Flagship Diagnostics Commands
// =============================================================================

use crate::connection_diagnostics::{
    NetworkPathAnalysis, DpiDetectionResult, DnsLeakTestResult, Ipv6LeakInfo,
    BandwidthEstimate, KillSwitchStatus, MultiPathProbeResult, UltimateDiagnosticReport,
};

/// Run network path analysis (traceroute-style)
#[tauri::command]
pub async fn analyze_network_path(
    server: String,
    port: u16,
    probes: Option<usize>,
) -> Result<NetworkPathAnalysis, String> {
    let probes = probes.unwrap_or(3);
    tracing::info!(server = %server, port = port, probes = probes, "Analyzing network path");

    let result = connection_diagnostics::analyze_network_path(&server, port, probes).await;

    tracing::info!(
        total_hops = result.total_hops,
        destination_reached = result.destination_reached,
        path_quality = ?result.path_quality,
        blocking_suspected = result.analysis.blocking_suspected,
        "Network path analysis complete"
    );

    Ok(result)
}

/// Detect DPI (Deep Packet Inspection) on the network path
#[tauri::command]
pub async fn detect_dpi(
    server: String,
    port: u16,
) -> Result<DpiDetectionResult, String> {
    tracing::info!(server = %server, port = port, "Detecting DPI");

    let result = connection_diagnostics::detect_dpi(&server, port).await;

    tracing::info!(
        dpi_detected = result.dpi_detected,
        dpi_type = ?result.dpi_type,
        confidence = result.confidence,
        evidence_count = result.evidence.len(),
        "DPI detection complete"
    );

    Ok(result)
}

/// Test for DNS leaks
#[tauri::command]
pub async fn test_dns_leak(
    expected_dns: Option<String>,
) -> Result<DnsLeakTestResult, String> {
    tracing::info!(expected_dns = ?expected_dns, "Testing for DNS leaks");

    let result = connection_diagnostics::test_dns_leak(expected_dns.as_deref()).await;

    tracing::info!(
        leak_detected = result.leak_detected,
        dns_servers_count = result.dns_servers_detected.len(),
        "DNS leak test complete"
    );

    Ok(result)
}

/// Test for IPv6 leaks
#[tauri::command]
pub async fn test_ipv6_leak() -> Result<Ipv6LeakInfo, String> {
    tracing::info!("Testing for IPv6 leaks");

    let result = connection_diagnostics::test_ipv6_leak().await;

    tracing::info!(
        ipv6_enabled = result.ipv6_enabled,
        ipv6_connectivity = result.ipv6_connectivity,
        leak_risk = result.leak_risk,
        addresses_count = result.ipv6_addresses.len(),
        "IPv6 leak test complete"
    );

    Ok(result)
}

/// Estimate bandwidth to server
#[tauri::command]
pub async fn estimate_bandwidth(
    server: String,
    port: u16,
    duration_secs: Option<u64>,
) -> Result<BandwidthEstimate, String> {
    let duration = duration_secs.unwrap_or(5);
    tracing::info!(server = %server, port = port, duration_secs = duration, "Estimating bandwidth");

    let result = connection_diagnostics::estimate_bandwidth(&server, port, duration).await;

    tracing::info!(
        download_mbps = result.download_mbps,
        upload_mbps = result.upload_mbps,
        latency_ms = result.latency_ms,
        "Bandwidth estimation complete"
    );

    Ok(result)
}

/// Verify kill switch status
#[tauri::command]
pub async fn verify_kill_switch(
    tun_interface: Option<String>,
) -> Result<KillSwitchStatus, String> {
    let tun = tun_interface.unwrap_or_else(|| "vpr0".to_string());
    tracing::info!(tun_interface = %tun, "Verifying kill switch");

    let result = connection_diagnostics::verify_kill_switch(&tun).await;

    tracing::info!(
        enabled = result.enabled,
        active = result.active,
        firewall_rules = result.firewall_rules_present,
        ipv4_protected = result.leak_protection.ipv4_protected,
        ipv6_protected = result.leak_protection.ipv6_protected,
        dns_protected = result.leak_protection.dns_protected,
        "Kill switch verification complete"
    );

    Ok(result)
}

/// Probe multiple paths to server
#[tauri::command]
pub async fn probe_multiple_paths(
    server: String,
    ports: Option<Vec<u16>>,
    transports: Option<Vec<String>>,
) -> Result<MultiPathProbeResult, String> {
    let ports = ports.unwrap_or_else(|| vec![443, 80, 8443]);
    let transports = transports.unwrap_or_else(|| vec!["tcp".to_string(), "udp".to_string()]);

    tracing::info!(
        server = %server,
        ports = ?ports,
        transports = ?transports,
        "Probing multiple paths"
    );

    let transport_refs: Vec<&str> = transports.iter().map(|s| s.as_str()).collect();
    let result = connection_diagnostics::probe_multiple_paths(&server, &ports, &transport_refs).await;

    tracing::info!(
        paths_count = result.paths.len(),
        best_path = ?result.best_path,
        diversity_score = result.diversity_score,
        "Multi-path probing complete"
    );

    Ok(result)
}

/// Run ultimate flagship diagnostics (everything)
#[tauri::command]
pub async fn run_ultimate_diagnostics(
    app: AppHandle,
    server: String,
    port: u16,
    secrets_dir: Option<String>,
    run_network_analysis: Option<bool>,
    run_dpi_detection: Option<bool>,
    run_leak_tests: Option<bool>,
    run_bandwidth_test: Option<bool>,
) -> Result<UltimateDiagnosticReport, String> {
    tracing::info!(
        server = %server,
        port = port,
        "Running ULTIMATE flagship diagnostics"
    );

    // Emit start event
    let _ = app.emit("ultimate_diagnostic_start", ());

    // Build diagnostic params
    let secrets_path = secrets_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".silentway/secrets"))
                .unwrap_or_else(|_| PathBuf::from("secrets"))
        });

    let params = DiagnosticParams {
        server: server.clone(),
        port,
        secrets_dir: secrets_path,
        timeout_ms: 10000,
        tun_name: "vpr0".to_string(),
    };

    let result = connection_diagnostics::run_ultimate_diagnostics(
        &params,
        run_network_analysis.unwrap_or(true),
        run_dpi_detection.unwrap_or(true),
        run_leak_tests.unwrap_or(true),
        run_bandwidth_test.unwrap_or(false), // Slow, disabled by default
    )
    .await;

    // Emit result
    let _ = app.emit("ultimate_diagnostic_result", &result);

    tracing::info!(
        score = result.overall_health.score,
        grade = %result.overall_health.grade,
        status = %result.overall_health.status,
        critical_issues = result.critical_issues.len(),
        warnings = result.warnings.len(),
        duration_ms = result.duration_ms,
        "ULTIMATE diagnostics complete"
    );

    Ok(result)
}

/// Get reconnect strategy
#[tauri::command]
pub fn get_reconnect_strategy() -> connection_diagnostics::ReconnectStrategy {
    connection_diagnostics::ReconnectStrategy::default()
}
