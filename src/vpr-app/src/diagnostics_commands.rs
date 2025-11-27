//! Tauri commands for VPN diagnostics and auto-fix

use masque_core::diagnostics::{
    engine::DiagnosticEngine,
    fixes::FixResult,
    ssh_client::SshConfig as CoreSshConfig,
    DiagnosticConfig, DiagnosticContext, DiagnosticResult, FixConsentLevel,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use tokio::sync::Mutex;

/// Diagnostic state for the UI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticState {
    pub running: bool,
    pub progress: u8, // 0-100
    pub current_check: Option<String>,
    pub report: Option<SerializableReport>,
}

impl Default for DiagnosticState {
    fn default() -> Self {
        Self {
            running: false,
            progress: 0,
            current_check: None,
            report: None,
        }
    }
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

        let fixable_issues = ctx.all_failures().into_iter().filter(|r| r.fix.is_some()).count();
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Option<String>,
    pub key_path: Option<String>,
}

impl From<SshConfig> for CoreSshConfig {
    fn from(config: SshConfig) -> Self {
        CoreSshConfig {
            host: config.host,
            ssh_port: config.port,
            user: config.user,
            password: config.password,
            ssh_key: config.key_path.map(|p| p.into()),
        }
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

    let ssh_cfg = ssh_config.map(CoreSshConfig::from);
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
        let ip: IpAddr = parts[0]
            .parse()
            .map_err(|e| format!("Invalid IP: {}", e))?;
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

    let ssh_cfg = ssh_config.map(CoreSshConfig::from);
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
