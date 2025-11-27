//! Diagnostic engine orchestrator

use super::{
    client, cross_checks, fixes::{FixExecutor, FixResult, SshClient}, DiagnosticConfig,
    DiagnosticContext, DiagnosticReport, DiagnosticResult, FixConsentLevel
};
use super::ssh_client::{SshClientImpl, SshConfig};
use anyhow::{bail, Context, Result};

/// Diagnostic engine that orchestrates full diagnostic workflow
pub struct DiagnosticEngine {
    config: DiagnosticConfig,
    ssh_config: Option<SshConfig>,
}

impl DiagnosticEngine {
    /// Create new diagnostic engine
    pub fn new(config: DiagnosticConfig, ssh_config: Option<SshConfig>) -> Self {
        Self { config, ssh_config }
    }

    /// Run full diagnostics (client + server + cross-checks)
    pub async fn run_full_diagnostics(&self) -> Result<DiagnosticContext> {
        tracing::info!("Running full diagnostics");

        // Phase 1: Client-side checks (always run)
        tracing::debug!("Running client-side diagnostics");
        let client_report = client::run_diagnostics(&self.config)
            .await
            .context("Client diagnostics failed")?;

        tracing::info!(
            "Client diagnostics complete: {} checks, status: {:?}",
            client_report.results.len(),
            client_report.overall_status
        );

        // Phase 2: Server-side checks (if SSH available)
        let server_report = if self.ssh_config.is_some() {
            tracing::debug!("Running server-side diagnostics via SSH");
            match self.run_server_diagnostics_via_ssh().await {
                Ok(report) => {
                    tracing::info!(
                        "Server diagnostics complete: {} checks, status: {:?}",
                        report.results.len(),
                        report.overall_status
                    );
                    Some(report)
                }
                Err(e) => {
                    tracing::warn!("Server diagnostics failed: {}", e);
                    None
                }
            }
        } else {
            tracing::debug!("Skipping server diagnostics (no SSH config)");
            None
        };

        // Phase 3: Cross-checks (if both reports available)
        let cross_checks = if let Some(server_report) = &server_report {
            tracing::debug!("Running cross-checks");
            match cross_checks::run_cross_checks(&client_report, server_report).await {
                Ok(checks) => {
                    tracing::info!("Cross-checks complete: {} checks", checks.len());
                    checks
                }
                Err(e) => {
                    tracing::warn!("Cross-checks failed: {}", e);
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        Ok(DiagnosticContext {
            client_report: Some(client_report),
            server_report,
            cross_checks,
        })
    }

    /// Apply auto-fixes based on consent level
    pub async fn apply_auto_fixes(
        &self,
        context: &DiagnosticContext,
        consent_level: FixConsentLevel,
    ) -> Result<Vec<FixResult>> {
        tracing::info!("Applying auto-fixes with consent level: {:?}", consent_level);

        // Create SSH client if available
        let ssh_client: Option<Box<dyn SshClient>> = if let Some(ssh_config) = &self.ssh_config {
            match SshClientImpl::connect(ssh_config).await {
                Ok(client) => Some(Box::new(client)),
                Err(e) => {
                    tracing::warn!("Failed to connect SSH client: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let mut executor = FixExecutor::new(ssh_client);
        let mut results = Vec::new();

        // Collect all fixable issues based on consent level
        let issues = self.collect_fixable_issues(context, consent_level);

        if issues.is_empty() {
            tracing::info!("No fixable issues found");
            return Ok(results);
        }

        tracing::info!("Found {} fixable issues", issues.len());

        // Apply fixes sequentially
        for (idx, (check_name, fix)) in issues.iter().enumerate() {
            tracing::info!(
                "Applying fix {}/{}: {} -> {:?}",
                idx + 1,
                issues.len(),
                check_name,
                fix
            );

            match executor.apply_fix(fix).await {
                Ok(result) => {
                    tracing::info!("Fix result: {:?}", result);
                    results.push(result);
                }
                Err(e) => {
                    tracing::error!("Fix failed: {}, rolling back all changes", e);
                    executor.rollback_all().await?;
                    bail!("Auto-fix failed: {}", e);
                }
            }
        }

        tracing::info!("All fixes applied successfully");
        Ok(results)
    }

    /// Collect fixable issues based on consent level
    fn collect_fixable_issues(
        &self,
        context: &DiagnosticContext,
        consent_level: FixConsentLevel,
    ) -> Vec<(String, super::Fix)> {
        let mut issues = Vec::new();

        // Get all failed checks with fixes
        for result in context.all_failures() {
            if let Some(fix) = &result.fix {
                // Determine if we should apply this fix based on consent level
                let should_apply = match consent_level {
                    FixConsentLevel::Auto => result.auto_fixable && is_auto_safe(fix),
                    FixConsentLevel::SemiAuto => result.auto_fixable,
                    FixConsentLevel::Manual => false, // Never auto-apply in manual mode
                };

                if should_apply {
                    issues.push((result.check_name.clone(), fix.clone()));
                }
            }
        }

        issues
    }

    /// Run server diagnostics via SSH
    async fn run_server_diagnostics_via_ssh(&self) -> Result<DiagnosticReport> {
        let ssh_config = self
            .ssh_config
            .as_ref()
            .context("SSH config not available")?;

        let ssh_client = SshClientImpl::connect(ssh_config)
            .await
            .context("Failed to connect to server via SSH")?;

        // Try to run diagnostic binary on server
        let output = ssh_client
            .run_command("/opt/vpr/bin/vpn-server --diagnose --json")
            .context("Failed to execute server diagnostics")?;

        if !output.success {
            // If dedicated diagnostic command doesn't exist, create minimal report
            tracing::warn!("Server diagnostic binary not found, creating minimal report");
            return Ok(create_minimal_server_report());
        }

        // Parse JSON output
        let report: DiagnosticReport = serde_json::from_str(&output.stdout)
            .context("Failed to parse server diagnostic output")?;

        Ok(report)
    }
}

/// Check if a fix is safe for fully automatic application
fn is_auto_safe(fix: &super::Fix) -> bool {
    matches!(
        fix,
        super::Fix::FlushDns
            | super::Fix::LoadTunModule
            | super::Fix::CleanOrphanedState
    )
}

/// Create minimal server report when SSH diagnostics not available
fn create_minimal_server_report() -> DiagnosticReport {
    use super::{HealthStatus, Severity, Side};

    DiagnosticReport {
        timestamp: std::time::SystemTime::now(),
        side: Side::Server,
        results: vec![DiagnosticResult {
            check_name: "Server Reachable".to_string(),
            passed: true,
            severity: Severity::Info,
            message: "Server is reachable via SSH (limited diagnostics)".to_string(),
            fix: None,
            auto_fixable: false,
        }],
        overall_status: HealthStatus::Healthy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_auto_safe() {
        assert!(is_auto_safe(&super::super::Fix::FlushDns));
        assert!(is_auto_safe(&super::super::Fix::LoadTunModule));
        assert!(!is_auto_safe(&super::super::Fix::OpenFirewallPort {
            port: 443,
            protocol: super::super::Protocol::Udp,
        }));
    }

    #[tokio::test]
    async fn test_diagnostic_engine_creation() {
        let config = DiagnosticConfig::default();
        let engine = DiagnosticEngine::new(config, None);

        // Should be able to run client diagnostics without SSH
        let context = engine.run_full_diagnostics().await.unwrap();
        assert!(context.client_report.is_some());
        assert!(context.server_report.is_none());
    }
}
