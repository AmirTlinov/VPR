//! Unit tests for diagnostic system

#[cfg(test)]
mod client_tests {
    use crate::diagnostics::{client, DiagnosticConfig, HealthStatus, Severity};

    #[tokio::test]
    async fn test_client_diagnostics_basic() {
        let config = DiagnosticConfig {
            auto_fix: false,
            timeout_secs: 5,
            server_addr: None,
            privileged: false,
        };

        let report = client::run_diagnostics(&config).await;
        assert!(report.is_ok(), "Client diagnostics should not fail");

        let report = report.unwrap();
        assert!(!report.results.is_empty(), "Should have diagnostic results");

        // Should have at least noise keys, CA cert, and DNS checks
        assert!(
            report.results.len() >= 3,
            "Should have at least 3 basic checks"
        );
    }

    #[tokio::test]
    async fn test_client_dns_check() {
        let config = DiagnosticConfig {
            auto_fix: false,
            timeout_secs: 5,
            server_addr: None,
            privileged: false,
        };

        let report = client::run_diagnostics(&config).await.unwrap();

        let dns_check = report
            .results
            .iter()
            .find(|r| r.check_name == "DNS Resolution");

        assert!(dns_check.is_some(), "Should have DNS resolution check");

        let dns_check = dns_check.unwrap();
        // DNS should work in test environment
        assert!(
            dns_check.passed || dns_check.severity != Severity::Critical,
            "DNS check should either pass or be non-critical"
        );
    }

    #[tokio::test]
    async fn test_health_status_determination() {
        let config = DiagnosticConfig {
            auto_fix: false,
            timeout_secs: 5,
            server_addr: None,
            privileged: false,
        };

        let report = client::run_diagnostics(&config).await.unwrap();

        // Overall status should be one of the valid variants
        assert!(
            matches!(
                report.overall_status,
                HealthStatus::Healthy
                    | HealthStatus::Degraded
                    | HealthStatus::Unhealthy
                    | HealthStatus::Critical
            ),
            "Overall status should be valid"
        );
    }
}

#[cfg(test)]
mod cross_checks_tests {
    use crate::diagnostics::{cross_checks, DiagnosticReport, HealthStatus, Side};
    use std::time::SystemTime;

    #[tokio::test]
    async fn test_cross_checks_empty_reports() {
        let client_report = DiagnosticReport {
            timestamp: SystemTime::now(),
            side: Side::Client,
            results: vec![],
            overall_status: HealthStatus::Healthy,
        };

        let server_report = DiagnosticReport {
            timestamp: SystemTime::now(),
            side: Side::Server,
            results: vec![],
            overall_status: HealthStatus::Healthy,
        };

        let checks = cross_checks::run_cross_checks(&client_report, &server_report).await;
        assert!(checks.is_ok(), "Cross-checks should not fail on empty reports");
    }

    #[tokio::test]
    async fn test_time_skew_detection() {
        use std::time::Duration;

        let client_report = DiagnosticReport {
            timestamp: SystemTime::now(),
            side: Side::Client,
            results: vec![],
            overall_status: HealthStatus::Healthy,
        };

        // Server report 10 seconds in the future
        let server_report = DiagnosticReport {
            timestamp: SystemTime::now() + Duration::from_secs(10),
            side: Side::Server,
            results: vec![],
            overall_status: HealthStatus::Healthy,
        };

        let checks = cross_checks::run_cross_checks(&client_report, &server_report)
            .await
            .unwrap();

        // Should detect time skew
        let time_check = checks.iter().find(|c| c.check_name.contains("Time"));
        assert!(time_check.is_some(), "Should have time skew check");
    }
}

#[cfg(test)]
mod engine_tests {
    use crate::diagnostics::{engine::DiagnosticEngine, DiagnosticConfig};

    #[tokio::test]
    async fn test_engine_creation() {
        let config = DiagnosticConfig {
            auto_fix: false,
            timeout_secs: 5,
            server_addr: None,
            privileged: false,
        };

        let engine = DiagnosticEngine::new(config, None);

        // Should be able to run diagnostics without SSH
        let context = engine.run_full_diagnostics().await;
        assert!(context.is_ok(), "Engine diagnostics should not fail");

        let context = context.unwrap();
        assert!(
            context.client_report.is_some(),
            "Should have client report"
        );
        assert!(
            context.server_report.is_none(),
            "Should not have server report without SSH"
        );
    }

    #[tokio::test]
    async fn test_engine_auto_fix_integration() {
        use crate::diagnostics::FixConsentLevel;

        let config = DiagnosticConfig {
            auto_fix: false,
            timeout_secs: 5,
            server_addr: None,
            privileged: false,
        };

        let engine = DiagnosticEngine::new(config, None);
        let context = engine.run_full_diagnostics().await.unwrap();

        // Test auto-fix with Manual consent (should not apply any fixes)
        let result = engine
            .apply_auto_fixes(&context, FixConsentLevel::Manual)
            .await;

        assert!(result.is_ok(), "Auto-fix should not fail");
        let fixes = result.unwrap();
        assert_eq!(
            fixes.len(),
            0,
            "Manual consent should not apply any fixes"
        );
    }
}

#[cfg(test)]
mod fixes_tests {
    use crate::diagnostics::{
        fixes::{FixExecutor, FixResult},
        Fix, Protocol,
    };

    #[tokio::test]
    async fn test_executor_creation() {
        let mut executor = FixExecutor::new(None);

        // Should create executor without SSH client
        // We can't test dry_run directly as it's private, but we can test behavior
        let fix = Fix::FlushDns;
        let result = executor.apply_fix(&fix).await;
        assert!(result.is_ok(), "Executor should be created successfully");
    }

    #[tokio::test]
    async fn test_dry_run_mode() {
        let mut executor = FixExecutor::new(None);
        executor.set_dry_run(true);

        // All fixes should be skipped in dry-run
        let fix = Fix::FlushDns;
        let result = executor.apply_fix(&fix).await;

        assert!(result.is_ok(), "Dry-run should not fail");
        assert!(
            matches!(result.unwrap(), FixResult::Skipped(_)),
            "Dry-run should skip fixes"
        );
    }

    #[tokio::test]
    async fn test_flush_dns_fix() {
        let mut executor = FixExecutor::new(None);

        let fix = Fix::FlushDns;
        let result = executor.apply_fix(&fix).await;

        // Should either succeed or fail gracefully
        assert!(result.is_ok(), "FlushDns should not panic");
    }

    #[tokio::test]
    async fn test_rollback_empty_stack() {
        let mut executor = FixExecutor::new(None);

        // Rollback with empty stack should not fail
        let result = executor.rollback_all().await;
        assert!(result.is_ok(), "Rollback empty stack should not fail");
    }

    #[tokio::test]
    async fn test_open_firewall_port_validation() {
        let mut executor = FixExecutor::new(None);
        executor.set_dry_run(true); // Don't actually modify firewall

        let fix = Fix::OpenFirewallPort {
            port: 443,
            protocol: Protocol::Udp,
        };

        let result = executor.apply_fix(&fix).await;
        assert!(result.is_ok(), "OpenFirewallPort validation should work");
    }
}

#[cfg(test)]
mod context_tests {
    use crate::diagnostics::{
        DiagnosticContext, DiagnosticReport, DiagnosticResult, Fix, HealthStatus,
        Severity, Side,
    };
    use std::time::SystemTime;

    #[test]
    fn test_context_all_failures() {
        let client_report = DiagnosticReport {
            timestamp: SystemTime::now(),
            side: Side::Client,
            results: vec![
                DiagnosticResult {
                    check_name: "Pass".to_string(),
                    passed: true,
                    severity: Severity::Info,
                    message: "OK".to_string(),
                    fix: None,
                    auto_fixable: false,
                },
                DiagnosticResult {
                    check_name: "Fail".to_string(),
                    passed: false,
                    severity: Severity::Error,
                    message: "Error".to_string(),
                    fix: Some(Fix::FlushDns),
                    auto_fixable: true,
                },
            ],
            overall_status: HealthStatus::Unhealthy,
        };

        let context = DiagnosticContext {
            client_report: Some(client_report),
            server_report: None,
            cross_checks: vec![],
        };

        let failures: Vec<_> = context.all_failures().into_iter().collect();
        assert_eq!(failures.len(), 1, "Should have 1 failure");
        assert_eq!(failures[0].check_name, "Fail");
    }

    #[test]
    fn test_context_critical_failures() {
        let client_report = DiagnosticReport {
            timestamp: SystemTime::now(),
            side: Side::Client,
            results: vec![
                DiagnosticResult {
                    check_name: "Warning".to_string(),
                    passed: false,
                    severity: Severity::Warning,
                    message: "Warn".to_string(),
                    fix: None,
                    auto_fixable: false,
                },
                DiagnosticResult {
                    check_name: "Critical".to_string(),
                    passed: false,
                    severity: Severity::Critical,
                    message: "Critical".to_string(),
                    fix: None,
                    auto_fixable: false,
                },
            ],
            overall_status: HealthStatus::Critical,
        };

        let context = DiagnosticContext {
            client_report: Some(client_report),
            server_report: None,
            cross_checks: vec![],
        };

        let critical: Vec<_> = context
            .all_failures()
            .into_iter()
            .filter(|r| r.severity == Severity::Critical)
            .collect();

        assert_eq!(critical.len(), 1, "Should have 1 critical failure");
        assert_eq!(critical[0].check_name, "Critical");
    }

    #[test]
    fn test_context_fixable_count() {
        let client_report = DiagnosticReport {
            timestamp: SystemTime::now(),
            side: Side::Client,
            results: vec![
                DiagnosticResult {
                    check_name: "Fixable1".to_string(),
                    passed: false,
                    severity: Severity::Error,
                    message: "Error".to_string(),
                    fix: Some(Fix::FlushDns),
                    auto_fixable: true,
                },
                DiagnosticResult {
                    check_name: "Fixable2".to_string(),
                    passed: false,
                    severity: Severity::Error,
                    message: "Error".to_string(),
                    fix: Some(Fix::LoadTunModule),
                    auto_fixable: true,
                },
                DiagnosticResult {
                    check_name: "NotFixable".to_string(),
                    passed: false,
                    severity: Severity::Error,
                    message: "Error".to_string(),
                    fix: None,
                    auto_fixable: false,
                },
            ],
            overall_status: HealthStatus::Unhealthy,
        };

        let context = DiagnosticContext {
            client_report: Some(client_report),
            server_report: None,
            cross_checks: vec![],
        };

        let fixable: Vec<_> = context
            .all_failures()
            .into_iter()
            .filter(|r| r.fix.is_some())
            .collect();

        assert_eq!(fixable.len(), 2, "Should have 2 fixable failures");
    }
}
