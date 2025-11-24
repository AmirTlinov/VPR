//! Test report generation

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Individual test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub duration_ms: u64,
    pub details: Option<String>,
    pub metrics: Option<serde_json::Value>,
    pub error: Option<String>,
}

/// Complete E2E test report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eReport {
    pub timestamp: DateTime<Utc>,
    pub server_host: String,
    pub server_port: u16,
    pub tls_profile: String,
    pub total_duration_ms: u64,
    pub tests_passed: usize,
    pub tests_failed: usize,
    pub tests: Vec<TestResult>,
    pub server_logs: Option<String>,
    pub client_logs: Option<String>,
}

impl E2eReport {
    pub fn new(server_host: String, server_port: u16, tls_profile: String) -> Self {
        Self {
            timestamp: Utc::now(),
            server_host,
            server_port,
            tls_profile,
            total_duration_ms: 0,
            tests_passed: 0,
            tests_failed: 0,
            tests: Vec::new(),
            server_logs: None,
            client_logs: None,
        }
    }

    pub fn add_test(&mut self, result: TestResult) {
        if result.passed {
            self.tests_passed += 1;
        } else {
            self.tests_failed += 1;
        }
        self.total_duration_ms += result.duration_ms;
        self.tests.push(result);
    }

    pub fn all_passed(&self) -> bool {
        self.tests_failed == 0
    }

    /// Save report as JSON
    pub fn save_json(&self, path: &Path) -> anyhow::Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Save report as Markdown
    pub fn save_markdown(&self, path: &Path) -> anyhow::Result<()> {
        let md = self.to_markdown();
        std::fs::write(path, md)?;
        Ok(())
    }

    /// Generate Markdown report
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        md.push_str("# VPR E2E Test Report\n\n");
        md.push_str(&format!(
            "**Date:** {}\n\n",
            self.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        md.push_str(&format!(
            "**Server:** {}:{}\n\n",
            self.server_host, self.server_port
        ));
        md.push_str(&format!("**TLS Profile:** {}\n\n", self.tls_profile));

        // Summary
        let status = if self.all_passed() {
            "ALL TESTS PASSED"
        } else {
            "SOME TESTS FAILED"
        };
        md.push_str(&format!("## Result: {}\n\n", status));

        md.push_str("| Metric | Value |\n");
        md.push_str("|--------|-------|\n");
        md.push_str(&format!("| Tests Passed | {} |\n", self.tests_passed));
        md.push_str(&format!("| Tests Failed | {} |\n", self.tests_failed));
        md.push_str(&format!(
            "| Total Duration | {}ms |\n\n",
            self.total_duration_ms
        ));

        // Test results table
        md.push_str("## Test Results\n\n");
        md.push_str("| Test | Status | Duration | Details |\n");
        md.push_str("|------|--------|----------|--------|\n");

        for test in &self.tests {
            let status = if test.passed { "PASS" } else { "FAIL" };
            let details = test
                .details
                .as_deref()
                .or(test.error.as_deref())
                .unwrap_or("-");
            md.push_str(&format!(
                "| {} | {} | {}ms | {} |\n",
                test.name, status, test.duration_ms, details
            ));
        }

        // Metrics
        md.push_str("\n## Metrics\n\n");
        for test in &self.tests {
            if let Some(metrics) = &test.metrics {
                md.push_str(&format!("### {}\n\n", test.name));
                md.push_str("```json\n");
                md.push_str(&serde_json::to_string_pretty(metrics).unwrap_or_default());
                md.push_str("\n```\n\n");
            }
        }

        // Logs
        if let Some(logs) = &self.server_logs {
            md.push_str("## Server Logs\n\n");
            md.push_str("```\n");
            md.push_str(logs);
            md.push_str("\n```\n\n");
        }

        md
    }

    /// Print summary to console
    pub fn print_summary(&self) {
        use colored::Colorize;

        println!("\n{}", "═".repeat(60).blue());
        println!("{}", " VPR E2E Test Report ".bold().blue());
        println!("{}", "═".repeat(60).blue());

        println!(
            "\nServer: {}:{}",
            self.server_host.cyan(),
            self.server_port.to_string().cyan()
        );
        println!("TLS Profile: {}", self.tls_profile.cyan());
        println!("Duration: {}ms", self.total_duration_ms);

        println!("\n{}", "─".repeat(60));
        println!("{}", " Test Results ".bold());
        println!("{}", "─".repeat(60));

        for test in &self.tests {
            let status = if test.passed {
                "PASS".green()
            } else {
                "FAIL".red()
            };
            let details = test.details.as_deref().unwrap_or("");
            println!("  [{}] {} - {}", status, test.name, details.dimmed());

            if let Some(error) = &test.error {
                println!("       Error: {}", error.red());
            }
        }

        println!("\n{}", "─".repeat(60));

        if self.all_passed() {
            println!(
                "{} {}/{}",
                "ALL TESTS PASSED".green().bold(),
                self.tests_passed,
                self.tests_passed + self.tests_failed
            );
        } else {
            println!(
                "{} Passed: {}, Failed: {}",
                "TESTS FAILED".red().bold(),
                self.tests_passed,
                self.tests_failed
            );
        }

        println!("{}\n", "═".repeat(60).blue());
    }
}
