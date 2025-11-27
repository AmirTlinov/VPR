//! VPN Diagnostics and Auto-Fix System
//!
//! Automatically detects and fixes common VPN issues:
//! - Network connectivity problems
//! - Firewall misconfigurations
//! - Certificate issues
//! - Port availability
//! - DNS problems
//! - Kill switch conflicts

pub mod client;
pub mod server;
pub mod cross_checks;
pub mod fixes;
pub mod ssh_client;
pub mod engine;

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;

/// Diagnostic check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticResult {
    /// Name of the check
    pub check_name: String,
    /// Whether the check passed
    pub passed: bool,
    /// Severity if failed
    pub severity: Severity,
    /// Description of the issue
    pub message: String,
    /// Suggested fix (if any)
    pub fix: Option<Fix>,
    /// Whether auto-fix is available
    pub auto_fixable: bool,
}

/// Severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    /// Informational - not a problem
    Info,
    /// Warning - may cause issues
    Warning,
    /// Error - will prevent connection
    Error,
    /// Critical - system-level issue
    Critical,
}

/// Fix consent levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FixConsentLevel {
    /// No consent needed (DNS flush, TUN load, orphan cleanup)
    Auto,
    /// Ask user first (firewall ports, key sync, cert download)
    SemiAuto,
    /// Display instructions only (routing changes, DNS servers)
    Manual,
}

/// Diagnostic categories for grouping checks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosticCategory {
    /// Network layer (reachability, ports, DNS)
    Network,
    /// Firewall layer (kill switch, port blocking)
    Firewall,
    /// Cryptographic layer (keys, certificates, handshake)
    Cryptographic,
    /// System layer (TUN module, privileges, config)
    System,
    /// Configuration layer (routing, NAT, IP forwarding)
    Configuration,
}

/// Rollback operations for failed fixes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RollbackOperation {
    /// Undo a shell command
    CommandUndo { command: String },
    /// Restore file from backup
    FileRestore { path: PathBuf, content: Vec<u8> },
    /// Restore firewall rule
    FirewallRule { rule: String, action: FirewallAction },
}

/// Firewall actions
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum FirewallAction {
    Add,
    Remove,
}

/// Direction for key synchronization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncDirection {
    /// Upload client key to server
    ClientToServer,
    /// Download server key to client
    ServerToClient,
}

/// Auto-fix actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Fix {
    /// Open firewall port (UFW/iptables)
    OpenFirewallPort { port: u16, protocol: Protocol },
    /// Generate new certificate
    RegenerateCertificate { cn: String, san: Vec<String> },
    /// Adjust kill switch rules
    FixKillSwitch,
    /// Flush DNS cache
    FlushDns,
    /// Repair network configuration
    RepairNetwork,
    /// Custom shell command
    RunCommand { command: String, description: String },

    // New fixes
    /// Synchronize Noise protocol keys
    SyncNoiseKeys { direction: SyncDirection },
    /// Load TUN kernel module
    LoadTunModule,
    /// Clean orphaned VPN state
    CleanOrphanedState,
    /// Download CA certificate from server
    DownloadCaCert { server: String },
    /// Upload client public key to server
    UploadClientKey { server: String },
    /// Restart VPN service
    RestartVpnService,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Both,
}

/// Complete diagnostic report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    /// Timestamp of the report
    pub timestamp: std::time::SystemTime,
    /// Client or server side
    pub side: Side,
    /// All diagnostic results
    pub results: Vec<DiagnosticResult>,
    /// Overall health status
    pub overall_status: HealthStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Side {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Critical,
}

impl DiagnosticReport {
    /// Get all failed checks
    pub fn failures(&self) -> Vec<&DiagnosticResult> {
        self.results.iter().filter(|r| !r.passed).collect()
    }

    /// Get all auto-fixable issues
    pub fn auto_fixable_issues(&self) -> Vec<&DiagnosticResult> {
        self.results
            .iter()
            .filter(|r| !r.passed && r.auto_fixable)
            .collect()
    }

    /// Count by severity
    pub fn count_by_severity(&self, severity: Severity) -> usize {
        self.results
            .iter()
            .filter(|r| !r.passed && r.severity == severity)
            .count()
    }

    /// Check if there are critical issues
    pub fn has_critical_issues(&self) -> bool {
        self.count_by_severity(Severity::Critical) > 0
    }

    /// Check if there are auto-fixable issues
    pub fn has_auto_fixable_issues(&self) -> bool {
        !self.auto_fixable_issues().is_empty()
    }
}

/// Combined diagnostic context from client + server + cross-checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticContext {
    /// Client-side diagnostic report
    pub client_report: Option<DiagnosticReport>,
    /// Server-side diagnostic report (if SSH available)
    pub server_report: Option<DiagnosticReport>,
    /// Cross-checks between client and server
    pub cross_checks: Vec<DiagnosticResult>,
}

impl DiagnosticContext {
    /// Get all failures from all sources
    pub fn all_failures(&self) -> Vec<&DiagnosticResult> {
        let mut failures = Vec::new();

        if let Some(client) = &self.client_report {
            failures.extend(client.failures());
        }

        if let Some(server) = &self.server_report {
            failures.extend(server.failures());
        }

        failures.extend(self.cross_checks.iter().filter(|r| !r.passed));

        failures
    }

    /// Get all auto-fixable issues
    pub fn all_auto_fixable_issues(&self) -> Vec<&DiagnosticResult> {
        self.all_failures()
            .into_iter()
            .filter(|r| r.auto_fixable)
            .collect()
    }

    /// Check if there are critical issues
    pub fn has_critical_issues(&self) -> bool {
        self.all_failures()
            .iter()
            .any(|r| r.severity == Severity::Critical)
    }

    /// Check if there are auto-fixable issues
    pub fn has_auto_fixable_issues(&self) -> bool {
        !self.all_auto_fixable_issues().is_empty()
    }

    /// Get overall health status (worst of all reports)
    pub fn overall_health(&self) -> HealthStatus {
        let mut worst = HealthStatus::Healthy;

        if let Some(client) = &self.client_report {
            if client.overall_status as u8 > worst as u8 {
                worst = client.overall_status;
            }
        }

        if let Some(server) = &self.server_report {
            if server.overall_status as u8 > worst as u8 {
                worst = server.overall_status;
            }
        }

        // Check cross-checks
        let cross_check_health = if self.cross_checks.iter().any(|r| !r.passed && r.severity == Severity::Critical) {
            HealthStatus::Critical
        } else if self.cross_checks.iter().any(|r| !r.passed && r.severity == Severity::Error) {
            HealthStatus::Unhealthy
        } else if self.cross_checks.iter().any(|r| !r.passed && r.severity == Severity::Warning) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        if cross_check_health as u8 > worst as u8 {
            worst = cross_check_health;
        }

        worst
    }
}

/// Diagnostic configuration
#[derive(Debug, Clone)]
pub struct DiagnosticConfig {
    /// Enable auto-fix
    pub auto_fix: bool,
    /// Timeout for each check (seconds)
    pub timeout_secs: u64,
    /// Server address to check (for client-side)
    pub server_addr: Option<(IpAddr, u16)>,
    /// Whether to run privileged checks (requires root)
    pub privileged: bool,
}

impl Default for DiagnosticConfig {
    fn default() -> Self {
        Self {
            auto_fix: false,
            timeout_secs: 10,
            server_addr: None,
            privileged: false,
        }
    }
}
