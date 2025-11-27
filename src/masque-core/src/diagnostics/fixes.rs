//! Auto-fix engine with rollback support
//!
//! Security: All command execution is hardened against injection attacks.
//! - No `sh -c` shell execution with user input
//! - All values validated through typed wrappers
//! - Whitelist approach for services and modules

use super::{Fix, FirewallAction, Protocol, RollbackOperation, SyncDirection, ValidatedModuleName};
use anyhow::{bail, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Result of applying a fix
#[derive(Debug, Clone)]
pub enum FixResult {
    /// Fix applied successfully
    Success(String),
    /// Fix failed with error message
    Failed(String),
    /// Fix was skipped (e.g., already applied, not applicable)
    Skipped(String),
}

/// SSH client interface (will be implemented in ssh_client.rs)
pub trait SshClient: Send + Sync {
    fn run_command(&self, cmd: &str) -> Result<CommandOutput>;
    fn upload_file(&self, local: &Path, remote: &str) -> Result<()>;
    fn download_file(&self, remote: &str) -> Result<Vec<u8>>;
    fn download_file_to(&self, remote: &str, local: &Path) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
}

impl From<std::process::Output> for CommandOutput {
    fn from(output: std::process::Output) -> Self {
        Self {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            success: output.status.success(),
        }
    }
}

/// Fix executor with rollback support
pub struct FixExecutor {
    rollback_stack: Vec<RollbackOperation>,
    ssh_client: Option<Box<dyn SshClient>>,
    dry_run: bool,
}

impl FixExecutor {
    /// Create new fix executor
    pub fn new(ssh_client: Option<Box<dyn SshClient>>) -> Self {
        Self {
            rollback_stack: Vec::new(),
            ssh_client,
            dry_run: false,
        }
    }

    /// Enable dry-run mode (don't actually execute, just log)
    pub fn set_dry_run(&mut self, dry_run: bool) {
        self.dry_run = dry_run;
    }

    /// Apply a fix (security-hardened, no arbitrary command execution)
    pub async fn apply_fix(&mut self, fix: &Fix) -> Result<FixResult> {
        if self.dry_run {
            return Ok(FixResult::Skipped(format!(
                "[DRY RUN] Would apply: {:?}",
                fix
            )));
        }

        match fix {
            Fix::FlushDns => self.flush_dns().await,
            Fix::LoadTunModule => self.load_tun_module().await,
            Fix::OpenFirewallPort { port, protocol } => {
                self.open_firewall_port(*port, *protocol).await
            }
            Fix::SyncNoiseKeys { direction } => self.sync_noise_keys(direction).await,
            Fix::DownloadCaCert { server } => self.download_ca_cert(server.as_str()).await,
            Fix::UploadClientKey { server } => self.upload_client_key(server.as_str()).await,
            Fix::CleanOrphanedState => self.clean_orphaned_state().await,
            Fix::FixKillSwitch => self.fix_killswitch().await,
            Fix::RepairNetwork => self.repair_network().await,
            Fix::RestartVpnService => self.restart_vpn_service().await,
            Fix::RegenerateCertificate { cn, san } => {
                self.regenerate_certificate(cn.as_str(), san).await
            }
            // ManualInstruction: Display-only, never executes commands (security)
            Fix::ManualInstruction { instruction, description } => {
                Ok(FixResult::Skipped(format!(
                    "[MANUAL FIX REQUIRED] {}: Run manually: {}",
                    description, instruction
                )))
            }
            // NOTE: Fix::RunCommand REMOVED - was a critical security vulnerability
            // All fixes must use typed, validated operations
        }
    }

    /// Rollback all applied fixes in reverse order
    pub async fn rollback_all(&mut self) -> Result<()> {
        tracing::info!("Rolling back {} operations", self.rollback_stack.len());

        while let Some(op) = self.rollback_stack.pop() {
            if let Err(e) = self.execute_rollback(&op).await {
                tracing::error!("Rollback operation failed: {}", e);
                // Continue with other rollbacks even if one fails
            }
        }

        Ok(())
    }

    /// Execute rollback operation (security-hardened, no shell injection)
    async fn execute_rollback(&self, op: &RollbackOperation) -> Result<()> {
        match op {
            RollbackOperation::RestartService { service } => {
                // Security: Only whitelisted service names via ValidatedServiceName enum
                tracing::info!("Rolling back by restarting service: {}", service.as_str());
                let output = Command::new("systemctl")
                    .arg("restart")
                    .arg(service.as_str()) // Safe: validated enum value
                    .output()?;

                if !output.status.success() {
                    bail!(
                        "Service restart failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                Ok(())
            }
            RollbackOperation::FileRestore { path, content } => {
                tracing::info!("Restoring file: {}", path.display());
                // Security: Path should be validated before creating rollback op
                std::fs::write(path, content)?;
                Ok(())
            }
            RollbackOperation::FirewallRule { rule, action } => {
                tracing::info!("Rolling back firewall rule: {:?}", action);
                // Security: rule should be pre-validated when creating rollback op
                match action {
                    FirewallAction::Add => {
                        Command::new("nft")
                            .arg("delete")
                            .arg("rule")
                            .arg(rule)
                            .status()?;
                    }
                    FirewallAction::Remove => {
                        Command::new("nft")
                            .arg("add")
                            .arg("rule")
                            .arg(rule)
                            .status()?;
                    }
                }
                Ok(())
            }
            RollbackOperation::RemoveFirewallPort { port, protocol } => {
                tracing::info!("Rolling back firewall port: {}/{:?}", port, protocol);
                // Security: port is u16 (validated by type system)
                #[cfg(target_os = "linux")]
                {
                    let proto_str = match protocol {
                        Protocol::Tcp => "tcp",
                        Protocol::Udp => "udp",
                        Protocol::Both => "tcp",
                    };
                    // Use nft with separate arguments (no shell injection possible)
                    Command::new("nft")
                        .args(["delete", "rule", "inet", "filter", "input", proto_str, "dport"])
                        .arg(port.to_string())
                        .arg("accept")
                        .status()?;

                    // For "Both" protocol, also delete UDP rule
                    if matches!(protocol, Protocol::Both) {
                        Command::new("nft")
                            .args(["delete", "rule", "inet", "filter", "input", "udp", "dport"])
                            .arg(port.to_string())
                            .arg("accept")
                            .status()?;
                    }
                }
                Ok(())
            }
            RollbackOperation::UnloadModule { module } => {
                // Security: Only whitelisted module names via ValidatedModuleName enum
                tracing::info!("Unloading kernel module: {}", module.as_str());
                let output = Command::new("modprobe")
                    .arg("-r")
                    .arg(module.as_str()) // Safe: validated enum value
                    .output()?;

                if !output.status.success() {
                    tracing::warn!(
                        "Module unload failed (may be in use): {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    // Don't fail - module may be in use
                }
                Ok(())
            }
        }
    }

    async fn flush_dns(&mut self) -> Result<FixResult> {
        if self.dry_run {
            return Ok(FixResult::Skipped("[DRY RUN] Would flush DNS cache".to_string()));
        }

        #[cfg(target_os = "linux")]
        {
            // Try systemd-resolved first
            let output = Command::new("systemctl")
                .args(["restart", "systemd-resolved"])
                .output()?;

            if output.status.success() {
                return Ok(FixResult::Success("DNS cache flushed (systemd-resolved)".to_string()));
            }

            // Fallback: try nscd
            let output = Command::new("systemctl")
                .args(["restart", "nscd"])
                .output()?;

            if output.status.success() {
                return Ok(FixResult::Success("DNS cache flushed (nscd)".to_string()));
            }

            Ok(FixResult::Failed(
                "Failed to flush DNS: no systemd-resolved or nscd found".to_string(),
            ))
        }

        #[cfg(target_os = "macos")]
        {
            Command::new("dscacheutil").arg("-flushcache").status()?;
            Command::new("killall")
                .args(["-HUP", "mDNSResponder"])
                .status()?;
            Ok(FixResult::Success("DNS cache flushed".to_string()))
        }

        #[cfg(target_os = "windows")]
        {
            let output = Command::new("ipconfig").arg("/flushdns").output()?;
            if output.status.success() {
                Ok(FixResult::Success("DNS cache flushed".to_string()))
            } else {
                Ok(FixResult::Failed(format!(
                    "Failed to flush DNS: {}",
                    String::from_utf8_lossy(&output.stderr)
                )))
            }
        }
    }

    async fn load_tun_module(&mut self) -> Result<FixResult> {
        #[cfg(target_os = "linux")]
        {
            // Check if already loaded
            let output = Command::new("lsmod").output()?;
            let stdout = String::from_utf8_lossy(&output.stdout);

            if stdout.contains("tun") {
                return Ok(FixResult::Skipped("TUN module already loaded".to_string()));
            }

            // Load module
            let output = Command::new("modprobe").arg("tun").output()?;

            if output.status.success() {
                // Add rollback to unload module (security: using validated enum)
                self.rollback_stack.push(RollbackOperation::UnloadModule {
                    module: ValidatedModuleName::Tun,
                });

                Ok(FixResult::Success("TUN module loaded".to_string()))
            } else {
                Ok(FixResult::Failed(format!(
                    "Failed to load TUN module: {}",
                    String::from_utf8_lossy(&output.stderr)
                )))
            }
        }

        #[cfg(not(target_os = "linux"))]
        Ok(FixResult::Skipped(
            "TUN module loading not needed on this platform".to_string(),
        ))
    }

    async fn open_firewall_port(&mut self, port: u16, protocol: Protocol) -> Result<FixResult> {
        #[cfg(target_os = "linux")]
        {
            let proto_str = match protocol {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
                Protocol::Both => "tcp,udp",
            };

            // Try UFW first
            let ufw_check = Command::new("which").arg("ufw").output();
            if let Ok(output) = ufw_check {
                if output.status.success() {
                    let output = Command::new("ufw")
                        .args(["allow", &format!("{}/{}", port, proto_str)])
                        .output()?;

                    if output.status.success() {
                        // Add rollback (security: using typed operation)
                        self.rollback_stack.push(RollbackOperation::RemoveFirewallPort {
                            port,
                            protocol,
                        });

                        return Ok(FixResult::Success(format!(
                            "Opened {}/{} port via UFW",
                            port, proto_str
                        )));
                    }
                }
            }

            // Fallback: nftables
            let rule = format!(
                "inet filter input {} dport {} accept",
                proto_str, port
            );
            let output = Command::new("nft")
                .args(["add", "rule"])
                .arg(&rule)
                .output()?;

            if output.status.success() {
                self.rollback_stack.push(RollbackOperation::FirewallRule {
                    rule: rule.clone(),
                    action: FirewallAction::Add,
                });

                Ok(FixResult::Success(format!(
                    "Opened {}/{} port via nftables",
                    port, proto_str
                )))
            } else {
                Ok(FixResult::Failed(format!(
                    "Failed to open firewall port: {}",
                    String::from_utf8_lossy(&output.stderr)
                )))
            }
        }

        #[cfg(not(target_os = "linux"))]
        Ok(FixResult::Skipped(
            "Firewall port opening not implemented for this platform".to_string(),
        ))
    }

    async fn sync_noise_keys(&mut self, direction: &SyncDirection) -> Result<FixResult> {
        let ssh = match &self.ssh_client {
            Some(client) => client,
            None => {
                return Ok(FixResult::Failed(
                    "SSH connection not available for key sync".to_string(),
                ))
            }
        };

        match direction {
            SyncDirection::ClientToServer => {
                let local_key = PathBuf::from("secrets/client.noise.pub");
                let remote_path = "/opt/vpr/secrets/client.noise.pub";

                if !local_key.exists() {
                    return Ok(FixResult::Failed(
                        "Local client.noise.pub not found".to_string(),
                    ));
                }

                // Backup existing server key for rollback
                match ssh.download_file(remote_path) {
                    Ok(backup) => {
                        self.rollback_stack.push(RollbackOperation::FileRestore {
                            path: PathBuf::from(remote_path),
                            content: backup,
                        });
                    }
                    Err(_) => {
                        tracing::warn!("No existing server-side key to backup");
                    }
                }

                // Upload new key
                ssh.upload_file(&local_key, remote_path)?;

                Ok(FixResult::Success(
                    "Client public key synced to server".to_string(),
                ))
            }
            SyncDirection::ServerToClient => {
                let remote_path = "/opt/vpr/secrets/server.noise.pub";
                let local_key = PathBuf::from("secrets/server.noise.pub");

                // Backup existing local key
                if local_key.exists() {
                    let backup = std::fs::read(&local_key)?;
                    self.rollback_stack.push(RollbackOperation::FileRestore {
                        path: local_key.clone(),
                        content: backup,
                    });
                }

                // Download server key
                ssh.download_file_to(remote_path, &local_key)?;

                Ok(FixResult::Success(
                    "Server public key synced to client".to_string(),
                ))
            }
        }
    }

    async fn download_ca_cert(&mut self, server: &str) -> Result<FixResult> {
        let ssh = match &self.ssh_client {
            Some(client) => client,
            None => {
                return Ok(FixResult::Failed(
                    "SSH connection not available".to_string(),
                ))
            }
        };

        let remote_path = "/opt/vpr/secrets/server.crt";
        let local_path = PathBuf::from("secrets/server.crt");

        // Backup existing cert if present
        if local_path.exists() {
            let backup = std::fs::read(&local_path)?;
            self.rollback_stack.push(RollbackOperation::FileRestore {
                path: local_path.clone(),
                content: backup,
            });
        }

        // Download certificate
        ssh.download_file_to(remote_path, &local_path)?;

        Ok(FixResult::Success(format!(
            "CA certificate downloaded from {}",
            server
        )))
    }

    async fn upload_client_key(&mut self, _server: &str) -> Result<FixResult> {
        // This is essentially the same as ClientToServer sync
        self.sync_noise_keys(&SyncDirection::ClientToServer).await
    }

    async fn clean_orphaned_state(&mut self) -> Result<FixResult> {
        #[cfg(target_os = "linux")]
        {
            let mut cleaned = Vec::new();

            // Check for orphaned nftables rules
            let output = Command::new("nft")
                .args(["list", "tables"])
                .output()?;

            let tables = String::from_utf8_lossy(&output.stdout);

            if tables.contains("vpr_killswitch") {
                // Check if VPN process is actually running
                let vpn_running = Command::new("pgrep")
                    .arg("vpn-client")
                    .output()?
                    .status
                    .success();

                if !vpn_running {
                    // VPN not running but kill switch table exists - orphaned!
                    tracing::info!("Removing orphaned vpr_killswitch table");

                    let output = Command::new("nft")
                        .args(["delete", "table", "inet", "vpr_killswitch"])
                        .output()?;

                    if output.status.success() {
                        cleaned.push("Removed orphaned kill switch table");
                    }
                }
            }

            // Check for orphaned TUN devices
            let output = Command::new("ip")
                .args(["link", "show"])
                .output()?;

            let links = String::from_utf8_lossy(&output.stdout);
            for line in links.lines() {
                if line.contains("vpr") && line.contains("tun") {
                    // Extract interface name
                    if let Some(name) = line.split(':').nth(1) {
                        let name = name.trim();
                        tracing::info!("Removing orphaned TUN interface: {}", name);

                        Command::new("ip")
                            .args(["link", "delete", name])
                            .output()?;

                        cleaned.push("Removed orphaned TUN device");
                    }
                }
            }

            if cleaned.is_empty() {
                Ok(FixResult::Skipped("No orphaned state found".to_string()))
            } else {
                Ok(FixResult::Success(format!(
                    "Cleaned orphaned state: {}",
                    cleaned.join(", ")
                )))
            }
        }

        #[cfg(not(target_os = "linux"))]
        Ok(FixResult::Skipped(
            "Orphaned state cleanup not implemented for this platform".to_string(),
        ))
    }

    async fn fix_killswitch(&mut self) -> Result<FixResult> {
        // This would require access to killswitch module
        // For now, just suggest cleanup
        Ok(FixResult::Skipped(
            "Kill switch fix requires manual intervention".to_string(),
        ))
    }

    async fn repair_network(&mut self) -> Result<FixResult> {
        #[cfg(target_os = "linux")]
        {
            let mut repaired = Vec::new();

            // Restart NetworkManager
            let output = Command::new("systemctl")
                .args(["restart", "NetworkManager"])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    repaired.push("Restarted NetworkManager");
                }
            }

            if repaired.is_empty() {
                Ok(FixResult::Failed("Network repair failed".to_string()))
            } else {
                Ok(FixResult::Success(format!(
                    "Network repaired: {}",
                    repaired.join(", ")
                )))
            }
        }

        #[cfg(not(target_os = "linux"))]
        Ok(FixResult::Skipped(
            "Network repair not implemented for this platform".to_string(),
        ))
    }

    async fn restart_vpn_service(&mut self) -> Result<FixResult> {
        // This would require integration with service management
        Ok(FixResult::Skipped(
            "VPN service restart not implemented yet".to_string(),
        ))
    }

    async fn regenerate_certificate(&mut self, cn: &str, san: &[String]) -> Result<FixResult> {
        let cert_path = PathBuf::from("secrets/server.crt");
        let key_path = PathBuf::from("secrets/server.key");

        // Backup existing certificates
        if cert_path.exists() {
            let backup = std::fs::read(&cert_path)?;
            self.rollback_stack.push(RollbackOperation::FileRestore {
                path: cert_path.clone(),
                content: backup,
            });
        }

        if key_path.exists() {
            let backup = std::fs::read(&key_path)?;
            self.rollback_stack.push(RollbackOperation::FileRestore {
                path: key_path.clone(),
                content: backup,
            });
        }

        // Generate new certificate using openssl
        let san_str = san.join(",");
        let output = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_path.to_str().unwrap(),
                "-out",
                cert_path.to_str().unwrap(),
                "-days",
                "365",
                "-nodes",
                "-subj",
                &format!("/CN={}", cn),
                "-addext",
                &format!("subjectAltName={}", san_str),
            ])
            .output()?;

        if output.status.success() {
            Ok(FixResult::Success(format!(
                "Generated new certificate for {}",
                cn
            )))
        } else {
            Ok(FixResult::Failed(format!(
                "Certificate generation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    // NOTE: run_custom_command REMOVED - was a critical security vulnerability (CVE: command injection)
    // All fixes must use typed, validated operations with no shell string execution.
    // See: SECURITY_AUDIT_REPORT.md VPR-SEC-001
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rollback_mechanism() {
        let mut executor = FixExecutor::new(None);
        executor.set_dry_run(true);

        // Simulate fix application with safe typed rollback operation
        executor.rollback_stack.push(RollbackOperation::UnloadModule {
            module: ValidatedModuleName::Tun,
        });

        // Rollback should clear stack
        executor.rollback_all().await.unwrap();
        assert_eq!(executor.rollback_stack.len(), 0);
    }

    #[tokio::test]
    async fn test_dry_run_mode() {
        let mut executor = FixExecutor::new(None);
        executor.set_dry_run(true);

        let result = executor.flush_dns().await.unwrap();

        match result {
            FixResult::Skipped(msg) => {
                assert!(msg.contains("[DRY RUN]"));
            }
            _ => panic!("Expected Skipped result in dry-run mode"),
        }
    }

    #[test]
    fn test_validated_hostname() {
        // Valid hostnames
        assert!(super::super::ValidatedHostname::new("example.com").is_ok());
        assert!(super::super::ValidatedHostname::new("192.168.1.1").is_ok());
        assert!(super::super::ValidatedHostname::new("my-server").is_ok());

        // Invalid hostnames (command injection attempts)
        assert!(super::super::ValidatedHostname::new("example.com; rm -rf /").is_err());
        assert!(super::super::ValidatedHostname::new("$(whoami)").is_err());
        assert!(super::super::ValidatedHostname::new("`ls`").is_err());
        assert!(super::super::ValidatedHostname::new("../etc/passwd").is_err());
        assert!(super::super::ValidatedHostname::new("-oOption").is_err());
    }
}
