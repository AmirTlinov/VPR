//! VPS Server Deployment Module
//!
//! Handles automatic deployment of VPN server to remote VPS via SSH.
//! Provides progress events for GUI feedback.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tokio::process::Command;

/// SSH operation timeout
const SSH_TIMEOUT_SECS: u64 = 120;

/// SCP operation timeout
const SCP_TIMEOUT_SECS: u64 = 300;

/// Remote installation directory on VPS
const REMOTE_DIR: &str = "/opt/vpr";

/// VPN server port
const VPN_PORT: u16 = 443;

/// Deployment progress event payload
#[derive(Debug, Clone, Serialize)]
pub struct DeployProgress {
    pub stage: DeployStage,
    pub message: String,
    pub percent: u8,
    pub error: Option<String>,
}

/// Deployment stages
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeployStage {
    Connecting,
    PreparingServer,
    UploadingBinaries,
    GeneratingKeys,
    ConfiguringFirewall,
    StartingServer,
    DownloadingKeys,
    Completed,
    Failed,
}

/// Server deployment status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStatus {
    pub deployed: bool,
    pub running: bool,
    pub version: Option<String>,
    pub uptime_secs: Option<u64>,
    pub error: Option<String>,
}

/// SSH authentication method
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SshAuth {
    Password { password: String },
    Key { path: String, passphrase: Option<String> },
}

/// VPS configuration stored in app config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpsConfig {
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    #[serde(default = "default_ssh_user")]
    pub ssh_user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key_path: Option<String>,
    #[serde(default)]
    pub deployed: bool,
}

fn default_ssh_port() -> u16 { 22 }
fn default_ssh_user() -> String { "root".into() }

impl Default for VpsConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            ssh_port: default_ssh_port(),
            ssh_user: default_ssh_user(),
            ssh_password: None,
            ssh_key_path: None,
            deployed: false,
        }
    }
}

impl VpsConfig {
    pub fn is_configured(&self) -> bool {
        !self.host.is_empty() && (self.ssh_password.is_some() || self.ssh_key_path.is_some())
    }
}

/// Server deployer - handles SSH operations and binary deployment
pub struct Deployer {
    host: String,
    ssh_port: u16,
    user: String,
    auth: SshAuth,
    app_handle: Option<AppHandle>,
}

impl Deployer {
    pub fn new(config: &VpsConfig) -> Result<Self> {
        if config.host.is_empty() {
            anyhow::bail!("VPS host is required");
        }

        let auth = if let Some(password) = &config.ssh_password {
            SshAuth::Password { password: password.clone() }
        } else if let Some(key_path) = &config.ssh_key_path {
            SshAuth::Key { path: key_path.clone(), passphrase: None }
        } else {
            anyhow::bail!("SSH authentication required (password or key)");
        };

        Ok(Self {
            host: config.host.clone(),
            ssh_port: config.ssh_port,
            user: config.ssh_user.clone(),
            auth,
            app_handle: None,
        })
    }

    pub fn with_app_handle(mut self, handle: AppHandle) -> Self {
        self.app_handle = Some(handle);
        self
    }

    fn emit_progress(&self, stage: DeployStage, message: &str, percent: u8) {
        let progress = DeployProgress {
            stage,
            message: message.to_string(),
            percent,
            error: None,
        };

        tracing::info!(stage = ?stage, message, percent, "Deploy progress");

        if let Some(handle) = &self.app_handle {
            let _ = handle.emit("deploy_progress", progress);
        }
    }

    fn emit_error(&self, stage: DeployStage, error: &str) {
        let progress = DeployProgress {
            stage: DeployStage::Failed,
            message: format!("Failed at {:?}", stage),
            percent: 0,
            error: Some(error.to_string()),
        };

        tracing::error!(stage = ?stage, error, "Deploy failed");

        if let Some(handle) = &self.app_handle {
            let _ = handle.emit("deploy_progress", progress);
        }
    }

    /// Execute SSH command on remote server with timeout
    async fn ssh_exec(&self, cmd: &str) -> Result<String> {
        self.ssh_exec_with_timeout(cmd, Duration::from_secs(SSH_TIMEOUT_SECS)).await
    }

    /// Execute SSH command with custom timeout
    async fn ssh_exec_with_timeout(&self, cmd: &str, timeout: Duration) -> Result<String> {
        let mut command = match &self.auth {
            SshAuth::Password { password } => {
                let mut c = Command::new("sshpass");
                c.env("SSHPASS", password);
                c.args([
                    "-e",
                    "ssh",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "LogLevel=ERROR",
                    "-o", "ConnectTimeout=30",
                    "-p", &self.ssh_port.to_string(),
                    &format!("{}@{}", self.user, self.host),
                    cmd,
                ]);
                c
            }
            SshAuth::Key { path, passphrase } => {
                let mut c = if passphrase.is_some() {
                    let mut c = Command::new("sshpass");
                    c.env("SSHPASS", passphrase.as_deref().unwrap_or(""));
                    c.args(["-e", "-P", "passphrase", "ssh"]);
                    c
                } else {
                    Command::new("ssh")
                };
                c.args([
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "LogLevel=ERROR",
                    "-o", "ConnectTimeout=30",
                    "-i", path,
                    "-p", &self.ssh_port.to_string(),
                    &format!("{}@{}", self.user, self.host),
                    cmd,
                ]);
                c
            }
        };

        command.stdout(Stdio::piped()).stderr(Stdio::piped());

        let output_future = command.output();

        let output = tokio::time::timeout(timeout, output_future)
            .await
            .context("SSH command timed out")?
            .context("SSH command failed")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("SSH command failed: {}", stderr);
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Upload file via SCP
    async fn upload_file(&self, local: &Path, remote: &str) -> Result<()> {
        let local_str = local.to_str().context("Local path must be valid UTF-8")?;

        let mut command = match &self.auth {
            SshAuth::Password { password } => {
                let mut c = Command::new("sshpass");
                c.env("SSHPASS", password);
                c.args([
                    "-e",
                    "scp",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "LogLevel=ERROR",
                    "-P", &self.ssh_port.to_string(),
                    local_str,
                    &format!("{}@{}:{}", self.user, self.host, remote),
                ]);
                c
            }
            SshAuth::Key { path, passphrase: _ } => {
                let mut c = Command::new("scp");
                c.args([
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "LogLevel=ERROR",
                    "-i", path,
                    "-P", &self.ssh_port.to_string(),
                    local_str,
                    &format!("{}@{}:{}", self.user, self.host, remote),
                ]);
                c
            }
        };

        let status = tokio::time::timeout(Duration::from_secs(SCP_TIMEOUT_SECS), command.status())
            .await
            .context("SCP upload timed out")?
            .context("SCP failed")?;

        if !status.success() {
            anyhow::bail!("SCP upload failed");
        }
        Ok(())
    }

    /// Download file via SCP
    async fn download_file(&self, remote: &str, local: &Path) -> Result<()> {
        let local_str = local.to_str().context("Local path must be valid UTF-8")?;

        let mut command = match &self.auth {
            SshAuth::Password { password } => {
                let mut c = Command::new("sshpass");
                c.env("SSHPASS", password);
                c.args([
                    "-e",
                    "scp",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "LogLevel=ERROR",
                    "-P", &self.ssh_port.to_string(),
                    &format!("{}@{}:{}", self.user, self.host, remote),
                    local_str,
                ]);
                c
            }
            SshAuth::Key { path, passphrase: _ } => {
                let mut c = Command::new("scp");
                c.args([
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "LogLevel=ERROR",
                    "-i", path,
                    "-P", &self.ssh_port.to_string(),
                    &format!("{}@{}:{}", self.user, self.host, remote),
                    local_str,
                ]);
                c
            }
        };

        let status = tokio::time::timeout(Duration::from_secs(SCP_TIMEOUT_SECS), command.status())
            .await
            .context("SCP download timed out")?
            .context("SCP failed")?;

        if !status.success() {
            anyhow::bail!("SCP download failed");
        }
        Ok(())
    }

    /// Test SSH connection
    pub async fn test_connection(&self) -> Result<()> {
        tracing::info!(host = %self.host, "Testing SSH connection");
        let output = self.ssh_exec("echo 'OK'").await?;
        if output.trim() != "OK" {
            anyhow::bail!("Unexpected SSH response: {}", output);
        }
        tracing::info!("SSH connection successful");
        Ok(())
    }

    /// Check server status
    pub async fn check_status(&self) -> ServerStatus {
        let running = self.ssh_exec("pgrep -f vpn-server")
            .await
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

        let deployed = self.ssh_exec(&format!("test -f {REMOTE_DIR}/bin/vpn-server && echo yes"))
            .await
            .map(|s| s.trim() == "yes")
            .unwrap_or(false);

        let version = if deployed {
            self.ssh_exec(&format!("{REMOTE_DIR}/bin/vpn-server --version 2>/dev/null || echo unknown"))
                .await
                .ok()
                .map(|s| s.trim().to_string())
        } else {
            None
        };

        ServerStatus {
            deployed,
            running,
            version,
            uptime_secs: None,
            error: None,
        }
    }

    /// Full deployment pipeline
    pub async fn deploy(&self, server_binary: &Path, keygen_binary: &Path, secrets_dir: &Path) -> Result<()> {
        // Stage 1: Connect
        self.emit_progress(DeployStage::Connecting, "Connecting to VPS...", 5);
        if let Err(e) = self.test_connection().await {
            self.emit_error(DeployStage::Connecting, &e.to_string());
            return Err(e);
        }

        // Stage 2: Prepare server directory
        self.emit_progress(DeployStage::PreparingServer, "Creating directories on VPS...", 15);
        if let Err(e) = self.ssh_exec(&format!("mkdir -p {REMOTE_DIR}/{{bin,secrets,logs,config}}")).await {
            self.emit_error(DeployStage::PreparingServer, &e.to_string());
            return Err(e);
        }

        // Stage 3: Upload binaries
        self.emit_progress(DeployStage::UploadingBinaries, "Uploading VPN server binary...", 25);
        if let Err(e) = self.upload_file(server_binary, &format!("{REMOTE_DIR}/bin/vpn-server")).await {
            self.emit_error(DeployStage::UploadingBinaries, &e.to_string());
            return Err(e);
        }

        self.emit_progress(DeployStage::UploadingBinaries, "Uploading keygen binary...", 35);
        if let Err(e) = self.upload_file(keygen_binary, &format!("{REMOTE_DIR}/bin/vpr-keygen")).await {
            self.emit_error(DeployStage::UploadingBinaries, &e.to_string());
            return Err(e);
        }

        // Make binaries executable
        if let Err(e) = self.ssh_exec(&format!("chmod +x {REMOTE_DIR}/bin/*")).await {
            self.emit_error(DeployStage::UploadingBinaries, &e.to_string());
            return Err(e);
        }

        // Stage 4: Generate keys
        self.emit_progress(DeployStage::GeneratingKeys, "Generating cryptographic keys...", 50);

        // Check if Noise keys exist
        let keys_exist = self.ssh_exec(&format!("test -f {REMOTE_DIR}/secrets/server.noise.key && echo yes"))
            .await
            .map(|s| s.trim() == "yes")
            .unwrap_or(false);

        if !keys_exist {
            if let Err(e) = self.ssh_exec(&format!(
                "cd {REMOTE_DIR} && ./bin/vpr-keygen gen-noise-key --name server --output secrets"
            )).await {
                self.emit_error(DeployStage::GeneratingKeys, &e.to_string());
                return Err(e);
            }
        }

        // Check if TLS cert exists
        let cert_exists = self.ssh_exec(&format!("test -f {REMOTE_DIR}/secrets/server.crt && echo yes"))
            .await
            .map(|s| s.trim() == "yes")
            .unwrap_or(false);

        if !cert_exists {
            self.emit_progress(DeployStage::GeneratingKeys, "Generating TLS certificate...", 55);
            let host = &self.host;
            if let Err(e) = self.ssh_exec(&format!(
                "cd {REMOTE_DIR}/secrets && openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
                 -subj '/CN={host}' -addext 'subjectAltName=IP:{host},DNS:{host}' \
                 -keyout server.key -out server.crt"
            )).await {
                self.emit_error(DeployStage::GeneratingKeys, &e.to_string());
                return Err(e);
            }
        }

        // Stage 5: Configure firewall
        self.emit_progress(DeployStage::ConfiguringFirewall, "Configuring firewall...", 65);

        // Enable IP forwarding
        let _ = self.ssh_exec("sysctl -w net.ipv4.ip_forward=1").await;

        // Open VPN port (try both ufw and firewalld)
        let _ = self.ssh_exec(&format!("ufw allow {VPN_PORT}/tcp 2>/dev/null || firewall-cmd --add-port={VPN_PORT}/tcp --permanent 2>/dev/null && firewall-cmd --reload 2>/dev/null || iptables -A INPUT -p tcp --dport {VPN_PORT} -j ACCEPT 2>/dev/null")).await;

        // Stage 6: Start server
        self.emit_progress(DeployStage::StartingServer, "Starting VPN server...", 75);

        // Stop any existing server
        let _ = self.ssh_exec("pkill -9 -f vpn-server 2>/dev/null").await;
        let _ = self.ssh_exec("ip link del vpr-srv 2>/dev/null").await;
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Start server
        if let Err(e) = self.ssh_exec(&format!(
            "cd {REMOTE_DIR} && \
             RUST_LOG=info nohup ./bin/vpn-server \
             --bind 0.0.0.0:{VPN_PORT} \
             --tun-name vpr-srv \
             --tun-addr 10.9.0.1 \
             --pool-start 10.9.0.2 \
             --pool-end 10.9.0.254 \
             --mtu 1400 \
             --noise-dir secrets \
             --noise-name server \
             --cert secrets/server.crt \
             --key secrets/server.key \
             --enable-forwarding \
             --idle-timeout 300 \
             > logs/server.log 2>&1 &"
        )).await {
            self.emit_error(DeployStage::StartingServer, &e.to_string());
            return Err(e);
        }

        // Verify server started
        tokio::time::sleep(Duration::from_secs(3)).await;
        let running = self.ssh_exec("pgrep -f vpn-server")
            .await
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

        if !running {
            let logs = self.ssh_exec(&format!("tail -30 {REMOTE_DIR}/logs/server.log"))
                .await
                .unwrap_or_else(|_| "No logs available".into());
            let err = format!("Server failed to start. Logs:\n{}", logs);
            self.emit_error(DeployStage::StartingServer, &err);
            anyhow::bail!(err);
        }

        // Stage 7: Download keys for client
        self.emit_progress(DeployStage::DownloadingKeys, "Downloading server public key...", 90);

        std::fs::create_dir_all(secrets_dir).context("Failed to create secrets directory")?;

        if let Err(e) = self.download_file(
            &format!("{REMOTE_DIR}/secrets/server.noise.pub"),
            &secrets_dir.join("server.noise.pub")
        ).await {
            self.emit_error(DeployStage::DownloadingKeys, &e.to_string());
            return Err(e);
        }

        // Stage 8: Complete
        self.emit_progress(DeployStage::Completed, "Deployment completed successfully!", 100);

        Ok(())
    }

    /// Stop the VPN server
    pub async fn stop_server(&self) -> Result<()> {
        tracing::info!("Stopping VPN server");
        let _ = self.ssh_exec("pkill -9 -f vpn-server").await;
        let _ = self.ssh_exec("ip link del vpr-srv 2>/dev/null").await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        Ok(())
    }

    /// Start the VPN server (assuming already deployed)
    pub async fn start_server(&self) -> Result<()> {
        // Stop any existing
        let _ = self.stop_server().await;

        // Enable IP forwarding
        let _ = self.ssh_exec("sysctl -w net.ipv4.ip_forward=1").await;

        // Start server
        self.ssh_exec(&format!(
            "cd {REMOTE_DIR} && \
             RUST_LOG=info nohup ./bin/vpn-server \
             --bind 0.0.0.0:{VPN_PORT} \
             --tun-name vpr-srv \
             --tun-addr 10.9.0.1 \
             --pool-start 10.9.0.2 \
             --pool-end 10.9.0.254 \
             --mtu 1400 \
             --noise-dir secrets \
             --noise-name server \
             --cert secrets/server.crt \
             --key secrets/server.key \
             --enable-forwarding \
             --idle-timeout 300 \
             > logs/server.log 2>&1 &"
        )).await?;

        // Verify
        tokio::time::sleep(Duration::from_secs(3)).await;
        let running = self.ssh_exec("pgrep -f vpn-server")
            .await
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

        if !running {
            let logs = self.ssh_exec(&format!("tail -30 {REMOTE_DIR}/logs/server.log"))
                .await
                .unwrap_or_else(|_| "No logs available".into());
            anyhow::bail!("Server failed to start. Logs:\n{}", logs);
        }

        Ok(())
    }

    /// Uninstall server from VPS
    pub async fn uninstall(&self) -> Result<()> {
        tracing::info!("Uninstalling VPN server");

        // Stop server
        let _ = self.stop_server().await;

        // Remove files
        self.ssh_exec(&format!("rm -rf {REMOTE_DIR}")).await?;

        Ok(())
    }

    /// Get server logs
    pub async fn get_logs(&self, lines: u32) -> Result<String> {
        self.ssh_exec(&format!("tail -{lines} {REMOTE_DIR}/logs/server.log 2>/dev/null || echo 'No logs available'"))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vps_config_is_configured_requires_host_and_auth() {
        let mut config = VpsConfig::default();
        assert!(!config.is_configured());

        config.host = "1.2.3.4".into();
        assert!(!config.is_configured());

        config.ssh_password = Some("secret".into());
        assert!(config.is_configured());
    }

    #[test]
    fn vps_config_defaults() {
        let config = VpsConfig::default();
        assert_eq!(config.ssh_port, 22);
        assert_eq!(config.ssh_user, "root");
        assert!(!config.deployed);
    }
}
