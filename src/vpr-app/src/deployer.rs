//! VPS Server Deployment Module
//!
//! Handles automatic deployment of VPN server to remote VPS via SSH.
//! Provides progress events for GUI feedback.
//!
//! Security: All operations are type-safe and prevent command injection.
//! - Host, user, paths validated before use
//! - No arbitrary command execution
//! - Only predefined safe operations via SshOperation enum

use anyhow::{bail, Context, Result};
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

/// Remote installation directory on VPS (hardcoded, safe)
const REMOTE_DIR: &str = "/opt/vpr";

/// VPN server port
const VPN_PORT: u16 = 443;

// ==================== SECURITY: Validated Types ====================

/// Validated hostname (prevents command injection)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedHost(String);

impl ValidatedHost {
    /// Create validated hostname (alphanumeric, dots, hyphens, IPv4/IPv6 only)
    pub fn new(host: &str) -> Result<Self, &'static str> {
        if host.is_empty() || host.len() > 253 {
            return Err("Invalid hostname length");
        }

        // Allow: alphanumeric, dots, hyphens, colons (IPv6), brackets (IPv6)
        let valid_chars = host.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':' || c == '[' || c == ']'
        });

        if !valid_chars {
            return Err("Invalid hostname characters");
        }

        // Prevent injection patterns
        if host.contains("..") || host.starts_with('-') || host.starts_with('.') {
            return Err("Invalid hostname format");
        }

        // Prevent shell metacharacters that might slip through
        if host.contains(';') || host.contains('$') || host.contains('`')
            || host.contains('|') || host.contains('&') || host.contains('\'')
            || host.contains('"') || host.contains('\\') || host.contains('\n')
        {
            return Err("Shell metacharacters not allowed in hostname");
        }

        Ok(Self(host.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated SSH username (prevents injection)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedUser(String);

impl ValidatedUser {
    pub fn new(user: &str) -> Result<Self, &'static str> {
        if user.is_empty() || user.len() > 32 {
            return Err("Invalid username length");
        }
        if !user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err("Invalid username characters");
        }
        if user.starts_with('-') {
            return Err("Username cannot start with hyphen");
        }
        Ok(Self(user.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated remote path (prevents path traversal)
#[derive(Debug, Clone)]
pub struct ValidatedRemotePath(String);

impl ValidatedRemotePath {
    pub fn new(path: &str) -> Result<Self, &'static str> {
        if path.is_empty() || path.len() > 4096 {
            return Err("Invalid path length");
        }

        // Must start with our safe remote directory
        if !path.starts_with(REMOTE_DIR) && !path.starts_with("/opt/vpr") {
            return Err("Remote path must be within /opt/vpr");
        }

        // Prevent injection
        if path.contains(';') || path.contains('$') || path.contains('`')
            || path.contains('|') || path.contains('&') || path.contains('\n')
            || path.contains('\r') || path.contains('\0')
        {
            return Err("Shell metacharacters not allowed in path");
        }

        // Prevent path traversal
        if path.contains("..") {
            return Err("Path traversal not allowed");
        }

        Ok(Self(path.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ==================== SSH Operations (Whitelist Approach) ====================

/// Predefined safe SSH operations (no arbitrary command execution)
#[derive(Debug, Clone)]
pub enum SshOperation {
    /// Echo test for connection verification
    TestConnection,
    /// Create directory structure
    CreateDirectories,
    /// Make binaries executable
    MakeBinariesExecutable,
    /// Check if file exists
    FileExists { path: ValidatedRemotePath },
    /// Generate Noise keys
    GenerateNoiseKeys,
    /// Generate TLS certificate (host is validated)
    GenerateTlsCert { host: ValidatedHost },
    /// Enable IP forwarding
    EnableIpForwarding,
    /// Open firewall port (hardcoded VPN_PORT)
    OpenFirewallPort,
    /// Stop VPN server
    StopServer,
    /// Delete TUN interface
    DeleteTunInterface,
    /// Start VPN server with safe config
    StartServer,
    /// Check if server is running
    CheckServerRunning,
    /// Get server logs
    GetLogs { lines: u32 },
    /// Remove installation directory
    Uninstall,
}

impl SshOperation {
    /// Convert operation to safe command string
    /// Security: All commands are hardcoded templates, user input is validated
    fn to_command(&self) -> String {
        match self {
            SshOperation::TestConnection => "echo 'OK'".to_string(),

            SshOperation::CreateDirectories => {
                format!("mkdir -p {REMOTE_DIR}/{{bin,secrets,logs,config}}")
            }

            SshOperation::MakeBinariesExecutable => {
                format!("chmod +x {REMOTE_DIR}/bin/*")
            }

            SshOperation::FileExists { path } => {
                // Path is validated to be within REMOTE_DIR
                format!("test -f '{}' && echo yes", path.as_str().replace('\'', "'\"'\"'"))
            }

            SshOperation::GenerateNoiseKeys => {
                format!("cd {REMOTE_DIR} && ./bin/vpr-keygen gen-noise-key --name server --output secrets")
            }

            SshOperation::GenerateTlsCert { host } => {
                // Host is validated, safe to use
                // Using single quotes and escaping for safety
                let safe_host = host.as_str().replace('\'', "'\"'\"'");
                format!(
                    "cd {REMOTE_DIR}/secrets && openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
                     -subj '/CN={}' -addext 'subjectAltName=IP:{},DNS:{}' \
                     -keyout server.key -out server.crt",
                    safe_host, safe_host, safe_host
                )
            }

            SshOperation::EnableIpForwarding => {
                "sysctl -w net.ipv4.ip_forward=1".to_string()
            }

            SshOperation::OpenFirewallPort => {
                // VPN_PORT is hardcoded constant, safe
                format!(
                    "ufw allow {VPN_PORT}/tcp 2>/dev/null || \
                     firewall-cmd --add-port={VPN_PORT}/tcp --permanent 2>/dev/null && \
                     firewall-cmd --reload 2>/dev/null || \
                     iptables -A INPUT -p tcp --dport {VPN_PORT} -j ACCEPT 2>/dev/null"
                )
            }

            SshOperation::StopServer => {
                "pkill -9 -f vpn-server 2>/dev/null || true".to_string()
            }

            SshOperation::DeleteTunInterface => {
                "ip link del vpr-srv 2>/dev/null || true".to_string()
            }

            SshOperation::StartServer => {
                // All parameters are hardcoded constants, safe
                format!(
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
                )
            }

            SshOperation::CheckServerRunning => {
                "pgrep -f vpn-server".to_string()
            }

            SshOperation::GetLogs { lines } => {
                // lines is u32, safe to interpolate
                format!("tail -{lines} {REMOTE_DIR}/logs/server.log 2>/dev/null || echo 'No logs available'")
            }

            SshOperation::Uninstall => {
                format!("rm -rf {REMOTE_DIR}")
            }
        }
    }
}

// ==================== Types ====================

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
#[derive(Debug, Clone)]
pub enum SshAuth {
    /// SSH key authentication (secure, recommended)
    Key { path: String },
    /// Use ssh-agent (secure)
    Agent,
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
    #[deprecated(note = "Password auth is insecure, use SSH key instead")]
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
        #[allow(deprecated)]
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
    #[allow(deprecated)]
    pub fn is_configured(&self) -> bool {
        // Only accept SSH key auth now
        !self.host.is_empty() && self.ssh_key_path.is_some()
    }
}

/// Server deployer - handles SSH operations and binary deployment
pub struct Deployer {
    host: ValidatedHost,
    ssh_port: u16,
    user: ValidatedUser,
    auth: SshAuth,
    app_handle: Option<AppHandle>,
}

impl Deployer {
    #[allow(deprecated)]
    pub fn new(config: &VpsConfig) -> Result<Self> {
        if config.host.is_empty() {
            bail!("VPS host is required");
        }

        // Validate host
        let host = ValidatedHost::new(&config.host)
            .map_err(|e| anyhow::anyhow!("Invalid host: {}", e))?;

        // Validate user
        let user = ValidatedUser::new(&config.ssh_user)
            .map_err(|e| anyhow::anyhow!("Invalid SSH user: {}", e))?;

        // Security: Only key-based auth allowed
        let auth = if let Some(key_path) = &config.ssh_key_path {
            if !std::path::Path::new(key_path).exists() {
                bail!("SSH key file not found: {}", key_path);
            }
            SshAuth::Key { path: key_path.clone() }
        } else if std::env::var("SSH_AUTH_SOCK").is_ok() {
            SshAuth::Agent
        } else {
            // SECURITY: Password auth removed
            if config.ssh_password.is_some() {
                tracing::warn!(
                    "Password authentication is DEPRECATED and insecure. \
                     Please configure an SSH key instead."
                );
            }
            bail!("SSH key authentication required. Password auth is disabled for security.");
        };

        Ok(Self {
            host,
            ssh_port: config.ssh_port,
            user,
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

    /// Get SSH connection string (safe: uses validated host and user)
    fn connection_string(&self) -> String {
        format!("{}@{}", self.user.as_str(), self.host.as_str())
    }

    /// Execute predefined SSH operation (type-safe)
    async fn execute(&self, operation: SshOperation) -> Result<String> {
        self.execute_with_timeout(operation, Duration::from_secs(SSH_TIMEOUT_SECS)).await
    }

    /// Execute SSH operation with custom timeout
    async fn execute_with_timeout(&self, operation: SshOperation, timeout: Duration) -> Result<String> {
        let cmd = operation.to_command();

        let mut command = match &self.auth {
            SshAuth::Key { path } => {
                let mut c = Command::new("ssh");
                c.args([
                    "-o", "StrictHostKeyChecking=accept-new",
                    "-o", "BatchMode=yes",
                    "-o", "LogLevel=ERROR",
                    "-o", "ConnectTimeout=30",
                    "-i", path,
                    "-p", &self.ssh_port.to_string(),
                    &self.connection_string(),
                    &cmd,
                ]);
                c
            }
            SshAuth::Agent => {
                let mut c = Command::new("ssh");
                c.args([
                    "-o", "StrictHostKeyChecking=accept-new",
                    "-o", "BatchMode=yes",
                    "-o", "LogLevel=ERROR",
                    "-o", "ConnectTimeout=30",
                    "-p", &self.ssh_port.to_string(),
                    &self.connection_string(),
                    &cmd,
                ]);
                c
            }
        };

        command.stdout(Stdio::piped()).stderr(Stdio::piped());

        let output = tokio::time::timeout(timeout, command.output())
            .await
            .context("SSH command timed out")?
            .context("SSH command failed")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("SSH command failed: {}", stderr);
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Upload file via SCP with validated paths
    async fn upload_file(&self, local: &Path, remote: &ValidatedRemotePath) -> Result<()> {
        let local_str = local.to_str().context("Local path must be valid UTF-8")?;

        let remote_str = format!("{}:{}", self.connection_string(), remote.as_str());

        let mut command = match &self.auth {
            SshAuth::Key { path } => {
                let mut c = Command::new("scp");
                c.args([
                    "-o", "StrictHostKeyChecking=accept-new",
                    "-o", "BatchMode=yes",
                    "-o", "LogLevel=ERROR",
                    "-i", path,
                    "-P", &self.ssh_port.to_string(),
                    local_str,
                    &remote_str,
                ]);
                c
            }
            SshAuth::Agent => {
                let mut c = Command::new("scp");
                c.args([
                    "-o", "StrictHostKeyChecking=accept-new",
                    "-o", "BatchMode=yes",
                    "-o", "LogLevel=ERROR",
                    "-P", &self.ssh_port.to_string(),
                    local_str,
                    &remote_str,
                ]);
                c
            }
        };

        let status = tokio::time::timeout(Duration::from_secs(SCP_TIMEOUT_SECS), command.status())
            .await
            .context("SCP upload timed out")?
            .context("SCP failed")?;

        if !status.success() {
            bail!("SCP upload failed");
        }
        Ok(())
    }

    /// Download file via SCP with validated paths
    async fn download_file(&self, remote: &ValidatedRemotePath, local: &Path) -> Result<()> {
        let local_str = local.to_str().context("Local path must be valid UTF-8")?;

        let remote_str = format!("{}:{}", self.connection_string(), remote.as_str());

        let mut command = match &self.auth {
            SshAuth::Key { path } => {
                let mut c = Command::new("scp");
                c.args([
                    "-o", "StrictHostKeyChecking=accept-new",
                    "-o", "BatchMode=yes",
                    "-o", "LogLevel=ERROR",
                    "-i", path,
                    "-P", &self.ssh_port.to_string(),
                    &remote_str,
                    local_str,
                ]);
                c
            }
            SshAuth::Agent => {
                let mut c = Command::new("scp");
                c.args([
                    "-o", "StrictHostKeyChecking=accept-new",
                    "-o", "BatchMode=yes",
                    "-o", "LogLevel=ERROR",
                    "-P", &self.ssh_port.to_string(),
                    &remote_str,
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
            bail!("SCP download failed");
        }
        Ok(())
    }

    /// Test SSH connection
    pub async fn test_connection(&self) -> Result<()> {
        tracing::info!(host = %self.host.as_str(), "Testing SSH connection");
        let output = self.execute(SshOperation::TestConnection).await?;
        if output.trim() != "OK" {
            bail!("Unexpected SSH response: {}", output);
        }
        tracing::info!("SSH connection successful");
        Ok(())
    }

    /// Check server status
    pub async fn check_status(&self) -> ServerStatus {
        let running = self.execute(SshOperation::CheckServerRunning)
            .await
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

        let server_path = ValidatedRemotePath::new(&format!("{REMOTE_DIR}/bin/vpn-server"))
            .expect("hardcoded path");
        let deployed = self.execute(SshOperation::FileExists { path: server_path })
            .await
            .map(|s| s.trim() == "yes")
            .unwrap_or(false);

        ServerStatus {
            deployed,
            running,
            version: None, // TODO: implement version check safely
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
        if let Err(e) = self.execute(SshOperation::CreateDirectories).await {
            self.emit_error(DeployStage::PreparingServer, &e.to_string());
            return Err(e);
        }

        // Stage 3: Upload binaries
        self.emit_progress(DeployStage::UploadingBinaries, "Uploading VPN server binary...", 25);
        let server_remote = ValidatedRemotePath::new(&format!("{REMOTE_DIR}/bin/vpn-server"))
            .expect("hardcoded path is valid");
        if let Err(e) = self.upload_file(server_binary, &server_remote).await {
            self.emit_error(DeployStage::UploadingBinaries, &e.to_string());
            return Err(e);
        }

        self.emit_progress(DeployStage::UploadingBinaries, "Uploading keygen binary...", 35);
        let keygen_remote = ValidatedRemotePath::new(&format!("{REMOTE_DIR}/bin/vpr-keygen"))
            .expect("hardcoded path is valid");
        if let Err(e) = self.upload_file(keygen_binary, &keygen_remote).await {
            self.emit_error(DeployStage::UploadingBinaries, &e.to_string());
            return Err(e);
        }

        // Make binaries executable
        if let Err(e) = self.execute(SshOperation::MakeBinariesExecutable).await {
            self.emit_error(DeployStage::UploadingBinaries, &e.to_string());
            return Err(e);
        }

        // Stage 4: Generate keys
        self.emit_progress(DeployStage::GeneratingKeys, "Generating cryptographic keys...", 50);

        // Check if Noise keys exist
        let noise_key_path = ValidatedRemotePath::new(&format!("{REMOTE_DIR}/secrets/server.noise.key"))
            .expect("hardcoded path");
        let keys_exist = self.execute(SshOperation::FileExists { path: noise_key_path })
            .await
            .map(|s| s.trim() == "yes")
            .unwrap_or(false);

        if !keys_exist {
            if let Err(e) = self.execute(SshOperation::GenerateNoiseKeys).await {
                self.emit_error(DeployStage::GeneratingKeys, &e.to_string());
                return Err(e);
            }
        }

        // Check if TLS cert exists
        let cert_path = ValidatedRemotePath::new(&format!("{REMOTE_DIR}/secrets/server.crt"))
            .expect("hardcoded path");
        let cert_exists = self.execute(SshOperation::FileExists { path: cert_path })
            .await
            .map(|s| s.trim() == "yes")
            .unwrap_or(false);

        if !cert_exists {
            self.emit_progress(DeployStage::GeneratingKeys, "Generating TLS certificate...", 55);
            if let Err(e) = self.execute(SshOperation::GenerateTlsCert {
                host: self.host.clone()
            }).await {
                self.emit_error(DeployStage::GeneratingKeys, &e.to_string());
                return Err(e);
            }
        }

        // Stage 5: Configure firewall
        self.emit_progress(DeployStage::ConfiguringFirewall, "Configuring firewall...", 65);
        let _ = self.execute(SshOperation::EnableIpForwarding).await;
        let _ = self.execute(SshOperation::OpenFirewallPort).await;

        // Stage 6: Start server
        self.emit_progress(DeployStage::StartingServer, "Starting VPN server...", 75);

        // Stop any existing server
        let _ = self.execute(SshOperation::StopServer).await;
        let _ = self.execute(SshOperation::DeleteTunInterface).await;
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Start server
        if let Err(e) = self.execute(SshOperation::StartServer).await {
            self.emit_error(DeployStage::StartingServer, &e.to_string());
            return Err(e);
        }

        // Verify server started
        tokio::time::sleep(Duration::from_secs(3)).await;
        let running = self.execute(SshOperation::CheckServerRunning)
            .await
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

        if !running {
            let logs = self.execute(SshOperation::GetLogs { lines: 30 })
                .await
                .unwrap_or_else(|_| "No logs available".into());
            let err = format!("Server failed to start. Logs:\n{}", logs);
            self.emit_error(DeployStage::StartingServer, &err);
            bail!(err);
        }

        // Stage 7: Download keys for client
        self.emit_progress(DeployStage::DownloadingKeys, "Downloading server public key...", 90);

        std::fs::create_dir_all(secrets_dir).context("Failed to create secrets directory")?;

        let server_pub_remote = ValidatedRemotePath::new(&format!("{REMOTE_DIR}/secrets/server.noise.pub"))
            .expect("hardcoded path");
        if let Err(e) = self.download_file(&server_pub_remote, &secrets_dir.join("server.noise.pub")).await {
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
        let _ = self.execute(SshOperation::StopServer).await;
        let _ = self.execute(SshOperation::DeleteTunInterface).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        Ok(())
    }

    /// Start the VPN server (assuming already deployed)
    pub async fn start_server(&self) -> Result<()> {
        // Stop any existing
        let _ = self.stop_server().await;

        // Enable IP forwarding
        let _ = self.execute(SshOperation::EnableIpForwarding).await;

        // Start server
        self.execute(SshOperation::StartServer).await?;

        // Verify
        tokio::time::sleep(Duration::from_secs(3)).await;
        let running = self.execute(SshOperation::CheckServerRunning)
            .await
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

        if !running {
            let logs = self.execute(SshOperation::GetLogs { lines: 30 })
                .await
                .unwrap_or_else(|_| "No logs available".into());
            bail!("Server failed to start. Logs:\n{}", logs);
        }

        Ok(())
    }

    /// Uninstall server from VPS
    pub async fn uninstall(&self) -> Result<()> {
        tracing::info!("Uninstalling VPN server");

        // Stop server
        let _ = self.stop_server().await;

        // Remove files
        self.execute(SshOperation::Uninstall).await?;

        Ok(())
    }

    /// Get server logs
    pub async fn get_logs(&self, lines: u32) -> Result<String> {
        self.execute(SshOperation::GetLogs { lines }).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validated_host() {
        // Valid hosts
        assert!(ValidatedHost::new("192.168.1.1").is_ok());
        assert!(ValidatedHost::new("example.com").is_ok());
        assert!(ValidatedHost::new("my-server.example.com").is_ok());
        assert!(ValidatedHost::new("2001:db8::1").is_ok());

        // Invalid - injection attempts
        assert!(ValidatedHost::new("evil.com;rm -rf /").is_err());
        assert!(ValidatedHost::new("$(whoami)").is_err());
        assert!(ValidatedHost::new("`id`").is_err());
        assert!(ValidatedHost::new("host|cat /etc/passwd").is_err());
        assert!(ValidatedHost::new("host'--").is_err());
        assert!(ValidatedHost::new("host\"--").is_err());
        assert!(ValidatedHost::new("-evil").is_err());
        assert!(ValidatedHost::new("..").is_err());
    }

    #[test]
    fn test_validated_user() {
        // Valid users
        assert!(ValidatedUser::new("root").is_ok());
        assert!(ValidatedUser::new("admin").is_ok());
        assert!(ValidatedUser::new("vpn_user").is_ok());
        assert!(ValidatedUser::new("user-name").is_ok());

        // Invalid
        assert!(ValidatedUser::new("root;id").is_err());
        assert!(ValidatedUser::new("$(whoami)").is_err());
        assert!(ValidatedUser::new("-evil").is_err());
        assert!(ValidatedUser::new("").is_err());
    }

    #[test]
    fn test_validated_remote_path() {
        // Valid paths (within REMOTE_DIR)
        assert!(ValidatedRemotePath::new("/opt/vpr/bin/server").is_ok());
        assert!(ValidatedRemotePath::new("/opt/vpr/secrets/key").is_ok());

        // Invalid - outside allowed directory
        assert!(ValidatedRemotePath::new("/etc/passwd").is_err());
        assert!(ValidatedRemotePath::new("/root/.ssh/authorized_keys").is_err());

        // Invalid - injection attempts
        assert!(ValidatedRemotePath::new("/opt/vpr/../../etc/passwd").is_err());
        assert!(ValidatedRemotePath::new("/opt/vpr/file;rm -rf /").is_err());
        assert!(ValidatedRemotePath::new("/opt/vpr/$(cat /etc/passwd)").is_err());
    }

    #[test]
    fn test_ssh_operation_commands() {
        let cmd = SshOperation::TestConnection.to_command();
        assert_eq!(cmd, "echo 'OK'");

        let host = ValidatedHost::new("192.168.1.1").unwrap();
        let cmd = SshOperation::GenerateTlsCert { host }.to_command();
        assert!(cmd.contains("192.168.1.1"));
        assert!(cmd.contains("openssl"));
        assert!(!cmd.contains(";")); // No injection possible

        let cmd = SshOperation::StartServer.to_command();
        assert!(cmd.contains("vpn-server"));
        assert!(cmd.contains("--bind 0.0.0.0:443"));
    }

    #[test]
    #[allow(deprecated)]
    fn vps_config_requires_ssh_key() {
        let mut config = VpsConfig::default();
        config.host = "1.2.3.4".into();

        // Password alone should not work
        config.ssh_password = Some("secret".into());
        assert!(!config.is_configured()); // Now requires SSH key

        // SSH key should work
        config.ssh_key_path = Some("/path/to/key".into());
        assert!(config.is_configured());
    }
}
