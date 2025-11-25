//! Server deployment and management

use crate::config::E2eConfig;
use anyhow::{Context, Result};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// Default SSH operation timeout
const SSH_TIMEOUT_SECS: u64 = 120;

/// Default SCP operation timeout
const SCP_TIMEOUT_SECS: u64 = 300;

/// Server deployer - handles SSH operations and binary deployment
pub struct Deployer {
    config: E2eConfig,
}

impl Deployer {
    pub fn new(config: E2eConfig) -> Self {
        Self { config }
    }

    /// Execute SSH command on remote server with timeout
    pub async fn ssh_exec(&self, cmd: &str) -> Result<String> {
        self.ssh_exec_with_timeout(cmd, Duration::from_secs(SSH_TIMEOUT_SECS))
            .await
    }

    /// Execute SSH command with custom timeout
    pub async fn ssh_exec_with_timeout(&self, cmd: &str, timeout: Duration) -> Result<String> {
        let password = self
            .config
            .server
            .password
            .as_ref()
            .context("SSH password required")?;

        // Use SSHPASS env var to hide password from process list
        let output_future = Command::new("sshpass")
            .env("SSHPASS", password)
            .args([
                "-e", // Read password from SSHPASS env var (not visible in /proc/*/cmdline)
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "LogLevel=ERROR",
                "-o",
                "ConnectTimeout=30",
                &format!("{}@{}", self.config.server.user, self.config.server.host),
                cmd,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

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

    /// Execute SSH command in background (SSH exits immediately after launching)
    /// Uses spawn() to not wait for command completion
    pub async fn ssh_exec_background(&self, cmd: &str) -> Result<()> {
        let password = self
            .config
            .server
            .password
            .as_ref()
            .context("SSH password required")?;

        // Use spawn() instead of output() to not block waiting for completion
        // SSH -f flag forks to background, but Rust still waits for SSH process
        // By using spawn() + wait with timeout we can return early
        let mut child = Command::new("sshpass")
            .env("SSHPASS", password)
            .args([
                "-e",
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR",
                "-o", "ConnectTimeout=30",
                &format!("{}@{}", self.config.server.user, self.config.server.host),
                cmd,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .context("SSH background spawn failed")?;

        // Wait up to 10 seconds for SSH to connect and start the command
        // The remote command runs in background via nohup &, so SSH should exit quickly
        let timeout = Duration::from_secs(10);
        match tokio::time::timeout(timeout, child.wait()).await {
            Ok(Ok(status)) if status.success() => Ok(()),
            Ok(Ok(status)) => anyhow::bail!("SSH exited with status: {}", status),
            Ok(Err(e)) => anyhow::bail!("SSH wait error: {}", e),
            Err(_) => {
                // Timeout - SSH is hanging, kill it and assume command started
                // This can happen if SSH keeps connection open for some reason
                drop(child.kill().await);
                tracing::warn!("SSH background command timed out, assuming started");
                Ok(())
            }
        }
    }

    /// Check if SSH connection works
    pub async fn test_connection(&self) -> Result<()> {
        tracing::info!(host = %self.config.server.host, "Testing SSH connection");
        let output = self.ssh_exec("echo 'OK'").await?;
        if output.trim() != "OK" {
            anyhow::bail!("Unexpected SSH response: {}", output);
        }
        tracing::info!("SSH connection successful");
        Ok(())
    }

    /// Upload file via SCP with timeout
    pub async fn upload_file(&self, local: &Path, remote: &str) -> Result<()> {
        let password = self
            .config
            .server
            .password
            .as_ref()
            .context("SSH password required")?;

        let local_str = local.to_str().context("Local path must be valid UTF-8")?;

        tracing::info!(?local, remote, "Uploading file");

        let status_future = Command::new("sshpass")
            .env("SSHPASS", password)
            .args([
                "-e",
                "scp",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "LogLevel=ERROR",
                local_str,
                &format!(
                    "{}@{}:{}",
                    self.config.server.user, self.config.server.host, remote
                ),
            ])
            .status();

        let status = tokio::time::timeout(Duration::from_secs(SCP_TIMEOUT_SECS), status_future)
            .await
            .context("SCP upload timed out")?
            .context("SCP failed")?;

        if !status.success() {
            anyhow::bail!("SCP upload failed");
        }
        Ok(())
    }

    /// Download file via SCP with timeout
    pub async fn download_file(&self, remote: &str, local: &Path) -> Result<()> {
        let password = self
            .config
            .server
            .password
            .as_ref()
            .context("SSH password required")?;

        let local_str = local.to_str().context("Local path must be valid UTF-8")?;

        tracing::info!(remote, ?local, "Downloading file");

        let status_future = Command::new("sshpass")
            .env("SSHPASS", password)
            .args([
                "-e",
                "scp",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "LogLevel=ERROR",
                &format!(
                    "{}@{}:{}",
                    self.config.server.user, self.config.server.host, remote
                ),
                local_str,
            ])
            .status();

        let status = tokio::time::timeout(Duration::from_secs(SCP_TIMEOUT_SECS), status_future)
            .await
            .context("SCP download timed out")?
            .context("SCP failed")?;

        if !status.success() {
            anyhow::bail!("SCP download failed");
        }
        Ok(())
    }

    /// Prepare server directory structure
    pub async fn prepare_server(&self) -> Result<()> {
        tracing::info!("Preparing server directory structure");
        let remote_dir = &self.config.server.remote_dir;
        self.ssh_exec(&format!(
            "mkdir -p {remote_dir}/{{bin,secrets,logs,config}}"
        ))
        .await?;
        Ok(())
    }

    /// Check if server binary exists
    pub async fn server_binary_exists(&self) -> Result<bool> {
        let remote_dir = &self.config.server.remote_dir;
        let result = self
            .ssh_exec(&format!("test -f {remote_dir}/bin/vpn-server && echo yes"))
            .await;
        Ok(result.map(|s| s.trim() == "yes").unwrap_or(false))
    }

    /// Deploy VPN server binary
    pub async fn deploy_server_binary(&self, local_binary: &Path) -> Result<()> {
        let remote_dir = &self.config.server.remote_dir;
        self.upload_file(local_binary, &format!("{remote_dir}/bin/vpn-server"))
            .await?;
        self.ssh_exec(&format!("chmod +x {remote_dir}/bin/vpn-server"))
            .await?;
        Ok(())
    }

    /// Deploy keygen binary
    pub async fn deploy_keygen_binary(&self, local_binary: &Path) -> Result<()> {
        let remote_dir = &self.config.server.remote_dir;
        self.upload_file(local_binary, &format!("{remote_dir}/bin/vpr-keygen"))
            .await?;
        self.ssh_exec(&format!("chmod +x {remote_dir}/bin/vpr-keygen"))
            .await?;
        Ok(())
    }

    /// Generate server keys if they don't exist
    pub async fn ensure_server_keys(&self) -> Result<()> {
        let remote_dir = &self.config.server.remote_dir;

        // Check if keys exist
        let keys_exist = self
            .ssh_exec(&format!(
                "test -f {remote_dir}/secrets/server.noise.key && echo yes"
            ))
            .await
            .map(|s| s.trim() == "yes")
            .unwrap_or(false);

        if !keys_exist {
            tracing::info!("Generating server Noise keys");
            self.ssh_exec(&format!(
                "cd {remote_dir} && ./bin/vpr-keygen gen-noise-key --name server --output secrets"
            ))
            .await?;
        }

        // Check if TLS cert exists
        let cert_exists = self
            .ssh_exec(&format!(
                "test -f {remote_dir}/secrets/server.crt && echo yes"
            ))
            .await
            .map(|s| s.trim() == "yes")
            .unwrap_or(false);

        if !cert_exists {
            tracing::info!("Generating TLS certificate");
            let host = &self.config.server.host;
            self.ssh_exec(&format!(
                "cd {remote_dir}/secrets && openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
                 -subj '/CN={host}' -addext 'subjectAltName=IP:{host},DNS:{host}' \
                 -keyout server.key -out server.crt"
            ))
            .await?;
        }

        Ok(())
    }

    /// Download server public key for client
    pub async fn download_server_pubkey(&self, local_path: &Path) -> Result<()> {
        let remote_dir = &self.config.server.remote_dir;
        self.download_file(
            &format!("{remote_dir}/secrets/server.noise.pub"),
            local_path,
        )
        .await
    }

    /// Stop VPN server
    pub async fn stop_server(&self) -> Result<()> {
        tracing::info!("Stopping VPN server");
        let _ = self.ssh_exec("pkill -9 -f vpn-server").await;
        let _ = self.ssh_exec("ip link del vpr-srv 2>/dev/null").await;
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        Ok(())
    }

    /// Start VPN server
    pub async fn start_server(&self) -> Result<()> {
        let remote_dir = &self.config.server.remote_dir;
        let vpn_port = self.config.server.vpn_port;

        tracing::info!("Starting VPN server on port {}", vpn_port);

        // Enable IP forwarding
        let _ = self.ssh_exec("sysctl -w net.ipv4.ip_forward=1").await;

        // Start server using SSH -f flag for immediate detachment
        // The server process continues running after SSH exits
        self.ssh_exec_background(&format!(
            "cd {remote_dir} && \
             nohup ./bin/vpn-server \
             --bind 0.0.0.0:{vpn_port} \
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
             </dev/null >logs/server.log 2>&1 &"
        ))
        .await?;

        // Wait and verify
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        let running = self
            .ssh_exec("pgrep -f vpn-server")
            .await
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

        if !running {
            let logs = self
                .ssh_exec(&format!("tail -30 {remote_dir}/logs/server.log"))
                .await
                .unwrap_or_default();
            anyhow::bail!("Server failed to start. Logs:\n{}", logs);
        }

        tracing::info!("VPN server started successfully");
        Ok(())
    }

    /// Get server logs
    pub async fn get_server_logs(&self, lines: u32) -> Result<String> {
        let remote_dir = &self.config.server.remote_dir;
        self.ssh_exec(&format!("tail -{lines} {remote_dir}/logs/server.log"))
            .await
    }

    /// Check if server is running
    pub async fn is_server_running(&self) -> bool {
        self.ssh_exec("pgrep -f vpn-server")
            .await
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
    }
}
