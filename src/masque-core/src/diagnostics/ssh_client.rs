//! SSH client wrapper for secure remote operations

use super::fixes::{CommandOutput, SshClient as SshClientTrait};
use anyhow::{bail, Context, Result};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// SSH authentication methods
#[derive(Debug, Clone)]
pub enum SshAuth {
    /// Password authentication (convenience, current approach)
    Password(String),
    /// SSH key authentication (more secure)
    Key(PathBuf),
    /// Use ssh-agent
    Agent,
}

/// SSH configuration
#[derive(Debug, Clone)]
pub struct SshConfig {
    pub host: String,
    pub ssh_port: u16,
    pub user: String,
    pub password: Option<String>,
    pub ssh_key: Option<PathBuf>,
}

/// SSH client implementation
pub struct SshClientImpl {
    host: String,
    port: u16,
    user: String,
    auth: SshAuth,
}

impl SshClientImpl {
    /// Connect to SSH server with given configuration
    pub async fn connect(config: &SshConfig) -> Result<Self> {
        // Prefer key > agent > password
        let auth = if let Some(key_path) = &config.ssh_key {
            if !key_path.exists() {
                bail!("SSH key not found: {}", key_path.display());
            }
            SshAuth::Key(key_path.clone())
        } else if env::var("SSH_AUTH_SOCK").is_ok() {
            SshAuth::Agent
        } else if let Some(password) = &config.password {
            SshAuth::Password(password.clone())
        } else {
            bail!("No SSH authentication method available");
        };

        Ok(Self {
            host: config.host.clone(),
            port: config.ssh_port,
            user: config.user.clone(),
            auth,
        })
    }

    /// Get SSH connection string
    fn connection_string(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }

    /// Get common SSH arguments
    fn common_ssh_args(&self) -> Vec<String> {
        vec![
            "-o".to_string(),
            "StrictHostKeyChecking=accept-new".to_string(), // Safer than 'no'
            "-p".to_string(),
            self.port.to_string(),
        ]
    }

    /// Execute SSH command based on auth method
    fn exec_ssh(&self, args: &[&str]) -> Result<CommandOutput> {
        match &self.auth {
            SshAuth::Password(password) => {
                // Use sshpass for password authentication
                let mut cmd = Command::new("sshpass");
                cmd.env("SSHPASS", password);
                cmd.arg("-e"); // Read password from SSHPASS env var

                cmd.arg("ssh");
                for arg in self.common_ssh_args() {
                    cmd.arg(arg);
                }
                for arg in args {
                    cmd.arg(arg);
                }

                let output = cmd.output().context("Failed to execute sshpass")?;
                Ok(CommandOutput::from(output))
            }
            SshAuth::Key(key_path) => {
                let mut cmd = Command::new("ssh");
                cmd.arg("-i").arg(key_path);

                for arg in self.common_ssh_args() {
                    cmd.arg(arg);
                }
                for arg in args {
                    cmd.arg(arg);
                }

                let output = cmd.output().context("Failed to execute ssh")?;
                Ok(CommandOutput::from(output))
            }
            SshAuth::Agent => {
                let mut cmd = Command::new("ssh");

                for arg in self.common_ssh_args() {
                    cmd.arg(arg);
                }
                for arg in args {
                    cmd.arg(arg);
                }

                let output = cmd.output().context("Failed to execute ssh")?;
                Ok(CommandOutput::from(output))
            }
        }
    }

    /// Execute SCP command
    fn exec_scp(&self, args: &[&str]) -> Result<CommandOutput> {
        match &self.auth {
            SshAuth::Password(password) => {
                let mut cmd = Command::new("sshpass");
                cmd.env("SSHPASS", password);
                cmd.arg("-e");

                cmd.arg("scp");
                cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
                cmd.arg("-P").arg(self.port.to_string());

                for arg in args {
                    cmd.arg(arg);
                }

                let output = cmd.output().context("Failed to execute sshpass scp")?;
                Ok(CommandOutput::from(output))
            }
            SshAuth::Key(key_path) => {
                let mut cmd = Command::new("scp");
                cmd.arg("-i").arg(key_path);
                cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
                cmd.arg("-P").arg(self.port.to_string());

                for arg in args {
                    cmd.arg(arg);
                }

                let output = cmd.output().context("Failed to execute scp")?;
                Ok(CommandOutput::from(output))
            }
            SshAuth::Agent => {
                let mut cmd = Command::new("scp");
                cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
                cmd.arg("-P").arg(self.port.to_string());

                for arg in args {
                    cmd.arg(arg);
                }

                let output = cmd.output().context("Failed to execute scp")?;
                Ok(CommandOutput::from(output))
            }
        }
    }
}

impl SshClientTrait for SshClientImpl {
    fn run_command(&self, cmd: &str) -> Result<CommandOutput> {
        let args = [&self.connection_string(), cmd];
        let output = self.exec_ssh(&args)?;

        if !output.success {
            tracing::warn!(
                "SSH command failed: {}\nstderr: {}",
                cmd,
                sanitize_log(&output.stderr)
            );
        }

        Ok(output)
    }

    fn upload_file(&self, local: &Path, remote: &str) -> Result<()> {
        let local_str = local.to_str().context("Invalid local path")?;
        let remote_str = format!("{}:{}", self.connection_string(), remote);

        let args = [local_str, &remote_str];
        let output = self.exec_scp(&args)?;

        if !output.success {
            bail!(
                "Failed to upload file: {}",
                sanitize_log(&output.stderr)
            );
        }

        tracing::info!("Uploaded {} to {}", local.display(), remote);
        Ok(())
    }

    fn download_file(&self, remote: &str) -> Result<Vec<u8>> {
        // Download to temporary file first
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!("vpr_download_{}", uuid::Uuid::new_v4()));

        self.download_file_to(remote, &temp_file)?;

        let content = std::fs::read(&temp_file)?;
        std::fs::remove_file(&temp_file)?;

        Ok(content)
    }

    fn download_file_to(&self, remote: &str, local: &Path) -> Result<()> {
        let remote_str = format!("{}:{}", self.connection_string(), remote);
        let local_str = local.to_str().context("Invalid local path")?;

        let args = [&remote_str, local_str];
        let output = self.exec_scp(&args)?;

        if !output.success {
            bail!(
                "Failed to download file: {}",
                sanitize_log(&output.stderr)
            );
        }

        tracing::info!("Downloaded {} to {}", remote, local.display());
        Ok(())
    }
}

/// Sanitize log messages to prevent password leakage
fn sanitize_log(msg: &str) -> String {
    // Remove any potential password patterns from logs
    let mut sanitized = msg.to_string();

    // Remove SSHPASS environment variable if leaked
    if let Some(idx) = sanitized.find("SSHPASS=") {
        if let Some(end) = sanitized[idx..].find(char::is_whitespace) {
            sanitized.replace_range(idx..idx + end, "SSHPASS=<redacted>");
        }
    }

    // Remove password-like patterns
    sanitized = sanitized.replace(|c: char| c.is_control(), " ");

    sanitized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_log() {
        let msg = "SSHPASS=secret123 other stuff";
        let sanitized = sanitize_log(msg);
        assert!(!sanitized.contains("secret123"));
        assert!(sanitized.contains("SSHPASS=<redacted>"));
    }

    #[test]
    fn test_connection_string() {
        let client = SshClientImpl {
            host: "example.com".to_string(),
            port: 22,
            user: "root".to_string(),
            auth: SshAuth::Agent,
        };

        assert_eq!(client.connection_string(), "root@example.com");
    }
}
