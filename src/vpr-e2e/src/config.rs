//! E2E test configuration management
//!
//! Configuration can be loaded from:
//! 1. Environment variables (VPR_E2E_*)
//! 2. Config file (~/.vpr/e2e.json or ./config/e2e.json)
//! 3. CLI arguments (highest priority)

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// E2E test configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eConfig {
    /// Remote server configuration
    pub server: ServerConfig,
    /// Local client configuration
    pub client: ClientConfig,
    /// Test suite configuration
    pub tests: TestConfig,
    /// Output configuration
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server IP address
    pub host: String,
    /// SSH port (default: 22)
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    /// SSH username (default: root)
    #[serde(default = "default_user")]
    pub user: String,
    /// SSH password (can be from env: VPR_E2E_PASSWORD)
    #[serde(default)]
    pub password: Option<String>,
    /// SSH key path (alternative to password)
    #[serde(default)]
    pub ssh_key: Option<PathBuf>,
    /// VPN port (default: 4433)
    #[serde(default = "default_vpn_port")]
    pub vpn_port: u16,
    /// Remote installation directory
    #[serde(default = "default_remote_dir")]
    pub remote_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// TUN device name
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    /// Local secrets directory
    #[serde(default = "default_secrets_dir")]
    pub secrets_dir: PathBuf,
    /// TLS profile (chrome, safari, firefox)
    #[serde(default = "default_tls_profile")]
    pub tls_profile: String,
    /// Skip TLS verification (testing only!)
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestConfig {
    /// Enable ping test
    #[serde(default = "default_true")]
    pub ping: bool,
    /// Enable DNS test
    #[serde(default = "default_true")]
    pub dns: bool,
    /// Enable external connectivity test
    #[serde(default = "default_true")]
    pub external: bool,
    /// Enable throughput test
    #[serde(default)]
    pub throughput: bool,
    /// Enable latency test
    #[serde(default = "default_true")]
    pub latency: bool,
    /// Test timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Number of ping packets
    #[serde(default = "default_ping_count")]
    pub ping_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Output directory for logs and reports
    #[serde(default = "default_output_dir")]
    pub dir: PathBuf,
    /// Generate JSON report
    #[serde(default = "default_true")]
    pub json: bool,
    /// Generate Markdown report
    #[serde(default = "default_true")]
    pub markdown: bool,
    /// Verbose logging
    #[serde(default)]
    pub verbose: bool,
}

fn default_ssh_port() -> u16 {
    22
}
fn default_user() -> String {
    "root".into()
}
fn default_vpn_port() -> u16 {
    4433
}
fn default_remote_dir() -> String {
    "/opt/vpr".into()
}
fn default_tun_name() -> String {
    "vpr0".into()
}
fn default_secrets_dir() -> PathBuf {
    PathBuf::from("secrets")
}
fn default_tls_profile() -> String {
    "chrome".into()
}
fn default_true() -> bool {
    true
}
fn default_timeout() -> u64 {
    30
}
fn default_ping_count() -> u32 {
    5
}
fn default_output_dir() -> PathBuf {
    PathBuf::from("logs/e2e")
}

impl Default for E2eConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: String::new(),
                ssh_port: default_ssh_port(),
                user: default_user(),
                password: None,
                ssh_key: None,
                vpn_port: default_vpn_port(),
                remote_dir: default_remote_dir(),
            },
            client: ClientConfig {
                tun_name: default_tun_name(),
                secrets_dir: default_secrets_dir(),
                tls_profile: default_tls_profile(),
                insecure: true, // For testing
            },
            tests: TestConfig {
                ping: true,
                dns: true,
                external: true,
                throughput: false,
                latency: true,
                timeout_secs: default_timeout(),
                ping_count: default_ping_count(),
            },
            output: OutputConfig {
                dir: default_output_dir(),
                json: true,
                markdown: true,
                verbose: false,
            },
        }
    }
}

impl E2eConfig {
    /// Load configuration from file, environment, and CLI
    pub fn load(config_path: Option<&PathBuf>) -> Result<Self> {
        let mut config = Self::default();

        // Try loading from config file
        let config_paths = [
            config_path.cloned(),
            Some(PathBuf::from("config/e2e.json")),
            dirs::home_dir().map(|h| h.join(".vpr/e2e.json")),
        ];

        for path in config_paths.into_iter().flatten() {
            if path.exists() {
                let content = std::fs::read_to_string(&path)
                    .with_context(|| format!("reading config from {:?}", path))?;
                config = serde_json::from_str(&content)
                    .with_context(|| format!("parsing config from {:?}", path))?;
                tracing::info!(?path, "Loaded config from file");
                break;
            }
        }

        // Override with environment variables
        if let Ok(host) = std::env::var("VPR_E2E_HOST") {
            config.server.host = host;
        }
        if let Ok(password) = std::env::var("VPR_E2E_PASSWORD") {
            config.server.password = Some(password);
        }
        if let Ok(user) = std::env::var("VPR_E2E_USER") {
            config.server.user = user;
        }
        if let Ok(port) = std::env::var("VPR_E2E_VPN_PORT") {
            config.server.vpn_port = port.parse().unwrap_or(4433);
        }

        Ok(config)
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        if self.server.host.is_empty() {
            anyhow::bail!("Server host is required. Set via --host or VPR_E2E_HOST");
        }
        if self.server.password.is_none() && self.server.ssh_key.is_none() {
            anyhow::bail!(
                "SSH authentication required. Set password via --password or VPR_E2E_PASSWORD"
            );
        }
        Ok(())
    }

    /// Create sample config file
    pub fn create_sample(path: &PathBuf) -> Result<()> {
        let sample = Self {
            server: ServerConfig {
                host: "YOUR_SERVER_IP".into(),
                ssh_port: 22,
                user: "root".into(),
                password: Some("YOUR_PASSWORD".into()),
                ssh_key: None,
                vpn_port: 4433,
                remote_dir: "/opt/vpr".into(),
            },
            ..Default::default()
        };

        let content = serde_json::to_string_pretty(&sample)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)?;
        Ok(())
    }
}
