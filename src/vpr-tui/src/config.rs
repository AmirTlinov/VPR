//! Configuration persistence for VPR TUI
//!
//! Saves and loads user settings to ~/.config/vpr/tui.json

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::vpn::{ControllerConfig, ServerConfig};

/// Persistent TUI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuiConfig {
    /// Last used server
    pub last_server: Option<ServerConfig>,
    /// Saved server list
    pub servers: Vec<ServerConfig>,
    /// Auto-connect on startup
    pub auto_connect: bool,
    /// Auto-reconnect on disconnect
    pub auto_reconnect: bool,
    /// Max reconnect attempts
    pub max_reconnect_attempts: u32,
    /// TUN interface name
    pub tun_name: String,
    /// Insecure mode (skip cert verification)
    pub insecure: bool,
    /// Theme preference
    pub theme: Theme,
    /// Show notifications
    pub notifications: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum Theme {
    #[default]
    WatchDogs,
    Matrix,
    Cyberpunk,
    Minimal,
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            last_server: None,
            servers: default_server_list(),
            auto_connect: false,
            auto_reconnect: true,
            max_reconnect_attempts: 5,
            tun_name: "vpr0".into(),
            insecure: false,
            theme: Theme::default(),
            notifications: true,
        }
    }
}

impl TuiConfig {
    /// Get config file path
    pub fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("vpr")
            .join("tui.json")
    }

    /// Load config from file or create default
    pub fn load() -> Self {
        let path = Self::config_path();

        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(content) => match serde_json::from_str(&content) {
                    Ok(config) => return config,
                    Err(e) => {
                        tracing::warn!("Failed to parse config: {}, using defaults", e);
                    }
                },
                Err(e) => {
                    tracing::warn!("Failed to read config: {}, using defaults", e);
                }
            }
        }

        Self::default()
    }

    /// Save config to file
    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::config_path();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, content)?;

        tracing::info!("Config saved to {:?}", path);
        Ok(())
    }

    /// Convert to VPN controller config
    pub fn to_controller_config(&self) -> ControllerConfig {
        let secrets_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("vpr")
            .join("secrets");

        ControllerConfig {
            client_binary: find_client_binary(),
            secrets_dir,
            server: self.last_server.clone().unwrap_or_default(),
            tun_name: self.tun_name.clone(),
            insecure: self.insecure,
            auto_reconnect: self.auto_reconnect,
            max_reconnect_attempts: self.max_reconnect_attempts,
        }
    }

    /// Add server to list if not exists
    pub fn add_server(&mut self, server: ServerConfig) {
        if !self
            .servers
            .iter()
            .any(|s| s.host == server.host && s.port == server.port)
        {
            self.servers.push(server);
        }
    }

    /// Set last used server
    pub fn set_last_server(&mut self, server: ServerConfig) {
        self.last_server = Some(server.clone());
        self.add_server(server);
    }
}

/// Find VPN client binary
fn find_client_binary() -> PathBuf {
    let names = ["vpn-client", "masque-client", "vpr-client"];
    let search_paths = [
        // Development paths
        PathBuf::from("target/release"),
        PathBuf::from("target/debug"),
        PathBuf::from("../target/release"),
        PathBuf::from("../target/debug"),
        PathBuf::from("../../target/release"),
        PathBuf::from("../../target/debug"),
        // System paths
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/usr/bin"),
        // Config path
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("vpr")
            .join("bin"),
    ];

    for name in &names {
        for base in &search_paths {
            let path = base.join(name);
            if path.exists() {
                return path;
            }
        }

        // Check PATH
        if let Ok(output) = std::process::Command::new("which").arg(name).output() {
            if output.status.success() {
                let path_str = String::from_utf8_lossy(&output.stdout);
                let path = PathBuf::from(path_str.trim());
                if path.exists() {
                    return path;
                }
            }
        }
    }

    // Fallback to name only (will be searched in PATH at runtime)
    PathBuf::from("vpn-client")
}

/// Default server list
fn default_server_list() -> Vec<ServerConfig> {
    vec![
        ServerConfig {
            host: "64.176.70.203".into(),
            port: 443,
            name: "VPR-Tokyo".into(),
            location: "Tokyo, Japan".into(),
        },
        ServerConfig {
            host: String::new(),
            port: 443,
            name: "Custom Server".into(),
            location: "Enter manually".into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TuiConfig::default();
        assert_eq!(config.tun_name, "vpr0");
        assert_eq!(config.max_reconnect_attempts, 5);
        assert!(config.auto_reconnect);
        assert!(!config.insecure);
    }

    #[test]
    fn test_config_serialization() {
        let config = TuiConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let loaded: TuiConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.tun_name, config.tun_name);
        assert_eq!(loaded.auto_reconnect, config.auto_reconnect);
    }

    #[test]
    fn test_add_server() {
        let mut config = TuiConfig::default();
        let server = ServerConfig {
            host: "test.server.com".into(),
            port: 8443,
            name: "Test".into(),
            location: "Test".into(),
        };

        let initial_count = config.servers.len();
        config.add_server(server.clone());
        assert_eq!(config.servers.len(), initial_count + 1);

        // Adding same server again should not duplicate
        config.add_server(server);
        assert_eq!(config.servers.len(), initial_count + 1);
    }

    #[test]
    fn test_to_controller_config() {
        let config = TuiConfig {
            last_server: Some(ServerConfig {
                host: "test.com".into(),
                port: 443,
                name: "Test".into(),
                location: "Test".into(),
            }),
            ..TuiConfig::default()
        };

        let ctrl_config = config.to_controller_config();
        assert_eq!(ctrl_config.server.host, "test.com");
        assert_eq!(ctrl_config.tun_name, "vpr0");
    }
}
