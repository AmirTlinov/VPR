//! VPN Client Controller
//!
//! Manages real VPN connection lifecycle and metrics collection.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, Mutex, RwLock};

/// VPN connection state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected {
        server: String,
        connected_at: u64,
    },
    Reconnecting {
        attempt: u32,
        max_attempts: u32,
    },
    Error(String),
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::Disconnected
    }
}

/// Real-time VPN metrics
#[derive(Debug, Clone, Default)]
pub struct VpnMetrics {
    /// Bytes sent through tunnel
    pub bytes_sent: u64,
    /// Bytes received through tunnel
    pub bytes_received: u64,
    /// Current upload speed in bytes/sec
    pub upload_speed: u64,
    /// Current download speed in bytes/sec
    pub download_speed: u64,
    /// Round-trip latency to server in ms
    pub latency_ms: u32,
    /// Packet loss percentage (0-100)
    pub packet_loss: u8,
    /// Connection uptime in seconds
    pub uptime_secs: u64,
    /// Server location (city/country)
    pub server_location: String,
    /// External IP address (through VPN)
    pub external_ip: String,
    /// TUN interface name
    pub tun_interface: String,
}

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub name: String,
    pub location: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 443,
            name: "Default Server".into(),
            location: "Unknown".into(),
        }
    }
}

/// Log entry from VPN client
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: u64,
    pub level: LogLevel,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// VPN Controller - manages connection and collects metrics
pub struct VpnController {
    state: Arc<RwLock<ConnectionState>>,
    metrics: Arc<RwLock<VpnMetrics>>,
    logs: Arc<Mutex<Vec<LogEntry>>>,
    process: Arc<Mutex<Option<Child>>>,
    config: Arc<RwLock<ControllerConfig>>,
    shutdown_tx: Arc<Mutex<Option<mpsc::Sender<()>>>>,
}

#[derive(Debug, Clone)]
pub struct ControllerConfig {
    /// Path to vpn-client binary
    pub client_binary: PathBuf,
    /// Path to secrets directory
    pub secrets_dir: PathBuf,
    /// Current server configuration
    pub server: ServerConfig,
    /// TUN interface name
    pub tun_name: String,
    /// Enable insecure mode (skip cert verification)
    pub insecure: bool,
    /// Auto-reconnect on disconnect
    pub auto_reconnect: bool,
    /// Max reconnect attempts
    pub max_reconnect_attempts: u32,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        let secrets_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("vpr")
            .join("secrets");

        Self {
            client_binary: PathBuf::from("vpn-client"),
            secrets_dir,
            server: ServerConfig::default(),
            tun_name: "vpr0".into(),
            insecure: false,
            auto_reconnect: true,
            max_reconnect_attempts: 5,
        }
    }
}

impl VpnController {
    pub fn new(config: ControllerConfig) -> Self {
        Self {
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            metrics: Arc::new(RwLock::new(VpnMetrics::default())),
            logs: Arc::new(Mutex::new(Vec::with_capacity(1000))),
            process: Arc::new(Mutex::new(None)),
            config: Arc::new(RwLock::new(config)),
            shutdown_tx: Arc::new(Mutex::new(None)),
        }
    }

    /// Get current connection state
    pub async fn state(&self) -> ConnectionState {
        self.state.read().await.clone()
    }

    /// Get current metrics
    pub async fn metrics(&self) -> VpnMetrics {
        self.metrics.read().await.clone()
    }

    /// Get recent logs (last N entries)
    pub async fn logs(&self, count: usize) -> Vec<LogEntry> {
        let logs = self.logs.lock().await;
        logs.iter().rev().take(count).cloned().collect()
    }

    /// Get current configuration
    pub async fn config(&self) -> ControllerConfig {
        self.config.read().await.clone()
    }

    /// Update server configuration
    pub async fn set_server(&self, server: ServerConfig) {
        let mut config = self.config.write().await;
        config.server = server;
    }

    /// Connect to VPN server
    pub async fn connect(&self) -> anyhow::Result<()> {
        // Check if already connected or connecting
        {
            let state = self.state.read().await;
            if matches!(*state, ConnectionState::Connected { .. } | ConnectionState::Connecting) {
                anyhow::bail!("Already connected or connecting");
            }
        }

        // Update state to connecting
        *self.state.write().await = ConnectionState::Connecting;
        self.add_log(LogLevel::Info, "Initiating VPN connection...").await;

        let config = self.config.read().await.clone();
        
        // Validate configuration
        if config.server.host.is_empty() {
            *self.state.write().await = ConnectionState::Error("Server not configured".into());
            return Err(anyhow::anyhow!("Server host not configured"));
        }

        // Build command
        let mut cmd = Command::new(&config.client_binary);
        cmd.args([
            "--server", &config.server.host,
            "--port", &config.server.port.to_string(),
            "--tun-name", &config.tun_name,
            "--noise-dir", config.secrets_dir.to_str().unwrap_or("."),
            "--noise-name", "client",
        ]);

        if config.insecure {
            cmd.arg("--insecure");
        }

        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        self.add_log(LogLevel::Info, &format!("Starting client: {} -> {}:{}", 
            config.client_binary.display(), config.server.host, config.server.port)).await;

        // Spawn process
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let msg = format!("Failed to start VPN client: {}", e);
                self.add_log(LogLevel::Error, &msg).await;
                *self.state.write().await = ConnectionState::Error(msg.clone());
                return Err(anyhow::anyhow!(msg));
            }
        };

        // Setup shutdown channel
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        *self.shutdown_tx.lock().await = Some(shutdown_tx);

        // Take stdout/stderr for log parsing
        let stdout = child.stdout.take();
        let _stderr = child.stderr.take();

        // Store process
        *self.process.lock().await = Some(child);

        // Clone Arcs for background tasks
        let state = Arc::clone(&self.state);
        let metrics = Arc::clone(&self.metrics);
        let logs = Arc::clone(&self.logs);
        let server_host = config.server.host.clone();
        let server_location = config.server.location.clone();
        let tun_name = config.tun_name.clone();

        // Spawn log parser task
        tokio::spawn(async move {
            let connect_start = Instant::now();
            let mut connected = false;

            // Parse stdout
            if let Some(stdout) = stdout {
                let mut reader = BufReader::new(stdout).lines();
                
                loop {
                    tokio::select! {
                        _ = shutdown_rx.recv() => {
                            break;
                        }
                        line = reader.next_line() => {
                            match line {
                                Ok(Some(line)) => {
                                    // Parse log line
                                    let (level, msg) = parse_log_line(&line);
                                    
                                    // Add to logs
                                    {
                                        let mut logs = logs.lock().await;
                                        logs.push(LogEntry {
                                            timestamp: chrono::Utc::now().timestamp() as u64,
                                            level,
                                            message: msg.clone(),
                                        });
                                        // Keep only last 1000 logs
                                        if logs.len() > 1000 {
                                            logs.remove(0);
                                        }
                                    }

                                    // Detect connection established
                                    if !connected && (
                                        line.contains("Tunnel established") ||
                                        line.contains("Connected to") ||
                                        line.contains("TUN device created")
                                    ) {
                                        connected = true;
                                        *state.write().await = ConnectionState::Connected {
                                            server: server_host.clone(),
                                            connected_at: chrono::Utc::now().timestamp() as u64,
                                        };
                                        
                                        // Initialize metrics
                                        let mut m = metrics.write().await;
                                        m.server_location = server_location.clone();
                                        m.tun_interface = tun_name.clone();
                                    }

                                    // Parse metrics from logs
                                    if let Some(latency) = parse_latency(&line) {
                                        metrics.write().await.latency_ms = latency;
                                    }
                                }
                                Ok(None) => break,
                                Err(_) => break,
                            }
                        }
                    }
                }
            }

            // If we never connected, set error state
            if !connected {
                let elapsed = connect_start.elapsed();
                if elapsed > Duration::from_secs(30) {
                    *state.write().await = ConnectionState::Error("Connection timeout".into());
                }
            }
        });

        // Give the client a moment to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Check if process is still running
        {
            let mut proc = self.process.lock().await;
            if let Some(ref mut child) = *proc {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        let msg = format!("Client exited immediately with: {}", status);
                        self.add_log(LogLevel::Error, &msg).await;
                        *self.state.write().await = ConnectionState::Error(msg);
                        return Err(anyhow::anyhow!("Client process exited"));
                    }
                    Ok(None) => {
                        // Still running - good
                    }
                    Err(e) => {
                        let msg = format!("Failed to check client status: {}", e);
                        *self.state.write().await = ConnectionState::Error(msg.clone());
                        return Err(anyhow::anyhow!(msg));
                    }
                }
            }
        }

        self.add_log(LogLevel::Info, "VPN client started, waiting for tunnel...").await;
        Ok(())
    }

    /// Disconnect from VPN server
    pub async fn disconnect(&self) -> anyhow::Result<()> {
        self.add_log(LogLevel::Info, "Disconnecting VPN...").await;

        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.lock().await.take() {
            let _ = tx.send(()).await;
        }

        // Kill process
        {
            let mut proc = self.process.lock().await;
            if let Some(ref mut child) = *proc {
                let _ = child.kill().await;
                let _ = child.wait().await;
            }
            *proc = None;
        }

        // Reset state and metrics
        *self.state.write().await = ConnectionState::Disconnected;
        *self.metrics.write().await = VpnMetrics::default();

        self.add_log(LogLevel::Info, "VPN disconnected").await;
        Ok(())
    }

    /// Toggle connection (connect if disconnected, disconnect if connected)
    pub async fn toggle(&self) -> anyhow::Result<()> {
        match self.state().await {
            ConnectionState::Disconnected | ConnectionState::Error(_) => self.connect().await,
            ConnectionState::Connected { .. } => self.disconnect().await,
            ConnectionState::Connecting | ConnectionState::Reconnecting { .. } => {
                self.disconnect().await
            }
        }
    }

    /// Check if TUN interface exists (Linux)
    pub async fn check_tun_interface(&self) -> bool {
        let config = self.config.read().await;
        let output = Command::new("ip")
            .args(["link", "show", &config.tun_name])
            .output()
            .await;
        
        output.map(|o| o.status.success()).unwrap_or(false)
    }

    /// Get external IP through VPN
    pub async fn fetch_external_ip(&self) -> Option<String> {
        let output = Command::new("curl")
            .args(["-s", "--max-time", "5", "https://ifconfig.me"])
            .output()
            .await
            .ok()?;

        if output.status.success() {
            let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
            self.metrics.write().await.external_ip = ip.clone();
            Some(ip)
        } else {
            None
        }
    }

    /// Measure latency to server
    pub async fn measure_latency(&self) -> Option<u32> {
        let config = self.config.read().await;
        if config.server.host.is_empty() {
            return None;
        }

        let output = Command::new("ping")
            .args(["-c", "1", "-W", "2", &config.server.host])
            .output()
            .await
            .ok()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Parse "time=XX.XX ms" from ping output
            if let Some(time_start) = stdout.find("time=") {
                let rest = &stdout[time_start + 5..];
                if let Some(ms_end) = rest.find(" ms") {
                    if let Ok(ms) = rest[..ms_end].parse::<f32>() {
                        let latency = ms as u32;
                        self.metrics.write().await.latency_ms = latency;
                        return Some(latency);
                    }
                }
            }
        }
        None
    }

    /// Update traffic metrics from /sys/class/net
    pub async fn update_traffic_metrics(&self) {
        let config = self.config.read().await;
        let tun = &config.tun_name;

        // Read RX bytes
        let rx_path = format!("/sys/class/net/{}/statistics/rx_bytes", tun);
        let tx_path = format!("/sys/class/net/{}/statistics/tx_bytes", tun);

        let rx = tokio::fs::read_to_string(&rx_path).await
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);

        let tx = tokio::fs::read_to_string(&tx_path).await
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);

        let mut metrics = self.metrics.write().await;
        
        // Calculate speeds (bytes since last update)
        let prev_rx = metrics.bytes_received;
        let prev_tx = metrics.bytes_sent;
        
        metrics.bytes_received = rx;
        metrics.bytes_sent = tx;
        
        // Approximate speed (assuming 1 second between updates)
        if rx > prev_rx {
            metrics.download_speed = rx - prev_rx;
        }
        if tx > prev_tx {
            metrics.upload_speed = tx - prev_tx;
        }
    }

    async fn add_log(&self, level: LogLevel, message: &str) {
        let mut logs = self.logs.lock().await;
        logs.push(LogEntry {
            timestamp: chrono::Utc::now().timestamp() as u64,
            level,
            message: message.to_string(),
        });
        if logs.len() > 1000 {
            logs.remove(0);
        }
    }
}

/// Parse log level and message from VPN client output
fn parse_log_line(line: &str) -> (LogLevel, String) {
    let level = if line.contains("ERROR") || line.contains("error") {
        LogLevel::Error
    } else if line.contains("WARN") || line.contains("warn") {
        LogLevel::Warn
    } else if line.contains("DEBUG") || line.contains("debug") || line.contains("TRACE") {
        LogLevel::Debug
    } else {
        LogLevel::Info
    };

    // Strip ANSI codes and timestamps
    let cleaned = strip_ansi(line);
    (level, cleaned)
}

/// Parse latency from log line
fn parse_latency(line: &str) -> Option<u32> {
    // Look for patterns like "latency=42ms" or "RTT: 42ms"
    let patterns = ["latency=", "RTT:", "RTT: ", "rtt=", "ping="];
    for pat in patterns {
        if let Some(idx) = line.find(pat) {
            let rest = &line[idx + pat.len()..];
            // Skip leading whitespace
            let rest = rest.trim_start();
            let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(ms) = num.parse() {
                return Some(ms);
            }
        }
    }
    None
}

/// Strip ANSI escape codes from string
fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip escape sequence
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if nc.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state_default() {
        let state = ConnectionState::default();
        assert!(matches!(state, ConnectionState::Disconnected));
    }

    #[test]
    fn test_parse_log_line_levels() {
        let (level, _) = parse_log_line("2024-01-01 ERROR: Something failed");
        assert!(matches!(level, LogLevel::Error));

        let (level, _) = parse_log_line("2024-01-01 WARN: Something suspicious");
        assert!(matches!(level, LogLevel::Warn));

        let (level, _) = parse_log_line("2024-01-01 INFO: Normal operation");
        assert!(matches!(level, LogLevel::Info));
    }

    #[test]
    fn test_parse_latency() {
        assert_eq!(parse_latency("latency=42ms"), Some(42));
        assert_eq!(parse_latency("RTT: 100ms"), Some(100));
        assert_eq!(parse_latency("no latency here"), None);
    }

    #[test]
    fn test_strip_ansi() {
        let input = "\x1b[32mGreen text\x1b[0m";
        let output = strip_ansi(input);
        assert_eq!(output, "Green text");
    }

    #[test]
    fn test_controller_config_default() {
        let config = ControllerConfig::default();
        assert_eq!(config.tun_name, "vpr0");
        assert_eq!(config.max_reconnect_attempts, 5);
    }
}
