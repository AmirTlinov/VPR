#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod connection_diagnostics;
mod deployer;
mod diagnostics_commands;
mod killswitch;
mod process_manager;

use process_manager::{VpnClientConfig, VpnProcessManager};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::net::lookup_host;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::Duration;

#[cfg(unix)]
use caps::{CapSet, Capability};

/// Get the Silentway config directory (~/.silentway)
fn silentway_config_dir() -> PathBuf {
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(".silentway"))
        .unwrap_or_else(|_| PathBuf::from(".silentway"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum VpnStatus {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Error,
}

impl From<process_manager::ProcessStatus> for VpnStatus {
    fn from(status: process_manager::ProcessStatus) -> Self {
        match status {
            process_manager::ProcessStatus::Stopped => VpnStatus::Disconnected,
            process_manager::ProcessStatus::Starting => VpnStatus::Connecting,
            process_manager::ProcessStatus::Running => VpnStatus::Connected,
            process_manager::ProcessStatus::Stopping => VpnStatus::Disconnecting,
            process_manager::ProcessStatus::Error => VpnStatus::Error,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VpnState {
    status: VpnStatus,
    server: String,
    error: Option<String>,
    statistics: process_manager::VpnStatistics,
    /// Whether kill switch is currently active (not just configured)
    #[serde(default)]
    killswitch_active: bool,
}

impl Default for VpnState {
    fn default() -> Self {
        Self {
            status: VpnStatus::Disconnected,
            server: String::new(),
            error: None,
            statistics: process_manager::VpnStatistics::default(),
            killswitch_active: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    server: String,
    port: String,
    username: String,
    mode: String,
    doh_endpoint: String,
    autoconnect: bool,
    killswitch: bool,
    #[serde(default)]
    insecure: bool,
    /// Legacy single VPS config for backward compatibility
    #[serde(default)]
    vps: deployer::VpsConfig,
    /// List of saved servers
    #[serde(default)]
    servers: Vec<SavedServer>,
    /// Currently selected server index
    #[serde(default)]
    selected_server: Option<usize>,
}

/// Saved server configuration with display name
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SavedServer {
    /// Display name for the server
    name: String,
    /// VPS configuration
    #[serde(flatten)]
    vps: deployer::VpsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProbeResult {
    reachable: bool,
    latency_ms: Option<u128>,
    ip: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TunnelCheck {
    tun_present: bool,
    tun_addr: Option<String>,
    default_via_tun: bool,
    route_dev_to_inet: Option<String>,
    route_src_ip: Option<String>,
    warnings: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: "443".into(),
            username: String::new(),
            mode: "masque".into(),
            doh_endpoint: "/dns-query".into(),
            autoconnect: false,
            killswitch: false,
            insecure: false,
            vps: deployer::VpsConfig::default(),
            servers: Vec::new(),
            selected_server: None,
        }
    }
}

impl Config {
    fn path() -> PathBuf {
        silentway_config_dir().join("config.json")
    }

    fn load() -> Self {
        fs::read_to_string(Self::path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save(&self) -> Result<(), String> {
        if let Some(parent) = Self::path().parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                return Err(format!("Failed to create config directory: {}", e));
            }
        }
        fs::write(
            Self::path(),
            serde_json::to_string_pretty(self)
                .map_err(|e| format!("Failed to serialize config: {}", e))?,
        )
        .map_err(|e| format!("Failed to write config: {}", e))?;
        Ok(())
    }
}

struct AppState {
    vpn_manager: Arc<VpnProcessManager>,
    state: Arc<Mutex<VpnState>>,
    diagnostic_state: Arc<Mutex<diagnostics_commands::DiagnosticState>>,
}

async fn build_killswitch_policy(server: &str, port: u16) -> killswitch::KillSwitchPolicy {
    let mut allow_ipv4 = Vec::new();

    // Always include common control ports for DoH/health
    let allow_tcp_ports = vec![port, 443, 8053];
    let allow_udp_ports = vec![53, 443, 8053];

    if let Ok(mut addrs) = lookup_host((server, port)).await {
        for addr in addrs.by_ref() {
            if let IpAddr::V4(v4) = addr.ip() {
                allow_ipv4.push(v4);
            }
        }
    }

    killswitch::KillSwitchPolicy {
        allow_ipv4,
        allow_tcp_ports,
        allow_udp_ports,
    }
}

#[tauri::command]
async fn get_state(state: State<'_, AppState>) -> Result<VpnState, String> {
    let manager_status = state.vpn_manager.get_status().await;
    let manager_stats = state.vpn_manager.get_statistics().await;

    let mut vpn_state = state.state.lock().await.clone();
    vpn_state.status = manager_status.into();
    vpn_state.statistics = manager_stats;

    Ok(vpn_state)
}

#[tauri::command]
fn get_config() -> Config {
    Config::load()
}

#[tauri::command]
fn save_config(config: Config) -> Result<(), String> {
    config.save()
}

#[tauri::command]
async fn connect(
    server: String,
    port: String,
    _username: String,
    _password: String,
    _mode: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // Проверить текущий статус
    let current_status = state.vpn_manager.get_status().await;
    if current_status != process_manager::ProcessStatus::Stopped
        && current_status != process_manager::ProcessStatus::Error
    {
        return Err("Already connected or connecting".into());
    }

    // Обновить состояние
    {
        let mut vpn_state = state.state.lock().await;
        vpn_state.status = VpnStatus::Connecting;
        vpn_state.server = format!("{}:{}", server, port);
        vpn_state.error = None;
    }

    // Загрузить конфигурацию
    let config = Config::load();

    // Найти путь к секретам
    // 1) Проверяем VPR_SECRETS_DIR env
    // 2) Проверяем ./secrets относительно exe
    // 3) Проверяем ./secrets относительно cwd
    // 4) Проверяем ~/.config/vpr/secrets
    let secrets_dir = std::env::var("VPR_SECRETS_DIR")
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .or_else(|| {
            std::env::current_exe().ok().and_then(|exe| {
                let exe_dir = exe.parent()?;
                // Tauri dev: exe is in target/debug/, secrets is in workspace root
                let candidates = [
                    exe_dir.join("secrets"),
                    exe_dir.join("../secrets"),
                    exe_dir.join("../../secrets"),
                    exe_dir.join("../../../secrets"),
                ];
                candidates.into_iter().find(|p| p.exists())
            })
        })
        .or_else(|| {
            std::env::current_dir().ok().and_then(|cwd| {
                let p = cwd.join("secrets");
                if p.exists() {
                    Some(p)
                } else {
                    None
                }
            })
        })
        .or_else(|| {
            let p = silentway_config_dir().join("secrets");
            if p.exists() { Some(p) } else { None }
        })
        .unwrap_or_else(|| PathBuf::from("secrets"));

    tracing::info!(secrets_dir = %secrets_dir.display(), "Using secrets directory");

    // Построить конфигурацию VPN клиента
    let port_num: u16 = port.parse().map_err(|e| format!("Invalid port: {}", e))?;

    // === АВТОМАТИЧЕСКАЯ ДИАГНОСТИКА ПЕРЕД ПОДКЛЮЧЕНИЕМ ===
    let diag_params = connection_diagnostics::DiagnosticParams {
        server: server.clone(),
        port: port_num,
        secrets_dir: secrets_dir.clone(),
        timeout_ms: 5000,
        tun_name: "vpr0".to_string(),
    };

    let diag_result = connection_diagnostics::run_pre_connection_diagnostics(&diag_params).await;

    // Отправляем результаты диагностики в UI
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.emit("diagnostic_result", &diag_result);
    }

    // Если критические проверки не прошли - возвращаем понятную ошибку
    if diag_result.status == connection_diagnostics::DiagnosticStatus::Failed {
        let mut vpn_state = state.state.lock().await;
        vpn_state.status = VpnStatus::Error;
        vpn_state.error = Some(diag_result.summary.clone());

        let error_msg = if let Some(action) = &diag_result.action {
            format!("{}\n\nRecommended action: {}", diag_result.summary, action)
        } else {
            diag_result.summary
        };

        return Err(error_msg);
    }

    // Enable insecure mode if configured or for localhost
    let is_localhost = server == "localhost" || server == "127.0.0.1" || server.starts_with("127.");
    let use_insecure = if config.insecure && !is_localhost {
        // In release builds, require explicit opt-in for insecure mode
        #[cfg(not(debug_assertions))]
        {
            let allow_insecure = std::env::var("VPR_ALLOW_INSECURE")
                .map(|v| v == "1" || v.to_lowercase() == "true")
                .unwrap_or(false);

            if !allow_insecure {
                return Err("Insecure mode is disabled in release builds. \
                     Set VPR_ALLOW_INSECURE=1 environment variable to override."
                    .into());
            }
            tracing::warn!("VPR_ALLOW_INSECURE=1 set - TLS verification disabled");
        }
        true
    } else {
        is_localhost // Allow insecure only for localhost without env var
    };

    let vpn_config = VpnClientConfig {
        server: server.clone(),
        server_name: server.clone(),
        port: port_num,
        tun_name: "vpr0".to_string(),
        noise_dir: secrets_dir.clone(),
        noise_name: "client".to_string(),
        server_pub: secrets_dir.join("server.noise.pub"),
        ca_cert: Some(secrets_dir.join("server.crt")),
        set_default_route: true,
        dns_protection: true,
        dns_servers: vec![],
        tls_profile: "chrome".to_string(),
        insecure: use_insecure,
        killswitch: config.killswitch,
    };

    // Включить kill switch ПЕРЕД запуском VPN клиента
    // Правила разрешают UDP/TCP на VPN сервер + входящие ответы
    let killswitch_enabled = if config.killswitch {
        let policy = build_killswitch_policy(&server, port_num).await;
        if let Err(e) = state.vpn_manager.enable_killswitch(policy).await {
            return Err(format!("Failed to enable kill switch: {}", e));
        }
        true
    } else {
        false
    };

    // Запустить VPN клиент
    match state.vpn_manager.start(vpn_config).await {
        Ok(()) => {
            // Обновить состояние
            let mut vpn_state = state.state.lock().await;
            vpn_state.status = VpnStatus::Connected;
            vpn_state.error = None;
            vpn_state.killswitch_active = killswitch_enabled;
            Ok(())
        }
        Err(e) => {
            // Отключить kill switch при ошибке
            if killswitch_enabled {
                let _ = state.vpn_manager.disable_killswitch().await;
            }

            // === ДИАГНОСТИКА ПОСЛЕ НЕУДАЧНОГО ПОДКЛЮЧЕНИЯ ===
            let error_str = e.to_string();
            let failure_diag = connection_diagnostics::diagnose_connection_failure(
                &error_str,
                &server,
                port_num,
            );

            // Отправляем диагностику в UI
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.emit("diagnostic_result", &failure_diag);
            }

            // Формируем понятное сообщение об ошибке
            let failed_details: Vec<&str> = failure_diag.checks.iter()
                .filter(|c| c.status == connection_diagnostics::DiagnosticStatus::Failed)
                .filter_map(|c| c.details.as_deref())
                .collect();

            let detailed_error = if let Some(action) = &failure_diag.action {
                format!(
                    "{}\n\n{}\n\nRecommended: {}",
                    failure_diag.summary,
                    failed_details.join("\n"),
                    action
                )
            } else {
                format!("{}\n\n{}", failure_diag.summary, error_str)
            };

            // Обновить состояние с ошибкой
            let mut vpn_state = state.state.lock().await;
            vpn_state.status = VpnStatus::Error;
            vpn_state.error = Some(detailed_error.clone());
            vpn_state.killswitch_active = false;
            Err(detailed_error)
        }
    }
}

#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    // Проверить текущий статус
    let current_status = state.vpn_manager.get_status().await;
    if current_status == process_manager::ProcessStatus::Stopped {
        return Ok(());
    }

    // Запомнить состояние kill switch перед изменением статуса
    let was_killswitch_active = {
        let vpn_state = state.state.lock().await;
        vpn_state.killswitch_active
    };

    // Обновить состояние
    {
        let mut vpn_state = state.state.lock().await;
        vpn_state.status = VpnStatus::Disconnecting;
    }

    // Остановить VPN клиент
    let stop_result = state.vpn_manager.stop().await;

    // ALWAYS disable kill switch on disconnect to prevent traffic blocking
    if was_killswitch_active {
        if let Err(e) = state.vpn_manager.disable_killswitch().await {
            tracing::warn!(%e, "Failed to disable kill switch during disconnect");
        }
    }

    match stop_result {
        Ok(()) => {
            let mut vpn_state = state.state.lock().await;
            vpn_state.status = VpnStatus::Disconnected;
            vpn_state.server = String::new();
            vpn_state.error = None;
            vpn_state.killswitch_active = false;
            Ok(())
        }
        Err(e) => {
            let mut vpn_state = state.state.lock().await;
            vpn_state.status = VpnStatus::Error;
            vpn_state.error = Some(e.to_string());
            vpn_state.killswitch_active = false; // Also reset on error
            Err(format!("Failed to stop VPN client: {}", e))
        }
    }
}

#[tauri::command]
async fn get_statistics(
    state: State<'_, AppState>,
) -> Result<process_manager::VpnStatistics, String> {
    Ok(state.vpn_manager.get_statistics().await)
}

/// Lightweight client-side tunnel sanity check (no external network requests)
#[tauri::command]
async fn check_tunnel() -> Result<TunnelCheck, String> {
    // Check vpr0 presence
    let tun_present = std::process::Command::new("ip")
        .args(["link", "show", "vpr0"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let tun_addr = std::process::Command::new("ip")
        .args(["-4", "addr", "show", "dev", "vpr0"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.split_whitespace().nth(1))
                .map(|s| s.to_string())
        });

    let default_via_tun = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.contains(" dev vpr0"))
        .unwrap_or(false);

    let (route_dev_to_inet, route_src_ip) = std::process::Command::new("ip")
        .args(["route", "get", "8.8.8.8"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| {
            let dev = s
                .split_whitespace()
                .collect::<Vec<_>>()
                .windows(2)
                .find_map(|w| {
                    if w[0] == "dev" {
                        Some(w[1].to_string())
                    } else {
                        None
                    }
                });
            let src = s
                .split_whitespace()
                .collect::<Vec<_>>()
                .windows(2)
                .find_map(|w| {
                    if w[0] == "src" {
                        Some(w[1].to_string())
                    } else {
                        None
                    }
                });
            (dev, src)
        })
        .unwrap_or((None, None));

    let mut warnings = Vec::new();
    if !tun_present {
        warnings.push("vpr0 missing".into());
    }
    if !default_via_tun {
        warnings.push("default route not via vpr0".into());
    }
    if route_dev_to_inet.as_deref() != Some("vpr0") {
        warnings.push("internet route not via vpr0".into());
    }

    Ok(TunnelCheck {
        tun_present,
        tun_addr,
        default_via_tun,
        route_dev_to_inet,
        route_src_ip,
        warnings,
    })
}

/// Быстрая проверка доступности сервера: DNS -> TCP connect с таймаутом
#[tauri::command]
async fn probe_server(server: String, port: String) -> Result<ProbeResult, String> {
    let port_num: u16 = port.parse().map_err(|e| format!("Invalid port: {}", e))?;
    if server.is_empty() {
        return Ok(ProbeResult {
            reachable: false,
            latency_ms: None,
            ip: None,
            error: Some("server required".into()),
        });
    }

    let socket_str = format!("{}:{}", server, port_num);

    let start = std::time::Instant::now();
    let resolve = lookup_host(&socket_str)
        .await
        .map_err(|e| format!("DNS resolve failed: {}", e))?;

    let mut last_err: Option<String> = None;
    for addr in resolve {
        let ip_str = addr.ip().to_string();
        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => {
                let elapsed = start.elapsed().as_millis();
                return Ok(ProbeResult {
                    reachable: true,
                    latency_ms: Some(elapsed),
                    ip: Some(ip_str),
                    error: None,
                });
            }
            Ok(Err(e)) => last_err = Some(format!("connect failed: {}", e)),
            Err(_) => last_err = Some("connect timeout".into()),
        }
    }

    Ok(ProbeResult {
        reachable: false,
        latency_ms: None,
        ip: None,
        error: last_err,
    })
}

// ============================================================================
// VPS Deployment Commands
// ============================================================================

/// Save VPS configuration
#[tauri::command]
fn save_vps_config(vps: deployer::VpsConfig) -> Result<(), String> {
    let mut config = Config::load();
    config.vps = vps;
    config.save()
}

/// Get VPS configuration
#[tauri::command]
fn get_vps_config() -> deployer::VpsConfig {
    Config::load().vps
}

// ============================================================================
// Server List Commands
// ============================================================================

/// Get list of saved servers
#[tauri::command]
fn get_servers() -> Vec<SavedServer> {
    let config = Config::load();
    // Migrate legacy config if servers list is empty
    if config.servers.is_empty() {
        // Check vps.host first, then fall back to legacy server field
        let legacy_host = if !config.vps.host.is_empty() {
            config.vps.host.clone()
        } else if !config.server.is_empty() {
            config.server.clone()
        } else {
            return Vec::new();
        };

        vec![SavedServer {
            name: legacy_host.clone(),
            vps: deployer::VpsConfig {
                host: legacy_host,
                ssh_port: config.vps.ssh_port,
                ssh_user: config.vps.ssh_user.clone(),
                deployed: config.vps.deployed,
                ..Default::default()
            },
        }]
    } else {
        config.servers
    }
}

/// Get selected server index
#[tauri::command]
fn get_selected_server() -> Option<usize> {
    Config::load().selected_server
}

/// Set selected server index
#[tauri::command]
fn set_selected_server(index: Option<usize>) -> Result<(), String> {
    let mut config = Config::load();
    config.selected_server = index;
    config.save()
}

/// Add a new server to the list
#[tauri::command]
fn add_server(name: String, vps: deployer::VpsConfig) -> Result<usize, String> {
    let mut config = Config::load();
    let index = config.servers.len();
    config.servers.push(SavedServer { name, vps });
    config.selected_server = Some(index);
    config.save()?;
    Ok(index)
}

/// Update an existing server in the list
#[tauri::command]
fn update_server(index: usize, name: String, vps: deployer::VpsConfig) -> Result<(), String> {
    let mut config = Config::load();
    if index >= config.servers.len() {
        return Err("Server index out of bounds".into());
    }
    config.servers[index] = SavedServer { name, vps };
    config.save()
}

/// Remove a server from the list
#[tauri::command]
fn remove_server(index: usize) -> Result<(), String> {
    let mut config = Config::load();
    if index >= config.servers.len() {
        return Err("Server index out of bounds".into());
    }
    config.servers.remove(index);
    // Adjust selected_server if needed
    if let Some(selected) = config.selected_server {
        if selected == index {
            config.selected_server = None;
        } else if selected > index {
            config.selected_server = Some(selected - 1);
        }
    }
    config.save()
}

/// Get server by index
#[tauri::command]
fn get_server(index: usize) -> Result<SavedServer, String> {
    let config = Config::load();
    config
        .servers
        .get(index)
        .cloned()
        .ok_or_else(|| "Server not found".into())
}

/// Test SSH connection to VPS
#[tauri::command]
async fn test_vps_connection(vps: deployer::VpsConfig) -> Result<(), String> {
    let deployer =
        deployer::Deployer::new(&vps).map_err(|e| format!("Invalid VPS config: {}", e))?;

    deployer
        .test_connection()
        .await
        .map_err(|e| format!("Connection failed: {}", e))
}

/// Check VPS server status
#[tauri::command]
async fn check_vps_status(vps: deployer::VpsConfig) -> Result<deployer::ServerStatus, String> {
    let deployer =
        deployer::Deployer::new(&vps).map_err(|e| format!("Invalid VPS config: {}", e))?;

    Ok(deployer.check_status().await)
}

/// Deploy VPN server to VPS
#[tauri::command]
async fn deploy_server(vps: deployer::VpsConfig, app: AppHandle) -> Result<(), String> {
    // Validate VPS configuration before deployment
    if !vps.is_configured() {
        return Err("VPS not configured: host and authentication required".into());
    }

    let deployer = deployer::Deployer::new(&vps)
        .map_err(|e| format!("Invalid VPS config: {}", e))?
        .with_app_handle(app);

    // Find server and keygen binaries
    let (server_binary, keygen_binary) =
        find_server_binaries().map_err(|e| format!("Failed to find server binaries: {}", e))?;

    // Find or create secrets directory
    let secrets_dir = find_secrets_dir();

    // Run deployment
    deployer
        .deploy(&server_binary, &keygen_binary, &secrets_dir)
        .await
        .map_err(|e| format!("Deployment failed: {}", e))?;

    // Update config to mark as deployed
    let mut config = Config::load();
    config.vps = vps;
    config.vps.deployed = true;
    config.server = config.vps.host.clone();
    config.save()?;

    Ok(())
}

/// Stop VPN server on VPS
#[tauri::command]
async fn stop_vps_server(vps: deployer::VpsConfig) -> Result<(), String> {
    let deployer =
        deployer::Deployer::new(&vps).map_err(|e| format!("Invalid VPS config: {}", e))?;

    deployer
        .stop_server()
        .await
        .map_err(|e| format!("Failed to stop server: {}", e))
}

/// Start VPN server on VPS (must be deployed first)
#[tauri::command]
async fn start_vps_server(vps: deployer::VpsConfig) -> Result<(), String> {
    let deployer =
        deployer::Deployer::new(&vps).map_err(|e| format!("Invalid VPS config: {}", e))?;

    deployer
        .start_server()
        .await
        .map_err(|e| format!("Failed to start server: {}", e))
}

/// Uninstall VPN server from VPS
#[tauri::command]
async fn uninstall_server(vps: deployer::VpsConfig) -> Result<(), String> {
    let deployer =
        deployer::Deployer::new(&vps).map_err(|e| format!("Invalid VPS config: {}", e))?;

    deployer
        .uninstall()
        .await
        .map_err(|e| format!("Uninstall failed: {}", e))?;

    // Update config
    let mut config = Config::load();
    config.vps.deployed = false;
    config.save()?;

    Ok(())
}

/// Get VPS server logs
#[tauri::command]
async fn get_vps_logs(vps: deployer::VpsConfig, lines: u32) -> Result<String, String> {
    let deployer =
        deployer::Deployer::new(&vps).map_err(|e| format!("Invalid VPS config: {}", e))?;

    deployer
        .get_logs(lines)
        .await
        .map_err(|e| format!("Failed to get logs: {}", e))
}

/// Find server binaries for deployment
fn find_server_binaries() -> Result<(PathBuf, PathBuf), String> {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    // Search paths for binaries
    let search_paths = [
        exe_dir.clone(),
        exe_dir.join(".."),
        exe_dir.join("../.."),
        exe_dir.join("../../.."),
        PathBuf::from("target/release"),
        PathBuf::from("target/debug"),
    ];

    let mut server_binary = None;
    let mut keygen_binary = None;

    for base in &search_paths {
        let server_path = base.join("vpn-server");
        let keygen_path = base.join("vpr-keygen");

        if server_path.exists() && server_binary.is_none() {
            server_binary = Some(server_path);
        }
        if keygen_path.exists() && keygen_binary.is_none() {
            keygen_binary = Some(keygen_path);
        }

        if server_binary.is_some() && keygen_binary.is_some() {
            break;
        }
    }

    let server = server_binary.ok_or_else(|| {
        "vpn-server binary not found. Run 'cargo build --release -p masque-core' first.".to_string()
    })?;

    let keygen = keygen_binary.ok_or_else(|| {
        "vpr-keygen binary not found. Run 'cargo build --release -p vpr-crypto' first.".to_string()
    })?;

    Ok((server, keygen))
}

/// Find or create secrets directory
fn find_secrets_dir() -> PathBuf {
    // Try standard locations
    let candidates = [
        std::env::var("VPR_SECRETS_DIR").ok().map(PathBuf::from),
        Some(silentway_config_dir().join("secrets")),
        Some(PathBuf::from("secrets")),
    ];

    for candidate in candidates.into_iter().flatten() {
        if candidate.exists() || std::fs::create_dir_all(&candidate).is_ok() {
            return candidate;
        }
    }

    PathBuf::from("secrets")
}

fn main() {
    // Elevate only if we lack required caps (CAP_NET_ADMIN/CAP_NET_RAW) for TUN setup.
    if let Err(e) = ensure_privileges() {
        eprintln!("Fatal: {}", e);
        std::process::exit(1);
    }

    // Debug env to catch display/session issues early
    eprintln!(
        "env check: euid={} egid={} DISPLAY={:?} XDG_SESSION_TYPE={:?} WAYLAND_DISPLAY={:?}",
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        std::env::var("DISPLAY").ok(),
        std::env::var("XDG_SESSION_TYPE").ok(),
        std::env::var("WAYLAND_DISPLAY").ok()
    );

    // Инициализировать tracing
    tracing_subscriber::fmt::init();

    let vpn_manager = Arc::new(VpnProcessManager::new());
    let app_state = AppState {
        vpn_manager: vpn_manager.clone(),
        state: Arc::new(Mutex::new(VpnState::default())),
        diagnostic_state: Arc::new(Mutex::new(diagnostics_commands::DiagnosticState::default())),
    };

    // Запустить задачу для обновления состояния из менеджера
    let state_clone = app_state.state.clone();
    let manager_clone = vpn_manager.clone();
    tauri::async_runtime::spawn(async move {
        let mut status_rx = manager_clone.subscribe_status();
        let mut stats_rx = manager_clone.subscribe_statistics();

        loop {
            tokio::select! {
                Ok(status) = status_rx.recv() => {
                    let mut vpn_state = state_clone.lock().await;
                    vpn_state.status = status.into();
                }
                Ok(stats) = stats_rx.recv() => {
                    let mut vpn_state = state_clone.lock().await;
                    vpn_state.statistics = stats;
                }
            }
        }
    });

    // Проверить автоподключение
    let config = Config::load();
    if config.autoconnect && !config.server.is_empty() {
        let manager_for_autoconnect = vpn_manager.clone();
        let state_for_autoconnect = app_state.state.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            let port = config.port.parse::<u16>().unwrap_or(443);
            // Найти путь к секретам (та же логика что и в connect)
            let secrets_dir = std::env::var("VPR_SECRETS_DIR")
                .ok()
                .map(PathBuf::from)
                .filter(|p| p.exists())
                .or_else(|| {
                    std::env::current_exe().ok().and_then(|exe| {
                        let exe_dir = exe.parent()?;
                        let candidates = [
                            exe_dir.join("secrets"),
                            exe_dir.join("../secrets"),
                            exe_dir.join("../../secrets"),
                            exe_dir.join("../../../secrets"),
                        ];
                        candidates.into_iter().find(|p| p.exists())
                    })
                })
                .or_else(|| {
                    std::env::current_dir().ok().and_then(|cwd| {
                        let p = cwd.join("secrets");
                        if p.exists() {
                            Some(p)
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or_else(|| PathBuf::from("secrets"));

            // Enable insecure mode if configured or for localhost
            let is_localhost = config.server == "localhost"
                || config.server == "127.0.0.1"
                || config.server.starts_with("127.");
            let use_insecure = if config.insecure && !is_localhost {
                // In release builds, require explicit opt-in for insecure mode
                #[cfg(not(debug_assertions))]
                {
                    let allow_insecure = std::env::var("VPR_ALLOW_INSECURE")
                        .map(|v| v == "1" || v.to_lowercase() == "true")
                        .unwrap_or(false);

                    if !allow_insecure {
                        let mut vpn_state = state_for_autoconnect.lock().await;
                        vpn_state.status = VpnStatus::Error;
                        vpn_state.error = Some(
                            "Insecure mode is disabled in release builds. \
                             Set VPR_ALLOW_INSECURE=1 to override."
                                .into(),
                        );
                        return;
                    }
                    tracing::warn!("VPR_ALLOW_INSECURE=1 set - TLS verification disabled");
                }
                true
            } else {
                is_localhost
            };

            let vpn_config = VpnClientConfig {
                server: config.server.clone(),
                server_name: config.server.clone(),
                port,
                tun_name: "vpr0".to_string(),
                noise_dir: secrets_dir.clone(),
                noise_name: "client".to_string(),
                server_pub: secrets_dir.join("server.noise.pub"),
                ca_cert: Some(secrets_dir.join("server.crt")),
                set_default_route: true,
                dns_protection: true,
                dns_servers: vec![],
                tls_profile: "chrome".to_string(),
                insecure: use_insecure,
                killswitch: config.killswitch,
            };

            // Включить killswitch ПЕРЕД запуском VPN (как в connect)
            let killswitch_enabled = if config.killswitch {
                let policy = build_killswitch_policy(&vpn_config.server, vpn_config.port).await;
                if let Err(e) = manager_for_autoconnect.enable_killswitch(policy).await {
                    let mut vpn_state = state_for_autoconnect.lock().await;
                    vpn_state.status = VpnStatus::Error;
                    vpn_state.error = Some(format!("Failed to enable kill switch: {}", e));
                    return;
                }
                true
            } else {
                false
            };

            if let Err(e) = manager_for_autoconnect.start(vpn_config.clone()).await {
                // Отключить killswitch при ошибке запуска
                if killswitch_enabled {
                    let _ = manager_for_autoconnect.disable_killswitch().await;
                }
                let mut vpn_state = state_for_autoconnect.lock().await;
                vpn_state.status = VpnStatus::Error;
                vpn_state.error = Some(e.to_string());
                vpn_state.killswitch_active = false;
            } else {
                // Успешный старт - обновить состояние
                let mut vpn_state = state_for_autoconnect.lock().await;
                vpn_state.killswitch_active = killswitch_enabled;
            }
        });
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(app_state.diagnostic_state.clone())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            get_state,
            get_config,
            save_config,
            connect,
            disconnect,
            get_statistics,
            probe_server,
            check_tunnel,
            // VPS deployment commands
            save_vps_config,
            get_vps_config,
            test_vps_connection,
            check_vps_status,
            deploy_server,
            stop_vps_server,
            start_vps_server,
            uninstall_server,
            get_vps_logs,
            // Server list commands
            get_servers,
            get_selected_server,
            set_selected_server,
            add_server,
            update_server,
            remove_server,
            get_server,
            // Diagnostics commands
            diagnostics_commands::run_diagnostics,
            diagnostics_commands::apply_auto_fixes,
            diagnostics_commands::get_diagnostic_state,
            diagnostics_commands::cancel_diagnostics,
            // Extended flagship diagnostics
            diagnostics_commands::run_comprehensive_diagnostics,
            diagnostics_commands::measure_connection_quality,
            diagnostics_commands::diagnose_quic_connection,
            diagnostics_commands::run_server_diagnostics,
            diagnostics_commands::check_health_endpoint,
            diagnostics_commands::get_available_fixes,
            diagnostics_commands::apply_specific_fix,
            diagnostics_commands::is_retryable_error,
            diagnostics_commands::get_retry_config,
            diagnostics_commands::calculate_retry_state,
            diagnostics_commands::check_local_certificate,
            // Ultimate flagship diagnostics
            diagnostics_commands::analyze_network_path,
            diagnostics_commands::detect_dpi,
            diagnostics_commands::test_dns_leak,
            diagnostics_commands::test_ipv6_leak,
            diagnostics_commands::estimate_bandwidth,
            diagnostics_commands::verify_kill_switch,
            diagnostics_commands::probe_multiple_paths,
            diagnostics_commands::run_ultimate_diagnostics,
            diagnostics_commands::get_reconnect_strategy
        ])
        .run(tauri::generate_context!())
        .map_err(|e| {
            eprintln!("Fatal error: Failed to run Tauri application: {}", e);
            eprintln!("This is a critical error and the application cannot continue.");
            std::process::exit(1);
        })
        .expect("Fatal: Tauri application failed to start");
}

/// Ensure the process runs with root privileges (Linux). If not, attempt to re-exec
/// with pkexec or sudo, prompting the user for a password. Uses env guard to avoid loops.
fn ensure_root() -> Result<(), String> {
    #[cfg(unix)]
    {
        // Skip if already elevated or explicitly disabled
        // SAFETY: libc::geteuid() is always safe - it's a read-only syscall with no side effects
        if unsafe { libc::geteuid() } == 0 || std::env::var("VPR_SKIP_ELEVATE").is_ok() {
            return Ok(());
        }
        if std::env::var("VPR_ELEVATED").is_ok() {
            return Err("Elevation loop detected; aborting".into());
        }

        let exe =
            std::env::current_exe().map_err(|e| format!("Cannot determine current exe: {}", e))?;
        let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();

        // Prefer pkexec (GUI prompt if available)
        let mut pkexec = std::process::Command::new("pkexec");
        pkexec.arg(&exe);
        pkexec.args(&args);
        pkexec.env("VPR_ELEVATED", "1");

        let pk_result = pkexec.status();
        if let Ok(status) = pk_result {
            if status.success() {
                std::process::exit(0);
            }
        }

        // Fallback to sudo in terminal
        let mut sudo = std::process::Command::new("sudo");
        sudo.arg("-E");
        sudo.arg(&exe);
        sudo.args(&args);
        sudo.env("VPR_ELEVATED", "1");
        sudo.env("VPR_SKIP_ELEVATE", "1");

        match sudo.status() {
            Ok(status) if status.success() => std::process::exit(0),
            Ok(status) => Err(format!("sudo returned {}", status)),
            Err(err) => Err(format!("Failed to escalate privileges: {}", err)),
        }
    }
    #[cfg(not(unix))]
    {
        Ok(())
    }
}

/// Ensure we have privileges needed for TUN + firewall without running entire GUI as root.
/// 1) If CAP_NET_ADMIN and CAP_NET_RAW are present (via setcap) -> OK.
/// 2) Otherwise fallback to legacy root escalation (pkexec/sudo).
fn ensure_privileges() -> Result<(), String> {
    #[cfg(unix)]
    {
        const CAP_NET_ADMIN_BIT: u64 = 12;
        const CAP_NET_RAW_BIT: u64 = 13;

        if has_cap(CAP_NET_ADMIN_BIT) && has_cap(CAP_NET_RAW_BIT) {
            // Keep capabilities across child exec (iptables/nft) via ambient set
            if let Err(e) = activate_ambient_net_caps() {
                tracing::warn!(%e, "failed to activate ambient capabilities, falling back to root escalation");
            } else {
                return Ok(());
            }
        }
        ensure_root()
    }
    #[cfg(not(unix))]
    {
        Ok(())
    }
}

/// Check if effective capabilities include specific bit.
#[cfg(unix)]
fn has_cap(bit: u64) -> bool {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        if let Some(line) = status.lines().find(|l| l.starts_with("CapEff:")) {
            if let Some(hex_str) = line.split_whitespace().nth(1) {
                if let Ok(val) = u64::from_str_radix(hex_str, 16) {
                    return val & (1 << bit) != 0;
                }
            }
        }
    }
    false
}

/// Promote NET_ADMIN/NET_RAW to ambient so child processes (iptables/nft) keep them.
#[cfg(unix)]
fn activate_ambient_net_caps() -> Result<(), String> {
    use caps::errors::CapsError;

    let needed = [Capability::CAP_NET_ADMIN, Capability::CAP_NET_RAW];

    for cap in needed {
        // Ensure inheritable set includes the capability
        // Ensure inheritable contains the cap
        if !caps::has_cap(None, CapSet::Inheritable, cap).unwrap_or(false) {
            caps::raise(None, CapSet::Inheritable, cap)
                .map_err(|e: CapsError| format!("raise inheritable {:?}: {}", cap, e))?;
        }

        // Raise to ambient so exec'd children keep it
        caps::raise(None, CapSet::Ambient, cap)
            .map_err(|e: CapsError| format!("raise ambient {:?}: {}", cap, e))?;
    }

    Ok(())
}

#[cfg(not(unix))]
fn activate_ambient_net_caps() -> Result<(), String> {
    Ok(())
}
