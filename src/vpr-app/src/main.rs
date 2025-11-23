#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::State;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum VpnStatus {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VpnState {
    status: VpnStatus,
    server: String,
    error: Option<String>,
}

impl Default for VpnState {
    fn default() -> Self {
        Self {
            status: VpnStatus::Disconnected,
            server: String::new(),
            error: None,
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
        }
    }
}

impl Config {
    fn path() -> PathBuf {
        directories::ProjectDirs::from("com", "vpr", "client")
            .map(|d| d.config_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
            .join("config.json")
    }

    fn load() -> Self {
        fs::read_to_string(Self::path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save(&self) {
        if let Some(parent) = Self::path().parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(
            Self::path(),
            serde_json::to_string_pretty(self).unwrap_or_default(),
        );
    }
}

struct AppState(Mutex<VpnState>);

#[tauri::command]
fn get_state(state: State<AppState>) -> VpnState {
    state.0.lock().unwrap().clone()
}

#[tauri::command]
fn get_config() -> Config {
    Config::load()
}

#[tauri::command]
fn save_config(
    server: String,
    port: String,
    username: String,
    mode: String,
    doh_endpoint: String,
    autoconnect: bool,
    killswitch: bool,
) {
    Config {
        server,
        port,
        username,
        mode,
        doh_endpoint,
        autoconnect,
        killswitch,
    }
    .save();
}

#[tauri::command]
async fn connect(
    server: String,
    port: String,
    username: String,
    password: String,
    mode: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    {
        let mut s = state.0.lock().unwrap();
        if s.status != VpnStatus::Disconnected {
            return Err("Already connected".into());
        }
        s.status = VpnStatus::Connecting;
        s.server = format!("{}:{}", server, port);
        s.error = None;
    }

    // TODO: Real VPN connection using masque-core
    // For now, simulate connection
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    {
        let mut s = state.0.lock().unwrap();
        if server.is_empty() {
            s.status = VpnStatus::Disconnected;
            s.error = Some("Server address required".into());
            return Err("Server address required".into());
        }

        // Simulate successful connection
        s.status = VpnStatus::Connected;
        Ok(())
    }
}

#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    {
        let mut s = state.0.lock().unwrap();
        if s.status != VpnStatus::Connected {
            return Err("Not connected".into());
        }
        s.status = VpnStatus::Disconnecting;
    }

    // TODO: Real disconnection
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    {
        let mut s = state.0.lock().unwrap();
        s.status = VpnStatus::Disconnected;
        s.server = String::new();
    }

    Ok(())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState(Mutex::new(VpnState::default())))
        .invoke_handler(tauri::generate_handler![
            get_state,
            get_config,
            save_config,
            connect,
            disconnect
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
