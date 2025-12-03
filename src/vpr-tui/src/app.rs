//! Main TUI Application with full VPN control
//!
//! Watch Dogs 2 hacker aesthetic with real functionality

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::RwLock;

use crate::config::TuiConfig;
use crate::globe::GlobeRenderer;
use crate::render::{
    draw_help_screen, draw_logs_screen, draw_main_screen, draw_servers_screen, draw_settings_screen,
};
use crate::vpn::{ConnectionState, ControllerConfig, ServerConfig, VpnController, VpnMetrics};

/// Active screen in TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Main,
    Logs,
    Servers,
    Settings,
    Help,
}

impl Default for Screen {
    fn default() -> Self {
        Self::Main
    }
}

/// Application state
pub struct AppState {
    /// Current active screen
    pub screen: Screen,
    /// Animation tick counter
    pub tick: u64,
    /// Globe rotation angle
    pub angle: f32,
    /// VPN controller
    pub vpn: Arc<VpnController>,
    /// Cached connection state
    pub conn_state: ConnectionState,
    /// Cached metrics
    pub metrics: VpnMetrics,
    /// Available servers
    pub servers: Vec<ServerConfig>,
    /// Selected server index
    pub selected_server: usize,
    /// Log scroll offset
    pub log_scroll: usize,
    /// Show help overlay
    pub show_help: bool,
    /// Status message (temporary)
    pub status_message: Option<(String, Instant)>,
    /// Input mode for server entry
    pub input_mode: InputMode,
    /// Input buffer
    pub input_buffer: String,
    /// Persistent configuration
    pub config: TuiConfig,
    /// Settings screen selection index
    pub settings_selection: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputMode {
    #[default]
    Normal,
    ServerHost,
    ServerPort,
}

impl AppState {
    pub fn new(vpn: Arc<VpnController>, config: TuiConfig) -> Self {
        let servers = config.servers.clone();
        Self {
            screen: Screen::Main,
            tick: 0,
            angle: 0.0,
            vpn,
            conn_state: ConnectionState::Disconnected,
            metrics: VpnMetrics::default(),
            servers,
            selected_server: 0,
            log_scroll: 0,
            show_help: false,
            status_message: None,
            input_mode: InputMode::Normal,
            input_buffer: String::new(),
            config,
            settings_selection: 0,
        }
    }

    /// Save current configuration
    pub fn save_config(&mut self) -> anyhow::Result<()> {
        // Sync servers back to config
        self.config.servers = self.servers.clone();
        self.config.save()
    }

    /// Set temporary status message
    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status_message = Some((msg.into(), Instant::now()));
    }

    /// Get status message if not expired
    pub fn get_status(&self) -> Option<&str> {
        self.status_message.as_ref().and_then(|(msg, time)| {
            if time.elapsed() < Duration::from_secs(5) {
                Some(msg.as_str())
            } else {
                None
            }
        })
    }
}

// Server list is now loaded from TuiConfig

/// TUI event that can be handled by the caller
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuiEvent {
    /// User requested network repair (pressed 'R')
    RepairNetwork,
    /// User requested quit (pressed 'Q' or Esc)
    Quit,
}

/// Callbacks for TUI events and state queries (legacy interface)
pub struct TuiCallbacks<F, G>
where
    F: FnMut() -> crate::render::NetworkHealth,
    G: FnMut() -> bool,
{
    /// Get current network health status
    pub get_network_health: F,
    /// Attempt network repair, returns true if successful
    pub repair_network: G,
}

/// Run the interactive TUI with the rotating ASCII globe (legacy interface)
pub fn run() -> Result<()> {
    run_with_callbacks(TuiCallbacks {
        get_network_health: || crate::render::NetworkHealth::default(),
        repair_network: || false,
    })
}

/// Run TUI with custom callbacks for network status and repair (legacy interface)
pub fn run_with_callbacks<F, G>(_callbacks: TuiCallbacks<F, G>) -> Result<()>
where
    F: FnMut() -> crate::render::NetworkHealth,
    G: FnMut() -> bool,
{
    // Use new async runtime
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async())
}

/// Main async TUI entry point - loads config from file
pub async fn run_async() -> Result<()> {
    let tui_config = TuiConfig::load();
    let controller_config = tui_config.to_controller_config();
    run_with_tui_config(controller_config, tui_config).await
}

/// Run TUI with custom VPN configuration (legacy)
pub async fn run_with_config(config: ControllerConfig) -> Result<()> {
    let tui_config = TuiConfig::load();
    run_with_tui_config(config, tui_config).await
}

/// Run TUI with full configuration
pub async fn run_with_tui_config(
    controller_config: ControllerConfig,
    tui_config: TuiConfig,
) -> Result<()> {
    let vpn = Arc::new(VpnController::new(controller_config));
    let state = Arc::new(RwLock::new(AppState::new(Arc::clone(&vpn), tui_config)));

    let mut stdout = io::stdout();
    enable_raw_mode()?;
    stdout.execute(EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.hide_cursor()?;

    let result = event_loop(&mut terminal, state, vpn).await;

    disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

/// Main event loop
async fn event_loop<B>(
    terminal: &mut Terminal<B>,
    state: Arc<RwLock<AppState>>,
    vpn: Arc<VpnController>,
) -> Result<()>
where
    B: ratatui::backend::Backend,
{
    let globe = GlobeRenderer::new(4200, 0.32, 0.18);
    let tick_rate = Duration::from_millis(41); // ~24 FPS
    let mut last_tick = Instant::now();
    let mut metrics_update = Instant::now();

    loop {
        // Update cached state from VPN controller
        {
            let mut app = state.write().await;
            app.conn_state = vpn.state().await;

            // Update metrics less frequently
            if metrics_update.elapsed() > Duration::from_secs(1) {
                app.metrics = vpn.metrics().await;

                // Update traffic stats if connected
                if matches!(app.conn_state, ConnectionState::Connected { .. }) {
                    vpn.update_traffic_metrics().await;
                }

                metrics_update = Instant::now();
            }
        }

        // Render
        {
            let app = state.read().await;
            terminal.draw(|frame| {
                let area = frame.size();

                match app.screen {
                    Screen::Main => draw_main_screen(frame, &globe, area, &app),
                    Screen::Logs => draw_logs_screen(frame, area, &app, &vpn),
                    Screen::Servers => draw_servers_screen(frame, area, &app),
                    Screen::Settings => draw_settings_screen(frame, area, &app),
                    Screen::Help => draw_help_screen(frame, area, &app),
                }
            })?;
        }

        // Handle input
        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                let mut app = state.write().await;

                // Handle input mode first
                if app.input_mode != InputMode::Normal {
                    match key.code {
                        KeyCode::Esc => {
                            app.input_mode = InputMode::Normal;
                            app.input_buffer.clear();
                        }
                        KeyCode::Enter => {
                            handle_input_submit(&mut app).await;
                        }
                        KeyCode::Backspace => {
                            app.input_buffer.pop();
                        }
                        KeyCode::Char(c) => {
                            app.input_buffer.push(c);
                        }
                        _ => {}
                    }
                    continue;
                }

                // Global keys
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        if app.screen != Screen::Main {
                            app.screen = Screen::Main;
                        } else {
                            // Disconnect before quitting
                            if matches!(app.conn_state, ConnectionState::Connected { .. }) {
                                let _ = vpn.disconnect().await;
                            }
                            break;
                        }
                    }
                    KeyCode::Char('?') | KeyCode::F(1) => {
                        app.screen = Screen::Help;
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+C - force quit
                        let _ = vpn.disconnect().await;
                        break;
                    }
                    _ => {}
                }

                // Screen-specific keys
                match app.screen {
                    Screen::Main => {
                        handle_main_keys(&mut app, &vpn, key.code).await;
                    }
                    Screen::Logs => {
                        handle_logs_keys(&mut app, key.code);
                    }
                    Screen::Servers => {
                        handle_servers_keys(&mut app, &vpn, key.code).await;
                    }
                    Screen::Settings => {
                        handle_settings_keys(&mut app, key.code);
                    }
                    Screen::Help => {
                        // Any key returns to main
                        if key.code != KeyCode::Char('q') && key.code != KeyCode::Esc {
                            app.screen = Screen::Main;
                        }
                    }
                }
            }
        }

        // Update animation
        if last_tick.elapsed() >= tick_rate {
            let mut app = state.write().await;
            app.angle = (app.angle + globe.angular_step()) % std::f32::consts::TAU;
            app.tick = app.tick.wrapping_add(1);
            last_tick = Instant::now();
        }
    }

    Ok(())
}

/// Handle main screen keys
async fn handle_main_keys(app: &mut AppState, vpn: &VpnController, key: KeyCode) {
    match key {
        // Connect/Disconnect toggle
        KeyCode::Char(' ') | KeyCode::Enter => {
            match app.conn_state {
                ConnectionState::Disconnected | ConnectionState::Error(_) => {
                    // Select server first if not configured
                    let config = vpn.config().await;
                    if config.server.host.is_empty() {
                        if let Some(server) = app.servers.get(app.selected_server) {
                            if !server.host.is_empty() {
                                vpn.set_server(server.clone()).await;
                            } else {
                                app.set_status("⚠ Configure server first (press 's')");
                                return;
                            }
                        }
                    }

                    app.set_status(">>> INITIALIZING SECURE TUNNEL...");
                    if let Err(e) = vpn.connect().await {
                        app.set_status(format!("✗ Connection failed: {}", e));
                    }
                }
                ConnectionState::Connected { .. } => {
                    app.set_status(">>> TERMINATING CONNECTION...");
                    if let Err(e) = vpn.disconnect().await {
                        app.set_status(format!("✗ Disconnect failed: {}", e));
                    } else {
                        app.set_status("✓ TUNNEL CLOSED");
                    }
                }
                ConnectionState::Connecting | ConnectionState::Reconnecting { .. } => {
                    app.set_status(">>> ABORTING CONNECTION...");
                    let _ = vpn.disconnect().await;
                }
            }
        }
        // Server selection
        KeyCode::Char('s') | KeyCode::Char('S') => {
            app.screen = Screen::Servers;
        }
        // View logs
        KeyCode::Char('l') | KeyCode::Char('L') => {
            app.screen = Screen::Logs;
        }
        // Open settings
        KeyCode::Char('o') | KeyCode::Char('O') => {
            app.screen = Screen::Settings;
            app.settings_selection = 0;
        }
        // Refresh external IP
        KeyCode::Char('i') | KeyCode::Char('I') => {
            app.set_status(">>> Fetching external IP...");
            if let Some(ip) = vpn.fetch_external_ip().await {
                app.set_status(format!("✓ External IP: {}", ip));
            } else {
                app.set_status("✗ Failed to fetch IP");
            }
        }
        // Measure latency
        KeyCode::Char('p') | KeyCode::Char('P') => {
            app.set_status(">>> Measuring latency...");
            if let Some(ms) = vpn.measure_latency().await {
                app.set_status(format!("✓ Latency: {} ms", ms));
            } else {
                app.set_status("✗ Ping failed");
            }
        }
        // Repair (reconnect)
        KeyCode::Char('r') | KeyCode::Char('R') => {
            if matches!(app.conn_state, ConnectionState::Error(_)) {
                app.set_status(">>> INITIATING RECOVERY PROTOCOL...");
                let _ = vpn.disconnect().await;
                tokio::time::sleep(Duration::from_millis(500)).await;
                if let Err(e) = vpn.connect().await {
                    app.set_status(format!("✗ Recovery failed: {}", e));
                }
            }
        }
        _ => {}
    }
}

/// Handle logs screen keys
fn handle_logs_keys(app: &mut AppState, key: KeyCode) {
    match key {
        KeyCode::Up | KeyCode::Char('k') => {
            app.log_scroll = app.log_scroll.saturating_add(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.log_scroll = app.log_scroll.saturating_sub(1);
        }
        KeyCode::PageUp => {
            app.log_scroll = app.log_scroll.saturating_add(10);
        }
        KeyCode::PageDown => {
            app.log_scroll = app.log_scroll.saturating_sub(10);
        }
        KeyCode::Home => {
            app.log_scroll = 1000; // Max scroll
        }
        KeyCode::End => {
            app.log_scroll = 0;
        }
        _ => {}
    }
}

/// Handle servers screen keys
async fn handle_servers_keys(app: &mut AppState, vpn: &VpnController, key: KeyCode) {
    match key {
        KeyCode::Up | KeyCode::Char('k') => {
            if app.selected_server > 0 {
                app.selected_server -= 1;
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if app.selected_server < app.servers.len().saturating_sub(1) {
                app.selected_server += 1;
            }
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            if let Some(server) = app.servers.get(app.selected_server) {
                if server.host.is_empty() {
                    // Custom server - enter input mode
                    app.input_mode = InputMode::ServerHost;
                    app.input_buffer.clear();
                    app.set_status("Enter server host:");
                } else {
                    vpn.set_server(server.clone()).await;
                    app.set_status(format!("✓ Selected: {}", server.name));
                    app.screen = Screen::Main;
                }
            }
        }
        KeyCode::Char('e') | KeyCode::Char('E') => {
            // Edit custom server
            app.input_mode = InputMode::ServerHost;
            app.input_buffer.clear();
        }
        _ => {}
    }
}

/// Handle settings screen keys
fn handle_settings_keys(app: &mut AppState, key: KeyCode) {
    const MAX_SETTINGS: usize = 7; // Total number of settings items

    match key {
        KeyCode::Up | KeyCode::Char('k') => {
            if app.settings_selection > 0 {
                app.settings_selection -= 1;
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if app.settings_selection < MAX_SETTINGS - 1 {
                app.settings_selection += 1;
            }
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            // Toggle boolean settings or cycle enums
            match app.settings_selection {
                0 => app.config.auto_connect = !app.config.auto_connect,
                1 => app.config.auto_reconnect = !app.config.auto_reconnect,
                2 => {
                    // Cycle max reconnect attempts: 3 -> 5 -> 10 -> 3
                    app.config.max_reconnect_attempts = match app.config.max_reconnect_attempts {
                        3 => 5,
                        5 => 10,
                        _ => 3,
                    };
                }
                3 => {
                    // Cycle TUN name: vpr0 -> vpr1 -> tun0 -> vpr0
                    app.config.tun_name = match app.config.tun_name.as_str() {
                        "vpr0" => "vpr1".into(),
                        "vpr1" => "tun0".into(),
                        _ => "vpr0".into(),
                    };
                }
                4 => app.config.insecure = !app.config.insecure,
                5 => {
                    // Cycle themes
                    app.config.theme = match app.config.theme {
                        crate::config::Theme::WatchDogs => crate::config::Theme::Matrix,
                        crate::config::Theme::Matrix => crate::config::Theme::Cyberpunk,
                        crate::config::Theme::Cyberpunk => crate::config::Theme::Minimal,
                        crate::config::Theme::Minimal => crate::config::Theme::WatchDogs,
                    };
                }
                6 => app.config.notifications = !app.config.notifications,
                _ => {}
            }
        }
        KeyCode::Char('s') | KeyCode::Char('S') => {
            // Save configuration
            match app.save_config() {
                Ok(_) => app.set_status("✓ Configuration saved"),
                Err(e) => app.set_status(format!("✗ Save failed: {}", e)),
            }
        }
        _ => {}
    }
}

/// Handle input submission
async fn handle_input_submit(app: &mut AppState) {
    match app.input_mode {
        InputMode::ServerHost => {
            if !app.input_buffer.is_empty() {
                // Find custom server entry and update
                if let Some(custom) = app.servers.iter_mut().find(|s| s.name == "Custom Server") {
                    custom.host = app.input_buffer.clone();
                }
                app.input_mode = InputMode::ServerPort;
                app.input_buffer = "443".to_string();
                app.set_status("Enter port (default 443):");
            }
        }
        InputMode::ServerPort => {
            let port: u16 = app.input_buffer.parse().unwrap_or(443);
            if let Some(custom) = app.servers.iter_mut().find(|s| s.name == "Custom Server") {
                custom.port = port;
            }
            app.input_mode = InputMode::Normal;
            app.input_buffer.clear();
            app.set_status("✓ Custom server configured");
        }
        InputMode::Normal => {}
    }
}

// Re-exports for backwards compatibility
pub use crate::render::{NetworkHealth, UiStats};
