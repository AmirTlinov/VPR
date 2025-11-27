//! TUI-Tauri Bridge
//!
//! Renders the vpr-tui to ANSI strings for display in xterm.js

use ratatui::backend::TestBackend;
use ratatui::Terminal;
use std::sync::Arc;
use tokio::sync::RwLock;
use vpr_tui::app::{AppState, Screen};
use vpr_tui::config::TuiConfig;
use vpr_tui::globe::GlobeRenderer;
use vpr_tui::render::{
    draw_help_screen, draw_logs_screen, draw_main_screen, draw_servers_screen, draw_settings_screen,
};
use vpr_tui::vpn::{ConnectionState, VpnController};

/// TUI state managed by Tauri
pub struct TuiState {
    pub app: Arc<RwLock<AppState>>,
    pub globe: GlobeRenderer,
    pub vpn: Arc<VpnController>,
}

impl TuiState {
    pub fn new() -> Self {
        let config = TuiConfig::load();
        let controller_config = config.to_controller_config();
        let vpn = Arc::new(VpnController::new(controller_config));
        let app = Arc::new(RwLock::new(AppState::new(vpn.clone(), config)));
        let globe = GlobeRenderer::new(200, 0.3, 0.2);

        Self { app, globe, vpn }
    }

    /// Render current frame as ANSI string
    pub async fn render_frame(&self, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();

        let app = self.app.read().await;

        terminal
            .draw(|frame| {
                let area = frame.size();

                match app.screen {
                    Screen::Main => draw_main_screen(frame, &self.globe, area, &app),
                    Screen::Logs => draw_logs_screen(frame, area, &app, &self.vpn),
                    Screen::Servers => draw_servers_screen(frame, area, &app),
                    Screen::Settings => draw_settings_screen(frame, area, &app),
                    Screen::Help => draw_help_screen(frame, area, &app),
                }
            })
            .ok();

        // Convert TestBackend buffer to ANSI string
        let backend = terminal.backend();
        buffer_to_ansi(backend.buffer())
    }

    /// Update animation tick
    pub async fn tick(&self) {
        let mut app = self.app.write().await;
        app.angle = (app.angle + self.globe.angular_step()) % std::f32::consts::TAU;
        app.tick = app.tick.wrapping_add(1);

        // Sync connection state from VPN controller
        app.conn_state = self.vpn.state().await;
        app.metrics = self.vpn.metrics().await;
    }

    /// Handle key press
    pub async fn handle_key(&self, key: &str) -> bool {
        use crossterm::event::KeyCode;

        let key_code = match key {
            "Space" | " " => KeyCode::Char(' '),
            "Enter" => KeyCode::Enter,
            "Escape" | "Esc" => KeyCode::Esc,
            "ArrowUp" | "Up" => KeyCode::Up,
            "ArrowDown" | "Down" => KeyCode::Down,
            "ArrowLeft" | "Left" => KeyCode::Left,
            "ArrowRight" | "Right" => KeyCode::Right,
            "Tab" => KeyCode::Tab,
            "Backspace" => KeyCode::Backspace,
            "Delete" => KeyCode::Delete,
            "Home" => KeyCode::Home,
            "End" => KeyCode::End,
            "PageUp" => KeyCode::PageUp,
            "PageDown" => KeyCode::PageDown,
            "F1" => KeyCode::F(1),
            k if k.len() == 1 => KeyCode::Char(k.chars().next().unwrap()),
            _ => return false,
        };

        let mut app = self.app.write().await;

        // Global keys
        match key_code {
            KeyCode::Char('q') | KeyCode::Esc => {
                if app.screen != Screen::Main {
                    app.screen = Screen::Main;
                    return true;
                }
                // Signal to close app
                return false; // Let JS handle quit
            }
            KeyCode::Char('?') | KeyCode::F(1) => {
                app.screen = Screen::Help;
                return true;
            }
            _ => {}
        }

        // Screen-specific keys
        match app.screen {
            Screen::Main => {
                self.handle_main_key(&mut app, key_code).await;
            }
            Screen::Logs => {
                handle_logs_key(&mut app, key_code);
            }
            Screen::Servers => {
                self.handle_servers_key(&mut app, key_code).await;
            }
            Screen::Settings => {
                handle_settings_key(&mut app, key_code);
            }
            Screen::Help => {
                // Any key returns to main
                app.screen = Screen::Main;
            }
        }

        true
    }

    async fn handle_main_key(&self, app: &mut AppState, key: crossterm::event::KeyCode) {
        use crossterm::event::KeyCode;

        match key {
            KeyCode::Char(' ') | KeyCode::Enter => match &app.conn_state {
                ConnectionState::Disconnected | ConnectionState::Error(_) => {
                    app.set_status(">>> INITIALIZING SECURE TUNNEL...");
                    if let Err(e) = self.vpn.connect().await {
                        app.set_status(format!("✗ Connection failed: {}", e));
                    }
                }
                ConnectionState::Connected { .. } => {
                    app.set_status(">>> TERMINATING CONNECTION...");
                    if let Err(e) = self.vpn.disconnect().await {
                        app.set_status(format!("✗ Disconnect failed: {}", e));
                    } else {
                        app.set_status("✓ TUNNEL CLOSED");
                    }
                }
                _ => {
                    app.set_status(">>> ABORTING...");
                    let _ = self.vpn.disconnect().await;
                }
            },
            KeyCode::Char('s') | KeyCode::Char('S') => {
                app.screen = Screen::Servers;
            }
            KeyCode::Char('l') | KeyCode::Char('L') => {
                app.screen = Screen::Logs;
            }
            KeyCode::Char('o') | KeyCode::Char('O') => {
                app.screen = Screen::Settings;
                app.settings_selection = 0;
            }
            KeyCode::Char('i') | KeyCode::Char('I') => {
                app.set_status(">>> Fetching external IP...");
                if let Some(ip) = self.vpn.fetch_external_ip().await {
                    app.set_status(format!("✓ External IP: {}", ip));
                } else {
                    app.set_status("✗ Failed to fetch IP");
                }
            }
            KeyCode::Char('p') | KeyCode::Char('P') => {
                app.set_status(">>> Measuring latency...");
                if let Some(ms) = self.vpn.measure_latency().await {
                    app.set_status(format!("✓ Latency: {} ms", ms));
                } else {
                    app.set_status("✗ Ping failed");
                }
            }
            _ => {}
        }
    }

    async fn handle_servers_key(&self, app: &mut AppState, key: crossterm::event::KeyCode) {
        use crossterm::event::KeyCode;

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
                if let Some(server) = app.servers.get(app.selected_server).cloned() {
                    if !server.host.is_empty() {
                        self.vpn.set_server(server.clone()).await;
                        app.set_status(format!("✓ Selected: {}", server.name));
                        app.screen = Screen::Main;
                    }
                }
            }
            _ => {}
        }
    }
}

fn handle_logs_key(app: &mut AppState, key: crossterm::event::KeyCode) {
    use crossterm::event::KeyCode;

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
        _ => {}
    }
}

fn handle_settings_key(app: &mut AppState, key: crossterm::event::KeyCode) {
    use crossterm::event::KeyCode;
    const MAX_SETTINGS: usize = 7;

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
        KeyCode::Enter | KeyCode::Char(' ') => match app.settings_selection {
            0 => app.config.auto_connect = !app.config.auto_connect,
            1 => app.config.auto_reconnect = !app.config.auto_reconnect,
            2 => {
                app.config.max_reconnect_attempts = match app.config.max_reconnect_attempts {
                    3 => 5,
                    5 => 10,
                    _ => 3,
                };
            }
            3 => {
                app.config.tun_name = match app.config.tun_name.as_str() {
                    "vpr0" => "vpr1".into(),
                    "vpr1" => "tun0".into(),
                    _ => "vpr0".into(),
                };
            }
            4 => app.config.insecure = !app.config.insecure,
            5 => {
                app.config.theme = match app.config.theme {
                    vpr_tui::config::Theme::WatchDogs => vpr_tui::config::Theme::Matrix,
                    vpr_tui::config::Theme::Matrix => vpr_tui::config::Theme::Cyberpunk,
                    vpr_tui::config::Theme::Cyberpunk => vpr_tui::config::Theme::Minimal,
                    vpr_tui::config::Theme::Minimal => vpr_tui::config::Theme::WatchDogs,
                };
            }
            6 => app.config.notifications = !app.config.notifications,
            _ => {}
        },
        KeyCode::Char('s') | KeyCode::Char('S') => match app.save_config() {
            Ok(_) => app.set_status("✓ Configuration saved"),
            Err(e) => app.set_status(format!("✗ Save failed: {}", e)),
        },
        _ => {}
    }
}

/// Convert ratatui buffer to ANSI escape string for xterm.js
fn buffer_to_ansi(buffer: &ratatui::buffer::Buffer) -> String {
    use ratatui::style::{Color, Modifier};
    use std::fmt::Write;

    let mut output =
        String::with_capacity(buffer.area.width as usize * buffer.area.height as usize * 20);

    // Clear screen and move cursor home
    output.push_str("\x1b[2J\x1b[H");

    let mut prev_fg = Color::Reset;
    let mut prev_bg = Color::Reset;
    let mut prev_mods = Modifier::empty();

    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            let cell = buffer.get(x, y);
            let fg = cell.fg;
            let bg = cell.bg;
            let mods = cell.modifier;

            // Build escape sequence if style changed
            if fg != prev_fg || bg != prev_bg || mods != prev_mods {
                output.push_str("\x1b[0m"); // Reset first

                // Set modifiers
                if mods.contains(Modifier::BOLD) {
                    output.push_str("\x1b[1m");
                }
                if mods.contains(Modifier::DIM) {
                    output.push_str("\x1b[2m");
                }
                if mods.contains(Modifier::ITALIC) {
                    output.push_str("\x1b[3m");
                }
                if mods.contains(Modifier::UNDERLINED) {
                    output.push_str("\x1b[4m");
                }

                // Set foreground color
                match fg {
                    Color::Reset => {}
                    Color::Black => output.push_str("\x1b[30m"),
                    Color::Red => output.push_str("\x1b[31m"),
                    Color::Green => output.push_str("\x1b[32m"),
                    Color::Yellow => output.push_str("\x1b[33m"),
                    Color::Blue => output.push_str("\x1b[34m"),
                    Color::Magenta => output.push_str("\x1b[35m"),
                    Color::Cyan => output.push_str("\x1b[36m"),
                    Color::Gray => output.push_str("\x1b[37m"),
                    Color::DarkGray => output.push_str("\x1b[90m"),
                    Color::LightRed => output.push_str("\x1b[91m"),
                    Color::LightGreen => output.push_str("\x1b[92m"),
                    Color::LightYellow => output.push_str("\x1b[93m"),
                    Color::LightBlue => output.push_str("\x1b[94m"),
                    Color::LightMagenta => output.push_str("\x1b[95m"),
                    Color::LightCyan => output.push_str("\x1b[96m"),
                    Color::White => output.push_str("\x1b[97m"),
                    Color::Rgb(r, g, b) => {
                        let _ = write!(output, "\x1b[38;2;{};{};{}m", r, g, b);
                    }
                    Color::Indexed(i) => {
                        let _ = write!(output, "\x1b[38;5;{}m", i);
                    }
                }

                // Set background color
                match bg {
                    Color::Reset => {}
                    Color::Black => output.push_str("\x1b[40m"),
                    Color::Red => output.push_str("\x1b[41m"),
                    Color::Green => output.push_str("\x1b[42m"),
                    Color::Yellow => output.push_str("\x1b[43m"),
                    Color::Blue => output.push_str("\x1b[44m"),
                    Color::Magenta => output.push_str("\x1b[45m"),
                    Color::Cyan => output.push_str("\x1b[46m"),
                    Color::Gray => output.push_str("\x1b[47m"),
                    Color::DarkGray => output.push_str("\x1b[100m"),
                    Color::LightRed => output.push_str("\x1b[101m"),
                    Color::LightGreen => output.push_str("\x1b[102m"),
                    Color::LightYellow => output.push_str("\x1b[103m"),
                    Color::LightBlue => output.push_str("\x1b[104m"),
                    Color::LightMagenta => output.push_str("\x1b[105m"),
                    Color::LightCyan => output.push_str("\x1b[106m"),
                    Color::White => output.push_str("\x1b[107m"),
                    Color::Rgb(r, g, b) => {
                        let _ = write!(output, "\x1b[48;2;{};{};{}m", r, g, b);
                    }
                    Color::Indexed(i) => {
                        let _ = write!(output, "\x1b[48;5;{}m", i);
                    }
                }

                prev_fg = fg;
                prev_bg = bg;
                prev_mods = mods;
            }

            // Output the character
            output.push_str(cell.symbol());
        }
        output.push_str("\r\n");
    }

    // Reset at end
    output.push_str("\x1b[0m");

    output
}
