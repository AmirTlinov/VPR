//! Хакерский TUI в стиле Watch Dogs 2
//! ASCII арт, глитч эффекты, реальная функциональность

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::app::{AppState, InputMode, Screen};
use crate::ascii_art::{
    get_doge_message, get_hacker_message, glitch_text, hacker_progress_bar, pulse, spinner, DOGE,
    SKULL,
};
use crate::globe::GlobeRenderer;
use crate::vpn::{ConnectionState, VpnController};

/// Network health status for TUI display (legacy)
#[derive(Debug, Clone, Default)]
pub enum NetworkHealth {
    #[default]
    Connected,
    Disconnected,
    OrphanedState {
        pending_changes: usize,
        crashed_at: Option<u64>,
    },
    Repairing,
}

pub struct UiStats {
    pub tick: u64,
    pub fps: u16,
    pub latency_ms: u16,
    pub throughput_mbps: u16,
    pub network_health: NetworkHealth,
}

// =============================================================================
// Main Screen
// =============================================================================

pub fn draw_main_screen(frame: &mut Frame<'_>, globe: &GlobeRenderer, area: Rect, app: &AppState) {
    let has_status = app.get_status().is_some();
    
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Length(if has_status { 1 } else { 0 }), // Status message
            Constraint::Min(10),    // Content
            Constraint::Length(2),  // Footer
        ])
        .split(area);

    render_header(frame, layout[0], app);
    
    if has_status {
        render_status_bar(frame, layout[1], app);
    }

    // Content: Globe (Left), Stats Panel (Right)
    let content_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(layout[2]);

    render_globe(frame, content_layout[0], globe, app);
    render_stats_panel(frame, content_layout[1], app);
    render_footer(frame, layout[3], app);
}

fn render_header(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let (status_text, status_color) = match &app.conn_state {
        ConnectionState::Connected { server, .. } => {
            (format!("▓▓▓ SECURE TUNNEL TO {} ▓▓▓", server), Color::Green)
        }
        ConnectionState::Disconnected => ("░░░ OFFLINE ░░░".into(), Color::DarkGray),
        ConnectionState::Connecting => (">>> CONNECTING... <<<".into(), Color::Yellow),
        ConnectionState::Reconnecting { attempt, max_attempts } => {
            (format!(">>> RECONNECTING {}/{} <<<", attempt, max_attempts), Color::Yellow)
        }
        ConnectionState::Error(e) => (format!("!!! ERROR: {} !!!", e), Color::Red),
    };

    // Глитч эффект для заголовка при подключении
    let glitched_status = if app.tick % 50 < 3 && matches!(app.conn_state, ConnectionState::Connecting) {
        glitch_text(&status_text, app.tick, 0.4)
    } else {
        status_text
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(
                " ██╗   ██╗██████╗ ██████╗  ",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {} ", spinner(app.tick)),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(
                glitched_status,
                Style::default()
                    .fg(status_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {} ", pulse(app.tick)),
                Style::default().fg(Color::Red),
            ),
            Span::styled(
                format!("T-{:05}", timestamp % 100000),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                " ╚████╔╝ ██║     ██║  ██║  ",
                Style::default().fg(Color::Magenta),
            ),
            Span::styled(
                match &app.conn_state {
                    ConnectionState::Connected { .. } => " [ENCRYPTED:ML-KEM768] ",
                    _ => " [STANDBY] ",
                },
                Style::default()
                    .fg(if matches!(app.conn_state, ConnectionState::Connected { .. }) {
                        Color::Green
                    } else {
                        Color::DarkGray
                    }),
            ),
            Span::styled(
                get_hacker_message(app.tick),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ];

    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(Color::DarkGray)),
        ),
        area,
    );
}

fn render_status_bar(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    if let Some(msg) = app.get_status() {
        let style = if msg.starts_with('✓') {
            Style::default().fg(Color::Green)
        } else if msg.starts_with('✗') || msg.contains("ERROR") {
            Style::default().fg(Color::Red)
        } else {
            Style::default().fg(Color::Yellow)
        };

        frame.render_widget(
            Paragraph::new(format!(" {} ", msg))
                .style(style)
                .alignment(Alignment::Center),
            area,
        );
    }
}

fn render_globe(frame: &mut Frame<'_>, area: Rect, globe: &GlobeRenderer, app: &AppState) {
    let inner_area = Rect {
        x: area.x + 1,
        y: area.y + 1,
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(2),
    };

    let ascii = globe.render_frame(
        inner_area.width as usize,
        inner_area.height as usize,
        app.angle,
        app.tick,
    );

    // Цвет глобуса меняется в зависимости от статуса
    let globe_color = match &app.conn_state {
        ConnectionState::Connected { .. } => Color::Cyan,
        ConnectionState::Disconnected => Color::DarkGray,
        ConnectionState::Connecting | ConnectionState::Reconnecting { .. } => Color::Yellow,
        ConnectionState::Error(_) => Color::Red,
    };

    let title = match &app.conn_state {
        ConnectionState::Connected { server, connected_at } => {
            let uptime = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_sub(*connected_at);
            format!(" ◉ {} │ UP: {}s ", server, uptime)
        }
        ConnectionState::Connecting => " ◉ ESTABLISHING TUNNEL... ".into(),
        _ => " ◉ GLOBAL_NETWORK_MAP ".into(),
    };

    frame.render_widget(
        ascii.to_paragraph().block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(title)
                .title_style(Style::default().fg(globe_color)),
        ),
        area,
    );
}

fn render_stats_panel(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let blocks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),  // Connection Info
            Constraint::Length(7),  // Network Stats
            Constraint::Length(8),  // ASCII Art
            Constraint::Min(4),     // System Tasks
        ])
        .split(area);

    render_connection_info(frame, blocks[0], app);
    render_network_stats(frame, blocks[1], app);
    render_ascii_art(frame, blocks[2], app);
    render_system_tasks(frame, blocks[3], app);
}

fn render_connection_info(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let metrics = &app.metrics;
    
    let (status_icon, status_color) = match &app.conn_state {
        ConnectionState::Connected { .. } => ("●", Color::Green),
        ConnectionState::Connecting => ("◐", Color::Yellow),
        ConnectionState::Disconnected => ("○", Color::DarkGray),
        ConnectionState::Reconnecting { .. } => ("◑", Color::Yellow),
        ConnectionState::Error(_) => ("✗", Color::Red),
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(" STATUS:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(status_icon, Style::default().fg(status_color)),
            Span::styled(
                format!(" {}", match &app.conn_state {
                    ConnectionState::Connected { .. } => "CONNECTED",
                    ConnectionState::Connecting => "CONNECTING",
                    ConnectionState::Disconnected => "OFFLINE",
                    ConnectionState::Reconnecting { .. } => "RECONNECTING",
                    ConnectionState::Error(_) => "ERROR",
                }),
                Style::default().fg(status_color).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(" EXT_IP:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                if metrics.external_ip.is_empty() { "---".into() } else { metrics.external_ip.clone() },
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::styled(" TUNNEL:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                if metrics.tun_interface.is_empty() { "---" } else { &metrics.tun_interface },
                Style::default().fg(Color::Magenta),
            ),
        ]),
        Line::from(vec![
            Span::styled(" LOCATION: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                if metrics.server_location.is_empty() { "Unknown" } else { &metrics.server_location },
                Style::default().fg(Color::Yellow),
            ),
        ]),
    ];

    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" ◈ CONNECTION ◈ "),
        ),
        area,
    );
}

fn render_network_stats(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let metrics = &app.metrics;
    
    // Calculate progress bars based on real metrics
    let upload_mbps = metrics.upload_speed as f32 / 125_000.0; // Convert bytes/s to Mbps
    let download_mbps = metrics.download_speed as f32 / 125_000.0;
    let upload_progress = (upload_mbps / 100.0).min(1.0); // Assume 100 Mbps max
    let download_progress = (download_mbps / 100.0).min(1.0);
    let latency_progress = 1.0 - (metrics.latency_ms as f32 / 200.0).min(1.0);

    let lines = vec![
        Line::from(vec![
            Span::styled(" ▲ UPLOAD:   ", Style::default().fg(Color::Green)),
            Span::styled(
                hacker_progress_bar(upload_progress, 15),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(
                format!(" {:.1} Mbps", upload_mbps),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled(" ▼ DOWNLOAD: ", Style::default().fg(Color::Blue)),
            Span::styled(
                hacker_progress_bar(download_progress, 15),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(
                format!(" {:.1} Mbps", download_mbps),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled(" ◉ LATENCY:  ", Style::default().fg(Color::Yellow)),
            Span::styled(
                hacker_progress_bar(latency_progress, 15),
                Style::default().fg(if metrics.latency_ms < 50 {
                    Color::Green
                } else if metrics.latency_ms < 100 {
                    Color::Yellow
                } else {
                    Color::Red
                }),
            ),
            Span::styled(
                format!(" {} ms", metrics.latency_ms),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled(" ⚡ TRAFFIC: ", Style::default().fg(Color::Magenta)),
            Span::styled(
                format!("↑{} ↓{}", 
                    format_bytes(metrics.bytes_sent),
                    format_bytes(metrics.bytes_received)
                ),
                Style::default().fg(Color::White),
            ),
        ]),
    ];

    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" ◈ NET_STATS ◈ "),
        ),
        area,
    );
}

fn render_ascii_art(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    // Показываем Doge когда подключены, Skull когда отключены
    let show_doge = matches!(app.conn_state, ConnectionState::Connected { .. });

    let art: Vec<Line> = if show_doge {
        DOGE.iter()
            .take(area.height as usize - 2)
            .enumerate()
            .map(|(i, line)| {
                let color = if i % 2 == 0 {
                    Color::Yellow
                } else {
                    Color::Rgb(255, 200, 100)
                };
                Line::from(Span::styled(*line, Style::default().fg(color)))
            })
            .collect()
    } else {
        SKULL
            .iter()
            .take(area.height as usize - 2)
            .map(|line| Line::from(Span::styled(*line, Style::default().fg(Color::Red))))
            .collect()
    };

    let title = if show_doge {
        format!(
            " {} {} ",
            get_doge_message(app.tick),
            get_doge_message(app.tick + 7)
        )
    } else {
        " ☠ AWAITING ORDERS ☠ ".to_string()
    };

    frame.render_widget(
        Paragraph::new(art).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if show_doge {
                    Color::Yellow
                } else {
                    Color::Red
                }))
                .title(title),
        ),
        area,
    );
}

fn render_system_tasks(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let connected = matches!(app.conn_state, ConnectionState::Connected { .. });
    
    let tasks = if connected {
        vec![
            ("noise_handshake", "COMPLETE", Color::Green),
            ("ml_kem_768", "ACTIVE", Color::Cyan),
            ("dpi_evasion", "ENGAGED", Color::Magenta),
            ("traffic_morph", "RUNNING", Color::Yellow),
        ]
    } else {
        vec![
            ("noise_handshake", "STANDBY", Color::DarkGray),
            ("ml_kem_768", "READY", Color::DarkGray),
            ("dpi_evasion", "STANDBY", Color::DarkGray),
            ("traffic_morph", "IDLE", Color::DarkGray),
        ]
    };

    let lines: Vec<Line> = tasks
        .iter()
        .enumerate()
        .map(|(i, (name, status, color))| {
            let blink = (app.tick / 5 + i as u64) % 3 == 0 && connected;
            let prefix = if blink { "▶" } else { "►" };

            Line::from(vec![
                Span::styled(format!(" {} ", prefix), Style::default().fg(*color)),
                Span::styled(format!("{:<14}", name), Style::default().fg(Color::White)),
                Span::styled(
                    format!("[{}]", status),
                    Style::default().fg(*color).add_modifier(if blink {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
                ),
            ])
        })
        .collect();

    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(" ⚙ SYSTEM ⚙ "),
        ),
        area,
    );
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let msg = get_hacker_message(app.tick);
    let len = msg.len();
    let offset = (app.tick / 2) as usize % len.max(1);
    let _scrolled = if len > 0 {
        format!("{}{}", &msg[offset..], &msg[..offset])
    } else {
        String::new()
    };

    let action_key = match &app.conn_state {
        ConnectionState::Connected { .. } => "[SPACE: DISCONNECT]",
        ConnectionState::Disconnected | ConnectionState::Error(_) => "[SPACE: CONNECT]",
        _ => "[SPACE: ABORT]",
    };

    let action_style = match &app.conn_state {
        ConnectionState::Connected { .. } => Style::default().fg(Color::Red),
        ConnectionState::Disconnected | ConnectionState::Error(_) => Style::default().fg(Color::Green),
        _ => Style::default().fg(Color::Yellow),
    };

    let spans = vec![
        Span::styled(
            format!(" {} ", spinner(app.tick)),
            Style::default().fg(Color::Yellow),
        ),
        Span::styled(action_key, action_style.add_modifier(Modifier::BOLD)),
        Span::styled(" [S: SERVERS] ", Style::default().fg(Color::Cyan)),
        Span::styled(" [L: LOGS] ", Style::default().fg(Color::Magenta)),
        Span::styled(" [O: SETTINGS] ", Style::default().fg(Color::Yellow)),
        Span::styled(" [?: HELP] ", Style::default().fg(Color::Blue)),
        Span::styled(" [Q: EXIT] ", Style::default().fg(Color::Red)),
        Span::styled(
            format!(" // {} ", get_doge_message(app.tick + 3)),
            Style::default().fg(Color::Yellow),
        ),
    ];

    frame.render_widget(
        Paragraph::new(Line::from(spans)).block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(Color::DarkGray)),
        ),
        area,
    );
}

// =============================================================================
// Logs Screen
// =============================================================================

pub fn draw_logs_screen(frame: &mut Frame<'_>, area: Rect, app: &AppState, _vpn: &Arc<VpnController>) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(area);

    // Header
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    " ████ VPR SYSTEM LOGS ████ ",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" {} entries ", 1000), // Would need async here
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
        ])
        .block(Block::default().borders(Borders::BOTTOM)),
        layout[0],
    );

    // Logs content (placeholder - needs async runtime)
    let log_lines: Vec<ListItem> = (0..20)
        .map(|i| {
            let level = if i % 5 == 0 { "ERROR" } else if i % 3 == 0 { "WARN" } else { "INFO" };
            let color = match level {
                "ERROR" => Color::Red,
                "WARN" => Color::Yellow,
                _ => Color::Green,
            };
            
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("[{:05}] ", app.tick.wrapping_sub(i as u64 * 10)),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("{:<5} ", level),
                    Style::default().fg(color),
                ),
                Span::styled(
                    get_hacker_message(app.tick + i as u64),
                    Style::default().fg(Color::White),
                ),
            ]))
        })
        .collect();

    frame.render_widget(
        List::new(log_lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray))
                    .title(" LIVE_LOG_STREAM "),
            ),
        layout[1],
    );

    // Footer
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" [↑/↓: SCROLL] ", Style::default().fg(Color::Cyan)),
            Span::styled(" [PGUP/PGDN: PAGE] ", Style::default().fg(Color::Cyan)),
            Span::styled(" [HOME/END: JUMP] ", Style::default().fg(Color::Cyan)),
            Span::styled(" [Q/ESC: BACK] ", Style::default().fg(Color::Red)),
        ]))
        .block(Block::default().borders(Borders::TOP)),
        layout[2],
    );
}

// =============================================================================
// Servers Screen
// =============================================================================

pub fn draw_servers_screen(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(if app.input_mode != InputMode::Normal { 3 } else { 0 }),
            Constraint::Length(2),
        ])
        .split(area);

    // Header
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    " ████ SERVER SELECTION ████ ",
                    Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
                ),
            ]),
        ])
        .block(Block::default().borders(Borders::BOTTOM)),
        layout[0],
    );

    // Server list
    let server_items: Vec<ListItem> = app
        .servers
        .iter()
        .enumerate()
        .map(|(i, server)| {
            let selected = i == app.selected_server;
            let prefix = if selected { "▶ " } else { "  " };
            
            let style = if selected {
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            let host_display = if server.host.is_empty() {
                "<not configured>".to_string()
            } else {
                format!("{}:{}", server.host, server.port)
            };

            ListItem::new(Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(format!("{:<20}", server.name), style),
                Span::styled(
                    format!(" {} ", server.location),
                    Style::default().fg(Color::Yellow),
                ),
                Span::styled(
                    format!(" [{}]", host_display),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect();

    frame.render_widget(
        List::new(server_items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Magenta))
                    .title(" AVAILABLE_NODES "),
            ),
        layout[1],
    );

    // Input field
    if app.input_mode != InputMode::Normal {
        let label = match app.input_mode {
            InputMode::ServerHost => "Server Host: ",
            InputMode::ServerPort => "Port: ",
            InputMode::Normal => "",
        };

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(label, Style::default().fg(Color::Yellow)),
                Span::styled(&app.input_buffer, Style::default().fg(Color::White)),
                Span::styled("█", Style::default().fg(Color::Cyan)), // Cursor
            ]))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow))
                    .title(" INPUT "),
            ),
            layout[2],
        );
    }

    // Footer
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" [↑/↓: SELECT] ", Style::default().fg(Color::Cyan)),
            Span::styled(" [ENTER: CHOOSE] ", Style::default().fg(Color::Green)),
            Span::styled(" [E: EDIT CUSTOM] ", Style::default().fg(Color::Yellow)),
            Span::styled(" [Q/ESC: BACK] ", Style::default().fg(Color::Red)),
        ]))
        .block(Block::default().borders(Borders::TOP)),
        layout[3],
    );
}

// =============================================================================
// Help Screen
// =============================================================================

pub fn draw_help_screen(frame: &mut Frame<'_>, area: Rect, _app: &AppState) {
    let help_text = vec![
        "",
        "  ██╗  ██╗███████╗██╗     ██████╗ ",
        "  ██║  ██║██╔════╝██║     ██╔══██╗",
        "  ███████║█████╗  ██║     ██████╔╝",
        "  ██╔══██║██╔══╝  ██║     ██╔═══╝ ",
        "  ██║  ██║███████╗███████╗██║     ",
        "  ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ",
        "",
        "  ═══════════════════════════════════════",
        "  MAIN SCREEN COMMANDS:",
        "  ═══════════════════════════════════════",
        "  SPACE/ENTER  Connect or Disconnect",
        "  S            Server selection menu",
        "  L            View system logs",
        "  I            Fetch external IP",
        "  P            Measure latency (ping)",
        "  R            Repair/reconnect (on error)",
        "  ?/F1         This help screen",
        "  Q/ESC        Quit application",
        "  Ctrl+C       Force quit",
        "",
        "  ═══════════════════════════════════════",
        "  NAVIGATION:",
        "  ═══════════════════════════════════════",
        "  ↑/↓ or J/K   Navigate lists",
        "  PgUp/PgDn    Scroll pages",
        "  Home/End     Jump to start/end",
        "",
        "  Press any key to return...",
    ];

    let lines: Vec<Line> = help_text
        .iter()
        .map(|s| {
            if s.contains('═') || s.contains('╗') || s.contains('╔') {
                Line::from(Span::styled(*s, Style::default().fg(Color::Magenta)))
            } else if s.contains("SPACE") || s.contains("ENTER") {
                Line::from(Span::styled(*s, Style::default().fg(Color::Green)))
            } else if s.starts_with("  ") && s.len() > 3 && s.chars().nth(2).map(|c| c.is_uppercase()).unwrap_or(false) {
                Line::from(Span::styled(*s, Style::default().fg(Color::Cyan)))
            } else {
                Line::from(Span::styled(*s, Style::default().fg(Color::White)))
            }
        })
        .collect();

    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .title(" ◉ VPR HACKER MANUAL ◉ "),
            )
            .alignment(Alignment::Left)
            .wrap(Wrap { trim: false }),
        area,
    );
}

// =============================================================================
// Settings Screen
// =============================================================================

pub fn draw_settings_screen(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Min(15),    // Settings content
            Constraint::Length(2),  // Footer
        ])
        .split(area);

    // Header
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    " ████ SYSTEM CONFIGURATION ████ ",
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
            ]),
        ])
        .block(Block::default().borders(Borders::BOTTOM)),
        layout[0],
    );

    // Settings panels - split into two columns
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(layout[1]);

    // Left column - Connection settings
    render_connection_settings(frame, columns[0], app);

    // Right column - Appearance settings
    render_appearance_settings(frame, columns[1], app);

    // Footer
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" [↑/↓: NAVIGATE] ", Style::default().fg(Color::Cyan)),
            Span::styled(" [ENTER: TOGGLE/EDIT] ", Style::default().fg(Color::Green)),
            Span::styled(" [S: SAVE] ", Style::default().fg(Color::Yellow)),
            Span::styled(" [Q/ESC: BACK] ", Style::default().fg(Color::Red)),
        ]))
        .block(Block::default().borders(Borders::TOP)),
        layout[2],
    );
}

fn render_connection_settings(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let config = &app.config;
    let selected = app.settings_selection;
    
    // Pre-compute string values to avoid temporary lifetime issues
    let reconnect_str = config.max_reconnect_attempts.to_string();
    let tun_str = config.tun_name.clone();
    
    let items = vec![
        setting_item("Auto-connect on start", if config.auto_connect { "ON" } else { "OFF" }, 
                    if config.auto_connect { Color::Green } else { Color::DarkGray }, selected == 0),
        setting_item("Auto-reconnect", if config.auto_reconnect { "ON" } else { "OFF" },
                    if config.auto_reconnect { Color::Green } else { Color::DarkGray }, selected == 1),
        setting_item("Max reconnect attempts", &reconnect_str, 
                    Color::Cyan, selected == 2),
        setting_item("TUN interface name", &tun_str, Color::Magenta, selected == 3),
        setting_item("Insecure mode (no cert)", if config.insecure { "ON" } else { "OFF" },
                    if config.insecure { Color::Red } else { Color::Green }, selected == 4),
    ];

    frame.render_widget(
        List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .title(" ◈ CONNECTION ◈ "),
            ),
        area,
    );
}

fn render_appearance_settings(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let config = &app.config;
    let selected = app.settings_selection;
    
    let theme_name = match config.theme {
        crate::config::Theme::WatchDogs => "Watch Dogs",
        crate::config::Theme::Matrix => "Matrix",
        crate::config::Theme::Cyberpunk => "Cyberpunk",
        crate::config::Theme::Minimal => "Minimal",
    };
    
    let config_path = format!("{:?}", crate::config::TuiConfig::config_path());

    let items: Vec<ListItem> = vec![
        setting_item("Theme", theme_name, Color::Magenta, selected == 5),
        setting_item("Notifications", if config.notifications { "ON" } else { "OFF" },
                    if config.notifications { Color::Green } else { Color::DarkGray }, selected == 6),
        ListItem::new(Line::from("")),
        ListItem::new(Line::from(vec![
            Span::styled("  Config path: ", Style::default().fg(Color::DarkGray)),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled(
                format!("  {}", config_path),
                Style::default().fg(Color::DarkGray),
            ),
        ])),
    ];

    frame.render_widget(
        List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow))
                    .title(" ◈ APPEARANCE ◈ "),
            ),
        area,
    );
}

fn setting_item(label: &str, value: &str, value_color: Color, selected: bool) -> ListItem<'static> {
    let prefix = if selected { "▶ " } else { "  " };
    let style = if selected {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    
    ListItem::new(Line::from(vec![
        Span::styled(prefix.to_string(), style.fg(Color::Cyan)),
        Span::styled(format!("{:<24}", label), style.fg(Color::White)),
        Span::styled(format!("[{}]", value), style.fg(value_color)),
    ]))
}

// =============================================================================
// Utilities
// =============================================================================

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.1}GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.1}MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1}KB", bytes as f64 / 1_000.0)
    } else {
        format!("{}B", bytes)
    }
}

// =============================================================================
// Legacy draw function for backwards compatibility
// =============================================================================

pub fn draw(frame: &mut Frame<'_>, globe: &GlobeRenderer, area: Rect, angle: f32, stats: UiStats) {
    // Create a minimal app state for legacy interface
    let app = AppState {
        screen: Screen::Main,
        tick: stats.tick,
        angle,
        vpn: Arc::new(VpnController::new(crate::vpn::ControllerConfig::default())),
        conn_state: match stats.network_health {
            NetworkHealth::Connected => ConnectionState::Connected {
                server: "legacy".into(),
                connected_at: 0,
            },
            NetworkHealth::Disconnected => ConnectionState::Disconnected,
            NetworkHealth::OrphanedState { .. } => ConnectionState::Error("Orphaned".into()),
            NetworkHealth::Repairing => ConnectionState::Connecting,
        },
        metrics: crate::vpn::VpnMetrics {
            latency_ms: stats.latency_ms as u32,
            upload_speed: (stats.throughput_mbps as u64) * 125_000,
            ..Default::default()
        },
        servers: vec![],
        selected_server: 0,
        log_scroll: 0,
        show_help: false,
        status_message: None,
        input_mode: InputMode::Normal,
        input_buffer: String::new(),
        config: crate::config::TuiConfig::default(),
        settings_selection: 0,
    };

    draw_main_screen(frame, globe, area, &app);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn network_health_default_is_connected() {
        let health = NetworkHealth::default();
        assert!(matches!(health, NetworkHealth::Connected));
    }

    #[test]
    fn format_bytes_works() {
        assert_eq!(format_bytes(500), "500B");
        assert_eq!(format_bytes(1500), "1.5KB");
        assert_eq!(format_bytes(1_500_000), "1.5MB");
        assert_eq!(format_bytes(1_500_000_000), "1.5GB");
    }

    #[test]
    fn draw_does_not_panic() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let globe = crate::globe::GlobeRenderer::new(200, 0.3, 0.2);
        let stats = UiStats {
            tick: 1,
            fps: 60,
            latency_ms: 10,
            throughput_mbps: 900,
            network_health: NetworkHealth::Connected,
        };

        terminal
            .draw(|f| {
                draw(f, &globe, f.size(), 0.0, stats);
            })
            .unwrap();
    }
}
