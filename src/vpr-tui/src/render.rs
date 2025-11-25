//! Хакерский TUI в стиле Watch Dogs 2
//! ASCII арт, глитч эффекты, мемы

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ascii_art::{
    self, glitch_text, get_doge_message, get_hacker_message, hacker_progress_bar, pulse, spinner,
    DOGE, SKULL, VPR_LOGO,
};
use crate::globe::GlobeRenderer;

/// Network health status for TUI display
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

pub fn draw(frame: &mut Frame<'_>, globe: &GlobeRenderer, area: Rect, angle: f32, stats: UiStats) {
    let needs_warning = matches!(stats.network_health, NetworkHealth::OrphanedState { .. });

    let layout = if needs_warning {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Header (bigger for logo)
                Constraint::Length(3),  // Warning banner
                Constraint::Min(10),    // Content
                Constraint::Length(2),  // Footer
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Header
                Constraint::Length(0),  // No warning
                Constraint::Min(10),    // Content
                Constraint::Length(2),  // Footer
            ])
            .split(area)
    };

    render_hacker_header(frame, layout[0], &stats);

    if needs_warning {
        render_orphaned_warning(frame, layout[1], &stats.network_health);
    }

    let (content_idx, footer_idx) = (2, 3);

    // Content: Globe (Left), Hacker Panel (Right)
    let content_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(layout[content_idx]);

    render_globe_with_effects(frame, content_layout[0], globe, angle, &stats);
    render_hacker_panel(frame, content_layout[1], &stats);
    render_hacker_footer(frame, layout[footer_idx], &stats);
}

fn render_hacker_header(frame: &mut Frame<'_>, area: Rect, stats: &UiStats) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let (status_text, status_color) = match &stats.network_health {
        NetworkHealth::Connected => ("▓▓▓ SECURE TUNNEL ACTIVE ▓▓▓", Color::Green),
        NetworkHealth::Disconnected => ("░░░ OFFLINE ░░░", Color::DarkGray),
        NetworkHealth::OrphanedState { .. } => ("!!! RECOVERY NEEDED !!!", Color::Yellow),
        NetworkHealth::Repairing => (">>> REPAIRING <<<", Color::Cyan),
    };

    // Глитч эффект для заголовка
    let glitched_status = if stats.tick % 50 < 3 {
        glitch_text(status_text, stats.tick, 0.3)
    } else {
        status_text.to_string()
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(
                " ██╗   ██╗██████╗ ██████╗  ",
                Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {} ", spinner(stats.tick)),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(
                glitched_status,
                Style::default().fg(status_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {} ", pulse(stats.tick)),
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
                format!(" [ENCRYPTED:ML-KEM768] "),
                Style::default().fg(Color::Green).add_modifier(Modifier::RAPID_BLINK),
            ),
            Span::styled(
                get_hacker_message(stats.tick),
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

fn render_orphaned_warning(frame: &mut Frame<'_>, area: Rect, health: &NetworkHealth) {
    if let NetworkHealth::OrphanedState {
        pending_changes,
        crashed_at,
    } = health
    {
        let skull_line = SKULL.get(5).unwrap_or(&"");
        let warning_text = format!(
            "{} CRASH DETECTED: {} pending changes {} Press [R] to HACK THE RECOVERY",
            skull_line, pending_changes, skull_line
        );

        frame.render_widget(
            Paragraph::new(warning_text)
                .style(Style::default().fg(Color::Black).bg(Color::Yellow))
                .alignment(ratatui::layout::Alignment::Center)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Red))
                        .title(" ⚠ SYSTEM ALERT ⚠ "),
                ),
            area,
        );
    }
}

fn render_globe_with_effects(
    frame: &mut Frame<'_>,
    area: Rect,
    globe: &GlobeRenderer,
    angle: f32,
    stats: &UiStats,
) {
    let ascii = globe.render_frame(
        area.width as usize,
        area.height as usize,
        angle,
        stats.tick,
    );

    // Цвет глобуса меняется в зависимости от статуса
    let globe_color = match &stats.network_health {
        NetworkHealth::Connected => Color::Cyan,
        NetworkHealth::Disconnected => Color::DarkGray,
        NetworkHealth::OrphanedState { .. } => Color::Yellow,
        NetworkHealth::Repairing => Color::Magenta,
    };

    frame.render_widget(
        ascii.to_paragraph().block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(" ◉ GLOBAL_NETWORK_MAP ◉ ")
                .title_style(Style::default().fg(globe_color)),
        ),
        area,
    );
}

fn render_hacker_panel(frame: &mut Frame<'_>, area: Rect, stats: &UiStats) {
    let blocks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),  // ASCII Art (Doge!)
            Constraint::Length(5),  // Network Stats
            Constraint::Length(10), // Hex Dump
            Constraint::Min(5),     // System Tasks
        ])
        .split(area);

    // 1. ASCII Art - Doge или Skull в зависимости от статуса
    render_ascii_art(frame, blocks[0], stats);

    // 2. Network Stats с прогресс барами
    render_network_stats(frame, blocks[1], stats);

    // 3. Hex Dump с глитч эффектами
    render_hex_dump(frame, blocks[2], stats);

    // 4. System Tasks
    render_system_tasks(frame, blocks[3], stats);
}

fn render_ascii_art(frame: &mut Frame<'_>, area: Rect, stats: &UiStats) {
    // Показываем Doge каждые 100 тиков, иначе Skull
    let show_doge = (stats.tick / 100) % 2 == 0;
    
    let art: Vec<Line> = if show_doge {
        DOGE.iter()
            .take(area.height as usize - 2)
            .enumerate()
            .map(|(i, line)| {
                let color = if i % 2 == 0 { Color::Yellow } else { Color::Rgb(255, 200, 100) };
                Line::from(Span::styled(*line, Style::default().fg(color)))
            })
            .collect()
    } else {
        SKULL.iter()
            .take(area.height as usize - 2)
            .map(|line| {
                Line::from(Span::styled(*line, Style::default().fg(Color::Red)))
            })
            .collect()
    };

    let title = if show_doge {
        format!(" {} {} ", get_doge_message(stats.tick), get_doge_message(stats.tick + 7))
    } else {
        " ☠ DEDSEC ☠ ".to_string()
    };

    frame.render_widget(
        Paragraph::new(art).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if show_doge { Color::Yellow } else { Color::Red }))
                .title(title),
        ),
        area,
    );
}

fn render_network_stats(frame: &mut Frame<'_>, area: Rect, stats: &UiStats) {
    let upload_progress = (stats.throughput_mbps as f32 / 1000.0).min(1.0);
    let latency_progress = 1.0 - (stats.latency_ms as f32 / 200.0).min(1.0);

    let lines = vec![
        Line::from(vec![
            Span::styled(" ▲ UPLINK:  ", Style::default().fg(Color::Green)),
            Span::styled(
                hacker_progress_bar(upload_progress, 20),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(
                format!(" {} Mbps", stats.throughput_mbps),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled(" ◉ LATENCY: ", Style::default().fg(Color::Yellow)),
            Span::styled(
                hacker_progress_bar(latency_progress, 20),
                Style::default().fg(if stats.latency_ms < 50 { Color::Green } else { Color::Red }),
            ),
            Span::styled(
                format!(" {} ms", stats.latency_ms),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled(" ⚡ FPS:     ", Style::default().fg(Color::Magenta)),
            Span::styled(
                format!("{} ", stats.fps),
                Style::default().fg(Color::White),
            ),
            Span::styled(
                "█".repeat((stats.fps / 10) as usize),
                Style::default().fg(Color::Green),
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

fn render_hex_dump(frame: &mut Frame<'_>, area: Rect, stats: &UiStats) {
    let mut lines = vec![];
    
    for i in 0..8 {
        let offset = stats.tick.wrapping_add(i as u64) * 16;
        let hex_part: String = (0..8)
            .map(|j| {
                let val = (offset.wrapping_add(j) * 1337 + stats.tick) % 255;
                format!("{:02X} ", val)
            })
            .collect();

        // Глитч эффект на некоторых строках
        let display = if (stats.tick + i as u64) % 30 < 2 {
            glitch_text(&hex_part, stats.tick, 0.5)
        } else {
            hex_part
        };

        let color = if i % 2 == 0 { Color::DarkGray } else { Color::Rgb(80, 80, 80) };
        lines.push(Line::from(vec![
            Span::styled(format!("0x{:08X}: ", offset), Style::default().fg(Color::Yellow)),
            Span::styled(display, Style::default().fg(color)),
        ]));
    }

    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::LEFT | Borders::TOP)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(" MEM_DUMP "),
        ),
        area,
    );
}

fn render_system_tasks(frame: &mut Frame<'_>, area: Rect, stats: &UiStats) {
    let tasks = [
        ("noise_handshake", "OK", Color::Green),
        ("ml_kem_768", "ACTIVE", Color::Cyan),
        ("dpi_evasion", "ENGAGED", Color::Magenta),
        ("traffic_morph", "RUNNING", Color::Yellow),
        ("cover_traffic", "GENERATING", Color::Blue),
        ("geo_spoof", "TOKYO_03", Color::Red),
    ];

    let lines: Vec<Line> = tasks
        .iter()
        .enumerate()
        .map(|(i, (name, status, color))| {
            let blink = (stats.tick / 5 + i as u64) % 3 == 0;
            let prefix = if blink { "▶" } else { "►" };
            
            Line::from(vec![
                Span::styled(format!(" {} ", prefix), Style::default().fg(*color)),
                Span::styled(format!("{:<15}", name), Style::default().fg(Color::White)),
                Span::styled(
                    format!("[{}]", status),
                    Style::default().fg(*color).add_modifier(if blink { Modifier::BOLD } else { Modifier::empty() }),
                ),
            ])
        })
        .collect();

    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(" ⚙ SYSTEM_TASKS ⚙ "),
        ),
        area,
    );
}

fn render_hacker_footer(frame: &mut Frame<'_>, area: Rect, stats: &UiStats) {
    let msg = get_hacker_message(stats.tick);
    let len = msg.len();
    let offset = (stats.tick / 2) as usize % len.max(1);
    let scrolled = if len > 0 {
        format!("{}{}", &msg[offset..], &msg[..offset])
    } else {
        String::new()
    };

    let needs_repair = matches!(stats.network_health, NetworkHealth::OrphanedState { .. });

    let mut spans = vec![
        Span::styled(
            format!(" {} COMMAND > ", spinner(stats.tick)),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
        Span::styled(scrolled, Style::default().fg(Color::DarkGray)),
    ];

    if needs_repair {
        let repair_style = if stats.tick % 20 < 10 {
            Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
        };
        spans.push(Span::styled(" [R: HACK_REPAIR] ", repair_style));
    }

    spans.push(Span::styled(
        " [Q: EXIT_MATRIX] ",
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    ));

    // Doge message в углу
    spans.push(Span::styled(
        format!(" // {} ", get_doge_message(stats.tick + 3)),
        Style::default().fg(Color::Yellow),
    ));

    frame.render_widget(
        Paragraph::new(Line::from(spans)).block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(Color::DarkGray)),
        ),
        area,
    );
}
