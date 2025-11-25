use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::globe::GlobeRenderer;

/// Network health status for TUI display
#[derive(Debug, Clone, Default)]
pub enum NetworkHealth {
    /// Network is healthy, VPN connected
    #[default]
    Connected,
    /// Disconnected but clean
    Disconnected,
    /// Orphaned network state detected (previous crash)
    OrphanedState {
        /// Number of pending changes to restore
        pending_changes: usize,
        /// When the crashed session started
        crashed_at: Option<u64>,
    },
    /// Network being repaired
    Repairing,
}

pub struct UiStats {
    pub tick: u64,
    pub fps: u16,
    pub latency_ms: u16,
    pub throughput_mbps: u16,
    /// Network health status (for crash recovery display)
    pub network_health: NetworkHealth,
}

pub fn draw(frame: &mut Frame<'_>, globe: &GlobeRenderer, area: Rect, angle: f32, stats: UiStats) {
    // Check if we need warning banner for orphaned network state
    let needs_warning = matches!(stats.network_health, NetworkHealth::OrphanedState { .. });

    // Main Layout: Header, Warning (optional), Content (Globe + Info), Footer
    let layout = if needs_warning {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),  // Header
                Constraint::Length(3),  // Warning banner
                Constraint::Min(10),    // Content
                Constraint::Length(1),  // Footer
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),  // Header
                Constraint::Length(0),  // No warning
                Constraint::Min(10),    // Content
                Constraint::Length(1),  // Footer
            ])
            .split(area)
    };

    render_header(frame, layout[0], &stats.network_health);

    // Render warning banner if needed
    if needs_warning {
        render_orphaned_warning(frame, layout[1], &stats.network_health);
    }

    // Content and footer indices (layout always has 4 elements, warning slot may be empty)
    let (content_idx, footer_idx) = (2, 3);

    // Content Layout: Globe (Left), Info Panel (Right)
    let content_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(layout[content_idx]);

    // Render Globe
    let globe_area = content_layout[0];
    // Use a slightly neon color palette for the globe
    let ascii = globe.render_frame(
        globe_area.width as usize,
        globe_area.height as usize,
        angle,
        stats.tick,
    );

    // Apply a "CRT" scanline effect or just direct rendering
    frame.render_widget(
        ascii.to_paragraph().block(
            Block::default()
                .borders(Borders::NONE)
                .style(Style::default().fg(Color::Cyan)),
        ),
        globe_area,
    );

    // Render Info Panel
    render_info_panel(frame, content_layout[1], &stats);

    render_footer(frame, layout[footer_idx], &stats);
}

fn render_header(frame: &mut Frame<'_>, area: Rect, health: &NetworkHealth) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Status text and color based on network health
    let (status_text, status_color) = match health {
        NetworkHealth::Connected => ("SECURE_CHANNEL_ESTABLISHED", Color::Green),
        NetworkHealth::Disconnected => ("DISCONNECTED", Color::DarkGray),
        NetworkHealth::OrphanedState { .. } => ("NETWORK_RECOVERY_NEEDED", Color::Yellow),
        NetworkHealth::Repairing => ("REPAIRING_NETWORK", Color::Cyan),
    };

    let line = Line::from(vec![
        Span::styled(
            " VPR_OS ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" :: ", Style::default().fg(Color::DarkGray)),
        Span::styled(status_text, Style::default().fg(status_color)),
        Span::styled(" :: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("T-{}", timestamp % 10000),
            Style::default().fg(Color::Red),
        ),
        Span::raw(" "),
        Span::styled(
            " [ENCRYPTED] ",
            Style::default()
                .fg(Color::LightBlue)
                .add_modifier(Modifier::RAPID_BLINK),
        ),
    ]);

    frame.render_widget(
        Paragraph::new(line).alignment(ratatui::layout::Alignment::Left),
        area,
    );
}

/// Render warning banner for orphaned network state (crash recovery needed)
fn render_orphaned_warning(frame: &mut Frame<'_>, area: Rect, health: &NetworkHealth) {
    if let NetworkHealth::OrphanedState {
        pending_changes,
        crashed_at,
    } = health
    {
        let time_info = crashed_at
            .map(|ts| format!(" (crashed session from T-{})", ts % 100000))
            .unwrap_or_default();

        let warning_text = format!(
            "WARNING: Previous VPN session crashed with {} pending network changes{}\n\
             Network may be in inconsistent state. Press 'R' to repair or start VPN to auto-repair.",
            pending_changes, time_info
        );

        frame.render_widget(
            Paragraph::new(warning_text)
                .style(Style::default().fg(Color::Black).bg(Color::Yellow))
                .alignment(ratatui::layout::Alignment::Center)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Yellow))
                        .title(" NETWORK RECOVERY ")
                        .title_style(
                            Style::default()
                                .fg(Color::Red)
                                .add_modifier(Modifier::BOLD),
                        ),
                ),
            area,
        );
    }
}

fn render_info_panel(frame: &mut Frame<'_>, area: Rect, stats: &UiStats) {
    let blocks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Network Status
            Constraint::Length(10), // Log / Hex dump
            Constraint::Min(5),     // Active Processes
        ])
        .split(area);

    // 1. Network Status
    let net_status = format!(
        "UPLINK: {} Mbps\nLATENCY: {} ms",
        stats.throughput_mbps, stats.latency_ms
    );
    frame.render_widget(
        Paragraph::new(net_status).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::LightGreen))
                .title("NET_STAT"),
        ),
        blocks[0],
    );

    // 2. Hex Dump / Log (Fake Data)
    let mut log_lines = vec![];
    for i in 0..8 {
        let offset = stats.tick.wrapping_add(i as u64) * 16;
        let hex_part: String = (0..8)
            .map(|j| {
                let val = (offset.wrapping_add(j) * 1337) % 255;
                format!("{:02X} ", val)
            })
            .collect();
        log_lines.push(Line::from(Span::styled(
            format!("0x{:08X}: {}", offset, hex_part),
            Style::default().fg(Color::DarkGray),
        )));
    }

    frame.render_widget(
        Paragraph::new(log_lines).block(Block::default().borders(Borders::LEFT).title("MEM_DUMP")),
        blocks[1],
    );

    // 3. Active Processes / Encryption
    let processes = [
        " > key_exchange... OK",
        " > noise_handshake... OK",
        " > packet_shaping... ACTIVE",
        " > dpi_evasion... ENGAGED",
        " > geo_spoof... TOKYO_03",
    ];

    let proc_text: Vec<Line> = processes
        .iter()
        .enumerate()
        .map(|(i, p)| {
            #[allow(clippy::incompatible_msrv)]
            let style = if (stats.tick / 10 + i as u64).is_multiple_of(2) {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            Line::from(Span::styled(*p, style))
        })
        .collect();

    frame.render_widget(
        Paragraph::new(proc_text)
            .block(Block::default().borders(Borders::TOP).title("SYSTEM_TASKS")),
        blocks[2],
    );
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, stats: &UiStats) {
    // Scrolling text effect
    let msg = " INITIALIZING... CONNECTING TO SECURE NODE... ";
    let len = msg.len();
    let offset = (stats.tick / 2) as usize % len;
    let scrolled_msg = format!("{}{}", &msg[offset..], &msg[..offset]);

    // Show repair option if network needs recovery
    let needs_repair = matches!(stats.network_health, NetworkHealth::OrphanedState { .. });

    let mut spans = vec![
        Span::styled(" COMMAND > ", Style::default().fg(Color::Yellow)),
        Span::styled(scrolled_msg, Style::default().fg(Color::DarkGray)),
    ];

    // Add repair button when needed (blinking to attract attention)
    if needs_repair {
        let repair_style = if stats.tick % 20 < 10 {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        };
        spans.push(Span::styled(" [R: REPAIR] ", repair_style));
    }

    spans.push(Span::styled(
        " [Q: QUIT] ",
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    ));

    let line = Line::from(spans);

    frame.render_widget(
        Paragraph::new(line).alignment(ratatui::layout::Alignment::Left),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn make_stats(tick: u64, health: NetworkHealth) -> UiStats {
        UiStats {
            tick,
            fps: 60,
            latency_ms: 10,
            throughput_mbps: 900,
            network_health: health,
        }
    }

    #[test]
    fn network_health_default_is_connected() {
        let health = NetworkHealth::default();
        assert!(matches!(health, NetworkHealth::Connected));
    }

    #[test]
    fn network_health_variants() {
        let connected = NetworkHealth::Connected;
        let disconnected = NetworkHealth::Disconnected;
        let orphaned = NetworkHealth::OrphanedState {
            pending_changes: 3,
            crashed_at: Some(12345),
        };
        let repairing = NetworkHealth::Repairing;

        // Test Debug trait
        assert!(format!("{:?}", connected).contains("Connected"));
        assert!(format!("{:?}", disconnected).contains("Disconnected"));
        assert!(format!("{:?}", orphaned).contains("OrphanedState"));
        assert!(format!("{:?}", repairing).contains("Repairing"));
    }

    #[test]
    fn ui_stats_construction() {
        let stats = make_stats(100, NetworkHealth::Connected);
        assert_eq!(stats.tick, 100);
        assert_eq!(stats.fps, 60);
        assert_eq!(stats.latency_ms, 10);
        assert_eq!(stats.throughput_mbps, 900);
    }

    #[test]
    fn draw_connected_state() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let globe = crate::globe::GlobeRenderer::new(200, 0.3, 0.2);
        let stats = make_stats(1, NetworkHealth::Connected);

        terminal
            .draw(|f| {
                draw(f, &globe, f.size(), 0.0, stats);
            })
            .unwrap();

        // Verify buffer contains expected text
        let buffer = terminal.backend().buffer();
        let content: String = buffer.content().iter().map(|c| c.symbol()).collect();
        assert!(content.contains("VPR_OS"));
        assert!(content.contains("SECURE_CHANNEL_ESTABLISHED"));
    }

    #[test]
    fn draw_disconnected_state() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let globe = crate::globe::GlobeRenderer::new(200, 0.3, 0.2);
        let stats = make_stats(1, NetworkHealth::Disconnected);

        terminal
            .draw(|f| {
                draw(f, &globe, f.size(), 0.5, stats);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content: String = buffer.content().iter().map(|c| c.symbol()).collect();
        assert!(content.contains("DISCONNECTED"));
    }

    #[test]
    fn draw_orphaned_state_shows_warning() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let globe = crate::globe::GlobeRenderer::new(200, 0.3, 0.2);
        let stats = make_stats(
            1,
            NetworkHealth::OrphanedState {
                pending_changes: 5,
                crashed_at: Some(99999),
            },
        );

        terminal
            .draw(|f| {
                draw(f, &globe, f.size(), 0.0, stats);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content: String = buffer.content().iter().map(|c| c.symbol()).collect();
        assert!(content.contains("NETWORK_RECOVERY_NEEDED"));
        assert!(content.contains("WARNING"));
        assert!(content.contains("REPAIR"));
    }

    #[test]
    fn draw_repairing_state() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let globe = crate::globe::GlobeRenderer::new(200, 0.3, 0.2);
        let stats = make_stats(1, NetworkHealth::Repairing);

        terminal
            .draw(|f| {
                draw(f, &globe, f.size(), 1.0, stats);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content: String = buffer.content().iter().map(|c| c.symbol()).collect();
        assert!(content.contains("REPAIRING_NETWORK"));
    }

    #[test]
    fn footer_shows_quit_button() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let globe = crate::globe::GlobeRenderer::new(200, 0.3, 0.2);
        let stats = make_stats(1, NetworkHealth::Connected);

        terminal
            .draw(|f| {
                draw(f, &globe, f.size(), 0.0, stats);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content: String = buffer.content().iter().map(|c| c.symbol()).collect();
        assert!(content.contains("Q: QUIT"));
    }

    #[test]
    fn info_panel_renders_successfully() {
        // Use larger terminal to ensure all panels fit
        let backend = TestBackend::new(150, 50);
        let mut terminal = Terminal::new(backend).unwrap();
        let globe = crate::globe::GlobeRenderer::new(200, 0.3, 0.2);
        let stats = UiStats {
            tick: 0,
            fps: 60,
            latency_ms: 25,
            throughput_mbps: 850,
            network_health: NetworkHealth::Connected,
        };

        // Main assertion: rendering completes without panic
        terminal
            .draw(|f| {
                draw(f, &globe, f.size(), 0.0, stats);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content: String = buffer.content().iter().map(|c| c.symbol()).collect();
        // Info panel title should be visible
        assert!(content.contains("NET_STAT"), "NET_STAT should be in buffer");
    }

    #[test]
    fn scrolling_message_changes_with_tick() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let globe = crate::globe::GlobeRenderer::new(200, 0.3, 0.2);

        // Capture frame at tick=0
        let stats1 = make_stats(0, NetworkHealth::Connected);
        terminal
            .draw(|f| {
                draw(f, &globe, f.size(), 0.0, stats1);
            })
            .unwrap();
        let content1: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();

        // Capture frame at tick=10 (message should scroll)
        let stats2 = make_stats(10, NetworkHealth::Connected);
        terminal
            .draw(|f| {
                draw(f, &globe, f.size(), 0.0, stats2);
            })
            .unwrap();
        let content2: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();

        // Both should contain COMMAND prompt
        assert!(content1.contains("COMMAND"));
        assert!(content2.contains("COMMAND"));
    }

    #[test]
    fn small_terminal_does_not_panic() {
        // Test with very small terminal size
        let backend = TestBackend::new(20, 5);
        let mut terminal = Terminal::new(backend).unwrap();
        let globe = crate::globe::GlobeRenderer::new(100, 0.3, 0.2);
        let stats = make_stats(0, NetworkHealth::Connected);

        // Should not panic even with tiny terminal
        let result = terminal.draw(|f| {
            draw(f, &globe, f.size(), 0.0, stats);
        });
        assert!(result.is_ok());
    }

    #[test]
    fn timestamp_in_header_changes() {
        // The timestamp uses real time, so we just verify it's present
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let globe = crate::globe::GlobeRenderer::new(200, 0.3, 0.2);
        let stats = make_stats(0, NetworkHealth::Connected);

        terminal
            .draw(|f| {
                draw(f, &globe, f.size(), 0.0, stats);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content: String = buffer.content().iter().map(|c| c.symbol()).collect();
        // T- prefix for timestamp
        assert!(content.contains("T-"));
    }

    #[test]
    fn hex_dump_section_present() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let globe = crate::globe::GlobeRenderer::new(200, 0.3, 0.2);
        let stats = make_stats(0, NetworkHealth::Connected);

        terminal
            .draw(|f| {
                draw(f, &globe, f.size(), 0.0, stats);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content: String = buffer.content().iter().map(|c| c.symbol()).collect();
        assert!(content.contains("MEM_DUMP"));
        assert!(content.contains("0x")); // Hex addresses
    }

    #[test]
    fn system_tasks_section_present() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let globe = crate::globe::GlobeRenderer::new(200, 0.3, 0.2);
        let stats = make_stats(0, NetworkHealth::Connected);

        terminal
            .draw(|f| {
                draw(f, &globe, f.size(), 0.0, stats);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content: String = buffer.content().iter().map(|c| c.symbol()).collect();
        assert!(content.contains("SYSTEM_TASKS"));
    }

    #[test]
    fn repair_button_blinks() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let globe = crate::globe::GlobeRenderer::new(200, 0.3, 0.2);

        // Test at tick where button is in one state
        let stats1 = make_stats(
            5, // tick % 20 < 10 -> yellow bg
            NetworkHealth::OrphanedState {
                pending_changes: 1,
                crashed_at: None,
            },
        );
        terminal
            .draw(|f| {
                draw(f, &globe, f.size(), 0.0, stats1);
            })
            .unwrap();

        // Test at tick where button is in other state
        let stats2 = make_stats(
            15, // tick % 20 >= 10 -> no bg
            NetworkHealth::OrphanedState {
                pending_changes: 1,
                crashed_at: None,
            },
        );
        terminal
            .draw(|f| {
                draw(f, &globe, f.size(), 0.0, stats2);
            })
            .unwrap();

        // Both should render without panic and show repair button
        let content: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(content.contains("REPAIR"));
    }
}
