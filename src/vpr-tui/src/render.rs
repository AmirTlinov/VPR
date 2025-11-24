use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::globe::GlobeRenderer;

pub struct UiStats {
    pub tick: u64,
    pub fps: u16,
    pub latency_ms: u16,
    pub throughput_mbps: u16,
}

pub fn draw(frame: &mut Frame<'_>, globe: &GlobeRenderer, area: Rect, angle: f32, stats: UiStats) {
    // Main Layout: Header, Content (Globe + Info), Footer
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(10),
            Constraint::Length(1),
        ])
        .split(area);

    render_header(frame, layout[0]);

    // Content Layout: Globe (Left), Info Panel (Right)
    let content_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(layout[1]);

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

    render_footer(frame, layout[2], &stats);
}

fn render_header(frame: &mut Frame<'_>, area: Rect) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let line = Line::from(vec![
        Span::styled(
            " VPR_OS ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" :: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            "SECURE_CHANNEL_ESTABLISHED",
            Style::default().fg(Color::Green),
        ),
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
    let processes = vec![
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
            let style = if (stats.tick / 10 + i as u64) % 2 == 0 {
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

    let line = Line::from(vec![
        Span::styled(" COMMAND > ", Style::default().fg(Color::Yellow)),
        Span::styled(scrolled_msg, Style::default().fg(Color::DarkGray)),
        Span::styled(
            " [Q: ABORT] ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
    ]);

    frame.render_widget(
        Paragraph::new(line).alignment(ratatui::layout::Alignment::Left),
        area,
    );
}
