use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::globe::GlobeRenderer;

pub struct UiStats {
    pub tick: u64,
    pub fps: u16,
    pub latency_ms: u16,
    pub throughput_mbps: u16,
}

pub fn draw(frame: &mut Frame<'_>, globe: &GlobeRenderer, area: Rect, angle: f32, stats: UiStats) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(6),
            Constraint::Length(1),
        ])
        .split(area);

    render_header(frame, layout[0]);

    let body = layout[1];
    let ascii = globe.render_frame(body.width as usize, body.height as usize, angle, stats.tick);
    frame.render_widget(
        ascii
            .to_paragraph()
            .block(Block::default().borders(Borders::NONE)),
        body,
    );

    render_footer(frame, layout[2], &stats);
}

fn render_header(frame: &mut Frame<'_>, area: Rect) {
    let line = Line::from(vec![
        Span::styled(
            " VPR // STEALTH LINK // ASCII EARTH ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" press q to exit ", Style::default().fg(Color::DarkGray)),
    ]);

    frame.render_widget(Paragraph::new(line).wrap(Wrap { trim: false }), area);
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, stats: &UiStats) {
    let line = Line::from(vec![
        Span::styled(
            format!("FPS {:02}", stats.fps),
            Style::default().fg(Color::Green),
        ),
        Span::styled("  |  ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("Latency {:>2} ms", stats.latency_ms),
            Style::default().fg(Color::Yellow),
        ),
        Span::styled("  |  ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("Throughput {:>4} Mbps", stats.throughput_mbps),
            Style::default().fg(Color::LightCyan),
        ),
        Span::styled("  |  globe@VPR", Style::default().fg(Color::DarkGray)),
    ]);

    frame.render_widget(Paragraph::new(line).wrap(Wrap { trim: false }), area);
}
