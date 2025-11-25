use ratatui::backend::TestBackend;
use ratatui::Terminal;
use vpr_tui::globe::GlobeRenderer;
use vpr_tui::render::{draw, NetworkHealth, UiStats};

#[test]
fn render_draw_smoke() {
    let backend = TestBackend::new(60, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    let globe = GlobeRenderer::new(200, 0.3, 0.2);
    let stats = UiStats {
        tick: 1,
        fps: 60,
        latency_ms: 10,
        throughput_mbps: 900,
        network_health: NetworkHealth::default(),
    };

    terminal
        .draw(|f| {
            let area = f.size();
            draw(f, &globe, area, 0.5, stats);
        })
        .unwrap();
}
