use super::*;
use ratatui::backend::TestBackend;
use ratatui::Terminal;

#[test]
fn draw_smoke_renders() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let globe = GlobeRenderer::new(120, 0.25, 0.12);
    let stats = UiStats {
        tick: 3,
        fps: 60,
        latency_ms: 15,
        throughput_mbps: 850,
    };
    terminal
        .draw(|f| {
            let area = f.size();
            draw(f, &globe, area, 0.4, stats);
        })
        .unwrap();
}
