use std::env;

use vpr_tui::globe::GlobeRenderer;

fn parse_arg(idx: usize, default: usize) -> usize {
    env::args()
        .nth(idx)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn parse_angle(idx: usize, default: f32) -> f32 {
    env::args()
        .nth(idx)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let width = parse_arg(1, 64);
    let height = parse_arg(2, 32);
    let angle = parse_angle(3, 0.6);

    let globe = GlobeRenderer::new(3200, 0.32, 0.18);
    let frame = globe.render_frame(width, height, angle, 3);

    for line in frame.as_strings() {
        println!("{line}");
    }
}
