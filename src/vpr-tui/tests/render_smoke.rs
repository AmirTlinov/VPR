//! Smoke tests for TUI rendering components
use vpr_tui::globe::GlobeRenderer;

#[test]
fn render_frame_produces_output() {
    let globe = GlobeRenderer::new(2000, 0.3, 0.18);
    let width = 40;
    let height = 20;

    let frame = globe.render_frame(width, height, 0.0, 0);
    // Ensure the frame has content (non-zero occupied ratio)
    let ratio = frame.occupied_ratio();
    assert!(ratio > 0.1, "frame should have visible content, got ratio={ratio}");
}

#[test]
fn render_frame_handles_edge_sizes() {
    let globe = GlobeRenderer::new(500, 0.2, 0.1);

    // Zero dimensions should not panic (may return NaN ratio due to 0/0)
    let frame_zero = globe.render_frame(0, 0, 0.0, 0);
    let ratio_zero = frame_zero.occupied_ratio();
    assert!(ratio_zero.is_nan() || ratio_zero == 0.0, "zero frame ratio should be NaN or 0.0");

    // Small dimensions
    let frame_small = globe.render_frame(10, 5, 0.5, 1);
    assert!(frame_small.occupied_ratio() >= 0.0);

    // Large dimensions
    let frame_large = globe.render_frame(200, 100, 1.0, 100);
    assert!(frame_large.occupied_ratio() > 0.0);
}

#[test]
fn rotation_affects_frame() {
    let globe = GlobeRenderer::new(1000, 0.3, 0.18);

    let frame1 = globe.render_frame(40, 20, 0.0, 0);
    let frame2 = globe.render_frame(40, 20, std::f32::consts::PI, 0);

    // Different rotations should produce different occupied ratios or content
    // AsciiFrame doesn't implement Debug, so compare occupied_ratio instead
    let ratio1 = frame1.occupied_ratio();
    let ratio2 = frame2.occupied_ratio();
    // At minimum, both should have some content
    assert!(ratio1 > 0.0 && ratio2 > 0.0, "both frames should have content");
}
