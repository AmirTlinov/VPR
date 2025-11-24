use vpr_tui::globe::GlobeRenderer;

fn build_frame() -> (GlobeRenderer, Vec<String>) {
    let globe = GlobeRenderer::new(3200, 0.32, 0.18);
    let frame = globe.render_frame(64, 32, 0.6, 3);
    let rows = frame.as_strings();
    (globe, rows)
}

#[test]
fn globe_frame_matches_fixture() {
    // Детализированный снепшот фиксирует форму планеты, освещение и текстуру.
    let expected = include_str!("fixtures/frame.txt");
    let (_globe, rows) = build_frame();
    let actual = rows.join("\n") + "\n";

    assert_eq!(actual, expected);
}

#[test]
fn equator_has_continuous_band() {
    let (_globe, rows) = build_frame();
    let mid = rows[rows.len() / 2].chars().filter(|c| *c != ' ').count();
    assert!(mid > 20, "equator band is too thin: {mid}");
}

#[test]
fn poles_fade_out() {
    let (_globe, rows) = build_frame();
    let north = rows[2].chars().filter(|c| *c != ' ').count();
    let south = rows[rows.len() - 3].chars().filter(|c| *c != ' ').count();
    let equator = rows[rows.len() / 2].chars().filter(|c| *c != ' ').count();

    assert!(north < equator / 2, "north cap too large");
    assert!(south < equator / 2, "south cap too large");
}
