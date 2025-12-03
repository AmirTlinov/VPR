use ratatui::style::Color;
use vpr_tui::frame::AsciiFrame;

#[test]
fn frame_put_respects_depth() {
    let mut f = AsciiFrame::new(4, 2);
    f.put(0, 0, 0.1, 'A', Color::Green);
    // Lower depth ignored
    f.put(0, 0, -1.0, 'B', Color::Red);
    let rows = f.as_strings();
    assert_eq!(rows[0].chars().next().unwrap(), 'A');
}

#[test]
fn occupied_ratio_reports_fill() {
    let mut f = AsciiFrame::new(2, 1);
    assert_eq!(f.occupied_ratio(), 0.0);
    f.put(0, 0, 0.0, '#', Color::White);
    assert!(f.occupied_ratio() > 0.0);
}
