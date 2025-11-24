fn main() {
    if let Err(err) = vpr_tui::run() {
        eprintln!("vpr-tui failed: {err}");
        std::process::exit(1);
    }
}
