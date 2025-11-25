use std::io;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::globe::GlobeRenderer;
use crate::render::{draw, NetworkHealth, UiStats};

/// TUI event that can be handled by the caller
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuiEvent {
    /// User requested network repair (pressed 'R')
    RepairNetwork,
    /// User requested quit (pressed 'Q' or Esc)
    Quit,
}

/// Callbacks for TUI events and state queries
pub struct TuiCallbacks<F, G>
where
    F: FnMut() -> NetworkHealth,
    G: FnMut() -> bool,
{
    /// Get current network health status
    pub get_network_health: F,
    /// Attempt network repair, returns true if successful
    pub repair_network: G,
}

/// Run the interactive TUI with the rotating ASCII globe.
pub fn run() -> Result<()> {
    run_with_callbacks(TuiCallbacks {
        get_network_health: || NetworkHealth::default(),
        repair_network: || false,
    })
}

/// Run TUI with custom callbacks for network status and repair
pub fn run_with_callbacks<F, G>(callbacks: TuiCallbacks<F, G>) -> Result<()>
where
    F: FnMut() -> NetworkHealth,
    G: FnMut() -> bool,
{
    let mut stdout = io::stdout();
    enable_raw_mode()?;
    stdout.execute(EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.hide_cursor()?;

    let result = event_loop_with_callbacks(&mut terminal, callbacks);

    disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn event_loop_with_callbacks<B, F, G>(
    terminal: &mut Terminal<B>,
    mut callbacks: TuiCallbacks<F, G>,
) -> Result<()>
where
    B: ratatui::backend::Backend,
    F: FnMut() -> NetworkHealth,
    G: FnMut() -> bool,
{
    let globe = GlobeRenderer::new(4200, 0.32, 0.18);
    let mut angle = 0.0f32;
    let mut tick: u64 = 0;

    let tick_rate = Duration::from_millis(41); // ~24 FPS
    let mut last_tick = Instant::now();

    loop {
        // Get current network health from callback
        let network_health = (callbacks.get_network_health)();

        terminal.draw(|frame| {
            let area = frame.size();
            let fps = (1000.0 / tick_rate.as_millis() as f64).round() as u16;
            let stats = UiStats {
                tick,
                fps,
                latency_ms: 18 + ((tick * 7) % 14) as u16,
                throughput_mbps: 940 + ((tick * 11) % 160) as u16,
                network_health,
            };

            draw(frame, &globe, area, angle, stats);
        })?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('r') | KeyCode::Char('R') => {
                        // Attempt network repair via callback
                        let _ = (callbacks.repair_network)();
                    }
                    _ => {}
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            angle = (angle + globe.angular_step()) % std::f32::consts::TAU;
            tick = tick.wrapping_add(1);
            last_tick = Instant::now();
        }
    }

    Ok(())
}
