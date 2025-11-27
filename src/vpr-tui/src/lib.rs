//! VPR TUI - Terminal User Interface for VPN Client
//!
//! Beautiful terminal interface for VPR VPN with real-time metrics,
//! ASCII globe visualization, and network health monitoring.
//!
//! # Features
//!
//! - **Live connection status**: Connect, disconnect, reconnect
//! - **Traffic metrics**: Bytes in/out, packets, latency
//! - **ASCII Globe**: Rotating 3D globe showing connection location
//! - **Network health**: Real-time health indicators
//! - **Theme support**: Light and dark themes
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                         TUI App                             │
//! │  ┌──────────────┐  ┌───────────────┐  ┌─────────────────┐  │
//! │  │   Renderer   │  │  VpnController│  │   Globe Widget  │  │
//! │  │ (ratatui)    │  │  (async cmds) │  │   (ASCII art)   │  │
//! │  └──────────────┘  └───────────────┘  └─────────────────┘  │
//! │         │                  │                   │           │
//! │         └──────────────────┴───────────────────┘           │
//! │                            │                               │
//! │                     ┌──────────────┐                       │
//! │                     │ Frame/Render │                       │
//! │                     │   Pipeline   │                       │
//! │                     └──────────────┘                       │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use vpr_tui::{run, TuiConfig, Theme};
//!
//! let config = TuiConfig {
//!     theme: Theme::Dark,
//!     ..Default::default()
//! };
//! run_with_tui_config(config)?;
//! ```

pub mod app;
pub mod ascii_art;
pub mod config;
pub mod frame;
pub mod globe;
pub mod render;
pub mod vpn;

pub use app::{run, run_async, run_with_callbacks, run_with_config, run_with_tui_config, TuiCallbacks, TuiEvent};
pub use config::{Theme, TuiConfig};
pub use render::{NetworkHealth, UiStats};
pub use vpn::{ConnectionState, ControllerConfig, ServerConfig, VpnController, VpnMetrics};
