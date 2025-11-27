# VPR TUI

Terminal User Interface for VPR VPN client.

## Features

- **Live Status** - Real-time connection status
- **Traffic Metrics** - Bytes in/out, packets, latency
- **ASCII Globe** - Rotating 3D globe showing server location
- **Network Health** - Real-time health indicators
- **Theme Support** - Light and dark themes

## Screenshot

```
╭─ VPR VPN ─────────────────────────────────────────────────────╮
│                                                               │
│     ████████  Status: Connected                               │
│   ██        ██  Server: 64.176.70.203                        │
│  █    ▓▓▓    █  Latency: 42ms                                │
│  █   ▓▓▓▓▓   █                                               │
│   ██        ██  ↓ 1.2 GB  ↑ 256 MB                           │
│     ████████                                                  │
│                                                               │
│  [Connect]  [Disconnect]  [Settings]  [Quit]                  │
╰───────────────────────────────────────────────────────────────╯
```

## Quick Start

```bash
# Build and run
cargo run --bin vpr-tui

# With custom config
cargo run --bin vpr-tui -- --theme dark --server vpn.example.com
```

## Architecture

```
vpr-tui/
├── app.rs       # Main application loop
├── render.rs    # UI rendering (ratatui)
├── globe.rs     # ASCII globe widget
├── ascii_art.rs # Logo and decorations
├── config.rs    # Configuration
├── frame.rs     # Frame pipeline
└── vpn.rs       # VPN controller
```

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `c` | Connect |
| `d` | Disconnect |
| `s` | Settings |
| `q` | Quit |
| `Tab` | Next panel |
| `↑/↓` | Navigate |

## Configuration

```rust
use vpr_tui::{TuiConfig, Theme};

let config = TuiConfig {
    theme: Theme::Dark,
    server: "vpn.example.com:443".to_string(),
    ..Default::default()
};
```

## Programmatic Usage

```rust
use vpr_tui::{run_with_callbacks, TuiCallbacks, TuiEvent};

let callbacks = TuiCallbacks {
    on_connect: Some(Box::new(|| { /* ... */ })),
    on_disconnect: Some(Box::new(|| { /* ... */ })),
    ..Default::default()
};

run_with_callbacks(callbacks)?;
```

## Testing

```bash
cargo test -p vpr-tui
```
