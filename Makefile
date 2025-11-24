.PHONY: vpn app dev build clean

.PHONY: tui tui-frame

# Run ASCII TUI globe
tui:
	@cargo run -p vpr-tui --release

# Dump single frame to stdout (usage: make tui-frame WIDTH=64 HEIGHT=32 ANGLE=0.6)
tui-frame:
	@cargo run -p vpr-tui --bin frame_dump -- $${WIDTH:-64} $${HEIGHT:-32} $${ANGLE:-0.6}

# Build and run VPN client
vpn:
	@cd src/vpr-app && cargo tauri build 2>&1 | grep -E "(Compiling|Finished|Built|Error)" || true
	@./target/release/vpr-app &

# Run VPN app in development mode
dev:
	@cd src/vpr-app && cargo tauri dev

# Build release
build:
	@cd src/vpr-app && cargo tauri build

# Run built app
app: build
	@./target/release/vpr-app

# Clean build artifacts
clean:
	@cargo clean
