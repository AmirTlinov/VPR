.PHONY: vpn app dev build clean diag tui

# Run VPR desktop app (Tauri) with headless-safe Xvfb fallback
# Uses a virtual X server so GTK/WebKit always initialize, even без реального дисплея
tui:
	@cargo build -p masque-core --bin vpn-client
	@if ! getcap target/debug/vpn-client | grep -q cap_net_admin; then \
		echo "Granting CAP_NET_ADMIN,CAP_NET_RAW to vpn-client (needed for TUN)"; \
		sudo setcap cap_net_admin,cap_net_raw+eip target/debug/vpn-client || true; \
	fi
	@if [ -n "$$DISPLAY" ]; then \
		echo "Using host display $$DISPLAY"; \
		cd src/vpr-app && \
			XDG_SESSION_TYPE=$${XDG_SESSION_TYPE:-x11} WINIT_UNIX_BACKEND=x11 GDK_BACKEND=x11 QT_QPA_PLATFORM=xcb VPR_SKIP_ELEVATE=1 \
			cargo tauri dev; \
	else \
		echo "No DISPLAY found, falling back to Xvfb headless display"; \
		cd src/vpr-app && \
			XDG_SESSION_TYPE=x11 WAYLAND_DISPLAY= WINIT_UNIX_BACKEND=x11 GDK_BACKEND=x11 QT_QPA_PLATFORM=xcb VPR_SKIP_ELEVATE=1 \
			dbus-run-session -- xvfb-run -s "-screen 0 1920x1080x24" cargo tauri dev; \
	fi

# Diagnostics: run after "Online" to verify tunnel and routing
diag:
	@sudo ./scripts/diag_vpn.sh

# Build and run VPN client
vpn:
	@if [ ! -f ./target/release/vpr-app ]; then \
		echo "Building VPR app..."; \
		cd src/vpr-app && cargo tauri build 2>&1 | grep -E "(Compiling|Finished|Built|Error)" || true; \
	else \
		echo "VPR app already built (use 'make build' to rebuild)"; \
	fi
	@echo "Starting VPR..."
	@./target/release/vpr-app 2>/dev/null &
	@sleep 1 && pgrep -x vpr-app > /dev/null && echo "✓ VPR running (PID: $(pgrep -x vpr-app))" || echo "✗ Failed to start"

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
