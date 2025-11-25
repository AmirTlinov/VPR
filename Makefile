.PHONY: vpn app dev build clean diag tui

# Run VPR desktop app (hacker style Watch Dogs 2)
tui:
	@cd src/vpr-app && cargo tauri dev

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
