.PHONY: app dev build clean

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
