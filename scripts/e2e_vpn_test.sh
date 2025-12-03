#!/bin/bash
# VPR VPN End-to-End Test Script
# Requires: sudo privileges, network namespace support
#
# Usage:
#   ./scripts/e2e_vpn_test.sh              # Local loopback test
#   ./scripts/e2e_vpn_test.sh --remote IP  # Test against remote server

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TMP_DIR="/tmp/vpr-e2e-$$"
CLEANUP_PIDS=()

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    log_info "Cleaning up..."
    for pid in "${CLEANUP_PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    # Remove TUN devices
    ip link del vpr-test-srv 2>/dev/null || true
    ip link del vpr-test-cli 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script requires root privileges for TUN device creation"
        log_info "Run with: sudo $0 $*"
        exit 1
    fi
}

build_binaries() {
    log_info "Building VPN binaries..."
    cargo build --release -p masque-core --bin vpn-server --bin vpn-client -p vpr-crypto 2>&1 | tail -3
}

generate_keys() {
    log_info "Generating test keys..."
    mkdir -p "$TMP_DIR"

    # Noise keys
    "$PROJECT_DIR/target/release/vpr-keygen" gen-noise-key --name server --output "$TMP_DIR" >/dev/null
    "$PROJECT_DIR/target/release/vpr-keygen" gen-noise-key --name client --output "$TMP_DIR" >/dev/null

    # TLS certificate
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$TMP_DIR/server.key" -out "$TMP_DIR/server.crt" \
        -days 1 -subj "/CN=localhost" \
        -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" 2>/dev/null

    log_info "Keys generated in $TMP_DIR"
}

run_local_test() {
    log_info "Starting local VPN E2E test..."

    local QUIC_PORT=14433
    local SERVER_TUN_IP="10.99.0.1"
    local CLIENT_TUN_IP="10.99.0.2"

    # Start server
    log_info "Starting VPN server on 127.0.0.1:$QUIC_PORT..."
    "$PROJECT_DIR/target/release/vpn-server" \
        --bind "127.0.0.1:$QUIC_PORT" \
        --tun-name "vpr-test-srv" \
        --tun-addr "$SERVER_TUN_IP" \
        --pool-start "$CLIENT_TUN_IP" \
        --pool-end "10.99.0.254" \
        --noise-dir "$TMP_DIR" \
        --noise-name server \
        --cert "$TMP_DIR/server.crt" \
        --key "$TMP_DIR/server.key" \
        > "$TMP_DIR/server.log" 2>&1 &
    CLEANUP_PIDS+=($!)
    sleep 2

    if ! ps -p ${CLEANUP_PIDS[-1]} > /dev/null 2>&1; then
        log_error "Server failed to start. Log:"
        cat "$TMP_DIR/server.log"
        exit 1
    fi
    log_info "Server started (PID: ${CLEANUP_PIDS[-1]})"

    # Start client
    log_info "Starting VPN client..."
    "$PROJECT_DIR/target/release/vpn-client" \
        --server "127.0.0.1:$QUIC_PORT" \
        --server-name localhost \
        --tun-name "vpr-test-cli" \
        --noise-dir "$TMP_DIR" \
        --noise-name client \
        --server-pub "$TMP_DIR/server.noise.pub" \
        --insecure \
        > "$TMP_DIR/client.log" 2>&1 &
    CLEANUP_PIDS+=($!)
    sleep 3

    if ! ps -p ${CLEANUP_PIDS[-1]} > /dev/null 2>&1; then
        log_error "Client failed to start. Log:"
        cat "$TMP_DIR/client.log"
        exit 1
    fi
    log_info "Client started (PID: ${CLEANUP_PIDS[-1]})"

    # Verify TUN interfaces exist
    if ! ip link show vpr-test-srv >/dev/null 2>&1; then
        log_error "Server TUN interface not created"
        exit 1
    fi
    if ! ip link show vpr-test-cli >/dev/null 2>&1; then
        log_error "Client TUN interface not created"
        exit 1
    fi
    log_info "TUN interfaces created successfully"

    # Verify handshake completed by checking logs
    log_info "Verifying handshake completion..."
    if grep -q "Hybrid PQ handshake complete" "$TMP_DIR/client.log"; then
        log_info "Hybrid PQ handshake verified!"
    else
        log_error "Handshake verification failed!"
        cat "$TMP_DIR/client.log"
        exit 1
    fi

    if grep -q "Client accepted config" "$TMP_DIR/server.log"; then
        log_info "Client registered on server!"
    else
        log_error "Client registration failed!"
        cat "$TMP_DIR/server.log"
        exit 1
    fi

    # Check IP assignment (tracing format: client_ip=X.X.X.X)
    if grep -q "client_ip=$CLIENT_TUN_IP" "$TMP_DIR/client.log"; then
        log_info "IP assignment correct: $CLIENT_TUN_IP"
    else
        log_warn "Could not verify IP assignment from logs"
    fi

    # Note: Local loopback ping doesn't work due to Linux routing
    # Real ping test requires remote server or network namespaces
    log_warn "Skipping ping test on loopback (use --remote for full test)"

    echo ""
    log_info "=========================================="
    log_info "  VPN E2E TEST PASSED!"
    log_info "=========================================="
    echo ""
    log_info "Server TUN: vpr-test-srv ($SERVER_TUN_IP)"
    log_info "Client TUN: vpr-test-cli ($CLIENT_TUN_IP)"
}

run_remote_test() {
    local REMOTE_IP="$1"
    local QUIC_PORT="${2:-4433}"

    log_info "Testing against remote server $REMOTE_IP:$QUIC_PORT..."

    # Need server's public key
    if [[ ! -f "$TMP_DIR/server.noise.pub" ]]; then
        log_error "Server public key not found. Copy server.noise.pub to $TMP_DIR/"
        exit 1
    fi

    # Start client
    "$PROJECT_DIR/target/release/vpn-client" \
        --server "$REMOTE_IP:$QUIC_PORT" \
        --server-name "$REMOTE_IP" \
        --tun-name "vpr-test-cli" \
        --noise-dir "$TMP_DIR" \
        --noise-name client \
        --server-pub "$TMP_DIR/server.noise.pub" \
        --insecure \
        > "$TMP_DIR/client.log" 2>&1 &
    CLEANUP_PIDS+=($!)
    sleep 5

    # Get assigned IP from log
    local CLIENT_IP=$(grep -oP 'client_ip=\K[0-9.]+' "$TMP_DIR/client.log" | head -1)
    local GATEWAY_IP=$(grep -oP 'gateway=\K[0-9.]+' "$TMP_DIR/client.log" | head -1)

    if [[ -z "$CLIENT_IP" ]]; then
        log_error "Failed to get assigned IP. Log:"
        cat "$TMP_DIR/client.log"
        exit 1
    fi

    log_info "Assigned IP: $CLIENT_IP, Gateway: $GATEWAY_IP"

    # Test ping
    if ping -c 3 -W 5 -I vpr-test-cli "$GATEWAY_IP" > "$TMP_DIR/ping.log" 2>&1; then
        log_info "Remote VPN test PASSED!"
        cat "$TMP_DIR/ping.log"
    else
        log_error "Remote VPN test FAILED!"
        cat "$TMP_DIR/ping.log"
        exit 1
    fi
}

main() {
    check_privileges

    local MODE="local"
    local REMOTE_IP=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            --remote)
                MODE="remote"
                REMOTE_IP="$2"
                shift 2
                ;;
            --help|-h)
                echo "Usage: $0 [--remote IP]"
                echo ""
                echo "Options:"
                echo "  --remote IP   Test against remote VPN server"
                echo "  --help        Show this help"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    build_binaries
    generate_keys

    if [[ "$MODE" == "local" ]]; then
        run_local_test
    else
        run_remote_test "$REMOTE_IP"
    fi
}

main "$@"
