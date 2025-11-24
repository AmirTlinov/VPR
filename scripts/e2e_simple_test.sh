#!/usr/bin/env bash
# VPR Simple E2E Test - Using Pre-built Binaries
# Lightweight end-to-end test against remote VPN server
#
# Usage:
#   ./scripts/e2e_simple_test.sh --server IP --user USER --password PASS

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TMP_DIR="/tmp/vpr-e2e-simple-$$"
LOG_DIR="${PROJECT_DIR}/logs/e2e_full"
mkdir -p "${LOG_DIR}"
mkdir -p "${TMP_DIR}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SERVER_IP=""
SERVER_USER="root"
SERVER_PASSWORD=""
VPN_PORT=4433
TUN_NAME="vpr0"
VPN_CLIENT_PID=""
ORIGINAL_GATEWAY=""

log_info() { echo -e "${GREEN}[INFO]${NC} $1" | tee -a "${LOG_DIR}/test.log"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "${LOG_DIR}/test.log"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "${LOG_DIR}/test.log"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1" | tee -a "${LOG_DIR}/test.log"; }

cleanup() {
    log_info "Cleaning up..."
    
    if [[ -n "${VPN_CLIENT_PID:-}" ]]; then
        kill -TERM "$VPN_CLIENT_PID" 2>/dev/null || true
        sleep 2
        kill -9 "$VPN_CLIENT_PID" 2>/dev/null || true
    fi
    
    ip link del "${TUN_NAME}" 2>/dev/null || true
    
    if [[ -n "${ORIGINAL_GATEWAY:-}" ]]; then
        ip route del default 2>/dev/null || true
        ip route add default via "${ORIGINAL_GATEWAY}" 2>/dev/null || true
    fi
    
    if [[ -f "${TMP_DIR}/resolv.conf.backup" ]]; then
        sudo cp "${TMP_DIR}/resolv.conf.backup" /etc/resolv.conf 2>/dev/null || true
    fi
    
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script requires root privileges"
        exit 1
    fi
}

check_dependencies() {
    log_step "Checking dependencies..."
    for cmd in sshpass cargo ip ping curl; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_error "Missing dependency: $cmd"
            exit 1
        fi
    done
    log_info "All dependencies available"
}

ssh_exec() {
    sshpass -p "$SERVER_PASSWORD" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=30 \
        -o UserKnownHostsFile=/dev/null \
        "${SERVER_USER}@${SERVER_IP}" "$@"
}

scp_upload() {
    sshpass -p "$SERVER_PASSWORD" scp -o StrictHostKeyChecking=no \
        -o ConnectTimeout=30 \
        -o UserKnownHostsFile=/dev/null \
        "$1" "${SERVER_USER}@${SERVER_IP}:$2"
}

scp_download() {
    sshpass -p "$SERVER_PASSWORD" scp -o StrictHostKeyChecking=no \
        -o ConnectTimeout=30 \
        -o UserKnownHostsFile=/dev/null \
        "${SERVER_USER}@${SERVER_IP}:$1" "$2"
}

test_ssh() {
    log_step "Testing SSH connection..."
    if ssh_exec "echo 'OK'"; then
        log_info "SSH connection successful"
        return 0
    else
        log_error "SSH connection failed"
        return 1
    fi
}

check_server_space() {
    log_step "Checking server disk space..."
    local space=$(ssh_exec "df -h / | tail -1 | awk '{print \$4}'")
    log_info "Server free space: $space"
    
    local available_mb=$(ssh_exec "df -m / | tail -1 | awk '{print \$4}'")
    if [[ $available_mb -lt 500 ]]; then
        log_warn "Low disk space on server (${available_mb}MB free)"
        log_info "Will use pre-built binary approach"
        return 1
    fi
    return 0
}

prepare_server_minimal() {
    log_step "Preparing server (minimal setup)..."
    
    ssh_exec "mkdir -p /opt/vpr/{bin,secrets,logs}"
    
    # Check if server binary exists
    if ssh_exec "test -f /opt/vpr/bin/vpn-server"; then
        log_info "Server binary already exists"
        return 0
    fi
    
    log_info "Server binary not found. Please build and upload manually:"
    log_info "  1. Build: cargo build --release --bin vpn-server -p masque-core"
    log_info "  2. Upload: scp target/release/vpn-server ${SERVER_USER}@${SERVER_IP}:/opt/vpr/bin/"
    log_info ""
    log_warn "Attempting to upload local binary..."
    
    if [[ -f "${PROJECT_DIR}/target/release/vpn-server" ]]; then
        log_info "Uploading local vpn-server binary..."
        scp_upload "${PROJECT_DIR}/target/release/vpn-server" "/opt/vpr/bin/vpn-server"
        ssh_exec "chmod +x /opt/vpr/bin/vpn-server"
        log_info "Server binary uploaded"
    else
        log_error "Local server binary not found. Please build it first."
        exit 1
    fi
}

generate_server_keys() {
    log_step "Generating server keys..."
    
    if ! ssh_exec "test -f /opt/vpr/secrets/server.noise.key"; then
        log_info "Generating Noise keys on server..."
        # Generate keys directly on server using available tools
        ssh_exec "cd /opt/vpr/secrets && \
            if command -v vpr-keygen >/dev/null 2>&1; then \
                vpr-keygen gen-noise-key --name server --output /opt/vpr/secrets; \
            else \
                # Fallback: generate random keys (32 bytes for X25519)
                dd if=/dev/urandom bs=32 count=1 of=server.noise.key 2>/dev/null && \
                dd if=/dev/urandom bs=32 count=1 of=server.noise.pub 2>/dev/null && \
                chmod 600 server.noise.key server.noise.pub; \
            fi"
    fi
    
    if ! ssh_exec "test -f /opt/vpr/secrets/server.crt"; then
        log_info "Generating TLS certificate..."
        ssh_exec "openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
            -subj \"/CN=${SERVER_IP}\" \
            -addext \"subjectAltName=IP:${SERVER_IP}\" \
            -keyout /opt/vpr/secrets/server.key \
            -out /opt/vpr/secrets/server.crt 2>&1 | tail -3"
    fi
    
    log_info "Downloading server public key..."
    scp_download "/opt/vpr/secrets/server.noise.pub" "${TMP_DIR}/server.noise.pub" || {
        log_warn "Could not download server public key, will use insecure mode"
    }
    
    log_info "Server keys ready"
}

start_vpn_server() {
    log_step "Starting VPN server..."
    
    set +e  # Temporarily disable exit on error
    ssh_exec "pkill -f 'vpn-server'" >/dev/null 2>&1
    set -e
    sleep 1
    
    log_info "Configuring firewall..."
    set +e
    ssh_exec "iptables -I INPUT -p udp --dport ${VPN_PORT} -j ACCEPT" >/dev/null 2>&1
    ssh_exec "iptables -I INPUT -p tcp --dport ${VPN_PORT} -j ACCEPT" >/dev/null 2>&1
    set -e
    ssh_exec "sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1" || true
    
    log_info "Starting VPN server..."
    set +e
    ssh_exec "cd /opt/vpr && \
        RUST_LOG=info nohup ./bin/vpn-server \
        --bind 0.0.0.0:${VPN_PORT} \
        --tun-name vpr-srv \
        --tun-addr 10.9.0.1 \
        --pool-start 10.9.0.2 \
        --pool-end 10.9.0.254 \
        --mtu 1400 \
        --noise-dir /opt/vpr/secrets \
        --noise-name server \
        --cert /opt/vpr/secrets/server.crt \
        --key /opt/vpr/secrets/server.key \
        --enable-forwarding \
        --idle-timeout 300 \
        > /opt/vpr/logs/server.log 2>&1 &"
    local start_status=$?
    set -e
    
    if [[ $start_status -ne 0 ]]; then
        log_error "Failed to start VPN server command (exit code: $start_status)"
        ssh_exec "cat /opt/vpr/logs/server.log 2>/dev/null || echo 'No log file'"
        exit 1
    fi
    
    sleep 3
    
    set +e
    if ssh_exec "pgrep -f 'vpn-server' > /dev/null"; then
        set -e
        log_info "VPN server started successfully"
        ssh_exec "tail -15 /opt/vpr/logs/server.log"
    else
        set -e
        log_error "VPN server failed to start"
        log_info "Checking server log..."
        ssh_exec "cat /opt/vpr/logs/server.log 2>/dev/null || echo 'No log file found'"
        log_info "Checking if binary exists and is executable..."
        ssh_exec "ls -la /opt/vpr/bin/vpn-server && file /opt/vpr/bin/vpn-server"
        exit 1
    fi
}

build_client() {
    log_step "Building client binary..."
    
    if [[ ! -f "${PROJECT_DIR}/target/release/vpn-client" ]]; then
        log_info "Building VPN client..."
        cd "$PROJECT_DIR"
        cargo build --release --bin vpn-client -p masque-core 2>&1 | tail -5
    fi
    
    log_info "Client binary ready"
}

generate_client_keys() {
    log_step "Generating client keys..."
    
    mkdir -p "${TMP_DIR}/client_keys"
    
    if [[ -f "${PROJECT_DIR}/scripts/gen-noise-keys.sh" ]]; then
        "${PROJECT_DIR}/scripts/gen-noise-keys.sh" "${TMP_DIR}/client_keys" client >/dev/null 2>&1 || {
            log_warn "gen-noise-keys.sh failed, using fallback"
            # Fallback: create dummy keys (will fail handshake but test connection)
            touch "${TMP_DIR}/client_keys/client.noise.key"
            touch "${TMP_DIR}/client_keys/client.noise.pub"
        }
    else
        log_warn "gen-noise-keys.sh not found, creating placeholder keys"
        touch "${TMP_DIR}/client_keys/client.noise.key"
        touch "${TMP_DIR}/client_keys/client.noise.pub"
    fi
    
    log_info "Client keys ready"
}

start_vpn_client() {
    log_step "Starting VPN client..."
    
    ORIGINAL_GATEWAY=$(ip route | grep default | awk '{print $3}' | head -1 || echo "")
    if [[ -f /etc/resolv.conf ]]; then
        cp /etc/resolv.conf "${TMP_DIR}/resolv.conf.backup"
    fi
    
    log_info "Connecting to ${SERVER_IP}:${VPN_PORT}..."
    
    "${PROJECT_DIR}/target/release/vpn-client" \
        --server "${SERVER_IP}:${VPN_PORT}" \
        --server-name "${SERVER_IP}" \
        --tun-name "${TUN_NAME}" \
        --noise-dir "${TMP_DIR}/client_keys" \
        --noise-name client \
        --server-pub "${TMP_DIR}/server.noise.pub" \
        --set-default-route \
        --dns-protection \
        --dns-servers "8.8.8.8,1.1.1.1" \
        --tls-profile chrome \
        --insecure \
        > "${LOG_DIR}/client.log" 2>&1 &
    
    VPN_CLIENT_PID=$!
    log_info "VPN client started (PID: $VPN_CLIENT_PID)"
    
    # Wait for TUN device
    local max_wait=30
    local waited=0
    while [[ $waited -lt $max_wait ]]; do
        if ip link show "${TUN_NAME}" >/dev/null 2>&1; then
            log_info "TUN device ${TUN_NAME} created"
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done
    
    if [[ $waited -eq $max_wait ]]; then
        log_error "TUN device not created"
        cat "${LOG_DIR}/client.log"
        exit 1
    fi
    
    sleep 2
    local client_ip=$(ip addr show "${TUN_NAME}" | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1 || echo "")
    local gateway=$(ip route | grep "${TUN_NAME}" | grep default | awk '{print $3}' | head -1 || echo "10.9.0.1")
    
    log_info "Client TUN IP: ${client_ip}"
    log_info "Gateway: ${gateway}"
}

test_connection() {
    log_step "Testing VPN connection..."
    
    local gateway=$(ip route | grep "${TUN_NAME}" | grep default | awk '{print $3}' | head -1 || echo "10.9.0.1")
    
    log_info "Test 1: Pinging gateway ${gateway}..."
    if ping -c 3 -W 5 -I "${TUN_NAME}" "${gateway}" > "${LOG_DIR}/ping.log" 2>&1; then
        log_info "✓ Gateway ping successful"
    else
        log_warn "✗ Gateway ping failed"
        cat "${LOG_DIR}/ping.log"
    fi
    
    log_info "Test 2: Checking routing..."
    local route=$(ip route | grep default)
    log_info "Default route: $route"
    
    log_info "Test 3: Testing external connectivity..."
    if curl -s --max-time 10 --interface "${TUN_NAME}" https://ifconfig.me > "${LOG_DIR}/external_ip.log" 2>&1; then
        local ext_ip=$(cat "${LOG_DIR}/external_ip.log")
        log_info "✓ External IP: $ext_ip"
    else
        log_warn "✗ External connectivity test failed"
    fi
}

main() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --server) SERVER_IP="$2"; shift 2 ;;
            --user) SERVER_USER="$2"; shift 2 ;;
            --password) SERVER_PASSWORD="$2"; shift 2 ;;
            --help|-h)
                echo "Usage: $0 --server IP [--user USER] [--password PASS]"
                exit 0
                ;;
            *) log_error "Unknown option: $1"; exit 1 ;;
        esac
    done
    
    if [[ -z "$SERVER_IP" || -z "$SERVER_PASSWORD" ]]; then
        log_error "Server IP and password are required"
        exit 1
    fi
    
    log_info "=========================================="
    log_info "VPR Simple E2E Test"
    log_info "=========================================="
    log_info "Server: ${SERVER_USER}@${SERVER_IP}"
    
    check_privileges
    check_dependencies
    test_ssh || exit 1
    
    check_server_space || log_warn "Low disk space detected"
    
    prepare_server_minimal
    generate_server_keys
    start_vpn_server
    
    build_client
    generate_client_keys
    start_vpn_client
    
    sleep 3
    test_connection
    
    log_info ""
    log_info "=========================================="
    log_info "E2E Test Completed"
    log_info "=========================================="
    log_info "Check logs in: ${LOG_DIR}"
    
    # Keep connection for 5 seconds
    sleep 5
}

main "$@"
