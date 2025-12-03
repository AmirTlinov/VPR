#!/usr/bin/env bash
# VPR Automated E2E Test - "One Button" Deployment
# 
# This script fully automates VPN server deployment and client connection testing.
# It mimics the user experience: press button 1 -> server installs, press button 2 -> VPN works.
#
# Usage:
#   sudo ./scripts/e2e_automated.sh --server IP --password PASS
#   sudo ./scripts/e2e_automated.sh --server 64.176.70.203 --password 'PASS'

set -euo pipefail

# Strict error handling - fail immediately on any error
set -E
trap 'log_error "FATAL ERROR at line $LINENO. Command: $BASH_COMMAND"; exit 1' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TMP_DIR="/tmp/vpr-e2e-auto-$$"
LOG_DIR="${PROJECT_DIR}/logs/e2e_automated"
mkdir -p "${LOG_DIR}"
mkdir -p "${TMP_DIR}"

# Timeouts (in seconds)
SSH_TIMEOUT=30
BUILD_TIMEOUT=600
CONNECTION_TIMEOUT=30
TEST_TIMEOUT=10

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SERVER_IP=""
SERVER_USER="root"
SERVER_PASSWORD=""
VPN_PORT=4433
TUN_NAME="vpr0"
SERVER_TUN_NAME="vpr-srv"
VPN_CLIENT_PID=""
ORIGINAL_GATEWAY=""
ORIGINAL_DNS=""

# State tracking
SERVER_INSTALLED=false
SERVER_STARTED=false
CLIENT_CONNECTED=false

log_info() { echo -e "${GREEN}[INFO]${NC} $1" | tee -a "${LOG_DIR}/test.log"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "${LOG_DIR}/test.log"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "${LOG_DIR}/test.log"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1" | tee -a "${LOG_DIR}/test.log"; }
log_success() { echo -e "${CYAN}[✓]${NC} $1" | tee -a "${LOG_DIR}/test.log"; }

cleanup() {
    log_info "Cleaning up..."
    
    # Stop VPN client
    if [[ -n "${VPN_CLIENT_PID:-}" ]] && kill -0 "$VPN_CLIENT_PID" 2>/dev/null; then
        log_info "Stopping VPN client..."
        kill -TERM "$VPN_CLIENT_PID" 2>/dev/null || true
        sleep 2
        kill -9 "$VPN_CLIENT_PID" 2>/dev/null || true
    fi
    
    # Remove TUN device
    ip link del "${TUN_NAME}" 2>/dev/null || true
    
    # Restore routing
    if [[ -n "${ORIGINAL_GATEWAY:-}" ]]; then
        ip route del default 2>/dev/null || true
        ip route add default via "${ORIGINAL_GATEWAY}" 2>/dev/null || true
    fi
    
    # Restore DNS
    if [[ -n "${ORIGINAL_DNS:-}" ]] && [[ -f "${TMP_DIR}/resolv.conf.backup" ]]; then
        cp "${TMP_DIR}/resolv.conf.backup" /etc/resolv.conf 2>/dev/null || true
    fi
    
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script requires root privileges"
        log_info "Run with: sudo $0 $*"
        exit 1
    fi
}

check_dependencies() {
    log_step "Checking local dependencies..."
    local missing=()
    
    for cmd in sshpass cargo ip ping curl; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing[*]}"
        log_info "Install with: sudo apt-get install -y sshpass iproute2 iputils-ping curl"
        exit 1
    fi
    
    log_success "All local dependencies available"
}

ssh_exec() {
    local cmd="$*"
    
    # Use timeout only for long-running commands, not for simple checks
    if sshpass -p "$SERVER_PASSWORD" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=${SSH_TIMEOUT} \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -o ServerAliveInterval=10 \
        -o ServerAliveCountMax=3 \
        "${SERVER_USER}@${SERVER_IP}" "$cmd"; then
        return 0
    else
        local exit_code=$?
        log_error "SSH command failed (exit code: $exit_code): $cmd"
        exit 1
    fi
}

ssh_check() {
    local cmd="$*"
    # This function doesn't exit on failure - returns exit code
    sshpass -p "$SERVER_PASSWORD" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=${SSH_TIMEOUT} \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -o ServerAliveInterval=10 \
        -o ServerAliveCountMax=3 \
        "${SERVER_USER}@${SERVER_IP}" "$cmd" >/dev/null 2>&1
    return $?
}

scp_upload() {
    local local_file="$1"
    local remote_path="$2"
    
    if [[ ! -f "$local_file" ]]; then
        log_error "File not found for upload: $local_file"
        exit 1
    fi
    
    if ! timeout ${SSH_TIMEOUT} sshpass -p "$SERVER_PASSWORD" scp -o StrictHostKeyChecking=no \
        -o ConnectTimeout=${SSH_TIMEOUT} \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "$local_file" "${SERVER_USER}@${SERVER_IP}:$remote_path"; then
        log_error "SCP upload failed or timed out: $local_file -> $remote_path"
        exit 1
    fi
}

scp_download() {
    local remote_path="$1"
    local local_file="$2"
    
    if ! timeout ${SSH_TIMEOUT} sshpass -p "$SERVER_PASSWORD" scp -o StrictHostKeyChecking=no \
        -o ConnectTimeout=${SSH_TIMEOUT} \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "${SERVER_USER}@${SERVER_IP}:$remote_path" "$local_file"; then
        log_error "SCP download failed or timed out: $remote_path -> $local_file"
        exit 1
    fi
}

test_ssh() {
    log_step "Testing SSH connection..."
    if ! timeout 10 sshpass -p "$SERVER_PASSWORD" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        -o UserKnownHostsFile=/dev/null \
        "${SERVER_USER}@${SERVER_IP}" "echo 'SSH OK'" >/dev/null 2>&1; then
        log_error "SSH connection failed or timed out"
        exit 1
    fi
    log_success "SSH connection successful"
}

# ============================================================================
# PHASE 1: SERVER INSTALLATION & SETUP (Button 1)
# ============================================================================

install_server_dependencies() {
    log_step "Installing server dependencies..."
    
    # Check if Rust is installed
    if ssh_check "command -v rustc"; then
        log_info "Rust already installed"
    else
        log_info "Installing Rust (this may take a few minutes)..."
        if ! sshpass -p "$SERVER_PASSWORD" timeout 300 ssh -o StrictHostKeyChecking=no \
            -o ConnectTimeout=${SSH_TIMEOUT} \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            "${SERVER_USER}@${SERVER_IP}" \
            "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"; then
            log_error "Failed to install Rust (timeout or error)"
            exit 1
        fi
        if ! ssh_exec "source \$HOME/.cargo/env && rustc --version"; then
            log_error "Rust installation verification failed"
            exit 1
        fi
    fi
    
    # Install system dependencies
    log_info "Installing system packages..."
    if ! sshpass -p "$SERVER_PASSWORD" timeout 180 ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=${SSH_TIMEOUT} \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "${SERVER_USER}@${SERVER_IP}" \
        "apt-get update -qq && apt-get install -y -qq build-essential pkg-config libssl-dev iproute2 iptables net-tools openssl"; then
        log_error "Failed to install system packages"
        exit 1
    fi
    
    log_success "Server dependencies installed"
}

build_and_upload_binaries() {
    log_step "Building and uploading VPN binaries..."
    
    # Create server directory structure
    ssh_exec "mkdir -p /opt/vpr/{bin,secrets,logs,config}"
    
    # Check if binaries already exist on server
    if ssh_check "test -f /opt/vpr/bin/vpn-server && test -f /opt/vpr/bin/vpr-keygen"; then
        log_info "Binaries already exist on server, skipping build"
        return 0
    fi
    
    # Build binaries locally
    log_info "Building VPN binaries locally..."
    cd "$PROJECT_DIR"
    
    if [[ ! -f "${PROJECT_DIR}/target/release/vpn-server" ]]; then
        log_info "Building vpn-server (timeout: ${BUILD_TIMEOUT}s)..."
        if ! timeout ${BUILD_TIMEOUT} cargo build --release --bin vpn-server -p masque-core 2>&1 | tail -20; then
            log_error "Failed to build vpn-server (timeout or error)"
            exit 1
        fi
        if [[ ! -f "${PROJECT_DIR}/target/release/vpn-server" ]]; then
            log_error "vpn-server binary not found after build"
            exit 1
        fi
    fi
    
    if [[ ! -f "${PROJECT_DIR}/target/release/vpr-keygen" ]]; then
        log_info "Building vpr-keygen (timeout: ${BUILD_TIMEOUT}s)..."
        if ! timeout ${BUILD_TIMEOUT} cargo build --release --bin vpr-keygen -p vpr-crypto 2>&1 | tail -20; then
            log_error "Failed to build vpr-keygen (timeout or error)"
            exit 1
        fi
        if [[ ! -f "${PROJECT_DIR}/target/release/vpr-keygen" ]]; then
            log_error "vpr-keygen binary not found after build"
            exit 1
        fi
    fi
    
    # Upload binaries
    log_info "Uploading binaries to server..."
    scp_upload "${PROJECT_DIR}/target/release/vpn-server" "/opt/vpr/bin/vpn-server"
    scp_upload "${PROJECT_DIR}/target/release/vpr-keygen" "/opt/vpr/bin/vpr-keygen"
    ssh_exec "chmod +x /opt/vpr/bin/vpn-server /opt/vpr/bin/vpr-keygen"
    
    # Verify binaries on server
    if ! ssh_check "test -x /opt/vpr/bin/vpn-server && test -x /opt/vpr/bin/vpr-keygen"; then
        log_error "Binaries not executable on server"
        exit 1
    fi
    
    log_success "Binaries uploaded to server"
}

generate_server_keys() {
    log_step "Generating server cryptographic keys..."
    
    # Generate Noise keys
    if ssh_check "test -f /opt/vpr/secrets/server.noise.key"; then
        log_info "Noise keys already exist"
    else
        log_info "Generating Noise keypair..."
        if ! sshpass -p "$SERVER_PASSWORD" timeout 60 ssh -o StrictHostKeyChecking=no \
            -o ConnectTimeout=${SSH_TIMEOUT} \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            "${SERVER_USER}@${SERVER_IP}" \
            "cd /opt/vpr && source \$HOME/.cargo/env 2>/dev/null || true && \
            ./bin/vpr-keygen gen-noise-key --name server --output secrets"; then
            log_error "Failed to generate Noise keys (timeout or error)"
            exit 1
        fi
        if ! ssh_check "test -f /opt/vpr/secrets/server.noise.key && test -f /opt/vpr/secrets/server.noise.pub"; then
            log_error "Noise keys not generated properly"
            exit 1
        fi
    fi
    
    # Generate TLS certificate
    if ssh_check "test -f /opt/vpr/secrets/server.crt"; then
        log_info "TLS certificate already exists"
    else
        log_info "Generating TLS certificate..."
        if ! sshpass -p "$SERVER_PASSWORD" timeout 30 ssh -o StrictHostKeyChecking=no \
            -o ConnectTimeout=${SSH_TIMEOUT} \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            "${SERVER_USER}@${SERVER_IP}" \
            "cd /opt/vpr/secrets && \
            openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
            -subj \"/CN=${SERVER_IP}\" \
            -addext \"subjectAltName=IP:${SERVER_IP},DNS:${SERVER_IP}\" \
            -keyout server.key \
            -out server.crt"; then
            log_error "Failed to generate TLS certificate (timeout or error)"
            exit 1
        fi
        if ! ssh_check "test -f /opt/vpr/secrets/server.crt && test -f /opt/vpr/secrets/server.key"; then
            log_error "TLS certificate not generated properly"
            exit 1
        fi
    fi
    
    # Download server public key for client
    log_info "Downloading server public key..."
    if ! scp_download "/opt/vpr/secrets/server.noise.pub" "${TMP_DIR}/server.noise.pub"; then
        log_error "Failed to download server public key"
        exit 1
    fi
    if [[ ! -f "${TMP_DIR}/server.noise.pub" ]]; then
        log_error "Server public key file not found after download"
        exit 1
    fi
    
    log_success "Server keys generated"
}

configure_server_network() {
    log_step "Configuring server network..."
    
    # Enable IP forwarding
    ssh_exec "sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1" || true
    
    # Configure firewall
    log_info "Configuring firewall rules..."
    set +e
    ssh_exec "iptables -I INPUT -p udp --dport ${VPN_PORT} -j ACCEPT 2>/dev/null" || true
    ssh_exec "iptables -I INPUT -p tcp --dport ${VPN_PORT} -j ACCEPT 2>/dev/null" || true
    set -e
    
    log_success "Server network configured"
}

start_vpn_server() {
    log_step "Starting VPN server..."
    
    # Stop any existing server (ignore errors if not running)
    sshpass -p "$SERVER_PASSWORD" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=${SSH_TIMEOUT} \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "${SERVER_USER}@${SERVER_IP}" \
        "pkill -9 -f 'vpn-server' 2>/dev/null || true; \
         ip link del ${SERVER_TUN_NAME} 2>/dev/null || true" || true
    sleep 2
    
    log_info "Starting VPN server process..."
    sshpass -p "$SERVER_PASSWORD" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=${SSH_TIMEOUT} \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "${SERVER_USER}@${SERVER_IP}" \
        "cd /opt/vpr && \
        RUST_LOG=info nohup ./bin/vpn-server \
        --bind 0.0.0.0:${VPN_PORT} \
        --tun-name ${SERVER_TUN_NAME} \
        --tun-addr 10.9.0.1 \
        --pool-start 10.9.0.2 \
        --pool-end 10.9.0.254 \
        --mtu 1400 \
        --noise-dir secrets \
        --noise-name server \
        --cert secrets/server.crt \
        --key secrets/server.key \
        --enable-forwarding \
        --idle-timeout 300 \
        > logs/server.log 2>&1 &" || {
        log_error "Failed to start VPN server command"
        exit 1
    }
    
    sleep 3
    
    # Verify server is running
    local max_checks=10
    local checked=0
    while [[ $checked -lt $max_checks ]]; do
        if ssh_check "pgrep -f 'vpn-server'"; then
            log_success "VPN server started successfully"
            ssh_exec "tail -15 logs/server.log" || true
            SERVER_STARTED=true
            return 0
        fi
        sleep 1
        checked=$((checked + 1))
    done
    
    log_error "VPN server failed to start (not running after ${max_checks}s)"
    log_info "Server logs:"
    ssh_exec "cat logs/server.log 2>/dev/null || echo 'No log file'"
    log_info "Checking if binary exists:"
    ssh_exec "ls -la /opt/vpr/bin/vpn-server && file /opt/vpr/bin/vpn-server" || true
    exit 1
}

# ============================================================================
# PHASE 2: CLIENT CONNECTION & TESTING (Button 2)
# ============================================================================

build_client_binary() {
    log_step "Building client binary..."
    
    if [[ ! -f "${PROJECT_DIR}/target/release/vpn-client" ]]; then
        log_info "Building VPN client (timeout: ${BUILD_TIMEOUT}s)..."
        cd "$PROJECT_DIR"
        if ! timeout ${BUILD_TIMEOUT} cargo build --release --bin vpn-client -p masque-core 2>&1 | tail -20; then
            log_error "Failed to build vpn-client (timeout or error)"
            exit 1
        fi
        if [[ ! -f "${PROJECT_DIR}/target/release/vpn-client" ]]; then
            log_error "vpn-client binary not found after build"
            exit 1
        fi
    else
        log_info "Client binary already exists"
    fi
    
    log_success "Client binary ready"
}

generate_client_keys() {
    log_step "Generating client keys..."
    
    mkdir -p "${TMP_DIR}/client_keys"
    
    # Use vpr-keygen if available
    if [[ ! -f "${PROJECT_DIR}/target/release/vpr-keygen" ]]; then
        log_error "vpr-keygen not found. Please build it first."
        exit 1
    fi
    
    if ! timeout 30 "${PROJECT_DIR}/target/release/vpr-keygen" gen-noise-key \
        --name client \
        --output "${TMP_DIR}/client_keys" 2>&1 | tail -5; then
        log_error "Failed to generate client keys (timeout or error)"
        exit 1
    fi
    
    if [[ ! -f "${TMP_DIR}/client_keys/client.noise.key" ]] || [[ ! -f "${TMP_DIR}/client_keys/client.noise.pub" ]]; then
        log_error "Client keys not generated properly"
        exit 1
    fi
    
    log_success "Client keys generated"
}

start_vpn_client() {
    log_step "Starting VPN client..."
    
    # Save original network configuration
    ORIGINAL_GATEWAY=$(ip route | grep default | awk '{print $3}' | head -1 || echo "")
    if [[ -f /etc/resolv.conf ]]; then
        cp /etc/resolv.conf "${TMP_DIR}/resolv.conf.backup"
        ORIGINAL_DNS=$(grep nameserver /etc/resolv.conf | head -1 || echo "")
    fi
    
    # Clean up any existing TUN device
    ip link del "${TUN_NAME}" 2>/dev/null || true
    sleep 1
    
    # Verify client binary exists
    if [[ ! -f "${PROJECT_DIR}/target/release/vpn-client" ]]; then
        log_error "vpn-client binary not found"
        exit 1
    fi
    
    # Verify keys exist
    if [[ ! -f "${TMP_DIR}/client_keys/client.noise.key" ]] || [[ ! -f "${TMP_DIR}/server.noise.pub" ]]; then
        log_error "Client or server keys missing"
        exit 1
    fi
    
    log_info "Connecting to ${SERVER_IP}:${VPN_PORT}..."
    
    # Start client
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
    
    # Verify process is running
    sleep 1
    if ! kill -0 "$VPN_CLIENT_PID" 2>/dev/null; then
        log_error "VPN client process died immediately"
        log_info "Client logs:"
        tail -50 "${LOG_DIR}/client.log"
        exit 1
    fi
    
    # Wait for TUN device with timeout
    log_info "Waiting for TUN device (max ${CONNECTION_TIMEOUT}s)..."
    local waited=0
    while [[ $waited -lt ${CONNECTION_TIMEOUT} ]]; do
        if ! kill -0 "$VPN_CLIENT_PID" 2>/dev/null; then
            log_error "VPN client process died while waiting for TUN device"
            log_info "Client logs:"
            tail -50 "${LOG_DIR}/client.log"
            exit 1
        fi
        
        if ip link show "${TUN_NAME}" >/dev/null 2>&1; then
            log_success "TUN device ${TUN_NAME} created"
            break
        fi
        sleep 1
        waited=$((waited + 1))
        if [[ $((waited % 5)) -eq 0 ]]; then
            log_info "Still waiting... (${waited}/${CONNECTION_TIMEOUT}s)"
        fi
    done
    
    if [[ $waited -eq ${CONNECTION_TIMEOUT} ]]; then
        log_error "TUN device not created after ${CONNECTION_TIMEOUT}s"
        log_info "Client logs:"
        tail -100 "${LOG_DIR}/client.log"
        log_info "Killing client process..."
        kill -9 "$VPN_CLIENT_PID" 2>/dev/null || true
        exit 1
    fi
    
    sleep 2
    
    # Verify client is still running
    if ! kill -0 "$VPN_CLIENT_PID" 2>/dev/null; then
        log_error "VPN client process died after TUN creation"
        log_info "Client logs:"
        tail -100 "${LOG_DIR}/client.log"
        exit 1
    fi
    
    # Get client IP
    local client_ip=$(ip addr show "${TUN_NAME}" | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1 || echo "")
    local gateway=$(ip route | grep "${TUN_NAME}" | grep default | awk '{print $3}' | head -1 || echo "10.9.0.1")
    
    if [[ -z "$client_ip" ]]; then
        log_error "Client TUN device has no IP address"
        exit 1
    fi
    
    log_success "Client connected"
    log_info "  Client TUN IP: ${client_ip}"
    log_info "  Gateway: ${gateway}"
    
    CLIENT_CONNECTED=true
}

test_vpn_connection() {
    log_step "Testing VPN connection..."
    
    # Verify client is still running
    if ! kill -0 "$VPN_CLIENT_PID" 2>/dev/null; then
        log_error "VPN client process died during testing"
        exit 1
    fi
    
    local gateway=$(ip route | grep "${TUN_NAME}" | grep default | awk '{print $3}' | head -1 || echo "10.9.0.1")
    local tests_passed=0
    local tests_total=5
    
    # Test 1: Ping gateway
    log_info "Test 1/${tests_total}: Pinging gateway ${gateway}..."
    if timeout ${TEST_TIMEOUT} ping -c 3 -W 5 -I "${TUN_NAME}" "${gateway}" > "${LOG_DIR}/ping_gateway.log" 2>&1; then
        log_success "Gateway ping successful"
        tests_passed=$((tests_passed + 1))
    else
        log_error "Gateway ping failed"
        cat "${LOG_DIR}/ping_gateway.log"
        exit 1
    fi
    
    # Test 2: Check routing
    log_info "Test 2/${tests_total}: Checking routing..."
    local default_route=$(ip route | grep default)
    if echo "$default_route" | grep -q "${TUN_NAME}"; then
        log_success "Default route through VPN: $default_route"
        tests_passed=$((tests_passed + 1))
    else
        log_warn "Default route not through VPN: $default_route"
    fi
    
    # Test 3: DNS resolution
    log_info "Test 3/${tests_total}: Testing DNS resolution..."
    if dig @8.8.8.8 google.com +short +timeout=3 > "${LOG_DIR}/dns_test.log" 2>&1; then
        log_success "DNS resolution working"
        head -3 "${LOG_DIR}/dns_test.log"
        tests_passed=$((tests_passed + 1))
    else
        log_warn "DNS resolution test failed"
    fi
    
    # Test 4: External connectivity
    log_info "Test 4/${tests_total}: Testing external connectivity..."
    if timeout ${TEST_TIMEOUT} curl -s --max-time ${TEST_TIMEOUT} --interface "${TUN_NAME}" https://ifconfig.me > "${LOG_DIR}/external_ip.log" 2>&1; then
        local external_ip=$(cat "${LOG_DIR}/external_ip.log")
        log_success "External IP via VPN: $external_ip"
        tests_passed=$((tests_passed + 1))
    else
        log_error "External connectivity test failed"
        cat "${LOG_DIR}/external_ip.log"
        exit 1
    fi
    
    # Test 5: HTTP connectivity
    log_info "Test 5/${tests_total}: Testing HTTP connectivity..."
    if timeout ${TEST_TIMEOUT} curl -s --max-time ${TEST_TIMEOUT} --interface "${TUN_NAME}" http://httpbin.org/get > "${LOG_DIR}/http_test.log" 2>&1; then
        log_success "HTTP connectivity working"
        tests_passed=$((tests_passed + 1))
    else
        log_error "HTTP connectivity test failed"
        cat "${LOG_DIR}/http_test.log"
        exit 1
    fi
    
    log_info ""
    log_info "Test Results: ${tests_passed}/${tests_total} tests passed"
    
    if [[ $tests_passed -lt $tests_total ]]; then
        log_error "Not all tests passed. VPN may not be working correctly."
        exit 1
    fi
    
    log_success "All tests passed! VPN is working correctly."
}

test_kill_switch() {
    log_step "Testing kill switch..."
    
    log_info "Stopping VPN client to test kill switch..."
    kill -TERM "$VPN_CLIENT_PID" 2>/dev/null || true
    sleep 2
    
    # Check if traffic is blocked
    if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
        log_warn "Kill switch may not be active (ping succeeded after disconnect)"
    else
        log_success "Kill switch appears to be active (traffic blocked)"
    fi
    
    # Restart client for final tests
    start_vpn_client || return 1
}

generate_report() {
    log_step "Generating test report..."
    
    local report_file="${LOG_DIR}/test_report_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "=========================================="
        echo "VPR Automated E2E Test Report"
        echo "=========================================="
        echo "Date: $(date)"
        echo "Server: ${SERVER_USER}@${SERVER_IP}:${VPN_PORT}"
        echo "Client TUN: ${TUN_NAME}"
        echo ""
        echo "--- Installation Status ---"
        echo "Server Installed: ${SERVER_INSTALLED}"
        echo "Server Started: ${SERVER_STARTED}"
        echo "Client Connected: ${CLIENT_CONNECTED}"
        echo ""
        echo "--- Server Logs (last 20 lines) ---"
        ssh_exec "tail -20 /opt/vpr/logs/server.log 2>/dev/null || echo 'No server log'" || echo "Could not retrieve server logs"
        echo ""
        echo "--- Client Logs (last 30 lines) ---"
        tail -30 "${LOG_DIR}/client.log" 2>/dev/null || echo "No client log"
    } > "$report_file"
    
    log_info "Test report saved to: $report_file"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --server) SERVER_IP="$2"; shift 2 ;;
            --user) SERVER_USER="$2"; shift 2 ;;
            --password) SERVER_PASSWORD="$2"; shift 2 ;;
            --help|-h)
                echo "Usage: sudo $0 --server IP [--user USER] [--password PASS]"
                echo ""
                echo "This script automates:"
                echo "  1. Server installation and setup (Button 1)"
                echo "  2. VPN connection and testing (Button 2)"
                exit 0
                ;;
            *) log_error "Unknown option: $1"; exit 1 ;;
        esac
    done
    
    if [[ -z "$SERVER_IP" || -z "$SERVER_PASSWORD" ]]; then
        log_error "Server IP and password are required"
        log_info "Usage: sudo $0 --server IP --password PASS"
        exit 1
    fi
    
    log_info ""
    log_info "=========================================="
    log_info "VPR Automated E2E Test"
    log_info "=========================================="
    log_info "Server: ${SERVER_USER}@${SERVER_IP}"
    log_info "Log directory: ${LOG_DIR}"
    log_info ""
    
    check_privileges
    check_dependencies
    test_ssh || exit 1
    
    # PHASE 1: Server Installation (Button 1)
    log_info ""
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_info "PHASE 1: Server Installation & Setup"
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_info ""
    
    install_server_dependencies
    build_and_upload_binaries
    generate_server_keys
    configure_server_network
    start_vpn_server
    
    SERVER_INSTALLED=true
    
    log_info ""
    log_success "✓ Server installation complete!"
    log_info ""
    
    # PHASE 2: Client Connection & Testing (Button 2)
    log_info ""
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_info "PHASE 2: Client Connection & Testing"
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_info ""
    
    build_client_binary
    generate_client_keys
    start_vpn_client
    
    sleep 3  # Allow connection to stabilize
    
    test_vpn_connection
    
    log_info ""
    log_info "Keeping connection active for 10 seconds..."
    sleep 10
    
    generate_report
    
    log_info ""
    log_info "=========================================="
    log_success "E2E Test Completed Successfully!"
    log_info "=========================================="
    log_info "Check logs in: ${LOG_DIR}"
    log_info ""
}

main "$@"
