#!/usr/bin/env bash
# VPR Full E2E Test - Real Server Testing
# Comprehensive end-to-end test against remote VPN server
#
# Usage:
#   ./scripts/e2e_full_test.sh --server IP --user USER --password PASS
#   ./scripts/e2e_full_test.sh --server 64.176.70.203 --user root --password 'PASS'

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TMP_DIR="/tmp/vpr-e2e-full-$$"
LOG_DIR="${PROJECT_DIR}/logs/e2e_full"
mkdir -p "${LOG_DIR}"
mkdir -p "${TMP_DIR}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test configuration
SERVER_IP=""
SERVER_USER="root"
SERVER_PASSWORD=""
VPN_PORT=4433
TUN_NAME="vpr0"
CLIENT_TUN_IP=""
GATEWAY_IP=""
SSH_TIMEOUT=30

# Process tracking
CLEANUP_PIDS=()
SSH_PIDS=()

log_info() { echo -e "${GREEN}[INFO]${NC} $1" | tee -a "${LOG_DIR}/test.log"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "${LOG_DIR}/test.log"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "${LOG_DIR}/test.log"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1" | tee -a "${LOG_DIR}/test.log"; }

cleanup() {
    log_info "Cleaning up..."
    
    # Kill local VPN client
    if [[ -n "${VPN_CLIENT_PID:-}" ]]; then
        log_info "Stopping VPN client (PID: $VPN_CLIENT_PID)"
        kill -TERM "$VPN_CLIENT_PID" 2>/dev/null || true
        sleep 2
        kill -9 "$VPN_CLIENT_PID" 2>/dev/null || true
    fi
    
    # Remove TUN device
    ip link del "${TUN_NAME}" 2>/dev/null || true
    
    # Kill SSH connections
    for pid in "${SSH_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    
    # Restore routing if needed
    if [[ -n "${ORIGINAL_GATEWAY:-}" ]]; then
        ip route del default 2>/dev/null || true
        ip route add default via "${ORIGINAL_GATEWAY}" 2>/dev/null || true
    fi
    
    # Restore DNS
    if [[ -f "${TMP_DIR}/resolv.conf.backup" ]]; then
        sudo cp "${TMP_DIR}/resolv.conf.backup" /etc/resolv.conf 2>/dev/null || true
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
    log_step "Checking dependencies..."
    local missing=()
    
    for cmd in sshpass cargo rustc ip ping curl dig; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing[*]}"
        log_info "Install with: sudo apt-get install -y sshpass iproute2 iputils-ping curl dnsutils"
        exit 1
    fi
    
    log_info "All dependencies available"
}

ssh_exec() {
    local cmd="$1"
    sshpass -p "$SERVER_PASSWORD" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=$SSH_TIMEOUT \
        -o UserKnownHostsFile=/dev/null \
        "${SERVER_USER}@${SERVER_IP}" "$cmd"
}

ssh_exec_bg() {
    local cmd="$1"
    sshpass -p "$SERVER_PASSWORD" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=$SSH_TIMEOUT \
        -o UserKnownHostsFile=/dev/null \
        -f -N "${SERVER_USER}@${SERVER_IP}" "$cmd" &
    SSH_PIDS+=($!)
}

scp_upload() {
    local local_path="$1"
    local remote_path="$2"
    sshpass -p "$SERVER_PASSWORD" scp -o StrictHostKeyChecking=no \
        -o ConnectTimeout=$SSH_TIMEOUT \
        -o UserKnownHostsFile=/dev/null \
        "$local_path" "${SERVER_USER}@${SERVER_IP}:${remote_path}"
}

scp_download() {
    local remote_path="$1"
    local local_path="$2"
    sshpass -p "$SERVER_PASSWORD" scp -o StrictHostKeyChecking=no \
        -o ConnectTimeout=$SSH_TIMEOUT \
        -o UserKnownHostsFile=/dev/null \
        "${SERVER_USER}@${SERVER_IP}:${remote_path}" "$local_path"
}

test_ssh_connection() {
    log_step "Testing SSH connection to ${SERVER_USER}@${SERVER_IP}..."
    if ssh_exec "echo 'SSH connection OK'"; then
        log_info "SSH connection successful"
        return 0
    else
        log_error "SSH connection failed"
        return 1
    fi
}

prepare_server() {
    log_step "Preparing server environment..."
    
    # Check Rust installation
    if ! ssh_exec "command -v rustc >/dev/null 2>&1"; then
        log_info "Installing Rust on server..."
        ssh_exec "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y" || true
        ssh_exec "source \$HOME/.cargo/env && rustc --version"
    fi
    
    # Check system dependencies
    log_info "Installing system dependencies..."
    ssh_exec "apt-get update -qq && apt-get install -y -qq build-essential pkg-config libssl-dev iproute2 iptables net-tools" || true
    
    # Create server directory
    ssh_exec "mkdir -p /opt/vpr/{bin,secrets,logs,config}"
    
    log_info "Server environment prepared"
}

build_server_binaries() {
    log_step "Building server binaries..."
    
    # Ensure TMP_DIR exists
    mkdir -p "${TMP_DIR}"
    
    # Check if binaries already exist
    if ssh_exec "test -f /opt/vpr/bin/vpn-server"; then
        log_info "Server binaries already exist, skipping build"
        return 0
    fi
    
    log_info "Uploading source code..."
    local tar_file="${TMP_DIR}/vpr-source.tar.gz"
    cd "$PROJECT_DIR"
    tar --exclude='target' --exclude='.git' --exclude='logs' \
        -czf "$tar_file" . 2>&1 | grep -v "Removing leading" || true
    
    log_info "Preparing server build directory..."
    ssh_exec "rm -rf /tmp/vpr-build && mkdir -p /tmp/vpr-build"
    
    log_info "Uploading source archive (this may take a while)..."
    scp_upload "$tar_file" "/tmp/vpr-build/vpr-source.tar.gz"
    ssh_exec "cd /tmp/vpr-build && tar -xzf vpr-source.tar.gz"
    
    log_info "Building VPN server binary..."
    ssh_exec "cd /tmp/vpr-build && source \$HOME/.cargo/env && cargo build --release --bin vpn-server -p masque-core 2>&1 | tail -10"
    
    log_info "Copying binaries to /opt/vpr/bin..."
    ssh_exec "cp /tmp/vpr-build/target/release/vpn-server /opt/vpr/bin/"
    ssh_exec "chmod +x /opt/vpr/bin/vpn-server"
    
    log_info "Server binaries built successfully"
}

generate_server_keys() {
    log_step "Generating server keys..."
    
    # Generate Noise keys on server
    if ! ssh_exec "test -f /opt/vpr/secrets/server.noise.key"; then
        log_info "Generating Noise keys..."
        ssh_exec "cd /tmp/vpr-build && source \$HOME/.cargo/env && \
            if command -v vpr-keygen >/dev/null 2>&1; then \
                vpr-keygen gen-noise-key --name server --output /opt/vpr/secrets; \
            else \
                cargo run --release --bin vpr-keygen -- gen-noise-key --name server --output /opt/vpr/secrets 2>&1 | tail -5; \
            fi" || {
            log_warn "vpr-keygen not found, using alternative method"
            ssh_exec "cd /tmp/vpr-build && source \$HOME/.cargo/env && \
                cargo build --release --bin vpr-keygen -p vpr-crypto 2>&1 | tail -5 && \
                /tmp/vpr-build/target/release/vpr-keygen gen-noise-key --name server --output /opt/vpr/secrets"
        }
    fi
    
    # Generate TLS certificate
    if ! ssh_exec "test -f /opt/vpr/secrets/server.crt"; then
        log_info "Generating TLS certificate..."
        ssh_exec "openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
            -subj \"/CN=${SERVER_IP}\" \
            -addext \"subjectAltName=IP:${SERVER_IP},DNS:${SERVER_IP}\" \
            -keyout /opt/vpr/secrets/server.key \
            -out /opt/vpr/secrets/server.crt 2>&1 | tail -3"
    fi
    
    # Download server public key for client
    log_info "Downloading server public key..."
    scp_download "/opt/vpr/secrets/server.noise.pub" "${TMP_DIR}/server.noise.pub"
    
    log_info "Server keys generated"
}

start_vpn_server() {
    log_step "Starting VPN server..."
    
    # Stop existing server
    ssh_exec "pkill -f 'vpn-server' || true"
    sleep 1
    
    # Configure firewall
    log_info "Configuring firewall..."
    ssh_exec "iptables -I INPUT -p udp --dport ${VPN_PORT} -j ACCEPT 2>/dev/null || true"
    ssh_exec "iptables -I INPUT -p tcp --dport ${VPN_PORT} -j ACCEPT 2>/dev/null || true"
    
    # Enable IP forwarding
    ssh_exec "sysctl -w net.ipv4.ip_forward=1"
    
    # Start server in background
    log_info "Starting VPN server on ${SERVER_IP}:${VPN_PORT}..."
    ssh_exec_bg "cd /opt/vpr && \
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
    
    sleep 3
    
    # Verify server is running
    if ssh_exec "pgrep -f 'vpn-server' > /dev/null"; then
        log_info "VPN server started successfully"
        ssh_exec "tail -20 /opt/vpr/logs/server.log"
    else
        log_error "VPN server failed to start"
        ssh_exec "cat /opt/vpr/logs/server.log"
        exit 1
    fi
}

build_client_binary() {
    log_step "Building client binary..."
    
    if [[ ! -f "${PROJECT_DIR}/target/release/vpn-client" ]]; then
        log_info "Building VPN client..."
        cd "$PROJECT_DIR"
        cargo build --release --bin vpn-client -p masque-core 2>&1 | tail -10
    else
        log_info "Client binary already exists"
    fi
    
    log_info "Client binary ready: ${PROJECT_DIR}/target/release/vpn-client"
}

generate_client_keys() {
    log_step "Generating client keys..."
    
    mkdir -p "${TMP_DIR}/client_keys"
    
    # Generate client Noise keys
    if [[ -f "${PROJECT_DIR}/target/release/vpr-keygen" ]]; then
        "${PROJECT_DIR}/target/release/vpr-keygen" gen-noise-key \
            --name client \
            --output "${TMP_DIR}/client_keys" 2>&1 | tail -3 || {
            log_info "Building vpr-keygen..."
            cargo build --release --bin vpr-keygen -p vpr-crypto
            "${PROJECT_DIR}/target/release/vpr-keygen" gen-noise-key \
                --name client \
                --output "${TMP_DIR}/client_keys"
        }
    else
        log_info "Building vpr-keygen..."
        cargo build --release --bin vpr-keygen -p vpr-crypto
        "${PROJECT_DIR}/target/release/vpr-keygen" gen-noise-key \
            --name client \
            --output "${TMP_DIR}/client_keys"
    fi
    
    log_info "Client keys generated"
}

start_vpn_client() {
    log_step "Starting VPN client..."
    
    # Save original gateway and DNS
    ORIGINAL_GATEWAY=$(ip route | grep default | awk '{print $3}' | head -1)
    if [[ -f /etc/resolv.conf ]]; then
        cp /etc/resolv.conf "${TMP_DIR}/resolv.conf.backup"
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
    CLEANUP_PIDS+=($VPN_CLIENT_PID)
    
    log_info "VPN client started (PID: $VPN_CLIENT_PID)"
    
    # Wait for TUN device
    log_info "Waiting for TUN device..."
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
        log_error "TUN device not created after ${max_wait}s"
        cat "${LOG_DIR}/client.log"
        exit 1
    fi
    
    # Get assigned IP and gateway
    sleep 2
    CLIENT_TUN_IP=$(ip addr show "${TUN_NAME}" | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1)
    GATEWAY_IP=$(ip route | grep "${TUN_NAME}" | grep default | awk '{print $3}' | head -1 || echo "10.9.0.1")
    
    log_info "Client TUN IP: ${CLIENT_TUN_IP}"
    log_info "Gateway IP: ${GATEWAY_IP}"
    
    # Check client log for connection status
    if grep -q "Hybrid PQ handshake complete" "${LOG_DIR}/client.log"; then
        log_info "Handshake completed successfully"
    else
        log_warn "Handshake status unclear, checking logs..."
        tail -30 "${LOG_DIR}/client.log"
    fi
}

test_connection() {
    log_step "Testing VPN connection..."
    
    # Test 1: Ping gateway
    log_info "Test 1: Pinging gateway ${GATEWAY_IP}..."
    if ping -c 3 -W 5 -I "${TUN_NAME}" "${GATEWAY_IP}" > "${LOG_DIR}/ping_gateway.log" 2>&1; then
        log_info "✓ Gateway ping successful"
        cat "${LOG_DIR}/ping_gateway.log"
    else
        log_error "✗ Gateway ping failed"
        cat "${LOG_DIR}/ping_gateway.log"
        return 1
    fi
    
    # Test 2: Check routing
    log_info "Test 2: Checking routing..."
    local default_route=$(ip route | grep default)
    if echo "$default_route" | grep -q "${TUN_NAME}"; then
        log_info "✓ Default route through VPN: $default_route"
    else
        log_warn "✗ Default route not through VPN: $default_route"
    fi
    
    # Test 3: DNS resolution
    log_info "Test 3: Testing DNS resolution..."
    if dig @8.8.8.8 google.com +short > "${LOG_DIR}/dns_test.log" 2>&1; then
        log_info "✓ DNS resolution working"
        cat "${LOG_DIR}/dns_test.log" | head -3
    else
        log_warn "✗ DNS resolution test inconclusive"
    fi
    
    # Test 4: External connectivity
    log_info "Test 4: Testing external connectivity..."
    if curl -s --max-time 10 --interface "${TUN_NAME}" https://ifconfig.me > "${LOG_DIR}/external_ip.log" 2>&1; then
        local external_ip=$(cat "${LOG_DIR}/external_ip.log")
        log_info "✓ External IP via VPN: $external_ip"
        if [[ "$external_ip" == "$SERVER_IP" ]]; then
            log_info "✓ IP matches server IP (tunneling working)"
        else
            log_warn "IP does not match server IP (may be NAT)"
        fi
    else
        log_warn "✗ External connectivity test failed"
    fi
    
    # Test 5: HTTP connectivity
    log_info "Test 5: Testing HTTP connectivity..."
    if curl -s --max-time 10 --interface "${TUN_NAME}" http://httpbin.org/get > "${LOG_DIR}/http_test.log" 2>&1; then
        log_info "✓ HTTP connectivity working"
    else
        log_warn "✗ HTTP connectivity test failed"
    fi
    
    log_info "Connection tests completed"
}

test_kill_switch() {
    log_step "Testing kill switch..."
    
    log_info "Stopping VPN client to test kill switch..."
    kill -TERM "$VPN_CLIENT_PID" 2>/dev/null || true
    sleep 2
    
    # Check if kill switch is active (traffic should be blocked)
    log_info "Testing if traffic is blocked..."
    if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
        log_warn "✗ Kill switch may not be active (ping succeeded)"
    else
        log_info "✓ Kill switch appears to be active (ping blocked)"
    fi
    
    # Note: Kill switch implementation depends on vpn-client configuration
    log_info "Kill switch test completed (manual verification recommended)"
}

test_statistics() {
    log_step "Testing statistics collection..."
    
    # Check client log for statistics
    if grep -q "bytes_sent\|bytes_received\|packets" "${LOG_DIR}/client.log"; then
        log_info "✓ Statistics found in logs"
        grep -E "bytes|packets|uptime" "${LOG_DIR}/client.log" | tail -5
    else
        log_warn "Statistics not found in logs"
    fi
}

test_graceful_shutdown() {
    log_step "Testing graceful shutdown..."
    
    log_info "Sending SIGTERM to VPN client..."
    kill -TERM "$VPN_CLIENT_PID" 2>/dev/null || true
    
    local max_wait=10
    local waited=0
    while [[ $waited -lt $max_wait ]]; do
        if ! kill -0 "$VPN_CLIENT_PID" 2>/dev/null; then
            log_info "✓ VPN client terminated gracefully"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    
    log_warn "Client did not terminate, forcing kill..."
    kill -9 "$VPN_CLIENT_PID" 2>/dev/null || true
}

generate_report() {
    log_step "Generating test report..."
    
    local report_file="${LOG_DIR}/test_report_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "=========================================="
        echo "VPR E2E Test Report"
        echo "=========================================="
        echo "Date: $(date)"
        echo "Server: ${SERVER_USER}@${SERVER_IP}:${VPN_PORT}"
        echo "Client TUN: ${TUN_NAME}"
        echo "Client IP: ${CLIENT_TUN_IP}"
        echo "Gateway: ${GATEWAY_IP}"
        echo ""
        echo "--- Test Results ---"
        echo ""
        echo "Connection: $(grep -q "Hybrid PQ handshake complete" "${LOG_DIR}/client.log" && echo "PASS" || echo "FAIL")"
        echo "Gateway Ping: $(grep -q "0% packet loss" "${LOG_DIR}/ping_gateway.log" 2>/dev/null && echo "PASS" || echo "FAIL")"
        echo ""
        echo "--- Server Logs (last 20 lines) ---"
        ssh_exec "tail -20 /opt/vpr/logs/server.log" || echo "Could not retrieve server logs"
        echo ""
        echo "--- Client Logs (last 30 lines) ---"
        tail -30 "${LOG_DIR}/client.log"
    } > "$report_file"
    
    log_info "Test report saved to: $report_file"
    cat "$report_file"
}

main() {
    local SERVER_IP=""
    local SERVER_USER="root"
    local SERVER_PASSWORD=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --server)
                SERVER_IP="$2"
                shift 2
                ;;
            --user)
                SERVER_USER="$2"
                shift 2
                ;;
            --password)
                SERVER_PASSWORD="$2"
                shift 2
                ;;
            --help|-h)
                echo "Usage: $0 --server IP [--user USER] [--password PASS]"
                echo ""
                echo "Options:"
                echo "  --server IP      VPN server IP address (required)"
                echo "  --user USER      SSH username (default: root)"
                echo "  --password PASS  SSH password (required)"
                echo "  --help           Show this help"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    if [[ -z "$SERVER_IP" ]]; then
        log_error "Server IP is required. Use --server IP"
        exit 1
    fi
    
    if [[ -z "$SERVER_PASSWORD" ]]; then
        log_error "Server password is required. Use --password PASS"
        exit 1
    fi
    
    # Export for use in functions
    export SERVER_IP SERVER_USER SERVER_PASSWORD
    
    log_info "=========================================="
    log_info "VPR Full E2E Test"
    log_info "=========================================="
    log_info "Server: ${SERVER_USER}@${SERVER_IP}"
    log_info "Log directory: ${LOG_DIR}"
    log_info ""
    
    check_privileges
    check_dependencies
    test_ssh_connection || exit 1
    
    prepare_server
    build_server_binaries
    generate_server_keys
    start_vpn_server
    
    build_client_binary
    generate_client_keys
    start_vpn_client
    
    sleep 3  # Allow connection to stabilize
    
    test_connection
    test_statistics
    
    # Keep connection for a bit to test stability
    log_info "Keeping connection active for 10 seconds..."
    sleep 10
    
    test_graceful_shutdown
    
    generate_report
    
    log_info ""
    log_info "=========================================="
    log_info "E2E Test Completed"
    log_info "=========================================="
    log_info "Check logs in: ${LOG_DIR}"
}

main "$@"
